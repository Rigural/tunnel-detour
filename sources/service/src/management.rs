use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    num::NonZeroUsize,
    path::Path,
};

use serde_json::{Value, json};
use tunnel_detour_core::{DomainPattern, RuleSet};

use crate::{
    ServiceError,
    adguard::{AdguardControl, AdguardError},
    config::{AdguardSettings, DnsIntegration, ResourceLimits},
    kernel::Kernel,
    uci,
};

const INPUT_LIMIT: u64 = 1_048_576;

/// rpcd executable-plugin signature. No arbitrary commands or file paths are accepted.
pub fn rpc_methods() -> Value {
    json!({"status": {}, "credentials_status": {}, "set_credentials":{"username":"","password":""}, "validate": {"patterns": ""}, "check": {}, "test_adguard": {"api_url":"", "username":"", "password":"", "use_saved_credentials":false}, "preview_upstream":{"api_url":"","username":"","password":"","real_upstream":"","import_current":false,"use_saved_credentials":false}, "restart": {}, "inbound_status":{}, "inbound_devices":{"network":""}, "inbound_port_usage":{"port":0}, "check_inbound":{}, "restart_inbound":{}})
}

async fn draft_adguard(request: &Value) -> Result<AdguardSettings, ServiceError> {
    if request
        .get("use_saved_credentials")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(ServiceError::Protocol);
    }
    let field = |name: &str| request[name].as_str().ok_or(ServiceError::Protocol);
    let api_url = field("api_url")?.to_owned();
    let username = field("username")?;
    let password = field("password")?;
    let settings = if request["use_saved_credentials"] == true {
        if !username.is_empty() || !password.is_empty() {
            return Err(ServiceError::Protocol);
        }
        let revision = crate::uci::credential_revision().await?;
        tokio::task::block_in_place(|| crate::credentials::settings(api_url, revision.as_deref()))?
    } else {
        let authenticated = !username.is_empty() || !password.is_empty();
        AdguardSettings {
            api_url,
            username: authenticated.then(|| username.to_owned()),
            password: authenticated.then(|| password.to_owned()),
        }
    };
    settings.endpoint()?;
    Ok(settings)
}

fn read_private(path: &Path) -> Result<Option<Vec<u8>>, ServiceError> {
    read_private_bounded(path, INPUT_LIMIT)
}

/// Read the ownership identity from a private runtime snapshot, when present.
pub(crate) fn snapshot_owner(path: &Path) -> Result<Option<[u64; 2]>, ServiceError> {
    #[derive(serde::Deserialize)]
    struct SnapshotOwner {
        #[serde(alias = "observability_owner")]
        status_owner: Option<[u64; 2]>,
    }

    let Some(bytes) = read_private(path)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice::<SnapshotOwner>(&bytes)?.status_owner)
}

pub(crate) fn status_writer(
    path: &Path,
    create: bool,
    conflict: impl FnOnce() -> ServiceError,
) -> Result<Option<File>, ServiceError> {
    use crate::integration_state::IntegrationStateError::{Io, Json, Lock, Unsafe};

    crate::integration_state::try_status_writer(path, create).map_err(|error| match error {
        Io(error) | Lock(std::fs::TryLockError::Error(error)) => error.into(),
        Json(error) => error.into(),
        Lock(std::fs::TryLockError::WouldBlock) | Unsafe => conflict(),
    })
}

pub(crate) fn snapshot_matches_lock(path: &Path, lock: &File) -> Result<bool, ServiceError> {
    let identity = crate::integration_state::lock_identity(lock)?;
    Ok(snapshot_owner(path)? == Some(identity))
}

/// Identify package-managed status files even when the parent directory has an alias.
pub(crate) fn is_uci_status_path(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let reserved = [uci::STATUS_FILE, crate::inbound_uci::STATUS].map(Path::new);
    if reserved.contains(&path) {
        return Ok(true);
    }
    let parent_identity = |path: &Path| match path.parent().map(fs::metadata) {
        Some(Ok(metadata)) => Ok(Some((metadata.dev(), metadata.ino()))),
        Some(Err(error)) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(None),
    };
    let Some(parent) = parent_identity(path)? else {
        return Ok(false);
    };
    for reserved_path in reserved {
        if path.file_name() == reserved_path.file_name()
            && parent_identity(reserved_path)? == Some(parent)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn read_private_bounded(
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, ServiceError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(
        i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
            .map_err(|_| ServiceError::Protocol)?,
    );
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(ServiceError::Protocol);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ServiceError::Protocol)? > limit {
        return Err(ServiceError::Protocol);
    }
    Ok(Some(bytes))
}

fn redact_observations(status: &mut Value, inbound: bool) -> bool {
    let Some(fields) = status.as_object_mut() else {
        return false;
    };
    let legacy = !fields.contains_key("observability");
    let mut changed =
        fields.insert("observability".into(), Value::Bool(false)) != Some(Value::Bool(false));
    for key in [
        "connections",
        "dns_queries",
        "failures",
        "last_request_error",
        "completed_connections",
        "bytes_to_wan",
        "bytes_from_wan",
        "mapping_usage",
        "relay",
        "observability_epoch",
        "observability_grant",
    ] {
        changed |= fields.remove(key).is_some();
    }
    // A legacy ownership stamp belongs to the snapshot, not to its diagnostic period.
    if let Some(owner) = fields.remove("observability_owner") {
        fields.entry("status_owner").or_insert(owner);
        changed = true;
    }
    if legacy && !inbound {
        // Older DNS versions shared last_error between lifecycle and request failures.
        changed |= fields.remove("last_error").is_some();
    }
    changed
}

/// Scrub prior diagnostics before startup only when no running daemon owns the state.
pub fn clear_uci_observations(inbound: bool) {
    let state_path = Path::new(if inbound {
        crate::inbound_uci::STATE
    } else {
        uci::STATE_FILE
    });
    tokio::task::block_in_place(|| {
        clear_when_idle(state_path, |_| {
            clear_snapshot(crate::observability::uci_status_path(inbound), inbound)
        });
    });
}

pub(crate) fn finish_uci_cleanup(inbound: bool) -> Result<(), ServiceError> {
    clear_snapshot(crate::observability::uci_status_path(inbound), inbound)?;
    crate::observability::revoke_uci_grant(inbound)
}

async fn uci_status(inbound: bool, pid: Option<u64>) -> Result<(Value, bool, bool), ServiceError> {
    let bytes = tokio::task::block_in_place(|| {
        read_private(crate::observability::uci_status_path(inbound))
    })?;
    let mut status = match bytes {
        Some(bytes) => serde_json::from_slice::<Value>(&bytes)?,
        None => Value::Null,
    };
    let section = if inbound { "inbound" } else { "globals" };
    let requested = uci::read_sections()
        .await
        .map_or(crate::observability::Consent::Off, |sections| {
            sections.consent(section)
        });
    let current = (pid.is_some() && status["process_id"].as_u64() == pid)
        || (pid.is_none() && matches!(status["phase"].as_str(), Some("failed" | "stopped")));
    let observing = current && pid.is_some() && status["observability"] == true;
    let revocation_pending = if !observing {
        false
    } else if !requested.enabled() {
        // A reader can observe the withdrawal before procd runs. Remove the
        // grant before responding, even if the UCI transaction later rolls back.
        crate::observability::revoke_uci_grant(inbound)?;
        true
    } else {
        !crate::observability::read_uci_grant(inbound).is_ok_and(|grant| {
            grant.is_some_and(|token| status["observability_grant"] == json!(token))
        }) || status["observability_epoch"] != json!(requested.epoch())
    };
    if !observing || revocation_pending || !requested.enabled() {
        redact_observations(&mut status, inbound);
    }
    if let Some(fields) = status.as_object_mut() {
        fields.remove("observability_epoch");
        fields.remove("observability_revocation");
        fields.remove("observability_grant");
        fields.remove("observability_owner");
        fields.remove("status_owner");
    }
    Ok((
        if current { status } else { Value::Null },
        requested.enabled(),
        revocation_pending,
    ))
}

pub(crate) fn clear_snapshot(path: &Path, inbound: bool) -> Result<(), ServiceError> {
    tokio::task::block_in_place(|| {
        let parent = path.parent().ok_or(crate::ConfigError::Paths)?;
        match fs::symlink_metadata(parent) {
            Ok(_) => crate::runtime::prepare_parent(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let bytes = match read_private(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(crate::observability::discard_snapshot(path)?),
        };
        if let Some(bytes) = bytes {
            let Ok(mut status) = serde_json::from_slice::<Value>(&bytes) else {
                return Ok(crate::observability::discard_snapshot(path)?);
            };
            if !status.is_object() {
                return Ok(crate::observability::discard_snapshot(path)?);
            }
            if redact_observations(&mut status, inbound)
                && crate::integration_state::atomic_write(path, &status).is_err()
            {
                crate::observability::discard_snapshot(path)?;
            }
        }
        Ok(())
    })
}

/// Validate with the same parser and capacity as production configuration.
pub fn validate_patterns(lines: &str) -> Value {
    let Some(capacity) = NonZeroUsize::new(ResourceLimits::default().max_rules) else {
        return json!({"valid": false, "error": "invalid_capacity"});
    };
    // Row diagnostics use the production hostname type; errors never echo invalid input.
    // Bound diagnostics independently of the request-size limit.
    let mut rows = Vec::new();
    let mut seen = BTreeMap::new();
    for line in lines.lines().take(capacity.get()) {
        let row = match line.trim().parse::<DomainPattern>() {
            Ok(pattern) => {
                let pattern = pattern.to_string();
                let duplicate = seen.insert(pattern.clone(), rows.len());
                if let Some(first) = duplicate {
                    rows[first] = json!({"pattern":pattern,"error":"duplicate"});
                    json!({"pattern":pattern,"error":"duplicate"})
                } else {
                    json!({"pattern":pattern})
                }
            }
            Err(_) => json!({"error":"invalid_domain"}),
        };
        rows.push(row);
    }
    let mut result = match RuleSet::from_lines(lines, capacity) {
        Ok(rules) => {
            let patterns: Vec<_> = rules
                .rules()
                .iter()
                .map(|rule| rule.pattern.to_string())
                .collect();
            json!({"valid": true, "patterns": patterns})
        }
        Err(error) => json!({"valid": false, "error": error.to_string()}),
    };
    result["rows"] = json!(rows);
    result
}

/// Serve one rpcd request. rpcd owns authentication and applies method-specific ACLs.
pub async fn rpc_call(method: &str, input: &[u8]) -> Result<Value, ServiceError> {
    if u64::try_from(input.len()).map_err(|_| ServiceError::Protocol)? > INPUT_LIMIT {
        return Err(ServiceError::Protocol);
    }
    let request: Value = serde_json::from_slice(input)?;
    let object = request.as_object().ok_or(ServiceError::Protocol)?;
    if object.keys().any(|key| {
        key != "ubus_rpc_session"
            && !(method == "validate" && key == "patterns")
            && !(method == "inbound_devices" && key == "network")
            && !(method == "inbound_port_usage" && key == "port")
            && !(method == "test_adguard"
                && matches!(
                    key.as_str(),
                    "api_url" | "username" | "password" | "use_saved_credentials"
                ))
            && !(method == "set_credentials" && matches!(key.as_str(), "username" | "password"))
            && !(method == "preview_upstream"
                && matches!(
                    key.as_str(),
                    "api_url"
                        | "username"
                        | "password"
                        | "real_upstream"
                        | "import_current"
                        | "use_saved_credentials"
                ))
    }) {
        return Err(ServiceError::Protocol);
    }
    match method {
        "credentials_status" => {
            let revision = crate::uci::credential_revision().await?;
            Ok(
                match tokio::task::block_in_place(|| {
                    crate::credentials::configured(revision.as_deref())
                }) {
                    Ok(configured) => json!({"configured":configured}),
                    Err(error) => json!({"configured":false,"error":error.code()}),
                },
            )
        }
        "set_credentials" => {
            let username = request["username"]
                .as_str()
                .ok_or(ServiceError::Protocol)?
                .to_owned();
            let password = request["password"]
                .as_str()
                .ok_or(ServiceError::Protocol)?
                .to_owned();
            let applied = crate::uci::credential_revision().await?;
            let revision = tokio::task::block_in_place(|| {
                crate::credentials::replace(username, password, applied.as_deref())
            })?;
            Ok(json!({"saved":true,"revision":revision}))
        }
        "preview_upstream" => {
            let result = async {
                let field = |key: &str| request[key].as_str().ok_or(ServiceError::Protocol);
                let mut config = crate::load_uci(true).await?.ok_or(ServiceError::Protocol)?;
                let settings = draft_adguard(&request).await?;
                config.adguard = Some(settings);
                let endpoint = field("real_upstream")?;
                let resolver = crate::config::parse_resolver_endpoint(endpoint)?;
                config.validate_resolver_endpoint(resolver)?;
                config.real_upstream = resolver;
                crate::preview_adguard_upstream(
                    &config,
                    request["import_current"]
                        .as_bool()
                        .ok_or(ServiceError::Protocol)?,
                )
                .await
            }
            .await;
            Ok(match result {
                Ok(mut preview) => {
                    preview["valid"] = json!(true);
                    preview
                }
                Err(error) => {
                    json!({"valid":false,"error":error.code(), "recovery_resolvers":match &error {
                        ServiceError::ResolverRecovery {allowed} => allowed.clone(),
                        _ => Vec::new(),
                    }})
                }
            })
        }
        "inbound_port_usage" => {
            let port = request["port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or(ServiceError::Protocol)?;
            Ok(
                match crate::port_guard::inspect([port].into_iter().collect()).await {
                    Ok(mut ports) => {
                        let uses = ports.remove(&port).unwrap_or_default();
                        json!({"available":uses.iter().all(|usage| usage.tunnel_detour),"uses":uses})
                    }
                    Err(error) => json!({"available":false,"error":error.code()}),
                },
            )
        }
        "inbound_devices" => {
            let name = request["network"].as_str().ok_or(ServiceError::Protocol)?;
            Ok(match crate::inbound_uci::device_hints(name).await {
                Ok(value) => value,
                Err(error) => json!({"devices":[],"error":error.code()}),
            })
        }
        "inbound_status" => {
            let services: Value = serde_json::from_slice(
                &uci::ubus("service", "list", json!({"name":"tunnel-detour-inbound"})).await?,
            )?;
            let instance = &services["tunnel-detour-inbound"]["instances"]["inbound"];
            let pid = (instance["running"] == true)
                .then(|| instance["pid"].as_u64())
                .flatten();
            let (status, observability_requested, revocation_pending) =
                uci_status(true, pid).await?;
            Ok(
                json!({"enabled":crate::inbound_uci::is_enabled().await.ok(),"running":pid.is_some(),"observability_requested":observability_requested,"observability_revocation_pending":revocation_pending,"status":status}),
            )
        }
        "check_inbound" => {
            let result = async {
                let config = crate::load_inbound_uci(true)
                    .await?
                    .ok_or(crate::UciError::Options)?;
                crate::check_inbound_config(&config).await
            }
            .await;
            Ok(match result {
                Ok(()) => json!({"valid":true}),
                Err(error) => {
                    json!({"valid":false,"error":error.code(),"port_conflict":crate::port_guard::diagnostic(&error)})
                }
            })
        }
        "restart_inbound" => {
            let output = crate::kernel::command(
                "/etc/init.d/tunnel-detour-inbound",
                &["restart".into()],
                None,
            )
            .await?;
            Ok(json!({"accepted":output.success}))
        }
        "status" => {
            let services: Value = serde_json::from_slice(
                &uci::ubus("service", "list", json!({"name": "tunnel-detour"})).await?,
            )?;
            let pid = services["tunnel-detour"]["instances"]
                .as_object()
                .and_then(|instances| {
                    instances
                        .values()
                        .find(|instance| instance["running"] == true)
                        .and_then(|instance| instance["pid"].as_u64())
                });
            let (status, observability_requested, revocation_pending) =
                uci_status(false, pid).await?;
            Ok(
                json!({"enabled":uci::is_enabled().await.ok(), "dns_integration":uci::configured_integration().await?, "running":pid.is_some(), "observability_requested":observability_requested,"observability_revocation_pending":revocation_pending, "status":status}),
            )
        }
        "validate" => {
            let lines = request["patterns"].as_str().ok_or(ServiceError::Protocol)?;
            Ok(validate_patterns(lines))
        }
        "check" => match crate::load_uci(true).await {
            Ok(Some(config)) => match crate::frontend::check(&config).await {
                Ok(()) => Ok(json!({"valid": true})),
                Err(error) => Ok(json!({"valid":false,"error":error.code()})),
            },
            Ok(None) => Err(ServiceError::Protocol),
            Err(error) => Ok(json!({"valid": false, "error": error.code()})),
        },
        "test_adguard" => {
            let draft = ["api_url", "username", "password"]
                .iter()
                .any(|key| object.contains_key(*key));
            if !draft && uci::configured_integration().await? != Some(DnsIntegration::Adguard) {
                return Ok(json!({"connected":false,"error":"adguard_integration_disabled"}));
            }
            let result = async {
                let settings = if draft {
                    // Draft credentials are transient: no UCI writes, persistence, or logging.
                    // Partial drafts must never silently fall back to applied credentials.
                    draft_adguard(&request).await?
                } else {
                    uci::cleanup_settings().await?
                };
                AdguardControl::new(settings)?
                    .probe()
                    .await
                    .map_err(ServiceError::from)
            }
            .await;
            match result {
                Ok(health) => Ok(json!({"connected":true,"health":health})),
                Err(error) => {
                    let code = match &error {
                        ServiceError::Adguard(AdguardError::HttpStatus(401 | 403)) => {
                            "adguard_authentication_failed"
                        }
                        ServiceError::Adguard(AdguardError::Request(source))
                            if source.is_timeout() =>
                        {
                            "adguard_timeout"
                        }
                        ServiceError::Adguard(AdguardError::Request(source))
                            if source.is_connect() =>
                        {
                            "adguard_unreachable"
                        }
                        ServiceError::Adguard(
                            AdguardError::Endpoint | AdguardError::RemoteEndpoint,
                        )
                        | ServiceError::Config(crate::config::ConfigError::AdguardEndpoint) => {
                            "adguard_endpoint_invalid"
                        }
                        ServiceError::Adguard(
                            AdguardError::Response { .. }
                            | AdguardError::Json(_)
                            | AdguardError::Encoding(_),
                        ) => "adguard_response_invalid",
                        _ => error.code(),
                    };
                    Ok(json!({"connected":false,"error":code}))
                }
            }
        }
        "restart" => {
            let output =
                crate::kernel::command("/etc/init.d/tunnel-detour", &["restart".into()], None)
                    .await?;
            Ok(json!({"accepted": output.success}))
        }
        _ => Err(ServiceError::Protocol),
    }
}

pub(crate) fn idle_lock(path: &Path) -> Result<Option<File>, ServiceError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).write(true).custom_flags(
        i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
            .map_err(|_| tunnel_detour_core::StoreError::UnsafeFile)?,
    );
    let lock = match options.open(crate::integration_state::appended_path(path, ".lock")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(tunnel_detour_core::StoreError::UnsafeFile.into());
    }
    lock.try_lock()
        .map_err(tunnel_detour_core::StoreError::from)?;
    Ok(Some(lock))
}

/// Startup recovery may scrub a snapshot without taking over the daemon's work.
/// Keep the primary startup failure when the old snapshot cannot safely be changed.
pub(crate) fn clear_when_idle(path: &Path, clear: impl FnOnce(&File) -> Result<(), ServiceError>) {
    let result = match idle_lock(path) {
        Ok(Some(lock)) => clear(&lock),
        Ok(None)
        | Err(ServiceError::Store(tunnel_detour_core::StoreError::Lock(
            std::fs::TryLockError::WouldBlock,
        ))) => return,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        tracing::warn!(
            target: "tunnel_detour::health",
            code = error.code(),
            "prior traffic diagnostics could not be cleared before startup"
        );
    }
}

/// Remove remote forwarding only after the running service released its state lock.
/// This does not require WAN or LAN to be up, so disabling and uninstalling work offline.
pub async fn cleanup_uci(uninstall: bool) -> Result<(), ServiceError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(50);
    let _lock = loop {
        match tokio::task::block_in_place(|| idle_lock(Path::new(uci::STATE_FILE))) {
            Ok(lock) => break lock,
            Err(ServiceError::Store(tunnel_detour_core::StoreError::Lock(
                std::fs::TryLockError::WouldBlock,
            ))) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            Err(error) => return Err(error),
        }
    };
    if uninstall {
        crate::cleanup_inbound_uci().await?;
    }
    let cleaned = crate::frontend::cleanup_all(Path::new(uci::STATE_FILE)).await;
    if !uninstall {
        return cleaned.and(finish_uci_cleanup(false));
    }
    cleaned?;
    if uninstall {
        crate::ipv6_routing::Ipv6Routing::cleanup(Path::new(uci::STATE_FILE)).await?;
        crate::cache_guard::remove().await?;
        Kernel::uninstall().await?;
        // Delete only known package-owned files, never recursively remove a directory.
        for path in [
            crate::credentials::PATH.to_string(),
            format!("{}.lock", crate::credentials::PATH),
            uci::STATE_FILE.to_string(),
            format!("{}.lock", uci::STATE_FILE),
            format!("{}.adguard.json", uci::STATE_FILE),
            format!("{}.adguard.json.lock", uci::STATE_FILE),
            format!("{}.adguard-preview.json", uci::STATE_FILE),
            format!("{}.dnsmasq.json", uci::STATE_FILE),
            format!("{}.dnsmasq.json.lock", uci::STATE_FILE),
            format!("{}.ipv6-routing.json", uci::STATE_FILE),
            format!("{}.ipv6-routing.json.lock", uci::STATE_FILE),
            uci::STATUS_FILE.to_string(),
            "/var/run/tunnel-detour/observability.revoked".to_string(),
            "/var/run/tunnel-detour/observability.grant".to_string(),
            crate::inbound_uci::STATE.to_string(),
            format!("{}.lock", crate::inbound_uci::STATE),
            crate::inbound_uci::STATUS.to_string(),
            "/var/run/tunnel-detour/inbound/observability.revoked".to_string(),
            "/var/run/tunnel-detour/inbound/observability.grant".to_string(),
            "/etc/config/tunnel-detour".to_string(),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for directory in [
            "/var/run/tunnel-detour/transport",
            "/etc/tunnel-detour/inbound",
            "/var/run/tunnel-detour/inbound",
            "/etc/tunnel-detour",
            "/var/run/tunnel-detour",
        ] {
            match fs::remove_dir(directory) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}
