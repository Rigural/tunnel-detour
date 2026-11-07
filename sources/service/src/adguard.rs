use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;
use tunnel_detour_core::{DomainName, RuleSet};

use crate::{ServiceConfig, ServiceError, config::AdguardSettings, kernel};

#[derive(Debug, Error)]
pub enum AdguardError {
    #[error("AdGuard control request failed")]
    Request(#[from] reqwest::Error),
    #[error("AdGuard control request returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("AdGuard response or ownership state is invalid JSON")]
    Json(#[from] serde_json::Error),
    #[error("AdGuard {operation} response has an incompatible field: {field}")]
    Response {
        operation: &'static str,
        field: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("AdGuard ownership state I/O failed")]
    Io(#[from] std::io::Error),
    #[error("another process owns the AdGuard reconciliation lock")]
    Lock(#[from] std::fs::TryLockError),
    #[error("AdGuard ownership state is unsafe or incompatible")]
    State,
    #[error("AdGuard response exceeds the supported size bound")]
    TooLarge,
    #[error("AdGuard file-based or fallback upstreams require a different integration policy")]
    UnsupportedUpstreams,
    #[error("an existing domain-specific upstream overlaps the requested exception rules")]
    UpstreamConflict,
    #[error("AdGuard upstream configuration changed while applying the exception rules")]
    ConcurrentChange,
    #[error("the dedicated real resolver points back to AdGuard and would create a DNS loop")]
    ResolverLoop,
    #[error("local interface addresses could not be inspected")]
    LocalAddresses(#[source] Box<ServiceError>),
    #[error("AdGuard control endpoint is invalid")]
    Endpoint,
    #[error("AdGuard control endpoint must belong to this router")]
    RemoteEndpoint,
}

const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u8,
    managed: BTreeSet<String>,
}

#[derive(Deserialize, Eq, PartialEq)]
struct DnsInfo {
    upstream_dns: Vec<String>,
    #[serde(default)]
    upstream_dns_file: String,
    #[serde(default)]
    fallback_dns: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ServerStatus {
    dns_addresses: Vec<String>,
    dns_port: u16,
    protection_enabled: bool,
}

pub(crate) struct AdguardManager {
    real_upstream: Option<SocketAddrV4>,
    control: AdguardControl,
    journal_path: PathBuf,
    _lock: File,
    owned: BTreeSet<String>,
}

#[derive(Clone)]
pub(crate) struct AdguardControl {
    settings: AdguardSettings,
    endpoint: reqwest::Url,
    client: Client,
    slots: Arc<tokio::sync::Semaphore>,
    local_endpoint: Arc<tokio::sync::OnceCell<()>>,
}

impl AdguardManager {
    pub fn new(config: Arc<ServiceConfig>) -> Result<Option<Self>, ServiceError> {
        let Some(settings) = config.adguard.clone() else {
            return Ok(None);
        };
        Ok(Some(Self::open(
            settings,
            &config.state_file,
            Some(config.real_upstream),
        )?))
    }

    pub(crate) fn open(
        settings: AdguardSettings,
        state_file: &std::path::Path,
        real_upstream: Option<SocketAddrV4>,
    ) -> Result<Self, ServiceError> {
        let control = AdguardControl::new(settings)?;
        let journal_path = appended_path(state_file, ".adguard.json");
        let lock_path = appended_path(&journal_path, ".lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| AdguardError::State)?,
            );
        }
        let (lock, new_lock) = match options.open(&lock_path) {
            Ok(lock) => (lock, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options.create_new(false);
                (options.open(&lock_path).map_err(AdguardError::from)?, false)
            }
            Err(error) => return Err(AdguardError::Io(error).into()),
        };
        validate_private(&lock.metadata().map_err(AdguardError::from)?)?;
        lock.try_lock().map_err(AdguardError::from)?;
        let owned = match fs::symlink_metadata(&journal_path) {
            Ok(metadata) => {
                validate_private(&metadata)?;
                let mut bytes = Vec::new();
                let mut options = OpenOptions::new();
                options.read(true);
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(
                        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                            .map_err(|_| AdguardError::State)?,
                    );
                }
                options
                    .open(&journal_path)
                    .map_err(AdguardError::from)?
                    .take(u64::try_from(RESPONSE_LIMIT + 1).map_err(|_| AdguardError::TooLarge)?)
                    .read_to_end(&mut bytes)
                    .map_err(AdguardError::from)?;
                if bytes.len() > RESPONSE_LIMIT {
                    return Err(AdguardError::TooLarge.into());
                }
                let ownership: Ownership =
                    serde_json::from_slice(&bytes).map_err(AdguardError::from)?;
                if ownership.version != 1
                    || ownership.managed.len() > 4096
                    || ownership.managed.iter().any(|line| !valid_owned_line(line))
                {
                    return Err(AdguardError::State.into());
                }
                ownership.managed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && new_lock => {
                BTreeSet::new()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AdguardError::State.into());
            }
            Err(error) => return Err(AdguardError::Io(error).into()),
        };
        let manager = Self {
            real_upstream,
            control,
            journal_path,
            _lock: lock,
            owned,
        };
        if new_lock {
            manager.save_ownership(manager.owned.clone())?;
        }
        Ok(manager)
    }

    fn save_ownership(&self, managed: BTreeSet<String>) -> Result<(), AdguardError> {
        let parent = self.journal_path.parent().ok_or(AdguardError::State)?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        let bytes = serde_json::to_vec(&Ownership {
            version: 1,
            managed,
        })?;
        if bytes.len() > RESPONSE_LIMIT {
            return Err(AdguardError::TooLarge);
        }
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.journal_path)
            .map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

impl AdguardControl {
    pub(crate) fn new(settings: AdguardSettings) -> Result<Self, ServiceError> {
        let endpoint = settings.endpoint()?;
        let client = Client::builder()
            .no_proxy()
            // Binding the verified local address also fails if it is removed before connect.
            .local_address(IpAddr::V4(
                endpoint
                    .host_str()
                    .and_then(|host| host.parse::<Ipv4Addr>().ok())
                    .ok_or(AdguardError::Endpoint)?,
            ))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .build()
            .map_err(AdguardError::from)?;
        Ok(Self {
            settings,
            endpoint,
            client,
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
            local_endpoint: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    fn request(&self, method: Method, operation: &str) -> Result<RequestBuilder, AdguardError> {
        let endpoint = self
            .endpoint
            .join(operation)
            .map_err(|_| AdguardError::Endpoint)?;
        let mut request = self.client.request(method, endpoint);
        if let (Some(user), Some(password)) = (&self.settings.username, &self.settings.password) {
            request = request.basic_auth(user, Some(password));
        }
        Ok(request)
    }

    async fn bytes(&self, request: RequestBuilder) -> Result<Vec<u8>, AdguardError> {
        self.local_endpoint
            .get_or_try_init(|| async {
                let host = self.endpoint.host_str().ok_or(AdguardError::Endpoint)?;
                if host
                    .parse::<Ipv4Addr>()
                    .map_err(|_| AdguardError::Endpoint)?
                    .is_loopback()
                {
                    return Ok(());
                }
                let output = kernel::command(
                    "ip",
                    &["-j".into(), "-4".into(), "addr".into(), "show".into()],
                    None,
                )
                .await
                .map_err(|error| AdguardError::LocalAddresses(Box::new(error)))?;
                let interfaces: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
                    .map_err(|_| AdguardError::RemoteEndpoint)?;
                if !output.success
                    || !interfaces
                        .iter()
                        .filter_map(|interface| interface["addr_info"].as_array())
                        .flatten()
                        .any(|address| address["local"].as_str() == Some(host))
                {
                    return Err(AdguardError::RemoteEndpoint);
                }
                Ok(())
            })
            .await?;
        let _permit = self
            .slots
            .acquire()
            .await
            .map_err(|_| AdguardError::State)?;
        let mut response = request.send().await?;
        if !response.status().is_success() {
            return Err(AdguardError::HttpStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|size| size > RESPONSE_LIMIT as u64)
        {
            return Err(AdguardError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > RESPONSE_LIMIT)
            {
                return Err(AdguardError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn get<T: DeserializeOwned>(&self, operation: &'static str) -> Result<T, AdguardError> {
        let bytes = self.bytes(self.request(Method::GET, operation)?).await?;
        Self::decode(operation, &bytes)
    }

    fn decode<T: DeserializeOwned>(
        operation: &'static str,
        bytes: &[u8],
    ) -> Result<T, AdguardError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
            AdguardError::Response {
                operation,
                field: error.path().to_string(),
                source: error.into_inner(),
            }
        })
    }

    pub(crate) async fn filtering_enabled(&self, client: Ipv4Addr) -> Result<bool, ServiceError> {
        #[derive(Deserialize)]
        struct FilteringStatus {
            enabled: bool,
        }
        #[derive(Deserialize)]
        struct ClientPolicy {
            name: String,
            ids: Vec<String>,
            use_global_settings: bool,
            filtering_enabled: bool,
        }
        #[derive(Deserialize)]
        struct Clients {
            clients: Option<Vec<ClientPolicy>>,
        }
        #[derive(Deserialize)]
        struct ClientMatch {
            name: String,
            ids: Vec<String>,
            disallowed: bool,
        }
        let status: ServerStatus = self.get("status").await?;
        let filtering: FilteringStatus = self.get("filtering/status").await?;
        let persistent: Clients = self.get("clients").await?;
        let request = self
            .request(Method::POST, "clients/search")?
            .json(&serde_json::json!({"clients": [{"id": client.to_string()}]}));
        let bytes = self.bytes(request).await?;
        let clients: Vec<std::collections::BTreeMap<String, ClientMatch>> =
            Self::decode("clients/search", &bytes)?;
        let mut enabled = filtering.enabled;
        for entry in clients {
            if let Some(policy) = entry.get(&client.to_string()) {
                if policy.disallowed {
                    return Err(ServiceError::Unauthorized);
                }
                // Auto-discovered clients also contain zero-valued settings. Only a matching
                // persistent client can override the global policy.
                if let Some(settings) = persistent
                    .clients
                    .iter()
                    .flatten()
                    .find(|entry| entry.name == policy.name && entry.ids == policy.ids)
                    && !settings.use_global_settings
                {
                    enabled = settings.filtering_enabled;
                }
            }
        }
        Ok(status.protection_enabled && enabled)
    }

    pub(crate) async fn check_host(
        &self,
        name: &str,
        qtype: &str,
        client: Ipv4Addr,
    ) -> Result<(), ServiceError> {
        #[derive(Deserialize)]
        struct FilterResult {
            reason: String,
        }
        let mut endpoint = self
            .endpoint
            .join("filtering/check_host")
            .map_err(|_| AdguardError::Endpoint)?;
        endpoint
            .query_pairs_mut()
            .append_pair("name", name)
            .append_pair("client", &client.to_string())
            .append_pair("qtype", qtype);
        let request = self.request(Method::GET, endpoint.as_str())?;
        let bytes = self.bytes(request).await?;
        let result: FilterResult = Self::decode("filtering/check_host", &bytes)?;
        if !matches!(
            result.reason.as_str(),
            "NotFilteredNotFound" | "NotFilteredWhiteList"
        ) {
            return Err(ServiceError::FilteredTarget);
        }
        Ok(())
    }
}

impl AdguardManager {
    pub async fn reconcile(
        &mut self,
        selection: Option<(SocketAddrV4, &RuleSet)>,
    ) -> Result<(), AdguardError> {
        if selection.is_none() && self.owned.is_empty() {
            return Ok(());
        }
        let mut desired = BTreeSet::new();
        if let Some((dns, rules)) = selection {
            for rule in rules.rules().iter().filter(|rule| rule.enabled) {
                desired.insert(format!("[/{}/]{dns}", rule.pattern.domain));
            }
        }
        let current: DnsInfo = self.control.get("dns_info").await?;
        if !desired.is_empty() {
            if !current.upstream_dns_file.is_empty()
                || current
                    .fallback_dns
                    .as_ref()
                    .is_some_and(|values| !values.is_empty())
            {
                return Err(AdguardError::UnsupportedUpstreams);
            }
            self.check_resolver_loop().await?;
        }
        let foreign: Vec<_> = current
            .upstream_dns
            .iter()
            .filter(|line| !self.owned.contains(*line))
            .cloned()
            .collect();
        if let Some((_, rules)) = selection {
            check_conflicts(&foreign, rules)?;
        }
        if foreign.iter().any(|line| desired.contains(line)) {
            return Err(AdguardError::UpstreamConflict);
        }
        let mut merged = foreign;
        merged.extend(desired.iter().cloned());
        if current.upstream_dns != merged {
            // Journal the union before any remote write. A timeout cannot lose ownership of a
            // change that the remote endpoint may already have applied.
            let body = serde_json::to_vec(&serde_json::json!({"upstream_dns":merged}))?;
            if body.len() > RESPONSE_LIMIT {
                return Err(AdguardError::TooLarge);
            }
            let pending: BTreeSet<_> = self.owned.union(&desired).cloned().collect();
            tokio::task::block_in_place(|| self.save_ownership(pending.clone()))?;
            self.owned = pending;
            let before: DnsInfo = self.control.get("dns_info").await?;
            if current != before {
                return Err(AdguardError::ConcurrentChange);
            }
            let request = self
                .control
                .request(Method::POST, "dns_config")?
                .header("content-type", "application/json")
                .body(body);
            self.control.bytes(request).await?;
            let after: DnsInfo = self.control.get("dns_info").await?;
            if after.upstream_dns != merged
                || after.upstream_dns_file != current.upstream_dns_file
                || after.fallback_dns != current.fallback_dns
            {
                return Err(AdguardError::ConcurrentChange);
            }
        }
        // A previous request may have changed upstreams before its cache-clear response was
        // lost. Retry that idempotent cleanup even when the remote list already matches.
        if !self.owned.is_empty() || !desired.is_empty() {
            self.control
                .bytes(self.control.request(Method::POST, "cache_clear")?)
                .await?;
        }
        tokio::task::block_in_place(|| self.save_ownership(desired.clone()))?;
        self.owned = desired;
        Ok(())
    }

    async fn check_resolver_loop(&self) -> Result<(), AdguardError> {
        let upstream = self.real_upstream.ok_or(AdguardError::ResolverLoop)?;
        let status: ServerStatus = self.control.get("status").await?;
        if upstream.port() != status.dns_port {
            return Ok(());
        }
        let real = *upstream.ip();
        let mut wildcard = false;
        for address in status.dns_addresses {
            // AdGuard's presentation includes the port when it is nonstandard.
            let binding = address
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|value| (value.ip(), value.port()))
                .or_else(|| {
                    address
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| (ip, status.dns_port))
                });
            if let Some((IpAddr::V4(ip), port)) = binding
                && port == upstream.port()
            {
                if ip == real {
                    return Err(AdguardError::ResolverLoop);
                }
                wildcard |= ip.is_unspecified();
            }
        }
        if wildcard {
            if real.is_loopback() {
                return Err(AdguardError::ResolverLoop);
            }
            let output = kernel::command(
                "ip",
                &["-j".into(), "-4".into(), "addr".into(), "show".into()],
                None,
            )
            .await
            .map_err(|error| AdguardError::LocalAddresses(Box::new(error)))?;
            if !output.success {
                return Err(AdguardError::ResolverLoop);
            }
            #[derive(Deserialize)]
            struct Interface {
                addr_info: Vec<Address>,
            }
            #[derive(Deserialize)]
            struct Address {
                local: Ipv4Addr,
            }
            let interfaces: Vec<Interface> = serde_json::from_slice(&output.stdout)?;
            if interfaces.into_iter().any(|interface| {
                interface
                    .addr_info
                    .into_iter()
                    .any(|address| address.local == real)
            }) {
                return Err(AdguardError::ResolverLoop);
            }
        }
        Ok(())
    }
}

fn appended_path(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn valid_owned_line(line: &str) -> bool {
    let Some((domain, address)) = line
        .strip_prefix("[/")
        .and_then(|line| line.split_once("/]"))
    else {
        return false;
    };
    let Ok(parsed) = domain.parse::<DomainName>() else {
        return false;
    };
    let Ok(address) = address.parse::<SocketAddrV4>() else {
        return false;
    };
    parsed.as_str() == domain
        && address.ip().is_loopback()
        && address.port() != 0
        && line == format!("[/{parsed}/]{address}")
}

fn validate_private(metadata: &fs::Metadata) -> Result<(), AdguardError> {
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(AdguardError::State);
    }
    Ok(())
}

fn check_conflicts(foreign: &[String], rules: &RuleSet) -> Result<(), AdguardError> {
    for line in foreign {
        let Some(domains) = line.strip_prefix("[/") else {
            continue;
        };
        let (domains, _) = domains
            .split_once("/]")
            .ok_or(AdguardError::UpstreamConflict)?;
        for domain in domains.split('/') {
            if domain.is_empty() {
                continue;
            }
            let base = domain.strip_prefix("*.").unwrap_or(domain);
            let base: DomainName = base.parse().map_err(|_| AdguardError::UpstreamConflict)?;
            for rule in rules.rules().iter().filter(|rule| rule.enabled) {
                let desired = rule.pattern.domain.as_str();
                let existing = base.as_str();
                if desired == existing
                    || desired.ends_with(&format!(".{existing}"))
                    || existing.ends_with(&format!(".{desired}"))
                {
                    return Err(AdguardError::UpstreamConflict);
                }
            }
        }
    }
    Ok(())
}
