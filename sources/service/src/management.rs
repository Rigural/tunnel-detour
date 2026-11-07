use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    num::NonZeroUsize,
    path::Path,
};

use serde_json::{Value, json};
use tunnel_detour_core::RuleSet;

use crate::{ServiceError, adguard::AdguardManager, config::ResourceLimits, kernel::Kernel, uci};

const INPUT_LIMIT: u64 = 1_048_576;

/// rpcd executable-plugin signature. No arbitrary commands or file paths are accepted.
pub fn rpc_methods() -> Value {
    json!({"status": {}, "validate": {"patterns": ""}, "check": {}, "restart": {}})
}

fn read_private(path: &Path) -> Result<Option<Vec<u8>>, ServiceError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(
        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ServiceError::Protocol)?,
    );
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ServiceError::Protocol);
    }
    let mut bytes = Vec::new();
    file.take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ServiceError::Protocol)? > INPUT_LIMIT {
        return Err(ServiceError::Protocol);
    }
    Ok(Some(bytes))
}

/// Validate with the same parser and capacity as production configuration.
pub fn validate_patterns(lines: &str) -> Value {
    let Some(capacity) = NonZeroUsize::new(ResourceLimits::default().max_rules) else {
        return json!({"valid": false, "error": "invalid_capacity"});
    };
    match RuleSet::from_lines(lines, capacity) {
        Ok(rules) => {
            let patterns: Vec<_> = rules
                .rules()
                .iter()
                .map(|rule| rule.pattern.to_string())
                .collect();
            json!({"valid": true, "patterns": patterns})
        }
        Err(error) => json!({"valid": false, "error": error.to_string()}),
    }
}

/// Serve one rpcd request. rpcd owns authentication and applies method-specific ACLs.
pub async fn rpc_call(method: &str, input: &[u8]) -> Result<Value, ServiceError> {
    if u64::try_from(input.len()).map_err(|_| ServiceError::Protocol)? > INPUT_LIMIT {
        return Err(ServiceError::Protocol);
    }
    let request: Value = serde_json::from_slice(input)?;
    let object = request.as_object().ok_or(ServiceError::Protocol)?;
    if object
        .keys()
        .any(|key| key != "ubus_rpc_session" && !(method == "validate" && key == "patterns"))
    {
        return Err(ServiceError::Protocol);
    }
    match method {
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
            let bytes = tokio::task::block_in_place(|| read_private(Path::new(uci::STATUS_FILE)))?;
            let status = match bytes {
                Some(bytes) => serde_json::from_slice::<Value>(&bytes)?,
                None => Value::Null,
            };
            // A status snapshot from a prior process must never claim current readiness.
            let current = (pid.is_some() && status["process_id"].as_u64() == pid)
                || (pid.is_none()
                    && matches!(status["phase"].as_str(), Some("failed" | "stopped")));
            Ok(
                json!({"running": pid.is_some(), "status": if current { status } else { Value::Null }}),
            )
        }
        "validate" => {
            let lines = request["patterns"].as_str().ok_or(ServiceError::Protocol)?;
            Ok(validate_patterns(lines))
        }
        "check" => match crate::load_uci(true).await {
            Ok(Some(_)) => Ok(json!({"valid": true})),
            Ok(None) => Err(ServiceError::Protocol),
            Err(error) => Ok(json!({"valid": false, "error": error.code()})),
        },
        "restart" => {
            let output =
                crate::kernel::command("/etc/init.d/tunnel-detour", &["restart".into()], None)
                    .await?;
            Ok(json!({"accepted": output.success}))
        }
        _ => Err(ServiceError::Protocol),
    }
}

fn idle_lock() -> Result<Option<File>, ServiceError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).write(true).custom_flags(
        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| ServiceError::Protocol)?,
    );
    let lock = match options.open(format!("{}.lock", uci::STATE_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ServiceError::Protocol);
    }
    lock.try_lock()
        .map_err(tunnel_detour_core::StoreError::from)?;
    Ok(Some(lock))
}

/// Remove remote forwarding only after the running service released its state lock.
/// This does not require WAN or LAN to be up, so disabling and uninstalling work offline.
pub async fn cleanup_uci(uninstall: bool) -> Result<(), ServiceError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(50);
    let _lock = loop {
        match tokio::task::block_in_place(idle_lock) {
            Ok(lock) => break lock,
            Err(ServiceError::Store(tunnel_detour_core::StoreError::Lock(
                std::fs::TryLockError::WouldBlock,
            ))) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            Err(error) => return Err(error),
        }
    };
    let journal = format!("{}.adguard.json", uci::STATE_FILE);
    let has_journal = match fs::symlink_metadata(&journal) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::symlink_metadata(format!("{journal}.lock")) {
                Ok(_) => return Err(crate::adguard::AdguardError::State.into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };
    if has_journal {
        let settings = uci::cleanup_settings().await?;
        let mut manager = tokio::task::block_in_place(|| {
            AdguardManager::open(settings, Path::new(uci::STATE_FILE), None)
        })?;
        manager.reconcile(None).await?;
    }
    if uninstall {
        Kernel::uninstall().await?;
        // Delete only known package-owned files, never recursively remove a directory.
        for path in [
            uci::STATE_FILE.to_string(),
            format!("{}.lock", uci::STATE_FILE),
            journal.clone(),
            format!("{journal}.lock"),
            uci::STATUS_FILE.to_string(),
            "/etc/config/tunnel-detour".to_string(),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for directory in ["/etc/tunnel-detour", "/var/run/tunnel-detour"] {
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
