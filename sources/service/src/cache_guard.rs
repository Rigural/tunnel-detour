//! Native firewall protection survives a daemon failure and loss of kernel state.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

use serde_json::Value;
use tempfile::NamedTempFile;
use tunnel_detour_core::FakeIpRange;

use crate::{ServiceError, kernel};

const DIRECTORY: &str = "/etc/nftables.d";
const PATH: &str = "/etc/nftables.d/tunnel-detour-cache-guard.nft";
const OWNER: &str = "tunnel-detour:cache-guard:v1";
const CHAINS: [&str; 2] = ["tunnel_detour_cache_forward", "tunnel_detour_cache_output"];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn rules(range: FakeIpRange) -> String {
    let mut text = format!("# {OWNER}\n");
    for (name, hook) in CHAINS.iter().zip(["forward", "output"]) {
        text.push_str(&format!(
            "chain {name} {{\n type filter hook {hook} priority -6; policy accept;\n comment \"{OWNER}\";\n ip daddr {range} reject with icmpx type admin-prohibited\n ip6 daddr {} reject with icmpx type admin-prohibited\n}}\n",
            range.ipv6_range(),
        ));
    }
    text
}

fn options() -> Result<OpenOptions, ServiceError> {
    let mut options = OpenOptions::new();
    options.custom_flags(
        i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
            .map_err(|_| ServiceError::KernelConflict)?,
    );
    Ok(options)
}

fn safe_directory() -> Result<bool, ServiceError> {
    let metadata = match fs::symlink_metadata(DIRECTORY) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(ServiceError::KernelConflict);
    }
    Ok(true)
}

fn existing() -> Result<Option<String>, ServiceError> {
    let file = match options()?.read(true).open(PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > 4096 {
        return Err(ServiceError::KernelConflict);
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(ServiceError::KernelConflict);
    }
    Ok(Some(text))
}

/// Share the actual platform lock with `/sbin/fw4`, so a concurrent reload cannot
/// reintroduce chains between removing their persistent source and live objects.
async fn lock() -> Result<File, ServiceError> {
    let file = options()?
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open("/var/run/fw4.lock")?;
    if !file.metadata()?.is_file() {
        return Err(ServiceError::KernelConflict);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(ServiceError::Busy),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

async fn owned_chains() -> Result<Vec<&'static str>, ServiceError> {
    let listing = kernel::command_with_limit(
        "nft",
        &strings(&["-j", "list", "table", "inet", "fw4"]),
        None,
        4 * 1_048_576,
    )
    .await?;
    if !listing.success {
        let tables = kernel::command("nft", &strings(&["-j", "list", "tables"]), None).await?;
        if !tables.success {
            return Err(ServiceError::KernelConflict);
        }
        let tables: Value = serde_json::from_slice(&tables.stdout)?;
        if tables["nftables"]
            .as_array()
            .ok_or(ServiceError::Protocol)?
            .iter()
            .any(|object| object["table"]["family"] == "inet" && object["table"]["name"] == "fw4")
        {
            return Err(ServiceError::KernelConflict);
        }
        return Ok(Vec::new());
    }
    let listing: Value = serde_json::from_slice(&listing.stdout)?;
    let objects = listing["nftables"]
        .as_array()
        .ok_or(ServiceError::Protocol)?;
    let mut owned = Vec::new();
    for name in CHAINS {
        if let Some(chain) = objects
            .iter()
            .find_map(|object| (object["chain"]["name"] == name).then_some(&object["chain"]))
        {
            if chain["family"] != "inet" || chain["table"] != "fw4" || chain["comment"] != OWNER {
                return Err(ServiceError::KernelConflict);
            }
            owned.push(name);
        }
    }
    Ok(owned)
}

/// Persist the exact leased ranges before native service readiness can publish DNS.
/// A different existing file is a conflict, never an invitation to overwrite it.
pub(crate) async fn preserve(range: FakeIpRange) -> Result<(), ServiceError> {
    let _lock = lock().await?;
    if !safe_directory()? {
        return Err(ServiceError::KernelConflict);
    }
    owned_chains().await?;
    let expected = rules(range);
    match existing()? {
        Some(text) if text != expected => return Err(ServiceError::KernelConflict),
        Some(_) => {}
        None => {
            let mut temporary = NamedTempFile::new_in(DIRECTORY)?;
            temporary.write_all(expected.as_bytes())?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(PATH)
                .map_err(|error| error.error)?;
            File::open(DIRECTORY)?.sync_all()?;
        }
    }
    // Printing is read-only and does not reacquire fw4's mutation lock. Refuse
    // DNS publication if the administrator disabled the required include path.
    let rendered = kernel::command_with_limit("fw4", &["print".into()], None, 1_048_576).await?;
    if !rendered.success
        || !String::from_utf8_lossy(&rendered.stdout).contains("include \"/etc/nftables.d/*.nft\"")
    {
        return Err(ServiceError::KernelConflict);
    }
    kernel::checked("fw4", strings(&["check"]), None).await?;
    Ok(())
}

pub(crate) async fn remove() -> Result<(), ServiceError> {
    let _lock = lock().await?;
    safe_directory()?;
    if let Some(text) = existing()? {
        // Recover ownership without reading the possibly invalid UCI or lease
        // snapshot. Only canonical output from our validated range is accepted.
        let range = text
            .lines()
            .find_map(|line| {
                line.strip_prefix(" ip daddr ")
                    .and_then(|line| line.split_whitespace().next())
                    .and_then(|value| value.parse::<FakeIpRange>().ok())
            })
            .ok_or(ServiceError::KernelConflict)?;
        if text != rules(range) {
            return Err(ServiceError::KernelConflict);
        }
    }
    let mut transaction = String::new();
    for name in owned_chains().await? {
        transaction.push_str(&format!(
            "flush chain inet fw4 {name}\ndelete chain inet fw4 {name}\n"
        ));
    }
    // A failed transaction must retain the persistent protection for the next
    // boot. The platform lock prevents a reload between live and file removal.
    if !transaction.is_empty() {
        kernel::checked("nft", strings(&["-f", "-"]), Some(transaction.as_bytes())).await?;
    }
    match fs::remove_file(Path::new(PATH)) {
        Ok(()) => File::open(DIRECTORY)?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
