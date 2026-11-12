//! Own only domain forwarding entries in an existing, standard OpenWrt dnsmasq frontend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tunnel_detour_core::{DomainName, RuleSet};

use crate::{
    ServiceConfig, ServiceError,
    integration_state::{self, IntegrationStateError, PrivateJournal, appended_path},
    kernel, uci,
};

#[derive(Debug, Error)]
pub enum DnsmasqError {
    #[error(transparent)]
    Ownership(#[from] IntegrationStateError),
    #[error("select one running dnsmasq instance with the standard DNS/local-name profile")]
    Profile,
    #[error(
        "dnsmasq filtering, rewrites, DNSSEC, or extra configuration are not supported by this profile"
    )]
    Unsupported,
    #[error("dnsmasq local or conditional rules overlap an exception")]
    Conflict,
    #[error("the real resolver points back to the dnsmasq frontend")]
    ResolverLoop,
    #[error("dnsmasq ownership state is unsafe or belongs to another instance")]
    State,
    #[error(
        "dnsmasq configuration changed or has unapplied changes; no foreign settings were committed"
    )]
    ConcurrentChange,
    #[error("dnsmasq could not apply or reload its owned forwarding entries")]
    Apply,
}

#[derive(Deserialize, Eq, PartialEq)]
struct Snapshot {
    values: BTreeMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u8,
    section: String,
    managed: BTreeSet<String>,
    original: Option<Value>,
    #[serde(default)]
    pending: bool,
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parser(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    integration_state::fuzz_roundtrip(bytes, Ownership::validate)
}

fn section_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn values(value: Option<&Value>) -> Result<Vec<String>, DnsmasqError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(value)) => Ok(vec![value.clone()]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(DnsmasqError::Profile)
            })
            .collect(),
        _ => Err(DnsmasqError::Profile),
    }
}

fn owned_line(line: &str) -> bool {
    let Some((domain, endpoint)) = line.strip_prefix('/').and_then(|line| line.split_once('/'))
    else {
        return false;
    };
    let Ok(name) = domain.parse::<DomainName>() else {
        return false;
    };
    let Some((address, port)) = endpoint.split_once('#') else {
        return false;
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    address.is_loopback() && port != 0 && line == format!("/{name}/{address}#{port}")
}

impl Ownership {
    fn validate(&self) -> Result<(), DnsmasqError> {
        if self.version != 1
            || !section_name(&self.section)
            || self.managed.len() > 4096
            || self.managed.iter().any(|line| !owned_line(line))
        {
            return Err(DnsmasqError::State);
        }
        values(self.original.as_ref())?;
        Ok(())
    }
}

async fn snapshot() -> Result<Snapshot, ServiceError> {
    Ok(serde_json::from_slice(
        &uci::ubus("uci", "get", json!({"config":"dhcp"})).await?,
    )?)
}

async fn no_pending_changes() -> Result<(), ServiceError> {
    let output = kernel::command("uci", &["changes".into(), "dhcp".into()], None).await?;
    if !output.success {
        return Err(DnsmasqError::Apply.into());
    }
    if !output.stdout.is_empty() {
        return Err(DnsmasqError::ConcurrentChange.into());
    }
    Ok(())
}

fn overlap(name: &str, rules: &RuleSet) -> Result<(), DnsmasqError> {
    let name: DomainName = name.parse().map_err(|_| DnsmasqError::Unsupported)?;
    for rule in rules.rules().iter().filter(|rule| rule.enabled) {
        let base = rule.pattern.domain.as_str();
        if base == name.as_str()
            || base.ends_with(&format!(".{name}"))
            || name.as_str().ends_with(&format!(".{base}"))
        {
            return Err(DnsmasqError::Conflict);
        }
    }
    Ok(())
}

fn regular_file(path: &Path) -> Result<Option<File>, DnsmasqError> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).map_err(|_| DnsmasqError::Unsupported)?)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DnsmasqError::Unsupported),
    };
    if !file
        .metadata()
        .map_err(|_| DnsmasqError::Unsupported)?
        .is_file()
    {
        return Err(DnsmasqError::Unsupported);
    }
    Ok(Some(file))
}

fn comment_only(path: &Path) -> Result<(), DnsmasqError> {
    let Some(file) = regular_file(path)? else {
        return Ok(());
    };
    let mut bytes = String::new();
    file.take(131073)
        .read_to_string(&mut bytes)
        .map_err(|_| DnsmasqError::Unsupported)?;
    if bytes.len() > 131072
        || bytes.lines().any(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
    {
        return Err(DnsmasqError::Unsupported);
    }
    Ok(())
}

fn local_hosts(path: &Path, rules: &RuleSet) -> Result<(), DnsmasqError> {
    let Some(file) = regular_file(path)? else {
        return Ok(());
    };
    let mut bytes = String::new();
    file.take(131073)
        .read_to_string(&mut bytes)
        .map_err(|_| DnsmasqError::Unsupported)?;
    if bytes.len() > 131072 {
        return Err(DnsmasqError::Unsupported);
    }
    for line in bytes.lines() {
        for name in line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .skip(1)
        {
            if name.parse::<DomainName>().is_ok() {
                overlap(name, rules)?;
            }
        }
    }
    Ok(())
}

fn profile<'a>(
    current: &'a Snapshot,
    owned: &BTreeSet<String>,
    rules: &RuleSet,
) -> Result<(&'a str, &'a Value), DnsmasqError> {
    let instances: Vec<_> = current
        .values
        .iter()
        .filter(|(_, value)| value[".type"] == "dnsmasq")
        .collect();
    let [(section, options)] = instances.as_slice() else {
        return Err(DnsmasqError::Profile);
    };
    if !section_name(section)
        || options["disabled"].as_str().is_some_and(|v| v != "0")
        || options["port"].as_str().is_some_and(|v| v != "53")
    {
        return Err(DnsmasqError::Profile);
    }
    // This initial profile deliberately excludes opaque filter sources and per-client DNS
    // policies: ordinary forwarding cannot reproduce AdGuard's per-client filter API.
    const ALLOWED: &[&str] = &[
        "domainneeded",
        "boguspriv",
        "filterwin2k",
        "localise_queries",
        "rebind_protection",
        "rebind_localhost",
        "rebind_domain",
        "local",
        "domain",
        "expandhosts",
        "nonegcache",
        "cachesize",
        "authoritative",
        "readethers",
        "leasefile",
        "resolvfile",
        "nonwildcard",
        "localservice",
        "ednspacket_max",
        "filter_aaaa",
        "filter_a",
        "server",
        "noresolv",
        "port",
        "disabled",
        "logqueries",
        "logdhcp",
        "quietdhcp",
        "dhcpleasemax",
        "dnsforwardmax",
        "localuse",
        "ubus",
        "dhcp_ignore_names",
        "sequential_ip",
    ];
    let object = options.as_object().ok_or(DnsmasqError::Profile)?;
    if object
        .keys()
        .any(|key| !key.starts_with('.') && !ALLOWED.contains(&key.as_str()))
        || ["filterwin2k", "filter_aaaa", "filter_a"]
            .iter()
            .any(|key| options[*key].as_str().is_some_and(|value| value != "0"))
    {
        return Err(DnsmasqError::Unsupported);
    }
    for local in values(object.get("local"))? {
        for name in local.split('/').filter(|name| !name.is_empty()) {
            overlap(name, rules)?;
        }
    }
    if let Some(domain) = options["domain"].as_str().filter(|value| !value.is_empty()) {
        overlap(domain, rules)?;
    }
    for line in values(object.get("server"))? {
        if owned.contains(&line) {
            continue;
        }
        if line
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(DnsmasqError::Unsupported);
        }
        if let Some(domains) = line.strip_prefix('/') {
            let (domains, _) = domains.rsplit_once('/').ok_or(DnsmasqError::Unsupported)?;
            for domain in domains.split('/') {
                overlap(domain, rules)?;
            }
        }
    }
    // Local host records are preserved, but selected public aliases cannot be rewritten
    // before reaching Fake-IP policy. Arbitrary filter/config files need a dedicated adapter.
    for reserved in ["bind", "invalid", "local", "localhost", "onion", "test"] {
        overlap(reserved, rules)?;
    }
    for value in current.values.values() {
        match value[".type"].as_str() {
            Some("hostrecord" | "domain" | "host") => {
                for name in values(value.get("name"))? {
                    overlap(&name, rules)?;
                }
            }
            Some("cname" | "dnsrr" | "ipset") => return Err(DnsmasqError::Unsupported),
            _ => {}
        }
    }
    comment_only(Path::new("/etc/dnsmasq.conf"))?;
    comment_only(&Path::new("/etc").join(format!("dnsmasq.{section}.conf")))?;
    local_hosts(Path::new("/etc/hosts"), rules)?;
    if options["readethers"]
        .as_str()
        .is_some_and(|value| value != "0")
    {
        local_hosts(Path::new("/etc/ethers"), rules)?;
    }
    let entries = match std::fs::read_dir("/tmp/hosts") {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(DnsmasqError::Unsupported),
    };
    if let Some(entries) = entries {
        for (index, entry) in entries.enumerate() {
            if index >= 1024 {
                return Err(DnsmasqError::Unsupported);
            }
            let entry = entry.map_err(|_| DnsmasqError::Unsupported)?;
            if !entry
                .file_type()
                .map_err(|_| DnsmasqError::Unsupported)?
                .is_file()
            {
                return Err(DnsmasqError::Unsupported);
            }
            local_hosts(&entry.path(), rules)?;
        }
    }
    let directory = Path::new("/tmp").join(format!("dnsmasq.{section}.d"));
    if directory.exists()
        && std::fs::read_dir(directory)
            .map_err(|_| DnsmasqError::Unsupported)?
            .next()
            .is_some()
    {
        return Err(DnsmasqError::Unsupported);
    }
    Ok((section, options))
}

async fn pid(section: &str) -> Result<Option<u64>, ServiceError> {
    let services: Value =
        serde_json::from_slice(&uci::ubus("service", "list", json!({"name":"dnsmasq"})).await?)?;
    let instance = &services["dnsmasq"]["instances"][section];
    Ok((instance["running"] == true)
        .then(|| instance["pid"].as_u64())
        .flatten())
}

pub(crate) struct DnsmasqManager {
    config: Option<Arc<ServiceConfig>>,
    journal: PrivateJournal,
    ownership: Ownership,
}

impl DnsmasqManager {
    pub(crate) fn resolver_settings(&mut self, config: Arc<ServiceConfig>) {
        self.config = Some(config);
    }
}

impl DnsmasqManager {
    pub(crate) fn has_owned(state: &Path) -> Result<bool, ServiceError> {
        let saved: Option<Ownership> =
            integration_state::existing(&appended_path(state, ".dnsmasq.json"))
                .map_err(DnsmasqError::from)?;
        if let Some(saved) = saved {
            saved.validate()?;
            return Ok(!saved.managed.is_empty() || saved.pending);
        }
        Ok(false)
    }

    pub(crate) async fn open(config: Arc<ServiceConfig>) -> Result<Self, ServiceError> {
        let current = snapshot().await?;
        let (section, _) = tokio::task::block_in_place(|| {
            profile(
                &current,
                &BTreeSet::new(),
                &RuleSet::from_lines(
                    "",
                    std::num::NonZeroUsize::new(1).ok_or(DnsmasqError::State)?,
                )
                .map_err(|_| DnsmasqError::State)?,
            )
        })?;
        let journal = tokio::task::block_in_place(|| {
            PrivateJournal::open(appended_path(&config.state_file, ".dnsmasq.json"))
        })
        .map_err(DnsmasqError::from)?;
        let mut ownership = tokio::task::block_in_place(|| {
            journal.load(Ownership {
                version: 1,
                section: section.to_owned(),
                managed: BTreeSet::new(),
                original: current.values[section].get("server").cloned(),
                pending: false,
            })
        })
        .map_err(DnsmasqError::from)?;
        ownership.validate()?;
        if ownership.section != section {
            return Err(DnsmasqError::State.into());
        }
        if ownership.managed.is_empty() && !ownership.pending {
            ownership.original = current.values[section].get("server").cloned();
        }
        if journal.is_new() || ownership.managed.is_empty() {
            tokio::task::block_in_place(|| journal.save(&ownership)).map_err(DnsmasqError::from)?;
        }
        let manager = Self {
            config: Some(config),
            journal,
            ownership,
        };
        manager.validate().await?;
        Ok(manager)
    }

    pub(crate) fn recovery(state: &Path) -> Result<Self, ServiceError> {
        let journal = PrivateJournal::open(appended_path(state, ".dnsmasq.json"))
            .map_err(DnsmasqError::from)?;
        let ownership: Ownership = journal
            .load(Ownership {
                version: 1,
                section: String::new(),
                managed: BTreeSet::new(),
                original: None,
                pending: false,
            })
            .map_err(DnsmasqError::from)?;
        ownership.validate()?;
        Ok(Self {
            config: None,
            journal,
            ownership,
        })
    }

    pub(crate) async fn validate(&self) -> Result<(), ServiceError> {
        let config = self.config.as_ref().ok_or(DnsmasqError::State)?;
        validate_frontend(config, &self.ownership.managed, false).await
    }

    pub(crate) async fn reconcile(
        &mut self,
        selection: Option<(SocketAddrV4, &RuleSet)>,
    ) -> Result<(), ServiceError> {
        if selection.is_none() && self.ownership.managed.is_empty() && !self.ownership.pending {
            return Ok(());
        }
        let current = snapshot().await?;
        if selection.is_some() {
            self.validate().await?;
        }
        let options = current
            .values
            .get(&self.ownership.section)
            .ok_or(DnsmasqError::State)?;
        if options[".type"] != "dnsmasq" {
            return Err(DnsmasqError::State.into());
        }
        let before = values(options.get("server"))?;
        let desired: BTreeSet<_> = selection
            .into_iter()
            .flat_map(|(dns, rules)| {
                rules
                    .rules()
                    .iter()
                    .filter(|rule| rule.enabled)
                    .map(move |rule| {
                        format!(
                            "/{}/{ip}#{port}",
                            rule.pattern.domain,
                            ip = dns.ip(),
                            port = dns.port()
                        )
                    })
            })
            .collect();
        let foreign: Vec<_> = before
            .iter()
            .filter(|line| !self.ownership.managed.contains(*line))
            .cloned()
            .collect();
        if foreign.iter().any(|line| desired.contains(line)) {
            return Err(DnsmasqError::Conflict.into());
        }
        let mut merged = foreign.clone();
        merged.extend(desired.iter().cloned());
        let original = values(self.ownership.original.as_ref())?;
        let value = if desired.is_empty() && foreign == original {
            self.ownership.original.clone()
        } else if merged.is_empty() {
            None
        } else {
            Some(json!(merged))
        };
        if options.get("server") != value.as_ref() {
            let pending = self.ownership.managed.union(&desired).cloned().collect();
            self.ownership.managed = pending;
            self.ownership.pending = true;
            tokio::task::block_in_place(|| self.journal.save(&self.ownership))
                .map_err(DnsmasqError::from)?;
            self.apply(&current, value.as_ref()).await?;
        } else {
            self.reload(self.ownership.pending, false).await?;
        }
        self.ownership.managed = desired;
        self.ownership.pending = false;
        tokio::task::block_in_place(|| self.journal.save(&self.ownership))
            .map_err(DnsmasqError::from)?;
        Ok(())
    }

    async fn apply(&self, before: &Snapshot, value: Option<&Value>) -> Result<(), ServiceError> {
        no_pending_changes().await?;
        let staging = tokio::task::block_in_place(tempfile::tempdir)?;
        let staging_path = staging.path().to_str().ok_or(DnsmasqError::State)?;
        let key = format!("dhcp.{}.server", self.ownership.section);
        let invoke = |operation: &str, argument: String| {
            vec!["-t".into(), staging_path.into(), operation.into(), argument]
        };
        if before.values[&self.ownership.section]
            .get("server")
            .is_some()
            && !kernel::command("uci", &invoke("delete", key.clone()), None)
                .await?
                .success
        {
            return Err(DnsmasqError::Apply.into());
        }
        for line in values(value)? {
            let operation = if value.is_some_and(Value::is_string) {
                "set"
            } else {
                "add_list"
            };
            if !kernel::command("uci", &invoke(operation, format!("{key}={line}")), None)
                .await?
                .success
            {
                return Err(DnsmasqError::Apply.into());
            }
        }
        no_pending_changes().await?;
        if snapshot().await? != *before {
            return Err(DnsmasqError::ConcurrentChange.into());
        }
        if !kernel::command("uci", &invoke("commit", "dhcp".into()), None)
            .await?
            .success
        {
            return Err(DnsmasqError::Apply.into());
        }
        let after = snapshot().await?;
        let mut expected = before.values.clone();
        let object = expected
            .get_mut(&self.ownership.section)
            .and_then(Value::as_object_mut)
            .ok_or(DnsmasqError::State)?;
        match value {
            Some(value) => {
                object.insert("server".into(), value.clone());
            }
            None => {
                object.remove("server");
            }
        }
        if after.values != expected {
            return Err(DnsmasqError::ConcurrentChange.into());
        }
        self.reload(false, true).await
    }

    async fn reload(&self, force: bool, changed: bool) -> Result<(), ServiceError> {
        let old_pid = pid(&self.ownership.section).await?;
        if old_pid.is_none() && self.config.is_none() {
            return Ok(());
        }
        let operation = if force { "restart" } else { "reload" };
        if !kernel::command(
            "/etc/init.d/dnsmasq",
            &[operation.into(), self.ownership.section.clone()],
            None,
        )
        .await?
        .success
        {
            return Err(DnsmasqError::Apply.into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let current_pid = pid(&self.ownership.section).await?;
            if current_pid.is_some()
                && (!(force || changed) || current_pid != old_pid)
                && tokio::time::timeout(
                    Duration::from_millis(100),
                    tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, 53)),
                )
                .await
                .is_ok_and(|result| result.is_ok())
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(DnsmasqError::Apply.into())
    }
}

/// Recheck the supported profile at connection admission, including changes made outside LuCI.
pub(crate) async fn validate_frontend(
    config: &ServiceConfig,
    owned: &BTreeSet<String>,
    require_forwarding: bool,
) -> Result<(), ServiceError> {
    let current = snapshot().await?;
    let (section, options) =
        tokio::task::block_in_place(|| profile(&current, owned, &config.rules))?;
    if require_forwarding && !owned.is_subset(&values(options.get("server"))?.into_iter().collect())
    {
        return Err(DnsmasqError::State.into());
    }
    if pid(section).await?.is_none() {
        return Err(DnsmasqError::Profile.into());
    }
    if config.real_upstream.port() == 53 {
        let addresses = kernel::command(
            "ip",
            &[
                "-j".into(),
                if config.real_upstream.is_ipv4() {
                    "-4"
                } else {
                    "-6"
                }
                .into(),
                "addr".into(),
                "show".into(),
            ],
            None,
        )
        .await?;
        if !addresses.success {
            return Err(DnsmasqError::Profile.into());
        }
        let addresses: Value = serde_json::from_slice(&addresses.stdout)?;
        if config.real_upstream.ip().is_loopback()
            || addresses
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|interface| interface["addr_info"].as_array())
                .flatten()
                .any(|address| {
                    address["local"]
                        .as_str()
                        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                        .is_some_and(|value| value == config.real_upstream.ip())
                })
        {
            return Err(DnsmasqError::ResolverLoop.into());
        }
    }
    Ok(())
}

/// Validate without creating journals, changing UCI, or reloading the DNS frontend.
pub(crate) async fn check(config: &ServiceConfig) -> Result<(), ServiceError> {
    no_pending_changes().await?;
    let saved: Option<Ownership> = tokio::task::block_in_place(|| {
        integration_state::existing(&appended_path(&config.state_file, ".dnsmasq.json"))
    })
    .map_err(DnsmasqError::from)?;
    let owned = match saved {
        Some(saved) => {
            saved.validate()?;
            saved.managed
        }
        None => BTreeSet::new(),
    };
    validate_frontend(config, &owned, false).await
}

/// An upstream alias must not bypass a conditional or local rule in the frontend.
pub(crate) async fn validate_alias(
    config: &ServiceConfig,
    owned: &BTreeSet<String>,
    domain: &DomainName,
) -> Result<(), ServiceError> {
    let mut alias_config = config.clone();
    alias_config.rules = RuleSet::from_lines(
        domain.as_str(),
        std::num::NonZeroUsize::new(1).ok_or(DnsmasqError::State)?,
    )
    .map_err(|_| DnsmasqError::State)?;
    validate_frontend(&alias_config, owned, false).await
}

/// Preserve dnsmasq 2.93's additional rebind checks for documentation networks.
/// Other private and local IPv4 ranges are already rejected by `permits_real_target`.
pub(crate) async fn validate_target(
    query: &DomainName,
    address: impl Into<IpAddr>,
) -> Result<(), ServiceError> {
    // Native IPv6 ULA/link-local/mapped ranges are already rejected by the
    // service target policy; this additional dnsmasq rule concerns IPv4 docs.
    if !matches!(address.into(), IpAddr::V4(address) if address.is_documentation()) {
        return Ok(());
    }
    let current = snapshot().await?;
    let instances: Vec<_> = current
        .values
        .values()
        .filter(|value| value[".type"] == "dnsmasq")
        .collect();
    let [options] = instances.as_slice() else {
        return Err(DnsmasqError::Profile.into());
    };
    if options["rebind_protection"].as_str() == Some("0") {
        return Ok(());
    }
    for group in values(options.get("rebind_domain"))? {
        for value in group.trim_matches('/').split('/') {
            let name: DomainName = value.parse().map_err(|_| DnsmasqError::Unsupported)?;
            if query == &name || query.as_str().ends_with(&format!(".{name}")) {
                return Ok(());
            }
        }
    }
    Err(ServiceError::ForbiddenTarget)
}
