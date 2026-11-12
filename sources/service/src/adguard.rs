mod collections;
mod upstream;

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod response_tests;

use upstream::{ManagedUpstream, UpstreamPreview};

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tunnel_detour_core::{DomainName, RuleSet};

use crate::{
    ServiceConfig, ServiceError,
    config::AdguardSettings,
    integration_state::{self, IntegrationStateError, PrivateJournal, appended_path},
    kernel,
};

#[derive(Debug, Error)]
pub enum AdguardError {
    #[error(transparent)]
    Ownership(#[from] IntegrationStateError),
    #[error("AdGuard control request failed")]
    Request(#[from] reqwest::Error),
    #[error("AdGuard control request returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("AdGuard response or ownership state is invalid JSON")]
    Json(#[from] serde_json::Error),
    #[error("AdGuard response is not UTF-8 JSON")]
    Encoding(#[from] std::str::Utf8Error),
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
    #[error("AdGuard disables IPv6 resolution; IPv6 exceptions cannot bypass that setting")]
    Ipv6Disabled,
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
    #[error("the selected AdGuard DNS frontend is stopped")]
    DnsStopped,
    #[error("general upstream management requires a fresh approved preview")]
    UpstreamApproval,
    #[error(
        "general upstream adoption requires explicit IPv4 or IPv6 plaintext resolvers; encrypted, implicit, or file-based defaults are not converted"
    )]
    UnsupportedGeneralUpstreams,
}

const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parser(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if bytes.len() > RESPONSE_LIMIT {
        return Ok(());
    }
    integration_state::fuzz_roundtrip(bytes, Ownership::validate)?;
    // A typed API reply must also be a complete JSON document, not merely
    // a deserializable prefix. These checks never perform API or file I/O.
    if AdguardControl::decode::<ServerStatus>("status", bytes).is_ok()
        || AdguardControl::decode::<DnsInfo>("dns_info", bytes).is_ok()
        || AdguardControl::decode::<Clients>("clients", bytes).is_ok()
        || AdguardControl::decode::<ClientSearch>("clients/search", bytes).is_ok()
    {
        let text = std::str::from_utf8(bytes)?;
        // Validate a whole JSON text without imposing Value's f64/String model
        // on unused future fields (for example a valid, very large number).
        let _: serde::de::IgnoredAny = serde_json::from_str(text)?;
    }
    Ok(())
}

fn approved_preview(
    state: &std::path::Path,
    control: &AdguardSettings,
    receipt: Option<&str>,
) -> Result<Option<UpstreamPreview>, AdguardError> {
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let preview: Option<UpstreamPreview> =
        integration_state::existing(&appended_path(state, ".adguard-preview.json"))
            .map_err(AdguardError::from)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AdguardError::State)?
        .as_secs();
    Ok(preview.filter(|preview| {
        preview.receipt == receipt
            && &preview.control == control
            && preview.expires_at >= now
            && now
                .checked_add(600)
                .is_some_and(|limit| preview.expires_at <= limit)
    }))
}

/// Prepare an explicit, short-lived adoption preview without changing AdGuard.
/// Only the local administrator's separately saved receipt can authorize adoption.
pub async fn preview_adguard_upstream(
    config: &ServiceConfig,
    import_current: bool,
) -> Result<serde_json::Value, ServiceError> {
    let settings = config.adguard.clone().ok_or(AdguardError::State)?;
    let control = AdguardControl::new(settings.clone())?;
    let current: DnsInfo = control.get("dns_info").await?;
    current.validate_managed()?;
    upstream::validate_general(&upstream::general(&current.upstream_dns))?;
    let resolver = if import_current {
        upstream::import(&current.upstream_dns)?
    } else {
        config.real_upstream
    };
    config.validate_resolver_endpoint(resolver)?;
    let mut proposed = config.clone();
    proposed.real_upstream = resolver;
    let path = crate::upstream_route::ResolverPath::prepare(&proposed).await?;
    kernel::Kernel::check_resolver_transition(&path).await?;
    AdguardManager::validate_resolver(&control, resolver).await?;
    let mut bytes = [0_u8; 16];
    let mut initialized = 0;
    // Nonblocking entropy and a finite retry count keep administrative requests bounded.
    for _ in 0..32 {
        if initialized == bytes.len() {
            break;
        }
        match rustix::rand::getrandom(
            &mut bytes[initialized..],
            rustix::rand::GetRandomFlags::NONBLOCK,
        ) {
            Ok(0) => return Err(AdguardError::State.into()),
            Ok(length) => initialized += length,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(AdguardError::Io(error.into()).into()),
        }
    }
    if initialized != bytes.len() {
        return Err(AdguardError::State.into());
    }
    let receipt: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let preview = UpstreamPreview {
        receipt: receipt.clone(),
        snapshot: current.clone(),
        resolver,
        control: settings,
        expires_at: crate::runtime::now()?
            .unix_seconds()
            .checked_add(600)
            .ok_or(ServiceError::Clock)?,
    };
    let path = appended_path(&config.state_file, ".adguard-preview.json");
    tokio::task::block_in_place(|| {
        crate::runtime::prepare_parent(&path)?;
        integration_state::atomic_write(&path, &preview).map_err(AdguardError::from)?;
        Ok::<_, ServiceError>(())
    })?;
    Ok(
        serde_json::json!({"receipt":receipt,"resolver":resolver,"transport":"tcp",
        "current_general":upstream::general(&current.upstream_dns),
        "proposed_general":[format!("tcp://{resolver}")],"bootstrap_preserved":current.bootstrap_dns,
        "expires_in_seconds":600,"single_editor_required":true}),
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u8,
    managed: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control: Option<AdguardSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream: Option<ManagedUpstream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_upstream_approval: Option<String>,
}

impl Ownership {
    fn validate(&self) -> Result<(), AdguardError> {
        if !matches!(self.version, 1..=3)
            || (self.version >= 2 && self.control.is_none())
            || (self.version < 3
                && (self.upstream.is_some() || self.last_upstream_approval.is_some()))
            || self.managed.len() > 4096
            || self.managed.iter().any(|line| !valid_owned_line(line))
        {
            return Err(AdguardError::State);
        }
        if let Some(upstream) = &self.upstream {
            upstream.validate()?;
            if self.last_upstream_approval.as_deref() != Some(upstream.last_approval()) {
                return Err(AdguardError::State);
            }
        }
        if let Some(receipt) = &self.last_upstream_approval {
            upstream::validate_receipt(receipt)?;
        }
        Ok(())
    }
}

pub(crate) struct AdguardRecovery {
    pub settings: Option<AdguardSettings>,
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
struct DnsInfo {
    #[serde(deserialize_with = "collections::upstreams")]
    upstream_dns: Vec<String>,
    #[serde(default)]
    upstream_dns_file: String,
    #[serde(default, deserialize_with = "collections::optional_auxiliary")]
    fallback_dns: Option<Vec<String>>,
    #[serde(default, deserialize_with = "collections::optional_auxiliary")]
    bootstrap_dns: Option<Vec<String>>,
}

impl DnsInfo {
    fn validate_managed(&self) -> Result<(), AdguardError> {
        if !self.upstream_dns_file.is_empty()
            || self
                .fallback_dns
                .as_ref()
                .is_none_or(|values| !values.is_empty())
            || self.bootstrap_dns.is_none()
        {
            return Err(AdguardError::UnsupportedUpstreams);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ServerStatus {
    running: bool,
    #[serde(deserialize_with = "collections::bindings")]
    dns_addresses: Vec<String>,
    dns_port: u16,
    protection_enabled: bool,
}

#[derive(Deserialize)]
struct ClientPolicy {
    name: String,
    #[serde(deserialize_with = "collections::client_ids")]
    ids: Vec<String>,
    use_global_settings: bool,
    filtering_enabled: bool,
}

#[derive(Deserialize)]
struct Clients {
    #[serde(default, deserialize_with = "collections::optional_clients")]
    clients: Option<Vec<ClientPolicy>>,
}

#[derive(Deserialize)]
struct ClientMatch {
    name: String,
    #[serde(deserialize_with = "collections::client_ids")]
    ids: Vec<String>,
    disallowed: bool,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct ClientSearch(#[serde(deserialize_with = "collections::search_results")] Vec<SearchEntry>);

#[derive(Deserialize)]
#[serde(transparent)]
struct SearchEntry(
    #[serde(deserialize_with = "collections::search_entry")]
    std::collections::BTreeMap<String, ClientMatch>,
);

#[derive(Serialize)]
pub(crate) struct AdguardHealth {
    dns_running: bool,
    protection_enabled: bool,
}

pub(crate) struct AdguardManager {
    real_upstream: Option<SocketAddr>,
    control: AdguardControl,
    journal: PrivateJournal,
    owned: BTreeSet<String>,
    legacy: bool,
    managed_upstream: Option<ManagedUpstream>,
    desired_upstream: Option<SocketAddr>,
    approval: Option<String>,
    state_file: std::path::PathBuf,
    last_upstream_approval: Option<String>,
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
    pub(crate) fn resolver_settings(&mut self, config: &ServiceConfig) {
        self.real_upstream = Some(config.real_upstream);
        self.desired_upstream = config
            .manage_adguard_upstream
            .then_some(config.real_upstream);
        self.approval.clone_from(&config.adguard_upstream_approval);
    }

    /// Check the selected endpoint and foreign forwarding before changing integrations.
    pub(crate) async fn check(config: &ServiceConfig) -> Result<(), ServiceError> {
        let settings = config.adguard.clone().ok_or(AdguardError::State)?;
        let control = AdguardControl::new(settings.clone())?;
        let saved: Option<Ownership> = tokio::task::block_in_place(|| {
            integration_state::existing(&appended_path(&config.state_file, ".adguard.json"))
        })
        .map_err(AdguardError::from)?;
        let saved = match saved {
            Some(saved) => {
                saved.validate()?;
                if saved
                    .control
                    .as_ref()
                    .is_none_or(|value| value == &settings)
                {
                    Some(saved)
                } else {
                    None
                }
            }
            None => None,
        };
        let owned = saved.as_ref().map(|saved| &saved.managed);
        let current: DnsInfo = control.get("dns_info").await?;
        if config.ipv6.is_some() {
            control.require_ipv6_enabled().await?;
        }
        if !current.upstream_dns_file.is_empty()
            || current
                .fallback_dns
                .as_ref()
                .is_some_and(|values| !values.is_empty())
        {
            return Err(AdguardError::UnsupportedUpstreams.into());
        }
        let foreign: Vec<_> = current
            .upstream_dns
            .iter()
            .filter(|line| !owned.is_some_and(|owned| owned.contains(*line)))
            .cloned()
            .collect();
        check_conflicts(&foreign, &config.rules)?;
        if config.manage_adguard_upstream
            || saved.as_ref().is_some_and(|state| state.upstream.is_some())
        {
            let mut preview = approved_preview(
                &config.state_file,
                &settings,
                config.adguard_upstream_approval.as_deref(),
            )?;
            if saved.as_ref().is_some_and(|saved| {
                saved.upstream.is_none()
                    && saved.last_upstream_approval.as_deref()
                        == config.adguard_upstream_approval.as_deref()
            }) {
                preview = None;
            }
            upstream::plan(
                &current,
                config
                    .manage_adguard_upstream
                    .then_some(config.real_upstream),
                saved.as_ref().and_then(|saved| saved.upstream.as_ref()),
                preview.as_ref(),
            )?;
        }
        if !control.probe().await?.dns_running {
            return Err(AdguardError::DnsStopped.into());
        }
        Self::validate_resolver(&control, config.real_upstream).await?;
        Ok(())
    }

    /// Recover the previous endpoint even after UCI selects a different frontend.
    pub(crate) fn recovery(
        state_file: &std::path::Path,
    ) -> Result<Option<AdguardRecovery>, ServiceError> {
        let saved: Option<Ownership> =
            integration_state::existing(&appended_path(state_file, ".adguard.json"))
                .map_err(AdguardError::from)?;
        let Some(saved) = saved else {
            return Ok(None);
        };
        saved.validate()?;
        Ok(
            (!saved.managed.is_empty() || saved.upstream.is_some()).then_some(AdguardRecovery {
                settings: saved.control,
            }),
        )
    }

    pub fn new(config: Arc<ServiceConfig>) -> Result<Option<Self>, ServiceError> {
        let Some(settings) = config.adguard.clone() else {
            return Ok(None);
        };
        let mut manager = Self::open(settings, &config.state_file, Some(config.real_upstream))?;
        manager.desired_upstream = config
            .manage_adguard_upstream
            .then_some(config.real_upstream);
        manager
            .approval
            .clone_from(&config.adguard_upstream_approval);
        Ok(Some(manager))
    }

    pub(crate) fn open(
        settings: AdguardSettings,
        state_file: &std::path::Path,
        real_upstream: Option<SocketAddr>,
    ) -> Result<Self, ServiceError> {
        let control = AdguardControl::new(settings)?;
        let journal = PrivateJournal::open(appended_path(state_file, ".adguard.json"))
            .map_err(AdguardError::from)?;
        let ownership = journal
            .load(Ownership {
                version: 3,
                managed: BTreeSet::new(),
                control: Some(control.settings.clone()),
                upstream: None,
                last_upstream_approval: None,
            })
            .map_err(AdguardError::from)?;
        ownership.validate()?;
        if (!ownership.managed.is_empty() || ownership.upstream.is_some())
            && ownership
                .control
                .as_ref()
                .is_some_and(|saved| saved != &control.settings)
        {
            return Err(AdguardError::State.into());
        }
        let initialize = ownership.managed.is_empty() && ownership.upstream.is_none();
        let manager = Self {
            real_upstream,
            control,
            journal,
            owned: ownership.managed,
            legacy: ownership.version == 1,
            managed_upstream: ownership.upstream,
            desired_upstream: None,
            approval: None,
            state_file: state_file.to_path_buf(),
            last_upstream_approval: ownership.last_upstream_approval,
        };
        if initialize {
            manager.save_ownership(manager.owned.clone(), None)?;
        }
        Ok(manager)
    }

    fn save_ownership(
        &self,
        managed: BTreeSet<String>,
        upstream: Option<ManagedUpstream>,
    ) -> Result<(), AdguardError> {
        let last_upstream_approval = upstream
            .as_ref()
            .map(|state| state.last_approval().to_owned())
            .or_else(|| self.last_upstream_approval.clone());
        self.journal.save(&Ownership {
            version: 3,
            managed,
            control: Some(self.control.settings.clone()),
            upstream,
            last_upstream_approval,
        })?;
        Ok(())
    }
}

impl AdguardControl {
    /// Verify access to the local AdGuard API without changing DNS, filtering, or ownership state.
    pub(crate) async fn probe(&self) -> Result<AdguardHealth, AdguardError> {
        let status: ServerStatus = self.get("status").await?;
        Ok(AdguardHealth {
            dns_running: status.running,
            protection_enabled: status.protection_enabled,
        })
    }

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
        // A slice deserializer can skip invalid UTF-8 inside ignored fields.
        // Validate the complete text without allocating another response copy.
        let text = std::str::from_utf8(bytes)?;
        let mut deserializer = serde_json::Deserializer::from_str(text);
        let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
            AdguardError::Response {
                operation,
                field: error.path().to_string(),
                source: error.into_inner(),
            }
        })?;
        // A typed value may consume only a prefix. API replies are single JSON
        // documents; reject any remaining bytes except JSON whitespace.
        deserializer.end()?;
        Ok(value)
    }

    pub(crate) async fn require_ipv6_enabled(&self) -> Result<(), ServiceError> {
        #[derive(Deserialize)]
        struct Ipv6Policy {
            disable_ipv6: bool,
        }
        let policy: Ipv6Policy = self.get("dns_info").await?;
        if policy.disable_ipv6 {
            return Err(AdguardError::Ipv6Disabled.into());
        }
        Ok(())
    }

    pub(crate) async fn filtering_enabled(&self, client: IpAddr) -> Result<bool, ServiceError> {
        #[derive(Deserialize)]
        struct FilteringStatus {
            enabled: bool,
        }
        // Independent, read-only policy inputs share the existing API semaphore.
        // Serial HTTP authentication must not consume the whole DNS deadline.
        let search = async {
            let request = self
                .request(Method::POST, "clients/search")?
                .json(&serde_json::json!({"clients": [{"id": client.to_string()}]}));
            let bytes = self.bytes(request).await?;
            Self::decode("clients/search", &bytes)
        };
        let (status, filtering, persistent, clients): (
            ServerStatus,
            FilteringStatus,
            Clients,
            ClientSearch,
        ) = tokio::try_join!(
            self.get("status"),
            self.get("filtering/status"),
            self.get("clients"),
            search,
        )?;
        let mut enabled = filtering.enabled;
        for entry in clients.0 {
            if let Some(policy) = entry.0.get(&client.to_string()) {
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
        client: IpAddr,
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
        if selection.is_none() && self.owned.is_empty() && self.managed_upstream.is_none() {
            return Ok(());
        }
        let mut desired = BTreeSet::new();
        if let Some((dns, rules)) = selection {
            for rule in rules.rules().iter().filter(|rule| rule.enabled) {
                desired.insert(format!("[/{}/]{dns}", rule.pattern.domain));
            }
        }
        let current: DnsInfo = self.control.get("dns_info").await?;
        if self.legacy
            && self
                .owned
                .iter()
                .any(|line| !current.upstream_dns.contains(line))
        {
            return Err(AdguardError::State);
        }
        self.legacy = false;
        if !desired.is_empty() || (selection.is_some() && self.desired_upstream.is_some()) {
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
        let mut preview = if selection.is_some() && self.desired_upstream.is_some() {
            approved_preview(
                &self.state_file,
                &self.control.settings,
                self.approval.as_deref(),
            )?
        } else {
            None
        };
        if self.managed_upstream.is_none() && self.last_upstream_approval == self.approval {
            preview = None;
        }
        let upstream_plan = upstream::plan(
            &current,
            selection.and(self.desired_upstream),
            self.managed_upstream.as_ref(),
            preview.as_ref(),
        )?;
        let foreign: Vec<_> = upstream_plan
            .lines
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
        // Never write a list that our own bounded reader cannot recover. Keep
        // the same limit on both sides of the API before journaling a mutation.
        if merged.len() > collections::UPSTREAMS {
            return Err(AdguardError::TooLarge);
        }
        if current.upstream_dns != merged {
            // Journal the union before any remote write. A timeout cannot lose ownership of a
            // change that the remote endpoint may already have applied.
            let body = serde_json::to_vec(&serde_json::json!({"upstream_dns":merged}))?;
            if body.len() > RESPONSE_LIMIT {
                return Err(AdguardError::TooLarge);
            }
            let pending: BTreeSet<_> = self.owned.union(&desired).cloned().collect();
            tokio::task::block_in_place(|| {
                self.save_ownership(pending.clone(), upstream_plan.before.clone())
            })?;
            self.owned = pending;
            self.managed_upstream = upstream_plan.before.clone();
            if let Some(state) = &self.managed_upstream {
                self.last_upstream_approval = Some(state.last_approval().to_owned());
            }
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
                || after.bootstrap_dns != current.bootstrap_dns
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
        tokio::task::block_in_place(|| {
            self.save_ownership(desired.clone(), upstream_plan.after.clone())
        })?;
        self.owned = desired;
        if let Some(state) = &upstream_plan.before {
            self.last_upstream_approval = Some(state.last_approval().to_owned());
        }
        self.managed_upstream = upstream_plan.after;
        if upstream_plan.foreign_change_preserved {
            tracing::warn!(
                "general upstream management released without restoring a setting changed by another editor"
            );
        }
        Ok(())
    }

    async fn check_resolver_loop(&self) -> Result<(), AdguardError> {
        let upstream = self.real_upstream.ok_or(AdguardError::ResolverLoop)?;
        Self::validate_resolver(&self.control, upstream).await
    }

    async fn validate_resolver(
        control: &AdguardControl,
        upstream: SocketAddr,
    ) -> Result<(), AdguardError> {
        let status: ServerStatus = control.get("status").await?;
        if upstream.port() != status.dns_port {
            return Ok(());
        }
        let real = upstream.ip();
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
            if let Some((ip, port)) = binding
                && port == upstream.port()
            {
                if ip == real {
                    return Err(AdguardError::ResolverLoop);
                }
                // An IPv6 wildcard can include IPv4 on a dual-stack socket.
                wildcard |= ip.is_unspecified() && (ip.is_ipv6() || real.is_ipv4());
            }
        }
        if wildcard {
            if real.is_loopback() {
                return Err(AdguardError::ResolverLoop);
            }
            let output = kernel::command(
                "ip",
                &[
                    "-j".into(),
                    if real.is_ipv4() { "-4" } else { "-6" }.into(),
                    "addr".into(),
                    "show".into(),
                ],
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
                local: IpAddr,
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
