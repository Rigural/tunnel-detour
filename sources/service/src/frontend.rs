//! Select one DNS frontend and finish previous ownership before activating its replacement.

use std::{path::Path, sync::Arc};

use tunnel_detour_core::RuleSet;

use crate::{
    ServiceConfig, ServiceError,
    adguard::{AdguardError, AdguardManager},
    config::{AdguardSettings, DnsIntegration},
    dnsmasq::DnsmasqManager,
    uci,
};

pub(crate) enum FrontendManager {
    External,
    Adguard(Box<AdguardManager>),
    Dnsmasq(DnsmasqManager),
}

async fn previous_adguard(
    state: &Path,
    selected: Option<&AdguardSettings>,
) -> Result<(), ServiceError> {
    let state_path = state.to_path_buf();
    let recovery =
        tokio::task::spawn_blocking(move || AdguardManager::recovery(&state_path)).await??;
    if let Some(recovery) = recovery {
        // A legacy journal has no saved endpoint. UCI is used only for this explicit
        // recovery, never to activate an unselected integration or choose a fallback.
        if selected.is_some()
            && recovery
                .settings
                .as_ref()
                .is_none_or(|settings| Some(settings) == selected)
        {
            return Ok(());
        }
        let settings = match recovery.settings {
            Some(settings) => settings,
            None => uci::cleanup_settings().await?,
        };
        let state_path = state.to_path_buf();
        let mut previous =
            tokio::task::spawn_blocking(move || AdguardManager::open(settings, &state_path, None))
                .await??;
        previous.reconcile(None).await?;
    }
    Ok(())
}

async fn previous_dnsmasq(state: &Path) -> Result<(), ServiceError> {
    let state_path = state.to_path_buf();
    let owned =
        tokio::task::spawn_blocking(move || DnsmasqManager::has_owned(&state_path)).await??;
    if owned {
        let state_path = state.to_path_buf();
        let mut previous =
            tokio::task::spawn_blocking(move || DnsmasqManager::recovery(&state_path)).await??;
        previous.reconcile(None).await?;
    }
    Ok(())
}

impl FrontendManager {
    pub(crate) fn resolver_settings(&mut self, config: Arc<ServiceConfig>) {
        match self {
            Self::External => {}
            Self::Adguard(manager) => manager.resolver_settings(&config),
            Self::Dnsmasq(manager) => manager.resolver_settings(config),
        }
    }

    pub(crate) async fn new(config: Arc<ServiceConfig>) -> Result<Self, ServiceError> {
        check(&config).await?;
        previous_adguard(&config.state_file, config.adguard.as_ref()).await?;
        if config.dns_integration != DnsIntegration::Dnsmasq {
            previous_dnsmasq(&config.state_file).await?;
        }
        match config.dns_integration {
            DnsIntegration::Adguard => {
                let manager = tokio::task::spawn_blocking(move || AdguardManager::new(config))
                    .await??
                    .ok_or(AdguardError::State)?;
                Ok(Self::Adguard(Box::new(manager)))
            }
            DnsIntegration::Dnsmasq => Ok(Self::Dnsmasq(DnsmasqManager::open(config).await?)),
            DnsIntegration::External => Ok(Self::External),
        }
    }

    pub(crate) async fn reconcile(
        &mut self,
        selection: Option<(std::net::SocketAddrV4, &RuleSet)>,
    ) -> Result<(), ServiceError> {
        match self {
            Self::External => Ok(()),
            Self::Adguard(manager) => Ok(manager.reconcile(selection).await?),
            Self::Dnsmasq(manager) => manager.reconcile(selection).await,
        }
    }
}

/// Preflight the selected integration without modifying either DNS frontend.
pub(crate) async fn check(config: &ServiceConfig) -> Result<(), ServiceError> {
    match config.dns_integration {
        DnsIntegration::Adguard => AdguardManager::check(config).await,
        DnsIntegration::Dnsmasq => crate::dnsmasq::check(config).await,
        DnsIntegration::External => Ok(()),
    }
}

/// Cleanup uses saved ownership, even when the currently selected mode has no AdGuard fields.
pub(crate) async fn cleanup_all(state: &Path) -> Result<(), ServiceError> {
    previous_adguard(state, None).await?;
    previous_dnsmasq(state).await
}
