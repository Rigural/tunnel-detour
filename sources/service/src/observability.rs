use std::{
    fs,
    future::Future,
    io::{self, Write},
    path::Path,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::ServiceError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ConsentToken([u8; 16]);

impl ConsentToken {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u128::from_str_radix(value, 16)
            .ok()
            .map(|value| Self(value.to_be_bytes()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Consent {
    #[default]
    Off,
    On(Option<ConsentToken>),
}

impl Consent {
    pub(crate) fn from_flag(enabled: bool) -> Self {
        if enabled { Self::On(None) } else { Self::Off }
    }

    pub(crate) fn enabled(self) -> bool {
        matches!(self, Self::On(_))
    }

    pub(crate) fn epoch(self) -> Option<ConsentToken> {
        match self {
            Self::Off => None,
            Self::On(epoch) => epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AppliedConsent {
    pub consent: Consent,
    pub grant: Option<ConsentToken>,
}

impl AppliedConsent {
    pub(crate) fn for_json(consent: Consent) -> Self {
        Self {
            consent,
            grant: None,
        }
    }

    /// Invalidate the active period before checking the rest of a new configuration.
    pub(crate) fn invalidate_uci(self, inbound: bool, requested: Consent) -> Self {
        if !self.consent.enabled()
            || (self.consent == requested
                && self.grant.is_some()
                && read_uci_grant(inbound).is_ok_and(|grant| grant == self.grant))
        {
            self
        } else {
            Self::default()
        }
    }

    /// Open a period only for a successfully validated candidate whose consent
    /// still matches UCI and has a live grant. Only activation needs storage.
    pub(crate) async fn confirm_uci(inbound: bool, candidate: Consent) -> Self {
        if !candidate.enabled() {
            return Self::default();
        }
        if let Err(error) = prepare_uci_grant(inbound) {
            tracing::warn!(
                target: "tunnel_detour::health",
                code = error.code(),
                "traffic diagnostics consent could not be activated"
            );
            return Self::default();
        }
        let section = if inbound { "inbound" } else { "globals" };
        Self::confirm(candidate, || read_uci_grant(inbound), async {
            crate::uci::read_sections()
                .await
                .map_or(Consent::Off, |sections| sections.consent(section))
        })
        .await
    }

    async fn confirm(
        candidate: Consent,
        read_grant: impl Fn() -> Result<Option<ConsentToken>, ServiceError>,
        read_consent: impl Future<Output = Consent>,
    ) -> Self {
        let before = read_grant();
        let requested = read_consent.await;
        if let Ok(Some(grant)) = read_grant()
            && candidate == requested
            && before.is_ok_and(|value| value == Some(grant))
        {
            Self {
                consent: candidate,
                grant: Some(grant),
            }
        } else {
            Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test]
    async fn r153c_revocation_between_uci_reads_cannot_reuse_prior_consent() {
        let consent = Consent::On(None);
        let old_token = ConsentToken([11; 16]);
        let new_token = ConsentToken([17; 16]);
        let marker = Cell::new(Some(old_token));
        let observed = AppliedConsent::confirm(consent, || Ok(marker.get()), async {
            tokio::task::yield_now().await;
            marker.set(None);
            consent
        })
        .await;
        assert_eq!(observed, AppliedConsent::default());

        marker.set(Some(new_token));
        let reopened =
            AppliedConsent::confirm(consent, || Ok(marker.get()), async { consent }).await;
        assert_eq!(
            reopened,
            AppliedConsent {
                consent,
                grant: Some(new_token)
            }
        );
    }
}

/// Local logging consent for one daemon. Revocation waits for any current write.
#[derive(Clone, Default)]
pub struct ObservabilityLog(Arc<RwLock<bool>>);

impl ObservabilityLog {
    pub fn enabled(&self) -> bool {
        self.0.read().is_ok_and(|enabled| *enabled)
    }

    pub fn set_enabled(&self, enabled: bool) {
        if let Ok(mut current) = self.0.write() {
            *current = enabled;
        }
    }
}

impl Write for ObservabilityLog {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Ok(enabled) = self.0.read()
            && *enabled
        {
            return io::stderr().write(data);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn discard_snapshot(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn uci_status_path(inbound: bool) -> &'static Path {
    Path::new(if inbound {
        crate::inbound_uci::STATUS
    } else {
        crate::uci::STATUS_FILE
    })
}

fn grant_path(inbound: bool) -> std::path::PathBuf {
    uci_status_path(inbound).with_file_name("observability.grant")
}

/// Read the current grant without waiting for the daemon or an RPC reader.
pub(crate) fn read_uci_grant(inbound: bool) -> Result<Option<ConsentToken>, ServiceError> {
    tokio::task::block_in_place(|| {
        crate::management::read_private_bounded(&grant_path(inbound), 16)?
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(ConsentToken)
                    .map_err(|_| ServiceError::Protocol)
            })
            .transpose()
    })
}

pub(crate) fn revoke_uci_grant(inbound: bool) -> Result<(), ServiceError> {
    tokio::task::block_in_place(|| {
        use rustix::fs::{AtFlags, Mode, OFlags, fstat, open, unlinkat};
        use rustix::io::Errno;

        let path = grant_path(inbound);
        let parent = path.parent().ok_or(crate::ConfigError::Paths)?;
        let name = path.file_name().ok_or(crate::ConfigError::Paths)?;
        let directory = match open(
            parent,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(io::Error::from(error).into()),
        };
        let metadata = fstat(&directory).map_err(io::Error::from)?;
        if metadata.st_mode & 0o077 != 0 || metadata.st_uid != rustix::process::geteuid().as_raw() {
            return Err(tunnel_detour_core::StoreError::UnsafeFile.into());
        }
        match unlinkat(&directory, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(io::Error::from(error).into()),
        }
    })
}

/// Withdraw the grant before HUP when saved consent is off. Removing the grant
/// needs no new inode and survives a rollback of the UCI values.
pub async fn queue_uci_revocation(inbound: bool) -> Result<(), ServiceError> {
    let section = if inbound { "inbound" } else { "globals" };
    if crate::uci::read_sections()
        .await
        .is_ok_and(|sections| sections.consent(section).enabled())
    {
        return Ok(());
    }
    revoke_uci_grant(inbound)
}

fn prepare_uci_grant(inbound: bool) -> Result<(), ServiceError> {
    if read_uci_grant(inbound)?.is_some() {
        return Ok(());
    }
    tokio::task::block_in_place(|| {
        let marker = grant_path(inbound);
        crate::runtime::prepare_parent(&marker)?;
        let mut token = [0; 16];
        if rustix::rand::getrandom(&mut token, rustix::rand::GetRandomFlags::NONBLOCK)
            .map_err(io::Error::from)?
            != token.len()
        {
            return Err(ServiceError::Protocol);
        }
        let mut temporary =
            tempfile::NamedTempFile::new_in(marker.parent().ok_or(crate::ConfigError::Paths)?)?;
        temporary.write_all(&token)?;
        match temporary.persist_noclobber(marker) {
            Ok(_) => Ok(()),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error.error.into()),
        }
    })
}
