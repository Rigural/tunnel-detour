//! Private AdGuard credentials. Administrative reads expose only their presence.

use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ServiceError, UciError,
    config::AdguardSettings,
    integration_state::{self, IntegrationStateError, PrivateJournal},
    kernel, uci,
};

pub(crate) const PATH: &str = "/etc/tunnel-detour/adguard-credentials.json";

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parser(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    integration_state::fuzz_roundtrip(bytes, Stored::validate)
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    fn validate(&self) -> Result<(), ServiceError> {
        self.settings("http://127.0.0.1".into()).endpoint()?;
        Ok(())
    }

    fn settings(&self, api_url: String) -> AdguardSettings {
        let authenticated = !self.username.is_empty() || !self.password.is_empty();
        AdguardSettings {
            api_url,
            username: authenticated.then(|| self.username.clone()),
            password: authenticated.then(|| self.password.clone()),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Version {
    revision: Option<String>,
    value: Credentials,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    // An unavailable applied version is distinct from explicit anonymous auth.
    current: Option<Version>,
    pending: Option<Version>,
}

impl Default for Stored {
    fn default() -> Self {
        Self {
            current: Some(Version::default()),
            pending: None,
        }
    }
}

impl Stored {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.pending.as_ref().is_some_and(|version| {
            version.revision.is_none()
                || self
                    .current
                    .as_ref()
                    .is_some_and(|current| version.revision == current.revision)
        }) {
            return Err(UciError::Credentials.into());
        }
        for version in self.current.iter().chain(self.pending.iter()) {
            version.value.validate()?;
            if version.revision.as_ref().is_some_and(|revision| {
                revision.len() != 32 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                return Err(UciError::Credentials.into());
            }
        }
        Ok(())
    }
    fn selected(&self, revision: Option<&str>) -> Result<&Version, ServiceError> {
        self.current
            .iter()
            .chain(self.pending.iter())
            .find(|value| value.revision.as_deref() == revision)
            .ok_or(UciError::Credentials.into())
    }
}

fn prepare(path: &Path) -> Result<(), ServiceError> {
    let directory = path.parent().ok_or(UciError::Options)?;
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == rustix::process::geteuid().as_raw() => {}
        Ok(_) => return Err(UciError::Options.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read(path: &Path) -> Result<Stored, ServiceError> {
    let directory = path.parent().ok_or(UciError::Options)?;
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == rustix::process::geteuid().as_raw() => {}
        Ok(_) => return Err(UciError::Options.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(UciError::Options.into());
    }
    let value = integration_state::existing::<Stored>(path)
        .map_err(ServiceError::CredentialStorage)?
        .unwrap_or_default();
    value.validate()?;
    Ok(value)
}

fn journal(path: &Path) -> Result<PrivateJournal, ServiceError> {
    prepare(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(UciError::Options.into());
    }
    PrivateJournal::open(path.to_path_buf()).map_err(ServiceError::CredentialStorage)
}

fn save(path: &Path, value: &Stored) -> Result<(), ServiceError> {
    value.validate()?;
    let journal = journal(path)?;
    let _: Stored = journal
        .load(Stored::default())
        .map_err(ServiceError::CredentialStorage)?;
    journal.save(value).map_err(ServiceError::CredentialStorage)
}

pub(crate) fn configured(revision: Option<&str>) -> Result<bool, ServiceError> {
    Ok(!read(Path::new(PATH))?
        .selected(revision)?
        .value
        .username
        .is_empty())
}

pub(crate) fn settings(
    api_url: String,
    revision: Option<&str>,
) -> Result<AdguardSettings, ServiceError> {
    Ok(read(Path::new(PATH))?
        .selected(revision)?
        .value
        .settings(api_url))
}

fn stage(
    path: &Path,
    applied: Option<&str>,
    value: Credentials,
    revision: String,
) -> Result<(), ServiceError> {
    value.validate()?;
    let journal = journal(path)?;
    let stored: Stored = match journal.load(Stored::default()) {
        Ok(stored) => stored,
        Err(IntegrationStateError::Unsafe) => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Only this explicit replacement may repair missing credentials.
                // Hold the validated journal lock and retain no invented applied
                // value. Ordinary reads and every old revision still fail closed
                // until UCI selects the new pending version.
                Stored {
                    current: None,
                    pending: None,
                }
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(ServiceError::CredentialStorage(
                    IntegrationStateError::Unsafe,
                ));
            }
        },
        Err(error) => return Err(ServiceError::CredentialStorage(error)),
    };
    stored.validate()?;
    if applied == Some(revision.as_str())
        || stored
            .current
            .iter()
            .chain(stored.pending.iter())
            .any(|version| version.revision.as_ref() == Some(&revision))
    {
        return Err(UciError::Credentials.into());
    }
    let current = match stored.selected(applied) {
        Ok(current) => Some(current.clone()),
        // Only an explicit replacement repairs a lost UCI reference. Ordinary
        // reads continue refusing it until the new revision is applied.
        Err(ServiceError::Uci(UciError::Credentials)) => stored.current.clone(),
        Err(error) => return Err(error),
    };
    let next = Stored {
        current,
        pending: Some(Version {
            revision: Some(revision),
            value,
        }),
    };
    next.validate()?;
    journal.save(&next).map_err(ServiceError::CredentialStorage)
}

/// Stage a write-only replacement. Only the nonsecret UCI revision selects it;
/// discarding the UCI draft retains the applied credentials. One draft is bounded.
pub(crate) fn replace(
    username: String,
    password: String,
    applied: Option<&str>,
) -> Result<String, ServiceError> {
    let mut random = [0; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let revision: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    stage(
        Path::new(PATH),
        applied,
        Credentials { username, password },
        revision.clone(),
    )?;
    Ok(revision)
}

/// Move legacy UCI credentials into private storage before starting or registering rpcd.
/// A retry preserves the private copy if the UCI commit was interrupted.
pub async fn migrate_adguard_credentials() -> Result<(), ServiceError> {
    let sections = uci::read_sections().await?;
    let globals = sections.values.get("globals").ok_or(UciError::Sections)?;
    let field = |name: &str| -> Result<String, ServiceError> {
        match globals.options.get(name) {
            None => Ok(String::new()),
            Some(value) => value
                .as_str()
                .map(str::to_owned)
                .ok_or(UciError::Options.into()),
        }
    };
    let legacy = Credentials {
        username: field("adguard_username")?,
        password: field("adguard_password")?,
    };
    legacy.validate()?;
    if !["adguard_username", "adguard_password"]
        .iter()
        .any(|name| globals.options.contains_key(*name))
    {
        return Ok(());
    }
    let changes = kernel::command("uci", &["changes".into(), "tunnel-detour".into()], None).await?;
    if !changes.success || !changes.stdout.is_empty() {
        return Err(UciError::Options.into());
    }
    if !legacy.username.is_empty() {
        let mut current = read(Path::new(PATH))?;
        let version = current.current.get_or_insert_with(Version::default);
        if !version.value.username.is_empty() && version.value != legacy {
            return Err(UciError::Options.into());
        }
        version.value = legacy;
        save(Path::new(PATH), &current)?;
    }
    uci::ubus(
        "uci", "delete",
        json!({"config":"tunnel-detour","section":"globals","options":["adguard_username","adguard_password"]}),
    ).await?;
    uci::ubus("uci", "commit", json!({"config":"tunnel-detour"})).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn r130_private_credentials_validate_permissions_and_reject_unsafe_storage()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("private/credentials.json");
        let value = Credentials {
            username: "lab-admin".into(),
            password: "synthetic-password".into(),
        };
        save(
            &path,
            &Stored {
                current: Some(Version {
                    revision: None,
                    value: value.clone(),
                }),
                pending: None,
            },
        )?;
        assert!(read(&path)?.selected(None)?.value == value);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        let alias = root.path().join("credentials-alias");
        fs::hard_link(&path, &alias)?;
        assert!(
            read(&path).is_err(),
            "aliased secret storage must be refused"
        );
        assert!(stage(&path, None, value.clone(), "a".repeat(32)).is_err());
        fs::remove_file(&alias)?;
        let directory = path.parent().ok_or("missing credential directory")?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
        assert!(
            read(&path).is_err(),
            "reads must verify the private directory too"
        );
        assert!(stage(&path, None, value.clone(), "a".repeat(32)).is_err());
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(read(&path).is_err());
        assert!(stage(&path, None, value.clone(), "a".repeat(32)).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, b"corrupt")?;
        assert!(stage(&path, None, value.clone(), "a".repeat(32)).is_err());
        assert_eq!(
            fs::read(&path)?,
            b"corrupt",
            "repair overwrote existing corrupt state"
        );
        fs::remove_file(&path)?;
        let target = root.path().join("foreign");
        fs::write(&target, b"{}")?;
        symlink(&target, &path)?;
        assert!(read(&path).is_err());
        assert!(stage(&path, None, value, "a".repeat(32)).is_err());
        assert_eq!(fs::read(target)?, b"{}");
        Ok(())
    }

    #[test]
    fn r136_credential_drafts_preserve_applied_values_until_the_uci_revision_selects_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("private/credentials.json");
        let original = Credentials {
            username: "lab-admin".into(),
            password: "original-synthetic".into(),
        };
        // The existing on-disk schema stores the version as a plain object.
        prepare(&path)?;
        fs::write(&path, br#"{"current":{"revision":null,"value":{"username":"lab-admin","password":"original-synthetic"}},"pending":null}"#)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(read(&path)?.selected(None)?.value == original);
        let first = "1".repeat(32);
        let second = "2".repeat(32);
        let third = "3".repeat(32);
        let replacement = Credentials {
            username: "replacement".into(),
            password: "draft-synthetic".into(),
        };
        stage(&path, None, replacement.clone(), first.clone())?;
        assert!(
            read(&path)?.selected(None)?.value == original,
            "saving a draft changed applied credentials"
        );
        assert!(read(&path)?.selected(Some(&first))?.value == replacement);
        stage(&path, None, Credentials::default(), second.clone())?;
        assert!(
            read(&path)?.selected(None)?.value == original,
            "discarded draft changed the applied values"
        );
        assert!(
            read(&path)?.selected(Some(&first)).is_err(),
            "a superseded draft must fail closed"
        );
        assert!(read(&path)?.selected(Some(&second))?.value == Credentials::default());
        stage(&path, Some(&second), replacement, third.clone())?;
        assert!(
            read(&path)?.selected(Some(&second))?.value == Credentials::default(),
            "staging after apply lost the committed anonymous configuration"
        );
        assert!(read(&path)?.selected(Some(&third)).is_ok());
        assert!(read(&path)?.selected(Some("unknown")).is_err());
        let fourth = "4".repeat(32);
        stage(&path, Some("unknown"), original.clone(), fourth.clone())?;
        assert!(
            read(&path)?.selected(Some("unknown")).is_err(),
            "repair must not authorize a missing reference before apply"
        );
        assert!(
            read(&path)?.selected(Some(&fourth)).is_ok(),
            "explicit replacement must repair the missing reference"
        );
        let lost = root.path().join("private/lost-credentials.json");
        save(
            &lost,
            &Stored {
                current: Some(Version {
                    revision: None,
                    value: original.clone(),
                }),
                pending: None,
            },
        )?;
        fs::remove_file(&lost)?;
        assert!(
            read(&lost).is_err(),
            "missing secret state must not become anonymous"
        );
        assert!(
            stage(&lost, Some(&fourth), original.clone(), fourth.clone()).is_err(),
            "repair reused the already selected revision before apply"
        );
        let fifth = "5".repeat(32);
        stage(&lost, None, original.clone(), fifth.clone())?;
        let repaired = read(&lost)?;
        assert!(
            repaired.selected(None).is_err(),
            "recovery fabricated applied anonymous credentials"
        );
        assert!(
            repaired.selected(Some(&fourth)).is_err(),
            "a lost revision became selectable"
        );
        assert!(repaired.selected(Some(&fifth))?.value == original);
        // A concurrent writer must receive a typed lock failure, never a
        // successful receipt or a partially updated applied/draft pair. Exercise
        // the credential boundary while a real independently opened lock is held.
        let before = fs::read(&path)?;
        let held = journal(&path)?;
        std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let writers: Vec<_> = (6_u8..=9)
                .map(|nonce| {
                    let path = &path;
                    let original = &original;
                    scope.spawn(move || {
                        matches!(
                            stage(path, None, original.clone(), format!("{nonce:032x}")),
                            Err(ServiceError::CredentialStorage(
                                IntegrationStateError::Lock(_)
                            ))
                        )
                    })
                })
                .collect();
            for writer in writers {
                assert!(
                    writer.join().map_err(|_| "credential writer panicked")?,
                    "parallel credential stage did not report its held lock"
                );
            }
            Ok(())
        })?;
        assert_eq!(
            fs::read(&path)?,
            before,
            "a refused writer altered credential state"
        );
        drop(held);
        let last = "a".repeat(32);
        stage(&path, Some(&second), original.clone(), last.clone())?;
        let after = read(&path)?;
        assert!(after.selected(Some(&second))?.value == Credentials::default());
        assert!(after.selected(Some(&fourth)).is_err());
        assert!(after.selected(Some(&last))?.value == original);
        Ok(())
    }
}
