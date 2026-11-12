//! Private, bounded journals for DNS frontend ownership and recovery.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;

const LIMIT: usize = 4 * 1024 * 1024;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_roundtrip<T, E>(
    bytes: &[u8],
    validate: impl Fn(&T) -> Result<(), E>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Serialize,
    E: std::error::Error + 'static,
{
    let Ok(value) = serde_json::from_slice::<T>(bytes) else {
        return Ok(());
    };
    if validate(&value).is_ok() {
        let encoded = serde_json::to_vec(&value)?;
        let restored: T = serde_json::from_slice(&encoded)?;
        validate(&restored)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum IntegrationStateError {
    #[error("integration ownership state I/O failed")]
    Io(#[from] std::io::Error),
    #[error("integration ownership state is invalid JSON")]
    Json(#[from] serde_json::Error),
    #[error("another process owns the integration journal")]
    Lock(#[from] std::fs::TryLockError),
    #[error("integration ownership state is unsafe, missing, or too large")]
    Unsafe,
}

pub(crate) fn appended_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn private(metadata: &fs::Metadata) -> Result<(), IntegrationStateError> {
    // Validate the opened descriptor, rather than only its pathname: a private
    // mode does not prove ownership or exclude a second name for the same inode.
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(IntegrationStateError::Unsafe);
    }
    Ok(())
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, IntegrationStateError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(
        i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
            .map_err(|_| IntegrationStateError::Unsafe)?,
    );
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    private(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(LIMIT + 1).map_err(|_| IntegrationStateError::Unsafe)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(IntegrationStateError::Unsafe);
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Read recovery metadata without creating state. A surviving lock detects lost ownership.
pub(crate) fn existing<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, IntegrationStateError> {
    let value = read(path)?;
    if value.is_none() {
        match fs::symlink_metadata(appended_path(path, ".lock")) {
            Ok(_) => return Err(IntegrationStateError::Unsafe),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(value)
}

pub(crate) struct PrivateJournal {
    path: PathBuf,
    new_lock: bool,
    _lock: File,
}

impl PrivateJournal {
    pub(crate) fn is_new(&self) -> bool {
        self.new_lock
    }

    pub(crate) fn open(path: PathBuf) -> Result<Self, IntegrationStateError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| IntegrationStateError::Unsafe)?,
            );
        let lock_path = appended_path(&path, ".lock");
        let (lock, new_lock) = match options.open(&lock_path) {
            Ok(lock) => (lock, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options.create_new(false);
                (options.open(&lock_path)?, false)
            }
            Err(error) => return Err(error.into()),
        };
        private(&lock.metadata()?)?;
        lock.try_lock()?;
        Ok(Self {
            path,
            new_lock,
            _lock: lock,
        })
    }

    /// The caller validates the deserialized policy before saving or mutating a frontend.
    pub(crate) fn load<T: DeserializeOwned>(&self, initial: T) -> Result<T, IntegrationStateError> {
        match read(&self.path)? {
            Some(value) => Ok(value),
            None if self.new_lock => Ok(initial),
            None => Err(IntegrationStateError::Unsafe),
        }
    }

    pub(crate) fn save<T: Serialize>(&self, state: &T) -> Result<(), IntegrationStateError> {
        atomic_write(&self.path, state)
    }
}

pub(crate) fn atomic_write<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), IntegrationStateError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > LIMIT {
        return Err(IntegrationStateError::Unsafe);
    }
    let parent = path.parent().ok_or(IntegrationStateError::Unsafe)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn r045_ownership_journals_lock_atomically_and_reject_lost_unsafe_or_oversized_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("dns.json");
        let journal = PrivateJournal::open(path.clone())?;
        assert!(journal.is_new());
        journal.save(&vec!["owned"])?;
        assert_eq!(journal.load::<Vec<String>>(vec![])?, vec!["owned"]);
        assert!(
            PrivateJournal::open(path.clone()).is_err(),
            "parallel writers must be excluded"
        );
        drop(journal);
        fs::remove_file(&path)?;
        assert!(
            existing::<Vec<String>>(&path).is_err(),
            "lost state must not reset ownership"
        );
        assert!(
            PrivateJournal::open(path.clone())?
                .load::<Vec<String>>(vec![])
                .is_err()
        );
        let foreign = directory.path().join("foreign");
        fs::write(&foreign, b"[]")?;
        symlink(&foreign, &path)?;
        assert!(existing::<Vec<String>>(&path).is_err());
        assert_eq!(fs::read(&foreign)?, b"[]");
        fs::remove_file(&path)?;
        fs::write(&path, b"[]")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(existing::<Vec<String>>(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, b"invalid")?;
        assert!(existing::<Vec<String>>(&path).is_err());
        fs::write(&path, vec![b' '; LIMIT + 1])?;
        assert!(existing::<Vec<String>>(&path).is_err());
        fs::remove_file(&path)?;
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        assert!(
            existing::<Vec<String>>(&path).is_err(),
            "a FIFO must be rejected without waiting for a writer"
        );
        Ok(())
    }
}
