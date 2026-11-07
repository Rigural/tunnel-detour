use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};

use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{DomainName, FakeIpError, FakeIpRange, Lease, LeaseTable, Timestamp};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("lease state I/O failed")]
    Io(#[from] io::Error),
    #[error("lease state could not be locked exclusively")]
    Lock(#[from] std::fs::TryLockError),
    #[error("lease state is not valid JSON")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Lease(#[from] FakeIpError),
    #[error("lease state exceeds its configured size bound")]
    TooLarge,
    #[error("lease state is not a private regular file")]
    UnsafeFile,
    #[error("lease state path must have a filename and parent directory")]
    InvalidPath,
    #[error(
        "lease store is unavailable after an uncertain persistence failure; reopen it before use"
    )]
    Unavailable,
    #[error(
        "lease state is missing for an existing allocator; refusing to reuse previously issued addresses"
    )]
    MissingSnapshot,
}

/// Synchronous durable lease storage. Call from a blocking boundary in an async service.
///
/// An exclusive lock prevents concurrent allocators. Updates become visible only after file
/// replacement and directory synchronization. Any write failure poisons admission until reopen.
pub struct LeaseStore {
    path: PathBuf,
    _lock: File,
    table: LeaseTable,
    available: bool,
}

impl LeaseStore {
    /// The containing directory must exist, be private, and remain on persistent storage.
    /// A missing snapshot initializes a new table; corrupt existing state is never reset.
    pub fn open(
        path: impl AsRef<Path>,
        range: FakeIpRange,
        capacity: NonZeroUsize,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(StoreError::InvalidPath)?;
        let filename = path.file_name().ok_or(StoreError::InvalidPath)?;
        validate_file(&fs::symlink_metadata(parent)?, true)?;
        let mut lock_name = filename.to_os_string();
        lock_name.push(".lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .map_err(|_| StoreError::UnsafeFile)?,
            );
        }
        let lock_path = parent.join(lock_name);
        let (lock, new_lock) = match options.open(&lock_path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                options.create_new(false).create(false);
                (options.open(&lock_path)?, false)
            }
            Err(error) => return Err(error.into()),
        };
        validate_file(&lock.metadata()?, false)?;
        lock.try_lock()?;
        let (table, initialize) = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_file(&metadata, false)?;
                let byte_limit = capacity
                    .get()
                    .checked_mul(1024)
                    .and_then(|size| size.checked_add(4096))
                    .ok_or(StoreError::TooLarge)?;
                if metadata.len() > u64::try_from(byte_limit).map_err(|_| StoreError::TooLarge)? {
                    return Err(StoreError::TooLarge);
                }
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(
                        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                            .map_err(|_| StoreError::UnsafeFile)?,
                    );
                }
                let mut bytes = Vec::new();
                let read_limit = u64::try_from(byte_limit)
                    .map_err(|_| StoreError::TooLarge)?
                    .checked_add(1)
                    .ok_or(StoreError::TooLarge)?;
                options
                    .open(&path)?
                    .take(read_limit)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > byte_limit {
                    return Err(StoreError::TooLarge);
                }
                (
                    LeaseTable::restore(serde_json::from_slice(&bytes)?, range, capacity)?,
                    false,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && new_lock => {
                (LeaseTable::new(range, capacity)?, true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::MissingSnapshot);
            }
            Err(error) => return Err(error.into()),
        };
        let store = Self {
            path,
            _lock: lock,
            table,
            available: true,
        };
        if initialize {
            store.persist(&store.table)?;
        }
        Ok(store)
    }

    pub fn table(&self) -> Result<&LeaseTable, StoreError> {
        if !self.available {
            return Err(StoreError::Unavailable);
        }
        Ok(&self.table)
    }

    /// Publish the returned lease only after this method succeeds.
    pub fn issue(
        &mut self,
        domain: &DomainName,
        now: Timestamp,
        ttl: Duration,
    ) -> Result<Lease, StoreError> {
        if !self.available {
            return Err(StoreError::Unavailable);
        }
        let mut next = self.table.clone();
        let lease = next.issue(domain, now, ttl)?;
        // Set this before I/O: a failure after rename can leave disk ahead of memory.
        self.available = false;
        self.persist(&next)?;
        self.table = next;
        self.available = true;
        Ok(lease)
    }

    fn persist(&self, table: &LeaseTable) -> Result<(), StoreError> {
        let parent = self.path.parent().ok_or(StoreError::InvalidPath)?;
        let bytes = serde_json::to_vec(&table.snapshot())?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        let persisted = temporary.persist(&self.path).map_err(|error| error.error)?;
        persisted.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn validate_file(metadata: &fs::Metadata, directory: bool) -> Result<(), StoreError> {
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(StoreError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::UnsafeFile);
        }
    }
    Ok(())
}
