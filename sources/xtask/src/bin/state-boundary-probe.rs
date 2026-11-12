//! Test-only ownership checks that require root in the isolated laboratory.

use std::{error::Error, fs, num::NonZeroUsize, os::unix::fs::PermissionsExt, process::ExitCode};
use tunnel_detour_core::{LeaseStore, StoreError};

fn run() -> Result<(), Box<dyn Error>> {
    if std::env::var("TUNNEL_DETOUR_STATE_LAB").as_deref() != Ok("1")
        || !rustix::process::geteuid().is_root()
    {
        return Err("use the isolated root ownership laboratory".into());
    }
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("leases.json");
    let capacity = NonZeroUsize::new(2).ok_or("invalid ownership fixture capacity")?;
    let open = || {
        LeaseStore::open(
            &path,
            "198.18.0.0/28".parse().map_err(StoreError::Lease)?,
            capacity,
        )
    };
    drop(open()?);
    let before = fs::read(&path)?;
    for target in [
        path.clone(),
        directory.path().join("leases.json.lock"),
        directory.path().to_path_buf(),
    ] {
        rustix::fs::chown(&target, Some(rustix::process::Uid::from_raw(65534)), None)?;
        let refused = matches!(open(), Err(StoreError::UnsafeFile));
        rustix::fs::chown(&target, Some(rustix::process::Uid::ROOT), None)?;
        if !refused {
            return Err(
                "foreign-owned allocator input was accepted with private permissions".into(),
            );
        }
        if fs::read(&path)? != before {
            return Err("refusal modified the allocator snapshot".into());
        }
    }
    drop(open()?);
    println!("foreign-owned snapshot, lock and parent refused; state preserved");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
