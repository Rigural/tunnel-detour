//! Exact public source inputs for measurements made from an uncommitted tree.

use std::{collections::BTreeMap, error::Error, path::Path, process::Command};

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Retain exactly the allowlisted inputs identified by a measurement manifest.
///
/// # Errors
/// Refuses an existing destination, changed input hashes, invalid inventories and
/// archive failures. Private local context is excluded by the same source policy.
pub fn archive_inputs(root: &Path, inputs: &Value, destination: &Path) -> Result<()> {
    use std::{io::Write, process::Stdio};
    if source_inputs(root)? != *inputs {
        return Err("source archive requires unchanged inputs".into());
    }
    let files = inputs["files"]
        .as_object()
        .ok_or("missing source input inventory")?;
    // Exclusive creation also refuses dangling symlinks. Hand the opened file
    // descriptor to tar so a second pathname lookup cannot replace evidence.
    let archive = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let writer = archive.try_clone()?;
    let mut child = Command::new("timeout")
        .current_dir(root)
        .args([
            "--kill-after=2",
            "30",
            "tar",
            "--create",
            "--format=posix",
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--pax-option=delete=atime,delete=ctime",
            "--null",
            "--no-recursion",
            "--files-from=-",
            "--file=-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .spawn()?;
    let write_result = match child.stdin.take() {
        Some(mut pipe) => (|| -> std::io::Result<()> {
            for name in files.keys() {
                pipe.write_all(name.as_bytes())?;
                pipe.write_all(&[0])?;
            }
            Ok(())
        })(),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "missing archive input pipe",
        )),
    };
    let output = child.wait_with_output()?;
    write_result?;
    if !output.status.success() || source_inputs(root)? != *inputs {
        return Err("source archive failed or inputs changed during capture".into());
    }
    archive.sync_all()?;
    Ok(())
}

/// Optional host accounting context, never environment variables or workload names.
/// Missing kernel interfaces are reported as unavailable instead of fabricated zeroes.
pub fn host_context() -> Value {
    use std::io::Read;
    let mut fields = BTreeMap::new();
    for (name, path) in [
        ("cpu_pressure", "/proc/pressure/cpu"),
        ("memory_pressure", "/proc/pressure/memory"),
        ("io_pressure", "/proc/pressure/io"),
        ("load_average", "/proc/loadavg"),
        ("online_cpus", "/sys/devices/system/cpu/online"),
        ("controller_status_and_affinity", "/proc/self/status"),
        ("host_memory", "/proc/meminfo"),
        ("host_socket_accounting", "/proc/net/sockstat"),
        ("cgroup_cpu_limit", "/sys/fs/cgroup/cpu.max"),
        ("cgroup_cpu_accounting", "/sys/fs/cgroup/cpu.stat"),
        ("cgroup_memory_events", "/sys/fs/cgroup/memory.events"),
        (
            "cpu0_frequency_khz",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        ),
    ] {
        let read = || -> std::io::Result<String> {
            let mut value = String::new();
            std::fs::File::open(path)?
                .take(16_385)
                .read_to_string(&mut value)?;
            if value.len() > 16_384 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            Ok(value)
        };
        let value = match read() {
            Ok(value) => json!({"available":true,"raw":value}),
            Err(error) => json!({"available":false,"error_kind":format!("{:?}", error.kind())}),
        };
        fields.insert(name, value);
    }
    json!({"scope":"host/controller cgroup context, not measured application resource use; no workload attribution or noise-free claim", "interfaces":fields})
}

/// Hash the intended repository inputs, including untracked implementation files.
/// Private context and arbitrary files outside the product allowlist are excluded.
///
/// # Errors
/// Refuses failed Git/hash operations, oversized inventories, non-UTF-8 paths and
/// symlinks or nonregular inputs. Call before and after building frozen binaries.
pub fn source_inputs(root: &Path) -> Result<Value> {
    let listed = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()?;
    if !listed.status.success() || listed.stdout.len() > 1_048_576 {
        return Err("source input inventory failed or exceeded its bound".into());
    }
    let mut files = BTreeMap::new();
    for raw in listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let name = std::str::from_utf8(raw)?;
        if !intended(name) {
            continue;
        }
        let path = root.join(name);
        if !std::fs::symlink_metadata(&path)?.is_file() || files.len() >= 4096 {
            return Err("source input is not regular or inventory exceeded capacity".into());
        }
        let hashed = Command::new("sha256sum").arg("--").arg(path).output()?;
        if !hashed.status.success() || hashed.stdout.len() < 64 {
            return Err("source input hashing failed".into());
        }
        let digest = std::str::from_utf8(&hashed.stdout[..64])?;
        if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("source input hashing returned an invalid digest".into());
        }
        files.insert(name.to_owned(), digest.to_owned());
    }
    if files.is_empty() {
        return Err("no intended source inputs were found".into());
    }
    Ok(json!({"version":1,"algorithm":"SHA-256","files":files,
        "scope":"allowlisted public source/configuration/documentation inputs, including untracked files; excludes private context and generated outputs"}))
}

fn intended(name: &str) -> bool {
    !Path::new(name).is_absolute()
        && !Path::new(name)
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        && (name.starts_with("sources/")
            || name.starts_with("docs/")
            || name.starts_with(".cargo/")
            || name.starts_with(".github/")
            || matches!(
                name,
                "Cargo.toml"
                    | "Cargo.lock"
                    | "rust-toolchain.toml"
                    | "README.md"
                    | "CHANGELOG.md"
                    | "LICENSE"
                    | ".gitignore"
            ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r137_source_provenance_detects_dirty_input_changes_and_excludes_private_files() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        if !Command::new("git")
            .args(["init", "--quiet"])
            .arg(root)
            .status()?
            .success()
        {
            return Err("cannot initialize an isolated provenance fixture".into());
        }
        std::fs::create_dir(root.join("sources"))?;
        std::fs::create_dir(root.join(".local"))?;
        std::fs::write(root.join("sources/input.rs"), "pub const VALUE: u8 = 1;\n")?;
        std::fs::write(root.join("CHANGELOG.md"), "# Changelog\n")?;
        std::fs::write(root.join("AGENTS.md"), "private fixture instructions")?;
        std::fs::write(root.join(".env"), "fixture secret")?;
        std::fs::write(root.join(".local/access.env"), "fixture access")?;
        let before = source_inputs(root)?;
        let files = before["files"].as_object().ok_or("missing inventory")?;
        assert_eq!(files.len(), 2);
        assert!(files.contains_key("sources/input.rs"));
        assert!(files.contains_key("CHANGELOG.md"));
        std::fs::write(root.join("sources/input.rs"), "pub const VALUE: u8 = 2;\n")?;
        assert_ne!(
            source_inputs(root)?,
            before,
            "uncommitted changes must change provenance"
        );
        let current = source_inputs(root)?;
        let archive = root.join(".local/source.tar");
        archive_inputs(root, &current, &archive)?;
        let listed = Command::new("tar")
            .args(["--list", "--file"])
            .arg(&archive)
            .output()?;
        assert!(listed.status.success());
        assert_eq!(
            listed.stdout, b"CHANGELOG.md\nsources/input.rs\n",
            "source archive included an unintended or private path"
        );
        let contents = Command::new("tar")
            .args(["--extract", "--to-stdout", "--file"])
            .arg(&archive)
            .arg("sources/input.rs")
            .output()?;
        assert!(contents.status.success());
        assert_eq!(contents.stdout, b"pub const VALUE: u8 = 2;\n");
        assert!(
            archive_inputs(root, &current, &archive).is_err(),
            "archival replaced existing evidence"
        );
        std::fs::write(root.join("sources/input.rs"), "pub const VALUE: u8 = 3;\n")?;
        let changed = root.join(".local/stale-source.tar");
        assert!(
            archive_inputs(root, &current, &changed).is_err(),
            "archival accepted a stale source inventory"
        );
        assert!(
            !changed.exists(),
            "a refused snapshot created an ambiguous archive"
        );
        #[cfg(unix)]
        {
            let current = source_inputs(root)?;
            let foreign = root.join(".local/foreign-archive");
            let link = root.join(".local/archive-link.tar");
            std::os::unix::fs::symlink(&foreign, &link)?;
            assert!(
                archive_inputs(root, &current, &link).is_err(),
                "archive followed a dangling destination symlink"
            );
            assert!(
                !foreign.exists(),
                "archive created a foreign symlink target"
            );
            std::os::unix::fs::symlink(root.join(".env"), root.join("sources/link.rs"))?;
            assert!(
                source_inputs(root).is_err(),
                "source symlinks must not import secrets"
            );
        }
        Ok(())
    }
}
