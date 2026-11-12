//! Qualify execution metadata before paired process measurements.

use super::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
};

fn identity(text: &str) -> Result<Value> {
    let (header, programs) = text
        .split_once("Program Headers:")
        .ok_or("missing ELF program headers")?;
    let entries = programs
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("INTERP"))
        .count();
    let mut interpreter = None;
    for line in programs.lines().map(str::trim) {
        if let Some(path) = line.strip_prefix("[Requesting program interpreter:") {
            let path = path
                .strip_suffix(']')
                .ok_or("invalid ELF interpreter observation")?
                .trim();
            if !path.starts_with('/') || path.chars().any(char::is_control) || interpreter.is_some()
            {
                return Err("invalid or duplicate ELF runtime interpreter".into());
            }
            interpreter = Some(path);
        }
    }
    if entries != usize::from(interpreter.is_some()) {
        return Err("incomplete ELF runtime interpreter".into());
    }
    let wanted = [
        "Class",
        "Data",
        "OS/ABI",
        "ABI Version",
        "Type",
        "Machine",
        "Flags",
    ];
    let mut fields = BTreeMap::new();
    for line in header.lines() {
        if let Some((key, value)) = line.trim().split_once(':')
            && wanted.contains(&key)
            && (value.trim().is_empty()
                || fields
                    .insert(key.to_owned(), value.trim().to_owned())
                    .is_some())
        {
            return Err("missing or duplicate ELF execution identity".into());
        }
    }
    if fields.len() != wanted.len() {
        return Err("incomplete ELF execution identity".into());
    }
    Ok(json!({"fields":fields,"interpreter":interpreter}))
}

fn inspect(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err("ELF qualification requires a regular executable below 64 MiB".into());
    }
    let expected = digest(path)?;
    let mut child = Command::new("timeout")
        .args([
            "--kill-after=1",
            "5",
            "readelf",
            "--file-header",
            "--program-headers",
            "--wide",
            "--",
        ])
        .arg(path)
        .env("LC_ALL", "C")
        .env("DEBUGINFOD_URLS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = match child.stdout.take() {
        Some(stdout) => stdout.take(65537).read_to_end(&mut bytes),
        None => Err(io::Error::other("ELF inspection stdout missing")),
    };
    if read.is_err() || bytes.len() > 65536 {
        // Dropping the bounded stdout reader closes its pipe. Keep timeout as
        // owner of the inspector until it exits or its finite deadline kills
        // the process group; killing just the wrapper could orphan its child.
        child.wait()?;
        read?;
        return Err("ELF inspection output exceeded its bound or could not be read".into());
    }
    let status = child.wait()?;
    read?;
    if !status.success() {
        return Err(format!("ELF inspection failed: {status}").into());
    }
    if digest(path)? != expected {
        return Err("executable changed during ELF inspection".into());
    }
    let raw = String::from_utf8(bytes)?;
    Ok(json!({"sha256":expected,"identity":identity(&raw)?,"readelf":raw}))
}

pub(super) fn matching(before: &Path, after: &Path) -> Result<Value> {
    let before = inspect(before)?;
    let after = inspect(after)?;
    if before["identity"] != after["identity"] {
        return Err(
            "paired executable execution ABI mismatch; use the same target and linkage".into(),
        );
    }
    // ELF without an interpreter cannot identify its statically linked libc.
    // Identical bytes prove this control; different static revisions need a
    // stronger build contract than this comparator currently supports.
    if before["identity"]["interpreter"].is_null() && before["sha256"] != after["sha256"] {
        return Err(
            "different static executables cannot qualify a shared runtime ABI from ELF metadata"
                .into(),
        );
    }
    Ok(
        json!({"before":before,"after":after,"scope":"ELF class/encoding/machine/type/flags and runtime interpreter; matching compiler, target, build profile and instrumentation remain prerequisites"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Class: ELF64\nData: 2's complement, little endian\nOS/ABI: UNIX - System V\nABI Version: 0\nType: DYN\nMachine: X86-64\nFlags: 0x0\n";

    #[test]
    fn r151b_elf_identity_requires_complete_unambiguous_metadata_and_distinguishes_linkage()
    -> Result {
        let plain = format!("{HEADER}\nProgram Headers:\n LOAD 0x0\n");
        let dynamic = format!(
            "{HEADER}\nProgram Headers:\n INTERP 0x0\n [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n"
        );
        assert_eq!(
            identity(&dynamic)?["interpreter"],
            "/lib64/ld-linux-x86-64.so.2"
        );
        assert!(identity(&plain)?["interpreter"].is_null());
        assert_ne!(identity(&dynamic)?, identity(&plain)?);
        assert!(identity(&plain.replace("Class: ELF64\n", "")).is_err());
        assert!(
            identity(&plain.replace("Program Headers:", "Machine: X86-64\nProgram Headers:"))
                .is_err()
        );
        assert!(identity(&dynamic.replace("INTERP 0x0", "LOAD 0x0")).is_err());
        assert!(
            identity(&dynamic.replace(
                " [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n",
                ""
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires qualified GNU before/after workers and a distinct static worker; no active measurement"]
    fn r151b_real_linkage_mismatch_is_refused_before_policy_or_api_output() -> Result {
        let before = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_ELF_BEFORE").ok_or("provide GNU before worker")?,
        );
        let after = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_ELF_AFTER").ok_or("provide GNU after worker")?,
        );
        let incompatible = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_ELF_INCOMPATIBLE")
                .ok_or("provide static control worker")?,
        );
        println!("POLICY_ELF_COMPATIBILITY={}", matching(&before, &after)?);
        if let (Some(before), Some(after)) = (
            std::env::var_os("TUNNEL_DETOUR_API_ELF_BEFORE"),
            std::env::var_os("TUNNEL_DETOUR_API_ELF_AFTER"),
        ) {
            println!(
                "API_ELF_COMPATIBILITY={}",
                matching(Path::new(&before), Path::new(&after))?
            );
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let cargo = std::env::var_os("CARGO").ok_or("missing Cargo")?;
        let directory = tempfile::tempdir()?;
        matching(&incompatible, &incompatible)?;
        let changed_static = directory.path().join("different-static");
        let mut bytes = fs::read(&incompatible)?;
        bytes.push(0);
        fs::write(&changed_static, bytes)?;
        match matching(&incompatible, &changed_static) {
            Ok(_) => {
                return Err(
                    "different static executables were treated as a qualified runtime".into(),
                );
            }
            Err(error) => assert!(
                error.to_string().contains("different static executables"),
                "unexpected static refusal: {error}"
            ),
        }
        let policy_output = directory.path().join("policy");
        let api_output = directory.path().join("api");
        let input = directory.path().join("input.json");
        fs::write(&input, b"{}")?;
        for (output, observed) in [
            (
                &policy_output,
                super::super::policy::run(
                    &cargo,
                    &root,
                    &policy_output,
                    &before,
                    &incompatible,
                    directory.path(),
                ),
            ),
            (
                &api_output,
                super::super::api::run(&cargo, &root, &api_output, &before, &incompatible, &input),
            ),
        ] {
            match observed {
                Ok(()) => return Err("incompatible execution ABI was accepted".into()),
                Err(error) => assert!(
                    error.to_string().contains("execution ABI mismatch"),
                    "unexpected refusal: {error}"
                ),
            }
            assert!(
                !output.exists(),
                "ABI refusal created output or reached measurement"
            );
        }
        Ok(())
    }
}
