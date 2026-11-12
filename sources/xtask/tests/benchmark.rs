//! The controller lock must protect a frozen experiment before any build or retag.

use serde_json::Value;
use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::{Command, Output},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
#[ignore = "requires a generated interrupted application matrix and local Docker for exclusion checks"]
fn r147_matrix_continuation_refuses_altered_prefix_without_replacing_observations() -> TestResult {
    let prior = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_APPLICATION_PREFIX")
            .ok_or("provide an interrupted application matrix")?,
    );
    let original = fs::read(prior.join("completed.json"))?;
    let reports: Value = serde_json::from_slice(&original)?;
    let first = &reports[0]["case"];
    let name = format!(
        "000-{}-rules{}-occupied{}-{}",
        first["frontend"].as_str().ok_or("missing frontend")?,
        first["rules"],
        first["initial_live_identities"],
        if first["http_connection_reuse"] == true {
            "reuse"
        } else {
            "churn"
        }
    );
    for scenario in ["coordinate", "raw", "started"] {
        let fixture = tempfile::tempdir()?;
        let input = fixture.path().join("input");
        fs::create_dir(&input)?;
        for file in [
            "manifest.json",
            "environment.json",
            "completed.json",
            "interruption.json",
        ] {
            fs::copy(prior.join(file), input.join(file))?;
        }
        if scenario == "started" {
            let manifest: Value = serde_json::from_slice(&fs::read(input.join("manifest.json"))?)?;
            let count = reports.as_array().ok_or("missing prefix")?.len();
            let next = &manifest["cases"][count];
            let directory = input.join(format!(
                "{count:03}-{}-rules{}-occupied{}-{}",
                next["frontend"].as_str().ok_or("missing next frontend")?,
                next["rules"],
                next["initial_live_identities"],
                if next["http_connection_reuse"] == true {
                    "reuse"
                } else {
                    "churn"
                }
            ));
            fs::create_dir(&directory)?;
            fs::write(directory.join("accounting.json"), b"{}")?;
        } else if scenario == "raw" {
            let directory = input.join(&name);
            fs::create_dir(&directory)?;
            for file in ["application.json", "summary.json", "cleanup.json"] {
                fs::copy(prior.join(&name).join(file), directory.join(file))?;
            }
            let path = directory.join("summary.json");
            let mut raw: Value = serde_json::from_slice(&fs::read(&path)?)?;
            raw["operations"][0]["successful"] = 0.into();
            fs::write(path, serde_json::to_vec(&raw)?)?;
        } else {
            let mut changed = reports.clone();
            changed[0]["case"]["rules"] = 999.into();
            fs::write(input.join("completed.json"), serde_json::to_vec(&changed)?)?;
        }
        let destination = fixture.path().join("output");
        let result = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["benchmark-app", "--resume-matrix"])
            .arg(&input)
            .arg("--output")
            .arg(&destination)
            .output()?;
        assert!(
            !result.status.success(),
            "corrupted matrix must refuse continuation"
        );
        let error = String::from_utf8(result.stderr)?;
        assert!(
            error.contains(match scenario {
                "raw" => "does not reproduce",
                "started" => "refusing to replace",
                _ => "changed its declared order",
            }),
            "unexpected refusal: {error}"
        );
        assert!(
            !destination.exists(),
            "refusal must precede new measurements or output creation"
        );
        assert_eq!(
            fs::read(prior.join("completed.json"))?,
            original,
            "original observations must remain untouched"
        );
    }
    Ok(())
}

#[test]
fn r139_forged_dns_header_counts_cannot_force_a_large_empty_message_reservation() -> TestResult {
    let result = Command::new(env!("CARGO_BIN_EXE_dns-boundary-probe"))
        .env("TUNNEL_DETOUR_DNS_PARSER_LAB", "1")
        .output()?;
    assert!(
        result.status.success(),
        "bounded DNS parser process failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        result.stdout,
        b"forged DNS counts rejected within an 8-MiB incremental address-space budget\n"
    );
    Ok(())
}

fn checked(mut command: Command) -> TestResult<Output> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "benchmark prerequisite failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

/// Use generated artifacts from an interrupted synthetic campaign. Never point
/// this test at production traffic; all counterfactual edits stay in a tempdir.
#[test]
#[ignore = "requires an interrupted synthetic campaign, its local image and an optional image export proof"]
fn r103_continuation_verifies_saved_pairs_and_refuses_corruption_without_modifying_observations()
-> TestResult {
    let input = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_BENCHMARK_PREFIX")
            .ok_or("provide a generated interrupted campaign")?,
    );
    let image =
        env::var_os("TUNNEL_DETOUR_BENCHMARK_IMAGE").ok_or("provide its existing local image")?;
    let proof = env::var_os("TUNNEL_DETOUR_BENCHMARK_IMAGE_PROOF").map(PathBuf::from);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let cargo = env::var_os("CARGO").ok_or("Cargo did not provide its executable path")?;
    let fixture = tempfile::tempdir()?;
    let directory = fixture.path();
    let plan: Value = serde_json::from_slice(&fs::read(input.join("plan.json"))?)?;
    let mut summary: Value = serde_json::from_slice(&fs::read(input.join("summary.json"))?)?;
    let pairs = summary["completed_pairs"]
        .as_array_mut()
        .ok_or("missing prefix")?;
    if pairs.len() < 2 {
        return Err("the fixture requires at least two completed pairs".into());
    }
    pairs.truncate(2);
    summary["complete"] = false.into();
    summary["campaign_complete"] = false.into();
    summary["measurements_complete"] = false.into();
    summary["failed_cases"] = serde_json::json!([]);
    summary["observations_complete"] = false.into();
    fs::copy(
        input.join("relay-bench-worker"),
        directory.join("relay-bench-worker"),
    )?;
    fs::copy(input.join("plan.json"), directory.join("plan.json"))?;
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec(&summary)?,
    )?;
    let case_name = |index: usize| -> TestResult<String> {
        let case = &plan["cases"][index];
        Ok(format!(
            "{index:03}-{}-c{:02}-b{:04}",
            case["workload"]
                .as_str()
                .ok_or("missing fixture workload")?,
            case["connections"]
                .as_u64()
                .ok_or("missing fixture capacity")?,
            case["message_bytes"].as_u64().unwrap_or_default()
        ))
    };
    let mut originals = Vec::new();
    for name in ["relay-bench-worker", "plan.json", "summary.json"] {
        originals.push((directory.join(name), fs::read(directory.join(name))?));
    }
    for index in 0..2 {
        let name = case_name(index)?;
        fs::create_dir(directory.join(&name))?;
        for file in ["manifest.json", "rust.json", "socat.json", "summary.json"] {
            let path = directory.join(&name).join(file);
            fs::copy(input.join(&name).join(file), &path)?;
            originals.push((path.clone(), fs::read(path)?));
        }
    }
    let retain_failures = std::cell::Cell::new(false);
    let invoke = |proof: Option<&Path>, successful: bool, reason: &str| -> TestResult {
        let mut child = Command::new("timeout");
        child
            .args(["--kill-after=2", "20", env!("CARGO_BIN_EXE_xtask")])
            .current_dir(&root)
            .env("CARGO", &cargo)
            .args([
                "benchmark-relay",
                "--resume-campaign",
                "--verify-only",
                "--output",
            ])
            .arg(directory)
            .arg("--image")
            .arg(&image);
        if let Some(proof) = proof {
            child.arg("--image-proof").arg(proof);
        }
        if retain_failures.get() {
            child.arg("--retain-failed-cases");
        }
        let output = child.output()?;
        if successful {
            assert!(
                output.status.success(),
                "valid continuation was refused: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("Verified 2 complete pairs"));
            if retain_failures.get() {
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("Retained 1 FAILED cases")
                );
            }
        } else {
            assert_eq!(
                output.status.code(),
                Some(1),
                "refusal hung or failed unexpectedly: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(reason),
                "wrong refusal: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            !directory.join("continuations").exists(),
            "verification created a continuation session"
        );
        Ok(())
    };
    invoke(proof.as_deref(), true, "")?;
    let failed = directory.join(case_name(2)?);
    fs::create_dir(&failed)?;
    fs::copy(
        input.join(case_name(2)?).join("manifest.json"),
        failed.join("manifest.json"),
    )?;
    let invalid = serde_json::json!({"valid":false,"case":plan["cases"][2],"reason":"synthetic uncertain control-plane start; not a successful measurement"});
    fs::write(failed.join("invalid.json"), serde_json::to_vec(&invalid)?)?;
    let failed_bytes = fs::read(failed.join("invalid.json"))?;
    invoke(proof.as_deref(), false, "unfinished case already exists")?;
    retain_failures.set(true);
    invoke(proof.as_deref(), true, "")?;
    assert_eq!(
        fs::read(failed.join("invalid.json"))?,
        failed_bytes,
        "failed attempt must remain unchanged"
    );
    let mut wrong = invalid;
    wrong["case"]["connections"] = 99.into();
    fs::write(failed.join("invalid.json"), serde_json::to_vec(&wrong)?)?;
    invoke(proof.as_deref(), false, "inconsistent evidence")?;
    fs::write(failed.join("invalid.json"), failed_bytes)?;
    fs::remove_file(failed.join("invalid.json"))?;
    fs::remove_file(failed.join("manifest.json"))?;
    fs::remove_dir(&failed)?;
    retain_failures.set(false);
    for (path, bytes) in &originals {
        assert_eq!(
            fs::read(path)?,
            *bytes,
            "verification changed an observation"
        );
    }
    let worker = directory.join("relay-bench-worker");
    let bytes = fs::read(&worker)?;
    let mut changed = bytes.clone();
    changed.push(0);
    fs::write(&worker, changed)?;
    invoke(
        proof.as_deref(),
        false,
        "frozen worker or campaign plan differs",
    )?;
    fs::write(&worker, bytes)?;
    let plan_path = directory.join("plan.json");
    let bytes = fs::read(&plan_path)?;
    let mut changed = plan.clone();
    changed["cases"][0]["connections"] = 33.into();
    fs::write(&plan_path, serde_json::to_vec(&changed)?)?;
    invoke(proof.as_deref(), false, "campaign plan differs")?;
    fs::write(&plan_path, bytes)?;
    let network_plan_bytes = fs::read(&plan_path)?;
    let mut changed = plan.clone();
    let fields = changed.as_object_mut().ok_or("invalid test plan")?;
    if fields.remove("generator_network").is_none() {
        fields.insert("generator_network".into(), "retained_owned_endpoint".into());
    }
    fs::write(&plan_path, serde_json::to_vec(&changed)?)?;
    invoke(proof.as_deref(), false, "frozen network lifetime")?;
    fs::write(&plan_path, network_plan_bytes)?;
    let manifest = directory.join(case_name(1)?).join("manifest.json");
    let bytes = fs::read(&manifest)?;
    let mut changed: Value = serde_json::from_slice(&bytes)?;
    changed["kernel"] = "synthetic incompatible kernel".into();
    fs::write(&manifest, serde_json::to_vec(&changed)?)?;
    invoke(proof.as_deref(), false, "incompatible operational contexts")?;
    fs::write(&manifest, bytes)?;
    let raw = directory.join(case_name(0)?).join("rust.json");
    fs::rename(&raw, directory.join("held-raw.json"))?;
    invoke(proof.as_deref(), false, "No such file")?;
    fs::rename(directory.join("held-raw.json"), &raw)?;
    let saved = directory.join(case_name(0)?).join("summary.json");
    let bytes = fs::read(&saved)?;
    let mut changed: Value = serde_json::from_slice(&bytes)?;
    changed["pair_complete"] = false.into();
    fs::write(&saved, serde_json::to_vec(&changed)?)?;
    invoke(proof.as_deref(), false, "incomplete or inconsistent pair")?;
    fs::write(&saved, bytes)?;
    let root_path = directory.join("summary.json");
    let root_bytes = fs::read(&root_path)?;
    let mut premature: Value = serde_json::from_slice(&root_bytes)?;
    for field in ["complete", "campaign_complete", "measurements_complete"] {
        premature[field] = true.into();
    }
    fs::write(&root_path, serde_json::to_vec(&premature)?)?;
    invoke(proof.as_deref(), false, "completion state is inconsistent")?;
    fs::write(&root_path, &root_bytes)?;
    let saved_bytes = fs::read(&saved)?;
    let mut changed: Value = serde_json::from_slice(&saved_bytes)?;
    changed["results"][0]["resources"]["cpu_nanoseconds_including_warmup_and_drain"] = 1.into();
    let mut root_summary: Value = serde_json::from_slice(&root_bytes)?;
    root_summary["completed_pairs"][0]["results"] = changed["results"].clone();
    fs::write(&saved, serde_json::to_vec(&changed)?)?;
    fs::write(&root_path, serde_json::to_vec(&root_summary)?)?;
    invoke(
        proof.as_deref(),
        false,
        "cannot be reproduced from their raw reports",
    )?;
    fs::write(&saved, saved_bytes)?;
    fs::write(&root_path, root_bytes)?;
    let partial = directory.join(case_name(2)?);
    fs::create_dir(&partial)?;
    invoke(proof.as_deref(), false, "unfinished case already exists")?;
    fs::remove_dir(partial)?;
    if let Some(proof) = &proof {
        let original: Value = serde_json::from_slice(&fs::read(proof)?)?;
        let mut changed = original.clone();
        let mut absolute = serde_json::Map::new();
        for (log, declaration) in original["build_exports"]
            .as_object()
            .ok_or("missing exports")?
        {
            absolute.insert(
                proof
                    .parent()
                    .ok_or("proof parent")?
                    .join(log)
                    .canonicalize()?
                    .to_string_lossy()
                    .into_owned(),
                declaration.clone(),
            );
        }
        changed["build_exports"] = absolute.into();
        let declaration = changed["build_exports"]
            .as_object_mut()
            .and_then(|exports| exports.values_mut().next())
            .ok_or("empty export proof")?;
        declaration["config"] = format!("sha256:{}", "0".repeat(64)).into();
        let bad_proof = directory.join("bad-proof.json");
        fs::write(&bad_proof, serde_json::to_vec(&changed)?)?;
        invoke(Some(&bad_proof), false, "image export declaration")?;
        fs::remove_file(bad_proof)?;
    }
    invoke(proof.as_deref(), true, "")?;
    for (path, bytes) in &originals {
        assert_eq!(fs::read(path)?, *bytes, "a refusal changed an observation");
    }
    Ok(())
}

#[test]
#[ignore = "requires the local benchmark image and compiled musl worker from a qualified pilot"]
fn r100_a_second_controller_refuses_before_building_retagging_or_creating_results() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let cargo = env::var_os("CARGO").ok_or("Cargo did not provide its executable path")?;
    let mut metadata = Command::new(&cargo);
    metadata
        .current_dir(&root)
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"]);
    let metadata: Value = serde_json::from_slice(&checked(metadata)?.stdout)?;
    let release = Path::new(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing Cargo target")?,
    )
    .join("x86_64-unknown-linux-musl/release");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(release.join("relay-benchmark.lock"))?;
    // A live campaign may already own this lock. Otherwise this test supplies
    // the real OS lock; the child must refuse in both cases.
    match lock.try_lock() {
        Ok(()) | Err(std::fs::TryLockError::WouldBlock) => {}
        Err(error) => return Err(error.into()),
    }
    let image = || -> TestResult<Vec<u8>> {
        let mut command = Command::new("docker");
        command.args([
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "tunnel-detour-relay-benchmark:local",
        ]);
        Ok(checked(command)?.stdout)
    };
    let worker = || -> TestResult<Vec<u8>> {
        let mut command = Command::new("sha256sum");
        command.arg(release.join("relay-bench-worker"));
        Ok(checked(command)?.stdout)
    };
    let image_before = image()?;
    let worker_before = worker()?;
    let directory = tempfile::tempdir()?;
    let results = directory.path().join("must-remain-absent");
    for mode in ["pilot", "continuation", "frozen-endpoints"] {
        let mut child = Command::new("timeout");
        child
            .args(["--kill-after=2", "8", env!("CARGO_BIN_EXE_xtask")])
            .current_dir(&root)
            .env("CARGO", &cargo);
        if mode == "continuation" {
            child
                .args(["benchmark-relay", "--resume-campaign", "--output"])
                .arg(directory.path())
                .args(["--image", "tunnel-detour-relay-benchmark:local"]);
        } else if mode == "frozen-endpoints" {
            child
                .args(["benchmark-relay", "--endpoint-reference", "--worker"])
                .arg(release.join("relay-bench-worker"))
                .args(["--image", "tunnel-detour-relay-benchmark:local", "--output"])
                .arg(&results);
        } else {
            child
                .args(["benchmark-relay", "--pilot", "--output"])
                .arg(&results);
        }
        let output = child.output()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "the competing controller failed to refuse promptly: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("cannot start another relay benchmark controller"),
            "the child failed for another reason: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !results.exists(),
            "the rejected controller created result artifacts"
        );
        assert!(
            fs::read_dir(directory.path())?
                .next()
                .transpose()?
                .is_none(),
            "the refused continuation wrote artifacts"
        );
    }
    assert_eq!(
        image()?,
        image_before,
        "the rejected controller moved the comparison image"
    );
    assert_eq!(
        worker()?,
        worker_before,
        "the rejected controller rebuilt the worker"
    );
    Ok(())
}
