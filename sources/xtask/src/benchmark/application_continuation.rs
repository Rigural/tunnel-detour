//! Preserve an interrupted matrix prefix and collect only its unmeasured suffix.

use super::*;
use std::collections::BTreeMap;

fn inventory(prior: &Path, completed: &[Value]) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for name in [
        "manifest.json",
        "environment.json",
        "completed.json",
        "interruption.json",
    ] {
        hashes.insert(name.into(), digest(&prior.join(name))?);
    }
    for (index, saved) in completed.iter().enumerate() {
        let directory = case_directory(prior, index, &saved["case"])?;
        let report = resume::read_json(&directory.join("application.json"), 16_777_216)?;
        let derived = summary(&report)?;
        let raw_summary = resume::read_json(&directory.join("summary.json"), 1_048_576)?;
        let cleanup = resume::read_json(&directory.join("cleanup.json"), 65_536)?;
        let qps = saved["case"]["http_qps_per_route"]
            .as_u64()
            .ok_or("missing prefix arrival rate")?;
        validate_client(&report["client_result"], qps)?;
        if derived != *saved
            || raw_summary != *saved
            || cleanup["complete"] != true
            || report["case"] != saved["case"]
            || report["final_status"]["status"]["process_id"]
                != report["initial_status"]["status"]["process_id"]
            || report["final_status"]["status"]["failures"]
                != report["initial_status"]["status"]["failures"]
            || report["final_status"]["status"]["phase"] != "ready"
            || report["final_status"]["status"]["configuration_applied"] != true
        {
            return Err(
                "application prefix does not reproduce its successful owning observations".into(),
            );
        }
        for name in ["wan", "vpn", "resolver"] {
            if report["paths_after"][name]
                .as_u64()
                .zip(report["paths_before"][name].as_u64())
                .is_none_or(|(after, before)| after <= before)
            {
                return Err("application prefix lacks a required path observation".into());
            }
        }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err("prefix evidence must be regular files".into());
            }
            let relative = path
                .strip_prefix(prior)?
                .to_str()
                .ok_or("non-UTF-8 prefix path")?
                .to_owned();
            hashes.insert(relative, digest(&path)?);
        }
    }
    Ok(hashes)
}

fn case_directory(root: &Path, index: usize, case: &Value) -> Result<PathBuf> {
    let frontend = case["frontend"].as_str().ok_or("missing frontend")?;
    if !matches!(frontend, "dnsmasq" | "adguard") {
        return Err("unknown matrix frontend".into());
    }
    Ok(root.join(format!(
        "{index:03}-{frontend}-rules{}-occupied{}-{}",
        case["rules"].as_u64().ok_or("missing rule count")?,
        case["initial_live_identities"]
            .as_u64()
            .ok_or("missing occupancy")?,
        if case["http_connection_reuse"] == true {
            "reuse"
        } else {
            "churn"
        }
    )))
}

/// Continue only after a complete audited prefix and an unmeasured preparation.
/// The original directory is read-only; new raw data and collector provenance
/// remain in a separate directory. No failed load may be replaced this way.
pub fn resume_matrix(cargo: &std::ffi::OsStr, root: &Path, prior: &Path, output: &Path) -> Result {
    let _activity = activity_lock(&cargo_target(cargo, root)?)?;
    let prior = prior.canonicalize()?;
    let manifest = resume::read_json(&prior.join("manifest.json"), 1_048_576)?;
    let saved = resume::read_json(&prior.join("completed.json"), 1_048_576)?;
    let completed = saved.as_array().ok_or("missing application prefix")?;
    let declared = manifest["cases"]
        .as_array()
        .ok_or("missing declared matrix")?;
    if manifest["kind"] != "descriptive native application qualification"
        || declared.len() != 48
        || completed.is_empty()
        || completed.len() >= declared.len()
        || prior.join("summary.json").exists()
        || prior.join("invalid.json").exists()
    {
        return Err(
            "continuation requires an interrupted, previously uncontinued 48-case matrix".into(),
        );
    }
    for (index, report) in completed.iter().enumerate() {
        if report["case"] != declared[index] {
            return Err("matrix prefix changed its declared order".into());
        }
    }
    let unfinished = case_directory(&prior, completed.len(), &declared[completed.len()])?;
    for name in [
        "accounting.json",
        "resource-samples.jsonl",
        "management-samples.jsonl",
        "application.json",
        "summary.json",
        "generator.log",
        "collection-outcome.json",
        "invalid.json",
    ] {
        if unfinished.join(name).exists() {
            return Err("refusing to replace a measured or failed matrix case".into());
        }
    }
    let prefix = inventory(&prior, completed)?;
    let mut images = Vec::new();
    for image in manifest["images"]
        .as_array()
        .ok_or("missing frozen images")?
    {
        let tag = image["tag"].as_str().ok_or("missing frozen image tag")?;
        let inspection: Value =
            serde_json::from_str(&docker(&strings(&["image", "inspect", tag]))?)?;
        for field in ["Id", "RootFS", "Architecture", "Os"] {
            if inspection[0][field] != image["inspection"][0][field] {
                return Err("frozen matrix image changed".into());
            }
        }
        images.push(ImageSnapshot {
            tag: tag.into(),
            inspection,
        });
    }
    if images.len() != 2 {
        return Err("matrix requires both frozen frontend images".into());
    }
    let environment = resume::read_json(&prior.join("environment.json"), 1_048_576)?;
    let kernel = Command::new("uname").arg("-srvm").output()?;
    if !kernel.status.success() || String::from_utf8(kernel.stdout)? != environment["kernel"] {
        return Err("continuation requires the same actual host kernel".into());
    }
    for (name, key) in [
        ("relay-bench-worker", "worker_sha256"),
        ("tunnel-detour", "service_sha256"),
        ("benchmark-driver", "driver_sha256"),
        ("source.tar", "source_archive_sha256"),
    ] {
        if digest(&prior.join(name))? != manifest[key] {
            return Err("frozen application artifact changed".into());
        }
    }
    let mut cases = Vec::new();
    for value in &declared[completed.len()..] {
        let case = Case {
            adguard: value["frontend"] == "adguard",
            rules: usize::try_from(value["rules"].as_u64().ok_or("missing rules")?)?,
            occupied: usize::try_from(
                value["initial_live_identities"]
                    .as_u64()
                    .ok_or("missing occupancy")?,
            )?,
            churn: value["http_connection_reuse"] != true,
            http_qps: value["http_qps_per_route"].as_u64().ok_or("missing rate")?,
        };
        if case.description() != *value {
            return Err("continuation cannot reproduce declared case settings".into());
        }
        cases.push(case);
    }
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    fs::copy("/proc/self/exe", output.join("benchmark-driver"))?;
    let inputs = xtask::provenance::source_inputs(root)?;
    xtask::provenance::archive_inputs(root, &inputs, &output.join("collector-source.tar"))?;
    let plan = json!({"kind":"audited matrix continuation","prior":prior,"prefix_cases":completed.len(),"prefix_evidence_sha256":prefix,"prior_manifest":manifest,"collector_source_inputs":inputs,"collector_source_sha256":digest(&output.join("collector-source.tar"))?,"collector_sha256":digest(&output.join("benchmark-driver"))?,"host_before":xtask::provenance::host_context(),"interpretation":"original complete observations remain untouched; only previously unmeasured cases collected here; no paired or causal frontend comparison"});
    fs::write(
        output.join("continuation.json"),
        serde_json::to_vec_pretty(&plan)?,
    )?;
    let context: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
    let socket = context[0]["Endpoints"]["docker"]["Host"]
        .as_str()
        .and_then(|value| value.strip_prefix("unix://"))
        .ok_or("local Docker Unix socket required")?;
    let api = Api(reqwest::Client::builder()
        .no_proxy()
        .unix_socket(socket)
        .connect_timeout(Duration::from_secs(3))
        .build()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(cancellable(collect(
        &api,
        &prior.join("relay-bench-worker"),
        &prior.join("tunnel-detour"),
        &images,
        (&cases, completed.len()),
        &output,
        Mode::Matrix,
    )));
    if inventory(&prior, completed)? != prefix {
        return Err("original matrix prefix changed during continuation".into());
    }
    resume::checkpoint(
        &output,
        &json!({"complete":result.is_ok(),"kind":"audited matrix continuation","prefix_cases":completed.len(),"remaining_cases":cases.len(),"prior":prior,"raw_aggregation":"completed.json","host_after":xtask::provenance::host_context()}),
    )?;
    if let Err(error) = &result {
        fs::write(
            output.join("invalid.json"),
            serde_json::to_vec_pretty(&json!({"error":error.to_string()}))?,
        )?;
    }
    result
}
