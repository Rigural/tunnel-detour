//! Paired observer perturbation. Requests are not independent statistical replicates.

use super::*;
use std::collections::BTreeMap;

fn captured_json(base: &Path, name: &str, hashes: &mut BTreeMap<String, String>) -> Result<Value> {
    let path = base.join(name);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err("observer input is not a bounded regular file".into());
    }
    let before = digest(&path)?;
    let value = resume::read_json(&path, 64 * 1024 * 1024)?;
    if digest(&path)? != before {
        return Err("observer input changed while reading".into());
    }
    hashes.insert(name.into(), before);
    Ok(value)
}

fn case_directory(index: usize, case: &Value) -> Result<String> {
    let workload = case["workload"]
        .as_str()
        .ok_or("missing observer workload")?;
    let connections = case["connections"]
        .as_u64()
        .ok_or("missing observer connections")?;
    let message = message_bytes(case)?;
    if !matches!(
        (workload, connections, message),
        ("latency", 4, 256) | ("duplex", 32, 0) | ("churn", 32, 256)
    ) {
        return Err("observer case is outside the qualified matrix".into());
    }
    Ok(format!(
        "{index:03}-{workload}-c{connections:02}-b{message:04}"
    ))
}

fn message_bytes(case: &Value) -> Result<u64> {
    match case.get("message_bytes") {
        Some(Value::Null) if case["workload"] == "duplex" => Ok(0),
        Some(Value::Number(value)) => value.as_u64().ok_or("invalid observer message size".into()),
        _ => Err("missing or invalid observer message size".into()),
    }
}

fn observation(case: &Value) -> Result<Observation> {
    match case.get("observation") {
        None => Ok(Observation::Full),
        Some(value) if value == "boundary_only" => Ok(Observation::BoundaryOnly),
        _ => Err("unknown observation treatment in the frozen plan".into()),
    }
}

fn context(manifest: &Value, tcp_parameters: &Value) -> Result<Value> {
    let mut common = resume::context(manifest);
    let fields = common
        .as_object_mut()
        .ok_or("observer manifest is not an object")?;
    for field in [
        "observation",
        "periodic_cgroup_sampling",
        "process_sampling",
        "executable_pages",
    ] {
        fields.remove(field);
    }
    for field in ["uid", "capabilities"] {
        fields
            .get_mut(field)
            .and_then(Value::as_object_mut)
            .ok_or("missing observer actor boundary")?
            .remove("observer");
    }
    // Unlike an explicit interrupted campaign, this collection has one frozen
    // image. An alternate image index is not silently accepted as equivalent.
    common["image"] = manifest["image"].clone();
    common["tcp_parameters"] = tcp_parameters.clone();
    Ok(common)
}

fn archive_checkpoint(
    base: &Path,
    session: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result {
    let expected = hashes
        .get("summary.json")
        .ok_or("missing checkpoint input hash")?
        .clone();
    let snapshot = session.join("producer-checkpoint.json");
    std::fs::copy(base.join("summary.json"), &snapshot)?;
    if digest(&snapshot)? != expected {
        return Err("producer checkpoint changed before its archival copy".into());
    }
    let name = snapshot
        .strip_prefix(base)?
        .to_str()
        .ok_or("invalid checkpoint snapshot path")?
        .to_owned();
    hashes.remove("summary.json");
    hashes.insert(name, expected);
    Ok(())
}

/// Validate every raw report before estimating the paired observer effect.
/// Refusals do not replace raw data or create an analysis directory.
pub(crate) fn analyze(cargo: &std::ffi::OsStr, root: &Path, directory: &Path) -> Result {
    use std::fs::{self, OpenOptions};
    let target = cargo_target(cargo, root)?;
    let release = target.join("x86_64-unknown-linux-musl/release");
    fs::create_dir_all(&release)?;
    let controller = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(release.join("relay-benchmark.lock"))?;
    controller
        .try_lock()
        .map_err(|_| "cannot analyze while a benchmark controller is active")?;
    let activity = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(target.join("validation-load.lock"))?;
    activity
        .try_lock()
        .map_err(|_| "cannot analyze while another laboratory is active")?;
    let directory = directory.canonicalize()?;
    let mut hashes = BTreeMap::new();
    let plan = captured_json(&directory, "plan.json", &mut hashes)?;
    retained_generator_network(&plan)?;
    let mut checkpoint = captured_json(&directory, "summary.json", &mut hashes)?;
    let provenance = captured_json(&directory, "provenance.json", &mut hashes)?;
    let cases = plan["cases"].as_array().ok_or("missing observer plan")?;
    let completed = checkpoint["completed_pairs"]
        .as_array()
        .ok_or("missing observer observations")?;
    if plan["kind"] != "paired observer qualification"
        || plan["seed"] != 20_261_114
        || cases.len() != 42
        || completed.len() != cases.len()
        || checkpoint["measurements_complete"] != true
    {
        return Err(
            "observer collection is not the complete frozen seven-repetition matrix".into(),
        );
    }
    let worker = directory.join("relay-bench-worker");
    if !fs::symlink_metadata(&worker)?.is_file() {
        return Err("frozen observer worker is not a regular file".into());
    }
    let worker_hash = digest(&worker)?;
    if plan["worker_sha256"] != worker_hash {
        return Err("frozen observer worker differs from the collected plan".into());
    }
    hashes.insert("relay-bench-worker".into(), worker_hash.clone());
    type Key = (String, u64, u64, String);
    let mut groups: BTreeMap<Key, BTreeMap<u8, Pair>> = BTreeMap::new();
    let mut reference_context = None;
    let mut footprints = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        if completed[index]["case"] != *case {
            return Err("observer checkpoint case differs from the frozen plan".into());
        }
        let treatment = observation(case)?;
        let path = case_directory(index, case)?;
        let manifest = captured_json(&directory, &format!("{path}/manifest.json"), &mut hashes)?;
        validate_generator_network(&plan, &manifest, None)?;
        let saved = captured_json(&directory, &format!("{path}/summary.json"), &mut hashes)?;
        let reverse = case["socat_first"]
            .as_bool()
            .ok_or("missing observer implementation order")?;
        let order = if reverse {
            ["socat", "rust"]
        } else {
            ["rust", "socat"]
        };
        if manifest["worker_sha256"] != worker_hash
            || manifest["image"] != provenance["image"]
            || manifest["window"] != case["window"]
            || manifest["workload"] != case["workload"]
            || manifest["connections"] != case["connections"]
            || manifest["repetition"] != case["repetition"]
            || manifest["message_bytes"] != case["message_bytes"]
            || manifest["order"] != json!(order)
            || saved["pair_complete"] != true
        {
            return Err(
                "observer manifest or completed pair differs from the frozen treatment".into(),
            );
        }
        match treatment {
            Observation::BoundaryOnly
                if manifest["observation"] != "boundary_only"
                    || manifest["periodic_cgroup_sampling"] != false
                    || !manifest["uid"]["observer"].is_null()
                    || !manifest["capabilities"]["observer"].is_null() =>
            {
                return Err("lower-observation manifest lost its treatment identity".into());
            }
            Observation::Full if manifest.get("observation").is_some() => {
                return Err(
                    "full-observation manifest has an unexpected treatment override".into(),
                );
            }
            _ => {}
        }
        let mut derived = Vec::new();
        for variant in order {
            let raw = captured_json(&directory, &format!("{path}/{variant}.json"), &mut hashes)?;
            validate_generator_network(&plan, &manifest, Some(&raw))?;
            if raw["case"] != *case
                || raw["variant"] != variant
                || raw["observation"] != treatment.label()
            {
                return Err("raw observer observation differs from its treatment".into());
            }
            let current_context = context(&manifest, &raw["tcp_parameters"])?;
            match &reference_context {
                Some(reference) if reference != &current_context => {
                    return Err("observer operational context changed".into());
                }
                None => reference_context = Some(current_context),
                _ => {}
            }
            let summary = summarize_report(&raw)?;
            let repetition = u8::try_from(
                case["repetition"]
                    .as_u64()
                    .ok_or("missing observer repetition")?,
            )?;
            let key = (
                case["workload"].as_str().ok_or("missing workload")?.into(),
                case["connections"].as_u64().ok_or("missing connections")?,
                message_bytes(case)?,
                variant.into(),
            );
            groups
                .entry(key)
                .or_default()
                .entry(repetition)
                .or_default()
                .push(
                    treatment,
                    Run {
                        index,
                        case: case.clone(),
                        summary: summary.clone(),
                    },
                )?;
            if treatment == Observation::Full {
                let stats = &raw["observer_resources_before_stop"];
                let cpu = stats["cpu_stats"]["cpu_usage"]["total_usage"]
                    .as_u64()
                    .ok_or("observer CPU counter is missing")?;
                let memory = stats["memory_stats"]["usage"]
                    .as_u64()
                    .ok_or("observer memory counter is missing")?;
                footprints.push(json!({"case_index":index,"variant":variant,"repetition":repetition,
                    "lifetime_cpu_nanoseconds_before_stop":cpu,"cgroup_current_bytes_before_stop":memory,
                    "process_pss":null,"memory_peak":null,
                    "scope":"observer cgroup before termination; PSS and a true memory peak were not collected"}));
            } else if !raw["observer_resources_before_stop"].is_null() {
                return Err("boundary-only treatment claims an observer process".into());
            }
            derived.push(summary);
        }
        if saved["results"] != json!(derived) || completed[index]["results"] != json!(derived) {
            return Err("observer summaries cannot be reproduced from the raw observations".into());
        }
    }
    if groups.len() != 6 {
        return Err("observer collection is missing a workload/implementation group".into());
    }
    let mut rows = Vec::new();
    for ((workload, connections, message, variant), pairs) in groups {
        for mut row in estimates(&pairs)? {
            row["workload"] = json!(workload);
            row["connections"] = json!(connections);
            row["message_bytes"] = json!(message);
            row["variant"] = json!(variant);
            rows.push(row);
        }
    }
    for (name, expected) in &hashes {
        if digest(&directory.join(name))? != *expected {
            return Err("observer inputs changed during statistical analysis".into());
        }
    }
    let mut table = String::from(
        "# Observer perturbation in the isolated relay laboratory\n\nSeven paired runs per row; bootstrap intervals use runs, not requests. Full minus boundary-only includes periodic cgroup polling and the PSS observer. Boundary integrity checks, completion polling and start/end CPU counters remain. CPU includes startup, warmup and drain. Rates use the declared measurement window. Memory peaks cannot be compared with an unmeasured control. These uncorrected intervals are conditional on this x86/Docker laboratory and do not establish ARM64, full-application or Internet performance.\n\n| Workload | Variant | Metric | Full mean | Boundary mean | Paired difference (95% CI) |\n| --- | --- | --- | ---: | ---: | --- |\n",
    );
    for row in &rows {
        table.push_str(&format!(
            "| {} | {} | {} | {:.4} | {:.4} | {:.4} [{:.4}, {:.4}] |\n",
            row["workload"].as_str().ok_or("missing row workload")?,
            row["variant"].as_str().ok_or("missing row variant")?,
            row["metric"].as_str().ok_or("missing row metric")?,
            row["full_mean"].as_f64().ok_or("missing full mean")?,
            row["boundary_mean"]
                .as_f64()
                .ok_or("missing boundary mean")?,
            row["paired_full_minus_boundary_mean"]
                .as_f64()
                .ok_or("missing paired mean")?,
            row["paired_full_minus_boundary_ci95"][0]
                .as_f64()
                .ok_or("missing interval")?,
            row["paired_full_minus_boundary_ci95"][1]
                .as_f64()
                .ok_or("missing interval")?
        ));
    }
    let parent = directory.join("analyses");
    match fs::symlink_metadata(&parent) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err("analysis destination is not an owned directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&parent)?,
        Err(error) => return Err(error.into()),
    }
    let session = tempfile::Builder::new()
        .prefix("observer-")
        .tempdir_in(parent)?;
    fs::copy("/proc/self/exe", session.path().join("analysis-driver"))?;
    // The live completion marker changes after analysis. Hash its immutable
    // exact-byte snapshot so every declared input remains directly verifiable.
    archive_checkpoint(&directory, session.path(), &mut hashes)?;
    fs::write(
        session.path().join("inputs.sha256.json"),
        serde_json::to_vec_pretty(&hashes)?,
    )?;
    fs::write(
        session.path().join("results.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version":2,"complete":true,"seed":20_261_114,"bootstrap_samples":10000,"paired_repetitions":7,
            "direction":"full minus boundary-only","memory_scope":"no numerical memory-overhead estimate; the control has no memory samples",
            "context":reference_context,"rows":rows,"observer_footprints":footprints,
            "source_inventory_at_analysis":xtask::provenance::source_inputs(root)?,
            "analysis_driver_sha256":digest(&session.path().join("analysis-driver"))?,
            "inference_limit":"uncorrected paired-run intervals; conditional on this laboratory and its host drift; not full-app or ARM64 results"
        }))?,
    )?;
    fs::write(session.path().join("results.md"), table)?;
    let session = session.keep();
    checkpoint["observer_analysis_complete"] = json!(true);
    checkpoint["observer_analysis"] = json!(
        session
            .strip_prefix(&directory)?
            .to_str()
            .ok_or("invalid analysis path")?
    );
    checkpoint["complete"] = json!(true);
    resume::checkpoint(&directory, &checkpoint)?;
    println!(
        "Validated 42 raw pairs; observer analysis: {}",
        session.display()
    );
    Ok(())
}

#[derive(Clone)]
pub(super) struct Run {
    pub index: usize,
    pub case: Value,
    pub summary: Value,
}

#[derive(Clone, Default)]
pub(super) struct Pair {
    full: Option<Run>,
    boundary: Option<Run>,
}

impl Pair {
    pub(super) fn push(&mut self, observation: Observation, run: Run) -> Result {
        let slot = match observation {
            Observation::Full => &mut self.full,
            Observation::BoundaryOnly => &mut self.boundary,
        };
        if slot.is_some() {
            return Err("duplicate observation treatment in a paired repetition".into());
        }
        *slot = Some(run);
        Ok(())
    }

    pub(super) fn validated(&self) -> Result<(&Run, &Run)> {
        let full = self
            .full
            .as_ref()
            .ok_or("missing full-observation treatment")?;
        let boundary = self
            .boundary
            .as_ref()
            .ok_or("missing boundary-only treatment")?;
        if full.index.abs_diff(boundary.index) != 1 {
            return Err("observation treatments were not measured consecutively".into());
        }
        if normalized_case(&full.case)? != normalized_case(&boundary.case)? {
            return Err(
                "observation treatments have different workload, window or variant order".into(),
            );
        }
        if full.summary["variant"] != boundary.summary["variant"]
            || !matches!(full.summary["variant"].as_str(), Some("rust" | "socat"))
        {
            return Err("observation treatments refer to different relay implementations".into());
        }
        Ok((full, boundary))
    }
}

fn normalized_case(case: &Value) -> Result<Value> {
    let mut case = case.clone();
    case.as_object_mut()
        .ok_or("observer case is not an object")?
        .remove("observation");
    Ok(case)
}

/// Estimate only metrics present in both treatments. Unmeasured memory peaks
/// must never become a zero-valued control or a purported memory improvement.
fn validated_repetitions(pairs: &BTreeMap<u8, Pair>) -> Result<&str> {
    if pairs.len() != 7 || !pairs.keys().copied().eq(0..7) {
        return Err("observer estimates require seven complete paired repetitions".into());
    }
    let mut reference = None;
    let mut workload = None;
    let mut orders = [[0_u8; 2]; 2];
    for (repetition, pair) in pairs {
        let (full, boundary) = pair.validated()?;
        if full.case["repetition"].as_u64() != Some(u64::from(*repetition)) {
            return Err("observer repetition does not match its recorded coordinate".into());
        }
        let mut common = normalized_case(&full.case)?;
        let fields = common
            .as_object_mut()
            .ok_or("observer case is not an object")?;
        fields.remove("repetition");
        fields.remove("socat_first");
        // Variant is a property of the paired metric, not a workload field.
        // Keep it in the cohort check so it cannot change between repetitions.
        let common = json!({"case":common,"variant":full.summary["variant"]});
        let boundary_first = usize::from(boundary.index < full.index);
        let socat_first = usize::from(
            full.case["socat_first"]
                .as_bool()
                .ok_or("missing variant order")?,
        );
        orders[boundary_first][socat_first] += 1;
        match &reference {
            Some(reference) if reference != &common => {
                return Err("observer workload or window changed between repetitions".into());
            }
            None => {
                reference = Some(common);
                workload = full.case["workload"].as_str();
            }
            _ => {}
        }
    }
    if orders
        .iter()
        .flatten()
        .any(|count| !(1..=2).contains(count))
    {
        return Err("observer and implementation orders are not independently balanced".into());
    }
    workload.ok_or_else(|| "missing observer workload".into())
}

pub(super) fn estimates(pairs: &BTreeMap<u8, Pair>) -> Result<Vec<Value>> {
    let workload = validated_repetitions(pairs)?;
    let mut metrics = vec![
        "cpu_nanoseconds_including_warmup_and_drain",
        "cpu_seconds_per_gib_including_warmup_and_drain",
    ];
    metrics.extend_from_slice(match workload {
        "latency" => &[
            "rtt_p50_microseconds",
            "rtt_p95_microseconds",
            "rtt_p99_microseconds",
            "exchanges_per_second",
        ],
        "churn" => &[
            "connection_cycle_p50_microseconds",
            "connection_cycle_p95_microseconds",
            "connection_cycle_p99_microseconds",
            "cpu_microseconds_per_completed_cycle_including_warmup_and_drain",
            "exchanges_per_second",
        ],
        "duplex" => &[
            "upload_received_bytes_per_second",
            "download_received_bytes_per_second",
        ],
        _ => return Err("unsupported observer qualification workload".into()),
    });
    let mut random = analysis::Random::new(20_261_114);
    let mut rows = Vec::new();
    for metric in metrics {
        let mut full_values = Vec::new();
        let mut boundary_values = Vec::new();
        for pair in pairs.values() {
            let (full, boundary) = pair.validated()?;
            for (run, values) in [(full, &mut full_values), (boundary, &mut boundary_values)] {
                let value = analysis::metric(&run.summary, metric)
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .ok_or("required observer metric is missing, negative or nonfinite")?;
                values.push(value);
            }
        }
        let differences: Vec<_> = full_values
            .iter()
            .zip(&boundary_values)
            .map(|(full, boundary)| full - boundary)
            .collect();
        let relative: Option<Vec<_>> = full_values
            .iter()
            .zip(&boundary_values)
            .map(|(full, boundary)| (*boundary > 0.0).then(|| (full / boundary - 1.0) * 100.0))
            .collect();
        let mean = |values: &[f64]| values.iter().sum::<f64>() / 7.0;
        let relative_interval = relative
            .as_ref()
            .map(|values| analysis::interval(values, &mut random))
            .transpose()?;
        rows.push(json!({
            "metric":metric,"full_runs":full_values,"boundary_runs":boundary_values,
            "full_mean":mean(&full_values),"boundary_mean":mean(&boundary_values),
            "paired_full_minus_boundary_mean":mean(&differences),
            "paired_full_minus_boundary_ci95":analysis::interval(&differences,&mut random)?,
            "paired_relative_percent_mean":relative.as_ref().map(|values|mean(values)),
            "paired_relative_percent_ci95":relative_interval,
        }));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(index: usize) -> Run {
        Run {
            index,
            case: json!({"workload":"latency","connections":4,"message_bytes":256,
                "repetition":0,"socat_first":false,"window":{"kind":"timed","warmup_seconds":2,"measured_seconds":10}}),
            summary: json!({"variant":"rust"}),
        }
    }

    #[test]
    fn r141_observer_pairing_refuses_missing_duplicate_nonadjacent_or_changed_treatments() -> Result
    {
        let mut pair = Pair::default();
        pair.push(Observation::Full, run(0))?;
        assert!(
            pair.validated().is_err(),
            "one treatment was treated as a pair"
        );
        assert!(
            pair.push(Observation::Full, run(1)).is_err(),
            "a duplicate treatment replaced a run"
        );
        let mut boundary = run(1);
        boundary.case["observation"] = json!("boundary_only");
        pair.push(Observation::BoundaryOnly, boundary)?;
        pair.validated()?;
        let mut changed = pair.clone();
        changed
            .boundary
            .as_mut()
            .ok_or("missing test treatment")?
            .index = 2;
        assert!(changed.validated().is_err(), "nonadjacent runs were paired");
        for (field, value) in [
            (
                "window",
                json!({"kind":"timed","warmup_seconds":2,"measured_seconds":20}),
            ),
            ("socat_first", json!(true)),
            ("connections", json!(32)),
        ] {
            let mut changed = pair.clone();
            changed
                .boundary
                .as_mut()
                .ok_or("missing test treatment")?
                .case[field] = value;
            assert!(
                changed.validated().is_err(),
                "different {field} was accepted within a pair"
            );
        }
        let mut changed = pair.clone();
        changed
            .boundary
            .as_mut()
            .ok_or("missing test treatment")?
            .summary["variant"] = json!("socat");
        assert!(
            changed.validated().is_err(),
            "different implementations were paired"
        );
        let incomplete = BTreeMap::from([(0, pair)]);
        assert!(
            estimates(&incomplete).is_err(),
            "an incomplete set gained a seven-run estimate"
        );
        let mut balanced = BTreeMap::new();
        for repetition in 0_u8..7 {
            let mut pair = Pair::default();
            let start = usize::from(repetition) * 2;
            let mut full = run(start + usize::from(repetition % 2 != 0));
            let mut boundary = run(start + usize::from(repetition % 2 == 0));
            for run in [&mut full, &mut boundary] {
                run.case["repetition"] = json!(repetition);
                run.case["socat_first"] = json!(repetition % 4 >= 2);
            }
            pair.push(Observation::Full, full)?;
            pair.push(Observation::BoundaryOnly, boundary)?;
            balanced.insert(repetition, pair);
        }
        validated_repetitions(&balanced)?;
        let mut changed = balanced.clone();
        let pair = changed.get_mut(&1).ok_or("missing paired repetition")?;
        for run in [&mut pair.full, &mut pair.boundary] {
            run.as_mut().ok_or("missing test treatment")?.summary["variant"] = json!("socat");
        }
        assert!(
            validated_repetitions(&changed).is_err(),
            "implementation changed between repetitions"
        );
        for pair in balanced.values_mut() {
            let full = pair.full.as_mut().ok_or("missing test treatment")?;
            let boundary = pair.boundary.as_mut().ok_or("missing test treatment")?;
            if full.index > boundary.index {
                std::mem::swap(&mut full.index, &mut boundary.index);
            }
        }
        assert!(
            validated_repetitions(&balanced).is_err(),
            "all full-observation runs were measured first"
        );
        Ok(())
    }

    #[test]
    fn r142_archived_inputs_remain_verifiable_after_analysis_updates_the_live_checkpoint() -> Result
    {
        let root = tempfile::tempdir()?;
        let checkpoint = root.path().join("summary.json");
        let original = b"{\"complete\":false,\"measurements_complete\":true}\n";
        std::fs::write(&checkpoint, original)?;
        let mut hashes = BTreeMap::from([("summary.json".into(), digest(&checkpoint)?)]);
        let session = root.path().join("analysis");
        std::fs::create_dir(&session)?;
        archive_checkpoint(root.path(), &session, &mut hashes)?;
        std::fs::write(&checkpoint, b"{\"complete\":true}\n")?;
        assert!(
            !hashes.contains_key("summary.json"),
            "mutable progress metadata remained an immutable input"
        );
        for (name, expected) in &hashes {
            assert_eq!(
                digest(&root.path().join(name))?,
                *expected,
                "archived input hash no longer verifies"
            );
        }
        assert_eq!(
            std::fs::read(session.join("producer-checkpoint.json"))?,
            original,
            "archival reserialization changed the producer's exact bytes"
        );
        let mut changed = BTreeMap::from([("summary.json".into(), "0".repeat(64))]);
        assert!(
            archive_checkpoint(root.path(), &session, &mut changed).is_err(),
            "a changed checkpoint gained an archival identity"
        );
        Ok(())
    }
}
