//! Continue a complete campaign prefix without rebuilding or replacing observations.

use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Write},
};

pub(super) fn read_json(path: &Path, limit: u64) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("campaign input is not a bounded regular file".into());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Only case coordinates and image provenance may differ. All operational
/// settings, executable hashes, packages and the actual host kernel must match.
pub(super) fn context(manifest: &Value) -> Value {
    let mut value = manifest.clone();
    if let Some(fields) = value.as_object_mut() {
        for field in [
            "image",
            "image_tag",
            "image_layers",
            "workload",
            "connections",
            "message_bytes",
            "repetition",
            "order",
            "window",
            "bulk_block_bytes",
        ] {
            fields.remove(field);
        }
    }
    value
}

fn case_path(output: &Path, index: usize, case: Scenario<'_>) -> PathBuf {
    output.join(format!(
        "{index:03}-{}-c{:02}-b{:04}",
        case.workload, case.connections, case.message_bytes
    ))
}

struct Prefix {
    pairs: Vec<Value>,
    failures: Vec<Value>,
    next_index: usize,
    context: Value,
    images: BTreeSet<String>,
    observations: BTreeMap<PathBuf, String>,
}

/// Publish aggregate progress atomically so interruption cannot truncate it.
pub(super) fn checkpoint(output: &Path, summary: &Value) -> Result {
    let mut temporary = tempfile::NamedTempFile::new_in(output)?;
    temporary.write_all(&serde_json::to_vec_pretty(summary)?)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(output.join("summary.json"))
        .map_err(|error| error.error)?;
    fs::File::open(output)?.sync_all()?;
    Ok(())
}

fn first_difference(saved: &Value, derived: &Value) -> Option<String> {
    if saved == derived {
        return None;
    }
    match (saved, derived) {
        (Value::Object(a), Value::Object(b)) if a.keys().eq(b.keys()) => {
            a.iter().find_map(|(key, value)| {
                first_difference(value, &b[key]).map(|difference| format!("/{key}{difference}"))
            })
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            a.iter().zip(b).enumerate().find_map(|(index, (a, b))| {
                first_difference(a, b).map(|difference| format!("/{index}{difference}"))
            })
        }
        (Value::Number(a), Value::Number(b)) => Some(format!(": saved={a}, derived={b}")),
        _ => Some(": structure or nonnumeric value differs".into()),
    }
}

fn audit(
    output: &Path,
    cases: &[Scenario<'_>],
    worker_hash: &str,
    verify_only: bool,
    retain_failures: bool,
) -> Result<Prefix> {
    let plan = read_json(&output.join("plan.json"), 1_048_576)?;
    retained_generator_network(&plan)?;
    let expected: Vec<_> = cases.iter().map(Scenario::description).collect();
    if plan["kind"] != "paired campaign"
        || plan["seed"] != 20_261_110
        || plan["cases"] != json!(expected)
        || plan["worker_sha256"] != worker_hash
    {
        return Err(
            "the frozen worker or campaign plan differs; existing results remain unchanged".into(),
        );
    }
    let summary = read_json(&output.join("summary.json"), 16 * 1_048_576)?;
    let pairs = summary["completed_pairs"]
        .as_array()
        .ok_or("missing complete prefix")?;
    let complete = summary["complete"] == true;
    if summary["kind"] != "paired campaign"
        || summary["complete"] != json!(complete)
        || summary["campaign_complete"] != json!(complete)
        || summary["measurements_complete"] != json!(pairs.len() == cases.len())
        || (complete && pairs.len() != cases.len())
        || output.join("invalid.json").exists()
    {
        return Err("the campaign completion state is inconsistent or invalid".into());
    }
    if complete && !verify_only {
        return Err("a complete campaign can only be audited with --verify-only".into());
    }
    if pairs.is_empty() || pairs.len() > cases.len() {
        return Err("a continuation requires a nonempty complete prefix".into());
    }
    let recorded_failures = match summary.get("failed_cases") {
        None => 0,
        Some(value) => value.as_array().ok_or("invalid failure checkpoint")?.len(),
    };
    let recorded_attempts = pairs
        .len()
        .checked_add(recorded_failures)
        .ok_or("attempt count overflow")?;
    if recorded_attempts > cases.len()
        || summary
            .get("observations_complete")
            .is_some_and(|value| *value != json!(recorded_attempts == cases.len()))
    {
        return Err("attempted-case completion state is inconsistent".into());
    }
    let mut baseline = None;
    let mut images = BTreeSet::new();
    let mut observations = BTreeMap::new();
    let mut failures = Vec::new();
    let mut pair_index = 0;
    let mut next_index = 0;
    for (index, spec) in cases.iter().copied().enumerate() {
        let path = case_path(output, index, spec);
        if retain_failures && path.join("invalid.json").try_exists()? {
            if index != next_index {
                return Err("a failed case cannot conceal an unattempted gap".into());
            }
            let invalid = read_json(&path.join("invalid.json"), 1_048_576)?;
            let manifest = read_json(&path.join("manifest.json"), 1_048_576)?;
            validate_generator_network(&plan, &manifest, None)?;
            if invalid["valid"] != false
                || invalid["case"] != expected[index]
                || invalid["reason"].as_str().is_none_or(str::is_empty)
                || manifest["worker_sha256"] != worker_hash
                || path.join("summary.json").exists()
            {
                return Err("a retained failed case has inconsistent evidence".into());
            }
            for field in [
                "workload",
                "connections",
                "message_bytes",
                "repetition",
                "window",
                "prepared_generator",
            ] {
                if manifest[field] != expected[index][field] {
                    return Err("failed case changed its declared coordinates".into());
                }
            }
            let failed_context = context(&manifest);
            if baseline
                .as_ref()
                .is_some_and(|value| *value != failed_context)
            {
                return Err("failed case changed its frozen operational context".into());
            }
            baseline = Some(failed_context);
            images.insert(
                manifest["image"]
                    .as_str()
                    .ok_or("missing failed-case image identity")?
                    .to_owned(),
            );
            for entry in fs::read_dir(&path)? {
                let file = entry?.path();
                if !fs::symlink_metadata(&file)?.is_file() {
                    return Err("failed-case evidence must be regular files".into());
                }
                observations.insert(file.strip_prefix(output)?.to_path_buf(), digest(&file)?);
            }
            failures.push(json!({"case_index":index,"case":expected[index],"artifact":path.file_name(),"reason":invalid["reason"],"interpretation":"attempt retained as failed; never resampled or included as a successful pair"}));
            next_index = index + 1;
            continue;
        }
        if pair_index >= pairs.len() {
            if path.try_exists()? {
                return Err(
                    "an unfinished case already exists; preserve and review it before continuing"
                        .into(),
                );
            }
            continue;
        }
        let pair = &pairs[pair_index];
        let saved = read_json(&path.join("summary.json"), 1_048_576)?;
        if pair["case"] != expected[index]
            || saved["pair_complete"] != true
            || pair["results"] != saved["results"]
            || path.join("invalid.json").exists()
        {
            return Err("the saved prefix contains an incomplete or inconsistent pair".into());
        }
        let manifest = read_json(&path.join("manifest.json"), 1_048_576)?;
        validate_generator_network(&plan, &manifest, None)?;
        for field in [
            "workload",
            "connections",
            "message_bytes",
            "repetition",
            "window",
            "prepared_generator",
        ] {
            if manifest[field] != expected[index][field] {
                return Err("a saved manifest belongs to another planned case".into());
            }
        }
        let order = if spec.reverse {
            ["socat", "rust"]
        } else {
            ["rust", "socat"]
        };
        if manifest["order"] != json!(order)
            || manifest["worker_sha256"] != worker_hash
            || manifest["bulk_block_bytes"]
                != if spec.echo() {
                    Value::Null
                } else {
                    json!(16384)
                }
        {
            return Err("the saved pair changed order, worker or bulk framing".into());
        }
        images.insert(
            manifest["image"]
                .as_str()
                .ok_or("missing image identity")?
                .to_owned(),
        );
        let actual_context = context(&manifest);
        if baseline
            .as_ref()
            .is_some_and(|value| *value != actual_context)
        {
            return Err("completed pairs have incompatible operational contexts".into());
        }
        baseline = Some(actual_context);
        let mut derived = Vec::new();
        for variant in order {
            let report = read_json(&path.join(format!("{variant}.json")), 64 * 1_048_576)?;
            if report["case"] != expected[index] || report["variant"] != variant {
                return Err("a raw report belongs to another case or variant".into());
            }
            validate_generator_network(&plan, &manifest, Some(&report))?;
            let state = &report["normal_shutdown"]["state"];
            let exit = state["ExitCode"]
                .as_i64()
                .ok_or("missing normal shutdown")?;
            if state["Running"] != false
                || state["OOMKilled"] != false
                || (exit != 0 && !(variant == "socat" && exit == 143))
            {
                return Err("a saved relay did not finish its normal shutdown".into());
            }
            derived.push(summarize_report(&report)?);
        }
        if saved["results"] != json!(derived) {
            return Err(format!(
                "saved summaries cannot be reproduced from their raw reports at pair {index}{}",
                first_difference(&saved["results"], &json!(derived))
                    .ok_or("missing summary difference")?
            )
            .into());
        }
        for file in ["manifest.json", "rust.json", "socat.json", "summary.json"] {
            let file = path.join(file);
            observations.insert(file.strip_prefix(output)?.to_path_buf(), digest(&file)?);
        }
        pair_index += 1;
        next_index = index + 1;
    }
    if pair_index != pairs.len() {
        return Err("saved successful pairs are missing from the declared sequence".into());
    }
    if let Some(saved_failures) = summary.get("failed_cases")
        && !failures.starts_with(
            saved_failures
                .as_array()
                .ok_or("invalid failure checkpoint")?,
        )
    {
        return Err("retained failures changed since the saved checkpoint".into());
    }
    // Reject unexpected numeric case directories as well as the canonical next
    // one: changing a name must never conceal an unfinished or foreign sample.
    let expected_names: BTreeSet<_> = cases
        .iter()
        .copied()
        .take(next_index)
        .enumerate()
        .filter_map(|(index, spec)| {
            case_path(output, index, spec)
                .file_name()
                .map(|name| name.to_owned())
        })
        .collect();
    for entry in fs::read_dir(output)? {
        let name = entry?.file_name();
        let value = name.to_string_lossy();
        if value.as_bytes().get(3) == Some(&b'-')
            && value.as_bytes()[..3].iter().all(u8::is_ascii_digit)
            && !expected_names.contains(&name)
        {
            return Err("an unexpected case artifact prevents continuation".into());
        }
    }
    Ok(Prefix {
        pairs: pairs.clone(),
        failures,
        next_index,
        context: baseline.ok_or("missing baseline")?,
        images,
        observations,
    })
}

/// An explicit local build log must pair each index with the same config digest.
/// OCI indexes may differ solely because of build attestations. Never infer
/// equivalence from installed package names alone.
fn image_proof(path: Option<&Path>, required: &BTreeSet<String>) -> Result<Vec<(PathBuf, Value)>> {
    let Some(path) = path else {
        return if required.len() == 1 {
            Ok(Vec::new())
        } else {
            Err("different OCI indexes require an explicit image export proof".into())
        };
    };
    let proof = read_json(path, 1_048_576)?;
    let exports = proof["build_exports"]
        .as_object()
        .ok_or("missing build exports")?;
    let mut configs = BTreeMap::new();
    let mut logs = Vec::new();
    for (log, declared) in exports {
        let log = path.parent().ok_or("proof needs a parent")?.join(log);
        let metadata = fs::symlink_metadata(&log)?;
        if !metadata.is_file() || metadata.len() > 16 * 1_048_576 {
            return Err("image export proof needs a bounded regular build log".into());
        }
        let mut text = String::new();
        fs::File::open(&log)?
            .take(16 * 1_048_576 + 1)
            .read_to_string(&mut text)?;
        let mut stages = BTreeMap::new();
        let mut confirmed = false;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if let [stage, "exporting", "config", digest, ..] = fields.as_slice() {
                stages.insert(*stage, *digest);
            }
            if let [stage, "exporting", "manifest", "list", index, ..] = fields.as_slice()
                && declared["manifest list"] == *index
                && stages
                    .get(stage)
                    .is_some_and(|digest| declared["config"] == *digest)
            {
                confirmed = true;
            }
        }
        let index = declared["manifest list"]
            .as_str()
            .ok_or("missing export index")?;
        let config = declared["config"].as_str().ok_or("missing export config")?;
        if !confirmed
            || configs
                .insert(index.to_owned(), config.to_owned())
                .is_some_and(|old| old != config)
        {
            return Err("an image export declaration is missing, ambiguous or contradicted by its build log".into());
        }
        logs.push((log, declared.clone()));
    }
    let cohort: BTreeSet<_> = required
        .iter()
        .map(|index| {
            configs
                .get(index)
                .ok_or("an observed image is absent from the verified export proof")
        })
        .collect::<std::result::Result<_, _>>()?;
    if cohort.len() != 1 {
        return Err("the campaign images do not share one OCI config digest".into());
    }
    Ok(logs)
}

pub fn run(cargo: &std::ffi::OsStr, root: &Path, args: &[OsString]) -> Result {
    let mut output = None;
    let mut image_ref = None;
    let mut proof = None;
    let mut verify_only = false;
    let mut retain_failures = false;
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--output") if output.is_none() => {
                output = Some(PathBuf::from(arguments.next().ok_or("missing output")?))
            }
            Some("--image") if image_ref.is_none() => {
                image_ref = Some(
                    arguments
                        .next()
                        .ok_or("missing local image")?
                        .to_str()
                        .ok_or("image must be UTF-8")?
                        .to_owned(),
                )
            }
            Some("--image-proof") if proof.is_none() => {
                proof = Some(PathBuf::from(
                    arguments.next().ok_or("missing image proof")?,
                ))
            }
            Some("--verify-only") if !verify_only => verify_only = true,
            Some("--retain-failed-cases") if !retain_failures => retain_failures = true,
            _ => return Err("unknown or repeated continuation option".into()),
        }
    }
    let output = output
        .ok_or("an existing output directory is required")?
        .canonicalize()?;
    let image_ref = image_ref
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or("an explicit existing local image is required")?;
    let target = cargo_target(cargo, root)?;
    let controller = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(target.join("x86_64-unknown-linux-musl/release/relay-benchmark.lock"))?;
    controller
        .try_lock()
        .map_err(|error| format!("cannot start another relay benchmark controller: {error}"))?;
    let activity = activity_lock(&target)?;
    let worker = output.join("relay-bench-worker");
    if !fs::symlink_metadata(&worker)?.is_file() {
        return Err("the frozen worker must be a regular file".into());
    }
    let worker_hash = digest(&worker)?;
    let plan = read_json(&output.join("plan.json"), 1_048_576)?;
    let mut cases = campaign_cases_for(Observation::from_plan(&plan)?)?;
    let retain_generator_network = retained_generator_network(&plan)?;
    match plan.get("prepared_generator") {
        None => {}
        Some(Value::Bool(true)) => {
            for case in &mut cases {
                case.prepared = true;
            }
        }
        _ => return Err("invalid frozen generator preparation policy".into()),
    }
    let mut prefix = audit(&output, &cases, &worker_hash, verify_only, retain_failures)?;
    if prefix.next_index == cases.len() && !verify_only {
        return Err(
            "all declared cases were attempted; use --verify-only to audit the retained outcome"
                .into(),
        );
    }
    let inspection: Value =
        serde_json::from_str(&docker(&strings(&["image", "inspect", &image_ref]))?)?;
    let image_id = inspection[0]["Id"]
        .as_str()
        .ok_or("missing local image identity")?;
    let mut required = prefix.images.clone();
    required.insert(image_id.to_owned());
    let logs = image_proof(proof.as_deref(), &required)?;
    println!(
        "Verified {} complete pairs, frozen worker and image cohort; no existing observation was modified",
        prefix.pairs.len()
    );
    if !prefix.failures.is_empty() {
        println!(
            "Retained {} FAILED cases; none will be resampled or count as a successful pair",
            prefix.failures.len()
        );
    }
    if verify_only {
        return Ok(());
    }
    let history = output.join("continuations");
    fs::create_dir_all(&history)?;
    let session = tempfile::Builder::new()
        .prefix("session-")
        .tempdir_in(&history)?
        .keep();
    let mut archived = serde_json::Map::new();
    for (index, (log, declaration)) in logs.iter().enumerate() {
        let name = format!("export-{index:03}.log");
        fs::copy(log, session.join(&name))?;
        archived.insert(name, declaration.clone());
    }
    fs::write(
        session.join("image-proof.json"),
        serde_json::to_vec_pretty(&json!({"build_exports":archived}))?,
    )?;
    fs::copy(&worker, session.join("relay-bench-worker"))?;
    let worker = session.join("relay-bench-worker");
    if digest(&worker)? != worker_hash {
        return Err("the frozen worker changed while being copied".into());
    }
    fs::copy("/proc/self/exe", session.join("benchmark-driver"))?;
    let collector_inputs = xtask::provenance::source_inputs(root)?;
    xtask::provenance::archive_inputs(
        root,
        &collector_inputs,
        &session.join("collector-source.tar"),
    )?;
    let image = freeze_image(&image_ref, "continued-relay")?;
    if image.inspection[0]["Id"] != image_id {
        return Err("the image changed during continuation preparation".into());
    }
    fs::copy(
        output.join("summary.json"),
        session.join("prefix-summary.json"),
    )?;
    fs::write(
        session.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "kind":"explicit campaign continuation","first_case_index":prefix.next_index,
            "retained_failed_cases":prefix.failures,"collector_source_inputs":collector_inputs,
            "collector_source_archive_sha256":digest(&session.join("collector-source.tar"))?,
            "started_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            "worker_sha256":worker_hash,"driver_sha256":digest(&session.join("benchmark-driver"))?,
            "image":image.inspection[0],"previous_image_indexes":prefix.images,
            "previous_raw_files":"preserved; summaries were rederived and compared before continuation",
            "interruption":"controller absent; cause unknown; wall-clock gap is not a measured sample",
            "context":prefix.context,"preserved_observation_sha256":prefix.observations
        }))?,
    )?;
    drop(activity);
    let connection: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
    let socket = connection[0]["Endpoints"]["docker"]["Host"]
        .as_str()
        .and_then(|value| value.strip_prefix("unix://"))
        .ok_or("a local Docker Unix socket is required")?;
    let api = Api(reqwest::Client::builder()
        .no_proxy()
        .unix_socket(socket)
        .connect_timeout(Duration::from_secs(3))
        .build()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for (index, spec) in cases.iter().copied().enumerate().skip(prefix.next_index) {
        let _activity = activity_lock(&target)?;
        let directory = case_path(&output, index, spec);
        fs::create_dir(&directory)?;
        println!(
            "Continued measurement {}/{}: {}, {} connections",
            index + 1,
            cases.len(),
            spec.workload,
            spec.connections
        );
        let result = runtime.block_on(measure(
            &api,
            &worker,
            &directory,
            spec,
            &image,
            Some(&prefix.context),
            retain_generator_network,
        ));
        match result {
            Ok(results) => prefix
                .pairs
                .push(json!({"case":spec.description(),"results":results})),
            Err(error) => {
                fs::write(
                    directory.join("invalid.json"),
                    serde_json::to_vec_pretty(
                        &json!({"valid":false,"reason":error.to_string(),"case":spec.description()}),
                    )?,
                )?;
                return Err(error);
            }
        }
        checkpoint(
            &output,
            &json!({"kind":"paired campaign","complete":false,"campaign_complete":false,"measurements_complete":prefix.failures.is_empty() && index+1==cases.len(),"observations_complete":index+1==cases.len(),"completed_pairs":prefix.pairs,"failed_cases":prefix.failures}),
        )?;
    }
    for (file, expected) in &prefix.observations {
        if digest(&output.join(file))? != *expected {
            return Err(
                "an earlier observation changed during continuation; completion is refused".into(),
            );
        }
    }
    let (comparable, omitted) = complete_groups(&prefix.pairs)?;
    if !comparable.is_empty() {
        analysis::write(&output, &comparable, true)?;
        let mut comparison = read_json(&output.join("comparison.json"), 16_777_216)?;
        comparison["failed_cases"] = json!(prefix.failures);
        comparison["omitted_incomplete_groups"] = json!(omitted);
        fs::write(
            output.join("comparison.json"),
            serde_json::to_vec_pretty(&comparison)?,
        )?;
        if !prefix.failures.is_empty() {
            let table = fs::read_to_string(output.join("comparison.md"))?;
            fs::write(
                output.join("comparison.md"),
                format!(
                    "This campaign contains {} FAILED cases. No failed attempt was repeated or treated as success. Estimates exclude every workload/capacity/message group without seven valid pairs; see comparison.json for the failed attempts and omitted groups. The campaign is not a passing 196-pair qualification.\n\n{table}",
                    prefix.failures.len()
                ),
            )?;
        }
    }
    checkpoint(
        &output,
        &json!({"kind":"paired campaign","complete":prefix.failures.is_empty(),"campaign_complete":prefix.failures.is_empty(),"measurements_complete":prefix.failures.is_empty(),"observations_complete":true,"completed_pairs":prefix.pairs,"failed_cases":prefix.failures,"omitted_incomplete_groups":omitted}),
    )?;
    if !prefix.failures.is_empty() {
        return Err("all declared cases were attempted, with retained failures; campaign qualification remains FAILED".into());
    }
    Ok(())
}

/// Never manufacture a seven-run estimate from a six-run group after a failure.
fn complete_groups(pairs: &[Value]) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for pair in pairs {
        let case = &pair["case"];
        let key = serde_json::to_string(&json!([
            case["workload"],
            case["connections"],
            case["message_bytes"]
        ]))?;
        groups.entry(key).or_default().push(pair.clone());
    }
    let mut comparable = Vec::new();
    let mut omitted = Vec::new();
    for (coordinate, group) in groups {
        if group.len() == 7 {
            comparable.extend(group);
        } else {
            omitted.push(json!({"coordinate":serde_json::from_str::<Value>(&coordinate)?,"valid_pairs":group.len(),"expected_pairs":7,"interpretation":"no confidence interval or point estimate; all raw successful and failed attempts retained"}));
        }
    }
    Ok((comparable, omitted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r103b_failed_repetition_excludes_the_entire_incomplete_group_from_estimates() -> Result {
        let mut pairs = Vec::new();
        for repetition in 0..7 {
            pairs.push(json!({"case":{"workload":"latency","connections":1,"message_bytes":64,"repetition":repetition}}));
            if repetition != 4 {
                pairs.push(json!({"case":{"workload":"churn","connections":4,"message_bytes":256,"repetition":repetition}}));
            }
        }
        let (valid, omitted) = complete_groups(&pairs)?;
        assert_eq!(valid.len(), 7);
        assert!(
            valid
                .iter()
                .all(|pair| pair["case"]["workload"] == "latency")
        );
        assert_eq!(omitted.len(), 1);
        assert_eq!(omitted[0]["valid_pairs"], 6);
        assert_eq!(omitted[0]["coordinate"], json!(["churn", 4, 256]));
        Ok(())
    }

    #[test]
    fn r104_reopening_metric_json_preserves_finite_f64_sign_exponent_and_mantissa_bits() -> Result {
        for sign in [0, 1_u64 << 63] {
            for exponent in 0..2047_u64 {
                for mantissa in [0, 1, (1_u64 << 52) / 3, (1_u64 << 52) - 1] {
                    let bits = sign | (exponent << 52) | mantissa;
                    let original = f64::from_bits(bits);
                    let bytes = serde_json::to_vec(&json!({"metric":original}))?;
                    let restored: Value = serde_json::from_slice(&bytes)?;
                    assert_eq!(
                        restored["metric"]
                            .as_f64()
                            .ok_or("missing finite metric")?
                            .to_bits(),
                        bits,
                        "a stored finite metric changed on reopening: IEEE bits {bits:016x}"
                    );
                }
            }
        }
        Ok(())
    }
}
