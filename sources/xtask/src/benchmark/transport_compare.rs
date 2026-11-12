//! Ten descriptive before/after pairs, with byte-identical load actors.

use super::*;
use std::fs;

pub(crate) fn run(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    before_directory: &Path,
    after: &Path,
    supplemental_duplex: bool,
) -> Result {
    let target = cargo_target(cargo, root)?;
    let _activity = activity_lock(&target)?;
    let before_directory = before_directory.canonicalize()?;
    let before = before_directory.join("relay-bench-worker");
    let original = resume::read_json(&before_directory.join("provenance.json"), 4 * 1024 * 1024)?;
    let original_plan = resume::read_json(&before_directory.join("plan.json"), 1024 * 1024)?;
    let original_summary =
        resume::read_json(&before_directory.join("summary.json"), 4 * 1024 * 1024)?;
    if original_summary["complete"] != true
        || original_plan["worker_sha256"] != digest(&before)?
        || original["source_archive_sha256"] != digest(&before_directory.join("source.tar"))?
    {
        return Err("before worker/source identities contradict the original freeze".into());
    }
    for worker in [&before, after] {
        if !fs::symlink_metadata(worker)?.is_file() || !prepared_worker(worker)? {
            return Err("comparison requires regular protocol-2 frozen workers".into());
        }
    }
    let image = freeze_image(
        original["image_tag"]
            .as_str()
            .ok_or("missing before image")?,
        "transport-comparison",
    )?;
    if image.inspection[0]["Id"] != original["image"] {
        return Err("the original image tag changed identity".into());
    }
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    let inputs = xtask::provenance::source_inputs(root)?;
    xtask::provenance::archive_inputs(root, &inputs, &output.join("after-source.tar"))?;
    fs::copy(
        before_directory.join("source.tar"),
        output.join("before-source.tar"),
    )?;
    if digest(&output.join("before-source.tar"))? != original["source_archive_sha256"] {
        return Err("before source archive changed during freezing".into());
    }
    fs::copy(
        before_directory.join("provenance.json"),
        output.join("before-provenance.json"),
    )?;
    fs::copy("/proc/self/exe", output.join("benchmark-driver"))?;
    for (name, worker) in [("before-worker", before.as_path()), ("after-worker", after)] {
        let expected = digest(worker)?;
        fs::copy(worker, output.join(name))?;
        if digest(&output.join(name))? != expected {
            return Err("worker changed during freezing".into());
        }
    }
    let before = output.join("before-worker");
    let after = output.join("after-worker");
    let cases: Vec<_> = cases()
        .into_iter()
        .enumerate()
        .filter(|(_, case)| {
            !supplemental_duplex || (case.workload == "duplex" && case.connections == 32)
        })
        .collect();
    let count = cases.len();
    let first_before = analysis::Random::new(20_261_112).index(2)? == 0;
    let plan = json!({
        "kind":if supplemental_duplex {"one independent supplemental duplex/c32 pair; never replaces the original interrupted attempt"} else {"ten representative before/after Rust relay pairs"},
        "seed":20261112,"cases":cases.iter().map(|(_,case)|case.description()).collect::<Vec<_>>(),
        "original_case_indices":cases.iter().map(|(index,_)|*index).collect::<Vec<_>>(),
        "before_first":cases.iter().map(|(index,_)|(*index%2==0)==first_before).collect::<Vec<_>>(),
        "before_worker_sha256":digest(&before)?,"after_worker_sha256":digest(&after)?,
        "actor_worker_sha256":digest(&before)?,"image":image.inspection[0]["Id"],"image_tag":image.tag,
        "source_inputs":inputs,"before_source_sha256":digest(&output.join("before-source.tar"))?,
        "after_source_sha256":digest(&output.join("after-source.tar"))?,
        "driver_sha256":digest(&output.join("benchmark-driver"))?,
        "generator_network":RETAINED_GENERATOR_NETWORK,
        "build_contract":"same pinned Rust, release profile and x86_64-unknown-linux-musl target; retain build logs separately",
        "inference":"one pair per coordinate, descriptive changes without cross-run intervals; no universal winner or physical-hardware claim",
        "actors":"before worker supplies identical origin/generator/observer bytes for both relay treatments"
    });
    fs::write(output.join("plan.json"), serde_json::to_vec_pretty(&plan)?)?;
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
    let mut pairs = Vec::new();
    resume::checkpoint(&output, &json!({"complete":false,"pairs":pairs}))?;
    for (sequence, (index, spec)) in cases.into_iter().enumerate() {
        let directory = output.join(format!(
            "{index:02}-{}-c{}",
            spec.workload, spec.connections
        ));
        fs::create_dir(&directory)?;
        let mut treatments = serde_json::Map::new();
        let mut pair_context = None;
        for treatment in if plan["before_first"][sequence] == true {
            ["before", "after"]
        } else {
            ["after", "before"]
        } {
            for (path, key) in [
                (&before, "before_worker_sha256"),
                (&after, "after_worker_sha256"),
            ] {
                if digest(path)? != plan[key] {
                    return Err("frozen worker changed".into());
                }
            }
            let destination = directory.join(treatment);
            fs::create_dir(&destination)?;
            println!(
                "Comparison {}/{count}: {} c{}, {treatment}",
                sequence + 1,
                spec.workload,
                spec.connections
            );
            let measured = runtime.block_on(measure_workers(
                &api,
                Workers {
                    relay: if treatment == "before" {
                        &before
                    } else {
                        &after
                    },
                    actors: &before,
                    rust_only: true,
                },
                &destination,
                spec,
                &image,
                None,
                true,
            ));
            let summaries = match measured {
                Ok(summaries) => summaries,
                Err(error) => {
                    fs::write(
                        output.join("invalid.json"),
                        serde_json::to_vec_pretty(&json!({
                            "case":index,"treatment":treatment,"error":error.to_string(),"retained":true
                        }))?,
                    )?;
                    return Err(error);
                }
            };
            if summaries.len() != 1 || summaries[0]["variant"] != "rust" {
                return Err("unexpected comparison treatment".into());
            }
            let manifest = resume::read_json(&destination.join("manifest.json"), 1024 * 1024)?;
            let raw = resume::read_json(&destination.join("rust.json"), 64 * 1024 * 1024)?;
            validate_generator_network(&plan, &manifest, Some(&raw))?;
            if manifest["actor_worker_sha256"] != plan["actor_worker_sha256"]
                || manifest["worker_sha256"] != plan[format!("{treatment}_worker_sha256")]
                || manifest["image"] != plan["image"]
            {
                return Err("load actor identity changed".into());
            }
            let mut common = resume::context(&manifest);
            common
                .as_object_mut()
                .ok_or("invalid comparison context")?
                .remove("worker_sha256");
            let observed = json!({"manifest":common,"tcp_parameters":raw["tcp_parameters"]});
            if pair_context
                .as_ref()
                .is_some_and(|expected| *expected != observed)
            {
                return Err("before/after operational context changed".into());
            }
            pair_context = Some(observed);
            treatments.insert(treatment.into(), summaries[0].clone());
        }
        pairs.push(json!({"case":spec.description(),"results":treatments}));
        resume::checkpoint(&output, &json!({"complete":false,"pairs":pairs}))?;
    }
    if xtask::provenance::source_inputs(root)? != inputs {
        return Err("source inputs changed during measurement".into());
    }
    for (path, key) in [
        (&before, "before_worker_sha256"),
        (&after, "after_worker_sha256"),
    ] {
        if digest(path)? != plan[key] {
            return Err("frozen worker changed during measurement".into());
        }
    }
    resume::checkpoint(
        &output,
        &json!({"complete":true,"pairs":pairs,"inference":plan["inference"]}),
    )?;
    Ok(())
}

fn cases() -> Vec<Scenario<'static>> {
    let mut cases = Vec::new();
    for workload in ["latency", "churn", "upload", "download", "duplex"] {
        for connections in [1, 32] {
            cases.push(Scenario {
                prepared: true,
                observation: Observation::BoundaryOnly,
                workload,
                connections,
                message_bytes: match workload {
                    "latency" if connections == 1 => 64,
                    "latency" => 1024,
                    "churn" => 256,
                    _ => 0,
                },
                window: if workload == "churn" {
                    Measurement::Cycles {
                        warmup: 1024,
                        measured: 8192,
                    }
                } else {
                    Measurement::Timed {
                        warmup: 5,
                        seconds: 20,
                    }
                },
                reverse: false,
                repetition: 0,
            });
        }
    }
    cases
}

/// Rederive only completed pairs. An interrupted tail never becomes a sample.
pub(crate) fn audit(directory: &Path) -> Result {
    let plan = resume::read_json(&directory.join("plan.json"), 4 * 1024 * 1024)?;
    let summary = resume::read_json(&directory.join("summary.json"), 4 * 1024 * 1024)?;
    let indices: Vec<usize> = match plan.get("original_case_indices") {
        None => (0..10).collect(),
        Some(value) if *value == json!([9]) => vec![9],
        Some(value) if *value == json!((0..10).collect::<Vec<_>>()) => (0..10).collect(),
        _ => return Err("unknown comparison selection".into()),
    };
    let cases = cases();
    let expected = json!(
        indices
            .iter()
            .map(|index| cases[*index].description())
            .collect::<Vec<_>>()
    );
    let first_before = analysis::Random::new(20_261_112).index(2)? == 0;
    let order = json!(
        indices
            .iter()
            .map(|index| (*index % 2 == 0) == first_before)
            .collect::<Vec<_>>()
    );
    if plan["cases"] != expected
        || plan["generator_network"] != RETAINED_GENERATOR_NETWORK
        || plan["seed"] != 20261112
        || plan["before_first"] != order
    {
        return Err("comparison changed its declared workload or network policy".into());
    }
    for (file, key) in [
        ("before-worker", "before_worker_sha256"),
        ("after-worker", "after_worker_sha256"),
        ("before-source.tar", "before_source_sha256"),
        ("after-source.tar", "after_source_sha256"),
        ("benchmark-driver", "driver_sha256"),
    ] {
        if digest(&directory.join(file))? != plan[key] {
            return Err("frozen comparison input changed".into());
        }
    }
    let pairs = summary["pairs"]
        .as_array()
        .ok_or("missing comparison pairs")?;
    if pairs.len() > indices.len() || (summary["complete"] == true && pairs.len() != indices.len())
    {
        return Err("comparison completion contradicts its original pair count".into());
    }
    for (index, pair) in pairs.iter().enumerate() {
        if pair["case"] != expected[index] {
            return Err("comparison changed a completed coordinate".into());
        }
        let case = &pair["case"];
        let original_index = indices[index];
        let path = directory.join(format!(
            "{original_index:02}-{}-c{}",
            case["workload"].as_str().ok_or("missing workload")?,
            case["connections"]
                .as_u64()
                .ok_or("missing connection count")?
        ));
        let mut context = None;
        for treatment in ["before", "after"] {
            let path = path.join(treatment);
            let manifest = resume::read_json(&path.join("manifest.json"), 1024 * 1024)?;
            let raw = resume::read_json(&path.join("rust.json"), 64 * 1024 * 1024)?;
            let completed = resume::read_json(&path.join("summary.json"), 1024 * 1024)?;
            validate_generator_network(&plan, &manifest, Some(&raw))?;
            let derived = summarize_report(&raw)?;
            if manifest["worker_sha256"] != plan[format!("{treatment}_worker_sha256")]
                || manifest["actor_worker_sha256"] != plan["actor_worker_sha256"]
                || manifest["image"] != plan["image"]
                || raw["normal_shutdown"]["state"]["ExitCode"] != 0
                || completed["pair_complete"] != true
                || completed["results"] != json!([derived.clone()])
                || pair["results"][treatment] != derived
            {
                return Err(
                    "completed comparison contradicts its raw acceptance or frozen inputs".into(),
                );
            }
            let mut common = resume::context(&manifest);
            common
                .as_object_mut()
                .ok_or("invalid comparison context")?
                .remove("worker_sha256");
            let observed = json!({"manifest":common,"tcp_parameters":raw["tcp_parameters"]});
            if context.as_ref().is_some_and(|value| *value != observed) {
                return Err("comparison treatments changed their operational context".into());
            }
            context = Some(observed);
        }
    }
    println!(
        "Verified {} of {} declared before/after pairs; complete={}; interrupted artifacts are not samples; no existing observation was modified",
        pairs.len(),
        indices.len(),
        summary["complete"]
    );
    Ok(())
}
