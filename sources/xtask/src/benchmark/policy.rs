//! Fresh-process confirmation of warm core policy, separate from network DNS.

use super::*;
use std::{collections::BTreeMap, fs};

#[derive(Clone, Copy, Debug, PartialEq)]
struct Cell {
    cpu_nanoseconds_per_query: f64,
    wall_nanoseconds_per_query: f64,
}

type Reduced = BTreeMap<(u64, u64), Cell>;

// The outer fresh-process pair is the independent sample. Its seven internal
// observations are averaged here, before any paired confidence interval.
fn reduce(report: &Value) -> Result<Reduced> {
    if report["complete"] != true {
        return Err("warm-policy worker did not complete its declared observations".into());
    }
    let rows = report["cases"]
        .as_array()
        .ok_or("missing policy observations")?;
    if rows.len() != 63 {
        return Err("warm-policy worker must retain all 63 internal observations".into());
    }
    let mut groups: BTreeMap<(u64, u64), BTreeMap<u64, Cell>> = BTreeMap::new();
    for row in rows {
        let number = |key: &str| -> Result<u64> {
            row[key]
                .as_u64()
                .ok_or_else(|| format!("invalid policy {key}").into())
        };
        let rules = number("rules")?;
        let allocated = number("allocated")?;
        let repetition = number("repetition")?;
        let cpu = number("cpu_nanoseconds")?;
        let wall = number("wall_nanoseconds")?;
        if ![1, 16, 128].contains(&rules)
            || ![1, 512, 4096].contains(&allocated)
            || repetition >= 7
            || number("queries")? != 100_000
            || row["durable_state_unchanged"] != true
            || cpu == 0
            || wall == 0
        {
            return Err(
                "warm-policy observation contradicts its declared fixture or outcome".into(),
            );
        }
        let cell = Cell {
            cpu_nanoseconds_per_query: cpu as f64 / 100_000.0,
            wall_nanoseconds_per_query: wall as f64 / 100_000.0,
        };
        if groups
            .entry((rules, allocated))
            .or_default()
            .insert(repetition, cell)
            .is_some()
        {
            return Err("duplicate warm-policy internal repetition".into());
        }
    }
    if groups.len() != 9 || groups.values().any(|values| values.len() != 7) {
        return Err("missing warm-policy coordinate or internal repetition".into());
    }
    Ok(groups
        .into_iter()
        .map(|(coordinate, observations)| {
            let cell = Cell {
                cpu_nanoseconds_per_query: observations
                    .values()
                    .map(|value| value.cpu_nanoseconds_per_query)
                    .sum::<f64>()
                    / 7.0,
                wall_nanoseconds_per_query: observations
                    .values()
                    .map(|value| value.wall_nanoseconds_per_query)
                    .sum::<f64>()
                    / 7.0,
            };
            (coordinate, cell)
        })
        .collect())
}

fn cells_json(cells: &Reduced) -> Value {
    json!(cells.iter().map(|(&(rules, allocated), cell)| {
        json!({"rules":rules,"allocated":allocated,"cpu_nanoseconds_per_query":cell.cpu_nanoseconds_per_query,"wall_nanoseconds_per_query":cell.wall_nanoseconds_per_query})
    }).collect::<Vec<_>>())
}

pub fn run(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    before: &Path,
    after: &Path,
    before_source: &Path,
) -> Result {
    let activity = activity_lock(&cargo_target(cargo, root)?)?;
    for path in [before, after] {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err("warm-policy workers must be regular files".into());
        }
    }
    let execution_abi = executable::matching(before, after)?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    for (variant, source) in [("before", before), ("after", after)] {
        let expected = digest(source)?;
        if execution_abi[variant]["sha256"] != expected {
            return Err("warm-policy executable changed after ABI qualification".into());
        }
        fs::copy(source, output.join(variant))?;
        if digest(&output.join(variant))? != expected {
            return Err("warm-policy worker changed while being frozen".into());
        }
    }
    fs::copy("/proc/self/exe", output.join("benchmark-driver"))?;
    let inputs = xtask::provenance::source_inputs(root)?;
    xtask::provenance::archive_inputs(root, &inputs, &output.join("producer-source.tar"))?;
    let before_inputs = xtask::provenance::source_inputs(before_source)?;
    xtask::provenance::archive_inputs(
        before_source,
        &before_inputs,
        &output.join("before-source.tar"),
    )?;
    // A policy worker retains these beside its executable. They identify the
    // original completed run, not new observations to pool into confirmation.
    let original_manifest = fs::read(before.with_file_name("manifest.json"))?;
    let original_results = fs::read(before.with_file_name("results.json"))?;
    let original: Value = serde_json::from_slice(&original_manifest)?;
    if original["source_inputs"] != before_inputs {
        return Err("original before-worker source graph no longer matches its checkout".into());
    }
    reduce(&serde_json::from_slice(&original_results)?)?;
    fs::write(
        output.join("before-original-manifest.json"),
        original_manifest,
    )?;
    fs::write(
        output.join("before-original-results.json"),
        original_results,
    )?;
    let mut random = analysis::Random::new(20_261_112);
    let first_before = random.index(2)? == 0;
    let plan = json!({
        "seed":20261112,"outer_pairs":7,"internal_repetitions_per_coordinate":7,
        "before_first":(0..7).map(|index|(index%2==0)==first_before).collect::<Vec<_>>(),
        "before_sha256":digest(&output.join("before"))?,"after_sha256":digest(&output.join("after"))?,
        "driver_sha256":digest(&output.join("benchmark-driver"))?,"source_inputs":inputs,
        "source_archive_sha256":digest(&output.join("producer-source.tar"))?,
        "execution_abi":execution_abi,
        "before_source_inputs":before_inputs,"before_source_archive_sha256":digest(&output.join("before-source.tar"))?,
        "before_original_manifest_sha256":digest(&output.join("before-original-manifest.json"))?,
        "before_original_results_sha256":digest(&output.join("before-original-results.json"))?,
        "scope":"warm pure core policy, synthetic durable identities; no network, frontend QPS or physical-hardware claim",
        "coordinates":{"rules":[1,16,128],"allocated":[1,512,4096]},
        "warmup_per_internal_observation":10000,"queries_per_internal_observation":100000,
        "process_timeout_seconds":120,
        "statistical_unit":"one fresh-process pair; average seven internal repetitions within each process before paired inference",
        "measurement":"worker monotonic wall and CLOCK_PROCESS_CPUTIME_ID around decision loop; fixture creation and process startup excluded; cumulative boundary RSS is context only"
    });
    fs::write(output.join("plan.json"), serde_json::to_vec_pretty(&plan)?)?;
    let mut paired_values = Vec::new();
    let mut pairs = Vec::new();
    for repetition in 0..7 {
        let before_first = plan["before_first"][repetition] == true;
        let mut reports = serde_json::Map::new();
        let mut observations = BTreeMap::new();
        for variant in if before_first {
            ["before", "after"]
        } else {
            ["after", "before"]
        } {
            let directory = output.join(format!("{repetition}-{variant}"));
            fs::create_dir(&directory)?;
            let host_before = xtask::provenance::host_context();
            let status = Command::new("timeout")
                .current_dir(root)
                // Keep campaign exclusion owned by the bounded worker even if
                // this collector is terminated. The worker never reads stdin.
                .stdin(Stdio::from(activity.try_clone()?))
                .args(["--kill-after=2", "120"])
                .arg(output.join(variant))
                .arg("--output")
                .arg(directory.join("worker"))
                .stdout(fs::File::create(directory.join("stdout.log"))?)
                .stderr(fs::File::create(directory.join("stderr.log"))?)
                .status()?;
            let host_after = xtask::provenance::host_context();
            let observed = (|| -> Result<Reduced> {
                if !status.success() {
                    return Err("warm-policy worker failed or timed out".into());
                }
                let manifest: Value =
                    serde_json::from_slice(&fs::read(directory.join("worker/manifest.json"))?)?;
                if manifest["iterations_per_case"] != 100000
                    || manifest["warmup_per_case"] != 10000
                    || manifest["repetitions"] != 7
                    || manifest["source_inputs"]
                        != plan[if variant == "before" {
                            "before_source_inputs"
                        } else {
                            "source_inputs"
                        }]
                    || digest(&directory.join("worker/policy-bench-worker"))?
                        != plan[format!("{variant}_sha256")]
                {
                    return Err("warm-policy worker contract or executed binary contradicts the frozen plan".into());
                }
                let raw: Value =
                    serde_json::from_slice(&fs::read(directory.join("worker/results.json"))?)?;
                reduce(&raw)
            })();
            let report = json!({"process_success":status.success(),"exit_code":status.code(),"host_before":host_before,"host_after":host_after,"arguments":["--output",directory.join("worker")]});
            fs::write(
                directory.join("process.json"),
                serde_json::to_vec_pretty(&report)?,
            )?;
            let cells = match observed {
                Ok(cells) => cells,
                Err(error) => {
                    fs::write(
                        output.join("invalid.json"),
                        serde_json::to_vec_pretty(
                            &json!({"repetition":repetition,"variant":variant,"error":error.to_string(),"raw_directory":directory.file_name(),"retained":true}),
                        )?,
                    )?;
                    return Err(error);
                }
            };
            reports.insert(
                variant.into(),
                json!({"process":report,"coordinate_means":cells_json(&cells)}),
            );
            observations.insert(variant, cells);
        }
        paired_values.push((
            observations
                .remove("before")
                .ok_or("missing before policy process")?,
            observations
                .remove("after")
                .ok_or("missing after policy process")?,
        ));
        pairs.push(json!({"repetition":repetition,"reports":reports}));
        fs::write(
            output.join("pairs.json"),
            serde_json::to_vec_pretty(&pairs)?,
        )?;
    }
    for variant in ["before", "after"] {
        if digest(&output.join(variant))? != plan[format!("{variant}_sha256")] {
            return Err("warm-policy executable changed during collection".into());
        }
    }
    let mut comparisons = Vec::new();
    for rules in [1, 16, 128] {
        for allocated in [1, 512, 4096] {
            for metric in ["cpu_nanoseconds_per_query", "wall_nanoseconds_per_query"] {
                let mut before_values = Vec::new();
                let mut after_values = Vec::new();
                let mut absolute = Vec::new();
                let mut relative = Vec::new();
                for (before, after) in &paired_values {
                    let value = |cells: &Reduced| -> Result<f64> {
                        let cell = cells
                            .get(&(rules, allocated))
                            .ok_or("missing reduced policy coordinate")?;
                        Ok(if metric == "cpu_nanoseconds_per_query" {
                            cell.cpu_nanoseconds_per_query
                        } else {
                            cell.wall_nanoseconds_per_query
                        })
                    };
                    let before = value(before)?;
                    let after = value(after)?;
                    before_values.push(before);
                    after_values.push(after);
                    absolute.push(after - before);
                    relative.push((after / before - 1.0) * 100.0);
                }
                let mean = |values: &[f64]| values.iter().sum::<f64>() / 7.0;
                comparisons.push(json!({"rules":rules,"allocated":allocated,"metric":metric,"outer_pairs":7,
                    "before_means":before_values,"after_means":after_values,
                    "before_mean":mean(&before_values),"after_mean":mean(&after_values),
                    "paired_difference_mean":mean(&absolute),"paired_difference_ci95":analysis::interval(&absolute,&mut random)?,
                    "paired_relative_percent_mean":mean(&relative),"paired_relative_percent_ci95":analysis::interval(&relative,&mut random)?}));
            }
        }
    }
    fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(
            &json!({"complete":true,"scope":plan["scope"],"comparisons":comparisons,"inference":"seven independent outer process pairs, internal repetitions averaged; uncorrected paired bootstrap intervals conditional on this shared x86 host, no application or ARM64 speedup claim"}),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r151_warm_policy_reduction_averages_internal_runs_and_refuses_corrupt_coverage() -> Result {
        let mut rows = Vec::new();
        for rules in [1, 16, 128] {
            for allocated in [1, 512, 4096] {
                for repetition in 0..7 {
                    rows.push(
                        json!({"rules":rules,"allocated":allocated,"repetition":repetition,
                        "queries":100000,"cpu_nanoseconds":(repetition+1)*100000,
                        "wall_nanoseconds":(repetition+1)*200000,"durable_state_unchanged":true}),
                    );
                }
            }
        }
        let report = json!({"complete":true,"cases":rows});
        let reduced = reduce(&report)?;
        assert_eq!(reduced.len(), 9);
        assert!(reduced.values().all(|cell| *cell
            == Cell {
                cpu_nanoseconds_per_query: 4.0,
                wall_nanoseconds_per_query: 8.0
            }));
        for change in [
            "missing",
            "duplicate",
            "foreign_coordinate",
            "changed_state",
            "wrong_volume",
            "incomplete",
        ] {
            let mut corrupt = report.clone();
            match change {
                "missing" => {
                    corrupt["cases"]
                        .as_array_mut()
                        .ok_or("missing test rows")?
                        .pop()
                        .ok_or("missing test tail")?;
                }
                "duplicate" => corrupt["cases"][1] = corrupt["cases"][0].clone(),
                "foreign_coordinate" => corrupt["cases"][0]["allocated"] = json!(2),
                "changed_state" => corrupt["cases"][0]["durable_state_unchanged"] = json!(false),
                "wrong_volume" => corrupt["cases"][0]["queries"] = json!(99999),
                "incomplete" => corrupt["complete"] = json!(false),
                _ => return Err("unknown test change".into()),
            }
            assert!(
                reduce(&corrupt).is_err(),
                "corrupt policy coverage accepted: {change}"
            );
        }
        Ok(())
    }
}
