//! Paired process measurements of one fixed synthetic API-parser replay.
//! The fuzz runtime and parser oracles are included, never attributed to service QPS.

use super::*;
use std::{fs, time::Instant};

pub fn run(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    before: &Path,
    after: &Path,
    input: &Path,
) -> Result {
    let activity = activity_lock(&cargo_target(cargo, root)?)?;
    for path in [before, after, input] {
        if !fs::symlink_metadata(path)?.is_file() {
            return Err("API replay inputs must be regular files".into());
        }
    }
    if fs::metadata(input)?.len() > 4 * 1024 * 1024 {
        return Err("API replay exceeds the HTTP boundary".into());
    }
    let execution_abi = executable::matching(before, after)?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    fs::copy(before, output.join("before"))?;
    fs::copy(after, output.join("after"))?;
    fs::copy(input, output.join("input.json"))?;
    for variant in ["before", "after"] {
        if digest(&output.join(variant))? != execution_abi[variant]["sha256"] {
            return Err("API replay executable changed after ABI qualification".into());
        }
    }
    fs::copy("/proc/self/exe", output.join("benchmark-driver"))?;
    let inputs = xtask::provenance::source_inputs(root)?;
    xtask::provenance::archive_inputs(root, &inputs, &output.join("producer-source.tar"))?;
    let mut random = analysis::Random::new(20_261_112);
    let first_before = random.index(2)? == 0;
    let plan = json!({
        "seed":20261112,"repetitions":7,"before_first":(0..7).map(|index| (index%2==0)==first_before).collect::<Vec<_>>(),
        "before_sha256":digest(&output.join("before"))?,"after_sha256":digest(&output.join("after"))?,"input_sha256":digest(&output.join("input.json"))?,
        "driver_sha256":digest(&output.join("benchmark-driver"))?,"source_inputs":inputs,
        "execution_abi":execution_abi,
        "scope":"x86_64 instrumented API fuzz target plus startup/oracles; one fixed replay per fresh process; no production QPS, exclusive heap or physical-hardware claim",
        "limits":{"seconds":15,"fuzzer_rss_mib":512,"input_bytes":4194304,"per_input_seconds":10},
        "measurement":"GNU time process user/system CPU and maximum RSS; outer monotonic wall time includes timeout/time wrappers; CPU resolution is 10 ms",
        "arguments":["-runs=1","-seed=20261112","-max_len=4194304","-rss_limit_mb=512","-timeout=10","-verbosity=0","input.json"]
    });
    fs::write(output.join("plan.json"), serde_json::to_vec_pretty(&plan)?)?;
    let mut pairs = Vec::new();
    for repetition in 0..7 {
        let mut reports = serde_json::Map::new();
        let before_first = plan["before_first"][repetition] == true;
        for variant in if before_first {
            ["before", "after"]
        } else {
            ["after", "before"]
        } {
            let path = output.join(format!("{repetition}-{variant}"));
            fs::create_dir(&path)?;
            let context = xtask::provenance::host_context();
            let started = Instant::now();
            let status = Command::new("timeout").current_dir(&output)
                // The fixed replay reads input.json, never stdin. Passing this
                // open lock description keeps a new campaign excluded until
                // the bounded child exits even if its controller is killed.
                .stdin(Stdio::from(activity.try_clone()?))
                .args(["--kill-after=2","15","/usr/bin/time","--output"])
                .arg(path.join("time.json"))
                .args(["--format",r#"{"user_seconds":%U,"system_seconds":%S,"maximum_rss_kib":%M,"exit_code":%x}"#])
                .arg(output.join(variant))
                .args(["-runs=1","-seed=20261112","-max_len=4194304","-rss_limit_mb=512","-timeout=10","-verbosity=0","input.json"])
                .stdout(fs::File::create(path.join("stdout.log"))?)
                .stderr(fs::File::create(path.join("stderr.log"))?).status()?;
            let wall = started.elapsed().as_secs_f64();
            if !status.success() {
                fs::write(
                    output.join("invalid.json"),
                    serde_json::to_vec_pretty(
                        &json!({"repetition":repetition,"variant":variant,"exit_code":status.code(),"wall_seconds":wall,"raw_directory":path.file_name(),"error":"API replay process failed or timed out; all raw output retained"}),
                    )?,
                )?;
                return Err("API replay failed; partial measurements retained".into());
            }
            let time: Value = serde_json::from_slice(&fs::read(path.join("time.json"))?)?;
            let report = json!({"time":time,"wall_seconds":wall,"host_before":context,"host_after":xtask::provenance::host_context(),"process_success":status.success()});
            fs::write(
                path.join("report.json"),
                serde_json::to_vec_pretty(&report)?,
            )?;
            if !status.success() || time["exit_code"] != 0 {
                fs::write(
                    output.join("invalid.json"),
                    serde_json::to_vec_pretty(
                        &json!({"repetition":repetition,"variant":variant,"report":report}),
                    )?,
                )?;
                return Err("API replay failed; partial measurements retained".into());
            }
            reports.insert(variant.into(), report);
        }
        pairs.push(json!({"repetition":repetition,"reports":reports}));
        fs::write(
            output.join("pairs.json"),
            serde_json::to_vec_pretty(&pairs)?,
        )?;
    }
    for variant in ["before", "after"] {
        if digest(&output.join(variant))? != plan[format!("{variant}_sha256")] {
            return Err("API replay executable changed during collection".into());
        }
    }
    if digest(&output.join("input.json"))? != plan["input_sha256"] {
        return Err("API replay input changed during collection".into());
    }
    let mut comparisons = Vec::new();
    for metric in ["cpu_seconds", "maximum_rss_kib", "wall_seconds"] {
        let mut absolute = Vec::new();
        let mut relative = Vec::new();
        let mut before_values = Vec::new();
        let mut after_values = Vec::new();
        for pair in &pairs {
            let measure = |variant: &str| -> Result<f64> {
                let report = &pair["reports"][variant];
                if metric == "wall_seconds" {
                    return report[metric]
                        .as_f64()
                        .ok_or("missing replay wall time".into());
                }
                if metric == "cpu_seconds" {
                    return Ok(report["time"]["user_seconds"]
                        .as_f64()
                        .ok_or("missing user CPU")?
                        + report["time"]["system_seconds"]
                            .as_f64()
                            .ok_or("missing system CPU")?);
                }
                report["time"][metric]
                    .as_f64()
                    .ok_or("missing replay resource".into())
            };
            let before = measure("before")?;
            let after = measure("after")?;
            if !before.is_finite() || before < 0.0 || !after.is_finite() || after < 0.0 {
                return Err("invalid replay resource value".into());
            }
            absolute.push(after - before);
            if before > 0.0 {
                relative.push((after - before) / before * 100.0);
            }
            before_values.push(before);
            after_values.push(after);
        }
        let average = |values: &[f64]| values.iter().sum::<f64>() / 7.0;
        comparisons.push(json!({"metric":metric,"before_mean":average(&before_values),"after_mean":average(&after_values),"after_minus_before_mean":average(&absolute),"absolute_uncorrected_ci95":analysis::interval(&absolute,&mut random)?,"paired_relative_percent_mean":(relative.len()==7).then(||average(&relative)),"relative_uncorrected_ci95":if relative.len()==7 {Some(analysis::interval(&relative,&mut random)?)} else {None},"relative_scope":"unavailable if any baseline is zero, including CPU rounded below GNU time resolution"}));
    }
    fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(
            &json!({"complete":true,"scope":plan["scope"],"comparisons":comparisons,"inference":"conditional paired-run bootstrap intervals on this shared x86 host; instrumented process results, not application latency or an exclusive-allocation measure"}),
        )?,
    )?;
    Ok(())
}
