//! Paired-run statistics. Individual messages are never independent CI samples.

use super::{Observation, Result, Value, json};
use std::{collections::BTreeMap, path::Path};

pub(super) struct Random(u64);
impl Random {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub(super) fn index(&mut self, length: usize) -> Result<usize> {
        if length == 0 {
            return Err("an empty sample cannot be resampled".into());
        }
        // SplitMix64; rejection avoids modulo bias for a bounded integer range.
        let bound = u64::try_from(length)?;
        let threshold = bound.wrapping_neg() % bound;
        loop {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^= value >> 31;
            if value >= threshold {
                return Ok(usize::try_from(value % bound)?);
            }
        }
    }
}

pub(super) fn interval(values: &[f64], random: &mut Random) -> Result<[f64; 2]> {
    if values.len() != 7 || values.iter().any(|value| !value.is_finite()) {
        return Err("a campaign estimate requires seven finite paired run values".into());
    }
    let mut means = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let mut total = 0.0;
        for _ in values {
            total += values[random.index(values.len())?];
        }
        means.push(total / values.len() as f64);
    }
    means.sort_by(f64::total_cmp);
    Ok([means[249], means[9749]])
}

pub(super) fn metric(value: &Value, name: &str) -> Option<f64> {
    value
        .get(name)
        .and_then(Value::as_f64)
        .or_else(|| value["resources"].get(name).and_then(Value::as_f64))
}

pub(super) fn write(output: &Path, pairs: &[Value], continued: bool) -> Result {
    let observation =
        Observation::from_plan(&pairs.first().ok_or("missing comparison pairs")?["case"])?;
    for pair in pairs {
        if Observation::from_plan(&pair["case"])? != observation {
            return Err("comparison analysis cannot pool observation policies".into());
        }
    }
    type Key = (String, u64, u64, String);
    let mut groups: BTreeMap<Key, Vec<(u64, f64, f64)>> = BTreeMap::new();
    let mut csv = String::from(
        "workload,connections,message_bytes,repetition,metric,rust,socat,rust_minus_socat,relative_percent\n",
    );
    for pair in pairs {
        let case = &pair["case"];
        let workload = case["workload"].as_str().ok_or("missing workload")?;
        let connections = case["connections"].as_u64().ok_or("missing capacity")?;
        let bytes = case["message_bytes"].as_u64().unwrap_or_default();
        let repetition = case["repetition"].as_u64().ok_or("missing repetition")?;
        let results = pair["results"].as_array().ok_or("missing paired results")?;
        if results.len() != 2 {
            return Err("a comparative pair must have exactly two variants".into());
        }
        let rust = results
            .iter()
            .find(|value| value["variant"] == "rust")
            .ok_or("missing Rust variant")?;
        let socat = results
            .iter()
            .find(|value| value["variant"] == "socat")
            .ok_or("missing socat variant")?;
        for name in [
            "rtt_p50_microseconds",
            "rtt_p95_microseconds",
            "rtt_p99_microseconds",
            "connection_cycle_p50_microseconds",
            "connection_cycle_p95_microseconds",
            "connection_cycle_p99_microseconds",
            "upload_received_bytes_per_second",
            "download_received_bytes_per_second",
            "exchanges_per_second",
            "cpu_seconds_per_gib_including_warmup_and_drain",
            "cpu_microseconds_per_completed_cycle_including_warmup_and_drain",
            "sampled_process_pss_peak_kib",
            "sampled_cgroup_peak_bytes",
        ] {
            if (name == "upload_received_bytes_per_second" && workload == "download")
                || (name == "download_received_bytes_per_second" && workload == "upload")
            {
                continue;
            }
            let (Some(a), Some(b)) = (metric(rust, name), metric(socat, name)) else {
                continue;
            };
            if !a.is_finite() || !b.is_finite() || a < 0.0 || b < 0.0 {
                return Err("nonfinite or negative campaign metric".into());
            }
            groups
                .entry((workload.into(), connections, bytes, name.into()))
                .or_default()
                .push((repetition, a, b));
            let relative = if b > 0.0 {
                ((a / b - 1.0) * 100.0).to_string()
            } else {
                String::new()
            };
            csv.push_str(&format!(
                "{workload},{connections},{bytes},{repetition},{name},{a},{b},{},{relative}\n",
                a - b
            ));
        }
    }
    let mut random = Random::new(20_261_110);
    let mut rows = Vec::new();
    for ((workload, connections, bytes, name), mut values) in groups {
        values.sort_by_key(|value| value.0);
        if values.len() != 7
            || values
                .iter()
                .enumerate()
                .any(|(index, value)| u64::try_from(index).ok() != Some(value.0))
        {
            return Err("campaign has missing or duplicate paired repetitions".into());
        }
        let a: Vec<_> = values.iter().map(|value| value.1).collect();
        let b: Vec<_> = values.iter().map(|value| value.2).collect();
        let differences: Vec<_> = values.iter().map(|value| value.1 - value.2).collect();
        let relative: Vec<_> = values
            .iter()
            .filter(|value| value.2 > 0.0)
            .map(|value| (value.1 / value.2 - 1.0) * 100.0)
            .collect();
        let mean = |values: &[f64]| values.iter().sum::<f64>() / values.len() as f64;
        rows.push(json!({"workload":workload,"connections":connections,"message_bytes":bytes,"metric":name,
            "rust_mean":mean(&a),"socat_mean":mean(&b),"rust_runs":a,"socat_runs":b,
            "paired_difference_mean":mean(&differences),"paired_difference_ci95":interval(&differences,&mut random)?,
            "paired_relative_percent_mean":if relative.len()==7 { Some(mean(&relative)) } else {None},
            "paired_relative_percent_ci95":if relative.len()==7 {Some(interval(&relative,&mut random)?)} else {None}}));
    }
    if rows.is_empty() {
        return Err("campaign contains no comparable metrics".into());
    }
    std::fs::write(output.join("runs.csv"), csv)?;
    let mut table = String::from(
        "# Local relay comparison\n\nDocker x86_64 only. Each row uses seven paired runs. CPU includes startup, warmup and drain; peaks are sampled. Confidence intervals are conditional on this laboratory and are not corrected for multiple comparisons. Check the direct endpoint reference before attributing a throughput ceiling to a relay. Integrated-service cost and ARM64 are separate.\n\n| Workload | Connections | Message bytes | Metric | Rust mean | socat mean | Paired difference (95% CI) |\n| --- | ---: | ---: | --- | ---: | ---: | --- |\n",
    );
    table.insert_str(0, if observation == Observation::BoundaryOnly {
        "Observation: boundary-only. Timing and CPU retain integrity/completion checks and start/end counters; memory peaks and process snapshots were not collected.\n\n"
    } else {
        "Observation: full periodic resource sampling. These timing results include observer perturbation; use a separately qualified boundary-only cohort for primary timing.\n\n"
    });
    for row in &rows {
        let string = |key: &str| -> Result<&str> {
            row[key]
                .as_str()
                .ok_or_else(|| "invalid comparison label".into())
        };
        let number = |key: &str| -> Result<f64> {
            row[key]
                .as_f64()
                .ok_or_else(|| "invalid comparison number".into())
        };
        let ci = row["paired_difference_ci95"]
            .as_array()
            .ok_or("missing paired interval")?;
        let low = ci
            .first()
            .and_then(Value::as_f64)
            .ok_or("missing paired interval lower bound")?;
        let high = ci
            .get(1)
            .and_then(Value::as_f64)
            .ok_or("missing paired interval upper bound")?;
        table.push_str(&format!(
            "| {} | {} | {} | {} | {:.3} | {:.3} | {:.3} [{low:.3}, {high:.3}] |\n",
            string("workload")?,
            row["connections"],
            row["message_bytes"],
            string("metric")?,
            number("rust_mean")?,
            number("socat_mean")?,
            number("paired_difference_mean")?
        ));
    }
    if continued {
        table.insert_str(0, "This campaign includes an explicit continuation. The preserved prefix, frozen worker, new driver and image-cohort evidence are recorded in `continuations/`. The wall-clock gap is outside the measured samples; paired intervals cannot establish the absence of host drift across that gap.\n\n");
    }
    std::fs::write(output.join("comparison.md"), table)?;
    std::fs::write(
        output.join("comparison.json"),
        serde_json::to_vec_pretty(&json!({
        "method":"seven paired runs; percentile bootstrap of paired differences and paired relative differences; 10000 resamples; SplitMix64 seed 20261110; no multiple-comparison correction",
        "scope":"Docker x86_64 only; endpoint limits, integrated-service cost and ARM64 must be assessed separately",
        "continued":continued,"continuation_records":if continued {Some("continuations/")} else {None},
        "rows":rows}))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r086_paired_confidence_interval_keeps_known_constant_difference_and_rejects_missing_runs()
    -> Result {
        let mut random = Random::new(42);
        assert_eq!(interval(&[3.0; 7], &mut random)?, [3.0, 3.0]);
        assert!(interval(&[3.0; 6], &mut random).is_err());
        assert!(interval(&[f64::NAN; 7], &mut random).is_err());
        let directory = tempfile::tempdir()?;
        let mut pairs = Vec::new();
        for repetition in 0..7 {
            let mut results = vec![
                json!({"variant":"rust","rtt_p95_microseconds":repetition+1}),
                json!({"variant":"socat","rtt_p95_microseconds":repetition+4}),
            ];
            if repetition % 2 != 0 {
                results.reverse();
            }
            pairs.push(json!({"case":{"workload":"latency","connections":4,"message_bytes":256,"repetition":repetition},"results":results}));
        }
        write(directory.path(), &pairs, false)?;
        let report: Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("comparison.json"))?)?;
        assert_eq!(
            report["rows"]
                .as_array()
                .ok_or("missing comparison rows")?
                .len(),
            1
        );
        let row = &report["rows"][0];
        assert_eq!(row["rust_mean"], json!(4.0));
        assert_eq!(row["socat_mean"], json!(7.0));
        assert_eq!(row["paired_difference_mean"], json!(-3.0));
        assert_eq!(row["paired_difference_ci95"], json!([-3.0, -3.0]));
        assert_eq!(
            std::fs::read_to_string(directory.path().join("runs.csv"))?
                .lines()
                .count(),
            8
        );
        assert!(
            std::fs::read_to_string(directory.path().join("comparison.md"))?
                .contains("-3.000 [-3.000, -3.000]")
        );
        assert!(
            write(directory.path(), &pairs[..6], false).is_err(),
            "a partial repetition set cannot produce another comparison"
        );
        Ok(())
    }
}
