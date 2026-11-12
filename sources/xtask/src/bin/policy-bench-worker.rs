//! Development-only measurements of warm DNS policy; no network or production state.

use std::{
    error::Error,
    fs,
    hint::black_box,
    net::Ipv4Addr,
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tunnel_detour_core::{
    DnsDecision, DnsQuestionType, DomainName, ExceptionPolicy, LeaseStore, RuleSet, Timestamp,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn cpu_nanoseconds() -> Result<u128> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    u128::try_from(value.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(u128::try_from(value.tv_nsec).ok()?))
        .ok_or_else(|| "process CPU clock overflow".into())
}

fn process_memory() -> Result<Value> {
    let status = fs::read_to_string("/proc/self/status")?;
    let fields: Vec<_> = status
        .lines()
        .filter(|line| {
            ["VmRSS:", "VmHWM:", "Threads:"]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .collect();
    Ok(
        json!({"fields":fields,"scope":"process status at boundary; VmHWM is process-lifetime RSS high-water, not per-case exclusive memory"}),
    )
}

fn measure(rules: usize, allocated: usize, repetition: usize) -> Result<Value> {
    let fixture = tempfile::tempdir()?;
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
    let path = fixture.path().join("leases.json");
    let mut names = Vec::new();
    let mut entries = Vec::new();
    for index in 0..allocated {
        let name: DomainName =
            format!("host-{index:04}.rule-{:03}.example.test", index % rules).parse()?;
        let address =
            Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + u32::try_from(index)? + 1);
        entries.push(json!({"domain":name,"address":address,"issued_at":100,"expires_at":3700}));
        names.push(name);
    }
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"version":1,"range":"198.18.0.0/16","last_issued_at":100,"entries":entries}),
        )?,
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let initial = fs::read(&path)?;
    let capacity = NonZeroUsize::new(4096).ok_or("invalid fixture capacity")?;
    let store = LeaseStore::open(&path, "198.18.0.0/16".parse()?, capacity)?;
    let patterns = (0..rules)
        .map(|index| format!("***.rule-{index:03}.example.test"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut policy = ExceptionPolicy::new(
        RuleSet::from_lines(&patterns, capacity)?,
        store,
        Duration::from_secs(3600),
    )?;
    policy.set_mapping_limit_per_rule(capacity);
    let now = Timestamp::from_unix_seconds(101);
    let iterations = 100_000_usize;
    for index in 0..10_000 {
        black_box(policy.decide_dns(&names[index % allocated], DnsQuestionType::A, now)?);
    }
    let memory_before = process_memory()?;
    let cpu_before = cpu_nanoseconds()?;
    let started = Instant::now();
    for index in 0..iterations {
        let name = &names[index % allocated];
        match black_box(policy.decide_dns(black_box(name), DnsQuestionType::A, now)?) {
            DnsDecision::Synthetic(lease) if lease.domain() == name => {}
            _ => return Err("warm policy did not retain its hostname identity".into()),
        }
    }
    let elapsed = started.elapsed().as_nanos();
    let cpu = cpu_nanoseconds()?
        .checked_sub(cpu_before)
        .ok_or("CPU clock reversed")?;
    if fs::read(&path)? != initial {
        return Err("warm reuse modified durable lease state".into());
    }
    Ok(
        json!({"rules":rules,"allocated":allocated,"repetition":repetition,"queries":iterations,
        "wall_nanoseconds":elapsed,"cpu_nanoseconds":cpu,"wall_nanoseconds_per_query":elapsed as f64 / iterations as f64,
        "cpu_nanoseconds_per_query":cpu as f64 / iterations as f64,"durable_state_unchanged":true,
        "memory_before":memory_before,"memory_after":process_memory()?}),
    )
}

fn run() -> Result {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [option, directory] = args.as_slice() else {
        return Err("use --output NEW_DIRECTORY".into());
    };
    if option != "--output" {
        return Err("use --output NEW_DIRECTORY".into());
    }
    let output = PathBuf::from(directory);
    fs::create_dir_all(output.parent().ok_or("output needs a parent")?)?;
    fs::create_dir(&output)?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let inputs = xtask::provenance::source_inputs(&root)?;
    fs::copy("/proc/self/exe", output.join("policy-bench-worker"))?;
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
        "scope":"warm core DNS policy with durable synthetic fixtures; no protocol/frontend/controller cost and no router claim",
        "clock":"monotonic wall and CLOCK_PROCESS_CPUTIME_ID","source_inputs":inputs,
        "iterations_per_case":100000,"warmup_per_case":10000,"repetitions":7,
        "memory_scope":"boundary process RSS and cumulative high-water; not an allocation profile or peak for an individual case"}))?,
    )?;
    let mut cases = Vec::new();
    for repetition in 0..7 {
        let sizes = if repetition % 2 == 0 {
            [1, 512, 4096]
        } else {
            [4096, 512, 1]
        };
        for allocated in sizes {
            for rules in [1, 16, 128] {
                let result = measure(rules, allocated, repetition)?;
                eprintln!(
                    "Warm DNS policy: repetition {}, {} rules, {} mappings",
                    repetition + 1,
                    rules,
                    allocated
                );
                cases.push(result);
                fs::write(
                    output.join("results.json"),
                    serde_json::to_vec_pretty(&json!({"complete":false,"cases":cases}))?,
                )?;
            }
        }
    }
    fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&json!({"complete":true,"cases":cases}))?,
    )?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
