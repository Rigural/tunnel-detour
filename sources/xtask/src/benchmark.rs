//! Isolated matched relay measurements. Never accesses a production router.

mod analysis;
pub mod api;
pub(super) mod application;
mod endpoints;
mod executable;
pub(super) mod integrated;
pub(super) mod observer_analysis;
pub mod policy;
pub(super) mod resume;
pub(super) mod transport_compare;

use serde_json::{Value, json};
use std::{
    error::Error,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const IMAGE: &str = "tunnel-detour-relay-benchmark:local";
const SOCAT_SHA256: &str = "4dded51ce29f9cbb3af21b5c97fdccd974b59555c67a3f03a3b5b57cfa09e573";
const RETAINED_GENERATOR_NETWORK: &str = "retained_owned_endpoint";

fn retained_generator_network(plan: &Value) -> Result<bool> {
    match plan.get("generator_network") {
        None => Ok(false),
        Some(value) if value == RETAINED_GENERATOR_NETWORK => Ok(true),
        _ => Err("invalid frozen generator network-lifetime policy".into()),
    }
}

fn validate_generator_network(plan: &Value, manifest: &Value, raw: Option<&Value>) -> Result {
    let retained = retained_generator_network(plan)?;
    if manifest["generator_network"] != plan["generator_network"] {
        return Err("manifest changed its frozen network lifetime".into());
    }
    if let Some(raw) = raw {
        let owner = &raw["generator_network_owner"];
        if raw["generator_network"] != manifest["generator_network"]
            || (retained
                && (owner["state"]["Running"] != true
                    || !owner["before"].is_object()
                    || !owner["after"].is_object()))
        {
            return Err("raw report changed its retained network-lifetime evidence".into());
        }
    }
    Ok(())
}

fn docker(args: &[String]) -> Result<String> {
    let started = std::time::Instant::now();
    let output = Command::new("timeout")
        .args(["--kill-after=2", "30", "docker"])
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Docker {} failed after {:.3} seconds ({}): {}",
            args.first().map_or("operation", String::as_str),
            started.elapsed().as_secs_f64(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let mut bytes = output.stdout;
    // Docker forwards a container's stderr to this command's stderr even on success.
    if args.first().is_some_and(|arg| arg == "logs") {
        bytes.extend_from_slice(&output.stderr);
    }
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

/// Only for owned preparations before traffic admission. Running is distinct
/// from readiness, which the caller must still establish. Never resend a start
/// after an uncertain reply: Docker may already have performed it.
fn start_prepared(lab: &Lab, id: &str) -> Result {
    if !lab.containers.iter().any(|owned| owned == id) {
        return Err("preparation start requires an owned actor".into());
    }
    prepared_start_result(lab, id, docker(&strings(&["start", id])))
}

fn prepared_start_result(lab: &Lab, id: &str, result: Result<String>) -> Result {
    if !lab.containers.iter().any(|owned| owned == id) {
        return Err("preparation observation requires an owned actor".into());
    }
    let Err(error) = result else {
        return Ok(());
    };
    let observed =
        docker(&strings(&["inspect", "--format", "{{json .State}}", id])).and_then(|text| {
            if text.len() > 65_536 {
                return Err("preparation state exceeded its diagnostic bound".into());
            }
            Ok(serde_json::from_str::<Value>(&text)?)
        });
    let record = json!({"actor":id,"start_error":error.to_string(),"observation":match &observed {Ok(state)=>json!({"state":state}),Err(error)=>json!({"error":error.to_string()})},"start_replayed":false,"scope":"owned preparation before measured traffic; running does not establish readiness"});
    let directory = lab
        .failure_directory
        .as_deref()
        .ok_or("uncertain preparation needs retained evidence")?;
    use std::io::Write;
    let mut evidence = tempfile::Builder::new()
        .prefix("uncertain-start-")
        .suffix(".json")
        .tempfile_in(directory)?;
    evidence.write_all(&serde_json::to_vec_pretty(&record)?)?;
    evidence.as_file().sync_all()?;
    evidence.keep().map_err(|error| error.error)?;
    if let Ok(state) = observed
        && state["Status"] == "running"
        && state["Running"] == true
        && state["Paused"] == false
        && state["Restarting"] == false
        && state["Dead"] == false
        && state["OOMKilled"] == false
    {
        return Ok(());
    }
    Err(format!("uncertain preparation did not establish a running actor: {error}").into())
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).into()).collect()
}

fn client_result(id: &str) -> Result<Value> {
    docker(&strings(&["logs", id]))?
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or_else(|| "the generator omitted its structured result".into())
}

fn cargo_target(cargo: &std::ffi::OsStr, root: &Path) -> Result<PathBuf> {
    let result = Command::new(cargo)
        .current_dir(root)
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"])
        .output()?;
    if !result.status.success() {
        return Err("benchmark Cargo metadata failed".into());
    }
    let metadata: Value = serde_json::from_slice(&result.stdout)?;
    Ok(PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing benchmark target directory")?,
    ))
}

fn activity_lock(target: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(target.join("validation-load.lock"))?;
    file.lock()?;
    for label in ["local-validation", "inbound-ui", "relay-benchmark"] {
        if !docker(&strings(&[
            "ps",
            "--quiet",
            "--filter",
            &format!("label=tunnel-detour.task={label}"),
        ]))?
        .is_empty()
        {
            return Err("another laboratory is still active at the measurement boundary".into());
        }
    }
    Ok(file)
}

struct ImageSnapshot {
    tag: String,
    inspection: Value,
}

fn freeze_image(source: &str, purpose: &str) -> Result<ImageSnapshot> {
    let nonce_dir = tempfile::tempdir()?;
    let nonce = nonce_dir
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("missing image snapshot nonce")?;
    let tag = format!(
        "tunnel-detour-{purpose}-benchmark:run-{}-{nonce}",
        std::process::id()
    );
    if !docker(&strings(&[
        "image",
        "ls",
        "--quiet",
        "--filter",
        &format!("reference={tag}"),
    ]))?
    .is_empty()
    {
        return Err("refusing to replace an existing replay image".into());
    }
    docker(&strings(&["image", "tag", source, &tag]))?;
    let inspection: Value = serde_json::from_str(&docker(&strings(&["image", "inspect", &tag]))?)?;
    if inspection[0]["Id"].as_str().is_none()
        || inspection[0]["RootFS"]["Layers"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err("the frozen image has no identity or filesystem layer record".into());
    }
    // Retain this visible, owned tag as a replay artifact. It anchors manifest
    // indexes that could otherwise disappear when another build moves its tag.
    Ok(ImageSnapshot { tag, inspection })
}

#[derive(Default)]
struct Lab {
    containers: Vec<String>,
    networks: Vec<String>,
    failure_directory: Option<PathBuf>,
    actor_image: Option<String>,
}
impl Lab {
    fn generator_network_owner(
        &mut self,
        worker: &Path,
        network: &str,
        address: &str,
    ) -> Result<String> {
        let owner = self.create(
            worker,
            network,
            address,
            "0.1",
            None,
            &["/bin/sleep", "600"],
        )?;
        start_prepared(self, &owner)?;
        let state: Value = serde_json::from_str(&docker(&strings(&[
            "inspect",
            "--format",
            "{{json .State}}",
            &owner,
        ]))?)?;
        if state["Running"] != true {
            return Err("generator network owner is not running".into());
        }
        Ok(owner)
    }
    fn network(&mut self, name: &str, subnet: &str, gateway: &str, ipv6: bool) -> Result<String> {
        let mut args = strings(&[
            "network",
            "create",
            "--internal",
            "--opt",
            "com.docker.network.bridge.enable_ip_masquerade=false",
            "--label",
            "tunnel-detour.task=relay-benchmark",
            "--subnet",
            subnet,
            "--gateway",
            gateway,
        ]);
        if ipv6 {
            args.extend(strings(&["--ipv6", "--subnet", "2001:db8:101::/64"]));
        }
        args.push(name.into());
        let id = docker(&args)?;
        self.networks.push(id.clone());
        Ok(id)
    }
    fn create(
        &mut self,
        worker: &Path,
        network: &str,
        address: &str,
        cpus: &str,
        pid_namespace: Option<&str>,
        command: &[&str],
    ) -> Result<String> {
        let shared = network.strip_prefix("container:");
        if shared.is_some_and(|id| !self.containers.iter().any(|owned| owned == id)) {
            return Err("shared benchmark networking requires an owned namespace actor".into());
        }
        let mut args = strings(&[
            "create",
            "--label",
            "tunnel-detour.task=relay-benchmark",
            "--network",
            &if shared.is_some() || network == "none" {
                network.into()
            } else {
                format!("name={network},driver-opt=com.docker.network.endpoint.ifname=bench0")
            },
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--cgroupns",
            "private",
            "--read-only",
            "--memory",
            "256m",
            "--cpus",
            cpus,
            "--env",
            "TUNNEL_DETOUR_BENCH_LAB=1",
        ]);
        if shared.is_none() {
            args.extend(strings(&["--dns", "127.0.0.1"]));
        }
        if matches!(command.get(1), Some(&"await-start" | &"namespace-origin")) {
            args.extend(strings(&[
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=4m,mode=1777",
            ]));
        }
        if command.get(1) == Some(&"relay") {
            args.extend(strings(&[
                "--user",
                "0:0",
                "--cap-add",
                "SYS_CHROOT",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SETGID",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=4m",
            ]));
        }
        if pid_namespace.is_some() {
            // The observer is outside the measured cgroup and confined to the
            // synthetic relay's PID namespace, including non-dumpable children.
            args.extend(strings(&[
                "--user",
                "0:0",
                "--cap-add",
                "SYS_PTRACE",
                "--cap-add",
                "DAC_READ_SEARCH",
            ]));
        }
        if network != "none" && shared.is_none() {
            args.extend(strings(&[
                if address.contains(':') {
                    "--ip6"
                } else {
                    "--ip"
                },
                address,
            ]));
        }
        if let Some(namespace) = pid_namespace {
            args.extend(strings(&["--pid", &format!("container:{namespace}")]));
        }
        args.push("--mount".into());
        args.push(format!(
            "type=bind,src={},dst=/relay-bench-worker,readonly",
            worker.display()
        ));
        args.push(self.actor_image.as_deref().unwrap_or(IMAGE).into());
        args.extend(strings(command));
        let id = docker(&args)?;
        self.containers.push(id.clone());
        Ok(id)
    }
    fn remove(&mut self, id: &str) -> Result {
        docker(&strings(&["rm", "--force", id]))?;
        self.containers.retain(|other| other != id);
        Ok(())
    }
    fn finish_networks(&mut self) -> Result {
        if !self.containers.is_empty() {
            return Err("cannot retire networks while owned actors remain".into());
        }
        for id in self.networks.clone() {
            docker(&strings(&["network", "rm", &id]))?;
            self.networks.retain(|other| other != &id);
        }
        Ok(())
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        if let Some(directory) = &self.failure_directory {
            let capture = || -> Result {
                let mut actors = Vec::new();
                for id in &self.containers {
                    let state: Value = serde_json::from_str(&docker(&strings(&[
                        "inspect",
                        "--format",
                        "{{json .State}}",
                        id,
                    ]))?)?;
                    let diagnostic = |observed: Result<String>| match observed {
                        Ok(raw) => json!({"available":true,"raw":raw}),
                        Err(error) => json!({"available":false,"error":error.to_string()}),
                    };
                    let (sockets, cgroup) = if state["Running"] == true {
                        (
                            diagnostic(docker(&strings(&[
                                "exec",
                                id,
                                "cat",
                                "/proc/net/tcp",
                                "/proc/net/tcp6",
                            ]))),
                            diagnostic(docker(&strings(&[
                                "exec",
                                id,
                                "cat",
                                "/sys/fs/cgroup/cpu.stat",
                                "/sys/fs/cgroup/memory.events",
                                "/sys/fs/cgroup/pids.current",
                            ]))),
                        )
                    } else {
                        (Value::Null, Value::Null)
                    };
                    actors.push(json!({"id":id,"state":state,"log":docker(&strings(&["logs",id]))?,"sockets":sockets,"cgroup":cgroup}));
                }
                std::fs::write(
                    directory.join("final-actors.json"),
                    serde_json::to_vec_pretty(&actors)?,
                )?;
                Ok(())
            };
            if let Err(error) = capture() {
                eprintln!("benchmark final diagnostics failed: {error}");
            }
        }
        for id in self.containers.iter().rev() {
            if let Err(error) = docker(&strings(&["rm", "--force", id])) {
                eprintln!("benchmark container cleanup failed: {error}");
            }
        }
        for id in self.networks.iter().rev() {
            if let Err(error) = docker(&strings(&["network", "rm", id])) {
                eprintln!("benchmark network cleanup failed: {error}");
            }
        }
    }
}

struct Api(reqwest::Client);
impl Api {
    async fn bulk_result(&self, id: &str) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let log = docker(&strings(&["logs", id]))?;
                if let Some(value) = log
                    .lines()
                    .last()
                    .and_then(|line| serde_json::from_str::<Value>(line).ok())
                    && value["role"] == "bulk-origin"
                    && value["connections"].is_array()
                {
                    return Ok(value);
                }
                let state = self.get(&format!("/containers/{id}/json")).await?;
                if state["State"]["Running"] != true {
                    return Err(format!("bulk origin exited before its result: {log}").into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?
    }
    async fn get(&self, path: &str) -> Result<Value> {
        let response = self
            .0
            .get(format!("http://localhost/v1.47{path}"))
            .timeout(Duration::from_secs(3))
            .send()
            .await?
            .error_for_status()?;
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
                return Err("Docker response exceeded the bounded pilot limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn stats(&self, id: &str) -> Result<Value> {
        self.get(&format!(
            "/containers/{id}/stats?stream=false&one-shot=true"
        ))
        .await
    }
    async fn ready(&self, id: &str) -> Result {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = self.get(&format!("/containers/{id}/json")).await?;
                if state["State"]["Running"] != true {
                    return Err("benchmark actor exited before readiness".into());
                }
                if docker(&strings(&["logs", id]))?.contains("\"ready\":true") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .await??;
        Ok(())
    }
}

fn build_worker(cargo: &std::ffi::OsStr, root: &Path) -> Result<PathBuf> {
    build_binary(cargo, root, "xtask", "relay-bench-worker")
}

fn build_binary(
    cargo: &std::ffi::OsStr,
    root: &Path,
    package: &str,
    binary: &str,
) -> Result<PathBuf> {
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--package",
            package,
            "--bin",
            binary,
            "--release",
            "--target",
            "x86_64-unknown-linux-musl",
            "--locked",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(Stdio::inherit())
        .output()?;
    let mut path = None;
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = serde_json::from_slice(line)?;
        if value["reason"] == "compiler-artifact" && value["target"]["name"] == binary {
            path = value["executable"].as_str().map(PathBuf::from);
        } else if value["reason"] == "compiler-message"
            && let Some(rendered) = value["message"]["rendered"].as_str()
        {
            eprint!("{rendered}");
        }
    }
    if !output.status.success() {
        return Err(format!("benchmark binary {binary} compilation failed").into());
    }
    path.ok_or_else(|| format!("Cargo did not identify benchmark binary {binary}").into())
}

pub fn pilot(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    pilot_workload(cargo, root, output, "latency")
}

pub fn pilot_workload(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    workload: &str,
) -> Result {
    pilot_case(cargo, root, output, workload, 4)
}

pub fn pilot_case(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    workload: &str,
    connections: usize,
) -> Result {
    if ![1, 4, 16, 32].contains(&connections) {
        return Err("unsupported pilot connection count".into());
    }
    if ![
        "latency",
        "upload",
        "download",
        "duplex",
        "churn",
        "slow-upload",
        "slow-download",
    ]
    .contains(&workload)
    {
        return Err("unknown pilot workload".into());
    }
    let cases = [Scenario {
        prepared: false,
        observation: Observation::Full,
        workload,
        connections,
        message_bytes: 256,
        window: if workload == "churn" {
            Measurement::Cycles {
                warmup: 512,
                measured: 2048,
            }
        } else {
            Measurement::Timed {
                warmup: 1,
                seconds: 3,
            }
        },
        reverse: false,
        repetition: 0,
    }];
    run_plan(cargo, root, output, &cases, PlanKind::PilotSingle)
}

/// Qualify every primary load at short duration before freezing a long campaign.
pub fn matrix_pilot(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    let mut cases = Vec::new();
    for (index, connections) in [1, 4, 16, 32].into_iter().enumerate() {
        for size in [64, 256, 1024] {
            cases.push(Scenario {
                prepared: false,
                observation: Observation::Full,
                workload: "latency",
                connections,
                message_bytes: size,
                window: Measurement::Timed {
                    warmup: 1,
                    seconds: 3,
                },
                reverse: index % 2 != 0,
                repetition: 0,
            });
        }
        for workload in ["upload", "download", "duplex"] {
            cases.push(Scenario {
                prepared: false,
                observation: Observation::Full,
                workload,
                connections,
                message_bytes: 0,
                window: Measurement::Timed {
                    warmup: 1,
                    seconds: 3,
                },
                reverse: index % 2 != 0,
                repetition: 0,
            });
        }
    }
    run_plan(cargo, root, output, &cases, PlanKind::PilotMatrix)
}

/// Repeated paired measurements, frozen before the first actor is started.
pub fn campaign(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    campaign_with_observation(cargo, root, output, "full")
}

pub fn campaign_with_observation(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    observation: &str,
) -> Result {
    let observation = Observation::parse(observation)?;
    run_plan(
        cargo,
        root,
        output,
        &campaign_cases_for(observation)?,
        PlanKind::Campaign,
    )
}

/// Keep the qualified generator and image byte-identical throughout the campaign.
pub fn frozen_campaign(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    worker: &Path,
    image: &str,
    observation: &str,
) -> Result {
    let observation = Observation::parse(observation)?;
    run_plan_with_source(
        cargo,
        root,
        output,
        &campaign_cases_for(observation)?,
        PlanKind::Campaign,
        WorkerSource::Frozen { worker, image },
    )
}

fn campaign_cases_for(observation: Observation) -> Result<Vec<Scenario<'static>>> {
    let mut cases = campaign_cases()?;
    for case in &mut cases {
        case.observation = observation;
    }
    Ok(cases)
}

/// Qualify a lower-observation control before estimating observer perturbation.
/// Both treatments retain the same integrity checks and boundary CPU counters.
pub fn observer_pilot(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    let cases: Vec<_> = [Observation::Full, Observation::BoundaryOnly]
        .into_iter()
        .enumerate()
        .map(|(index, observation)| Scenario {
            prepared: false,
            workload: "latency",
            connections: 4,
            message_bytes: 256,
            window: Measurement::Timed {
                warmup: 1,
                seconds: 5,
            },
            reverse: index % 2 != 0,
            repetition: 0,
            observation,
        })
        .collect();
    run_plan(cargo, root, output, &cases, PlanKind::PilotMatrix)
}

/// Collect seven paired observation treatments; retain the completed raw series
/// separately from the pending statistical analysis and the relay comparison.
pub fn observer_campaign(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    let mut cases = Vec::new();
    let mut random = analysis::Random::new(20_261_114);
    for repetition in 0..7 {
        let mut workloads = [("latency", 4), ("duplex", 32), ("churn", 32)];
        for index in (1..workloads.len()).rev() {
            let other = random.index(index + 1)?;
            workloads.swap(index, other);
        }
        let treatments = if repetition % 2 == 0 {
            [Observation::Full, Observation::BoundaryOnly]
        } else {
            [Observation::BoundaryOnly, Observation::Full]
        };
        for (workload, connections) in workloads {
            for observation in treatments {
                cases.push(Scenario {
                    prepared: false,
                    workload,
                    connections,
                    message_bytes: if workload == "duplex" { 0 } else { 256 },
                    window: if workload == "churn" {
                        Measurement::Cycles {
                            warmup: 1024,
                            measured: 8192,
                        }
                    } else {
                        Measurement::Timed {
                            warmup: 2,
                            seconds: 10,
                        }
                    },
                    // Keep variant order identical within an observation pair;
                    // balance that factor separately across repetitions.
                    reverse: repetition % 4 >= 2,
                    repetition,
                    observation,
                });
            }
        }
    }
    run_plan(cargo, root, output, &cases, PlanKind::ObserverQualification)
}

fn campaign_cases() -> Result<Vec<Scenario<'static>>> {
    let mut cases = Vec::new();
    let mut random = analysis::Random::new(20_261_110);
    for repetition in 0..7 {
        let mut block = Vec::new();
        for (index, connections) in [1, 4, 16, 32].into_iter().enumerate() {
            for (load, size) in [
                ("latency", 64),
                ("latency", 256),
                ("latency", 1024),
                ("upload", 0),
                ("download", 0),
                ("duplex", 0),
                ("churn", 256),
            ] {
                block.push(Scenario {
                    prepared: false,
                    observation: Observation::Full,
                    workload: load,
                    connections,
                    message_bytes: size,
                    window: if load == "churn" {
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
                    reverse: (index + usize::from(repetition)) % 2 != 0,
                    repetition,
                });
            }
        }
        for index in (1..block.len()).rev() {
            let other = random.index(index + 1)?;
            block.swap(index, other);
        }
        cases.extend(block);
    }
    Ok(cases)
}

pub fn operational(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    let mut cases = Vec::new();
    for connections in [1, 16, 32] {
        for workload in ["idle", "slow-upload", "slow-download"] {
            cases.push(Scenario {
                prepared: false,
                observation: Observation::Full,
                workload,
                connections,
                message_bytes: 0,
                window: Measurement::Timed {
                    warmup: if workload == "idle" { 0 } else { 1 },
                    seconds: 3,
                },
                reverse: connections == 16,
                repetition: 0,
            });
        }
    }
    cases.push(Scenario {
        prepared: false,
        observation: Observation::Full,
        workload: "saturation",
        connections: 32,
        message_bytes: 0,
        window: Measurement::Timed {
            warmup: 0,
            seconds: 3,
        },
        reverse: false,
        repetition: 0,
    });
    for connections in [1, 4, 16, 32] {
        cases.push(Scenario {
            prepared: false,
            observation: Observation::Full,
            workload: "churn",
            connections,
            message_bytes: 256,
            window: Measurement::Cycles {
                warmup: 512,
                measured: 2048,
            },
            reverse: connections == 4 || connections == 32,
            repetition: 0,
        });
    }
    run_plan(cargo, root, output, &cases, PlanKind::PilotMatrix)
}

pub fn endpoint_reference(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    run_plan(cargo, root, output, &endpoint_cases(), PlanKind::Endpoints)
}

pub fn frozen_endpoint_reference(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    worker: &Path,
    image: &str,
    observation: &str,
) -> Result {
    let observation = Observation::parse(observation)?;
    let mut cases = endpoint_cases();
    for case in &mut cases {
        case.observation = observation;
    }
    run_plan_with_source(
        cargo,
        root,
        output,
        &cases,
        PlanKind::Endpoints,
        WorkerSource::Frozen { worker, image },
    )
}

fn endpoint_cases() -> Vec<Scenario<'static>> {
    // One unpaired endpoint reference per primary load, not another relay candidate.
    let mut cases = Vec::new();
    for connections in [1, 4, 16, 32] {
        for (workload, message_bytes) in [
            ("latency", 64),
            ("latency", 256),
            ("latency", 1024),
            ("upload", 0),
            ("download", 0),
            ("duplex", 0),
        ] {
            cases.push(Scenario {
                prepared: false,
                observation: Observation::Full,
                workload,
                connections,
                message_bytes,
                window: Measurement::Timed {
                    warmup: 5,
                    seconds: 20,
                },
                reverse: false,
                repetition: 0,
            });
        }
    }
    cases.extend(churn_reference_cases());
    cases
}

fn churn_reference_cases() -> [Scenario<'static>; 4] {
    [1, 4, 16, 32].map(|connections| Scenario {
        prepared: false,
        observation: Observation::Full,
        workload: "churn",
        connections,
        message_bytes: 256,
        window: Measurement::Cycles {
            warmup: 1024,
            measured: 8192,
        },
        reverse: false,
        repetition: 0,
    })
}

pub fn churn_reference(cargo: &std::ffi::OsStr, root: &Path, output: &Path) -> Result {
    run_plan(
        cargo,
        root,
        output,
        &churn_reference_cases(),
        PlanKind::Endpoints,
    )
}

#[derive(Clone, Copy, PartialEq)]
enum PlanKind {
    PilotSingle,
    PilotMatrix,
    Campaign,
    Endpoints,
    ObserverQualification,
}

impl PlanKind {
    fn label(self) -> &'static str {
        match self {
            Self::PilotSingle | Self::PilotMatrix => "qualification pilot",
            Self::Campaign => "paired campaign",
            Self::Endpoints => "direct endpoint reference; no relay",
            Self::ObserverQualification => "paired observer qualification",
        }
    }
}

fn run_plan(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    cases: &[Scenario<'_>],
    kind: PlanKind,
) -> Result {
    run_plan_with_source(cargo, root, output, cases, kind, WorkerSource::Build)
}

#[derive(Clone, Copy)]
enum WorkerSource<'a> {
    Build,
    Frozen { worker: &'a Path, image: &'a str },
}

fn prepared_worker(worker: &Path) -> Result<bool> {
    let output = Command::new("timeout")
        .args(["--kill-after=2", "5"])
        .arg(worker)
        .arg("benchmark-info")
        .env("TUNNEL_DETOUR_BENCH_LAB", "1")
        .env_remove("TUNNEL_DETOUR_BENCH_NETNS")
        .output()?;
    if output.status.success() && output.stdout.len() <= 4096 {
        let info: Value = serde_json::from_slice(&output.stdout)?;
        if info
            == json!({"protocol":2,"prepared_generator":true,"preparation_seconds":60,"bulk_first_client_seconds":60})
        {
            return Ok(true);
        }
        return Err("unsupported benchmark worker preparation contract".into());
    }
    if output.status.code() == Some(1)
        && output.stdout.is_empty()
        && String::from_utf8_lossy(&output.stderr).trim()
            == "expected relay, echo or ping worker arguments"
    {
        return Ok(false);
    }
    Err("benchmark worker preparation inspection failed".into())
}

fn run_plan_with_source(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    cases: &[Scenario<'_>],
    kind: PlanKind,
    source: WorkerSource<'_>,
) -> Result {
    if kind == PlanKind::Campaign {
        uniform_observation(cases)?;
    }
    if cases
        .iter()
        .any(|case| (case.workload == "churn") != matches!(case.window, Measurement::Cycles { .. }))
    {
        return Err(
            "churn requires a fixed-volume window; other loads require a timed window".into(),
        );
    }
    let target = cargo_target(cargo, root)?;
    let release = target.join("x86_64-unknown-linux-musl/release");
    std::fs::create_dir_all(&release)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(release.join("relay-benchmark.lock"))?;
    // Reject a second controller before it can compile or move the image tag.
    lock.try_lock()
        .map_err(|error| format!("cannot start another relay benchmark controller: {error}"))?;
    let build_guard = activity_lock(&target)?;
    std::fs::create_dir_all(output.parent().ok_or("an output parent is required")?)?;
    std::fs::create_dir(output)?;
    let source_inputs = xtask::provenance::source_inputs(root)?;
    let (worker, image) = match source {
        WorkerSource::Build => {
            let worker = build_worker(cargo, root)?;
            let status = Command::new("docker")
                .current_dir(root)
                .args([
                    "build",
                    "--tag",
                    IMAGE,
                    "--file",
                    "sources/tests/benchmark/Dockerfile",
                    ".",
                ])
                .status()?;
            if !status.success() {
                return Err("benchmark image build failed".into());
            }
            (worker, freeze_image(IMAGE, "relay")?)
        }
        WorkerSource::Frozen { worker, image } => {
            if !std::fs::symlink_metadata(worker)?.is_file()
                || image.is_empty()
                || image.starts_with('-')
            {
                return Err(
                    "frozen measurements require a regular worker and an existing local image"
                        .into(),
                );
            }
            (
                worker.canonicalize()?,
                freeze_image(
                    image,
                    if kind == PlanKind::Endpoints {
                        "frozen-endpoints"
                    } else {
                        "frozen-relay"
                    },
                )?,
            )
        }
    };
    if xtask::provenance::source_inputs(root)? != source_inputs {
        return Err("source inputs changed while freezing benchmark binaries".into());
    }
    xtask::provenance::archive_inputs(root, &source_inputs, &output.join("source.tar"))?;
    let activity_path = target.join("validation-load.lock");
    let context: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
    let socket = context[0]["Endpoints"]["docker"]["Host"]
        .as_str()
        .and_then(|value| value.strip_prefix("unix://"))
        .ok_or("the benchmark requires the configured local Docker Unix socket")?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .unix_socket(socket)
        .connect_timeout(Duration::from_secs(3))
        .build()?;
    let snapshot = tempfile::tempdir()?;
    let stable_worker = snapshot.path().join("relay-bench-worker");
    let original_hash = digest(&worker)?;
    std::fs::copy(&worker, &stable_worker)?;
    if digest(&stable_worker)? != original_hash {
        return Err("the worker changed while its snapshot was copied".into());
    }
    std::fs::copy(&stable_worker, output.join("relay-bench-worker"))?;
    let prepared = prepared_worker(&stable_worker)?;
    let cases: Vec<_> = cases
        .iter()
        .copied()
        .map(|mut case| {
            case.prepared = prepared;
            case
        })
        .collect();
    // The collector can outlive a Cargo replacement of its pathname. Freeze
    // this running inode, independently of the explicitly supplied worker.
    let stable_driver = output.join("benchmark-driver");
    std::fs::copy("/proc/self/exe", &stable_driver)?;
    let metadata = |program: &std::ffi::OsStr, args: &[&str]| -> Result<String> {
        let result = Command::new(program)
            .current_dir(root)
            .args(args)
            .output()?;
        if !result.status.success() {
            return Err("benchmark provenance inspection failed".into());
        }
        Ok(String::from_utf8(result.stdout)?.trim().to_owned())
    };
    std::fs::write(
        output.join("provenance.json"),
        serde_json::to_vec_pretty(&json!({
            "source_inputs":source_inputs,
            "source_archive":"source.tar","source_archive_sha256":digest(&output.join("source.tar"))?,
            "driver_sha256":digest(&stable_driver)?,
            "commit":metadata(std::ffi::OsStr::new("git"), &["rev-parse","HEAD"])?,
            "working_tree":metadata(std::ffi::OsStr::new("git"), &["status","--porcelain=v1"])?,
            "rustc":metadata(std::ffi::OsStr::new("rustc"), &["-vV"])?,
            "cargo":metadata(cargo, &["--version"])?,
            "docker":metadata(std::ffi::OsStr::new("docker"), &["version","--format","{{json .}}"] )?,
            "image":image.inspection[0]["Id"],"image_tag":image.tag,"image_layers":image.inspection[0]["RootFS"]["Layers"],
            "image_retention":"owned run tags remain available as replay artifacts"
            ,"worker_source":if matches!(source, WorkerSource::Build) {"workspace build"} else {"explicit frozen binary; no rebuild"}
        }))?,
    )?;
    drop(build_guard);
    let plan: Vec<_> = cases.iter().map(Scenario::description).collect();
    let mut declaration = json!({"kind":kind.label(),"campaign_complete":false,"seed":if kind == PlanKind::ObserverQualification {20_261_114} else {20_261_110},"worker_sha256":digest(&stable_worker)?,"activity_lock":activity_path,"cases":plan});
    if kind == PlanKind::Campaign && uniform_observation(&cases)? == Observation::BoundaryOnly {
        declaration["observation"] = json!("boundary_only");
    }
    if prepared {
        declaration["prepared_generator"] = json!(true);
    }
    declaration["generator_network"] = json!(RETAINED_GENERATOR_NETWORK);
    std::fs::write(
        output.join("plan.json"),
        serde_json::to_vec_pretty(&declaration)?,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let api = Api(client);
    let mut completed = Vec::new();
    for (index, spec) in cases.iter().copied().enumerate() {
        let _activity = activity_lock(&target)?;
        let directory = if kind == PlanKind::PilotSingle {
            output.to_path_buf()
        } else {
            let path = output.join(format!(
                "{index:03}-{}-c{:02}-b{:04}",
                spec.workload, spec.connections, spec.message_bytes
            ));
            std::fs::create_dir(&path)?;
            path
        };
        println!(
            "Measurement {}/{}: {}, {} connections",
            index + 1,
            cases.len(),
            spec.workload,
            spec.connections
        );
        let result = if kind == PlanKind::Endpoints {
            runtime.block_on(endpoints::measure(
                &api,
                &stable_worker,
                &directory,
                spec,
                &image,
                true,
            ))
        } else {
            runtime.block_on(measure(
                &api,
                &stable_worker,
                &directory,
                spec,
                &image,
                None,
                true,
            ))
        };
        match result {
            Ok(results) => completed.push(json!({"case":plan[index],"results":results})),
            Err(error) => {
                std::fs::write(
                    directory.join("invalid.json"),
                    serde_json::to_vec_pretty(
                        &json!({"valid":false,"reason":error.to_string(),"case":plan[index]}),
                    )?,
                )?;
                return Err(error);
            }
        }
        if kind != PlanKind::PilotSingle {
            resume::checkpoint(
                output,
                &json!({"kind":kind.label(),"measurements_complete":index+1==cases.len(),"complete":!matches!(kind, PlanKind::Campaign | PlanKind::ObserverQualification) && index+1==cases.len(),"campaign_complete":false,"completed_pairs":completed}),
            )?;
        }
    }
    if kind == PlanKind::Campaign {
        if let Err(error) = analysis::write(output, &completed, false) {
            std::fs::write(
                output.join("invalid.json"),
                serde_json::to_vec_pretty(
                    &json!({"valid":false,"stage":"analysis","reason":error.to_string()}),
                )?,
            )?;
            return Err(error);
        }
        resume::checkpoint(
            output,
            &json!({"kind":kind.label(),"measurements_complete":true,"complete":true,"campaign_complete":true,"completed_pairs":completed}),
        )?;
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum Measurement {
    Timed { warmup: u8, seconds: u8 },
    Cycles { warmup: u16, measured: u16 },
}
impl Measurement {
    fn check_ports(self, parameters: &str) -> Result {
        if let Self::Cycles { warmup, measured } = self {
            let values = parameters
                .lines()
                .next()
                .ok_or("missing node ephemeral port range")?
                .split_whitespace()
                .map(str::parse::<u16>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let [first, last] = values.as_slice() else {
                return Err("incompatible node ephemeral port range".into());
            };
            let available = u32::from(*last)
                .checked_sub(u32::from(*first))
                .and_then(|value| value.checked_add(1))
                .ok_or("invalid node ephemeral port range")?;
            let required = (u32::from(warmup) + u32::from(measured)) * 2;
            if available < required {
                return Err("the churn volume requires more node ephemeral port headroom; kernel settings remain unchanged".into());
            }
        }
        Ok(())
    }
    fn arguments(self) -> (String, String) {
        match self {
            Self::Timed { warmup, seconds } => (warmup.to_string(), seconds.to_string()),
            Self::Cycles { warmup, measured } => (warmup.to_string(), measured.to_string()),
        }
    }
    fn description(self) -> Value {
        match self {
            Self::Timed { warmup, seconds } => {
                json!({"kind":"timed","warmup_seconds":warmup,"measured_seconds":seconds})
            }
            Self::Cycles { warmup, measured } => {
                json!({"kind":"fixed_volume","warmup_cycles":warmup,"measured_cycles":measured})
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Scenario<'a> {
    prepared: bool,
    workload: &'a str,
    connections: usize,
    message_bytes: usize,
    window: Measurement,
    reverse: bool,
    repetition: u8,
    observation: Observation,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Observation {
    Full,
    BoundaryOnly,
}

impl Observation {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "full" => Ok(Self::Full),
            "boundary-only" => Ok(Self::BoundaryOnly),
            _ => Err("observation must be full or boundary-only".into()),
        }
    }
    fn from_plan(plan: &Value) -> Result<Self> {
        let fields = plan
            .as_object()
            .ok_or("observation plan must be an object")?;
        match fields.get("observation") {
            None => Ok(Self::Full),
            Some(value) if value == "full" => Ok(Self::Full),
            Some(value) if value == "boundary_only" => Ok(Self::BoundaryOnly),
            _ => Err("invalid frozen observation policy".into()),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::BoundaryOnly => "boundary_only",
        }
    }
}

fn uniform_observation(cases: &[Scenario<'_>]) -> Result<Observation> {
    let observation = cases
        .first()
        .ok_or("an observation campaign cannot be empty")?
        .observation;
    if cases.iter().any(|case| case.observation != observation) {
        return Err("a comparative campaign cannot pool observation treatments".into());
    }
    Ok(observation)
}

impl Scenario<'_> {
    fn description(&self) -> Value {
        let mut value = json!({"workload":self.workload,"connections":self.connections,"message_bytes":if ["latency","churn"].contains(&self.workload) {Some(self.message_bytes)} else {None},"window":self.window.description(),"socat_first":self.reverse,"repetition":self.repetition});
        // Preserve the full-observation descriptions of saved campaigns. Only
        // the explicit lower-observation treatment changes the replay contract.
        if self.observation != Observation::Full {
            value["observation"] = json!(self.observation.label());
        }
        if self.prepared {
            value["prepared_generator"] = json!(true);
        }
        value
    }
    fn echo(self) -> bool {
        ["latency", "churn", "idle", "saturation"].contains(&self.workload)
    }
    fn origin_command(self) -> Vec<String> {
        if self.echo() {
            strings(&["/relay-bench-worker", "echo", "192.0.2.2:8080"])
        } else {
            strings(&[
                "/relay-bench-worker",
                "bulk-origin",
                "192.0.2.2:8080",
                &self.connections.to_string(),
            ])
        }
    }
    fn generator_command(self, remote: &str) -> Vec<String> {
        let (warmup, measured) = self.window.arguments();
        let mut command = if ["idle", "saturation"].contains(&self.workload) {
            strings(&[
                "/relay-bench-worker",
                self.workload,
                remote,
                &self.connections.to_string(),
                &measured,
            ])
        } else if ["latency", "churn"].contains(&self.workload) {
            strings(&[
                "/relay-bench-worker",
                if self.workload == "churn" {
                    "churn"
                } else {
                    "ping"
                },
                remote,
                &self.connections.to_string(),
                &self.message_bytes.to_string(),
                &warmup,
                &measured,
            ])
        } else {
            strings(&[
                "/relay-bench-worker",
                "bulk-client",
                remote,
                self.workload,
                &self.connections.to_string(),
                &warmup,
                &measured,
            ])
        };
        if self.prepared {
            command.insert(1, "await-start".into());
        }
        command
    }
}

async fn measure(
    api: &Api,
    worker: &Path,
    output: &Path,
    spec: Scenario<'_>,
    image: &ImageSnapshot,
    expected_context: Option<&Value>,
    retain_generator_network: bool,
) -> Result<Vec<Value>> {
    measure_workers(
        api,
        Workers {
            relay: worker,
            actors: worker,
            rust_only: false,
        },
        output,
        spec,
        image,
        expected_context,
        retain_generator_network,
    )
    .await
}

struct Workers<'a> {
    relay: &'a Path,
    actors: &'a Path,
    rust_only: bool,
}

async fn measure_workers(
    api: &Api,
    workers: Workers<'_>,
    output: &Path,
    spec: Scenario<'_>,
    image: &ImageSnapshot,
    expected_context: Option<&Value>,
    retain_generator_network: bool,
) -> Result<Vec<Value>> {
    let worker = workers.relay;
    let limits = tunnel_detour_service::RelayLimits::new(
        32,
        Duration::from_secs(5),
        Duration::from_secs(3600),
    )?;
    let socket_buffer = limits.socket_buffer_bytes();
    let backlog = tunnel_detour_service::RELAY_LISTEN_BACKLOG;
    let origin_worker = actor_copy(workers.actors, "origin")?;
    let generator_worker = actor_copy(workers.actors, "generator")?;
    let observer_worker = actor_copy(workers.actors, "observer")?;
    let mut lab = Lab {
        failure_directory: Some(output.to_path_buf()),
        containers: Vec::new(),
        networks: Vec::new(),
        actor_image: Some(image.tag.clone()),
    };
    let prefix = format!("td-relay-pilot-{}", std::process::id());
    let wan = lab.network(
        &format!("{prefix}-client"),
        "198.51.100.0/24",
        "198.51.100.254",
        true,
    )?;
    let lan = lab.network(
        &format!("{prefix}-origin"),
        "192.0.2.0/24",
        "192.0.2.254",
        false,
    )?;
    let mut summaries = Vec::new();
    let variants: &[&str] = if workers.rust_only {
        &["rust"]
    } else if spec.reverse {
        &["socat", "rust"]
    } else {
        &["rust", "socat"]
    };
    for (variant_index, variant) in variants.iter().copied().enumerate() {
        let host_before = xtask::provenance::host_context();
        let origin_command = spec.origin_command();
        let origin_refs: Vec<_> = origin_command.iter().map(String::as_str).collect();
        let origin = lab.create(&origin_worker, &lan, "192.0.2.2", "4", None, &origin_refs)?;
        if spec.prepared {
            start_prepared(&lab, &origin)?;
        } else {
            docker(&strings(&["start", &origin]))?;
        }
        api.ready(&origin).await?;
        let socat_digest = docker(&strings(&["exec", &origin, "sha256sum", "/usr/bin/socat"]))?;
        let socat_digest = socat_digest
            .split_whitespace()
            .next()
            .ok_or("missing socat executable digest")?;
        let mut manifest = json!({"kind":"isolated matched pair","image":image.inspection[0]["Id"],"socat_apk_sha256":SOCAT_SHA256,
            "socat_executable_sha256":socat_digest,
            "worker_sha256":digest(worker)?,"architecture":"x86_64","backend":"OpenWrt 25.12.6 userspace with the Docker host kernel",
            "kernel":docker(&strings(&["exec", &origin, "uname", "-r"]))?,
            "packages":docker(&strings(&["exec", &origin, "apk", "info", "-v"]))?,
            "relay_cpus":2,"actor_cpus":4,"relay_runtime_threads":2,"actor_runtime_threads":4,"memory_limit_bytes":268435456,
            "uid":{"tunnel-detour-controller":0,"tunnel-detour-transport":65534,"socat":65534,"generator":65534,"origin":65534,"observer":0},
            "capabilities":{"tunnel-detour-controller":["SYS_CHROOT","SETUID","SETGID"],"tunnel-detour-transport":[],"socat":[],"observer":["SYS_PTRACE","DAC_READ_SEARCH"]},
            "workload":spec.workload,"connections":spec.connections,"message_bytes":if ["latency", "churn"].contains(&spec.workload) { Some(spec.message_bytes) } else { None },"bulk_block_bytes":if spec.echo() { None } else { Some(16384) },"window":spec.window.description(),"order":variants,"repetition":spec.repetition,
            "backlog":backlog,"socket_buffer_request_bytes":socket_buffer,"transfer_buffer_bytes":8192,"max_connections":32,"connect_timeout_seconds":5,"inactivity_seconds":3600,"tcp_nodelay":false,
            "rust_pending_limit":tunnel_detour_service::RELAY_PENDING_LIMIT,"rust_pending_wait_milliseconds":tunnel_detour_service::RELAY_ADMISSION_WAIT.as_millis(),
            "socat_pending_policy":"kernel listen backlog; no equivalent 250-ms per-socket admission deadline",
            "resource_window":"client startup, warmup, measurement and normal TCP drain; all verified data is reported separately from the steady measurement window",
            "tcp_keepalive":false,"bulk_integrity":"unique monotonic per-direction block sequence and per-flow payload; exact sender/receiver totals",
            "slow_reader_policy":if ["slow-upload","slow-download"].contains(&spec.workload) { Some("sleep 5 ms after each successful read of at most 16384 bytes") } else {None},
            "scope":"opaque transport including per-connection process startup and isolation; integrated policy and ARM64 remain separate measurements; socat runs as nobody without the Rust chroot boundary",
            "process_sampling":"live address spaces; confirmed exits/zombies excluded; permission races require bounded retirement confirmation; observer is outside the measured cgroup",
            "context_switches":"not attributed: periodic proc samples cannot recover exited children's lifetime counters",
            "executable_pages":"separate inodes for relay, origin, generator and observer"});
        manifest["transport_seccomp"] = json!(
            "architecture-checked syscall allowlist; new network sockets, signals, filesystem access and process creation refused"
        );
        if spec.observation == Observation::BoundaryOnly {
            manifest["observation"] = json!(spec.observation.label());
            manifest["process_sampling"] = json!("unavailable; no PSS observer process");
            manifest["periodic_cgroup_sampling"] = json!(false);
            manifest["uid"]["observer"] = Value::Null;
            manifest["capabilities"]["observer"] = Value::Null;
            manifest["executable_pages"] =
                json!("separate inodes for relay, origin and generator; no observer process");
        }
        if spec.prepared {
            manifest["prepared_generator"] = json!(true);
            manifest["generator_preparation"] = json!({"barrier":"explicit file trigger after running/readiness confirmation","timeout_seconds":60,"bulk_first_client_seconds":60});
            manifest["resource_window"] = json!(
                "prepared client trigger, protocol setup, warmup, measurement and normal TCP drain; verified data also reported separately from the steady measurement window"
            );
        }
        if retain_generator_network {
            manifest["generator_network"] = json!(RETAINED_GENERATOR_NETWORK);
            manifest["generator_network_owner"] = json!({"command":["/bin/sleep","600"],"cpus":0.1,"memory_limit_bytes":268435456,"uid":65534,"capabilities":[],"dns":["127.0.0.1"],"scope":"separate cgroup outside relay and generator; keeps the owned endpoint alive through peer payload/EOF confirmation"});
        }
        if workers.rust_only {
            manifest["kind"] =
                json!("one frozen Rust treatment; root plan owns before/after pairing");
            manifest["actor_worker_sha256"] = json!(digest(workers.actors)?);
        }
        manifest["image_tag"] = json!(image.tag);
        manifest["image_layers"] = image.inspection[0]["RootFS"]["Layers"].clone();
        if let Some(expected) = expected_context
            && resume::context(&manifest) != *expected
        {
            return Err("the resumed runtime context differs from the completed pairs; no new measurement was started".into());
        }
        if variant_index == 0 {
            std::fs::write(
                output.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
        }
        let command = if variant == "rust" {
            strings(&[
                "/relay-bench-worker",
                "relay",
                "[2001:db8:101::2]:18080",
                "192.0.2.2:8080",
                "bench1",
                "bench0",
            ])
        } else {
            strings(&[
                "socat",
                "-b8192",
                "-t3600",
                "-T3600",
                &format!(
                    "TCP6-LISTEN:18080,bind=[2001:db8:101::2],ipv6only=1,reuseaddr,fork,max-children=32,backlog={backlog},rcvbuf={socket_buffer},sndbuf={socket_buffer}"
                ),
                &format!(
                    "TCP4:192.0.2.2:8080,connect-timeout=5,so-bindtodevice=bench1,rcvbuf={socket_buffer},sndbuf={socket_buffer}"
                ),
            ])
        };
        let refs: Vec<_> = command.iter().map(String::as_str).collect();
        let relay = lab.create(worker, &wan, "2001:db8:101::2", "2", None, &refs)?;
        docker(&strings(&[
            "network",
            "connect",
            "--driver-opt=com.docker.network.endpoint.ifname=bench1",
            "--ip",
            "192.0.2.1",
            &lan,
            &relay,
        ]))?;
        let availability_started = tokio::time::Instant::now();
        if spec.prepared {
            start_prepared(&lab, &relay)?;
        } else {
            docker(&strings(&["start", &relay]))?;
        }
        let route: Value = serde_json::from_str(&docker(&strings(&[
            "exec",
            &relay,
            "ip",
            "-j",
            "route",
            "get",
            "192.0.2.2",
        ]))?)?;
        if route[0]["dev"] != "bench1" {
            return Err("the benchmark LAN interface differs from its manifest".into());
        }
        if variant == "rust" {
            api.ready(&relay).await?;
        } else {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let listen = docker(&strings(&["exec", &relay, "cat", "/proc/net/tcp6"]))?;
                    if listen.lines().any(|line| {
                        line.contains(":46A0 ") && line.split_whitespace().nth(3) == Some("0A")
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok::<_, Box<dyn Error>>(())
            })
            .await??;
        }
        let availability_microseconds = availability_started.elapsed().as_micros();
        let tcp_parameters = docker(&strings(&[
            "exec",
            &relay,
            "cat",
            "/proc/sys/net/ipv4/ip_local_port_range",
            "/proc/sys/net/ipv4/tcp_tw_reuse",
        ]))?;
        spec.window.check_ports(&tcp_parameters)?;
        let observer = if spec.observation == Observation::Full {
            let observer = lab.create(
                &observer_worker,
                "none",
                "",
                "1",
                Some(&relay),
                &["/relay-bench-worker", "observe"],
            )?;
            if spec.prepared {
                start_prepared(&lab, &observer)?;
            } else {
                docker(&strings(&["start", &observer]))?;
            }
            api.ready(&observer).await?;
            Some(observer)
        } else {
            None
        };
        let generator_command = spec.generator_command("[2001:db8:101::2]:18080");
        let generator_refs: Vec<_> = generator_command.iter().map(String::as_str).collect();
        let network_owner = if retain_generator_network {
            Some(lab.generator_network_owner(workers.actors, &wan, "2001:db8:101::3")?)
        } else {
            None
        };
        let generator_network = network_owner
            .as_ref()
            .map_or_else(|| wan.clone(), |owner| format!("container:{owner}"));
        let generator = lab.create(
            &generator_worker,
            &generator_network,
            "2001:db8:101::3",
            "4",
            None,
            &generator_refs,
        )?;
        if spec.prepared {
            start_prepared(&lab, &generator)?;
            api.ready(&generator).await?;
        }
        let network_before = match &network_owner {
            Some(owner) => Some(api.stats(owner).await?),
            None => None,
        };
        let before = api.stats(&relay).await?;
        let origin_before = api.stats(&origin).await?;
        let epoch = tokio::time::Instant::now();
        if spec.prepared {
            docker(&strings(&[
                "exec",
                &generator,
                "touch",
                "/tmp/application-start",
            ]))?;
        } else {
            docker(&strings(&["start", &generator]))?;
        }
        let mut samples = Vec::new();
        let mut polls = 0_u32;
        let observed=tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let state = api.get(&format!("/containers/{generator}/json")).await?;
                if spec.observation == Observation::Full {
                    samples.push(json!({"elapsed_microseconds":epoch.elapsed().as_micros(),"relay":api.stats(&relay).await?,"origin":api.stats(&origin).await?,"generator":api.stats(&generator).await?,"generator_running":state["State"]["Running"]}));
                }
                if state["State"]["Running"] == false {
                    if state["State"]["ExitCode"] != 0 { return Err(format!("{variant} pilot failed: {}", docker(&strings(&["logs", &generator]))?).into()); }
                    break;
                }
                polls += 1;
                if polls >= 600 { return Err("pilot observation capacity exceeded".into()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_, Box<dyn Error>>(())
        }).await;
        let observed = match observed {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        if let Err(error) = observed {
            let mut actors = Vec::new();
            let mut failed = vec![
                ("relay", &relay),
                ("origin", &origin),
                ("generator", &generator),
            ];
            if let Some(observer) = &observer {
                failed.push(("observer", observer));
            }
            for (role, id) in failed {
                let inspection = api.get(&format!("/containers/{id}/json")).await?;
                let sockets = if inspection["State"]["Running"] == true {
                    Some(docker(&strings(&[
                        "exec",
                        id,
                        "cat",
                        "/proc/net/tcp",
                        "/proc/net/tcp6",
                    ]))?)
                } else {
                    None
                };
                actors.push(json!({"role":role,"inspection":inspection,"sockets":sockets,"log":docker(&strings(&["logs",id]))?}));
            }
            std::fs::write(
                output.join(format!("{variant}-failure.json")),
                serde_json::to_vec_pretty(
                    &json!({"error":error.to_string(),"samples":samples,"actors":actors}),
                )?,
            )?;
            return Err(error);
        }
        let result = client_result(&generator)?;
        let origin_result = if spec.echo() {
            Value::Null
        } else {
            api.bulk_result(&origin).await?
        };
        let mut observer_resources = Value::Null;
        let memory = if let Some(observer) = &observer {
            let observer_state = api.get(&format!("/containers/{observer}/json")).await?;
            if observer_state["State"]["Running"] != true {
                return Err(format!(
                    "the resource observer exited before measurement completion: {}",
                    docker(&strings(&["logs", observer]))?
                )
                .into());
            }
            observer_resources = api.stats(observer).await?;
            docker(&strings(&["kill", "--signal=TERM", observer]))?;
            if docker(&strings(&["wait", observer]))? != "0" {
                return Err("the PSS observer failed".into());
            }
            let observer_log = docker(&strings(&["logs", observer]))?;
            let memory: Value = serde_json::from_str(
                observer_log
                    .lines()
                    .last()
                    .ok_or("the PSS observer produced no report")?,
            )?;
            memory
        } else {
            Value::Null
        };
        let relay_state = api.get(&format!("/containers/{relay}/json")).await?;
        if relay_state["State"]["Running"] != true {
            return Err(format!(
                "{variant} relay exited unexpectedly: {}",
                docker(&strings(&["logs", &relay]))?
            )
            .into());
        }
        let mut report = json!({"variant":variant,"case":spec.description(),"workload":spec.workload,"connections":spec.connections,"availability_observed_microseconds_including_docker_control_and_route_check":availability_microseconds,"command":command,"generator_command":generator_command,"origin_command":origin_command,"result":result,"origin_result":origin_result,"memory_observer":memory,"relay_before":before,"relay_after":api.stats(&relay).await?,"origin_before":origin_before,"origin_after":api.stats(&origin).await?,"generator_after":api.stats(&generator).await?,"samples":samples});
        if let Some(owner) = &network_owner {
            let state = api.get(&format!("/containers/{owner}/json")).await?;
            if state["State"]["Running"] != true {
                return Err("generator network owner exited before peer confirmation".into());
            }
            report["generator_network"] = json!(RETAINED_GENERATOR_NETWORK);
            report["generator_network_owner"] = json!({"before":network_before,"after":api.stats(owner).await?,"state":state["State"],"scope":"independent owned endpoint cgroup; excluded from relay and generator resources"});
        }
        report["host_before"] = host_before;
        report["host_after"] = xtask::provenance::host_context();
        report["observation"] = json!(spec.observation.label());
        report["observer_resources_before_stop"] = observer_resources;
        if spec.observation != Observation::Full {
            report["observation_scope"] = json!(
                "no PSS observer or periodic cgroup sampling; integrity, completion polling and start/end cgroup counters remain; peaks and process snapshots unavailable"
            );
        }
        // This separate lifecycle window is deliberately excluded from the CPU cost.
        let shutdown_started = tokio::time::Instant::now();
        docker(&strings(&["kill", "--signal=TERM", &relay]))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let state = api.get(&format!("/containers/{relay}/json")).await?;
                if state["State"]["Running"] == false {
                    break Ok::<_, Box<dyn Error>>(state);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        report["normal_shutdown"] = json!({"elapsed_microseconds_including_docker_signal_and_observation":shutdown_started.elapsed().as_micros(),"state":stopped["State"]});
        report["tcp_parameters"] =
            json!({"fields":["ip_local_port_range","tcp_tw_reuse"],"values":tcp_parameters});
        report["relay_log"] = json!(docker(&strings(&["logs", &relay]))?);
        std::fs::write(
            output.join(format!("{variant}.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
        let exit = stopped["State"]["ExitCode"]
            .as_i64()
            .ok_or("missing relay exit status")?;
        if exit != 0 && !(variant == "socat" && exit == 143) {
            return Err(format!(
                "{variant} normal shutdown failed with exit {exit}: {}",
                docker(&strings(&["logs", &relay]))?
            )
            .into());
        }
        summaries.push(summarize_report(&report)?);
        docker(&strings(&["kill", "--signal=TERM", &origin]))?;
        if docker(&strings(&["wait", &origin]))? != "0" {
            return Err("the origin did not finish its owned work".into());
        }
        lab.remove(&generator)?;
        if let Some(observer) = observer {
            lab.remove(&observer)?;
        }
        lab.remove(&relay)?;
        lab.remove(&origin)?;
        if let Some(owner) = network_owner {
            lab.remove(&owner)?;
        }
    }
    lab.finish_networks()?;
    std::fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(&json!({"pair_complete":true,"results":summaries}))?,
    )?;
    println!("Raw results: {}", output.display());
    lab.failure_directory = None;
    Ok(summaries)
}
fn summarize_report(report: &Value) -> Result<Value> {
    match report["workload"].as_str().ok_or("missing workload")? {
        "latency" | "churn" => summarize(report),
        "idle" | "saturation" => {
            let bytes = report["result"]["verified_total_bytes"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or("missing operational verified bytes")?;
            if report["result"]["capacity_recovered"] != true {
                return Err("operational capacity was not recovered".into());
            }
            Ok(
                json!({"variant":report["variant"],"workload":report["workload"],"connections":report["connections"],
                "probe":report["result"],"resources":resource_summary(report,bytes)?,
                "cpu_scope":"whole setup, idle, resume and recovery; not an isolated idle CPU estimate"}),
            )
        }
        _ => summarize_bulk(report),
    }
}
fn summarize(report: &Value) -> Result<Value> {
    let histogram = report["result"]["histogram_microseconds"]
        .as_array()
        .ok_or("missing pilot histogram")?;
    let count = report["result"]["exchanges"]
        .as_u64()
        .ok_or("missing pilot count")?;
    if count == 0
        || histogram.len() != xtask::latency::BUCKETS
        || report["result"]["histogram_schema"] != xtask::latency::schema()
    {
        return Err("invalid pilot sample count or histogram size".into());
    }
    let total = histogram.iter().try_fold(0_u64, |total, bucket| {
        total
            .checked_add(bucket.as_u64().ok_or("invalid pilot histogram")?)
            .ok_or("pilot count overflow")
    })?;
    if total != count {
        return Err("pilot histogram and exchange count disagree".into());
    }
    let bins = histogram
        .iter()
        .map(|value| value.as_u64().ok_or("invalid pilot histogram"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let percentile = |percent: u8| xtask::latency::percentile_bounds(&bins, count, percent);
    let bytes = report["result"]["verified_total_bytes"]
        .as_u64()
        .filter(|bytes| *bytes > 0)
        .ok_or("missing total verified bytes")?;
    let resources = if report["variant"] == "direct" {
        Value::Null
    } else {
        resource_summary(report, bytes)?
    };
    if report["workload"] == "churn" {
        let expected = report["case"]["window"]["measured_cycles"]
            .as_u64()
            .ok_or("missing declared churn volume")?;
        let warmup = report["case"]["window"]["warmup_cycles"]
            .as_u64()
            .ok_or("missing declared warmup volume")?;
        let message = report["case"]["message_bytes"]
            .as_u64()
            .ok_or("missing churn message size")?;
        if count != expected
            || bytes
                != warmup
                    .checked_add(expected)
                    .and_then(|value| value.checked_mul(message))
                    .and_then(|value| value.checked_mul(2))
                    .ok_or("declared churn byte count overflow")?
        {
            return Err("churn did not verify the full planned volume".into());
        }
    }
    let elapsed = report["result"]["measured_elapsed_microseconds"]
        .as_f64()
        .filter(|value| *value > 0.0)
        .ok_or("missing measured interval")?
        / 1_000_000.0;
    let mut summary = json!({"variant":report["variant"],"workload":report["workload"],"connections":report["connections"],"exchanges":count,
        "latency_scope":if report["workload"]=="churn" {"connect, exact exchange and EOF"} else {"established request/response"},
        "exchanges_per_second":count as f64/elapsed,
        "percentile_method":"histogram bucket midpoint; lower-inclusive/upper-exclusive bounds provided",
        "overflow_exchanges":histogram.last(),"resources":resources,"comparative_inference":"none from an individual run; use paired campaign analysis"});
    let prefix = if report["workload"] == "churn" {
        "connection_cycle"
    } else {
        "rtt"
    };
    let mut intervals = serde_json::Map::new();
    for percent in [50, 95, 99] {
        let (lower, upper) = percentile(percent)?;
        let key = format!("{prefix}_p{percent}_microseconds");
        summary[&key] = json!((lower as f64 + upper as f64) / 2.0);
        intervals.insert(key, json!([lower, upper]));
    }
    summary["percentile_intervals_microseconds"] = Value::Object(intervals);
    if report["workload"] == "churn" && report["variant"] != "direct" {
        let warm = report["case"]["window"]["warmup_cycles"]
            .as_u64()
            .ok_or("missing warmup cycles")?;
        let measured = report["case"]["window"]["measured_cycles"]
            .as_u64()
            .ok_or("missing measured cycles")?;
        let completed = warm
            .checked_add(measured)
            .ok_or("completed cycle count overflow")?;
        let cpu = summary["resources"]["cpu_nanoseconds_including_warmup_and_drain"]
            .as_f64()
            .ok_or("missing cycle CPU count")?;
        summary["resources"]["cpu_microseconds_per_completed_cycle_including_warmup_and_drain"] =
            json!(cpu / 1000.0 / completed as f64);
    }
    Ok(summary)
}

fn memory_summary(report: &Value) -> Result<(Option<u64>, Option<u64>, Value, Value)> {
    match report.get("observation") {
        Some(value) if value == "boundary_only" => {
            if report["samples"]
                .as_array()
                .is_none_or(|samples| !samples.is_empty())
                || !report["memory_observer"].is_null()
            {
                return Err("boundary-only report contains periodic observer samples".into());
            }
            return Ok((None, None, Value::Null, Value::Null));
        }
        None => {} // Saved full-observation reports predate the explicit field.
        Some(value) if value == "full" => {}
        _ => return Err("unknown resource observation policy".into()),
    }
    let memory = report["samples"]
        .as_array()
        .ok_or("missing cgroup samples")?
        .iter()
        .map(|sample| {
            sample["relay"]["memory_stats"]["usage"]
                .as_u64()
                .ok_or("missing cgroup memory usage")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("no memory samples")?;
    let pss = report["memory_observer"]["samples"]
        .as_array()
        .ok_or("missing PSS samples")?
        .iter()
        .map(|sample| {
            sample["memory"]["pss_kib"]
                .as_u64()
                .ok_or("missing process PSS")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("no PSS samples")?;
    let samples = report["memory_observer"]["samples"]
        .as_array()
        .ok_or("missing process samples")?;
    let first = samples.first().ok_or("no process samples")?["memory"].clone();
    let last = samples.last().ok_or("no process samples")?["memory"].clone();
    Ok((Some(memory), Some(pss), first, last))
}

fn resource_counters(report: &Value) -> Result<Value> {
    let before = report["relay_before"]["cpu_stats"]["cpu_usage"]["total_usage"]
        .as_u64()
        .ok_or("missing cgroup CPU baseline")?;
    let after = report["relay_after"]["cpu_stats"]["cpu_usage"]["total_usage"]
        .as_u64()
        .ok_or("missing cgroup CPU result")?;
    let (memory, pss, first, last) = memory_summary(report)?;
    let cpu = after
        .checked_sub(before)
        .ok_or("cgroup CPU counter regressed")?;
    let delta = |name: &str| -> Result<u64> {
        let previous = report["relay_before"]["cpu_stats"]["cpu_usage"][name]
            .as_u64()
            .ok_or("missing CPU mode baseline")?;
        report["relay_after"]["cpu_stats"]["cpu_usage"][name]
            .as_u64()
            .ok_or("missing CPU mode counter")?
            .checked_sub(previous)
            .ok_or_else(|| "CPU mode counter regressed".into())
    };
    Ok(
        json!({"cpu_nanoseconds_including_warmup_and_drain":cpu,"cpu_user_nanoseconds":delta("usage_in_usermode")?,"cpu_kernel_nanoseconds":delta("usage_in_kernelmode")?,"sampled_cgroup_peak_bytes":memory,
        "sampled_process_pss_peak_kib":pss,"processes_at_start":first,"processes_at_end":last}),
    )
}

fn resource_summary(report: &Value, verified_bytes: u64) -> Result<Value> {
    let mut resources = resource_counters(report)?;
    let cpu = resources["cpu_nanoseconds_including_warmup_and_drain"]
        .as_u64()
        .ok_or("missing derived CPU counter")?;
    // Integer counters remain authoritative; this derived rate is approximate.
    let cpu_per_gib = (cpu as f64 / 1_000_000_000.0) / (verified_bytes as f64 / 1_073_741_824.0);
    resources["verified_total_bytes"] = json!(verified_bytes);
    resources["cpu_seconds_per_gib_including_warmup_and_drain"] = json!(cpu_per_gib);
    Ok(resources)
}

fn summarize_bulk(report: &Value) -> Result<Value> {
    use std::collections::{BTreeMap, BTreeSet};
    let clients = report["result"]["connections"]
        .as_array()
        .ok_or("missing bulk client results")?;
    let origins = report["origin_result"]["connections"]
        .as_array()
        .ok_or("missing bulk origin results")?;
    let expected = report["connections"]
        .as_u64()
        .ok_or("missing connection count")?;
    if u64::try_from(clients.len())? != expected || origins.len() != clients.len() {
        return Err("bulk session counts disagree".into());
    }
    let mut index = BTreeMap::new();
    for origin in origins {
        let id = origin["id"].as_u64().ok_or("missing bulk session ID")?;
        if id >= expected || index.insert(id, origin).is_some() {
            return Err("duplicate or invalid bulk origin ID".into());
        }
    }
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    let mut up = 0_u64;
    let mut down = 0_u64;
    let count = |value: &Value, key: &str| -> Result<u64> {
        value[key]
            .as_u64()
            .ok_or_else(|| format!("missing bulk counter: {key}").into())
    };
    for client in clients {
        let id = client["id"].as_u64().ok_or("missing bulk client ID")?;
        if !seen.insert(id) {
            return Err("duplicate bulk client ID".into());
        }
        let origin = index.get(&id).ok_or("bulk client has no origin result")?;
        let sent = count(client, "sent_total")?;
        let received = count(client, "received_total")?;
        if sent != count(origin, "received_total")? || received != count(origin, "sent_total")? {
            return Err(
                "bulk stream was truncated, duplicated or delivered to another client".into(),
            );
        }
        total = total
            .checked_add(sent)
            .and_then(|value| value.checked_add(received))
            .ok_or("bulk byte count overflow")?;
        up = up
            .checked_add(count(origin, "received_measured")?)
            .ok_or("bulk rate overflow")?;
        down = down
            .checked_add(count(client, "received_measured")?)
            .ok_or("bulk rate overflow")?;
    }
    if total == 0 {
        return Err("the bulk pilot transferred no data".into());
    }
    let workload = report["workload"].as_str().ok_or("missing bulk workload")?;
    if (["upload", "duplex", "slow-upload"].contains(&workload) && up == 0)
        || (["download", "duplex", "slow-download"].contains(&workload) && down == 0)
    {
        return Err("the requested bulk direction delivered no measured data".into());
    }
    let seconds = report["result"]["measured_seconds"]
        .as_u64()
        .filter(|seconds| *seconds > 0)
        .ok_or("invalid measurement duration")?;
    Ok(
        json!({"variant":report["variant"],"workload":report["workload"],"connections":expected,
        "upload_received_bytes_per_second":up as f64 / seconds as f64,"download_received_bytes_per_second":down as f64 / seconds as f64,
        "resources":if report["variant"] == "direct" { Value::Null } else {resource_summary(report,total)?},"comparative_inference":"none from an individual run; use paired campaign analysis"}),
    )
}
fn actor_copy(worker: &Path, role: &str) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = worker
        .parent()
        .ok_or("missing worker snapshot directory")?
        .join(format!("{role}-worker"));
    std::fs::copy(worker, &path)?;
    let original = std::fs::metadata(worker)?;
    let copy = std::fs::metadata(&path)?;
    if original.dev() == copy.dev() && original.ino() == copy.ino() {
        return Err("benchmark actor executables must use distinct inodes".into());
    }
    Ok(path)
}

fn digest(path: &Path) -> Result<String> {
    let output = Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err("worker digest failed".into());
    }
    String::from_utf8(output.stdout)?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "missing worker digest".into())
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    #[test]
    fn r152c_network_lifetime_validation_refuses_mixed_policies_and_missing_live_owner_evidence()
    -> Result {
        validate_generator_network(&json!({}), &json!({}), Some(&json!({})))?;
        let plan = json!({"generator_network":RETAINED_GENERATOR_NETWORK});
        let manifest = plan.clone();
        let raw = json!({"generator_network":RETAINED_GENERATOR_NETWORK,"generator_network_owner":{"state":{"Running":true},"before":{},"after":{}}});
        validate_generator_network(&plan, &manifest, Some(&raw))?;
        for change in [
            "unknown_policy",
            "legacy_manifest",
            "legacy_raw",
            "stopped_owner",
            "missing_before",
            "missing_after",
        ] {
            let mut changed_plan = plan.clone();
            let mut changed_manifest = manifest.clone();
            let mut changed_raw = raw.clone();
            match change {
                "unknown_policy" => changed_plan["generator_network"] = json!("unknown"),
                "legacy_manifest" => changed_manifest = json!({}),
                "legacy_raw" => changed_raw = json!({}),
                "stopped_owner" => {
                    changed_raw["generator_network_owner"]["state"]["Running"] = json!(false)
                }
                "missing_before" => changed_raw["generator_network_owner"]["before"] = Value::Null,
                "missing_after" => changed_raw["generator_network_owner"]["after"] = Value::Null,
                _ => return Err("unknown network policy counterfactual".into()),
            }
            assert!(
                validate_generator_network(&changed_plan, &changed_manifest, Some(&changed_raw))
                    .is_err(),
                "invalid network lifetime accepted: {change}"
            );
        }
        assert!(validate_generator_network(&json!({}), &manifest, Some(&raw)).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires current local worker/image, a new evidence directory, Docker and no active measurement"]
    fn r152b_retained_endpoint_duplex_qualification_preserves_all_bytes_and_eof_in_three_pairs()
    -> Result {
        let cargo = std::env::var_os("CARGO").ok_or("missing Cargo")?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let worker = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_BENCHMARK_WORKER").ok_or("provide a worker")?,
        )
        .canonicalize()?;
        let image = std::env::var("TUNNEL_DETOUR_BENCHMARK_IMAGE")?;
        let output = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_RETAINED_DUPLEX_EVIDENCE")
                .ok_or("provide a new evidence directory")?,
        );
        let cases: Vec<_> = (0..3)
            .map(|repetition| Scenario {
                prepared: true,
                workload: "duplex",
                connections: 4,
                message_bytes: 0,
                window: Measurement::Timed {
                    warmup: 5,
                    seconds: 20,
                },
                reverse: repetition % 2 == 0,
                repetition,
                observation: Observation::BoundaryOnly,
            })
            .collect();
        run_plan_with_source(
            &cargo,
            &root,
            &output,
            &cases,
            PlanKind::PilotMatrix,
            WorkerSource::Frozen {
                worker: &worker,
                image: &image,
            },
        )
    }

    #[test]
    #[ignore = "requires a local worker/image, new evidence directory, Docker and no active measurement"]
    fn r152_generator_exit_requires_a_live_owned_endpoint_until_peer_payload_and_eof_confirmation()
    -> Result {
        let cargo = std::env::var_os("CARGO").ok_or("missing Cargo")?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let _activity = activity_lock(&cargo_target(&cargo, &root)?)?;
        let worker = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_BENCHMARK_WORKER").ok_or("provide a worker")?,
        )
        .canonicalize()?;
        let image = std::env::var("TUNNEL_DETOUR_BENCHMARK_IMAGE")?;
        let evidence = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_NAMESPACE_EVIDENCE")
                .ok_or("provide a new evidence directory")?,
        );
        std::fs::create_dir(&evidence)?;
        let inputs = xtask::provenance::source_inputs(&root)?;
        xtask::provenance::archive_inputs(&root, &inputs, &evidence.join("source.tar"))?;
        std::fs::copy(&worker, evidence.join("relay-bench-worker"))?;
        std::fs::write(
            evidence.join("manifest.json"),
            serde_json::to_vec_pretty(
                &json!({"worker_sha256":digest(&worker)?,"image":image,"source_inputs":inputs,"source_archive_sha256":digest(&evidence.join("source.tar"))?,"expected_bytes":262144,"receiver_bytes_before_release":0,"scope":"real Docker endpoints, no relay; controlled queued close and delayed reader"}),
            )?,
        )?;
        let connection: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
        let socket = connection[0]["Endpoints"]["docker"]["Host"]
            .as_str()
            .and_then(|value| value.strip_prefix("unix://"))
            .ok_or("local Docker socket required")?;
        let api = Api(reqwest::Client::builder()
            .no_proxy()
            .unix_socket(socket)
            .connect_timeout(Duration::from_secs(3))
            .build()?);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            for anchored in [false,true] {
                let directory = evidence.join(if anchored {"retained-endpoint"} else {"exiting-endpoint"});
                std::fs::create_dir(&directory)?;
                let mut lab = Lab {containers:Vec::new(),networks:Vec::new(),failure_directory:Some(directory.clone()),actor_image:Some(image.clone())};
                let network = lab.network(&format!("td-namespace-{}-{anchored}",std::process::id()),"192.0.2.0/24","192.0.2.254",false)?;
                let origin = lab.create(&worker,&network,"192.0.2.2","1",None,&["/relay-bench-worker","namespace-origin","192.0.2.2:8080"])?;
                start_prepared(&lab,&origin)?;
                api.ready(&origin).await?;
                let anchor = if anchored {
                    let owner=lab.generator_network_owner(&worker,&network,"192.0.2.3")?;
                    let inspected=api.get(&format!("/containers/{owner}/json")).await?;
                    assert_eq!(inspected["State"]["Running"],true);
                    assert_eq!(inspected["HostConfig"]["Dns"],json!(["127.0.0.1"]));
                    Some(owner)
                } else {None};
                let client_network=anchor.as_ref().map_or_else(||network.clone(),|owner|format!("container:{owner}"));
                assert!(lab.create(&worker,"container:unowned","","1",None,&["/bin/sleep","1"]).is_err(),"unowned network namespace was accepted");
                let client=lab.create(&worker,&client_network,"192.0.2.3","1",None,&["/relay-bench-worker","namespace-client","192.0.2.2:8080"])?;
                start_prepared(&lab,&client)?;
                tokio::time::timeout(Duration::from_secs(10),async {
                    loop {
                        let state=api.get(&format!("/containers/{client}/json")).await?;
                        if state["State"]["Running"]==false {
                            if state["State"]["ExitCode"]!=0 {return Err("queued-close sender failed before its intended exit".into());}
                            break Ok::<_,Box<dyn Error>>(());
                        }
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                }).await??;
                let client_log=docker(&strings(&["logs",&client]))?;
                let queued:Value=serde_json::from_str(client_log.lines().last().ok_or("sender produced no report")?)?;
                assert_eq!(queued["queued_bytes"],262144);
                tokio::time::timeout(Duration::from_secs(10),async {
                    loop {
                        let inspected=api.get(&format!("/networks/{network}")).await?;
                        let endpoints=inspected["Containers"].as_object().ok_or("missing network endpoints")?;
                        let ready=match &anchor {Some(owner)=>endpoints.contains_key(owner),None=>!endpoints.contains_key(&client)};
                        if ready {break Ok::<_,Box<dyn Error>>(());}
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                }).await??;
                docker(&strings(&["exec",&origin,"touch","/tmp/application-start"]))?;
                let observed=tokio::time::timeout(Duration::from_secs(10),async {
                    loop {
                        let log=docker(&strings(&["logs",&origin]))?;
                        if let Some(report)=log.lines().filter_map(|line|serde_json::from_str::<Value>(line).ok()).find(|value|value.get("received_bytes").is_some()) {break Ok::<_,Box<dyn Error>>(report);}
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                }).await??;
                std::fs::write(directory.join("observed.json"),serde_json::to_vec_pretty(&json!({"anchored":anchored,"sender":queued,"peer":observed,"client_exit":api.get(&format!("/containers/{client}/json")).await?["State"],"network":api.get(&format!("/networks/{network}")).await?}))?)?;
                if anchored {
                    assert_eq!(observed["complete"],true,"retained namespace did not deliver every queued byte and EOF");
                    assert_eq!(observed["received_bytes"],262144);
                    assert_eq!(observed["eof"],true);
                    docker(&strings(&["kill","--signal=TERM",&origin]))?;
                    assert_eq!(docker(&strings(&["wait",&origin]))?,"0");
                } else {
                    assert_eq!(observed["complete"],false,"unanchored control did not reproduce endpoint teardown loss");
                    assert!(observed["received_bytes"].as_u64().is_some_and(|bytes|bytes<262144)||observed["eof"]==false);
                    assert_eq!(docker(&strings(&["wait",&origin]))?,"1");
                }
                // Preserve both controls before explicit checked cleanup.
                let mut actors=Vec::new();
                for id in &lab.containers {actors.push(json!({"id":id,"state":api.get(&format!("/containers/{id}/json")).await?["State"],"log":docker(&strings(&["logs",id]))?}));}
                std::fs::write(directory.join("actors.json"),serde_json::to_vec_pretty(&actors)?)?;
                for id in lab.containers.clone().iter().rev() {lab.remove(id)?;}
                docker(&strings(&["network","rm",&network]))?;
                lab.networks.retain(|id|id!=&network);
                lab.failure_directory=None;
            }
            Ok::<_,Box<dyn Error>>(())
        })
    }

    #[test]
    #[ignore = "requires a declared local worker/image, Docker and no active measurement"]
    fn r147d_bulk_origin_preparation_delay_preserves_the_connected_integrity_window() -> Result {
        delayed_bulk_preparation(false)
    }

    #[test]
    #[ignore = "requires a protocol-2 local worker/image and no active measurement"]
    fn r147e_prepared_generator_cannot_connect_until_the_driver_releases_its_barrier() -> Result {
        delayed_bulk_preparation(true)
    }

    fn delayed_bulk_preparation(prepared: bool) -> Result {
        let cargo = std::env::var_os("CARGO").ok_or("missing Cargo")?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let _activity = activity_lock(&cargo_target(&cargo, &root)?)?;
        let image = std::env::var("TUNNEL_DETOUR_BENCHMARK_IMAGE")?;
        let worker = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_BENCHMARK_WORKER").ok_or("provide a local worker")?,
        )
        .canonicalize()?;
        let directory = tempfile::tempdir()?;
        let mut lab = Lab {
            failure_directory: Some(directory.path().to_owned()),
            actor_image: Some(image),
            containers: Vec::new(),
            networks: Vec::new(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let connection: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
        let socket = connection[0]["Endpoints"]["docker"]["Host"]
            .as_str()
            .and_then(|value| value.strip_prefix("unix://"))
            .ok_or("local Docker socket required")?;
        let api = Api(reqwest::Client::builder()
            .no_proxy()
            .unix_socket(socket)
            .connect_timeout(Duration::from_secs(3))
            .build()?);
        let exercise = async {
            let network = lab.network(
                &format!("td-delayed-bulk-{}", std::process::id()),
                "192.0.2.0/24",
                "192.0.2.254",
                false,
            )?;
            let origin = lab.create(
                &worker,
                &network,
                "192.0.2.2",
                "1",
                None,
                &["/relay-bench-worker", "bulk-origin", "192.0.2.2:8080", "1"],
            )?;
            docker(&strings(&["start", &origin]))?;
            api.ready(&origin).await?;
            let spec = Scenario {
                prepared,
                workload: "download",
                connections: 1,
                message_bytes: 0,
                window: Measurement::Timed {
                    warmup: 0,
                    seconds: 1,
                },
                reverse: false,
                repetition: 0,
                observation: Observation::BoundaryOnly,
            };
            let command = spec.generator_command("192.0.2.2:8080");
            let arguments: Vec<_> = command.iter().map(String::as_str).collect();
            let client = lab.create(&worker, &network, "192.0.2.3", "1", None, &arguments)?;
            if prepared {
                start_prepared(&lab, &client)?;
                api.ready(&client).await?;
            }
            // Deliberate preparation delay. No TCP connection may begin until
            // after this interval, even if the generator is already ready.
            tokio::time::sleep(Duration::from_secs(6)).await;
            let state = api.get(&format!("/containers/{origin}/json")).await?;
            if state["State"]["Running"] != true {
                return Err(
                    "origin consumed its connected deadline before any client existed".into(),
                );
            }
            if prepared {
                let sockets = docker(&strings(&["exec", &origin, "cat", "/proc/net/tcp"]))?;
                assert!(
                    !sockets.lines().any(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        fields
                            .get(1)
                            .is_some_and(|address| address.ends_with(":1F90"))
                            && fields.get(3) == Some(&"01")
                    }),
                    "prepared generator opened a TCP connection before its trigger"
                );
                let log = docker(&strings(&["logs", &origin]))?;
                assert!(
                    !log.contains("\"connections\""),
                    "prepared generator completed work before admission"
                );
                docker(&strings(&[
                    "exec",
                    &client,
                    "touch",
                    "/tmp/application-start",
                ]))?;
            } else {
                docker(&strings(&["start", &client]))?;
            }
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let state = api.get(&format!("/containers/{client}/json")).await?;
                    if state["State"]["Running"] == false {
                        if state["State"]["ExitCode"] != 0 {
                            return Err("delayed bulk client failed integrity".into());
                        }
                        break Ok::<_, Box<dyn Error>>(());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await??;
            let result = client_result(&client)?;
            let source = api.bulk_result(&origin).await?;
            let received = result["connections"][0]["received_total"]
                .as_u64()
                .ok_or("missing received payload")?;
            let sent = source["connections"][0]["sent_total"]
                .as_u64()
                .ok_or("missing sent payload")?;
            assert!(
                received > 0,
                "delayed startup must still transfer verified payload"
            );
            assert_eq!(
                received, sent,
                "the entire delayed-start stream must arrive exactly"
            );
            docker(&strings(&["kill", "--signal=TERM", &origin]))?;
            assert_eq!(docker(&strings(&["wait", &origin]))?, "0");
            Ok::<_, Box<dyn Error>>(())
        };
        let result = runtime.block_on(exercise);
        if result.is_ok() {
            lab.failure_directory = None;
        }
        result
    }

    #[test]
    #[ignore = "requires the qualified local OpenWrt image and no active measurement"]
    fn r147c_uncertain_preparation_records_one_observation_and_refuses_a_stopped_actor() -> Result {
        let cargo = std::env::var_os("CARGO").ok_or("missing Cargo")?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let _activity = activity_lock(&cargo_target(&cargo, &root)?)?;
        let image = std::env::var("TUNNEL_DETOUR_BENCHMARK_IMAGE")?;
        let directory = tempfile::tempdir()?;
        let mut lab = Lab {
            failure_directory: Some(directory.path().to_owned()),
            actor_image: None,
            containers: Vec::new(),
            networks: Vec::new(),
        };
        let id = docker(&strings(&[
            "create",
            "--label",
            "tunnel-detour.task=relay-benchmark",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--memory",
            "16m",
            "--cpus",
            "1",
            "--entrypoint",
            "/bin/sleep",
            &image,
            "60",
        ]))?;
        lab.containers.push(id.clone());
        docker(&strings(&["start", &id]))?;
        let before: Value = serde_json::from_str(&docker(&strings(&[
            "inspect",
            "--format",
            "{{json .State}}",
            &id,
        ]))?)?;
        prepared_start_result(
            &lab,
            &id,
            Err("synthetic lost start acknowledgement".into()),
        )?;
        let after: Value = serde_json::from_str(&docker(&strings(&[
            "inspect",
            "--format",
            "{{json .State}}",
            &id,
        ]))?)?;
        assert_eq!(
            before["StartedAt"], after["StartedAt"],
            "observation must preserve the actual start"
        );
        assert_eq!(
            before["Pid"], after["Pid"],
            "observation must not replace the actor"
        );
        // This bare sleep is PID 1 and has no TERM handler. Make the stopped
        // control explicit instead of waiting for its natural sixty-second exit.
        docker(&strings(&["kill", "--signal=KILL", &id]))?;
        docker(&strings(&["wait", &id]))?;
        assert!(
            prepared_start_result(
                &lab,
                &id,
                Err("synthetic lost acknowledgement for stopped actor".into())
            )
            .is_err(),
            "stopped actors cannot be treated as available"
        );
        let evidence =
            std::fs::read_dir(directory.path())?.collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(
            evidence.len(),
            2,
            "both uncertain outcomes must remain recorded"
        );
        for entry in evidence {
            let record: Value = serde_json::from_slice(&std::fs::read(entry.path())?)?;
            assert_eq!(record["actor"], id);
            assert_eq!(record["start_replayed"], false);
            assert!(
                record["start_error"]
                    .as_str()
                    .is_some_and(|error| error.contains("synthetic lost"))
            );
        }
        assert!(
            prepared_start_result(&lab, "unowned", Ok(String::new())).is_err(),
            "unowned actors must never be accepted"
        );
        lab.remove(&id)?;
        lab.failure_directory = None;
        Ok(())
    }

    #[test]
    fn r143_campaign_policy_is_uniform_explicit_and_preserves_legacy_case_coordinates() -> Result {
        let legacy = Scenario {
            prepared: false,
            workload: "latency",
            connections: 1,
            message_bytes: 64,
            window: Measurement::Timed {
                warmup: 5,
                seconds: 20,
            },
            reverse: false,
            repetition: 0,
            observation: Observation::Full,
        };
        assert_eq!(
            legacy.description(),
            json!({"workload":"latency","connections":1,"message_bytes":64,
            "window":{"kind":"timed","warmup_seconds":5,"measured_seconds":20},
            "socat_first":false,"repetition":0})
        );
        assert!(
            Observation::from_plan(&json!({}))? == Observation::Full,
            "saved legacy plans changed policy"
        );
        assert!(
            Observation::from_plan(&json!({"observation":"boundary_only"}))?
                == Observation::BoundaryOnly
        );
        for value in [
            json!(false),
            json!({"observation":"unknown"}),
            json!({"observation":false}),
            json!({"observation":null}),
        ] {
            assert!(
                Observation::from_plan(&value).is_err(),
                "invalid policy became a default"
            );
        }
        let mut boundary = legacy;
        boundary.observation = Observation::BoundaryOnly;
        assert!(
            uniform_observation(&[legacy, boundary]).is_err(),
            "different treatments entered one comparison"
        );
        assert!(uniform_observation(&[]).is_err());
        let full = campaign_cases_for(Observation::Full)?;
        let boundary = campaign_cases_for(Observation::BoundaryOnly)?;
        assert_eq!(
            full.len(),
            196,
            "seven repetitions of 28 specified load coordinates are required"
        );
        assert_eq!(boundary.len(), full.len());
        assert!(uniform_observation(&boundary)? == Observation::BoundaryOnly);
        for (full, boundary) in full.iter().zip(boundary) {
            let mut description = boundary.description();
            assert_eq!(description["observation"], "boundary_only");
            description
                .as_object_mut()
                .ok_or("case must be an object")?
                .remove("observation");
            assert_eq!(
                description,
                full.description(),
                "changing observation altered a workload coordinate"
            );
        }
        Ok(())
    }

    #[test]
    fn r140_boundary_observation_keeps_unmeasured_memory_unknown_and_preserves_real_cpu() -> Result
    {
        let mut report = json!({
            "observation":"boundary_only", "samples":[], "memory_observer":null,
            "relay_before":{"cpu_stats":{"cpu_usage":{"total_usage":100,"usage_in_usermode":40,"usage_in_kernelmode":60}}},
            "relay_after":{"cpu_stats":{"cpu_usage":{"total_usage":130,"usage_in_usermode":50,"usage_in_kernelmode":80}}}
        });
        let summary = resource_summary(&report, 4096)?;
        assert_eq!(summary["cpu_nanoseconds_including_warmup_and_drain"], 30);
        assert_eq!(summary["cpu_user_nanoseconds"], 10);
        assert_eq!(summary["cpu_kernel_nanoseconds"], 20);
        for field in [
            "sampled_cgroup_peak_bytes",
            "sampled_process_pss_peak_kib",
            "processes_at_start",
            "processes_at_end",
        ] {
            assert!(
                summary[field].is_null(),
                "unmeasured {field} was fabricated"
            );
        }
        report["samples"] = json!([
            {"relay":{"memory_stats":{"usage":4096}}},
            {"relay":{"memory_stats":{"usage":8192}}}
        ]);
        assert!(
            resource_summary(&report, 4096).is_err(),
            "contradictory periodic sampling was accepted"
        );
        report["samples"] = json!([]);
        report["memory_observer"] =
            json!({"samples":[{"memory":{"pss_kib":64}},{"memory":{"pss_kib":32}}]});
        assert!(
            resource_summary(&report, 4096).is_err(),
            "contradictory process sampling was accepted"
        );
        report["observation"] = json!("full");
        report["samples"] = json!([
            {"relay":{"memory_stats":{"usage":4096}}},
            {"relay":{"memory_stats":{"usage":8192}}}
        ]);
        let full = resource_summary(&report, 4096)?;
        assert_eq!(full["sampled_cgroup_peak_bytes"], 8192);
        assert_eq!(full["sampled_process_pss_peak_kib"], 64);
        assert_eq!(full["processes_at_start"]["pss_kib"], 64);
        assert_eq!(full["processes_at_end"]["pss_kib"], 32);
        report
            .as_object_mut()
            .ok_or("report must be an object")?
            .remove("observation");
        assert_eq!(
            resource_summary(&report, 4096)?,
            full,
            "legacy full-observation reports changed"
        );
        Ok(())
    }
}
