//! Native application observations with actual DNS frontends, Fake-IP HTTP and WireGuard.
//! This is a descriptive x86 qualification matrix, separate from transport comparisons.

use super::integrated::{
    copy_into, dns_status, exec, node, observer, ready_dns, stop_observer, wait_native,
};
use super::*;
use std::{fs, io::Write, time::Instant};

#[path = "application_continuation.rs"]
mod continuation;
pub use continuation::resume_matrix;

const PASSWORD: &str = "synthetic-benchmark-password";
const SCOPE: &str = "entire native OpenWrt cgroup including UCI/procd/rpcd/firewall4, the selected DNS frontend, Tunnel Detour controller and isolated workers; generators, origins, VPN peer/resolver and PSS observer are separate cgroups";

/// Select a declared short qualification, descriptive matrix or persistent soak.
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Pilot,
    ChurnPilot,
    Matrix,
    SoakPilot,
    Soak,
}

#[derive(Clone, Copy)]
struct Case {
    adguard: bool,
    rules: usize,
    occupied: usize,
    churn: bool,
    http_qps: u64,
}
impl Case {
    fn description(self) -> Value {
        json!({"frontend":if self.adguard {"adguard"} else {"dnsmasq"},"rules":self.rules,"initial_live_identities":self.occupied,"mapping_limit":128,"primary_pattern":"***.selected.example.net","dns_cache":"disabled only in the synthetic frontend fixture","http_connection_reuse":!self.churn,"http_qps_per_route":self.http_qps,"seconds":20})
    }
}

fn input(id: &str, arguments: &[&str], bytes: &[u8]) -> Result<String> {
    let mut child = Command::new("timeout")
        .args(["--kill-after=2", "30", "docker", "exec", "-i", id])
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let written = match child.stdin.take() {
        Some(mut pipe) => pipe.write_all(bytes),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "missing application fixture stdin",
        )),
    };
    let output = child.wait_with_output()?;
    written?;
    if !output.status.success() {
        return Err(format!(
            "application fixture command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn control(node: &str, operation: &str, body: Option<Value>, authenticated: bool) -> Result<Value> {
    let mut arguments = strings(&[
        "curl",
        "--noproxy",
        "*",
        "--silent",
        "--show-error",
        "--fail",
        "--max-time",
        "5",
    ]);
    if authenticated {
        arguments.extend(strings(&["--user", &format!("benchmark:{PASSWORD}")]));
    }
    if body.is_some() {
        arguments.extend(strings(&[
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ]));
    }
    arguments.push(format!("http://127.0.0.1:13000/control/{operation}"));
    let refs: Vec<_> = arguments.iter().map(String::as_str).collect();
    let output = input(
        node,
        &refs,
        &body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .unwrap_or_default(),
    )?;
    if body.is_some() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&output)?)
}

async fn configure_adguard(node: &str, directory: &Path) -> Result {
    // Keep retained query logs on the owned container's disk-backed layer.
    // A tmpfs workdir would count those logs as unreclaimable application RAM.
    let instance = json!({"name":"application-adguard","instances":{"main":{"command":["/usr/bin/AdGuardHome","--no-check-update","--web-addr","127.0.0.1:13000","-w","/opt/application-adguard","-c","/opt/application-adguard/config.yaml"],"stdout":true,"stderr":true}}});
    exec(
        node,
        &["mkdir", "-p", "-m", "700", "/opt/application-adguard"],
    )?;
    exec(
        node,
        &["ubus", "call", "service", "set", &instance.to_string()],
    )?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while control(node, "install/get_addresses", None, false).is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    control(
        node,
        "install/configure",
        Some(
            json!({"web":{"ip":"127.0.0.1","port":13000},"dns":{"ip":"0.0.0.0","port":53},"username":"benchmark","password":PASSWORD}),
        ),
        false,
    )?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while control(node, "status", None, true).is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    if control(node, "status", None, true)?["version"] != "v0.107.80" {
        return Err("application measurement requires the pinned AdGuard fixture version".into());
    }
    // The pinned AdGuard fixture uses an explicit cache-enabled flag. Its
    // per-client DNS rate limit is disabled only here so the declared offered
    // load measures the application rather than the frontend's default quota.
    control(
        node,
        "dns_config",
        Some(
            json!({"upstream_dns":["tcp://10.254.0.2:53"],"bootstrap_dns":["10.254.0.2:53"],"fallback_dns":[],"upstream_dns_file":"","cache_enabled":false,"cache_size":1048576,"cache_optimistic":false,"ratelimit":0,"blocking_mode":"null_ip"}),
        ),
        true,
    )?;
    let policy = control(node, "dns_info", None, true)?;
    if policy["cache_enabled"] != false || policy["ratelimit"] != 0 {
        return Err(
            "synthetic AdGuard did not apply its explicit cache/rate-limit measurement policy"
                .into(),
        );
    }
    let subscriptions = control(node, "filtering/status", None, true)?;
    fs::write(
        directory.join("adguard-subscriptions-before.json"),
        serde_json::to_vec_pretty(&subscriptions)?,
    )?;
    for (field, whitelist) in [("filters", false), ("whitelist_filters", true)] {
        match subscriptions.get(field) {
            Some(Value::Null) => {}
            Some(Value::Array(entries)) => {
                for subscription in entries {
                    control(
                        node,
                        "filtering/remove_url",
                        Some(json!({"url":subscription["url"],"whitelist":whitelist})),
                        true,
                    )?;
                }
            }
            _ => return Err("missing or invalid synthetic subscription list".into()),
        }
    }
    let subscriptions = control(node, "filtering/status", None, true)?;
    fs::write(
        directory.join("adguard-subscriptions-after.json"),
        serde_json::to_vec_pretty(&subscriptions)?,
    )?;
    for field in ["filters", "whitelist_filters"] {
        // The pinned Go API leaves empty response slices nil, encoding null.
        if !matches!(subscriptions.get(field), Some(Value::Null))
            && !subscriptions
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return Err("synthetic AdGuard retained an external filter subscription".into());
        }
    }
    exec(
        node,
        &[
            "ubus",
            "call",
            "service",
            "delete",
            "{\"name\":\"application-adguard\"}",
        ],
    )?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while exec(node, &["pidof", "AdGuardHome"]).is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let settings = exec(node, &["cat", "/opt/application-adguard/config.yaml"])?;
    if !settings.contains("    whois: true\n") {
        return Err("unexpected synthetic AdGuard WHOIS setting".into());
    }
    input(
        node,
        &["tee", "/opt/application-adguard/config.yaml"],
        settings
            .replace("    whois: true\n", "    whois: false\n")
            .as_bytes(),
    )?;
    exec(
        node,
        &["ubus", "call", "service", "set", &instance.to_string()],
    )?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while control(node, "status", None, true).is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    for (name, value) in [
        ("adguard_url", "http://127.0.0.1:13000"),
        ("adguard_username", "benchmark"),
        ("adguard_password", PASSWORD),
    ] {
        exec(
            node,
            &[
                "uci",
                "set",
                &format!("tunnel-detour.globals.{name}={value}"),
            ],
        )?;
    }
    Ok(())
}

fn actor(
    lab: &mut Lab,
    worker: &Path,
    node: &str,
    namespace: &str,
    command: &[&str],
) -> Result<String> {
    let mut args = strings(&[
        "create",
        "--label",
        "tunnel-detour.task=relay-benchmark",
        "--network",
        "none",
        "--pid",
        &format!("container:{node}"),
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--cap-add",
        "SYS_ADMIN",
        "--cap-add",
        "SYS_PTRACE",
        "--security-opt",
        "apparmor=unconfined",
        "--read-only",
        "--cgroupns",
        "private",
        "--memory",
        "256m",
        "--cpus",
        "4",
        "--dns",
        "127.0.0.1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=4m",
        "--mount",
        &format!(
            "type=bind,src={},dst=/relay-bench-worker,readonly",
            worker.display()
        ),
        "--env",
        "TUNNEL_DETOUR_BENCH_LAB=1",
        "--env",
        &format!("TUNNEL_DETOUR_BENCH_NETNS={namespace}"),
    ]);
    args.push(
        lab.actor_image
            .as_deref()
            .ok_or("missing frozen application actor image")?
            .into(),
    );
    args.extend(strings(command));
    let id = docker(&args)?;
    lab.containers.push(id.clone());
    start_prepared(lab, &id)?;
    Ok(id)
}

fn key(node: &str, path: &str) -> Result<String> {
    let private = exec(node, &["wg", "genkey"])?;
    exec(node, &["touch", path])?;
    exec(node, &["chmod", "600", path])?;
    input(node, &["tee", path], private.as_bytes())?;
    input(node, &["wg", "pubkey"], private.as_bytes())
}

fn wireguard(node: &str, peer: &str) -> Result {
    let exec = |id: &str, command: &[&str]| -> Result<String> {
        if id == peer {
            let mut arguments = vec!["/relay-bench-worker", "namespace-exec"];
            arguments.extend_from_slice(command);
            integrated::exec(id, &arguments)
        } else {
            integrated::exec(id, command)
        }
    };
    let router_public = key(node, "/tmp/application-router.key")?;
    let peer_public = key(peer, "/tmp/application-peer.key")?;
    for (id, device) in [(node, "tdvpn0"), (peer, "wgpeer0")] {
        exec(id, &["ip", "link", "add", device, "type", "wireguard"])?;
        exec(id, &["ip", "link", "set", device, "up"])?;
    }
    exec(
        node,
        &["ip", "addr", "add", "10.254.0.1/32", "dev", "tdvpn0"],
    )?;
    exec(
        peer,
        &["ip", "addr", "add", "10.254.0.2/32", "dev", "wgpeer0"],
    )?;
    exec(peer, &["ip", "addr", "add", "203.0.113.2/32", "dev", "lo"])?;
    exec(
        node,
        &[
            "wg",
            "set",
            "tdvpn0",
            "private-key",
            "/tmp/application-router.key",
            "listen-port",
            "51831",
            "peer",
            &peer_public,
            "allowed-ips",
            "0.0.0.0/0",
            "endpoint",
            "198.51.100.3:51830",
        ],
    )?;
    exec(
        peer,
        &[
            "wg",
            "set",
            "wgpeer0",
            "private-key",
            "/tmp/application-peer.key",
            "listen-port",
            "51830",
            "peer",
            &router_public,
            "allowed-ips",
            "192.0.2.0/24,10.254.0.1/32",
            "endpoint",
            "198.51.100.2:51831",
        ],
    )?;
    exec(
        peer,
        &["ip", "route", "add", "192.0.2.0/24", "dev", "wgpeer0"],
    )?;
    exec(
        peer,
        &["ip", "route", "add", "10.254.0.1/32", "dev", "wgpeer0"],
    )?;
    exec(
        node,
        &["ip", "route", "replace", "default", "dev", "tdvpn0"],
    )?;
    input(node,&["uci","batch"],b"set firewall.application_vpn=zone\nset firewall.application_vpn.name='vpn'\nadd_list firewall.application_vpn.device='tdvpn0'\nset firewall.application_vpn.input='REJECT'\nset firewall.application_vpn.output='ACCEPT'\nset firewall.application_vpn.forward='REJECT'\nset firewall.application_to_vpn=forwarding\nset firewall.application_to_vpn.src='lan'\nset firewall.application_to_vpn.dest='vpn'\ncommit firewall\n")?;
    exec(node, &["fw4", "reload"])?;
    input(
        node,
        &["nft", "-f", "-"],
        br#"table inet application_paths {
 counter wan {}
 counter vpn {}
 counter resolver {}
 chain observe { type filter hook postrouting priority 301; policy accept;
  oifname "tdwan0" ip daddr 203.0.113.2 tcp dport 80 counter name wan
  oifname "tdvpn0" ip daddr 203.0.113.2 tcp dport 80 counter name vpn
  oifname "tdvpn0" ip daddr 10.254.0.2 tcp dport 53 counter name resolver
 }
}
"#,
    )?;
    Ok(())
}

fn path_counts(node: &str) -> Result<Value> {
    let rules: Value = serde_json::from_str(&exec(
        node,
        &["nft", "-j", "list", "table", "inet", "application_paths"],
    )?)?;
    let mut result = serde_json::Map::new();
    for name in ["wan", "vpn", "resolver"] {
        let count = rules["nftables"]
            .as_array()
            .ok_or("missing application path counters")?
            .iter()
            .find(|item| item["counter"]["name"] == name)
            .and_then(|item| item["counter"]["bytes"].as_u64())
            .ok_or("missing application path byte counter")?;
        result.insert(name.into(), json!(count));
    }
    Ok(Value::Object(result))
}

fn kernel_resources(node: &str) -> Value {
    let mut values = serde_json::Map::new();
    for file in [
        "cpu.max",
        "cpu.stat",
        "cpuset.cpus.effective",
        "memory.current",
        "memory.peak",
        "memory.events",
        "memory.pressure",
        "pids.current",
        "pids.events",
    ] {
        values.insert(
            file.into(),
            match exec(node, &["cat", &format!("/sys/fs/cgroup/{file}")]) {
                Ok(raw) => json!({"available":true,"raw":raw}),
                Err(error) => json!({"available":false,"error":error.to_string()}),
            },
        );
    }
    let mut processes = serde_json::Map::new();
    for program in ["AdGuardHome", "tunnel-detour"] {
        let snapshot = (|| -> Result<Value> {
            let pids = exec(node, &["pidof", program])?;
            let mut records = Vec::new();
            for pid in pids.split_whitespace().take(32) {
                let pid: u32 = pid.parse()?;
                let raw = exec(node, &["cat", &format!("/proc/{pid}/stat")])?;
                let (_, fields) = raw.rsplit_once(") ").ok_or("invalid process stat")?;
                let fields: Vec<_> = fields.split_whitespace().collect();
                let field = |index: usize| -> Result<u64> {
                    Ok(fields.get(index).ok_or("truncated process stat")?.parse()?)
                };
                records.push(json!({"pid":pid,"start_ticks":field(19)?,"user_ticks":field(11)?,"system_ticks":field(12)?,"reaped_child_user_ticks":field(13)?,"reaped_child_system_ticks":field(14)?}));
            }
            Ok(json!({"available":true,"records":records}))
        })();
        processes.insert(
            program.into(),
            match snapshot {
                Ok(value) => value,
                Err(error) => json!({"available":false,"error":error.to_string()}),
            },
        );
    }
    let mut sockets = serde_json::Map::new();
    for file in ["sockstat", "sockstat6"] {
        sockets.insert(
            file.into(),
            match exec(node, &["cat", &format!("/proc/net/{file}")]) {
                Ok(raw) => json!({"available":true,"raw":raw}),
                Err(error) => json!({"available":false,"error":error.to_string()}),
            },
        );
    }
    json!({"scope":"native cgroup; memory.peak is lifetime since container creation, including boot and observation commands, not a sampled or steady-window peak; process CPU ticks require matching PID/start time and CLK_TCK for seconds; socket files are read inside the disposable router network namespace, but sockstat mixes namespace inuse/TIME_WAIT counts with shared-kernel allocation/orphan/memory gauges; these raw gauges are not exclusive package resource use","files":values,"process_cpu":processes,"sockets":sockets})
}

fn resolver_fixture() -> String {
    let mut config = String::from(
        "server:\n interface: 10.254.0.2@53\n username: \"\"\n chroot: \"\"\n directory: \"/tmp\"\n pidfile: \"\"\n do-daemonize: no\n use-syslog: no\n module-config: \"iterator\"\n access-control: 0.0.0.0/0 allow\n local-zone: \".\" refuse\n local-zone: \"example.net.\" static\n local-data: \"selected.example.net. 0 IN A 203.0.113.2\"\n local-data: \"ordinary.example.net. 0 IN A 203.0.113.2\"\n",
    );
    for index in 1..128 {
        config.push_str(&format!(
            " local-data: \"occupancy{index}.selected.example.net. 0 IN A 203.0.113.2\"\n"
        ));
    }
    config
}

fn validate_client(result: &Value, http_qps: u64) -> Result {
    if result["role"] != "application-client"
        || result["seconds"] != 20
        || result["operations"]
            != json!([
                "dns_A",
                "dns_AAAA",
                "dns_HTTPS",
                "http_WAN",
                "http_WireGuard"
            ])
    {
        return Err("application actor returned an incompatible workload".into());
    }
    if result["http_qps_per_route"] != http_qps
        || !(1..=20).contains(&http_qps)
        || !200_u64.is_multiple_of(http_qps)
    {
        return Err("application actor changed its declared HTTP arrival rate".into());
    }
    let expected = [1334_u64, 1333, 1333, 20 * http_qps, 20 * http_qps];
    if result["results"]
        .as_array()
        .is_none_or(|values| values.len() != expected.len())
        || result["offered"] != json!(expected)
    {
        return Err("application actor changed its declared offered load".into());
    }
    for (index, offered) in expected.into_iter().enumerate() {
        let row = &result["results"][index];
        if row["successful"] != offered || row["errors"] != 0 || row["capacity_refused"] != 0 {
            return Err("application operation was lost, refused or failed".into());
        }
        for name in [
            "rtt_histogram_microseconds",
            "scheduled_histogram_microseconds",
        ] {
            let bins = row[name]
                .as_array()
                .filter(|bins| bins.len() == xtask::latency::BUCKETS)
                .ok_or("application histogram has an incompatible schema")?;
            let sum = bins.iter().try_fold(0_u64, |sum, value| {
                sum.checked_add(
                    value
                        .as_u64()
                        .ok_or("application histogram contains a noncount")?,
                )
                .ok_or("application histogram count overflow")
            })?;
            if sum != offered {
                return Err("application latency histogram omitted offered requests".into());
            }
        }
    }
    Ok(())
}

fn summary(report: &Value) -> Result<Value> {
    let result = &report["client_result"];
    validate_client(
        result,
        report["case"]["http_qps_per_route"]
            .as_u64()
            .ok_or("missing declared HTTP rate")?,
    )?;
    if result["histogram_schema"] != xtask::latency::schema() {
        return Err("application result changed the histogram schema".into());
    }
    let mut operations = Vec::new();
    for (index, row) in result["results"]
        .as_array()
        .ok_or("missing application operations")?
        .iter()
        .enumerate()
    {
        let count = row["successful"]
            .as_u64()
            .ok_or("missing application sample count")?;
        let mut item = json!({"operation":result["operations"][index],"successful":count,"errors":row["errors"],"capacity_refused":row["capacity_refused"]});
        for (field, prefix) in [
            ("rtt_histogram_microseconds", "rtt"),
            ("scheduled_histogram_microseconds", "scheduled"),
        ] {
            let bins = row[field]
                .as_array()
                .ok_or("missing application histogram")?
                .iter()
                .map(|value| value.as_u64().ok_or("invalid application histogram count"))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for percent in [50, 95, 99] {
                let bounds = xtask::latency::percentile_bounds(&bins, count, percent)?;
                item[format!("{prefix}_p{percent}_interval_microseconds")] =
                    json!([bounds.0, bounds.1]);
            }
            item[format!("{prefix}_overflow_count")] = json!(bins[xtask::latency::OVERFLOW]);
        }
        operations.push(item);
    }
    let mut resources = resource_counters(report)?;
    resources["scope"] = json!(SCOPE);
    Ok(
        json!({"case":report["case"],"operations":operations,"resources":resources,"percentile_method":"nearest rank; lower-inclusive/upper-exclusive histogram intervals, not confidence intervals","inference":"descriptive one-run qualification only; full observation perturbs timing; cgroup counters are not total host/kernel cost; no baseline subtraction"}),
    )
}

struct Prepared {
    lab: Lab,
    node: String,
    peer: String,
    origin: String,
    initial: Value,
    populated: Value,
    activation_us: u128,
    population_us: u128,
    expected_failures: u64,
}

async fn prepare(
    api: &Api,
    worker: &Path,
    service: &Path,
    native: &ImageSnapshot,
    actors: &ImageSnapshot,
    directory: &Path,
    case: Case,
) -> Result<Prepared> {
    let mut lab = Lab {
        failure_directory: Some(directory.to_path_buf()),
        actor_image: Some(actors.tag.clone()),
        containers: Vec::new(),
        networks: Vec::new(),
    };
    let prefix = format!("td-app-{}", std::process::id());
    let wan = lab.network(
        &format!("{prefix}-wan"),
        "198.51.100.0/24",
        "198.51.100.254",
        true,
    )?;
    let lan = lab.network(
        &format!("{prefix}-lan"),
        "192.0.2.0/24",
        "192.0.2.254",
        false,
    )?;
    let node = node(&mut lab, service, &native.tag, &wan, &lan, Some(worker))?;
    fs::write(
        directory.join("network.uci"),
        format!(
            "{}\toption gateway '198.51.100.4'\n",
            include_str!("../../../tests/benchmark/integrated.network")
        ),
    )?;
    let mut config = format!(
        "config globals 'globals'\n option enabled '0'\n option dns_integration '{}'\n option lan_network 'lan'\n option wan_network 'wan'\n option dns_port '10535'\n option proxy_port '10536'\n option real_upstream '10.254.0.2:53'\n option fake_range '198.18.0.0/24'\n option max_mappings '128'\n option max_mappings_per_rule '128'\nconfig exception 'selected'\n option pattern '***.selected.example.net'\n option enabled '1'\nconfig inbound 'inbound'\n option enabled '0'\n option lan_network 'lan'\n option wan_network 'wan'\n",
        if case.adguard { "adguard" } else { "dnsmasq" }
    );
    for index in 1..case.rules {
        config.push_str(&format!("config exception 'padding{index}'\n option pattern 'exact{index}.example.net'\n option enabled '1'\n"));
    }
    fs::write(directory.join("tunnel-detour.uci"), config)?;
    copy_into(&node, &directory.join("network.uci"), "/etc/config/network")?;
    copy_into(
        &node,
        &directory.join("tunnel-detour.uci"),
        "/etc/config/tunnel-detour",
    )?;
    docker(&strings(&["start", &node]))?;
    wait_native(api, &node).await?;
    exec(&node, &["/etc/init.d/tunnel-detour-lab", "stop"])?;
    // Docker's internal bridge drops off-subnet inner destinations even when
    // their Ethernet frame targets the router. Keep only boot links on Docker;
    // route all measured packets through veths entirely inside the disposable
    // node. Endpoint processes remain in separate Docker resource cgroups.
    for (device, namespace, address) in [
        ("tdlan0", "td-app-lan", "192.0.2.2/24"),
        ("tdwan0", "td-app-wan", "198.51.100.3/24"),
    ] {
        for command in [
            vec!["ip", "netns", "add", namespace],
            vec!["ip", "link", "del", device],
            vec![
                "ip", "link", "add", device, "type", "veth", "peer", "name", "bench0", "netns",
                namespace,
            ],
            vec!["ip", "link", "set", device, "up"],
            vec!["ip", "-n", namespace, "link", "set", "lo", "up"],
            vec!["ip", "-n", namespace, "link", "set", "bench0", "up"],
            vec![
                "ip", "-n", namespace, "addr", "add", address, "dev", "bench0",
            ],
        ] {
            exec(&node, &command)?;
        }
    }
    exec(
        &node,
        &[
            "ip",
            "-n",
            "td-app-lan",
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
        ],
    )?;
    exec(
        &node,
        &[
            "ip",
            "-n",
            "td-app-wan",
            "addr",
            "add",
            "198.51.100.4/24",
            "dev",
            "bench0",
        ],
    )?;
    exec(&node, &["ubus", "call", "network", "reload", "{}"])?;
    wait_native(api, &node).await?;
    let peer = actor(
        &mut lab,
        worker,
        &node,
        "wan",
        &[
            "/relay-bench-worker",
            "application-origin",
            "wgpeer0",
            "vpn",
        ],
    )?;
    let origin = actor(
        &mut lab,
        worker,
        &node,
        "wan",
        &["/relay-bench-worker", "application-origin", "bench0", "wan"],
    )?;
    input(
        &peer,
        &["tee", "/tmp/application-unbound.conf"],
        resolver_fixture().as_bytes(),
    )?;
    wireguard(&node, &peer)?;
    for id in [&peer, &origin] {
        exec(id, &["touch", "/tmp/application-start"])?;
        api.ready(id).await?;
    }
    if case.adguard {
        configure_adguard(&node, directory).await?;
    } else {
        input(&node,&["uci","batch"],b"delete dhcp.main.server\nadd_list dhcp.main.server='10.254.0.2#53'\nset dhcp.main.cachesize='0'\ncommit dhcp\n")?;
        exec(&node, &["/etc/init.d/dnsmasq", "restart"])?;
    }
    exec(&node, &["uci", "set", "tunnel-detour.globals.enabled=1"])?;
    exec(&node, &["uci", "commit", "tunnel-detour"])?;
    let activation = Instant::now();
    exec(&node, &["/etc/init.d/tunnel-detour", "start"])?;
    let initial = ready_dns(&node, directory).await?;
    let activation_us = activation.elapsed().as_micros();
    let population = Instant::now();
    for index in 0..case.occupied {
        let name = if index == 0 {
            "selected.example.net".to_owned()
        } else {
            format!("occupancy{index}.selected.example.net")
        };
        let answer = exec(
            &node,
            &["nslookup", "-retry=1", "-timeout=2", &name, "127.0.0.1"],
        )?;
        if !answer
            .split_whitespace()
            .any(|word| word.starts_with("198.18.0."))
        {
            return Err("application population did not obtain a synthetic identity".into());
        }
    }
    let population_us = population.elapsed().as_micros();
    let populated = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = dns_status(&node)?;
            if status["status"]["mapping_usage"]["allocated"].as_u64()
                == Some(u64::try_from(case.occupied)?)
            {
                return Ok::<_, Box<dyn Error>>(status);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    if populated["status"]["phase"] != "ready"
        || populated["status"]["configuration_applied"] != true
        || populated["status"]["failures"] != 0
    {
        return Err("application preparation failed before load began".into());
    }
    Ok(Prepared {
        lab,
        node,
        peer,
        origin,
        initial,
        populated,
        activation_us,
        population_us,
        expected_failures: 0,
    })
}

async fn load(
    api: &Api,
    worker: &Path,
    prepared: &mut Prepared,
    directory: &Path,
    case: Case,
) -> Result<Value> {
    let host_before = xtask::provenance::host_context();
    let Prepared {
        lab,
        node,
        peer,
        origin,
        initial: original,
        populated,
        activation_us,
        population_us,
        expected_failures,
    } = prepared;
    lab.failure_directory = Some(directory.to_path_buf());
    let initial = dns_status(node)?;
    if initial["status"]["process_id"] != original["status"]["process_id"] {
        return Err("application controller changed between load phases".into());
    }
    if initial["status"]["failures"].as_u64() != Some(*expected_failures) {
        return Err("application failed between observed load phases".into());
    }
    let completed_before = initial["status"]["completed_connections"]
        .as_u64()
        .ok_or("missing proxy completion baseline")?;
    let rate = case.http_qps.to_string();
    let generator_command = vec![
        "/relay-bench-worker",
        "application-client",
        "20",
        if case.churn { "churn" } else { "reuse" },
        &rate,
    ];
    let generator = actor(lab, worker, node, "lan", &generator_command)?;
    let observer = observer(lab, worker, node)?;
    api.ready(&observer).await?;
    let groups = [
        node.as_str(),
        peer.as_str(),
        origin.as_str(),
        generator.as_str(),
        observer.as_str(),
    ]
    .into_iter()
    .map(|id| exec(id, &["cat", "/proc/1/cgroup"]))
    .collect::<Result<Vec<_>>>()?;
    // /proc/1 is intentionally the same native PID namespace; each Docker exec
    // resolves its path relative to that actor's private cgroup namespace.
    if groups.first().is_none_or(|group| group != "0::/")
        || groups.iter().skip(1).any(|group| group == "0::/")
    {
        return Err("application endpoint accounting overlaps the native router cgroup".into());
    }
    fs::write(
        directory.join("accounting.json"),
        serde_json::to_vec_pretty(
            &json!({"native_pid1_cgroup_from_each_actor":groups,"scope":SCOPE,"process_observer":"only PID 1's cgroup and descendants; other shared-PID-namespace actors excluded"}),
        )?,
    )?;
    let before = api.stats(node).await?;
    let kernel_before = kernel_resources(node);
    let paths_before = path_counts(node)?;
    let peer_before = api.stats(peer).await?;
    let origin_before = api.stats(origin).await?;
    let started = Instant::now();
    exec(&generator, &["touch", "/tmp/application-start"])?;
    let mut samples = Vec::new();
    let mut management = Vec::new();
    let mut sample_file = fs::File::create(directory.join("resource-samples.jsonl"))?;
    let mut management_file = fs::File::create(directory.join("management-samples.jsonl"))?;
    let collection=tokio::time::timeout(Duration::from_secs(45),async {
        loop {
            let state=api.get(&format!("/containers/{generator}/json")).await?;
            if samples.len()>=450 { return Err("application resource sample capacity exceeded".into()); }
            samples.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"relay":api.stats(node).await?}));
            serde_json::to_writer(&mut sample_file,samples.last().ok_or("missing collected resource sample")?)?;
            sample_file.write_all(b"\n")?;
            if management.is_empty() || management.last().and_then(|row:&Value|row["elapsed_microseconds"].as_u64()).is_some_and(|last|started.elapsed().as_micros().saturating_sub(u128::from(last))>=2_000_000) {
                let request=Instant::now();
                let state=dns_status(node)?;
                management.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"request_microseconds_including_docker":request.elapsed().as_micros(),"status":state}));
                serde_json::to_writer(&mut management_file,management.last().ok_or("missing collected management sample")?)?;
                management_file.write_all(b"\n")?;
            }
            if state["State"]["Running"]==false { return Ok::<_,Box<dyn Error>>(state["State"]["ExitCode"].clone()); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await;
    fs::write(
        directory.join("collection-outcome.json"),
        serde_json::to_vec_pretty(&match &collection {
            Ok(Ok(code)) => json!({"exit_code":code}),
            Ok(Err(error)) => json!({"error":error.to_string()}),
            Err(error) => json!({"error":error.to_string()}),
        })?,
    )?;
    let minimum_completed = completed_before
        .checked_add(if case.churn {
            20 * case.http_qps + 1
        } else {
            1
        })
        .ok_or("application proxy completion count overflow")?;
    if matches!(&collection,Ok(Ok(code)) if code.as_i64()==Some(0)) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let state = dns_status(node)?;
                if state["status"]["connections"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
                    && state["status"]["completed_connections"]
                        .as_u64()
                        .is_some_and(|count| count >= minimum_completed)
                {
                    return Ok::<_, Box<dyn Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
    }
    let memory = stop_observer(api, &observer).await?;
    let log = docker(&strings(&["logs", &generator]))?;
    // Failure stderr can follow the final JSON. Keep the operation counts even
    // when the actor rejects its result, rather than dropping failed samples.
    let result = log
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["role"] == "application-client" && value["results"].is_array());
    let final_status = dns_status(node)?;
    let paths_after = path_counts(node)?;
    let collection_error = match &collection {
        Err(error) => Some(error.to_string()),
        Ok(Err(error)) => Some(error.to_string()),
        _ => None,
    };
    let report = json!({
        "case":case.description(),"scope":SCOPE,"host_before":host_before,"host_after":xtask::provenance::host_context(),
        "activation_observed_microseconds_including_native_control":activation_us,"population_observed_microseconds_including_docker":population_us,
        "initial_status":initial,"populated_status":populated,"final_status":final_status,
        "paths_before":paths_before,"paths_after":paths_after,
        "relay_before":before,"relay_after":api.stats(node).await?,
        "kernel_resources_before":kernel_before,"kernel_resources_after":kernel_resources(node),
        "peer_before":peer_before,"peer_after":api.stats(peer).await?,
        "origin_before":origin_before,"origin_after":api.stats(origin).await?,
        "generator_after":api.stats(&generator).await?,"samples":samples,"management":management,
        "memory_observer":memory,"client_result":result,"collection_error":collection_error,
        "resource_window":"client DNS/HTTP priming, fixed-arrival load, drain and final control collection; endpoints excluded; periodic observer and status refresh intentionally enabled"
    });
    fs::write(
        directory.join("application.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::write(directory.join("generator.log"), log)?;
    if !matches!(&collection, Ok(Ok(code)) if code.as_i64() == Some(0)) {
        let mut diagnostics = serde_json::Map::new();
        for (label, id, command) in [
            (
                "node_rules",
                node.as_str(),
                vec!["ip", "-4", "rule", "show"],
            ),
            (
                "node_routes",
                node.as_str(),
                vec!["ip", "-4", "route", "show", "table", "all"],
            ),
            (
                "node_firewall",
                node.as_str(),
                vec!["nft", "list", "ruleset"],
            ),
            (
                "node_log",
                node.as_str(),
                vec!["logread", "-e", "tunnel-detour"],
            ),
        ] {
            diagnostics.insert(
                label.into(),
                match exec(id, &command) {
                    Ok(value) => json!({"output":value}),
                    Err(error) => json!({"error":error.to_string()}),
                },
            );
        }
        fs::write(
            directory.join("network-diagnostics.json"),
            serde_json::to_vec_pretty(&diagnostics)?,
        )?;
    }
    if collection?? != 0 {
        return Err("application generator failed; raw evidence retained".into());
    }
    if final_status["status"]["process_id"] != initial["status"]["process_id"]
        || final_status["status"]["phase"] != "ready"
        || final_status["status"]["configuration_applied"] != true
        || final_status["status"]["failures"] != initial["status"]["failures"]
    {
        return Err(
            "application controller restarted, failed or rejected expected workload".into(),
        );
    }
    let completed_connections = final_status["status"]["completed_connections"]
        .as_u64()
        .ok_or("missing actual proxy completion count")?
        .checked_sub(completed_before)
        .ok_or("proxy completion counter regressed")?;
    if !case.churn && completed_connections > 20 * case.http_qps {
        return Err("HTTP reuse profile did not actually reuse its proxy connections".into());
    }
    for name in ["wan", "vpn", "resolver"] {
        if paths_after[name]
            .as_u64()
            .zip(paths_before[name].as_u64())
            .is_none_or(|(after, before)| after <= before)
        {
            return Err(
                format!("application workload did not traverse the required {name} path").into(),
            );
        }
    }
    validate_client(
        result
            .as_ref()
            .ok_or("application generator omitted its bounded operation report")?,
        case.http_qps,
    )?;
    if result.as_ref().ok_or("missing application result")?["http_connection_reuse"] != !case.churn
    {
        return Err("application generator changed its declared connection reuse policy".into());
    }
    let summary = summary(&report)?;
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    for id in [&generator, &observer] {
        lab.remove(id)?;
    }
    Ok(summary)
}

fn finish(prepared: &mut Prepared) -> Result {
    for id in [&prepared.origin, &prepared.peer] {
        docker(&strings(&["kill", "--signal=TERM", id]))?;
        if docker(&strings(&["wait", id]))? != "0" {
            return Err("application origin/resolver failed during shutdown".into());
        }
    }
    let containers = prepared.lab.containers.clone();
    let networks = prepared.lab.networks.clone();
    for id in containers.iter().rev() {
        prepared.lab.remove(id)?;
    }
    for id in networks.iter().rev() {
        docker(&strings(&["network", "rm", id]))?;
        prepared.lab.networks.retain(|other| other != id);
    }
    if let Some(directory) = &prepared.lab.failure_directory {
        fs::write(
            directory.join("cleanup.json"),
            serde_json::to_vec_pretty(
                &json!({"complete":true,"removed_containers":containers,"removed_networks":networks,"scope":"only the disposable fixture's owned identifiers; cleanup errors prevent completion"}),
            )?,
        )?;
    }
    prepared.lab.failure_directory = None;
    Ok(())
}

async fn measure(
    api: &Api,
    worker: &Path,
    service: &Path,
    native: &ImageSnapshot,
    actors: &ImageSnapshot,
    directory: &Path,
    case: Case,
) -> Result<Value> {
    let mut prepared = prepare(api, worker, service, native, actors, directory, case).await?;
    let result = load(api, worker, &mut prepared, directory, case).await?;
    finish(&mut prepared)?;
    Ok(result)
}

async fn worker_fault(
    api: &Api,
    worker: &Path,
    prepared: &mut Prepared,
    directory: &Path,
) -> Result<Value> {
    prepared.lab.failure_directory = Some(directory.to_path_buf());
    let before = dns_status(&prepared.node)?;
    if !before["status"]["connections"]
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        return Err("soak fault must begin with drained connections".into());
    }
    let parent = before["status"]["process_id"]
        .as_u64()
        .ok_or("missing soak controller PID")?;
    let failures = before["status"]["failures"]
        .as_u64()
        .ok_or("missing soak failure baseline")?;
    if failures != prepared.expected_failures {
        return Err("soak encountered an unplanned failure before fault injection".into());
    }
    fs::write(
        directory.join("fault-before.json"),
        serde_json::to_vec_pretty(&before)?,
    )?;
    let held = actor(
        &mut prepared.lab,
        worker,
        &prepared.node,
        "lan",
        &["/relay-bench-worker", "application-held"],
    )?;
    exec(&held, &["touch", "/tmp/application-start"])?;
    api.ready(&held).await?;
    let processes = exec(&prepared.node, &["ps", "w"])?;
    let workers: Vec<u32> = processes
        .lines()
        .filter(|line| line.contains("--transport-worker"))
        .map(|line| {
            line.split_whitespace()
                .next()
                .ok_or("missing worker process identifier")?
                .parse()
                .map_err(Into::into)
        })
        .collect::<Result<_>>()?;
    let [pid] = workers.as_slice() else {
        return Err("held soak connection did not have exactly one isolated worker".into());
    };
    // The helper opens a pidfd and verifies executable, parent and command before
    // signaling. Recycled numeric PIDs cannot redirect the signal to a new task.
    // The service deliberately makes its worker nondumpable. Inspect and signal
    // from a separate, explicitly privileged fault actor, never by granting the
    // measured controller additional capabilities.
    let fault = docker(&strings(&[
        "create",
        "--label",
        "tunnel-detour.task=relay-benchmark",
        "--network",
        "none",
        "--pid",
        &format!("container:{}", prepared.node),
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SYS_PTRACE",
        "--cap-add",
        "KILL",
        "--cap-add",
        "DAC_READ_SEARCH",
        "--security-opt",
        "apparmor=unconfined",
        "--read-only",
        "--cgroupns",
        "private",
        "--memory",
        "32m",
        "--cpus",
        "1",
        "--env",
        "TUNNEL_DETOUR_BENCH_LAB=1",
        "--mount",
        &format!(
            "type=bind,src={},dst=/relay-bench-worker,readonly",
            worker.display()
        ),
        prepared
            .lab
            .actor_image
            .as_deref()
            .ok_or("missing frozen fault actor image")?,
        "/relay-bench-worker",
        "application-kill-worker",
        &pid.to_string(),
        &parent.to_string(),
    ]))?;
    prepared.lab.containers.push(fault.clone());
    docker(&strings(&["start", &fault]))?;
    let exit = docker(&strings(&["wait", &fault]))?;
    let log = docker(&strings(&["logs", &fault]))?;
    fs::write(directory.join("fault-actor.log"), &log)?;
    if exit != "0" {
        return Err(format!("isolated fault actor failed: {log}").into());
    }
    prepared.lab.remove(&fault)?;
    exec(&held, &["touch", "/tmp/application-check-closed"])?;
    let state = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = api.get(&format!("/containers/{held}/json")).await?;
            if state["State"]["Running"] == false {
                return Ok::<_, Box<dyn Error>>(state);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let log = docker(&strings(&["logs", &held]))?;
    fs::write(directory.join("held-client.log"), &log)?;
    if state["State"]["ExitCode"] != 0 {
        return Err("held soak client did not observe its worker's actual connection close".into());
    }
    let result = log
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| {
            value["role"] == "application-held"
                && value["closed"] == true
                && value["payload_verified"] == true
        })
        .ok_or("held soak client omitted its closure proof")?;
    let after = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = dns_status(&prepared.node)?;
            if status["status"]["connections"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
                && status["status"]["failures"].as_u64() == failures.checked_add(1)
            {
                return Ok::<_, Box<dyn Error>>(status);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    if after["status"]["process_id"].as_u64() != Some(parent)
        || after["status"]["phase"] != "ready"
        || after["status"]["configuration_applied"] != true
    {
        return Err("worker fault stopped or replaced its soak controller".into());
    }
    if exec(&prepared.node, &["ps", "w"])?
        .lines()
        .any(|line| line.contains("--transport-worker"))
    {
        return Err("worker fault retained a transport process after drain".into());
    }
    let report = json!({"kind":"planned isolated-worker fault","before":before,"after":after,"client":result,"node_after":api.stats(&prepared.node).await?,"expected_failure_delta":1,"scope":"this expected failure remains counted; it is not a successful performance sample"});
    fs::write(
        directory.join("fault.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    prepared.expected_failures = failures
        .checked_add(1)
        .ok_or("soak expected failure counter overflow")?;
    prepared.lab.remove(&held)?;
    Ok(report)
}

async fn soak(
    api: &Api,
    worker: &Path,
    service: &Path,
    images: &[ImageSnapshot],
    directory: &Path,
    seconds: u64,
    http_qps: u64,
) -> Result<Value> {
    if ![300, 7200].contains(&seconds) {
        return Err(
            "soak requires its declared five-minute qualification or two-hour duration".into(),
        );
    }
    let case = Case {
        adguard: true,
        rules: 128,
        occupied: 128,
        churn: false,
        http_qps,
    };
    let actors = images.first().ok_or("missing frozen actor image")?;
    let native = images.get(1).ok_or("missing frozen AdGuard image")?;
    let mut prepared = prepare(api, worker, service, native, actors, directory, case).await?;
    let started = Instant::now();
    let mut phases = Vec::new();
    for cycle in 0..240_usize {
        if started.elapsed() >= Duration::from_secs(seconds)
            && phases
                .last()
                .is_none_or(|phase: &Value| phase["fault"].is_null())
        {
            break;
        }
        let round = directory.join(format!("round-{cycle:03}"));
        fs::create_dir(&round)?;
        prepared.lab.failure_directory = Some(round.clone());
        let idle = integrated::idle(api, &mut prepared.lab, worker, &prepared.node).await?;
        fs::write(round.join("idle.json"), serde_json::to_vec_pretty(&idle)?)?;
        let profile = Case {
            churn: cycle % 3 == 2,
            ..case
        };
        let observed = load(api, worker, &mut prepared, &round, profile).await?;
        let fault = if cycle % 6 == 5 {
            Some(worker_fault(api, worker, &mut prepared, &round).await?)
        } else {
            None
        };
        phases.push(json!({"cycle":cycle,"elapsed_microseconds":started.elapsed().as_micros(),"idle":integrated::idle_summary(&idle)?,"load":observed,"fault":fault}));
        fs::write(
            directory.join("checkpoint.json"),
            serde_json::to_vec_pretty(
                &json!({"complete":false,"elapsed_microseconds":started.elapsed().as_micros(),"target_seconds":seconds,"controller_process_id":prepared.initial["status"]["process_id"],"phases":phases}),
            )?,
        )?;
    }
    if started.elapsed() < Duration::from_secs(seconds)
        || phases.len() < 6
        || phases.last().is_some_and(|phase| !phase["fault"].is_null())
    {
        return Err(
            "soak ended before its declared duration or minimum fault/recovery phases".into(),
        );
    }
    let report = json!({"complete":true,"scope":SCOPE,"target_seconds":seconds,"elapsed_microseconds":started.elapsed().as_micros(),"controller_process_id":prepared.initial["status"]["process_id"],"phases":phases,"limits":"one uninterrupted AdGuard controller; idle, hot mixed load, TCP churn and isolated-worker faults; no controller/VM restart masks retained resources; finite observations do not prove absence of every leak; dnsmasq/IPv6/TLS long-duration behavior is outside this run"});
    fs::write(
        directory.join("soak.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    finish(&mut prepared)?;
    Ok(report)
}

async fn cancellable<T>(work: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        biased;
        _=terminate.recv()=>Err("application benchmark cancelled; partial evidence retained".into()),
        _=interrupt.recv()=>Err("application benchmark interrupted; partial evidence retained".into()),
        result=work=>result,
    }
}

async fn collect(
    api: &Api,
    worker: &Path,
    service: &Path,
    images: &[ImageSnapshot],
    cases: (&[Case], usize),
    output: &Path,
    mode: Mode,
) -> Result {
    let (cases, offset) = cases;
    let actors = images
        .first()
        .ok_or("missing frozen application actor image")?;
    if matches!(mode, Mode::Soak | Mode::SoakPilot) {
        let directory = output.join("persistent-controller");
        fs::create_dir(&directory)?;
        let seconds = if mode == Mode::Soak { 7200 } else { 300 };
        fs::write(
            output.join("soak-plan.json"),
            serde_json::to_vec_pretty(
                &json!({"target_seconds":seconds,"scope":SCOPE,"frontend":"AdGuard Home v0.107.80","rules":128,"occupied":128,"http_qps_per_route":cases.first().ok_or("missing soak rate")?.http_qps,"dns_qps":200,"idle_seconds_per_round":10,"load_seconds_per_round":20,"churn_every_rounds":3,"worker_fault_every_rounds":6,"maximum_rounds":240,"controller_restarts_allowed":false,"completion_requires_load_after_last_fault":true}),
            )?,
        )?;
        return match soak(
            api,
            worker,
            service,
            images,
            &directory,
            seconds,
            cases.first().ok_or("missing soak rate")?.http_qps,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                fs::write(
                    directory.join("invalid.json"),
                    serde_json::to_vec_pretty(&json!({"error":error.to_string()}))?,
                )?;
                Err(error)
            }
        };
    }
    let mut completed = Vec::new();
    for (relative, case) in cases.iter().copied().enumerate() {
        let index = offset + relative;
        let directory = output.join(format!(
            "{index:03}-{}-rules{}-occupied{}-{}",
            if case.adguard { "adguard" } else { "dnsmasq" },
            case.rules,
            case.occupied,
            if case.churn { "churn" } else { "reuse" }
        ));
        fs::create_dir(&directory)?;
        println!(
            "Application measurement {}/{}: {}",
            index + 1,
            offset + cases.len(),
            case.description()
        );
        match measure(
            api,
            worker,
            service,
            images
                .get(usize::from(case.adguard))
                .ok_or("missing selected frontend image")?,
            actors,
            &directory,
            case,
        )
        .await
        {
            Ok(report) => completed.push(report),
            Err(error) => {
                fs::write(
                    directory.join("invalid.json"),
                    serde_json::to_vec_pretty(&json!({"error":error.to_string()}))?,
                )?;
                return Err(error);
            }
        }
        fs::write(
            output.join("completed.json"),
            serde_json::to_vec_pretty(&completed)?,
        )?;
    }
    Ok(())
}

/// Qualify hot-DNS/HTTP path measurements with endpoints independently accounted.
/// Matrix rows are descriptive observations, not frontend performance estimates.
pub fn run(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    mode: Mode,
    http_qps: u64,
) -> Result {
    if !(1..=20).contains(&http_qps) || !200_u64.is_multiple_of(http_qps) {
        return Err("HTTP arrival rate must divide 200 and lie in 1..=20".into());
    }
    let matrix = mode == Mode::Matrix;
    let target = cargo_target(cargo, root)?;
    let _activity = activity_lock(&target)?;
    fs::create_dir_all(
        output
            .parent()
            .ok_or("application output parent required")?,
    )?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    let inputs = xtask::provenance::source_inputs(root)?;
    let worker = build_worker(cargo, root)?;
    let service = build_binary(cargo, root, "tunnel-detour-service", "tunnel-detour")?;
    let mut images = Vec::new();
    for (stage, tag) in [
        ("dnsmasq-lab", "tunnel-detour-app-dnsmasq:local"),
        ("adguard-lab", "tunnel-detour-app-adguard:local"),
    ] {
        if !Command::new("docker")
            .current_dir(root)
            .args([
                "build",
                "--target",
                stage,
                "--tag",
                tag,
                "--file",
                "sources/tests/openwrt/Dockerfile",
                ".",
            ])
            .status()?
            .success()
        {
            return Err("application image build failed".into());
        }
        images.push(freeze_image(tag, "application")?);
    }
    if xtask::provenance::source_inputs(root)? != inputs {
        return Err("application source inputs changed during qualification build".into());
    }
    fs::copy(worker, output.join("relay-bench-worker"))?;
    fs::copy(service, output.join("tunnel-detour"))?;
    fs::copy("/proc/self/exe", output.join("benchmark-driver"))?;
    xtask::provenance::archive_inputs(root, &inputs, &output.join("source.tar"))?;
    let mut cases = Vec::new();
    for rules in if matrix { &[1, 16, 128][..] } else { &[1][..] } {
        for occupied in if matrix {
            &[1, 64, 115, 128][..]
        } else {
            &[1][..]
        } {
            for adguard in [false, true] {
                for churn in [false, true] {
                    cases.push(Case {
                        adguard,
                        rules: *rules,
                        occupied: *occupied,
                        churn,
                        http_qps,
                    });
                }
            }
        }
    }
    if matches!(mode, Mode::Soak | Mode::SoakPilot) {
        cases = vec![
            Case {
                adguard: true,
                rules: 128,
                occupied: 128,
                churn: false,
                http_qps,
            },
            Case {
                adguard: true,
                rules: 128,
                occupied: 128,
                churn: true,
                http_qps,
            },
        ];
    }
    if mode == Mode::ChurnPilot {
        cases = vec![Case {
            adguard: true,
            rules: 1,
            occupied: 1,
            churn: true,
            http_qps,
        }];
    }
    let persistent = matches!(mode, Mode::Soak | Mode::SoakPilot);
    let manifest = json!({
        "source_inputs":inputs,"scope":SCOPE,
        "kind":if persistent {"persistent-controller resource soak"} else {"descriptive native application qualification"},
        "architecture":"x86_64 Docker with the host kernel; no ARM64 or physical acceptance",
        "inference":if persistent {"repeated phases of one controller; no paired comparison or causal frontend estimate"} else {"one observation per case; fixed declared order, no paired or cross-frontend causal estimate"},
        "node_cpus":2,"node_memory_limit_bytes":268435456,"actor_cpus":4,"observer_cpus":1,
        "dns_offered_qps":200,"http_offered_qps_per_route":http_qps,
        "status_refresh_seconds":2,"management_refresh":"native ubus status through Docker exec; HTTP/LuCI rendering is not measured",
        "adguard_fixture":{"version":"v0.107.80","cache_enabled":false,"ratelimit":0,"external_subscriptions":false,"whois":false,"workdir":"owned disk-backed container layer; retained log cache is reclaimable; default query logging remains enabled"},
        "mapping_occupancy":"one initial cold identity is primed before measured hot-DNS load; 64/115/128 represent 50/~90/100 percent; no empty steady-state or cold-QPS claim",
        "missing_scope":["TLS latency","IPv6 exception performance","exact-versus-wildcard comparison","cold DNS arrival matrix","LuCI HTTP and rendering","HTTP/3","physical hardware"],
        "topology":"native-container veths and named LAN/WAN namespaces; no measured packet traverses a Docker bridge; endpoints share its PID namespace but have independent private cgroups; endpoint capabilities are NET_ADMIN/NET_RAW/NET_BIND_SERVICE/SYS_ADMIN/SYS_PTRACE with AppArmor unconfined",
        "worker_sha256":digest(&output.join("relay-bench-worker"))?,"service_sha256":digest(&output.join("tunnel-detour"))?,"driver_sha256":digest(&output.join("benchmark-driver"))?,
        "source_archive":"source.tar","source_archive_sha256":digest(&output.join("source.tar"))?,
        "images":images.iter().map(|image|json!({"tag":image.tag,"inspection":image.inspection})).collect::<Vec<_>>(),
        "cases":cases.iter().map(|case|case.description()).collect::<Vec<_>>()
    });
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let mut environment = serde_json::Map::new();
    for (name, program, arguments) in [
        ("kernel", "uname", vec!["-srvm"]),
        ("clock_ticks_per_second", "getconf", vec!["CLK_TCK"]),
        ("rustc", "rustc", vec!["-vV"]),
        ("cargo", "cargo", vec!["--version"]),
        (
            "docker",
            "docker",
            vec!["version", "--format", "{{json .}}"],
        ),
    ] {
        let result = Command::new(program)
            .current_dir(root)
            .args(arguments)
            .output()?;
        if !result.status.success() || result.stdout.len() > 65536 {
            return Err("application environment inspection failed or exceeded its bound".into());
        }
        environment.insert(name.into(), json!(String::from_utf8(result.stdout)?));
    }
    environment.insert("host_context".into(), xtask::provenance::host_context());
    fs::write(
        output.join("environment.json"),
        serde_json::to_vec_pretty(&environment)?,
    )?;
    let context: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
    let socket = context[0]["Endpoints"]["docker"]["Host"]
        .as_str()
        .and_then(|value| value.strip_prefix("unix://"))
        .ok_or("application benchmark requires the local Docker Unix socket")?;
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
        &output.join("relay-bench-worker"),
        &output.join("tunnel-detour"),
        &images,
        (&cases, 0),
        &output,
        mode,
    )));
    resume::checkpoint(
        &output,
        &json!({"complete":result.is_ok(),"kind":manifest["kind"],"scope":SCOPE,"planned_profiles":manifest["cases"],"raw_aggregation":if persistent {"persistent-controller/soak.json"} else {"completed.json"},"interpretation":"completion requires every declared case/phase, exact payloads/routes/accounting and explicit owned-fixture cleanup; no physical or maximum-throughput acceptance"}),
    )?;
    if let Err(error) = &result {
        fs::write(
            output.join("invalid.json"),
            serde_json::to_vec_pretty(&json!({"error":error.to_string()}))?,
        )?;
    }
    result
}
