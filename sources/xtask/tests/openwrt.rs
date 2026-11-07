//! Native management acceptance uses real OpenWrt UCI, netifd, rpcd, procd and AdGuard.
//! This x86 laboratory validates integration; target-device acceptance remains separate.

use serde_json::{Value, json};
use std::{
    env,
    error::Error,
    fs::File,
    io::{Read, Write},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn output(program: &str, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Output> {
    let mut command = Command::new(program);
    if program == "curl" {
        command.args(["--noproxy", "*"]);
    }
    let mut child = command
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("missing child stdin")?
            .write_all(input)?;
    }
    Ok(child.wait_with_output()?)
}

fn checked(program: &str, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Vec<u8>> {
    let result = output(program, arguments, input)?;
    if !result.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(result.stdout)
}

fn wait(mut condition: impl FnMut() -> TestResult<bool>) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if condition()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("OpenWrt readiness deadline expired".into())
}

fn secret() -> TestResult<String> {
    let mut bytes = [0; 24];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct Lab {
    name: String,
    network: String,
    container_created: bool,
    network_created: bool,
    http: String,
    password: String,
}

impl Lab {
    fn new() -> TestResult<Self> {
        if env::var("TUNNEL_DETOUR_OPENWRT_LAB").as_deref() != Ok("1") {
            return Err("use cargo xtask test-openwrt".into());
        }
        let binary = env::var("TUNNEL_DETOUR_OPENWRT_BINARY")?;
        let mut lab = Self {
            name: format!("tunnel-detour-openwrt-{}", std::process::id()),
            network: format!("tunnel-detour-management-{}", std::process::id()),
            container_created: false,
            network_created: false,
            http: String::new(),
            password: secret()?,
        };
        checked(
            "docker",
            &[
                "network",
                "create",
                "--subnet",
                "10.203.0.0/24",
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
                "--label",
                "tunnel-detour.task=local-validation",
                &lab.network,
            ],
            None,
        )?;
        lab.network_created = true;
        checked(
            "docker",
            &[
                "run",
                "--detach",
                "--rm",
                "--name",
                &lab.name,
                "--label",
                "tunnel-detour.task=local-validation",
                "--network",
                &lab.network,
                "--ip",
                "10.203.0.2",
                "--cap-add",
                "NET_ADMIN",
                "--cap-add",
                "SYS_ADMIN",
                "--security-opt",
                "apparmor=unconfined",
                "--tmpfs",
                "/tmp",
                "--publish",
                "127.0.0.1::80",
                "--mount",
                &format!("type=bind,src={binary},dst=/usr/bin/tunnel-detour,readonly"),
                "tunnel-detour-openwrt-lab:local",
            ],
            None,
        )?;
        lab.container_created = true;
        let port = String::from_utf8(checked("docker", &["port", &lab.name, "80/tcp"], None)?)?;
        lab.http = format!("http://{}", port.trim());
        let mut diagnostic = String::new();
        wait(|| {
            let plugin = lab.exec(&["ubus", "list", "tunnel-detour"], None);
            let http = checked(
                "curl",
                &[
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "2",
                    &format!(
                        "{}/luci-static/resources/view/tunnel-detour/overview.js",
                        lab.http
                    ),
                ],
                None,
            );
            diagnostic = format!(
                "plugin: {}; HTTP: {}",
                plugin
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                http.as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            );
            Ok(plugin.is_ok() && http.is_ok())
        })
        .map_err(|error| format!("management startup: {error}; {diagnostic}"))?;
        assert!(
            !lab.raw(&["apk", "info", "--exists", "dnsmasq"], None)?
                .status
                .success(),
            "dnsmasq must be absent"
        );
        Ok(lab)
    }

    fn raw(&self, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Output> {
        let mut args = vec!["exec", "-i", &self.name];
        args.extend_from_slice(arguments);
        output("docker", &args, input)
    }

    fn exec(&self, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Vec<u8>> {
        let result = self.raw(arguments, input)?;
        if !result.status.success() {
            return Err(format!(
                "OpenWrt command failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        Ok(result.stdout)
    }

    fn ubus(&self, object: &str, method: &str, payload: Value) -> TestResult<Value> {
        let bytes = self.exec(
            &["ubus", "-S", "call", object, method, &payload.to_string()],
            None,
        )?;
        if object == "service" && method == "event" && bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("ubus {object}/{method}: {error}").into())
    }

    fn api(&self, operation: &str, body: Option<Value>, authenticated: bool) -> TestResult<Value> {
        let auth = format!("lab-admin:{}", self.password);
        let mut arguments = vec![
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
        ];
        if authenticated {
            arguments.extend(["--user", &auth]);
        }
        let bytes = body.map(|body| serde_json::to_vec(&body)).transpose()?;
        if bytes.is_some() {
            arguments.extend([
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ]);
        }
        let url = format!("http://127.0.0.1:13000/control/{operation}");
        arguments.push(&url);
        let result = self.exec(&arguments, bytes.as_deref())?;
        if result.is_empty()
            || result
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .eq(b"OK".iter().copied())
        {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&result)?)
    }

    fn configure(&self) -> TestResult {
        self.exec(&["mkdir", "-p", "/tmp/adguard"], None)?;
        checked(
            "docker",
            &[
                "exec",
                "--detach",
                &self.name,
                "AdGuardHome",
                "--no-check-update",
                "--web-addr",
                "127.0.0.1:13000",
                "-w",
                "/tmp/adguard",
                "-c",
                "/tmp/adguard/config.yaml",
                "--logfile",
                "/tmp/adguard.log",
            ],
            None,
        )?;
        wait(|| Ok(self.api("install/get_addresses", None, false).is_ok()))
            .map_err(|error| format!("AdGuard wizard: {error}"))?;
        self.api("install/configure", Some(json!({"web":{"ip":"127.0.0.1", "port":13000}, "dns":{"ip":"127.0.0.1", "port":53}, "username":"lab-admin", "password":self.password})), false)?;
        wait(|| Ok(self.api("status", None, true).is_ok()))
            .map_err(|error| format!("AdGuard authenticated API: {error}"))?;
        self.api("dns_config", Some(json!({"upstream_dns":["tcp://127.0.0.1:15353"], "fallback_dns":[], "cache_optimistic":false})), true)?;
        let batch = format!(
            "set tunnel-detour.globals.real_upstream='127.0.0.1:15353'\nset tunnel-detour.globals.adguard_url='http://127.0.0.1:13000'\nset tunnel-detour.globals.adguard_username='lab-admin'\nset tunnel-detour.globals.adguard_password='{}'\ncommit tunnel-detour\n",
            self.password
        );
        self.exec(&["uci", "batch"], Some(batch.as_bytes()))?;
        self.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
        Ok(())
    }

    fn change(&self, lines: &str) -> TestResult {
        self.exec(
            &["uci", "batch"],
            Some(format!("{lines}\ncommit tunnel-detour\n").as_bytes()),
        )?;
        self.ubus(
            "service",
            "event",
            json!({"type":"config.change", "data":{"package":"tunnel-detour"}}),
        )?;
        Ok(())
    }

    fn ready(&self, old_pid: Option<u64>) -> TestResult<u64> {
        let mut current = None;
        wait(|| {
            let value = self.ubus("tunnel-detour", "status", json!({}))?;
            let pid = value["status"]["process_id"].as_u64();
            if value["running"] == true && value["status"]["phase"] == "ready" && pid != old_pid {
                current = pid;
                return Ok(true);
            }
            Ok(false)
        })
        .map_err(|error| {
            format!(
                "service readiness: {error}; {}",
                String::from_utf8_lossy(
                    &self
                        .exec(&["logread", "-e", "tunnel-detour"], None)
                        .unwrap_or_default()
                )
            )
        })?;
        current.ok_or("ready status has no process identifier".into())
    }

    fn lookup(&self, hostname: &str) -> TestResult<String> {
        Ok(String::from_utf8(
            self.exec(&["nslookup", hostname, "127.0.0.1"], None)?,
        )?)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        if self.container_created
            && let Err(error) = checked("docker", &["stop", "--time", "3", &self.name], None)
        {
            eprintln!("owned container cleanup failed: {error}");
        }
        if self.network_created
            && let Err(error) = checked("docker", &["network", "rm", &self.network], None)
        {
            eprintln!("owned network cleanup failed: {error}");
        }
    }
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r030_uci_changes_reconcile_through_procd_and_uninstall_removes_owned_configuration_without_live_wan()
-> TestResult {
    let lab = Lab::new()?;
    lab.configure()?;
    lab.change("set tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.test'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
    let first = lab.ready(None)?;
    assert!(lab.lookup("selected.example.test")?.contains("198.18.0.1"));
    lab.change("set tunnel-detour.selected.enabled='0'")?;
    let second = lab.ready(Some(first))?;
    assert!(lab.lookup("selected.example.test")?.contains("203.0.113.2"));
    lab.change("set tunnel-detour.selected.enabled='1'")?;
    let third = lab.ready(Some(second))?;
    assert!(lab.lookup("selected.example.test")?.contains("198.18.0.1"));
    lab.change("set tunnel-detour.globals.enabled='0'")?;
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false
                && lab.api("dns_info", None, true)?["upstream_dns"]
                    == json!(["tcp://127.0.0.1:15353"]),
        )
    })
    .map_err(|error| format!("global disable: {error}"))?;
    assert!(lab.lookup("selected.example.test")?.contains("203.0.113.2"));
    lab.change("set tunnel-detour.globals.enabled='1'")?;
    lab.ready(Some(third))?;
    lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.selected.pattern='invalid * rule'\nset tunnel-detour.globals.lan_network='unavailable'\ncommit tunnel-detour\n"))?;
    lab.exec(&["ifdown", "wan"], None)?;
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    lab.exec(&["/usr/bin/tunnel-detour", "--uninstall"], None)?;
    assert_eq!(
        lab.api("dns_info", None, true)?["upstream_dns"],
        json!(["tcp://127.0.0.1:15353"])
    );
    assert!(
        !lab.raw(&["nft", "list", "table", "inet", "tunnel_detour"], None)?
            .status
            .success()
    );
    let rules: Value =
        serde_json::from_slice(&lab.exec(&["ip", "-j", "-N", "-4", "rule", "show"], None)?)?;
    assert!(
        rules
            .as_array()
            .ok_or("rule list is not an array")?
            .iter()
            .all(|rule| rule["protocol"] != 242)
    );
    for file in [
        "/etc/tunnel-detour/leases.json",
        "/etc/tunnel-detour/leases.json.lock",
        "/etc/tunnel-detour/leases.json.adguard.json",
        "/etc/tunnel-detour/leases.json.adguard.json.lock",
        "/var/run/tunnel-detour/status.json",
        "/etc/config/tunnel-detour",
    ] {
        assert!(
            !lab.raw(&["test", "-e", file], None)?.status.success(),
            "uninstall retained {file}"
        );
    }
    assert!(lab.lookup("router.example.test")?.contains("192.0.2.1"));
    let page = checked(
        "curl",
        &[
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "5",
            "--max-time",
            "3",
            &format!("{}/cgi-bin/luci/", lab.http),
        ],
        None,
    )?;
    assert!(
        String::from_utf8(page)?.contains("luci_username"),
        "router administration must still offer its normal login page"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r031_real_rpcd_read_only_permissions_allow_status_and_validation_but_deny_writes_and_commands()
-> TestResult {
    let lab = Lab::new()?;
    let password = secret()?;
    let hash = String::from_utf8(checked(
        "openssl",
        &["passwd", "-6", "-stdin"],
        Some(password.as_bytes()),
    )?)?;
    let batch = format!(
        "set rpcd.viewer=login\nset rpcd.viewer.username='lab-viewer'\nset rpcd.viewer.password='{}'\nadd_list rpcd.viewer.read='luci-app-tunnel-detour'\ncommit rpcd\n",
        hash.trim()
    );
    lab.exec(&["uci", "batch"], Some(batch.as_bytes()))?;
    lab.exec(&["/etc/init.d/rpcd", "restart"], None)?;
    let mut token = None;
    wait(|| {
        if let Ok(session) = lab.ubus(
            "session",
            "login",
            json!({"username":"lab-viewer", "password":password}),
        ) {
            token = session["ubus_rpc_session"].as_str().map(String::from);
        }
        Ok(token.is_some())
    })
    .map_err(|error| format!("read-only login: {error}"))?;
    let token = token.ok_or("read-only login did not return a session")?;
    for (object, method, payload, expected) in [
        ("tunnel-detour", "status", json!({}), 0),
        (
            "tunnel-detour",
            "validate",
            json!({"patterns":"***.example.test"}),
            0,
        ),
        ("tunnel-detour", "check", json!({}), 6),
        ("tunnel-detour", "restart", json!({}), 6),
        (
            "uci",
            "set",
            json!({"config":"tunnel-detour", "section":"globals", "values":{"enabled":"1"}}),
            6,
        ),
        (
            "file",
            "exec",
            json!({"command":"/usr/bin/tunnel-detour", "params":["--uninstall"]}),
            6,
        ),
    ] {
        let request = serde_json::to_vec(
            &json!({"jsonrpc":"2.0", "id":1, "method":"call", "params":[token, object, method, payload]}),
        )?;
        let reply: Value = serde_json::from_slice(&checked(
            "curl",
            &[
                "--silent",
                "--fail",
                "--max-time",
                "10",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                &format!("{}/ubus", lab.http),
            ],
            Some(&request),
        )?)?;
        let status = reply["result"][0].as_i64().or_else(|| {
            reply["error"]["code"]
                .as_i64()
                .filter(|code| *code == -32002)
                .map(|_| 6)
        });
        assert_eq!(
            status,
            Some(expected),
            "unexpected access for {object}/{method}"
        );
    }
    Ok(())
}
