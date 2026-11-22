//! Native management acceptance uses real OpenWrt UCI, netifd, rpcd, procd and AdGuard.
//! This x86 laboratory validates integration; target-device acceptance remains separate.

use serde_json::{Value, json};

mod external;
#[path = "openwrt/resource_faults.rs"]
mod resource_faults;
use std::{
    cell::RefCell,
    env,
    error::Error,
    fs::File,
    io::{Read, Write},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT_LAB: AtomicU64 = AtomicU64::new(0);
const MANAGEMENT_ASSET: &str = "/luci-static/resources/view/tunnel-detour/overview.js";

#[derive(Debug)]
struct PublishedHttpUnavailable(String);

impl std::fmt::Display for PublishedHttpUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PublishedHttpUnavailable {}

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

fn wait(condition: impl FnMut() -> TestResult<bool>) -> TestResult {
    wait_for(Duration::from_secs(30), condition)
}

fn wait_for(duration: Duration, mut condition: impl FnMut() -> TestResult<bool>) -> TestResult {
    let deadline = Instant::now() + duration;
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
    vm: Option<xtask::vm::VmTransport>,
    background: RefCell<Vec<Child>>,
    name: String,
    network: String,
    container_created: bool,
    network_created: bool,
    http: String,
    password: String,
}

impl Lab {
    fn new() -> TestResult<Self> {
        Self::create(false)
    }

    fn create(dnsmasq: bool) -> TestResult<Self> {
        Self::create_profile(dnsmasq, false)
    }

    fn create_profile(dnsmasq: bool, transition: bool) -> TestResult<Self> {
        if env::var("TUNNEL_DETOUR_OPENWRT_LAB").as_deref() != Ok("1") {
            return Err("use cargo xtask test-openwrt".into());
        }
        if env::var_os("TUNNEL_DETOUR_VM_IMAGE").is_some() {
            if !dnsmasq || transition {
                return Err("the kernel laboratory uses the dnsmasq reference fixture".into());
            }
            return Self::create_vm();
        }
        let binary = env::var("TUNNEL_DETOUR_OPENWRT_BINARY")?;
        let image = env::var(if transition {
            "TUNNEL_DETOUR_OPENWRT_TRANSITION_IMAGE"
        } else if dnsmasq {
            "TUNNEL_DETOUR_OPENWRT_DNSMASQ_IMAGE"
        } else {
            "TUNNEL_DETOUR_OPENWRT_ADGUARD_IMAGE"
        })?;
        match Self::create_native(&binary, &image, dnsmasq, transition) {
            Err(error) if error.is::<PublishedHttpUnavailable>() => {
                eprintln!("native laboratory startup retry after published HTTP failure: {error}");
                Self::create_native(&binary, &image, dnsmasq, transition)
            }
            result => result,
        }
    }

    fn create_native(
        binary: &str,
        image: &str,
        dnsmasq: bool,
        transition: bool,
    ) -> TestResult<Self> {
        let sequence = NEXT_LAB.fetch_add(1, Ordering::Relaxed);
        let mut lab = Self {
            vm: None,
            background: RefCell::new(Vec::new()),
            name: format!("tunnel-detour-openwrt-{}-{sequence}", std::process::id()),
            network: format!(
                "{}{}-{sequence}",
                xtask::native_openwrt::NETWORK_PREFIX,
                std::process::id()
            ),
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
                xtask::native_openwrt::SUBNET,
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
                "--label",
                xtask::native_openwrt::TASK_LABEL,
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
                "--pull",
                "never",
                "--name",
                &lab.name,
                "--label",
                "tunnel-detour.task=local-validation",
                "--network",
                &lab.network,
                "--ip",
                "10.203.0.2",
                "--dns",
                "127.0.0.1",
                "--cap-add",
                "NET_ADMIN",
                "--cap-add",
                "SYS_ADMIN",
                "--sysctl",
                "net.ipv6.conf.all.forwarding=1",
                "--security-opt",
                "apparmor=unconfined",
                "--security-opt",
                "seccomp=unconfined",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/etc/tunnel-detour-container:ro,size=4096",
                "--publish",
                "127.0.0.1::80",
                "--mount",
                &format!("type=bind,src={binary},dst=/usr/bin/tunnel-detour,readonly"),
                "--mount",
                &format!(
                    "type=bind,src={},dst=/usr/libexec/tunnel-detour-test-fixture,readonly",
                    env::current_exe()?.display()
                ),
                image,
            ],
            None,
        )?;
        lab.container_created = true;
        let port = String::from_utf8(checked("docker", &["port", &lab.name, "80/tcp"], None)?)?;
        lab.http = format!("http://{}", port.trim());
        let mut diagnostic = String::new();
        let mut published_connection_failed = false;
        wait(|| {
            let plugin = lab.exec(&["ubus", "list", "tunnel-detour"], None);
            let http = output(
                "curl",
                &[
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "2",
                    &format!("{}{MANAGEMENT_ASSET}", lab.http),
                ],
                None,
            );
            published_connection_failed = plugin.is_ok()
                && http
                    .as_ref()
                    .is_ok_and(|reply| reply.status.code() == Some(7));
            let detail = match &http {
                Ok(reply) => String::from_utf8_lossy(&reply.stderr).into_owned(),
                Err(error) => error.to_string(),
            };
            diagnostic = format!(
                "plugin: {}; HTTP: {detail}",
                plugin
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            );
            Ok(plugin.is_ok() && http.is_ok_and(|reply| reply.status.success()))
        })
        .map_err(|error| -> Box<dyn Error> {
            // Preserve startup evidence before Drop removes the disposable container.
            // Do not restart uhttpd here: healing the fixture would hide its failure.
            for arguments in [
                vec!["ubus", "call", "service", "list", "{\"name\":\"uhttpd\"}"],
                vec!["ip", "-j", "address", "show", "dev", "eth0"],
                vec!["logread", "-l", "60"],
            ] {
                match lab.raw(&arguments, None) {
                    Ok(output) => eprintln!(
                        "laboratory startup {arguments:?}: {} {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    Err(error) => eprintln!("laboratory startup diagnostic failed: {error}"),
                }
            }
            let message = format!("management startup: {error}; {diagnostic}");
            // Retry only when the management asset actually works inside this
            // guest and the host still cannot connect to the published port.
            // A fresh fixture must pass the original HTTP and RPC checks.
            if published_connection_failed
                && lab
                    .raw(
                        &[
                            "curl",
                            "--silent",
                            "--fail",
                            "--max-time",
                            "2",
                            "--output",
                            "/dev/null",
                            &format!("http://127.0.0.1{MANAGEMENT_ASSET}"),
                        ],
                        None,
                    )
                    .is_ok_and(|reply| reply.status.success())
            {
                PublishedHttpUnavailable(message).into()
            } else {
                message.into()
            }
        })?;
        assert_eq!(
            lab.raw(&["apk", "info", "--exists", "dnsmasq"], None)?
                .status
                .success(),
            dnsmasq,
            "the frontend must match the laboratory profile"
        );
        lab.exec(&["test", "/proc/kmsg", "-ef", "/dev/null"], None)
            .map_err(|error| {
                format!("native container did not mask the host kernel log: {error}")
            })?;
        if dnsmasq && !transition {
            assert!(
                lab.raw(&["test", "!", "-e", "/usr/bin/AdGuardHome"], None)?
                    .status
                    .success()
            );
        }
        Ok(lab)
    }

    fn create_vm() -> TestResult<Self> {
        let sequence = NEXT_LAB.fetch_add(1, Ordering::Relaxed);
        let name = format!("tunnel-detour-vm-{}-{sequence}", std::process::id());
        let vm = xtask::vm::VmTransport::start(name.clone())?;
        let lab = Self {
            vm: Some(vm),
            background: RefCell::new(Vec::new()),
            name,
            network: String::new(),
            container_created: false,
            network_created: false,
            http: "http://127.0.0.1:0".into(),
            password: secret()?,
        };
        let mut ssh_error = String::new();
        wait_for(Duration::from_secs(90), || {
            let reply = lab.raw(&["ubus", "list", "tunnel-detour"], None)?;
            ssh_error = String::from_utf8_lossy(&reply.stderr)
                .chars()
                .take(1024)
                .collect();
            Ok(reply.status.success())
        })
        .map_err(|error| {
            format!(
                "VM readiness: {error}; SSH: {ssh_error}; {}",
                lab.vm
                    .as_ref()
                    .and_then(|vm| vm.diagnostics().ok())
                    .unwrap_or_default()
            )
        })?;
        Ok(lab)
    }

    fn background_command(&self, arguments: &[&str]) -> TestResult<Command> {
        if let Some(vm) = &self.vm {
            return vm.command(arguments);
        }
        let mut command = Command::new("docker");
        command
            .args(["exec", "-i", &self.name])
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        Ok(command)
    }

    fn raw(&self, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Output> {
        let deadline = if arguments.first() == Some(&"logread") {
            "5"
        } else {
            "120"
        };
        self.raw_with_deadline(arguments, input, deadline)
    }

    fn raw_with_deadline(
        &self,
        arguments: &[&str],
        input: Option<&[u8]>,
        deadline: &str,
    ) -> TestResult<Output> {
        if let Some(vm) = &self.vm {
            let arguments = vm.arguments(arguments)?;
            let mut bounded = vec!["--kill-after=2", deadline, "docker"];
            bounded.extend(arguments.iter().map(String::as_str));
            return output("timeout", &bounded, input);
        }
        let mut args = vec![
            "--kill-after=2",
            deadline,
            "docker",
            "exec",
            "-i",
            &self.name,
        ];
        args.extend_from_slice(arguments);
        output("timeout", &args, input)
    }

    fn exec(&self, arguments: &[&str], input: Option<&[u8]>) -> TestResult<Vec<u8>> {
        let result = self.raw(arguments, input)?;
        if !result.status.success() {
            return Err(format!(
                "OpenWrt command {:?} failed: {}",
                arguments.first(),
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        Ok(result.stdout)
    }

    fn with_command_fault<T>(
        &self,
        program: &str,
        label: &str,
        script: &str,
        run: impl FnOnce() -> TestResult<T>,
    ) -> TestResult<T> {
        let path = String::from_utf8(self.exec(
            &[
                "sh",
                "-c",
                "readlink -f \"$(command -v \"$1\")\"",
                "lab",
                program,
            ],
            None,
        )?)?;
        let path = path.trim();
        let real = format!("/usr/libexec/{label}-real");
        let wrapper = format!("/usr/libexec/{label}-wrapper");
        self.exec(&["cp", path, &real], None)?;
        let body = format!("#!/bin/sh\nREAL='{real}'\n{script}\nexec \"$REAL\" \"$@\"\n");
        self.exec(&["tee", &wrapper], Some(body.as_bytes()))?;
        self.exec(&["chmod", "755", &wrapper], None)?;
        self.exec(&["mount", "--bind", &wrapper, path], None)?;
        let result = run();
        let unmounted = self.exec(&["umount", path], None);
        result.and_then(|value| {
            unmounted?;
            Ok(value)
        })
    }

    fn ubus(&self, object: &str, method: &str, payload: Value) -> TestResult<Value> {
        let bytes = self
            .exec(
                &["ubus", "-S", "call", object, method, &payload.to_string()],
                None,
            )
            .map_err(|error| format!("ubus {object}/{method}: {error}"))?;
        // Native action methods may acknowledge success without a response payload.
        if bytes.is_empty() {
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
        // Removing a subscription returns a plain-text acknowledgement.
        if operation == "filtering/remove_url"
            || result.is_empty()
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
        self.configure_adguard(53)
    }

    fn configure_adguard(&self, dns_port: u16) -> TestResult {
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
        self.api("install/configure", Some(json!({"web":{"ip":"127.0.0.1", "port":13000}, "dns":{"ip":"127.0.0.1", "port":dns_port}, "username":"lab-admin", "password":self.password})), false)?;
        wait(|| Ok(self.api("status", None, true).is_ok()))
            .map_err(|error| format!("AdGuard authenticated API: {error}"))?;
        self.api("dns_config", Some(json!({"upstream_dns":["tcp://127.0.0.1:15353"], "bootstrap_dns":["127.0.0.1:15353"], "fallback_dns":[], "cache_optimistic":false})), true)?;
        let subscriptions = self.api("filtering/status", None, true)?;
        for subscription in subscriptions["filters"]
            .as_array()
            .ok_or("missing laboratory filter subscriptions")?
        {
            self.api(
                "filtering/remove_url",
                Some(json!({"url":subscription["url"]})),
                true,
            )?;
        }
        assert!(
            self.api("filtering/status", None, true)?["filters"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        self.exec(&["killall", "-TERM", "AdGuardHome"], None)?;
        wait(|| Ok(!self.raw(&["pidof", "AdGuardHome"], None)?.status.success()))?;
        self.exec(
            &[
                "sed",
                "-i",
                "s/^    whois: true$/    whois: false/",
                "/tmp/adguard/config.yaml",
            ],
            None,
        )?;
        self.exec(
            &[
                "grep",
                "-q",
                "^    whois: false$",
                "/tmp/adguard/config.yaml",
            ],
            None,
        )?;
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
        wait(|| Ok(self.api("status", None, true).is_ok()))?;
        let batch = format!(
            "set tunnel-detour.globals.dns_integration='adguard'\nset tunnel-detour.globals.real_upstream='127.0.0.1:15353'\nset tunnel-detour.globals.adguard_url='http://127.0.0.1:13000'\nset tunnel-detour.globals.adguard_username='lab-admin'\nset tunnel-detour.globals.adguard_password='{}'\ncommit tunnel-detour\n",
            self.password
        );
        self.exec(&["uci", "batch"], Some(batch.as_bytes()))?;
        self.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
        Ok(())
    }

    fn dnsmasq_endpoints(&self) -> TestResult {
        for (device, namespace, address, gateway) in [
            ("tdlan0", "td-dns-client", "192.0.2.2/24", "192.0.2.1"),
            ("tdwan0", "td-dns-origin", "203.0.113.2/24", "203.0.113.1"),
        ] {
            for arguments in [
                vec!["ip", "netns", "add", namespace],
                vec!["ip", "link", "del", device],
                vec![
                    "ip", "link", "add", device, "type", "veth", "peer", "name", "peer0", "netns",
                    namespace,
                ],
                vec!["ip", "link", "set", device, "up"],
                vec!["ip", "-n", namespace, "link", "set", "lo", "up"],
                vec!["ip", "-n", namespace, "link", "set", "peer0", "up"],
                vec![
                    "ip", "-n", namespace, "addr", "add", address, "dev", "peer0",
                ],
                vec![
                    "ip", "-n", namespace, "route", "add", "default", "via", gateway,
                ],
            ] {
                self.exec(&arguments, None)?;
            }
        }
        self.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
        self.exec(&["mkdir", "-p", "/tmp/native-origin"], None)?;
        self.exec(
            &["tee", "/tmp/native-origin/route.txt"],
            Some(b"native-wan-dnsmasq"),
        )?;
        self.exec(
            &[
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                "/tmp/native-origin/key.pem",
                "-out",
                "/tmp/native-origin/cert.pem",
                "-subj",
                "/CN=selected.example.net",
                "-addext",
                "subjectAltName=DNS:selected.example.net,DNS:alias.example.net",
            ],
            None,
        )?;
        checked(
            "docker",
            &[
                "exec",
                "--detach",
                "--workdir",
                "/tmp/native-origin",
                &self.name,
                "ip",
                "netns",
                "exec",
                "td-dns-origin",
                "openssl",
                "s_server",
                "-accept",
                "203.0.113.2:443",
                "-cert",
                "cert.pem",
                "-key",
                "key.pem",
                "-WWW",
                "-quiet",
            ],
            None,
        )?;
        Ok(())
    }

    fn inbound_endpoints(&self) -> TestResult {
        self.exec(&["mkdir", "-m", "700", "/tmp/inbound-test"], None)?;
        for (device, namespace, router, peer) in [
            (
                "tdlan0",
                "td-in-lan",
                "2001:db8:1::1/64",
                "2001:db8:1::2/64",
            ),
            (
                "tdwan0",
                "td-in-wan",
                "2001:db8:2::1/64",
                "2001:db8:2::2/64",
            ),
        ] {
            for arguments in [
                vec!["ip", "netns", "add", namespace],
                vec!["ip", "link", "del", device],
                vec![
                    "ip", "link", "add", device, "type", "veth", "peer", "name", "peer0", "netns",
                    namespace,
                ],
                vec!["ip", "link", "set", device, "up"],
                vec!["ip", "-6", "addr", "add", router, "dev", device, "nodad"],
                vec!["ip", "-n", namespace, "link", "set", "lo", "up"],
                vec!["ip", "-n", namespace, "link", "set", "peer0", "up"],
                vec![
                    "ip", "-n", namespace, "-6", "addr", "add", peer, "dev", "peer0", "nodad",
                ],
            ] {
                self.exec(&arguments, None)?;
            }
        }
        self.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
        self.exec(
            &[
                "ip",
                "-n",
                "td-in-lan",
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8:1::1",
            ],
            None,
        )?;
        self.exec(
            &[
                "ip",
                "-n",
                "td-in-lan",
                "addr",
                "add",
                "192.0.2.2/24",
                "dev",
                "peer0",
            ],
            None,
        )?;
        self.exec(
            &[
                "ip",
                "-n",
                "td-in-lan",
                "route",
                "replace",
                "default",
                "via",
                "192.0.2.1",
            ],
            None,
        )?;
        self.exec(
            &[
                "ip",
                "-n",
                "td-in-wan",
                "addr",
                "replace",
                "203.0.113.2/24",
                "dev",
                "peer0",
            ],
            None,
        )?;
        // The client is beyond the WAN gateway: its replies need the selected default,
        // rather than the connected WAN prefix accidentally making a wrong policy pass.
        self.exec(
            &[
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "addr",
                "add",
                "2001:db8:3::2/128",
                "dev",
                "lo",
                "nodad",
            ],
            None,
        )?;
        self.exec(&["ip", "link", "add", "tdvpn0", "type", "dummy"], None)?;
        self.exec(&["ip", "link", "set", "tdvpn0", "up"], None)?;
        self.exec(
            &[
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8:2::2",
                "dev",
                "tdwan0",
                "metric",
                "500",
            ],
            None,
        )?;
        self.exec(
            &[
                "ip", "-6", "route", "add", "default", "dev", "tdvpn0", "metric", "10",
            ],
            None,
        )?;
        assert_eq!(
            self.exec(&["sysctl", "-n", "net.ipv6.conf.all.forwarding"], None)?,
            b"1\n"
        );
        wait(|| {
            let addresses: Value =
                serde_json::from_slice(&self.exec(&["ip", "-j", "addr", "show", "tdwan0"], None)?)?;
            Ok(addresses[0]["addr_info"]
                .as_array()
                .is_some_and(|addresses| {
                    addresses
                        .iter()
                        .any(|address| address["local"] == "203.0.113.1")
                }))
        })?;
        // Automatic link-local routes appear when DAD completes. Establish that
        // readiness before a test takes its foreign-routing preservation baseline.
        wait(|| {
            let interfaces: Value =
                serde_json::from_slice(&self.exec(&["ip", "-j", "-6", "addr", "show"], None)?)?;
            Ok(interfaces.as_array().is_some_and(|interfaces| {
                interfaces.iter().all(|interface| {
                    interface["addr_info"].as_array().is_some_and(|addresses| {
                        addresses.iter().all(|address| {
                            address["tentative"] != true && address["dadfailed"] != true
                        })
                    })
                })
            }))
        })?;
        self.exec(&["fw4", "reload"], None)?;
        self.spawn_inbound_probe("server")?;
        wait(|| {
            Ok(self
                .inbound_marker("td-in-lan", "test", "endpoint-ready")?
                .status
                .success())
        })?;
        Ok(())
    }

    fn inbound_marker(&self, namespace: &str, operation: &str, name: &str) -> TestResult<Output> {
        let path = format!("/tmp/inbound-test/{name}");
        let mut command = if self.vm.is_some() {
            vec!["ip", "netns", "exec", namespace]
        } else {
            Vec::new()
        };
        command.push(operation);
        if operation == "test" {
            command.push("-e");
        }
        command.push(&path);
        self.raw(&command, None)
    }

    fn inbound_configuration(&self) -> Value {
        json!({
            "lan_device":"tdlan0", "lan_networks":["2001:db8:1::/64"], "router_addresses":[],
            "wan":{"device":"tdwan0","addresses":["2001:db8:2::1"],"gateway":"2001:db8:2::2","route_table":41900,"mark_prefix":1413742592_u32,"rule_priority":100},
            "state_file":"/tmp/inbound-test/state.json", "status_file":"/tmp/inbound-test/status.json",
            "rules":[{"id":"sample","name":"Native traffic","enabled":true,"protocol":"tcp_udp","access":"wan_only","public_port":18080,"destination":"[2001:db8:1::2]:8080"}]
        })
    }

    fn inbound_wireguard(&self) -> TestResult {
        let router_key = self.exec(&["wg", "genkey"], None)?;
        let peer_key = self.exec(&["wg", "genkey"], None)?;
        let router_public = String::from_utf8(self.exec(&["wg", "pubkey"], Some(&router_key))?)?;
        let peer_public = String::from_utf8(self.exec(&["wg", "pubkey"], Some(&peer_key))?)?;
        self.exec(&["tee", "/tmp/inbound-test/router.key"], Some(&router_key))?;
        self.exec(&["tee", "/tmp/inbound-test/peer.key"], Some(&peer_key))?;
        for args in [
            vec!["ip", "link", "del", "tdvpn0"],
            vec!["ip", "link", "add", "tdvpn0", "type", "wireguard"],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "link",
                "add",
                "wgpeer0",
                "type",
                "wireguard",
            ],
            vec![
                "wg",
                "set",
                "tdvpn0",
                "private-key",
                "/tmp/inbound-test/router.key",
                "listen-port",
                "51831",
                "peer",
                peer_public.trim(),
                "allowed-ips",
                "::/0",
                "endpoint",
                "203.0.113.2:51830",
            ],
            vec![
                "ip",
                "netns",
                "exec",
                "td-in-wan",
                "wg",
                "set",
                "wgpeer0",
                "private-key",
                "/tmp/inbound-test/peer.key",
                "listen-port",
                "51830",
                "peer",
                router_public.trim(),
                "allowed-ips",
                "2001:db8:1::/64",
                "endpoint",
                "203.0.113.1:51831",
            ],
            vec!["ip", "link", "set", "tdvpn0", "up"],
            vec!["ip", "-n", "td-in-wan", "link", "set", "wgpeer0", "up"],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "addr",
                "add",
                "2001:db8:4::2/128",
                "dev",
                "wgpeer0",
                "nodad",
            ],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "route",
                "add",
                "2001:db8:1::/64",
                "dev",
                "wgpeer0",
            ],
            vec![
                "ip", "-6", "route", "add", "default", "dev", "tdvpn0", "metric", "10",
            ],
        ] {
            self.exec(&args, None)?;
        }
        // WireGuard's device/peer byte counts include encrypted maintenance packets.
        // Independent IP hooks observe the actual inner traffic in both directions.
        self.exec(&["nft","-f","-"],Some(b"table inet inbound_vpn_probe {\n counter incoming {}\n counter outgoing {}\n chain receive { type filter hook prerouting priority -301; policy accept; iifname \"tdvpn0\" counter name incoming; }\n chain send { type filter hook postrouting priority 301; policy accept; oifname \"tdvpn0\" counter name outgoing; }\n}\n"))?;
        self.exec(&["uci", "batch"], Some(b"set firewall.vpn=zone\nset firewall.vpn.name='vpn'\nadd_list firewall.vpn.device='tdvpn0'\nset firewall.vpn.input='REJECT'\nset firewall.vpn.output='ACCEPT'\nset firewall.vpn.forward='REJECT'\nset firewall.to_vpn=forwarding\nset firewall.to_vpn.src='lan'\nset firewall.to_vpn.dest='vpn'\ncommit firewall\n"))?;
        self.exec(&["fw4", "reload"], None)?;
        self.spawn_inbound_probe("vpn_server")?;
        wait(|| {
            Ok(self
                .inbound_marker("td-in-wan", "test", "vpn-endpoint-ready")?
                .status
                .success())
        })?;
        Ok(())
    }

    /// Extend the established IPv6 tunnel with a real IPv4 default and a separate
    /// synthetic target. Management, underlay and authorized LAN routes stay connected.
    fn inbound_ipv4_wireguard(&self) -> TestResult {
        let peer = String::from_utf8(self.exec(&["wg", "show", "tdvpn0", "peers"], None)?)?;
        let router = String::from_utf8(self.exec(
            &[
                "ip",
                "netns",
                "exec",
                "td-in-wan",
                "wg",
                "show",
                "wgpeer0",
                "peers",
            ],
            None,
        )?)?;
        if peer.split_whitespace().count() != 1 || router.split_whitespace().count() != 1 {
            return Err("one isolated WireGuard peer is required".into());
        }
        for args in [
            vec![
                "wg",
                "set",
                "tdvpn0",
                "peer",
                peer.trim(),
                "allowed-ips",
                "2001:db8:4::/64,0.0.0.0/0",
            ],
            vec![
                "ip",
                "netns",
                "exec",
                "td-in-wan",
                "wg",
                "set",
                "wgpeer0",
                "peer",
                router.trim(),
                "allowed-ips",
                "2001:db8:1::/64,192.0.2.0/24",
            ],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "addr",
                "add",
                "198.51.100.40/32",
                "dev",
                "wgpeer0",
            ],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "route",
                "add",
                "192.0.2.0/24",
                "dev",
                "wgpeer0",
            ],
            // Replace Docker's management default (metric zero). The connected
            // management subnet remains reachable without providing a DNS/traffic bypass.
            vec!["ip", "route", "replace", "default", "dev", "tdvpn0"],
        ] {
            self.exec(&args, None)?;
        }
        self.spawn_inbound_probe("vpn_server4")?;
        wait(|| {
            Ok(self
                .inbound_marker("td-in-wan", "test", "vpn4-endpoint-ready")?
                .status
                .success())
        })
    }

    fn inbound_vpn_plaintext(&self) -> TestResult<Vec<u64>> {
        let table: Value = serde_json::from_slice(&self.exec(
            &["nft", "-j", "list", "table", "inet", "inbound_vpn_probe"],
            None,
        )?)?;
        let entries = table["nftables"]
            .as_array()
            .ok_or("missing independent VPN IP counters")?;
        let mut counters = Vec::new();
        for name in ["incoming", "outgoing"] {
            let counter = entries
                .iter()
                .find(|entry| entry["counter"]["name"] == name)
                .ok_or("missing named VPN IP counter")?;
            counters.push(
                counter["counter"]["bytes"]
                    .as_u64()
                    .ok_or("invalid VPN IP byte count")?,
            );
        }
        Ok(counters)
    }

    fn inbound_vpn_transfer(&self) -> TestResult<Vec<u64>> {
        let text = String::from_utf8(self.exec(&["wg", "show", "tdvpn0", "transfer"], None)?)?;
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.len() != 3 {
            return Err("expected exactly one isolated WireGuard peer".into());
        }
        Ok(vec![fields[1].parse()?, fields[2].parse()?])
    }

    fn prepare_inbound_uci(&self) -> TestResult {
        self.exec(&["/etc/init.d/tunnel-detour-inbound", "start"], None)?;
        self.exec(&["uci", "batch"], Some(b"set tunnel-detour.sample=inbound_port\nset tunnel-detour.sample.name='Independent publication'\nset tunnel-detour.sample.enabled='1'\nset tunnel-detour.sample.protocol='tcp_udp'\nset tunnel-detour.sample.public_port='18080'\nset tunnel-detour.sample.destination_address='2001:db8:1::2'\nset tunnel-detour.sample.destination_port='8080'\ncommit tunnel-detour\n"))?;
        Ok(())
    }

    fn start_inbound(&self, config: &Value) -> TestResult {
        self.exec(
            &["tee", "/tmp/inbound-config.json"],
            Some(&serde_json::to_vec(config)?),
        )?;
        let mut actor = self
            .background_command(&[
                "/usr/bin/tunnel-detour",
                "--inbound-config",
                "/tmp/inbound-config.json",
            ])?
            .spawn()?;
        let ready = wait(|| {
            if let Some(status) = actor.try_wait()? {
                let mut errors = String::new();
                if let Some(stderr) = actor.stderr.take() {
                    stderr.take(8192).read_to_string(&mut errors)?;
                }
                return Err(format!("inbound actor exited {status}: {errors}").into());
            }
            let state = self.raw(&["cat", "/tmp/inbound-test/state.json"], None)?;
            if !state.status.success() {
                return Ok(false);
            }
            let state: Value = serde_json::from_slice(&state.stdout)?;
            let guard = self.raw(
                &[
                    "nft",
                    "list",
                    "chain",
                    "inet",
                    "tunnel_detour_inbound",
                    "tag",
                ],
                None,
            )?;
            Ok(state["pending"].is_null()
                && state["admissions"]["sample"].as_u64().is_some()
                && String::from_utf8_lossy(&guard.stdout).contains("ct mark set"))
        });
        self.background.borrow_mut().push(actor);
        ready.map_err(|error| {
            format!(
                "inbound startup: {error}; state: {}",
                String::from_utf8_lossy(
                    &self
                        .exec(&["cat", "/tmp/inbound-test/state.json"], None)
                        .unwrap_or_default()
                )
            )
            .into()
        })
    }

    fn inbound_probe(&self, role: &str) -> TestResult<Output> {
        let namespace = if matches!(
            role,
            "vpn_client"
                | "vpn_client4"
                | "cached_client4"
                | "dns_once"
                | "dns_once6"
                | "dns_rejected6"
                | "other_control"
                | "dns_rejected"
        ) || role.starts_with("lan_public_")
        {
            "td-in-lan"
        } else {
            "td-in-wan"
        };
        self.raw(
            &[
                "env",
                &format!("TUNNEL_DETOUR_INBOUND_PROBE={role}"),
                &format!(
                    "TUNNEL_DETOUR_LUCI_REVIEW={}",
                    if env::var_os("TUNNEL_DETOUR_LUCI_IPV6_REVIEW").is_some() {
                        "2"
                    } else if env::var_os("TUNNEL_DETOUR_LUCI_RELAY_REVIEW").is_some() {
                        "1"
                    } else {
                        "0"
                    }
                ),
                &format!(
                    "TUNNEL_DETOUR_EXPECT_OFFLOAD={}",
                    if self.vm.is_some() { "1" } else { "0" }
                ),
                "/sbin/ip",
                "netns",
                "exec",
                namespace,
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
                "--nocapture",
            ],
            None,
        )
    }

    fn reload_inbound(&self, config: &Value) -> TestResult {
        self.exec(
            &["tee", "/tmp/inbound-config.json"],
            Some(&serde_json::to_vec(config)?),
        )?;
        let status: Value =
            serde_json::from_slice(&self.exec(&["cat", "/tmp/inbound-test/status.json"], None)?)?;
        let revision = status["revision"]
            .as_u64()
            .ok_or("missing inbound revision")?;
        let pid = status["process_id"]
            .as_u64()
            .ok_or("missing inbound PID")?
            .to_string();
        self.exec(&["kill", "-HUP", &pid], None)?;
        wait(|| {
            let status: Value = serde_json::from_slice(
                &self.exec(&["cat", "/tmp/inbound-test/status.json"], None)?,
            )?;
            Ok(status["phase"] == "ready"
                && status["revision"]
                    .as_u64()
                    .is_some_and(|value| value > revision)
                && status["last_error"].is_null()
                && status["publications"] == config["rules"])
        })
    }

    fn spawn_inbound_probe(&self, role: &str) -> TestResult {
        let namespace = if matches!(
            role,
            "dns_holding"
                | "dns_reloading"
                | "dns_rejected"
                | "server"
                | "ula_server"
                | "other_server"
                | "relay_server"
                | "relay_other_server"
        ) || role.starts_with("lan_public_")
        {
            "td-in-lan"
        } else {
            "td-in-wan"
        };
        let probe = format!("TUNNEL_DETOUR_INBOUND_PROBE={role}");
        let review = format!(
            "TUNNEL_DETOUR_LUCI_REVIEW={}",
            if env::var_os("TUNNEL_DETOUR_LUCI_IPV6_REVIEW").is_some() {
                "2"
            } else if env::var_os("TUNNEL_DETOUR_LUCI_RELAY_REVIEW").is_some()
                || env::var_os("TUNNEL_DETOUR_LUCI_DNS_DIAGNOSTICS_REVIEW").is_some()
            {
                "1"
            } else {
                "0"
            }
        );
        let offload = format!(
            "TUNNEL_DETOUR_EXPECT_OFFLOAD={}",
            if self.vm.is_some() { "1" } else { "0" }
        );
        let mut args = vec!["env", &probe, &review, &offload];
        if role != "unmarked_router_server" {
            args.extend(["/sbin/ip", "netns", "exec", namespace]);
        }
        args.extend([
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
            "--nocapture",
        ]);
        let child = self.background_command(&args)?.spawn()?;
        self.background.borrow_mut().push(child);
        Ok(())
    }

    fn stop_inbound(&self) -> TestResult {
        let status: Value =
            serde_json::from_slice(&self.exec(&["cat", "/tmp/inbound-test/status.json"], None)?)?;
        let pid = status["process_id"]
            .as_u64()
            .ok_or("missing inbound PID")?
            .to_string();
        self.exec(&["kill", "-TERM", &pid], None)?;
        wait(|| {
            Ok(!self
                .raw(
                    &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
                    None,
                )?
                .status
                .success())
        })
    }

    fn dnsmasq_ready(&self) -> TestResult {
        let mut lookup_error = String::new();
        wait(|| {
            let reply = self.raw(
                &[
                    "nslookup",
                    "-retry=1",
                    "-timeout=2",
                    "ordinary.example.net",
                    "127.0.0.1",
                ],
                None,
            )?;
            lookup_error = format!(
                "{}: {} {}",
                reply.status,
                String::from_utf8_lossy(&reply.stdout),
                String::from_utf8_lossy(&reply.stderr)
            );
            Ok(reply.status.success()
                && String::from_utf8_lossy(&reply.stdout).contains("Address: 203.0.113.2"))
        })
        .map_err(|error| {
            format!(
                "dnsmasq startup: {error}; {lookup_error}; {}",
                String::from_utf8_lossy(
                    &self
                        .exec(&["logread", "-l", "40"], None)
                        .unwrap_or_default()
                )
            )
            .into()
        })
    }

    fn configure_dnsmasq(&self) -> TestResult {
        self.dnsmasq_ready()?;
        self.prepare_dnsmasq()?;
        self.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
        Ok(())
    }

    fn prepare_dnsmasq(&self) -> TestResult {
        self.exec(&["uci", "batch"], Some(b"set tunnel-detour.globals.dns_integration='dnsmasq'\nset tunnel-detour.globals.real_upstream='127.0.0.1:15353'\nset tunnel-detour.globals.adguard_url='unused-invalid-endpoint'\nset tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'\ncommit tunnel-detour\n"))?;
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
        Ok(String::from_utf8(self.exec(
            &["nslookup", "-retry=1", "-timeout=2", hostname, "127.0.0.1"],
            None,
        )?)?)
    }
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r082_uci_relay_capacity_refuses_excess_before_lan_dial_and_remains_manageable_during_limit_changes()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.prepare_inbound_uci()?;
    for role in ["relay_server", "relay_other_server"] {
        lab.spawn_inbound_probe(role)?;
    }
    for marker in ["relay-endpoint-ready", "relay-other-endpoint-ready"] {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "test", marker)?
                .status
                .success())
        })?;
    }
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.relay_connections='2'\nset tunnel-detour.inbound.observability='1'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    let marker = |name: &str| -> TestResult {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", name)?
                .status
                .success())
        })
    };
    lab.exec(&["nft", "-f", "-"], Some(br#"table inet td_lab_relay_capacity {
 counter dials {}
 chain output { type filter hook output priority 0; policy accept;
  oifname "tdlan0" ip daddr 192.0.2.2 tcp dport {8080,8081} tcp flags & (syn|ack) == syn counter name dials
 }
}
"#))?;
    let dials = || -> TestResult<Value> {
        let value: Value = serde_json::from_slice(&lab.exec(
            &[
                "nft",
                "-j",
                "list",
                "counter",
                "inet",
                "td_lab_relay_capacity",
                "dials",
            ],
            None,
        )?)?;
        Ok(value["nftables"][1]["counter"]["packets"].clone())
    };
    lab.spawn_inbound_probe("relay_capacity")?;
    marker("relay-capacity-ready")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["relay"]["connections"].as_array().is_some_and(|sessions| sessions.len() == 2))
    })?;
    let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
    assert_eq!(
        status["status"]["relay"]["connections"]
            .as_array()
            .ok_or("missing sessions")?
            .len(),
        2
    );
    lab.inbound_marker("td-in-wan", "touch", "check-relay-capacity")?;
    marker("relay-capacity-rejected")?;
    assert_eq!(
        dials()?,
        2,
        "capacity refusal must not start an excess backend connection"
    );
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["relay"]["rejected"]
                .as_u64()
                .is_some_and(|count| count >= 1),
        )
    })?;
    let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
    assert_eq!(
        status["status"]["relay"]["connections"]
            .as_array()
            .ok_or("missing sessions")?
            .len(),
        2
    );
    assert!(
        status["status"]["relay"]["rejected"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "cat", "relay-server-active")?
            .stdout
            == b"2")
    })?;
    assert!(lab.lookup("ordinary.example.net")?.contains("203.0.113.2"));
    lab.change("set tunnel-detour.inbound.relay_connections='1'\nset tunnel-detour.sample.destination_port='8081'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["applied"] == true
            && status["status"]["publications"][0]["destination"] == "192.0.2.2:8081")
    })?;
    lab.inbound_marker("td-in-wan", "touch", "check-relay-new-limit")?;
    marker("relay-capacity-reconfigured")?;
    assert_eq!(
        dials()?,
        3,
        "only one new backend connection is allowed by the reduced limit"
    );
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "cat", "relay-server-active")?
            .stdout
            == b"0")
    })?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "cat", "relay-other-server-active")?
            .stdout
            == b"1")
    })?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["relay"]["connections"].as_array().is_some_and(|sessions| sessions.len() == 1))
    })?;
    let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
    assert_eq!(
        status["status"]["relay"]["connections"]
            .as_array()
            .ok_or("missing sessions")?
            .len(),
        1
    );
    assert!(lab.ubus("system", "board", json!({}))?["kernel"].is_string());
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    lab.inbound_marker("td-in-wan", "touch", "check-relay-capacity-stop")?;
    marker("relay-capacity-complete")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "cat", "relay-other-server-active")?
            .stdout
            == b"0")
    })?;
    assert_eq!(
        lab.ubus("tunnel-detour", "inbound_port_usage", json!({"port":10537}))?["uses"],
        json!([])
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r079_relay_target_changes_disable_and_reenable_retire_both_tcp_sides_while_native_publications_and_dual_stack_vpn_traffic_are_preserved()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    // Management readiness does not imply that the asynchronous DNS startup is complete.
    // Establish the baseline before claiming that publication changes preserve it.
    lab.dnsmasq_ready()?;
    lab.inbound_wireguard()?;
    lab.inbound_ipv4_wireguard()?;
    if lab.vm.is_some() {
        lab.exec(&["uci", "batch"], Some(b"set firewall.@defaults[0].flow_offloading='1'\nset firewall.@defaults[0].flow_offloading_hw='0'\ncommit firewall\n"))?;
        lab.exec(&["fw4", "reload"], None)?;
    }
    for role in ["vpn_client", "vpn_client4"] {
        let before = lab.inbound_vpn_plaintext()?;
        let probe = lab.inbound_probe(role)?;
        assert!(
            probe.status.success(),
            "the real WireGuard baseline failed for {role}: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let after = lab.inbound_vpn_plaintext()?;
        assert!(
            after[0] > before[0] && after[1] > before[1],
            "both request and response must cross WireGuard for {role}"
        );
    }
    // Prove that the collector excludes a real WireGuard control packet while
    // the positive baselines above prove that it includes application traffic.
    let ip_before = lab.inbound_vpn_plaintext()?;
    let transport_before = lab.inbound_vpn_transfer()?;
    let peer = String::from_utf8(lab.exec(&["wg", "show", "tdvpn0", "peers"], None)?)?;
    if peer.split_whitespace().count() != 1 {
        return Err("one isolated WireGuard peer is required".into());
    }
    lab.exec(
        &[
            "wg",
            "set",
            "tdvpn0",
            "peer",
            peer.trim(),
            "persistent-keepalive",
            "1",
        ],
        None,
    )?;
    wait(|| Ok(lab.inbound_vpn_transfer()?[1] > transport_before[1]))?;
    lab.exec(
        &[
            "wg",
            "set",
            "tdvpn0",
            "peer",
            peer.trim(),
            "persistent-keepalive",
            "0",
        ],
        None,
    )?;
    assert_eq!(
        lab.inbound_vpn_plaintext()?,
        ip_before,
        "WireGuard maintenance is not an inner IP packet"
    );
    for role in ["relay_server", "relay_other_server"] {
        lab.spawn_inbound_probe(role)?;
    }
    for marker in ["relay-endpoint-ready", "relay-other-endpoint-ready"] {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "test", marker)?
                .status
                .success())
        })?;
    }
    let mut config = lab.inbound_configuration();
    config["lan_networks"] = json!(["2001:db8:1::/64", "192.0.2.0/24"]);
    config["observability"] = json!(false);
    let mut stable = config["rules"][0].clone();
    stable["id"] = json!("stable");
    stable["name"] = json!("Unchanged native publication");
    stable["public_port"] = json!(18081);
    config["rules"][0]["protocol"] = json!("tcp");
    config["rules"][0]["destination"] = json!("192.0.2.2:8080");
    config["rules"]
        .as_array_mut()
        .ok_or("missing rules")?
        .push(stable);
    let controller_index = lab.background.borrow().len();
    let inject_first_probe = env::var("TUNNEL_DETOUR_R079_FAIL_FIRST_PROBE").as_deref() == Ok("1");
    let start = || {
        lab.start_inbound(&config)?;
        wait_r079_baseline(&lab, &config, inject_first_probe)
    };
    let initial_status = if inject_first_probe {
        // This read occurs after the committed journal and admitted rules,
        // but before status publication. Release only after observing absence.
        lab.with_command_fault(
            "nft",
            "r079-status-delay",
            r#"if [ "$*" = '--stateless --handle list table inet tunnel_detour_inbound' ] &&
   [ ! -e /tmp/r079-release-status ]; then
  touch /tmp/r079-status-held
  for attempt in 1 2 3 4 5 6 7 8; do
    if [ -e /tmp/r079-release-status ]; then
      touch /tmp/r079-status-unblocked
      exec "$REAL" "$@"
    fi
    sleep 1 || exit 1
  done
  exit 1
fi"#,
            start,
        )?
    } else {
        start()?
    };
    let state = || -> TestResult<Value> {
        Ok(serde_json::from_slice(
            &lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?,
        )?)
    };
    let initial = state()?["admissions"].clone();
    let plaintext = lab.inbound_vpn_plaintext()?;
    let marker = |name: &str| -> TestResult {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", name)?
                .status
                .success())
        })
    };
    if lab.vm.is_some() {
        observe_inbound_forward(&lab)?;
    }
    let first_probe = lab.background.borrow().len();
    let first_role = if inject_first_probe {
        "relay_lifecycle_fixture_failure"
    } else {
        "relay_lifecycle"
    };
    lab.spawn_inbound_probe(first_role)?;
    if let Err(error) = wait_r079_initial_probe(&lab, first_probe) {
        let snapshot = lab.raw_with_deadline(
            &[
                "cat",
                "/tmp/inbound-test/status.json",
                "/tmp/inbound-test/relay-server-active",
                "/tmp/inbound-test/relay-other-server-active",
            ],
            None,
            "5",
        );
        let degraded = r079_status(&lab).and_then(|status| r079_worker_degraded(&status));
        let recovery =
            verify_r079_recovery(&lab, "relay_client", &initial_status, inject_first_probe)
                .map(|()| "backend and echo verified, unchanged PID, revision and publications");
        let controller = lab
            .stop_inbound()
            .and_then(|()| collect_r079_controller(&lab, controller_index));
        let diagnostic = match snapshot {
            Ok(snapshot) => format!(
                "relay lifecycle readiness: {error}; local status and backend counts:\n{}\n{}",
                String::from_utf8_lossy(&snapshot.stdout),
                String::from_utf8_lossy(&snapshot.stderr)
            ),
            Err(diagnostic) => {
                format!("relay lifecycle readiness: {error}; local state unavailable: {diagnostic}")
            }
        };
        let worker = controller.map(|output| {
            (
                output.status,
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        });
        return Err(format!(
            "{diagnostic}; worker degraded before recovery: {degraded:?}; same-controller recovery: {recovery:?}; worker: {worker:?}"
        )
        .into());
    }
    if lab.vm.is_some() {
        wait(|| {
            for protocol in ["tcp", "udp"] {
                let flows = lab.exec(
                    &[
                        "conntrack",
                        "-L",
                        "--family",
                        "ipv6",
                        "--proto",
                        protocol,
                        "--orig-dst",
                        "2001:db8:2::1",
                        "--orig-port-dst",
                        "18081",
                    ],
                    None,
                )?;
                if !String::from_utf8_lossy(&flows).contains("[OFFLOAD]") {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        let packets = inbound_forwarded_packets(&lab)?;
        assert!(
            packets > 0,
            "the forward probe missed the initial native traffic"
        );
        lab.inbound_marker("td-in-wan", "touch", "check-relay-fastpath")?;
        marker("relay-fastpath-checked")?;
        assert_eq!(
            inbound_forwarded_packets(&lab)?,
            packets,
            "native payload in a mixed relay policy must use its verified shortcut"
        );
    }
    let active = |name: &str| -> TestResult<String> {
        Ok(
            String::from_utf8(lab.inbound_marker("td-in-lan", "cat", name)?.stdout)?
                .trim()
                .to_owned(),
        )
    };
    wait(|| Ok(active("relay-server-active")? == "1"))?;
    config["rules"][0]["destination"] = json!("192.0.2.2:8081");
    lab.reload_inbound(&config)?;
    assert_ne!(state()?["admissions"]["sample"], initial["sample"]);
    assert_eq!(state()?["admissions"]["stable"], initial["stable"]);
    lab.inbound_marker("td-in-wan", "touch", "check-relay-retarget")?;
    marker("relay-lifecycle-retargeted")?;
    wait(|| {
        Ok(active("relay-server-active")? == "0" && active("relay-other-server-active")? == "1")
    })?;
    config["rules"][0]["enabled"] = json!(false);
    lab.reload_inbound(&config)?;
    lab.inbound_marker("td-in-wan", "touch", "check-relay-disabled")?;
    marker("relay-lifecycle-disabled")?;
    wait(|| Ok(active("relay-other-server-active")? == "0"))?;
    config["rules"][0]["enabled"] = json!(true);
    lab.reload_inbound(&config)?;
    lab.inbound_marker("td-in-wan", "touch", "check-relay-restored")?;
    marker("relay-lifecycle-restored")?;
    assert_eq!(
        lab.inbound_vpn_plaintext()?,
        plaintext,
        "publication bytes or their replies leaked into WireGuard"
    );
    for role in ["vpn_client", "vpn_client4"] {
        let before = lab.inbound_vpn_plaintext()?;
        assert!(
            lab.inbound_probe(role)?.status.success(),
            "ordinary VPN traffic was lost for {role}"
        );
        let after = lab.inbound_vpn_plaintext()?;
        assert!(after[0] > before[0] && after[1] > before[1]);
    }
    let before_refusal = r079_status(&lab)?;
    assert_eq!(before_refusal["observability"], false);
    let worker_root = "/var/run/tunnel-detour/transport/r079-block-worker";
    lab.exec(&["touch", worker_root], None)?;
    let failed = lab.inbound_probe("transport_start_refused");
    let wait_for_degradation = failed.and_then(|probe| {
        assert!(
            probe.status.success(),
            "the worker refusal must close only the fresh connection: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        wait_for(Duration::from_secs(6), || {
            let status = r079_status(&lab)?;
            same_r079_controller(&before_refusal, &status)?;
            r079_worker_degraded(&status)
        })
    });
    let restored_root = lab.exec(&["rm", worker_root], None);
    wait_for_degradation?;
    restored_root?;
    verify_r079_recovery(&lab, "relay_recovery_client", &before_refusal, false)?;
    lab.stop_inbound()?;
    let controller = collect_r079_controller(&lab, controller_index)?;
    assert!(controller.status.success());
    let stderr = String::from_utf8(controller.stderr)?;
    assert!(
        stderr.contains("code=\"transport_worker_failed\"")
            && stderr.contains("stage=\"worker_root\""),
        "worker root failure must be identifiable without traffic diagnostics: {stderr}"
    );
    lab.inbound_marker("td-in-wan", "touch", "check-relay-stopped")?;
    marker("relay-lifecycle-complete")?;
    wait(|| Ok(active("relay-other-server-active")? == "0"))?;
    assert!(lab.lookup("ordinary.example.net")?.contains("203.0.113.2"));
    Ok(())
}

fn r079_status(lab: &Lab) -> TestResult<Value> {
    Ok(serde_json::from_slice(
        &lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?,
    )?)
}

fn wait_r079_baseline(lab: &Lab, config: &Value, delayed: bool) -> TestResult<Value> {
    let mut released = false;
    let mut baseline = None;
    let consent = config["observability"]
        .as_bool()
        .ok_or("R079 fixture requires an explicit observability setting")?;
    wait_for(Duration::from_secs(15), || {
        let reply = lab.raw_with_deadline(
            &["sh", "-c", "test -e /tmp/inbound-test/status.json || exit 3; cat /tmp/inbound-test/status.json"],
            None,
            "4",
        )?;
        if reply.status.code() == Some(3) {
            if delayed
                && !released
                && lab
                    .raw(&["test", "-e", "/tmp/r079-status-held"], None)?
                    .status
                    .success()
            {
                verify_r079_held_publication(lab, config)?;
                lab.exec(&["touch", "/tmp/r079-release-status"], None)?;
                released = true;
                eprintln!("R079 held publication after committed journal and applied guard");
            }
            return Ok(false);
        }
        if !reply.status.success() {
            return Err("R079 could not read its initial status".into());
        }
        let status: Value = serde_json::from_slice(&reply.stdout)?;
        if status["applied"] != true
            || status["phase"] != "ready"
            || status["process_id"].as_u64().is_none_or(|pid| pid == 0)
            || status["revision"]
                .as_u64()
                .is_none_or(|revision| revision == 0)
            || status["publications"] != config["rules"]
            || status["observability"] != consent
        {
            return Ok(false);
        }
        r079_worker_degraded(&status)?;
        if status["degraded"] != json!([]) {
            return Err("R079 initial status was already degraded".into());
        }
        if delayed
            && (!released
                || !lab
                    .raw(&["test", "-e", "/tmp/r079-status-unblocked"], None)?
                    .status
                    .success())
        {
            return Err("R079 did not observe the delayed publication".into());
        }
        baseline = Some(status);
        Ok(true)
    })?;
    baseline.ok_or_else(|| "R079 has no applied baseline snapshot".into())
}

fn verify_r079_held_publication(lab: &Lab, config: &Value) -> TestResult {
    let journal: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?)?;
    let admissions = journal["admissions"]
        .as_object()
        .ok_or("R079 journal lacks committed admissions")?;
    let expected = config["rules"]
        .as_array()
        .ok_or("R079 fixture lacks publications")?;
    if journal.get("pending") != Some(&Value::Null) || admissions.len() != expected.len() {
        return Err("R079 journal is not committed for the expected publications".into());
    }
    let ruleset: Value = serde_json::from_slice(&lab.exec(
        &[
            "nft",
            "-j",
            "-s",
            "list",
            "table",
            "inet",
            "tunnel_detour_inbound",
        ],
        None,
    )?)?;
    let objects = ruleset["nftables"]
        .as_array()
        .ok_or("R079 could not inspect its guard")?;
    if !objects.iter().any(|entry| {
        entry["table"]["name"] == "tunnel_detour_inbound"
            && entry["table"]["comment"] == "tunnel-detour:inbound:v1"
    }) {
        return Err("R079 guard has no package ownership marker".into());
    }
    let prefix = config["wan"]["mark_prefix"]
        .as_u64()
        .ok_or("R079 fixture lacks a mark prefix")?;
    for publication in expected {
        let id = publication["id"]
            .as_str()
            .ok_or("R079 publication has no ID")?;
        let generation = admissions
            .get(id)
            .and_then(Value::as_u64)
            .filter(|generation| (1..=u64::from(u16::MAX)).contains(generation))
            .ok_or("R079 journal is missing an expected admission")?;
        let port = publication["public_port"]
            .as_u64()
            .ok_or("R079 publication has no numeric port")?;
        for protocol in match publication["protocol"].as_str() {
            Some("tcp") => &["tcp"][..],
            Some("tcp_udp") => &["tcp", "udp"][..],
            _ => return Err("unexpected R079 fixture protocol".into()),
        } {
            verify_r079_admission_rule(objects, protocol, port, prefix | generation)?;
        }
    }
    // Check again after inspecting both live components, before releasing.
    lab.exec(&["test", "!", "-e", "/tmp/inbound-test/status.json"], None)?;
    Ok(())
}

fn verify_r079_admission_rule(
    objects: &[Value],
    protocol: &str,
    port: u64,
    mark: u64,
) -> TestResult {
    let selector = json!({
        "op":"==", "left":{"payload":{"protocol":protocol,"field":"dport"}}, "right":port
    });
    if objects.iter().any(|entry| {
        let rule = &entry["rule"];
        rule["chain"] == "tag"
            && rule["expr"].as_array().is_some_and(|expr| {
                expr.iter().any(|item| item["match"] == selector)
                    && expr.iter().any(|item| {
                        item["mangle"]["key"]["ct"]["key"] == "mark"
                            && item["mangle"]["value"] == mark
                    })
            })
    }) {
        Ok(())
    } else {
        Err("R079 guard does not admit an expected publication".into())
    }
}

#[test]
fn r079c_comparator_rejects_a_rule_that_excludes_the_published_port() -> TestResult {
    let mark = 1_413_742_594_u64;
    let matching = [json!({"rule":{"chain":"tag", "expr":[
        {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":18081}},
        {"mangle":{"key":{"ct":{"key":"mark"}},"value":mark}}
    ]}})];
    verify_r079_admission_rule(&matching, "udp", 18081, mark)?;

    let mut excluding = matching.clone();
    excluding[0]["rule"]["expr"][0]["match"]["op"] = json!("!=");
    assert!(
        verify_r079_admission_rule(&excluding, "udp", 18081, mark).is_err(),
        "a rule excluding the published UDP port must not release the R079c barrier"
    );
    Ok(())
}

fn r079_worker_degraded(status: &Value) -> TestResult<bool> {
    let flags = status["degraded"]
        .as_array()
        .filter(|flags| {
            flags
                .iter()
                .all(|flag| flag.as_str().is_some_and(|code| !code.is_empty()))
        })
        .ok_or("R079 status requires a valid degraded list")?;
    Ok(flags.iter().any(|flag| flag == "transport_worker_failed"))
}

fn wait_r079_initial_probe(lab: &Lab, index: usize) -> TestResult {
    wait(|| {
        if lab
            .inbound_marker("td-in-wan", "test", "relay-lifecycle-ready")?
            .status
            .success()
        {
            return Ok(true);
        }
        let mut jobs = lab.background.borrow_mut();
        let probe = jobs.get_mut(index).ok_or("missing initial relay probe")?;
        if let Some(status) = probe.try_wait()? {
            let mut stderr = String::new();
            if let Some(output) = probe.stderr.take() {
                output.take(4096).read_to_string(&mut stderr)?;
            }
            return Err(format!("initial relay probe exited {status}: {}", stderr.trim()).into());
        }
        Ok(false)
    })
}

fn same_r079_controller(before: &Value, after: &Value) -> TestResult {
    for field in ["process_id", "revision", "publications", "observability"] {
        if before.get(field).is_none() || before[field] != after[field] {
            return Err(format!("relay controller changed {field}").into());
        }
    }
    Ok(())
}

fn r079_recovery_ready(before: &Value, after: &Value) -> TestResult<bool> {
    same_r079_controller(before, after)?;
    Ok(!r079_worker_degraded(after)?)
}

fn verify_r079_recovery(lab: &Lab, role: &str, before: &Value, check_invalid: bool) -> TestResult {
    // An active worker can die without a startup warning. Always exercise a
    // fresh connection; the controlled startup test asserts its warning separately.
    let recovered = lab.inbound_probe(role)?;
    if !recovered.status.success() {
        return Err(format!(
            "fresh relay failed: {}",
            String::from_utf8_lossy(&recovered.stderr)
        )
        .into());
    }
    wait_for(Duration::from_secs(10), || {
        let after = r079_status(lab)?;
        if !r079_recovery_ready(before, &after)? {
            return Ok(false);
        }
        if check_invalid {
            let mut invalid = after.clone();
            invalid
                .as_object_mut()
                .ok_or("expected an R079 status object")?
                .remove("degraded");
            if r079_recovery_ready(before, &invalid).is_ok() {
                return Err("R079 accepted a missing degraded list after a successful echo".into());
            }
            invalid["degraded"] = Value::Null;
            if r079_recovery_ready(before, &invalid).is_ok() {
                return Err("R079 accepted a null degraded list after a successful echo".into());
            }
            eprintln!("R079 rejected missing and null health fields after the fresh echo");
        }
        Ok(true)
    })
}

fn collect_r079_controller(lab: &Lab, controller_index: usize) -> TestResult<Output> {
    wait_for(Duration::from_secs(10), || {
        let mut jobs = lab.background.borrow_mut();
        let controller = jobs
            .get_mut(controller_index)
            .ok_or("missing relay controller")?;
        Ok(controller.try_wait()?.is_some())
    })?;
    Ok(lab
        .background
        .borrow_mut()
        .remove(controller_index)
        .wait_with_output()?)
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r078_relay_capture_listener_rejects_direct_access_from_wan_lan_and_the_router_in_both_access_modes()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    let initial = lab.inbound_probe("relay_client")?;
    assert!(
        initial.status.success(),
        "the positive control relay is unavailable"
    );
    let blocked = lab.inbound_probe("lan_public_relay_blocked")?;
    assert!(
        blocked.status.success(),
        "WAN-only relay accepted a LAN public connection: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    for access in ["wan_only", "wan_and_lan"] {
        lab.change(&format!("set tunnel-detour.sample.access='{access}'"))?;
        wait(|| {
            let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(status["status"]["applied"] == true
                && status["status"]["publications"][0]["access"] == access)
        })?;
        for role in ["relay_direct_wan", "lan_public_relay_internal"] {
            let result = lab.inbound_probe(role)?;
            assert!(
                result.status.success(),
                "direct listener access was accepted ({access}, {role}): {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let local = lab.raw(
            &[
                "env",
                "TUNNEL_DETOUR_INBOUND_PROBE=relay_direct_router",
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
                "--nocapture",
            ],
            None,
        )?;
        assert!(
            local.status.success(),
            "loopback listener bypass was accepted"
        );
        let positive = lab.inbound_probe("relay_client")?;
        assert!(
            positive.status.success(),
            "listener isolation closed the authorized publication"
        );
    }
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    let port = lab.ubus("tunnel-detour", "inbound_port_usage", json!({"port":10537}))?;
    assert!(
        port["uses"].as_array().is_some_and(Vec::is_empty),
        "the capture listener survived stop"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r077_ipv6_tcp_publication_reaches_a_fixed_ipv4_lan_target_without_dns_and_preserves_client_identity_in_status()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    // IPv6 ingress to an IPv4 server does not require a global IPv6 LAN prefix.
    // Keep its later optional-LAN-access scenario in this same owning test.
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "del",
            "2001:db8:1::1/64",
            "dev",
            "tdlan0",
        ],
        None,
    )?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.observability='1'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })
    .map_err(|error| {
        format!(
            "relay startup: {error}; {}",
            String::from_utf8_lossy(
                &lab.exec(&["logread", "-e", "tunnel-detour", "-l", "25"], None)
                    .unwrap_or_default()
            )
        )
    })?;
    let probe = lab.inbound_probe("relay_client")?;
    assert!(
        probe.status.success(),
        "real IPv6-to-IPv4 relay failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["running"],
        false,
        "ports must remain independent of DNS"
    );
    lab.spawn_inbound_probe("relay_holding")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-ready")?
            .status
            .success())
    })?;
    let client = String::from_utf8(
        lab.inbound_marker("td-in-wan", "cat", "relay-client-endpoint")?
            .stdout,
    )?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["relay"]["connections"]
            .as_array()
            .is_some_and(|connections| {
                connections.iter().any(|connection| {
                    connection["client"].as_str() == Some(client.as_str())
                        && connection["publication"] == "sample"
                        && connection["target"] == "192.0.2.2:8080"
                        && connection["connected"] == true
                })
            }))
    })?;
    pause_for_luci_review(
        "TUNNEL_DETOUR_LUCI_RELAY_REVIEW",
        json!({"url":lab.http,"client":client,"container":lab.name}),
    )?;
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-complete")?
            .status
            .success())
    })?;
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "tdlan0",
            "nodad",
        ],
        None,
    )?;
    lab.change("set tunnel-detour.sample.access='wan_and_lan'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["applied"] == true
            && status["status"]["publications"][0]["access"] == "wan_and_lan")
    })?;
    let local = lab.inbound_probe("lan_public_relay_client")?;
    assert!(
        local.status.success(),
        "local access to the public IPv6-to-IPv4 endpoint failed: {}",
        String::from_utf8_lossy(&local.stderr)
    );
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    assert!(
        lab.raw(
            &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
            None
        )?
        .status
        .code()
        .is_some_and(|code| code != 0)
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r068_foreign_router_ports_are_reserved_across_families_and_protocols_while_verified_owned_ports_remain_usable()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.prepare_inbound_uci()?;
    lab.change(
        "set tunnel-detour.sample.public_port='19080'\nset tunnel-detour.inbound.enabled='1'",
    )?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    // An unrelated executable named tunnel-detour must not acquire ownership by its name.
    lab.exec(
        &[
            "cp",
            "/usr/libexec/tunnel-detour-test-fixture",
            "/tmp/tunnel-detour",
        ],
        None,
    )?;
    let child = lab
        .background_command(&[
            "env",
            "TUNNEL_DETOUR_INBOUND_PROBE=router_ports",
            "/tmp/tunnel-detour",
            "--ignored",
            "--exact",
            "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
            "--nocapture",
        ])?
        .spawn()?;
    lab.background.borrow_mut().push(child);
    wait(|| {
        Ok(lab
            .raw(
                &["test", "-e", "/tmp/inbound-test/router-ports-ready"],
                None,
            )?
            .status
            .success())
    })?;
    // Docker shares the host kernel; older hosts do not expose TCP_BOUND_INACTIVE.
    // The pinned-kernel run owns that additional bound-before-listen assertion.
    // Port 53 is reserved by the real DNS frontend only once it is serving queries.
    lab.dnsmasq_ready()?;
    let mut ports = vec![53_u16, 18080, 18081];
    if lab.vm.is_some() {
        ports.push(18082);
    } else {
        eprintln!("R068: bound-before-listen coverage requires test-openwrt-flow r068");
    }
    for port in ports {
        let usage = lab.ubus("tunnel-detour", "inbound_port_usage", json!({"port":port}))?;
        assert_eq!(
            usage["available"], false,
            "foreign port {port} was declared available"
        );
        let uses = usage["uses"].as_array().ok_or("missing port uses")?;
        assert!(uses.iter().any(|usage| usage["tunnel_detour"] == false));
        if matches!(port, 18080 | 18081) {
            assert!(
                uses.iter().any(|usage| usage["services"]
                    .as_array()
                    .is_some_and(|names| names.iter().any(|name| name == "tunnel-detour"))
                    && usage["tunnel_detour"] == false),
                "a renamed foreign executable was trusted or not identified"
            );
        }
        lab.change(&format!("set tunnel-detour.sample.public_port='{port}'"))?;
        let mut rejected = Value::Null;
        wait(|| {
            rejected = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(rejected["status"]["port_conflict"]["port"] == port)
        })?;
        assert_eq!(rejected["status"]["applied"], false);
        assert_eq!(rejected["status"]["publications"][0]["public_port"], 19080);
        assert_eq!(rejected["status"]["port_conflict"]["publication"], "sample");
        let traffic = lab.inbound_probe("guard_baseline")?;
        assert!(
            traffic.status.success(),
            "rejected port {port} disrupted the previous publication: {}",
            String::from_utf8_lossy(&traffic.stderr)
        );
    }
    let control = lab.raw(
        &[
            "env",
            "TUNNEL_DETOUR_INBOUND_PROBE=router_ports_control",
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
            "--nocapture",
        ],
        None,
    )?;
    assert!(
        control.status.success(),
        "reservation checks disrupted router services: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    lab.configure_dnsmasq()?;
    lab.ready(None)?;
    let owned = lab.ubus("tunnel-detour", "inbound_port_usage", json!({"port":10536}))?;
    assert_eq!(
        owned["available"], true,
        "a verified Tunnel Detour process was treated as foreign"
    );
    assert!(owned["uses"].as_array().is_some_and(
        |uses| !uses.is_empty() && uses.iter().all(|usage| usage["tunnel_detour"] == true)
    ));
    lab.change("set tunnel-detour.sample.public_port='10536'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    let traffic = lab.inbound_probe("owned_port_client")?;
    assert!(
        traffic.status.success(),
        "owned public port failed: {}",
        String::from_utf8_lossy(&traffic.stderr)
    );
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    // The same ownership policy protects the relay's internal port, before binding
    // or replacing the previously working native publication.
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.relay_port='80'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(
            status["status"]["port_conflict"]["location"] == "relay_listener"
                && status["status"]["port_conflict"]["port"] == 80,
        )
    })?;
    let checked = lab.ubus("tunnel-detour", "check_inbound", json!({}))?;
    assert_eq!(checked["valid"], false);
    assert_eq!(checked["port_conflict"]["location"], "relay_listener");
    let traffic = lab.inbound_probe("owned_port_client")?;
    assert!(
        traffic.status.success(),
        "a refused internal port disrupted the previous publication: {}",
        String::from_utf8_lossy(&traffic.stderr)
    );
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    assert!(
        lab.raw(
            &[
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "http://127.0.0.1/luci-static/resources/view/tunnel-detour/overview.js"
            ],
            None
        )?
        .status
        .success(),
        "refusing the web server's port disrupted management HTTP"
    );
    lab.change("set tunnel-detour.inbound.enabled='0'\nset tunnel-detour.globals.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r067_optional_lan_public_address_access_routes_tcp_udp_locally_and_mode_changes_retire_old_flows()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    if lab.vm.is_some() {
        lab.exec(&["uci", "batch"], Some(b"set firewall.@defaults[0].flow_offloading='1'\nset firewall.@defaults[0].flow_offloading_hw='0'\ncommit firewall\n"))?;
        lab.exec(&["fw4", "reload"], None)?;
    }
    let firewall = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    let mut config = lab.inbound_configuration();
    config["lan_router_addresses"] = json!(["2001:db8:1::1"]);
    lab.start_inbound(&config)?;
    let denied = lab.inbound_probe("lan_public_denied")?;
    assert!(
        denied.status.success(),
        "LAN public-address access must start disabled: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    config["rules"][0]["access"] = json!("wan_and_lan");
    lab.reload_inbound(&config)?;
    for role in ["lan_public_client", "client"] {
        let traffic = lab.inbound_probe(role)?;
        assert!(
            traffic.status.success(),
            "{role}: {}",
            String::from_utf8_lossy(&traffic.stderr)
        );
    }
    if lab.vm.is_some() {
        observe_inbound_forward(&lab)?;
    }
    lab.spawn_inbound_probe("lan_public_holding")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "lan-public-ready")?
            .status
            .success())
    })?;
    if lab.vm.is_some() {
        wait(|| {
            for protocol in ["tcp", "udp"] {
                let flows = lab.exec(
                    &[
                        "conntrack",
                        "-L",
                        "--family",
                        "ipv6",
                        "--proto",
                        protocol,
                        "--orig-src",
                        "2001:db8:1::2",
                        "--orig-dst",
                        "2001:db8:2::1",
                        "--orig-port-dst",
                        "18080",
                    ],
                    None,
                )?;
                if !String::from_utf8_lossy(&flows).contains("[OFFLOAD]") {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        let before = inbound_forwarded_packets(&lab)?;
        assert!(
            before > 0,
            "the forward probe missed the initial native traffic"
        );
        lab.inbound_marker("td-in-lan", "touch", "check-lan-public-fastpath")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "test", "lan-public-fastpath-checked")?
                .status
                .success())
        })?;
        assert_eq!(
            inbound_forwarded_packets(&lab)?,
            before,
            "LAN TCP/UDP payload did not bypass the ordinary guard through software offloading"
        );
    }
    config["rules"][0]["access"] = json!("wan_only");
    lab.reload_inbound(&config)?;
    lab.inbound_marker("td-in-lan", "touch", "check-lan-public-disabled")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "lan-public-closed")?
            .status
            .success())
    })?;
    let denied = lab.inbound_probe("lan_public_denied")?;
    assert!(
        denied.status.success(),
        "disabling LAN access admitted a new LAN flow: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let external = lab.inbound_probe("client")?;
    assert!(
        external.status.success(),
        "Internet publication stopped with LAN access: {}",
        String::from_utf8_lossy(&external.stderr)
    );
    config["rules"][0]["access"] = json!("wan_and_lan");
    lab.reload_inbound(&config)?;
    lab.inbound_marker("td-in-lan", "touch", "check-lan-public-restored")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "lan-public-complete")?
            .status
            .success())
    })?;
    let fresh = lab.inbound_probe("lan_public_client")?;
    assert!(
        fresh.status.success(),
        "fresh LAN TCP/UDP failed after re-enable: {}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    let current = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    for (name, section) in firewall["values"].as_object().ok_or("missing firewall")? {
        assert_eq!(
            &current["values"][name], section,
            "LAN access altered foreign configuration or zone masquerading"
        );
    }
    lab.stop_inbound()?;
    assert_eq!(
        lab.ubus("uci", "get", json!({"config":"firewall"}))?,
        firewall
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r065_invalid_saved_publications_keep_previous_flows_and_report_that_changes_were_not_applied()
-> TestResult {
    // PF-01d/PF-09c: rejection preserves policy and reports what is still active.
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    let mut initial = Value::Null;
    wait(|| {
        initial = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(initial["running"] == true && initial["status"]["applied"] == true)
    })?;
    assert_eq!(initial["status"]["observability"], false);
    lab.spawn_inbound_probe("independent")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "independent-ready")?
            .status
            .success())
    })?;
    for (candidate, error) in [
        (
            "set tunnel-detour.sample.destination_address='rejected-destination.example.test'",
            "inbound_configuration_failed",
        ),
        (
            "set tunnel-detour.sample.destination_address='2001:db8:1::2'\nset tunnel-detour.sample.public_port='80'",
            "inbound_local_port_conflict",
        ),
    ] {
        lab.change(candidate)?;
        let mut rejected = Value::Null;
        wait(|| {
            rejected = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(rejected["status"]["last_error"] == error)
        })
        .map_err(|failure| {
            format!("expected rejection {error}: {failure}; actual status: {rejected}")
        })?;
        assert_eq!(rejected["status"]["observability"], false);
        wait(|| {
            let logs = String::from_utf8(lab.exec(&["logread"], None)?)?;
            let health_code = format!("code=\"{error}\"");
            let mut reported = false;
            for line in logs.lines().filter(|line| line.contains(&health_code)) {
                reported = true;
                for private in ["example.test", "2001:db8:", "192.0.2.", "198.51.100."] {
                    assert!(
                        !line.contains(private),
                        "health log exposed an input: {line}"
                    );
                }
            }
            Ok(reported)
        })
        .map_err(|failure| format!("expected operational log code {error}: {failure}"))?;
        assert_eq!(rejected["running"], true);
        assert_eq!(rejected["status"]["phase"], "ready");
        assert_eq!(
            rejected["status"]["applied"], false,
            "rejected saved changes must not be reported as applied"
        );
        // Harmless native network events may advance revision without changing policy.
        for field in ["process_id", "publications"] {
            assert_eq!(rejected["status"][field], initial["status"][field]);
        }
        let traffic = lab.inbound_probe("client")?;
        assert!(
            traffic.status.success(),
            "previous TCP/UDP publication lost traffic: {}",
            String::from_utf8_lossy(&traffic.stderr)
        );
    }
    lab.change("set tunnel-detour.sample.public_port='18080'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["applied"] == true && status["status"]["last_error"].is_null())
    })?;
    lab.exec(&["touch", "/tmp/inbound-test/check-independent"], None)?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "independent-complete")?
            .status
            .success())
    })?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["running"],
        false
    );
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r064_offline_uninstall_cleans_dns_and_inbound_owners_together_and_preserves_admin_resources()
-> TestResult {
    // PF-07c: exercise the native prerm sequence with both independent features active.
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let dns_before = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["running"] == true && status["status"]["phase"] == "ready")
    })?;
    let probe = lab.inbound_probe("client")?;
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    lab.configure_dnsmasq()?;
    lab.ready(None)?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.exec(
        &["nft", "--file", "-"],
        Some(b"add table inet admin_uninstall_probe\nadd chain inet admin_uninstall_probe preserved\n"),
    )?;
    let foreign_nft = lab.exec(
        &[
            "nft",
            "-j",
            "-a",
            "list",
            "table",
            "inet",
            "admin_uninstall_probe",
        ],
        None,
    )?;
    for family in ["-4", "-6"] {
        lab.exec(
            &[
                "ip",
                family,
                "route",
                "add",
                "unreachable",
                "default",
                "table",
                "41999",
                "proto",
                "242",
            ],
            None,
        )?;
    }
    let foreign_routes = |family| {
        lab.exec(
            &["ip", "-j", "-N", family, "route", "show", "table", "41999"],
            None,
        )
    };
    let v4_before = foreign_routes("-4")?;
    let v6_before = foreign_routes("-6")?;
    // A crashed controller can leave a snapshot that cannot be opened safely.
    // Use a symlink so cleanup must discard the link and preserve its target.
    let inbound = lab.ubus("service", "list", json!({"name":"tunnel-detour-inbound"}))?;
    let inbound_pid = inbound["tunnel-detour-inbound"]["instances"]["inbound"]["pid"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or("missing isolated inbound controller")?;
    let sentinel = "/tmp/uninstall-status-sentinel";
    lab.exec(&["tee", sentinel], Some(b"untouched"))?;
    lab.exec(&["kill", "-STOP", &inbound_pid.to_string()], None)?;
    lab.exec(
        &[
            "ln",
            "-sf",
            sentinel,
            "/var/run/tunnel-detour/inbound/status.json",
        ],
        None,
    )?;
    lab.exec(&["ifdown", "wan"], None)?;
    lab.exec(&["kill", "-KILL", &inbound_pid.to_string()], None)?;
    for command in [
        vec!["/etc/init.d/tunnel-detour-inbound", "stop"],
        vec!["/etc/init.d/tunnel-detour", "stop"],
        vec!["/usr/bin/tunnel-detour", "--uninstall"],
    ] {
        lab.exec(&command, None)?;
    }
    for table in ["tunnel_detour", "tunnel_detour_inbound"] {
        assert!(
            !lab.raw(&["nft", "list", "table", "inet", table], None)?
                .status
                .success(),
            "uninstall retained the owned table {table}"
        );
    }
    assert_eq!(lab.exec(&["cat", sentinel], None)?, b"untouched");
    lab.exec(
        &["test", "!", "-e", "/var/run/tunnel-detour/transport"],
        None,
    )?;
    for family in ["-4", "-6"] {
        let rules: Value =
            serde_json::from_slice(&lab.exec(&["ip", "-j", "-N", family, "rule", "show"], None)?)?;
        assert!(
            rules
                .as_array()
                .ok_or("missing routing rules")?
                .iter()
                .all(|rule| rule["priority"] != 100),
            "uninstall retained an owned {family} routing rule"
        );
    }
    let firewall = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    assert!(
        firewall["values"]
            .as_object()
            .ok_or("missing firewall")?
            .keys()
            .all(|name| !name.starts_with("td_in_"))
    );
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns_before);
    assert_eq!(foreign_routes("-4")?, v4_before);
    assert_eq!(foreign_routes("-6")?, v6_before);
    assert_eq!(
        lab.exec(
            &[
                "nft",
                "-j",
                "-a",
                "list",
                "table",
                "inet",
                "admin_uninstall_probe"
            ],
            None
        )?,
        foreign_nft
    );
    for path in [
        "/etc/config/tunnel-detour",
        "/etc/tunnel-detour",
        "/var/run/tunnel-detour",
    ] {
        assert!(
            !lab.raw(&["test", "-e", path], None)?.status.success(),
            "uninstall retained {path}"
        );
    }
    // Restart the existing frontend to discard its old cache, then prove normal and local DNS.
    lab.exec(&["/etc/init.d/dnsmasq", "restart"], None)?;
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|reply| reply.contains("203.0.113.2")))
    })?;
    assert!(lab.lookup("ordinary.example.net")?.contains("203.0.113.2"));
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    assert!(lab.ubus("system", "board", json!({}))?["kernel"].is_string());
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r063_wan_publications_enforce_selected_ports_protocols_and_nonlocal_internet_sources()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-lan",
            "-6",
            "addr",
            "add",
            "2001:db8:1::3/64",
            "dev",
            "peer0",
            "nodad",
        ],
        None,
    )?;
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "route",
            "add",
            "2001:db8:1::/64",
            "via",
            "2001:db8:2::1",
        ],
        None,
    )?;
    lab.spawn_inbound_probe("other_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "other-endpoint-ready")?
            .status
            .success())
    })?;
    assert!(
        lab.inbound_probe("other_control")?.status.success(),
        "the unselected LAN endpoint must actually serve its positive control"
    );
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:ffff::1/128",
            "dev",
            "lo",
            "nodad",
        ],
        None,
    )?;
    lab.exec(&["nft", "-f", "-"], Some(b"table inet inbound_source_probe {\n counter arrivals {}\n counter other {}\n chain observe {\n type filter hook prerouting priority -301; policy accept;\n iifname \"tdwan0\" ip6 saddr { 2001:db8:1::9, 2001:db8:ffff::1, fd00:1234::9 } udp dport 18081 counter name arrivals\n iifname \"tdwan0\" ip6 daddr 2001:db8:1::3 tcp dport 8080 counter name other\n }\n}\n"))?;
    lab.exec(&["ip", "netns", "exec", "td-in-lan", "nft", "-f", "-"], Some(b"table inet inbound_source_probe {\n counter arrivals {}\n counter baseline {}\n chain observe {\n type filter hook input priority -10; policy accept;\n udp dport 8080 counter name baseline\n ip6 saddr { 2001:db8:1::9, 2001:db8:ffff::1, fd00:1234::9 } udp dport 8080 counter name arrivals\n }\n}\n"))?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.datagram=inbound_port\nset tunnel-detour.datagram.name='Datagram publication'\nset tunnel-detour.datagram.enabled='1'\nset tunnel-detour.datagram.protocol='udp'\nset tunnel-detour.datagram.public_port='18081'\nset tunnel-detour.datagram.destination_address='2001:db8:1::2'\nset tunnel-detour.datagram.destination_port='8080'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["phase"] == "ready")
    })?;
    let probe = lab.inbound_probe("protocol_matrix")?;
    assert!(
        probe.status.success(),
        "publication protocol/source matrix failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let packets = |backend: bool, name: &str| -> TestResult<u64> {
        let mut args = if backend {
            vec!["ip", "netns", "exec", "td-in-lan"]
        } else {
            Vec::new()
        };
        args.extend([
            "nft",
            "-j",
            "list",
            "counter",
            "inet",
            "inbound_source_probe",
            name,
        ]);
        let value: Value = serde_json::from_slice(&lab.exec(&args, None)?)?;
        value["nftables"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find_map(|item| item["counter"]["packets"].as_u64())
            })
            .ok_or_else(|| "missing packet observation".into())
    };
    assert!(
        packets(false, "arrivals")? >= 3,
        "every forged source must actually reach WAN ingress"
    );
    assert!(
        packets(false, "other")? > 0,
        "the attempted connection to the unselected endpoint must reach the router"
    );
    assert!(
        packets(true, "baseline")? >= 2,
        "the real backend and its input observer must receive valid control traffic"
    );
    assert_eq!(
        packets(true, "arrivals")?,
        0,
        "LAN, router-local and ULA source packets must never reach the published backend"
    );
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r062_explicit_dhcpv6_reservation_keeps_the_selected_host_across_renewal_and_inbound_cleanup()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.exec(&["uci", "batch"], Some(b"set network.lan.ip6addr='2001:db8:1::1/64'\ncommit network\nset dhcp.lan=dhcp\nset dhcp.lan.interface='lan'\nset dhcp.lan.dhcpv6='server'\nset dhcp.lan.ra='disabled'\nset dhcp.lan.ndp='disabled'\nset dhcp.lan.dns_service='0'\nset dhcp.reserved_client=host\nset dhcp.reserved_client.name='reserved-client'\nset dhcp.reserved_client.duid='000400112233445566778899aabbccddeeff'\nset dhcp.reserved_client.hostid='2'\nset dhcp.reserved_client.leasetime='10m'\ncommit dhcp\n"))?;
    lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
    wait(
        || match lab.ubus("network.interface.lan", "status", json!({})) {
            Ok(status) => Ok(status["up"] == true
                && status["ipv6-address"].as_array().is_some_and(|addresses| {
                    addresses
                        .iter()
                        .any(|address| address["address"] == "2001:db8:1::1")
                })),
            Err(_) => Ok(false),
        },
    )?;
    lab.exec(&["/etc/init.d/odhcpd", "reload"], None)?;
    let client = lab
        .background_command(&[
            "ip",
            "netns",
            "exec",
            "td-in-lan",
            "odhcp6c",
            "-E",
            "-N",
            "force",
            "-R",
            "-c",
            "000400112233445566778899aabbccddeeff",
            "-t",
            "15",
            "peer0",
        ])?
        .spawn()?;
    let client_index = {
        let mut background = lab.background.borrow_mut();
        let index = background.len();
        background.push(client);
        index
    };
    let mut client_state = Value::Null;
    wait(|| {
        if let Ok(state) = lab.ubus("odhcp6c.peer0", "get_state", json!({})) {
            client_state = state;
            return Ok(client_state["ADDRESSES"].as_array().is_some_and(|values| values.len() == 1 && values[0]["target"] == "2001:db8:1::2"));
        }
        Ok(false)
    }).map_err(|error| format!("DHCPv6 client did not receive its explicit reservation: {error}; state: {client_state}; leases: {}", lab.ubus("dhcp", "ipv6leases", json!({})).unwrap_or_default()))?;
    let reservation = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["phase"] == "ready")
    })?;
    let baseline = lab.inbound_probe("client")?;
    assert!(
        baseline.status.success(),
        "the reserved host was not published: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let before = lab.ubus("odhcp6c.peer0", "get_statistics", json!({}))?;
    let renewals = before["dhcp_renew"]
        .as_u64()
        .ok_or("missing DHCPv6 renewal count")?;
    let replies = before["dhcp_reply"]
        .as_u64()
        .ok_or("missing DHCPv6 reply count")?;
    lab.ubus("odhcp6c.peer0", "renew", json!({}))?;
    wait(|| {
        let current = lab.ubus("odhcp6c.peer0", "get_statistics", json!({}))?;
        Ok(current["dhcp_renew"]
            .as_u64()
            .is_some_and(|value| value > renewals)
            && current["dhcp_reply"]
                .as_u64()
                .is_some_and(|value| value > replies))
    })?;
    let renewed = lab.ubus("odhcp6c.peer0", "get_state", json!({}))?;
    assert_eq!(renewed["ADDRESSES"][0]["target"], "2001:db8:1::2");
    let traffic = lab.inbound_probe("client")?;
    assert!(
        traffic.status.success(),
        "DHCPv6 renewal changed the publication target: {}",
        String::from_utf8_lossy(&traffic.stderr)
    );
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| {
        Ok(!lab
            .raw(
                &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
                None,
            )?
            .status
            .success())
    })?;
    assert_eq!(
        lab.exec(&["uci", "export", "dhcp"], None)?,
        reservation,
        "inbound cleanup must preserve the administrator's explicit reservation"
    );
    // Stop the client while ubus is still available. Destroying its bus first can crash
    // the pinned client's reconnect path, obscuring otherwise successful teardown.
    // The supervised foreground client does not write a pidfile. Require exactly one
    // odhcp6c process inside this disposable container before sending it a signal.
    let pid = String::from_utf8(lab.exec(&["pidof", "odhcp6c"], None)?)?
        .trim()
        .parse::<u32>()?;
    if pid <= 1 {
        return Err("invalid isolated DHCPv6 client PID".into());
    }
    lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
    let mut client_exit = None;
    wait(|| {
        client_exit = lab
            .background
            .borrow_mut()
            .get_mut(client_index)
            .ok_or("missing supervised DHCPv6 client")?
            .try_wait()?;
        Ok(client_exit.is_some())
    })?;
    assert!(
        client_exit.ok_or("missing DHCPv6 exit status")?.success(),
        "DHCPv6 client did not terminate cleanly"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r061_inbound_device_hints_are_lan_scoped_bounded_and_read_only_without_dns() -> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let peer: Value = serde_json::from_slice(&lab.exec(
        &["ip", "-n", "td-in-lan", "-j", "link", "show", "peer0"],
        None,
    )?)?;
    let mac = peer[0]["address"].as_str().ok_or("missing LAN peer MAC")?;
    for (address, device) in [
        ("2001:db8:1::2", "tdlan0"),
        ("192.0.2.2", "tdlan0"),
        ("198.51.100.2", "tdlan0"),
        ("203.0.113.2", "tdwan0"),
        ("2001:db8:ffff::2", "tdlan0"),
        ("fe80::2", "tdlan0"),
        ("2001:db8:2::2", "tdwan0"),
    ] {
        lab.exec(
            &[
                "ip",
                if address.contains(':') { "-6" } else { "-4" },
                "neigh",
                "replace",
                address,
                "lladdr",
                mac,
                "dev",
                device,
                "nud",
                "permanent",
            ],
            None,
        )?;
    }
    let dns = lab.exec(&["uci", "export", "dhcp"], None)?;
    let settings = lab.exec(&["uci", "export", "tunnel-detour"], None)?;
    let firewall = lab.exec(&["uci", "export", "firewall"], None)?;
    let hints = lab.ubus("tunnel-detour", "inbound_devices", json!({"network":"lan"}))?;
    assert_eq!(hints["network"], "lan");
    assert_eq!(hints["stability"], "unverified");
    let mut devices = hints["devices"]
        .as_array()
        .ok_or("missing device hints")?
        .clone();
    devices.sort_by_key(|device| device["address"].as_str().map(str::to_owned));
    assert_eq!(
        devices,
        vec![
            json!({"address":"192.0.2.2","mac":mac}),
            json!({"address":"2001:db8:1::2","mac":mac})
        ]
    );
    let invalid = lab.ubus(
        "tunnel-detour",
        "inbound_devices",
        json!({"network":"../../system"}),
    )?;
    assert_eq!(invalid["devices"], json!([]));
    assert_eq!(invalid["error"], "uci_configuration_failed");
    lab.exec(&["ip", "link", "set", "tdwan0", "down"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "inbound_devices", json!({"network":"lan"}))?,
        hints,
        "LAN hints must not depend on WAN or DNS readiness"
    );
    let mut batch = String::new();
    for index in 0x100..0x22c {
        batch.push_str(&format!(
            "neigh replace 2001:db8:1::{index:x} lladdr {mac} dev tdlan0 nud permanent\n"
        ));
    }
    lab.exec(&["ip", "-6", "-batch", "-"], Some(batch.as_bytes()))?;
    let bounded = lab.ubus("tunnel-detour", "inbound_devices", json!({"network":"lan"}))?;
    assert_eq!(
        bounded["devices"]
            .as_array()
            .ok_or("missing bounded hints")?
            .len(),
        256
    );
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns);
    assert_eq!(lab.exec(&["uci", "export", "firewall"], None)?, firewall);
    assert_eq!(
        lab.exec(&["uci", "export", "tunnel-detour"], None)?,
        settings
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r060_lost_lan_authorization_fences_existing_flows_and_recovery_never_revives_their_generations()
-> TestResult {
    for (relay, read_only_state) in [(false, false), (false, true), (true, false), (true, true)] {
        let lab = Lab::create(true)?;
        lab.inbound_endpoints()?;
        lab.prepare_inbound_uci()?;
        if relay {
            lab.spawn_inbound_probe("relay_server")?;
            wait(|| {
                Ok(lab
                    .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
                    .status
                    .success())
            })?;
            lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'")?;
        }
        lab.change("set tunnel-detour.inbound.enabled='1'")?;
        wait(|| {
            Ok(
                lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["phase"]
                    == "ready",
            )
        })?;
        let state = || -> TestResult<Value> {
            Ok(serde_json::from_slice(&lab.exec(
                &["cat", "/etc/tunnel-detour/inbound/state.json"],
                None,
            )?)?)
        };
        let generation = state()?["admissions"]["sample"].clone();
        lab.spawn_inbound_probe(if relay {
            "relay_context_holding"
        } else {
            "context_holding"
        })?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "context-ready")?
                .status
                .success())
        })?;
        let directory = "/etc/tunnel-detour/inbound";
        if read_only_state {
            lab.exec(&["mount", "-o", "bind", directory, directory], None)?;
            lab.exec(
                &["mount", "-o", "remount,bind,ro", directory, directory],
                None,
            )?;
            assert!(
                !lab.raw(&["touch", "/etc/tunnel-detour/inbound/denied-probe"], None)?
                    .status
                    .success(),
                "the scenario must actually prevent state writes"
            );
        }
        let family = if relay { "-4" } else { "-6" };
        let authorized = if relay {
            "192.0.2.1/24"
        } else {
            "2001:db8:1::1/64"
        };
        let replacement = if relay {
            "192.0.3.1/24"
        } else {
            "2001:db8:5::1/64"
        };
        lab.exec(
            &["ip", family, "addr", "del", authorized, "dev", "tdlan0"],
            None,
        )?;
        lab.exec(
            &["ip", family, "addr", "add", replacement, "dev", "tdlan0"],
            None,
        )?;
        lab.ubus(
            "service",
            "event",
            json!({"type":"interface.update","data":{"interface":"lan"}}),
        )?;
        wait(|| {
            let guard = lab.raw(
                &[
                    "nft",
                    "list",
                    "chain",
                    "inet",
                    "tunnel_detour_inbound",
                    "tag",
                ],
                None,
            )?;
            Ok(guard.status.success()
                && !String::from_utf8_lossy(&guard.stdout).contains("ct mark set"))
        })?;
        lab.exec(&["touch", "/tmp/inbound-test/check-context"], None)?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "context-closed")?
                .status
                .success())
        })?;
        assert_eq!(
            state()?["pending"].is_null(),
            read_only_state,
            "a writable journal must record retirement; a read-only journal must remain unchanged"
        );
        if read_only_state {
            lab.exec(
                &["mount", "-o", "remount,bind,rw", directory, directory],
                None,
            )?;
            lab.exec(&["umount", directory], None)?;
        }
        lab.exec(
            &["ip", family, "addr", "del", replacement, "dev", "tdlan0"],
            None,
        )?;
        lab.exec(
            &["ip", family, "addr", "add", authorized, "dev", "tdlan0"],
            None,
        )?;
        lab.ubus(
            "service",
            "event",
            json!({"type":"interface.update","data":{"interface":"lan"}}),
        )?;
        wait(|| {
            Ok(
                lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["phase"]
                    == "ready",
            )
        })?;
        assert_ne!(state()?["admissions"]["sample"], generation);
        let fresh = lab.inbound_probe(if relay { "relay_client" } else { "client" })?;
        assert!(
            fresh.status.success(),
            "restored LAN authorization must admit fresh publication traffic: {}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        lab.exec(&["touch", "/tmp/inbound-test/check-context-restored"], None)?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "context-complete")?
                .status
                .success())
        })?;
        lab.change("set tunnel-detour.inbound.enabled='0'")?;
        wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r059_inbound_restores_publications_after_firewall_reload_public_ipv6_change_and_procd_respawn()
-> TestResult {
    for relay in [false, true] {
        inbound_recovery(relay)?;
    }
    Ok(())
}

fn inbound_recovery(relay: bool) -> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.prepare_inbound_uci()?;
    if relay {
        lab.spawn_inbound_probe("relay_server")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
                .status
                .success())
        })?;
        lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'")?;
    }
    let client = if relay { "relay_client" } else { "client" };
    let updated = if relay {
        "updated_relay_client"
    } else {
        "updated_address_client"
    };
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    let ready = || -> TestResult<Value> {
        let mut status = Value::Null;
        wait(|| {
            status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(status["running"] == true && status["status"]["phase"] == "ready")
        })?;
        Ok(status)
    };
    let initial = ready()?;
    lab.exec(&["fw4", "reload"], None)?;
    let reloaded = lab.inbound_probe(client)?;
    assert!(
        reloaded.status.success(),
        "native firewall reload lost publication traffic: {}",
        String::from_utf8_lossy(&reloaded.stderr)
    );
    assert_eq!(
        ready()?["status"]["process_id"],
        initial["status"]["process_id"]
    );
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "del",
            "2001:db8:2::1/64",
            "dev",
            "tdwan0",
        ],
        None,
    )?;
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:2::10/64",
            "dev",
            "tdwan0",
            "nodad",
        ],
        None,
    )?;
    lab.ubus(
        "service",
        "event",
        json!({"type":"interface.update","data":{"interface":"wan"}}),
    )?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(
            status["status"]["public_addresses"] == json!(["2001:db8:2::10"])
                && status["status"]["last_error"].is_null(),
        )
    })?;
    let address_changed = lab.inbound_probe(updated)?;
    assert!(
        address_changed.status.success(),
        "the new public IPv6 was not reconciled: {}",
        String::from_utf8_lossy(&address_changed.stderr)
    );
    let sections = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    assert_eq!(
        sections["values"]["td_in_sample_0"]["src_dip"],
        "2001:db8:2::10"
    );
    let retired = lab.inbound_probe(client)?;
    assert!(
        !retired.status.success(),
        "the retired public IPv6 remained published"
    );
    let previous_pid = ready()?["status"]["process_id"]
        .as_u64()
        .ok_or("missing inbound PID")?;
    if relay {
        lab.spawn_inbound_probe("relay_crash_holding")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "relay-crash-ready")?
                .status
                .success())
        })?;
    }
    let roots_before = lab.exec(
        &[
            "find",
            "/var/run",
            "-maxdepth",
            "1",
            "-type",
            "d",
            "-name",
            "tunnel-detour-transport-*",
        ],
        None,
    )?;
    lab.exec(&["kill", "-KILL", &previous_pid.to_string()], None)?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["running"] == true
            && status["status"]["phase"] == "ready"
            && status["status"]["process_id"]
                .as_u64()
                .is_some_and(|pid| pid != previous_pid))
    })?;
    assert_eq!(
        lab.exec(
            &[
                "find",
                "/var/run",
                "-maxdepth",
                "1",
                "-type",
                "d",
                "-name",
                "tunnel-detour-transport-*"
            ],
            None
        )?,
        roots_before,
        "hard-crash recovery leaked a per-controller transport root"
    );
    if relay {
        lab.inbound_marker("td-in-wan", "touch", "check-relay-crash")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "relay-crash-closed")?
                .status
                .success())
        })?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "cat", "relay-server-active")?
                .stdout
                == b"0")
        })?;
    }
    let recovered = lab.inbound_probe(updated)?;
    assert!(
        recovered.status.success(),
        "procd respawn did not restore traffic: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["running"],
        false
    );
    assert!(lab.ubus("system", "board", json!({}))?["kernel"].is_string());
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    Ok(())
}

fn restrict_wan_dispatch(lab: &Lab, predicate: &str) -> TestResult {
    let dstnat: Value = serde_json::from_slice(&lab.exec(
        &[
            "nft", "-j", "-s", "-a", "list", "chain", "inet", "fw4", "dstnat",
        ],
        None,
    )?)?;
    let wan_dispatch: Vec<_> = dstnat["nftables"]
        .as_array()
        .ok_or("missing native dstnat base chain")?
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| {
            rule["expr"].as_array().is_some_and(|expr| {
                expr.last()
                    .is_some_and(|verdict| verdict["jump"]["target"] == "dstnat_wan")
            })
        })
        .filter_map(|rule| rule["handle"].as_u64())
        .collect();
    let [handle] = wan_dispatch.as_slice() else {
        return Err("expected exactly one native WAN NAT dispatch".into());
    };
    let restriction = format!(
        "replace rule inet fw4 dstnat handle {handle} iifname \"tdwan0\" {predicate} jump dstnat_wan comment \"lab WAN dispatch policy\"\n"
    );
    lab.exec(&["nft", "-f", "-"], Some(restriction.as_bytes()))?;
    Ok(())
}

fn shadow_wan_tcp(lab: &Lab, chain: &str, port: u16) -> TestResult {
    let restriction = format!(
        "insert rule inet fw4 {chain} iifname \"tdwan0\" ip6 saddr 2001:db8:3::2 ip6 daddr 2001:db8:2::1 tcp dport {port} return comment \"lab WAN TCP policy\"\n"
    );
    lab.exec(&["nft", "-f", "-"], Some(restriction.as_bytes()))?;
    Ok(())
}

fn enable_software_flow_offload(lab: &Lab) -> TestResult {
    lab.exec(&["uci", "batch"], Some(b"set firewall.@defaults[0].flow_offloading='1'\nset firewall.@defaults[0].flow_offloading_hw='0'\ncommit firewall\n"))?;
    lab.exec(&["fw4", "reload"], None)?;
    lab.exec(&["nft", "list", "flowtable", "inet", "fw4", "ft"], None)?;
    Ok(())
}

fn large_foreign_set(lab: &Lab) -> TestResult<String> {
    use std::fmt::Write as _;

    lab.exec(
        &["nft", "-f", "-"],
        Some(b"add set inet fw4 lab_large_foreign { type ipv6_addr; }\n"),
    )?;
    let comment = "fixture".repeat(16);
    for start in (0..36_000).step_by(1000) {
        let mut batch = String::from("add element inet fw4 lab_large_foreign { ");
        for item in start..start + 1000 {
            if item != start {
                batch.push_str(", ");
            }
            write!(batch, "2001:db8:ff::{item:x} comment \"{comment}\"")?;
        }
        batch.push_str(" }\n");
        lab.exec(&["nft", "-f", "-"], Some(batch.as_bytes()))?;
    }
    let size = String::from_utf8(lab.exec(
        &[
            "sh",
            "-c",
            "set -o pipefail; nft -j -s -a list table inet fw4 | wc -c",
        ],
        None,
    )?)?;
    assert!(
        size.trim().parse::<usize>()? > 4 * 1024 * 1024,
        "the real fw4 listing must exceed the old capture limit"
    );
    foreign_set_fingerprint(lab)
}

fn foreign_set_fingerprint(lab: &Lab) -> TestResult<String> {
    let digest = lab.exec(
        &[
            "sh",
            "-c",
            "set -o pipefail; nft -j -s -a list set inet fw4 lab_large_foreign | sha256sum",
        ],
        None,
    )?;
    Ok(String::from_utf8(digest)?)
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r057_inbound_recovers_partial_native_firewall_commits_without_reusing_retired_generations_or_changing_foreign_rules()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let accelerated = lab.vm.is_some();
    if accelerated {
        enable_software_flow_offload(&lab)?;
    }
    let flowtable = || {
        lab.exec(
            &["nft", "-s", "list", "flowtable", "inet", "fw4", "ft"],
            None,
        )
    };
    let initial_flowtable = accelerated.then(flowtable).transpose()?;
    lab.exec(&["uci", "batch"], Some(b"set firewall.preserved=rule\nset firewall.preserved.name='Administrator rule'\nset firewall.preserved.src='wan'\nset firewall.preserved.proto='tcp'\nset firewall.preserved.dest_port='3022'\nset firewall.preserved.target='ACCEPT'\ncommit firewall\n"))?;
    lab.exec(
        &["nft", "--file", "-"],
        Some(b"table inet preserved_by_admin { comment \"foreign fixture\"; }\n"),
    )?;
    let foreign =
        lab.ubus("uci", "get", json!({"config":"firewall"}))?["values"]["preserved"].clone();
    let foreign_nft = lab.exec(
        &[
            "nft",
            "-j",
            "-a",
            "list",
            "table",
            "inet",
            "preserved_by_admin",
        ],
        None,
    )?;
    let dns = lab.exec(&["uci", "export", "dhcp"], None)?;
    let mut config = lab.inbound_configuration();
    lab.start_inbound(&config)?;
    assert!(lab.inbound_probe("client")?.status.success());
    let active: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?)?;
    lab.exec(
        &[
            "kill",
            "-KILL",
            &active["process_id"]
                .as_u64()
                .ok_or("missing PID")?
                .to_string(),
        ],
        None,
    )?;
    let mut crashed = lab
        .background
        .borrow_mut()
        .pop()
        .ok_or("missing actor owner")?;
    assert!(
        !crashed.wait()?.success(),
        "the recovery fixture must exercise a hard crash"
    );
    let journal = lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?;
    let fw4_policy = || -> TestResult<Value> {
        let mut value: Value = serde_json::from_slice(&lab.exec(
            &["nft", "-j", "-s", "-a", "list", "table", "inet", "fw4"],
            None,
        )?)?;
        let objects = value["nftables"]
            .as_array_mut()
            .ok_or("missing fw4 objects")?;
        // Cache replacement may change the flowtable and offload rule handles.
        // Every other object, including the live NAT rule, must keep its handle.
        objects.retain(|object| {
            object["flowtable"]["name"] != "ft"
                && !object["rule"]["expr"].as_array().is_some_and(|expr| {
                    expr.iter().any(|entry| entry["flow"]["flowtable"] == "@ft")
                })
        });
        Ok(value)
    };
    let verify_flowtable = || -> TestResult {
        if let Some(expected) = &initial_flowtable {
            assert_eq!(&flowtable()?, expected);
        }
        Ok(())
    };
    for chain in [None, Some("dstnat"), Some("dstnat_wan")] {
        let probe = if let Some(chain) = chain {
            shadow_wan_tcp(&lab, chain, 18080)?;
            "native_tcp_redirect_missing"
        } else {
            restrict_wan_dispatch(&lab, "meta nfproto ipv4")?;
            "native_wan_dispatch_restricted"
        };
        assert!(lab.inbound_probe(probe)?.status.success());
        let restricted = fw4_policy()?;
        let saved_firewall = lab.exec(&["uci", "export", "firewall"], None)?;
        for _ in 0..2 {
            let restarted = lab.raw_with_deadline(
                &[
                    "/usr/bin/tunnel-detour",
                    "--inbound-config",
                    "/tmp/inbound-config.json",
                ],
                None,
                "8",
            )?;
            assert_eq!(restarted.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&restarted.stderr).contains("kernel_conflict"));
            assert_eq!(fw4_policy()?, restricted);
            assert_eq!(
                lab.exec(&["uci", "export", "firewall"], None)?,
                saved_firewall
            );
            assert_eq!(
                lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?,
                journal
            );
            assert!(lab.inbound_probe(probe)?.status.success());
        }
        lab.exec(&["fw4", "reload"], None)?;
    }
    let mut state: Value = serde_json::from_slice(&journal)?;
    assert_eq!(state["admissions"], json!({"sample":1}));
    config["rules"][0]["public_port"] = json!(18082);
    let mut extra = config["rules"][0].clone();
    extra["id"] = json!("extra");
    extra["name"] = json!("Additional publication");
    extra["protocol"] = json!("tcp");
    extra["public_port"] = json!(18083);
    config["rules"]
        .as_array_mut()
        .ok_or("missing candidate rules")?
        .push(extra);
    let mut control = state["control"].clone();
    control["rules"] = config["rules"].clone();
    let mut sample = state["owned"]["td_in_sample_0"].clone();
    sample["src_dport"] = json!("18082");
    sample["mark"] = json!("1413742594/0xffffffff");
    let mut extra = sample.clone();
    extra["name"] = json!("Tunnel Detour: Additional publication");
    extra["src_dport"] = json!("18083");
    extra["mark"] = json!("1413742595/0xffffffff");
    extra["proto"] = json!("tcp");
    state["next_generation"] = json!(4);
    state["pending"] = json!({"control":control,"admissions":{"sample":2,"extra":3},"owned":{"td_in_sample_0":sample,"td_in_extra_0":extra}});
    lab.exec(
        &["tee", "/tmp/inbound-test/state.json"],
        Some(&serde_json::to_vec(&state)?),
    )?;
    // Emulate a durable intent followed by withdrawal and a partial libuci commit:
    // the old redirect is already deleted and only the newly added redirect exists.
    lab.exec(&["nft", "--file", "-"], Some(b"flush chain inet tunnel_detour_inbound authorized\nadd rule inet tunnel_detour_inbound authorized drop\n"))?;
    lab.exec(&["uci", "batch"], Some(b"delete firewall.td_in_sample_0\nset firewall.td_in_extra_0=redirect\nset firewall.td_in_extra_0.name='Tunnel Detour: Additional publication'\nset firewall.td_in_extra_0.enabled='1'\nset firewall.td_in_extra_0.family='ipv6'\nset firewall.td_in_extra_0.src='wan'\nset firewall.td_in_extra_0.dest='lan'\nset firewall.td_in_extra_0.src_dip='2001:db8:2::1'\nset firewall.td_in_extra_0.src_dport='18083'\nset firewall.td_in_extra_0.dest_ip='2001:db8:1::2'\nset firewall.td_in_extra_0.dest_port='8080'\nset firewall.td_in_extra_0.proto='tcp'\nset firewall.td_in_extra_0.target='DNAT'\nset firewall.td_in_extra_0.reflection='0'\nset firewall.td_in_extra_0.mark='1413742595/0xffffffff'\ncommit firewall\n"))?;
    lab.exec(&["fw4", "reload"], None)?;
    lab.exec(
        &["tee", "/tmp/inbound-config.json"],
        Some(&serde_json::to_vec(&config)?),
    )?;
    // A known partial commit must not authorize removing a live administrator
    // rule. Retry after the laboratory administrator withdraws the restriction.
    shadow_wan_tcp(&lab, "dstnat", 18083)?;
    let restricted = fw4_policy()?;
    let partial_uci = lab.exec(&["uci", "export", "firewall"], None)?;
    let partial_journal: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?)?;
    for _ in 0..2 {
        let blocked = lab.raw_with_deadline(
            &[
                "/usr/bin/tunnel-detour",
                "--inbound-config",
                "/tmp/inbound-config.json",
            ],
            None,
            "8",
        )?;
        assert_eq!(blocked.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&blocked.stderr).contains("kernel_conflict"));
        assert_eq!(fw4_policy()?, restricted);
        assert_eq!(lab.exec(&["uci", "export", "firewall"], None)?, partial_uci);
        assert_eq!(
            serde_json::from_slice::<Value>(
                &lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?
            )?,
            partial_journal
        );
        verify_flowtable()?;
        assert!(
            lab.inbound_probe("native_candidate_closed")?
                .status
                .success()
        );
    }
    lab.exec(&["fw4", "reload"], None)?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"insert rule inet fw4 forward iifname \"tdwan0\" meta nfproto ipv6 meta l4proto tcp ct original proto-dst 18083 reject with tcp reset comment \"lab recovered forward restriction\"\n"),
    )?;
    let forward_policy = || -> TestResult<(usize, Value)> {
        let listing: Value = serde_json::from_slice(&lab.exec(
            &[
                "nft", "-j", "-s", "-a", "list", "chain", "inet", "fw4", "forward",
            ],
            None,
        )?)?;
        listing["nftables"]
            .as_array()
            .and_then(|items| {
                items.iter().enumerate().find_map(|(index, item)| {
                    let rule = &item["rule"];
                    (rule["comment"] == "lab recovered forward restriction")
                        .then(|| (index, rule.clone()))
                })
            })
            .ok_or_else(|| "missing recovery forward restriction".into())
    };
    let forward_before = forward_policy()?;
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );
    lab.start_inbound(&config)?;
    let recovered: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?)?;
    assert!(recovered["pending"].is_null());
    let sample = recovered["admissions"]["sample"]
        .as_u64()
        .ok_or("missing sample generation")?;
    let extra = recovered["admissions"]["extra"]
        .as_u64()
        .ok_or("missing extra generation")?;
    assert!(
        sample > 3 && extra > 3 && sample != extra,
        "interrupted generations must never be reused"
    );
    assert_eq!(forward_policy()?, forward_before);
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );
    let handle = forward_before.1["handle"]
        .as_u64()
        .ok_or("missing forward restriction handle")?;
    lab.exec(
        &[
            "nft",
            "delete",
            "rule",
            "inet",
            "fw4",
            "forward",
            "handle",
            &handle.to_string(),
        ],
        None,
    )?;
    let traffic = lab.inbound_probe("updated_client")?;
    assert!(
        traffic.status.success(),
        "recovered traffic failed: {}",
        String::from_utf8_lossy(&traffic.stderr)
    );
    assert_eq!(
        lab.ubus("uci", "get", json!({"config":"firewall"}))?["values"]["preserved"],
        foreign
    );
    assert_eq!(
        lab.exec(
            &[
                "nft",
                "-j",
                "-a",
                "list",
                "table",
                "inet",
                "preserved_by_admin"
            ],
            None
        )?,
        foreign_nft
    );
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns);
    shadow_wan_tcp(&lab, "dstnat", 18083)?;
    let restricted = fw4_policy()?;
    let saved_uci = lab.exec(&["uci", "export", "firewall"], None)?;
    let ready: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?)?;
    let pid = ready["process_id"].as_u64().ok_or("missing inbound PID")?;
    lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
    let mut stopped = lab
        .background
        .borrow_mut()
        .pop()
        .ok_or("missing inbound controller")?;
    wait(|| Ok(stopped.try_wait()?.is_some()))?;
    let stopped = stopped.wait_with_output()?;
    assert_eq!(stopped.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&stopped.stderr).contains("kernel_conflict"));
    assert_eq!(fw4_policy()?, restricted);
    assert_eq!(lab.exec(&["uci", "export", "firewall"], None)?, saved_uci);
    verify_flowtable()?;
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );

    lab.exec(&["fw4", "reload"], None)?;
    lab.start_inbound(&config)?;
    verify_concurrent_nat_edit(&lab)?;
    lab.exec(&["fw4", "reload"], None)?;
    lab.start_inbound(&config)?;
    verify_named_dnat_counter_preserved(&lab)?;
    lab.exec(&["fw4", "reload"], None)?;
    lab.start_inbound(&config)?;
    assert!(lab.inbound_probe("updated_client")?.status.success());
    let counted = r057_redirect(&lab, false)?;
    assert!(
        counted["expr"]
            .as_array()
            .is_some_and(|expr| expr.iter().any(|entry| {
                entry["counter"]["packets"]
                    .as_u64()
                    .is_some_and(|packets| packets > 0)
                    && entry["counter"]["bytes"]
                        .as_u64()
                        .is_some_and(|bytes| bytes > 0)
            })),
        "the canonical redirect must count actual traffic before withdrawal"
    );
    lab.stop_inbound()?;
    assert!(
        !lab.raw(&["uci", "get", "firewall.td_in_extra_0"], None)?
            .status
            .success()
    );
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );
    Ok(())
}

fn r057_redirect(lab: &Lab, stateless: bool) -> TestResult<Value> {
    let mut options = vec!["nft", "-j", "-a"];
    if stateless {
        options.push("-s");
    }
    options.extend(["list", "chain", "inet", "fw4", "dstnat_wan"]);
    let listing: Value = serde_json::from_slice(&lab.exec(&options, None)?)?;
    listing["nftables"]
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|entry| {
                let rule = &entry["rule"];
                (rule["comment"] == "!fw4: Tunnel Detour: Additional publication")
                    .then(|| rule.clone())
            })
        })
        .ok_or_else(|| "missing owned rule selected for the redirect test".into())
}

fn stop_json_controller(lab: &Lab) -> TestResult<Output> {
    let ready: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?)?;
    let pid = ready["process_id"].as_u64().ok_or("missing ready PID")?;
    lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
    let mut controller = lab
        .background
        .borrow_mut()
        .pop()
        .ok_or("missing controller")?;
    wait(|| Ok(controller.try_wait()?.is_some()))?;
    Ok(controller.wait_with_output()?)
}

fn verify_concurrent_nat_edit(lab: &Lab) -> TestResult {
    let original = r057_redirect(lab, true)?;
    let mut replacement = original.clone();
    replacement["expr"]
        .as_array_mut()
        .ok_or("missing DNAT expression")?
        .insert(
            0,
            json!({
                "match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},
                "right":"2001:db8:2::2"}
            }),
        );
    lab.exec(
        &["tee", "/tmp/r057-edit.json"],
        Some(&serde_json::to_vec(
            &json!({"nftables":[{"replace":{"rule":replacement}}]}),
        )?),
    )?;
    let stopped = lab.with_command_fault(
        "uci",
        "r057-commit",
        r#"if [ "$1" = '-t' ] && [ "$3" = commit ] && [ "$4" = firewall ]; then
  "$REAL" "$@" || exit
  nft -j -f /tmp/r057-edit.json || exit
  touch /tmp/r057-concurrent-edit
  exit
fi"#,
        || stop_json_controller(lab),
    )?;
    lab.exec(&["test", "-e", "/tmp/r057-concurrent-edit"], None)?;
    assert_owned_rule_conflict(stopped);
    let actual = r057_redirect(lab, true)?;
    assert_eq!(actual["handle"], original["handle"]);
    assert_eq!(actual["expr"], replacement["expr"]);
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );
    Ok(())
}

fn assert_owned_rule_conflict(stopped: Output) {
    assert_eq!(stopped.status.code(), Some(1));
    let diagnostic = String::from_utf8_lossy(&stopped.stderr);
    assert!(
        diagnostic.contains("kernel_conflict") && diagnostic.contains("nat_stage=owned_rule"),
        "{diagnostic}"
    );
}

fn verify_named_dnat_counter_preserved(lab: &Lab) -> TestResult {
    let original = r057_redirect(lab, true)?;
    let mut replacement = original.clone();
    let expressions = replacement["expr"]
        .as_array_mut()
        .ok_or("missing DNAT expression")?;
    let action = expressions
        .iter()
        .position(|entry| entry.get("dnat").is_some())
        .ok_or("missing DNAT action")?;
    expressions.insert(action, json!({"counter":"r057_admin"}));
    let batch = json!({"nftables":[
        {"add":{"counter":{"family":"inet","table":"fw4","name":"r057_admin"}}},
        {"replace":{"rule":replacement}}
    ]});
    lab.exec(
        &["nft", "-j", "-f", "-"],
        Some(&serde_json::to_vec(&batch)?),
    )?;
    assert!(lab.inbound_probe("updated_client")?.status.success());
    let counters = || -> TestResult<Value> {
        Ok(serde_json::from_slice(&lab.exec(
            &[
                "nft",
                "-j",
                "-a",
                "list",
                "counter",
                "inet",
                "fw4",
                "r057_admin",
            ],
            None,
        )?)?)
    };
    let observed = counters()?;
    assert!(
        observed["nftables"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["counter"]["packets"]
                    .as_u64()
                    .is_some_and(|packets| packets > 0)
            })),
        "the preserved rule must have fed the administrator's counter"
    );
    assert_owned_rule_conflict(stop_json_controller(lab)?);
    let actual = r057_redirect(lab, true)?;
    assert_eq!(actual["handle"], original["handle"]);
    assert_eq!(actual["expr"], replacement["expr"]);
    assert!(
        lab.inbound_probe("native_candidate_closed")?
            .status
            .success()
    );
    assert_eq!(
        counters()?,
        observed,
        "the fenced publication cannot feed the administrator's counter"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r098_native_container_masks_the_host_kernel_log_while_its_own_syslog_remains_available()
-> TestResult {
    if env::var("TUNNEL_DETOUR_KERNEL_LOG_PROBE").as_deref() == Ok("1") {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = std::fs::metadata("/proc/kmsg")?;
        if !metadata.file_type().is_char_device() || metadata.rdev() != 0x103 {
            return Err("refusing to read an unmasked kernel-log stream".into());
        }
        assert_eq!(
            File::open("/proc/kmsg")?.read(&mut [0_u8; 1])?,
            0,
            "the native fixture exposed kernel bytes instead of the null device"
        );
        return Ok(());
    }
    let lab = Lab::create(true)?;
    if lab.vm.is_some() {
        return Err("this isolation owner targets Docker's shared host kernel".into());
    }
    lab.exec(&["env", "TUNNEL_DETOUR_KERNEL_LOG_PROBE=1", "/usr/libexec/tunnel-detour-test-fixture", "--ignored", "--exact", "r098_native_container_masks_the_host_kernel_log_while_its_own_syslog_remains_available", "--nocapture"], None)?;
    wait(|| {
        let result = lab.raw(&["ubus", "list", "log"], None)?;
        Ok(result.status.success() && result.stdout == b"log\n")
    })
    .map_err(|error| {
        let diagnostics = lab.ubus("service", "list", json!({"name":"log"}));
        let startup = output("docker", &["logs", &lab.name], None);
        format!(
            "container syslog readiness: {error}; service: {diagnostics:?}; startup: {}",
            startup
                .map(|result| format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                ))
                .unwrap_or_else(|error| error.to_string())
        )
    })?;
    let marker = "synthetic-container-log-isolation-check";
    lab.exec(&["logger", "-t", "tunnel-detour-lab", marker], None)?;
    wait(|| Ok(String::from_utf8(lab.exec(&["logread", "-e", marker], None)?)?.contains(marker)))?;
    assert!(lab.ubus("system", "board", json!({}))?["kernel"].is_string());
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r116_native_ipv6_opt_in_restarts_for_family_changes_preserves_cached_ipv4_and_cleans_offline_without_network_adoption()
-> TestResult {
    for adguard in [false, true] {
        let lab = Lab::create(!adguard)?;
        lab.inbound_endpoints()?;
        lab.exec(&["uci", "batch"], Some(b"set network.lan.ip6addr='2001:db8:1::1/64'\nset network.wan6=interface\nset network.wan6.proto='static'\nset network.wan6.device='tdwan0'\nset network.wan6.ip6addr='2001:db8:2::1/64'\nset network.wan6.ip6gw='2001:db8:2::2'\ncommit network\n"))?;
        lab.exec(&["uci", "batch"], Some(b"set network.auxiliary=route6\nset network.auxiliary.interface='wan6'\nset network.auxiliary.target='::/0'\nset network.auxiliary.gateway='::'\nset network.auxiliary.table='50001'\ncommit network\n"))?;
        lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
        wait(|| Ok(lab.ubus("network.interface.wan6", "status", json!({}))?["up"] == true))?;
        let wan_status = lab.ubus("network.interface.wan6", "status", json!({}))?;
        assert!(
            wan_status["route"]
                .as_array()
                .ok_or("missing WAN routes")?
                .iter()
                .any(|route| route["table"] == 50001),
            "the auxiliary netifd default is missing from the regression scenario"
        );
        lab.exec(
            &["tee", "-a", "/etc/tunnel-detour-lab-unbound.conf"],
            Some(b"    local-data: \"ipv6-only.example.net. 0 IN AAAA 2001:db8:3::2\"\n"),
        )?;
        lab.exec(&["/etc/init.d/tunnel-detour-lab", "restart"], None)?;
        wait(|| {
            Ok(lab
                .raw(
                    &[
                        "nslookup",
                        "-retry=1",
                        "-timeout=1",
                        "-port=15353",
                        "-type=AAAA",
                        "ipv6-only.example.net",
                        "127.0.0.1",
                    ],
                    None,
                )?
                .status
                .success())
        })?;
        let mut network_before = lab.exec(&["uci", "export", "network"], None)?;
        let dhcp_before = lab.exec(&["uci", "export", "dhcp"], None)?;
        if adguard {
            lab.configure()?;
            lab.change("set tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
        } else {
            lab.configure_dnsmasq()?;
        }
        let first = lab.ready(None)?;
        assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
        for role in ["dns_server", "dns_server6"] {
            lab.spawn_inbound_probe(role)?;
        }
        for marker in ["dns-endpoint-ready", "dns6-endpoint-ready"] {
            wait(|| {
                Ok(lab
                    .inbound_marker("td-in-wan", "test", marker)?
                    .status
                    .success())
            })?;
        }
        let enable = if adguard { "1" } else { "on" };
        lab.change(&format!("set tunnel-detour.globals.enabled='{enable}'\nset tunnel-detour.globals.ipv6_enabled='1'\nset tunnel-detour.globals.wan6_network='wan6'\nset tunnel-detour.ipv6only=exception\nset tunnel-detour.ipv6only.pattern='ipv6-only.example.net'\nset tunnel-detour.ipv6only.enabled='1'"))?;
        let dual = lab.ready(Some(first))?;
        let status = lab.ubus("tunnel-detour", "status", json!({}))?;
        assert_eq!(status["status"]["ipv6_wan_source"], "2001:db8:2::1");
        assert_eq!(status["status"]["ipv6_wan_device"], "tdwan0");
        if adguard && let Some(path) = env::var_os("TUNNEL_DETOUR_LUCI_IPV6_REVIEW") {
            use std::os::unix::fs::OpenOptionsExt;
            let path = std::path::PathBuf::from(path);
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&serde_json::to_vec(
                &json!({"url":lab.http,"container":lab.name}),
            )?)?;
            wait_for(Duration::from_secs(600), || {
                Ok(path.with_extension("continue").exists())
            })?;
        }
        assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
        let answer = lab.exec(
            &[
                "nslookup",
                "-retry=1",
                "-timeout=2",
                "-type=AAAA",
                "ipv6-only.example.net",
                "127.0.0.1",
            ],
            None,
        )?;
        assert!(String::from_utf8(answer)?.contains("2001:2::c612:2"));
        for role in ["dns_once", "dns_once6"] {
            let reply = lab.inbound_probe(role)?;
            assert!(
                reply.status.success(),
                "{role}: {} {}",
                String::from_utf8_lossy(&reply.stdout),
                String::from_utf8_lossy(&reply.stderr)
            );
        }
        assert_eq!(
            lab.exec(&["uci", "export", "network"], None)?,
            network_before
        );
        lab.exec(
            &[
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "addr",
                "add",
                "fe80::2/64",
                "dev",
                "peer0",
                "nodad",
            ],
            None,
        )?;
        lab.exec(
            &["uci", "batch"],
            Some(b"set network.wan6.ip6gw='fe80::2'\ncommit network\n"),
        )?;
        network_before = lab.exec(&["uci", "export", "network"], None)?;
        lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
        let link_local = lab.ready(Some(dual)).map_err(|error| {
            let read = |args: &[&str]| lab.exec(args, None).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            format!(
                "link-local readiness: {error}; wan6={:?}; routes6={:?}; rules6={:?}; journal={:?}; routes4={:?}; service={:?}",
                lab.ubus("network.interface.wan6", "status", json!({})),
                read(&["ip", "-j", "-N", "-6", "route", "show", "table", "41872"]),
                read(&["ip", "-j", "-N", "-6", "rule", "show", "pref", "11000"]),
                read(&["cat", "/etc/tunnel-detour/leases.json.ipv6-routing.json"]),
                read(&["ip", "-j", "-N", "-4", "route", "show", "table", "41872"]),
                lab.ubus("service", "list", json!({"name":"tunnel-detour"}))
            )
        })?;
        let reply = lab.inbound_probe("dns_once6")?;
        assert!(
            reply.status.success(),
            "WAN6 interface events or scoped gateway failed: {} {}",
            String::from_utf8_lossy(&reply.stdout),
            String::from_utf8_lossy(&reply.stderr)
        );
        lab.change("set tunnel-detour.globals.ipv6_enabled='0'")?;
        let compatibility = lab.ready(Some(link_local))?;
        assert!(
            lab.inbound_probe("dns_rejected6")?.status.success(),
            "disabled IPv6 leaked a cached identity"
        );
        assert!(lab.inbound_probe("dns_once")?.status.success());
        lab.change("set tunnel-detour.globals.ipv6_enabled='1'")?;
        lab.ready(Some(compatibility))?;
        assert!(lab.inbound_probe("dns_once6")?.status.success());
        lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
        wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
        lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.globals.wan6_network='unavailable'\nset tunnel-detour.selected.pattern='invalid * pattern'\ncommit tunnel-detour\n"))?;
        lab.exec(&["ifdown", "wan6"], None)?;
        lab.exec(&["/usr/bin/tunnel-detour", "--uninstall"], None)?;
        for path in [
            "/etc/tunnel-detour/leases.json.ipv6-routing.json",
            "/etc/tunnel-detour/leases.json.ipv6-routing.json.lock",
            "/etc/nftables.d/tunnel-detour-cache-guard.nft",
        ] {
            assert!(
                !lab.raw(&["test", "-e", path], None)?.status.success(),
                "uninstall retained {path}"
            );
        }
        let rules: Value = serde_json::from_slice(
            &lab.exec(&["ip", "-j", "-6", "rule", "show", "pref", "11000"], None)?,
        )?;
        assert_eq!(rules, json!([]));
        assert_eq!(
            lab.exec(&["uci", "export", "network"], None)?,
            network_before
        );
        assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dhcp_before);
        assert!(lab.lookup("ordinary.example.net")?.contains("203.0.113.2"));
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r095_native_resolver_reload_preserves_established_tcp_and_requires_explicit_recovery_from_adguard_conflicts()
-> TestResult {
    for adguard in [false, true] {
        let lab = Lab::create(!adguard)?;
        lab.inbound_endpoints()?;
        if adguard {
            lab.configure()?;
            lab.change("set tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
        } else {
            lab.configure_dnsmasq()?;
        }
        let pid = lab.ready(None)?;
        lab.change("set tunnel-detour.globals.observability='1'")?;
        wait(|| {
            Ok(lab.ubus("tunnel-detour", "status", json!({}))?["status"]["observability"] == true)
        })?;
        let marker = |name: &str| -> TestResult {
            wait(|| {
                Ok(lab
                    .inbound_marker("td-in-wan", "test", name)?
                    .status
                    .success())
            })
            .map_err(|error| format!("resolver reload marker {name}: {error}").into())
        };
        let current = || lab.ubus("tunnel-detour", "status", json!({}));
        let applied = |resolver: &str| -> TestResult {
            wait(|| {
                let state = current()?;
                Ok(state["running"] == true
                    && state["status"]["process_id"] == pid
                    && state["status"]["phase"] == "ready"
                    && state["status"]["configuration_applied"] == true
                    && state["status"]["applied_resolver"] == resolver)
            })
            .map_err(|error| {
                format!(
                    "resolver {resolver} was not applied: {error}; status: {}",
                    match current() {
                        Ok(status) => status.to_string(),
                        Err(error) => format!("status unavailable: {error}"),
                    }
                )
                .into()
            })
        };
        if adguard {
            let preview = lab.ubus("tunnel-detour", "preview_upstream", json!({"api_url":"http://127.0.0.1:13000","username":"lab-admin","password":lab.password,"real_upstream":"127.0.0.1:15353","import_current":false}))?;
            assert_eq!(preview["valid"], true);
            let receipt = preview["receipt"]
                .as_str()
                .ok_or("missing preview receipt")?;
            lab.change(&format!("set tunnel-detour.globals.manage_adguard_upstream='1'\nset tunnel-detour.globals.adguard_upstream_approval='{receipt}'"))?;
            wait(|| Ok(current()?["status"]["managed_upstream"] == true))?;
            if let Some(path) = env::var_os("TUNNEL_DETOUR_LUCI_DNS_REVIEW") {
                use std::os::unix::fs::OpenOptionsExt;
                let path = std::path::PathBuf::from(path);
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(&serde_json::to_vec(
                    &json!({"url":lab.http,"container":lab.name}),
                )?)?;
                wait_for(Duration::from_secs(600), || {
                    Ok(path.with_extension("continue").exists())
                })?;
            }
        }
        let network_before = lab.exec(&["uci", "export", "network"], None)?;
        let dhcp_before = lab.exec(&["uci", "export", "dhcp"], None)?;
        for role in ["dns_server", "dns_other_server"] {
            if role == "dns_other_server" {
                lab.exec(
                    &[
                        "ip",
                        "-n",
                        "td-in-wan",
                        "addr",
                        "add",
                        "203.0.113.3/32",
                        "dev",
                        "lo",
                    ],
                    None,
                )?;
            }
            lab.spawn_inbound_probe(role)?;
        }
        marker("dns-endpoint-ready")?;
        marker("dns-other-endpoint-ready")?;
        assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
        lab.spawn_inbound_probe("dns_reloading")?;
        marker("dns-reloading-ready")?;
        wait(|| {
            Ok(current()?["status"]["connections"]
                .as_object()
                .is_some_and(|connections| connections.len() == 1))
        })?;
        lab.exec(&["tee", "/tmp/reloaded-resolver.conf"], Some(b"server:\n interface: ::1@15355\n username: \"\"\n chroot: \"\"\n directory: \"/tmp\"\n pidfile: \"\"\n do-daemonize: no\n use-syslog: no\n module-config: \"iterator\"\n local-zone: \".\" refuse\n local-zone: \"example.net.\" static\n local-data: \"selected.example.net. 0 IN A 203.0.113.3\"\n local-data: \"ordinary.example.net. 0 IN A 203.0.113.3\"\n"))?;
        lab.background.borrow_mut().push(
            lab.background_command(&["unbound", "-d", "-c", "/tmp/reloaded-resolver.conf"])?
                .spawn()?,
        );
        wait(|| {
            Ok(
                String::from_utf8(lab.exec(&["cat", "/proc/net/tcp6"], None)?)?
                    .lines()
                    .any(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        fields.get(1) == Some(&"00000000000000000000000001000000:3BFB")
                            && fields.get(3) == Some(&"0A")
                    }),
            )
        })?;
        lab.change("set tunnel-detour.globals.real_upstream='[::1]:15355'")?;
        applied("[::1]:15355")?;
        lab.spawn_inbound_probe("dns_holding")?;
        marker("dns-holding-ready")?;
        wait(|| {
            Ok(current()?["status"]["connections"]
                .as_object()
                .is_some_and(|connections| connections.len() == 2))
        })?;
        let state = current()?;
        let destinations: Vec<_> = state["status"]["connections"]
            .as_object()
            .ok_or("missing active streams")?
            .values()
            .map(|connection| connection["destination"].clone())
            .collect();
        assert!(destinations.contains(&json!("203.0.113.2:80")));
        assert!(destinations.contains(&json!("203.0.113.3:80")));
        if adguard {
            let mut upstreams = lab.api("dns_info", None, true)?["upstream_dns"]
                .as_array()
                .ok_or("missing upstreams")?
                .clone();
            let general = upstreams
                .iter_mut()
                .find(|value| value.as_str().is_some_and(|line| !line.starts_with('[')))
                .ok_or("missing general resolver")?;
            assert_eq!(*general, "tcp://[::1]:15355");
            *general = json!("tcp://127.0.0.1:15353");
            lab.api("dns_config", Some(json!({"upstream_dns":upstreams})), true)?;
            // The normal audit must notice a foreign edit without a UCI event
            // or a repairing write from the package.
            wait_for(Duration::from_secs(45), || {
                Ok(current()?["status"]["phase"] == "failed")
            })?;
            assert_eq!(
                current()?["status"]["last_error"],
                "adguard_upstream_conflict"
            );
            assert_eq!(current()?["status"]["process_id"], pid);
            assert_eq!(
                lab.api("dns_info", None, true)?["upstream_dns"],
                json!(upstreams)
            );
            let denied = lab.inbound_probe("dns_rejected")?;
            assert!(
                denied.status.success(),
                "{}",
                String::from_utf8_lossy(&denied.stderr)
            );
            let preview = lab.ubus("tunnel-detour", "preview_upstream", json!({"api_url":"http://127.0.0.1:13000","username":"lab-admin","password":lab.password,"real_upstream":"[::1]:15355","import_current":false}))?;
            assert_eq!(preview["valid"], true);
            lab.change(&format!(
                "set tunnel-detour.globals.adguard_upstream_approval='{}'",
                preview["receipt"].as_str().ok_or("fresh receipt missing")?
            ))?;
            applied("[::1]:15355")?;
            assert!(
                lab.api("dns_info", None, true)?["upstream_dns"]
                    .as_array()
                    .ok_or("upstreams missing")?
                    .contains(&json!("tcp://[::1]:15355"))
            );
        }
        let dns_status = || -> TestResult<Value> {
            Ok(serde_json::from_slice(&lab.exec(
                &["cat", "/var/run/tunnel-detour/status.json"],
                None,
            )?)?)
        };
        // A fresh transfer yields visible details even if the AdGuard audit
        // paused a previous period. Keep the original streams held as well.
        assert!(lab.lookup("selected.example.net")?.contains("198.18."));
        assert!(lab.inbound_probe("dns_once")?.status.success());
        wait(|| {
            Ok(current()?["status"]["completed_connections"]
                .as_u64()
                .is_some_and(|completed| completed > 0))
        })?;
        lab.change("set tunnel-detour.globals.real_upstream='203.0.113.2:53'")?;
        wait(|| Ok(current()?["status"]["last_error"] == "resolver_route_unavailable"))?;
        let rejected = current()?;
        assert_eq!(rejected["status"]["process_id"], pid);
        assert_eq!(rejected["status"]["applied_resolver"], "[::1]:15355");
        assert_eq!(rejected["status"]["configuration_applied"], false);
        assert_eq!(rejected["observability_requested"], true);
        for state in [&rejected["status"], &dns_status()?] {
            assert_diagnostics_off(
                state,
                &["dns_queries", "connections", "completed_connections"],
            );
        }
        lab.change("set tunnel-detour.globals.real_upstream='[::1]:15355'")?;
        applied("[::1]:15355")?;
        assert_eq!(current()?["status"]["connections"], json!({}));
        assert_eq!(current()?["status"]["completed_connections"], 0);
        for stem in ["dns-reloading", "dns-holding"] {
            lab.exec(&["touch", &format!("/tmp/inbound-test/check-{stem}")], None)?;
            marker(&format!("{stem}-complete"))?;
        }
        assert_eq!(current()?["status"]["process_id"], pid);
        assert_eq!(
            lab.exec(&["uci", "export", "network"], None)?,
            network_before
        );
        assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dhcp_before);
        lab.change("set tunnel-detour.globals.enabled='0'")?;
        wait(|| Ok(current()?["running"] == false))?;
        if adguard {
            assert_eq!(
                lab.api("dns_info", None, true)?["upstream_dns"],
                json!(["tcp://127.0.0.1:15353"])
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r056_uci_ports_and_dns_run_independently_and_port_edits_preserve_existing_dns_proxy_connections()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let marker = |name: &str| -> TestResult {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", name)?
                .status
                .success())
        })
    };
    let ready_ports = || -> TestResult<Value> {
        let mut current = Value::Null;
        wait(|| {
            current = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(current["running"] == true && current["status"]["phase"] == "ready")
        })?;
        Ok(current)
    };
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["enabled"],
        false
    );
    lab.prepare_inbound_uci()?;
    assert_eq!(
        lab.ubus("tunnel-detour", "check_inbound", json!({}))?,
        json!({"valid":true}),
        "ports must not require DNS integration or a real resolver"
    );
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    let initial = ready_ports()?;
    let probe = lab.inbound_probe("client")?;
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["running"],
        false
    );
    lab.spawn_inbound_probe("independent")?;
    marker("independent-ready")?;
    lab.configure_dnsmasq()?;
    let dns_pid = lab.ready(None)?;
    assert_eq!(
        ready_ports()?["status"]["process_id"],
        initial["status"]["process_id"],
        "enabling DNS restarted inbound ports"
    );
    lab.spawn_inbound_probe("dns_server")?;
    marker("dns-endpoint-ready")?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.spawn_inbound_probe("dns_holding")?;
    marker("dns-holding-ready")?;
    lab.change("set tunnel-detour.sample.name='Renamed publication'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["revision"]
            .as_u64()
            .is_some_and(|revision| Some(revision) > initial["status"]["revision"].as_u64())
            && status["status"]["publications"][0]["name"] == "Renamed publication")
    })?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["status"]["process_id"],
        dns_pid,
        "port edits restarted DNS"
    );
    lab.exec(&["touch", "/tmp/inbound-test/check-dns-holding"], None)?;
    marker("dns-holding-complete")?;
    lab.change("set tunnel-detour.globals.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
    assert_eq!(
        ready_ports()?["status"]["process_id"],
        initial["status"]["process_id"],
        "disabling DNS restarted inbound ports"
    );
    lab.exec(&["touch", "/tmp/inbound-test/check-independent"], None)?;
    marker("independent-complete")?;
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    wait(|| {
        Ok(!lab
            .raw(
                &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
                None,
            )?
            .status
            .success())
    })?;
    assert!(lab.ubus("system", "board", json!({}))?["kernel"].is_string());
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    ready_ports()?;
    let restored = lab.inbound_probe("client")?;
    assert!(
        restored.status.success(),
        "UCI re-enable must restore real TCP and UDP traffic without a manual service start: {}",
        String::from_utf8_lossy(&restored.stderr)
    );

    lab.change("set tunnel-detour.globals.enabled='1'")?;
    let dns_pid = lab.ready(None)?;
    let inode = |path| lab.exec(&["ls", "-i", path], None);
    let table = |name| lab.exec(&["nft", "-s", "-a", "list", "table", "inet", name], None);
    let dns_status = "/var/run/tunnel-detour/status.json";
    let inbound_status = "/var/run/tunnel-detour/inbound/status.json";
    let initial_dns_guard = table("tunnel_detour")?;
    let mut dns_snapshot = inode(dns_status)?;
    for enabled in [true, false] {
        let consent = u8::from(enabled);
        lab.change(&format!(
            "set tunnel-detour.inbound.observability='{consent}'"
        ))?;
        wait(|| {
            assert!(
                lab.lookup("selected.example.net")?.contains("198.18.0.1"),
                "DNS must answer a selected query during an inbound-only Apply"
            );
            let connection = lab.inbound_probe("dns_once")?;
            assert!(
                connection.status.success(),
                "DNS must admit a new WAN connection during an inbound-only Apply: {}",
                String::from_utf8_lossy(&connection.stderr)
            );
            let result = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(result["status"]["observability"] == enabled
                && result["observability_revocation_pending"] == false
                && inode(dns_status)? != dns_snapshot)
        })?;
        dns_snapshot = inode(dns_status)?;
        assert_eq!(
            table("tunnel_detour")?,
            initial_dns_guard,
            "inbound consent Apply must not reinstall the DNS guard"
        );
    }
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["status"]["process_id"],
        dns_pid
    );

    // A native fw4 reload replaces handles but leaves the same effective policy.
    lab.exec(&["fw4", "reload"], None)?;
    let native_guard = table("tunnel_detour_inbound")?;
    let fw4 = table("fw4")?;
    let inbound_snapshot = inode(inbound_status)?;
    let inbound_pid = ready_ports()?["status"]["process_id"].clone();
    lab.change("set tunnel-detour.globals.observability='1'")?;
    wait(|| {
        let reply = lab.inbound_probe("client")?;
        assert!(
            reply.status.success(),
            "native publications must admit new TCP and UDP traffic during a DNS-only Apply: {}",
            String::from_utf8_lossy(&reply.stderr)
        );
        let result = lab.ubus("tunnel-detour", "status", json!({}))?;
        Ok(result["status"]["observability"] == true && inode(inbound_status)? != inbound_snapshot)
    })?;
    assert_eq!(ready_ports()?["status"]["process_id"], inbound_pid);
    assert_eq!(
        table("tunnel_detour_inbound")?,
        native_guard,
        "DNS consent Apply must not reinstall the inbound guard"
    );
    assert_eq!(table("fw4")?, fw4, "DNS consent Apply must not reload fw4");

    let chain = |name| -> TestResult<Value> {
        Ok(serde_json::from_slice(&lab.exec(
            &[
                "nft", "-j", "-s", "-a", "list", "chain", "inet", "fw4", name,
            ],
            None,
        )?)?)
    };
    let admin_rule = || -> TestResult<Value> {
        let current = chain("input_wan")?;
        let mut rule = current["nftables"]
            .as_array()
            .and_then(|objects| {
                objects.iter().find_map(|object| {
                    (object["rule"]["comment"] == "!fw4: Allow-ICMPv6-ND")
                        .then(|| object["rule"].clone())
                })
            })
            .ok_or("missing administrator firewall rule")?;
        rule.as_object_mut()
            .ok_or("invalid administrator rule")?
            .remove("handle");
        Ok(rule)
    };
    let administrator = admin_rule()?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"add table inet td_r056_admin\nadd chain inet td_r056_admin marker\n"),
    )?;
    let administrator_table = table("td_r056_admin")?;
    let nat_chain = chain("dstnat_wan")?;
    let tcp_redirects: Vec<_> = nat_chain["nftables"]
        .as_array()
        .ok_or("missing native DNAT listing")?
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| rule["comment"] == "!fw4: Tunnel Detour: Renamed publication")
        .filter(|rule| {
            rule["expr"].as_array().is_some_and(|expr| {
                expr.iter().any(|entry| entry.get("dnat").is_some())
                    && expr.iter().any(|entry| {
                        entry["match"]["left"]["payload"]
                            == json!({"protocol":"tcp","field":"dport"})
                            && entry["match"]["right"] == 18080
                    })
            })
        })
        .cloned()
        .collect();
    let [tcp_rule] = tcp_redirects.as_slice() else {
        return Err("expected exactly one owned TCP DNAT rule".into());
    };
    let handle = tcp_rule["handle"].as_u64().ok_or("missing DNAT handle")?;
    lab.exec(
        &[
            "nft",
            "delete",
            "rule",
            "inet",
            "fw4",
            "dstnat_wan",
            "handle",
            &handle.to_string(),
        ],
        None,
    )?;
    let denied = lab.inbound_probe("native_tcp_redirect_missing")?;
    assert!(
        denied.status.success(),
        "missing TCP DNAT must fail closed while UDP still reaches the native backend: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"insert rule inet fw4 forward iifname \"tdwan0\" ip6 daddr 2001:db8:1::2 tcp dport 8080 reject with tcp reset comment \"lab live forward restriction\"\n"),
    )?;
    let forward_restriction = || -> TestResult<(usize, Value)> {
        let inventory = chain("forward")?;
        inventory["nftables"]
            .as_array()
            .and_then(|items| {
                items.iter().enumerate().find_map(|(index, item)| {
                    let rule = &item["rule"];
                    (rule["comment"] == "lab live forward restriction")
                        .then(|| (index, rule.clone()))
                })
            })
            .ok_or_else(|| "missing live forward restriction".into())
    };
    let restriction = forward_restriction()?;
    let revision = ready_ports()?["status"]["revision"]
        .as_u64()
        .ok_or("missing pre-repair inbound revision")?;
    lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
    wait(|| {
        let state = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(state["status"]["applied"] == true
            && state["status"]["revision"]
                .as_u64()
                .is_some_and(|current| current > revision))
    })?;
    assert_eq!(forward_restriction()?, restriction);
    assert!(
        lab.inbound_probe("native_tcp_redirect_missing")?
            .status
            .success(),
        "the live forward restriction must still deny TCP after repair while UDP remains available"
    );
    let restriction_handle = restriction.1["handle"]
        .as_u64()
        .ok_or("missing live forward handle")?;
    lab.exec(
        &[
            "nft",
            "delete",
            "rule",
            "inet",
            "fw4",
            "forward",
            "handle",
            &restriction_handle.to_string(),
        ],
        None,
    )?;
    let restored = lab.inbound_probe("client")?;
    assert!(
        restored.status.success(),
        "reloading unchanged UCI must restore the missing DNAT and real TCP delivery: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(ready_ports()?["status"]["process_id"], inbound_pid);
    assert_eq!(admin_rule()?, administrator);
    assert_eq!(table("td_r056_admin")?, administrator_table);

    let log_sequence = std::cell::Cell::new(0_u32);
    let mark_nat_log = || -> TestResult<String> {
        let next = log_sequence.get() + 1;
        log_sequence.set(next);
        let marker = format!("r056 NAT check {next} begins");
        lab.exec(&["logger", "-t", "r056-fixture", &marker], None)?;
        Ok(marker)
    };
    let verify_nat_log = |marker: &str, stage| -> TestResult {
        let expected = format!("nat_stage=\"{stage}\"");
        wait(|| {
            let logs = String::from_utf8(lab.exec(&["logread"], None)?)?;
            Ok(logs
                .lines()
                .skip_while(|line| !line.contains(marker))
                .skip(1)
                .find(|line| line.contains("inbound reconciliation failed"))
                .is_some_and(|line| {
                    line.contains("kernel_conflict")
                        && line.contains(&expected)
                        && !line.contains("2001:db8")
                        && !line.contains("18080")
                }))
        })
    };

    let independent_publication = || -> TestResult {
        lab.exec(
            &["uci", "batch"],
            Some(b"set tunnel-detour.independent=inbound_port\nset tunnel-detour.independent.name='Other publication'\nset tunnel-detour.independent.enabled='1'\nset tunnel-detour.independent.protocol='tcp'\nset tunnel-detour.independent.public_port='18081'\nset tunnel-detour.independent.destination_address='2001:db8:1::2'\nset tunnel-detour.independent.destination_port='8080'\ncommit tunnel-detour\n"),
        )?;
        Ok(())
    };
    // Neither a different publication edit nor a failed read can turn a
    // recognizable restricted rule into a repairable absence.
    for fault in [
        None,
        Some("exit 1"),
        Some("printf 'invalid JSON\\n'; exit 0"),
        Some("exec sleep 20"),
    ] {
        let repaired_chain = chain("dstnat_wan")?;
        let mut restricted_tcp = repaired_chain["nftables"]
            .as_array()
            .ok_or("missing repaired DNAT listing")?
            .iter()
            .filter_map(|object| object.get("rule"))
            .find(|rule| rule["comment"] == tcp_rule["comment"] && rule["expr"] == tcp_rule["expr"])
            .cloned()
            .ok_or("missing repaired TCP DNAT")?;
        restricted_tcp["expr"]
            .as_array_mut()
            .ok_or("missing TCP DNAT expressions")?
            .insert(0, json!({"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"prefix":{"addr":"2001:db8:2::","len":64}}}}));
        lab.exec(
            &["nft", "-j", "-f", "-"],
            Some(&serde_json::to_vec(
                &json!({"nftables":[{"replace":{"rule":restricted_tcp}}]}),
            )?),
        )?;
        let restricted_fw4 = table("fw4")?;
        let restricted_guard = table("tunnel_detour_inbound")?;
        let saved_firewall = lab.exec(&["uci", "export", "firewall"], None)?;
        assert!(
            lab.inbound_probe("native_tcp_redirect_missing")?
                .status
                .success()
        );
        let rejected = |stage| -> TestResult {
            let marker = mark_nat_log()?;
            lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
            wait(|| {
                let state = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
                Ok(state["status"]["last_error"] == "kernel_conflict"
                    && state["status"]["applied"] == false
                    && state["status"]["process_id"] == inbound_pid)
            })?;
            assert!(
                lab.inbound_probe("native_tcp_redirect_missing")?
                    .status
                    .success()
            );
            assert_eq!(table("fw4")?, restricted_fw4);
            assert_eq!(table("tunnel_detour_inbound")?, restricted_guard);
            assert_eq!(
                lab.exec(&["uci", "export", "firewall"], None)?,
                saved_firewall
            );
            assert_eq!(table("td_r056_admin")?, administrator_table);
            verify_nat_log(&marker, stage)
        };
        if let Some(fault) = fault {
            let nft_path = String::from_utf8(
                lab.exec(&["sh", "-c", "readlink -f \"$(command -v nft)\""], None)?,
            )?;
            let nft_path = nft_path.trim();
            lab.exec(&["cp", nft_path, "/usr/libexec/r056-real-nft"], None)?;
            lab.exec(&["rm", "-f", "/tmp/r056-nft-fault-observed"], None)?;
            let script = format!(
                "#!/bin/sh\ncase \"$*\" in\n  '-j -s -a list chain inet fw4 dstnat_wan') touch /tmp/r056-nft-fault-observed; {fault} ;;\nesac\nexec /usr/libexec/r056-real-nft \"$@\"\n"
            );
            lab.exec(
                &["tee", "/usr/libexec/r056-nft-read-fault"],
                Some(script.as_bytes()),
            )?;
            lab.exec(&["chmod", "755", "/usr/libexec/r056-nft-read-fault"], None)?;
            lab.exec(
                &[
                    "mount",
                    "--bind",
                    "/usr/libexec/r056-nft-read-fault",
                    nft_path,
                ],
                None,
            )?;
            let outcome = rejected("inspection");
            let unmounted = lab.exec(&["umount", nft_path], None);
            outcome?;
            unmounted?;
            lab.exec(&["test", "-e", "/tmp/r056-nft-fault-observed"], None)?;
        } else {
            independent_publication()?;
            rejected("owned_rule")?;
            lab.exec(
                &["uci", "batch"],
                Some(b"delete tunnel-detour.independent\ncommit tunnel-detour\n"),
            )?;
        }
        lab.exec(&["fw4", "reload"], None)?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
        wait(|| Ok(ready_ports()?["status"]["applied"] == true))?;
    }

    for chain_name in ["dstnat", "dstnat_wan"] {
        shadow_wan_tcp(&lab, chain_name, 18080)?;
        let restricted_fw4 = table("fw4")?;
        let restricted_guard = table("tunnel_detour_inbound")?;
        let saved_firewall = lab.exec(&["uci", "export", "firewall"], None)?;
        assert!(
            lab.inbound_probe("native_tcp_redirect_missing")?
                .status
                .success()
        );

        independent_publication()?;
        let marker = mark_nat_log()?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
        wait(|| {
            let state = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(state["status"]["last_error"] == "kernel_conflict"
                && state["status"]["applied"] == false
                && state["status"]["process_id"] == inbound_pid)
        })?;
        assert!(
            lab.inbound_probe("native_tcp_redirect_missing")?
                .status
                .success()
        );
        verify_nat_log(&marker, "rule_order")?;
        assert_eq!(table("fw4")?, restricted_fw4);
        assert_eq!(table("tunnel_detour_inbound")?, restricted_guard);
        assert_eq!(table("td_r056_admin")?, administrator_table);
        assert_eq!(
            lab.exec(&["uci", "export", "firewall"], None)?,
            saved_firewall
        );

        lab.exec(
            &["uci", "batch"],
            Some(b"delete tunnel-detour.independent\ncommit tunnel-detour\n"),
        )?;
        lab.exec(&["fw4", "reload"], None)?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
        wait(|| Ok(ready_ports()?["status"]["applied"] == true))?;
    }

    // Foreign restrictions can leave the owned DNAT intact while excluding the
    // external IPv6 client's traffic at the WAN dispatch.
    for predicate in ["ip6 saddr 2001:db8:2::/64", "meta nfproto ipv4"] {
        let nat_before = chain("dstnat_wan")?;
        restrict_wan_dispatch(&lab, predicate)?;
        assert_eq!(chain("dstnat_wan")?, nat_before);
        let restricted_fw4 = table("fw4")?;
        let restricted_guard = table("tunnel_detour_inbound")?;
        let saved_firewall = lab.exec(&["uci", "export", "firewall"], None)?;
        let denied = lab.inbound_probe("native_wan_dispatch_restricted")?;
        assert!(
            denied.status.success(),
            "the WAN predicate {predicate} must exclude the external fixture client: {}",
            String::from_utf8_lossy(&denied.stderr)
        );

        let marker = mark_nat_log()?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
        wait(|| {
            let state = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(state["running"] == true
                && state["status"]["phase"] == "ready"
                && state["status"]["applied"] == false
                && state["status"]["last_error"] == "kernel_conflict"
                && state["status"]["process_id"] == inbound_pid)
        })?;
        assert_eq!(table("fw4")?, restricted_fw4);
        assert_eq!(table("tunnel_detour_inbound")?, restricted_guard);
        assert_eq!(
            lab.exec(&["uci", "export", "firewall"], None)?,
            saved_firewall
        );
        assert_eq!(table("td_r056_admin")?, administrator_table);
        verify_nat_log(&marker, "dispatch")?;
        let denied = lab.inbound_probe("native_wan_dispatch_restricted")?;
        assert!(
            denied.status.success(),
            "reload must preserve the foreign WAN predicate {predicate} for new TCP and UDP traffic: {}",
            String::from_utf8_lossy(&denied.stderr)
        );
        lab.exec(&["fw4", "reload"], None)?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
        wait(|| {
            let state = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
            Ok(state["status"]["applied"] == true && state["status"]["process_id"] == inbound_pid)
        })?;
    }

    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    Ok(())
}

#[track_caller]
fn assert_diagnostics_off(status: &Value, fields: &[&str]) {
    assert_eq!(
        status["observability"], false,
        "missing applied privacy state: {status}"
    );
    for field in fields {
        assert!(
            status.get(*field).is_none(),
            "off snapshot contains {field}: {status}"
        );
    }
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r153b_startup_cannot_scrub_an_active_dns_or_inbound_owner() -> TestResult {
    const DNS: &str = "/var/run/tunnel-detour/status.json";
    const INBOUND: &str = "/var/run/tunnel-detour/inbound/status.json";
    let lab = Lab::create(true)?;
    let read_status = |path: &str| -> TestResult<Value> {
        Ok(serde_json::from_slice(&lab.exec(&["cat", path], None)?)?)
    };
    let reject_inbound_json = |path: &str, options: &[&str]| -> TestResult {
        const CANDIDATE: &str = "/tmp/r153b-inbound-contender.json";
        const JOURNAL: &str = "/tmp/r153b-inbound-contender/state.json";
        let read = || -> TestResult<Option<Vec<u8>>> {
            if lab.raw(&["test", "-e", path], None)?.status.success() {
                Ok(Some(lab.exec(&["cat", path], None)?))
            } else {
                Ok(None)
            }
        };
        let snapshot = read()?;
        let resolved = String::from_utf8(lab.exec(&["readlink", "-f", path], None)?)?;
        let mut config = lab.inbound_configuration();
        config["state_file"] = json!(JOURNAL);
        config["status_file"] = json!(resolved.trim());
        lab.exec(&["tee", CANDIDATE], Some(&serde_json::to_vec(&config)?))?;
        for option in options {
            let result =
                lab.raw_with_deadline(&["/usr/bin/tunnel-detour", option, CANDIDATE], None, "8")?;
            assert_eq!(
                result.status.code(),
                Some(1),
                "inbound candidate {option} accepted or failed unexpectedly: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                String::from_utf8_lossy(&result.stderr).contains("inbound_configuration_failed")
            );
            assert_eq!(read()?, snapshot);
        }
        for candidate in [JOURNAL, &format!("{JOURNAL}.lock")] {
            assert!(!lab.raw(&["test", "-e", candidate], None)?.status.success());
        }
        Ok(())
    };
    lab.inbound_endpoints()?;
    // The reserved UCI paths below are independent of collisions between JSON
    // controllers. First give the DNS JSON controller a live private snapshot.
    const JSON_DNS: &str = "/tmp/r153b-json-dns/status.json";
    let mut json_dns = json!({
        "dns_listen": "127.0.0.1:15535", "proxy_listen": "0.0.0.0:15536",
        "real_upstream": "127.0.0.1:15353", "observability": false,
        "state_file": "/tmp/r153b-json-dns/leases.json", "status_file": JSON_DNS,
        "fake_range": "198.18.2.0/28", "lan_device": "tdlan0",
        "lan_networks": ["192.0.2.0/24"],
        "wan": {"device":"tdwan0","gateway":null,"route_table":41874,"mark":21573,"rule_priority":11001},
        "rules": [{"pattern":"selected.example.net","enabled":true}],
        "limits": {"max_mappings":14}
    });
    const JSON_CONFIG: &str = "/tmp/r153b-json-dns-config.json";
    lab.exec(&["tee", JSON_CONFIG], Some(&serde_json::to_vec(&json_dns)?))?;
    let mut json_controller = lab
        .background_command(&["/usr/bin/tunnel-detour", "--config", JSON_CONFIG])?
        .spawn()?;
    wait(|| {
        if let Some(status) = json_controller.try_wait()? {
            let mut diagnostic = String::new();
            if let Some(stderr) = json_controller.stderr.take() {
                stderr.take(8192).read_to_string(&mut diagnostic)?;
            }
            return Err(format!(
                "JSON DNS exited before recording ownership: {status}: {diagnostic}"
            )
            .into());
        }
        Ok(read_status(JSON_DNS).is_ok_and(|status| status["phase"] == "ready"))
    })?;
    let json_pid = read_status(JSON_DNS)?["process_id"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or("missing JSON DNS controller")?
        .to_string();
    let owner = read_status(JSON_DNS)?["status_owner"].clone();
    assert!(owner.as_array().is_some_and(|identity| identity.len() == 2));
    let reject_with_owner = |observing: bool| -> TestResult {
        lab.exec(&["kill", "-STOP", &json_pid], None)?;
        let checked = (|| {
            let status = read_status(JSON_DNS)?;
            assert_eq!(status["status_owner"], owner);
            assert_eq!(status["observability"], observing);
            if !observing {
                assert_diagnostics_off(&status, &["dns_queries", "connections"]);
            }
            reject_inbound_json(JSON_DNS, &["--check-inbound-config", "--inbound-config"])
        })();
        let resumed = lab.exec(&["kill", "-CONT", &json_pid], None);
        checked?;
        resumed?;
        Ok(())
    };
    reject_with_owner(false)?;
    lab.exec(&["kill", "-STOP", &json_pid], None)?;
    let conflict_without_snapshot = (|| {
        const SAVED: &str = "/tmp/r153b-json-dns/status.saved";
        lab.exec(&["mv", JSON_DNS, SAVED], None)?;
        let rejected =
            reject_inbound_json(JSON_DNS, &["--check-inbound-config", "--inbound-config"]);
        let restored = lab.exec(&["mv", SAVED, JSON_DNS], None);
        rejected?;
        restored?;
        Ok::<_, Box<dyn Error>>(())
    })();
    let resumed = lab.exec(&["kill", "-CONT", &json_pid], None);
    conflict_without_snapshot?;
    resumed?;

    json_dns["observability"] = json!(true);
    lab.exec(&["tee", JSON_CONFIG], Some(&serde_json::to_vec(&json_dns)?))?;
    lab.exec(&["kill", "-HUP", &json_pid], None)?;
    wait(|| Ok(read_status(JSON_DNS)?["observability"] == true))?;
    lab.exec(
        &[
            "nslookup",
            "-retry=1",
            "-timeout=2",
            "-port=15535",
            "-type=A",
            "selected.example.net",
            "127.0.0.1",
        ],
        None,
    )?;
    wait(|| {
        Ok(read_status(JSON_DNS)?["dns_queries"]
            .as_u64()
            .is_some_and(|queries| queries > 0))
    })?;
    reject_with_owner(true)?;
    json_dns["observability"] = json!(false);
    lab.exec(&["tee", JSON_CONFIG], Some(&serde_json::to_vec(&json_dns)?))?;
    lab.exec(&["kill", "-HUP", &json_pid], None)?;
    wait(|| Ok(read_status(JSON_DNS)?["observability"] == false))?;
    reject_with_owner(false)?;
    lab.exec(&["kill", "-TERM", &json_pid], None)?;
    wait(|| {
        Ok(json_controller
            .try_wait()?
            .is_some_and(|status| status.success()))
    })?;

    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    lab.prepare_inbound_uci()?;
    lab.configure_dnsmasq()?;
    lab.ready(None)?;
    lab.change("set tunnel-detour.globals.observability='1'")?;
    wait(|| Ok(read_status(DNS)?["observability"] == true))?;
    lab.lookup("selected.example.net")?;
    let dns_pid = read_status(DNS)?["process_id"]
        .as_u64()
        .ok_or("missing DNS PID")?
        .to_string();
    lab.exec(&["kill", "-STOP", &dns_pid], None)?;
    let rejected = reject_inbound_json(DNS, &["--check-inbound-config", "--inbound-config"]);
    lab.exec(&["kill", "-CONT", &dns_pid], None)?;
    rejected?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.enabled='1'\nset tunnel-detour.inbound.observability='1'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        let dns = lab.ubus("tunnel-detour", "status", json!({}))?;
        Ok(status["status"]["applied"] == true
            && status["status"]["observability"] == true
            && dns["status"]["observability"] == true)
    })?;
    lab.lookup("selected.example.net")?;
    assert!(lab.inbound_probe("relay_client")?.status.success());
    wait(|| {
        Ok(read_status(DNS)?["dns_queries"]
            .as_u64()
            .is_some_and(|count| count > 0)
            && read_status(INBOUND)?["relay"]["completed"]
                .as_u64()
                .is_some_and(|count| count > 0))
    })?;
    for (file, mode, rpc, service, section, field) in [
        (
            DNS,
            "--uci",
            "status",
            "tunnel-detour",
            "globals",
            "dns_queries",
        ),
        (
            INBOUND,
            "--inbound-uci",
            "inbound_status",
            "tunnel-detour-inbound",
            "inbound",
            "relay",
        ),
    ] {
        let pid = read_status(file)?["process_id"]
            .as_u64()
            .filter(|pid| *pid > 1)
            .ok_or("missing active controller")?;
        lab.exec(&["kill", "-STOP", &pid.to_string()], None)?;
        let snapshot = lab.exec(&["cat", file], None)?;
        if file == DNS {
            let contender_path = "/tmp/r153b-foreign-dns.json";
            let resolved = String::from_utf8(lab.exec(&["readlink", "-f", DNS], None)?)?;
            let config = json!({
                "dns_listen": "127.0.0.1:15535", "proxy_listen": "0.0.0.0:15536",
                "real_upstream": "127.0.0.1:15353",
                "state_file": "/tmp/r153b-foreign-dns/leases.json",
                "status_file": resolved.trim(), "observability": false,
                "fake_range": "198.18.2.0/28", "lan_device": "tdlan0",
                "lan_networks": ["192.0.2.0/24"],
                "wan": {"device":"tdwan0","gateway":null,"route_table":41874,"mark":21573,"rule_priority":11001},
                "rules": [{"pattern":"other.example.test","enabled":true}],
                "limits": {"max_mappings":14}
            });
            lab.exec(
                &["tee", contender_path],
                Some(&serde_json::to_vec(&config)?),
            )?;
            let contender = lab.raw_with_deadline(
                &["/usr/bin/tunnel-detour", "--config", contender_path],
                None,
                "8",
            )?;
            assert_eq!(contender.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&contender.stderr).contains("invalid_configuration"));
            assert_eq!(lab.exec(&["cat", file], None)?, snapshot);
        }
        // Commit without running the reload script so the contender cannot rely on a marker.
        let batch =
            format!("set tunnel-detour.{section}.observability='0'\ncommit tunnel-detour\n");
        lab.exec(&["uci", "batch"], Some(batch.as_bytes()))?;
        let contender = lab.raw_with_deadline(&["/usr/bin/tunnel-detour", mode], None, "8")?;
        assert_eq!(
            contender.status.code(),
            Some(1),
            "duplicate controller did not exit with a startup error: {}",
            String::from_utf8_lossy(&contender.stderr)
        );
        assert_eq!(lab.exec(&["cat", file], None)?, snapshot);
        if file == INBOUND {
            reject_inbound_json(file, &["--check-inbound-config", "--inbound-config"])?;
        }
        let visible = lab.ubus("tunnel-detour", rpc, json!({}))?;
        assert_eq!(visible["observability_revocation_pending"], true);
        assert_diagnostics_off(&visible["status"], &[field]);
        lab.exec(&["kill", "-CONT", &pid.to_string()], None)?;
        lab.exec(&[&format!("/etc/init.d/{service}"), "reload"], None)?;
        wait(|| {
            let visible = lab.ubus("tunnel-detour", rpc, json!({}))?;
            Ok(visible["status"]["process_id"] == pid
                && visible["observability_revocation_pending"] == false)
        })?;
        assert_diagnostics_off(&read_status(file)?, &[field]);
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r155e_inbound_json_hup_rejects_a_fifo_without_blocking_active_publications() -> TestResult {
    const CONFIG: &str = "/tmp/inbound-config.json";
    const STATUS: &str = "/tmp/inbound-test/status.json";
    let lab = Lab::create(true)?;
    let status =
        || -> TestResult<Value> { Ok(serde_json::from_slice(&lab.exec(&["cat", STATUS], None)?)?) };
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    let mut config = lab.inbound_configuration();
    config["observability"] = json!(true);
    config["lan_networks"] = json!(["2001:db8:1::/64", "192.0.2.0/24"]);
    config["rules"][0]["protocol"] = json!("tcp");
    config["rules"][0]["destination"] = json!("192.0.2.2:8080");
    lab.start_inbound(&config)?;
    lab.spawn_inbound_probe("relay_holding")?;
    wait(|| {
        Ok(status()?["relay"]["connections"]
            .as_array()
            .is_some_and(|sessions| sessions.len() == 1))
    })?;
    let before = status()?;
    let pid = before["process_id"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or("missing active controller")?
        .to_string();
    lab.exec(&["rm", CONFIG], None)?;
    lab.exec(&["mkfifo", CONFIG], None)?;
    lab.exec(&["kill", "-HUP", &pid], None)?;
    wait_for(Duration::from_secs(10), || {
        let current = status()?;
        Ok(current["observability"] == false && current["last_error"] == "invalid_configuration")
    })?;
    let after = status()?;
    assert_diagnostics_off(&after, &["relay"]);
    assert_eq!(after["phase"], "ready");
    assert_eq!(after["process_id"], before["process_id"]);
    assert_eq!(after["publications"], before["publications"]);
    assert!(lab.inbound_probe("relay_client")?.status.success());
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-complete")?
            .status
            .success())
    })?;
    assert_diagnostics_off(&status()?, &["relay"]);
    lab.stop_inbound()
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r155g_inbound_json_startup_redacts_only_its_idle_snapshot_when_the_journal_is_corrupt()
-> TestResult {
    const CONFIG: &str = "/tmp/inbound-config.json";
    const STATE: &str = "/tmp/inbound-test/state.json";
    const STATUS: &str = "/tmp/inbound-test/status.json";
    const FOREIGN: &str = "/tmp/inbound-test/foreign.json";
    const CORRUPT: &[u8] = b"{incomplete";
    let lab = Lab::create(true)?;
    let status = || lab.exec(&["cat", STATUS], None);
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    let mut config = lab.inbound_configuration();
    config["observability"] = json!(true);
    config["lan_networks"] = json!(["2001:db8:1::/64", "192.0.2.0/24"]);
    config["rules"][0]["protocol"] = json!("tcp");
    config["rules"][0]["destination"] = json!("192.0.2.2:8080");
    let controller = lab.background.borrow().len();
    lab.start_inbound(&config)?;
    lab.spawn_inbound_probe("relay_holding")?;
    let mut live = Value::Null;
    wait(|| {
        live = serde_json::from_slice(&status()?)?;
        Ok(live["relay"]["connections"]
            .as_array()
            .is_some_and(|sessions| sessions.len() == 1 && sessions[0]["client"].is_string()))
    })?;
    let pid = live["process_id"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or("missing active controller")?
        .to_string();
    // Let the bound controller audit its own locked snapshot before simulating a crash.
    thread::sleep(Duration::from_secs(6));
    let audited: Value = serde_json::from_slice(&status()?)?;
    assert_eq!(audited["process_id"], live["process_id"]);
    assert_eq!(audited["phase"], "ready");
    assert!(lab.inbound_probe("relay_client")?.status.success());
    lab.exec(&["kill", "-STOP", &pid], None)?;
    let prior = status()?;
    config["observability"] = json!(false);
    lab.exec(&["tee", STATE], Some(CORRUPT))?;
    let refused = |candidate: &Value| -> TestResult {
        lab.exec(&["tee", CONFIG], Some(&serde_json::to_vec(candidate)?))?;
        let failed = lab.raw_with_deadline(
            &["/usr/bin/tunnel-detour", "--inbound-config", CONFIG],
            None,
            "5",
        )?;
        assert_eq!(failed.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&failed.stderr).lines().last(),
            Some("Tunnel Detour daemon exited: inbound_configuration_failed")
        );
        Ok(())
    };
    refused(&config)?;
    assert_eq!(status()?, prior, "the active owner holds this snapshot");
    lab.exec(&["kill", "-KILL", &pid], None)?;
    assert!(!lab.background.borrow_mut()[controller].wait()?.success());

    lab.exec(&["cp", "-p", STATE, FOREIGN], None)?;
    lab.exec(
        &[
            "cp",
            "-p",
            "/tmp/inbound-test/state.json.lock",
            "/tmp/inbound-test/foreign.json.lock",
        ],
        None,
    )?;
    let mut foreign = config.clone();
    foreign["state_file"] = json!(FOREIGN);
    refused(&foreign)?;
    assert_eq!(
        status()?,
        prior,
        "an unrelated idle lock cannot grant ownership"
    );

    refused(&config)?;
    let redacted = serde_json::from_slice(&status()?)?;
    assert_diagnostics_off(&redacted, &["relay", "observability_owner"]);
    assert_eq!(redacted["process_id"], live["process_id"]);
    assert_eq!(redacted["publications"], live["publications"]);
    assert_eq!(lab.exec(&["cat", STATE], None)?, CORRUPT);
    assert_eq!(lab.exec(&["cat", FOREIGN], None)?, CORRUPT);
    Ok(())
}

fn apply_coalesced_revocation(
    lab: &Lab,
    pid: u64,
    service: &str,
    section: &str,
    method: &str,
    fields: &[&str],
) -> TestResult {
    assert!(pid > 1, "expected the active fixture controller");
    let directory = if section == "inbound" {
        "/var/run/tunnel-detour/inbound"
    } else {
        "/var/run/tunnel-detour"
    };
    let locker = lab
        .background_command(&[
            "env",
            "TUNNEL_DETOUR_INBOUND_PROBE=observability_lock",
            "flock",
            "-x",
            directory,
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
        ])?
        .spawn()?;
    let locker_index = lab.background.borrow().len();
    lab.background.borrow_mut().push(locker);
    wait(|| {
        Ok(lab
            .raw(&["test", "-e", "/tmp/observability-lock-ready"], None)?
            .status
            .success())
    })?;
    if section == "inbound" {
        assert!(lab.inbound_probe("relay_client")?.status.success());
    } else {
        assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    }
    lab.exec(&["kill", "-STOP", &pid.to_string()], None)?;
    for value in ["0", "1"] {
        let batch =
            format!("set tunnel-detour.{section}.observability='{value}'\ncommit tunnel-detour\n");
        lab.exec(&["uci", "batch"], Some(batch.as_bytes()))?;
        let reloaded =
            lab.raw_with_deadline(&[&format!("/etc/init.d/{service}"), "reload"], None, "5")?;
        assert!(
            reloaded.status.success(),
            "{service} reload returned {} with a held directory lock: {}",
            reloaded.status,
            String::from_utf8_lossy(&reloaded.stderr)
        );
        let rpc = lab.raw_with_deadline(
            &["ubus", "-S", "call", "tunnel-detour", method, "{}"],
            None,
            "5",
        )?;
        assert!(
            rpc.status.success(),
            "{method} returned {} with a held directory lock: {}",
            rpc.status,
            String::from_utf8_lossy(&rpc.stderr)
        );
        let visible: Value = serde_json::from_slice(&rpc.stdout)?;
        assert_eq!(visible["observability_revocation_pending"], true);
        assert_eq!(visible["observability_requested"], value == "1");
        assert_diagnostics_off(&visible["status"], fields);
        assert_eq!(visible["status"]["process_id"], pid);
    }
    let acknowledged = finish_coalesced_revocation(lab, pid, service, method);
    let lock_still_held = lab.background.borrow_mut()[locker_index]
        .try_wait()?
        .is_none();
    lab.exec(&["touch", "/tmp/observability-lock-release"], None)?;
    assert!(
        lock_still_held,
        "revocation waited for the obsolete directory lock to be released"
    );
    acknowledged
}

fn mount_status_quota(lab: &Lab, directory: &str) -> TestResult {
    lab.exec(
        &[
            "sh",
            "-c",
            "umask 077; mkdir -p \"$1\"",
            "prepare-status-quota",
            directory,
        ],
        None,
    )?;
    lab.exec(
        &[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "mode=0700,nr_inodes=32",
            "tmpfs",
            directory,
        ],
        None,
    )?;
    Ok(())
}

fn fill_status_quota(lab: &Lab, directory: &str) -> TestResult {
    let filled = lab.raw(
        &[
            "sh",
            "-c",
            "for i in $(seq 1 32); do touch \"$1/quota-$i\" || exit $?; done",
            "fill-status-quota",
            directory,
        ],
        None,
    )?;
    assert!(!filled.status.success());
    assert!(String::from_utf8_lossy(&filled.stderr).contains("No space left on device"));
    Ok(())
}

fn release_status_quota(lab: &Lab, directory: &str) -> TestResult {
    lab.exec(
        &[
            "sh",
            "-c",
            "for i in $(seq 1 32); do rm -f \"$1/quota-$i\" || exit $?; done",
            "release-status-quota",
            directory,
        ],
        None,
    )?;
    Ok(())
}

fn apply_coalesced_luci_revocation(
    lab: &Lab,
    pid: u64,
    service: &str,
    section: &str,
    method: &str,
    fields: &[&str],
) -> TestResult {
    assert!(pid > 1, "expected the active fixture controller");
    let script = format!("/etc/init.d/{service}");
    let hold = "/tmp/hold-consent-reload";
    let triggered = "/tmp/consent-reload-deferred";
    let injection = format!(
        "/^reload_service() {{/a\\\n\tif [ -e {hold} ]; then touch {triggered}; return 0; fi"
    );
    lab.exec(&["sed", "-i", &injection, &script], None)?;
    lab.exec(&["touch", hold], None)?;
    let directory = if section == "inbound" {
        "/var/run/tunnel-detour/inbound"
    } else {
        "/var/run/tunnel-detour"
    };
    let grant = format!("{directory}/observability.grant");
    assert_eq!(lab.exec(&["cat", &grant], None)?.len(), 16);
    let consent = format!("tunnel-detour.{section}.observability");
    let epoch = format!("{consent}_epoch");
    let restored_epoch = lab.exec(&["uci", "get", &epoch], None)?;
    let password = secret()?;
    lab.exec(
        &["passwd", "root"],
        Some(format!("{password}\n{password}\n").as_bytes()),
    )?;
    lab.exec(&["kill", "-STOP", &pid.to_string()], None)?;
    fill_status_quota(lab, directory)?;
    for (value, confirm) in [("0", false), ("0", true), ("1", true)] {
        let session = lab.ubus(
            "session",
            "login",
            json!({"username":"root", "password":password}),
        )?;
        let session = session["ubus_rpc_session"]
            .as_str()
            .ok_or("missing synthetic LuCI RPC session")?;
        let values = if value == "1" {
            json!({"observability":"1", "observability_epoch":"0123456789abcdef0123456789abcdef"})
        } else {
            json!({"observability":"0"})
        };
        let prior = lab.ubus("tunnel-detour", method, json!({}))?;
        lab.ubus("uci", "set", json!({"config":"tunnel-detour", "section":section, "values":values, "ubus_rpc_session":session}))?;
        if value == "0" {
            lab.ubus("uci", "delete", json!({"config":"tunnel-detour", "section":section, "options":["observability_epoch"], "ubus_rpc_session":session}))?;
        }
        let staged = lab.ubus("tunnel-detour", method, json!({}))?;
        assert_eq!(
            staged["observability_requested"], prior["observability_requested"],
            "staging a form did not apply it"
        );
        lab.exec(&["rm", "-f", triggered], None)?;
        lab.ubus(
            "uci",
            "apply",
            json!({"rollback":true, "timeout":8, "ubus_rpc_session":session}),
        )?;
        if confirm {
            lab.ubus("uci", "confirm", json!({"ubus_rpc_session":session}))?;
        } else {
            // The first application expires under a real inode quota. The
            // withdrawal must already be recorded before any status read.
            wait(|| {
                Ok(lab
                    .raw(&["test", "!", "-e", &grant], None)?
                    .status
                    .success())
            })?;
            let withdrawn = lab.ubus("tunnel-detour", method, json!({}))?;
            assert_eq!(withdrawn["observability_requested"], false);
            assert_eq!(withdrawn["observability_revocation_pending"], true);
            assert_diagnostics_off(&withdrawn["status"], fields);
            wait(|| Ok(lab.exec(&["uci", "get", &consent], None)? == b"1\n"))?;
            assert_eq!(lab.exec(&["uci", "get", &epoch], None)?, restored_epoch);
        }
        wait(|| Ok(lab.raw(&["test", "-e", triggered], None)?.status.success()))?;
        let visible = lab.ubus("tunnel-detour", method, json!({}))?;
        assert_eq!(visible["observability_revocation_pending"], true);
        assert_eq!(visible["observability_requested"], !confirm || value == "1");
        assert_diagnostics_off(&visible["status"], fields);
        assert_eq!(visible["status"]["process_id"], pid);
        assert!(visible["status"].get("observability_epoch").is_none());
        assert!(visible["status"].get("observability_grant").is_none());
        if !confirm {
            release_status_quota(lab, directory)?;
        }
    }
    lab.exec(&["rm", hold], None)?;
    lab.exec(&[&script, "reload"], None)?;
    finish_coalesced_revocation(lab, pid, service, method)
}

fn finish_coalesced_revocation(lab: &Lab, pid: u64, service: &str, method: &str) -> TestResult {
    lab.exec(&["kill", "-CONT", &pid.to_string()], None)?;
    wait(|| {
        let visible = lab.ubus("tunnel-detour", method, json!({}))?;
        Ok(visible["observability_revocation_pending"] == false
            && visible["status"]["observability"] == true
            && visible["status"]["process_id"] == pid)
    })
    .map_err(|error| {
        format!(
            "{service} did not acknowledge the coalesced revocation: {error}; state: {:?}",
            lab.ubus("tunnel-detour", method, json!({}))
        )
        .into()
    })
}

fn pause_for_luci_review(variable: &str, details: Value) -> TestResult {
    use std::os::unix::fs::OpenOptionsExt;

    let Some(path) = env::var_os(variable).map(std::path::PathBuf::from) else {
        return Ok(());
    };
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&serde_json::to_vec(&details)?)?;
    wait_for(Duration::from_secs(240), || {
        Ok(path.with_extension("continue").exists())
    })
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r153_dns_observability_requires_consent_and_revokes_live_and_stale_diagnostics() -> TestResult {
    const FILE: &str = "/var/run/tunnel-detour/status.json";
    const FIELDS: &[&str] = &[
        "connections",
        "dns_queries",
        "completed_connections",
        "failures",
        "last_request_error",
        "bytes_to_wan",
        "bytes_from_wan",
        "mapping_usage",
    ];
    let lab = Lab::create(true)?;
    mount_status_quota(&lab, "/var/run/tunnel-detour")?;
    let raw =
        || -> TestResult<Value> { Ok(serde_json::from_slice(&lab.exec(&["cat", FILE], None)?)?) };
    let status = || lab.ubus("tunnel-detour", "status", json!({}));
    let logs = || -> TestResult<String> { Ok(String::from_utf8(lab.exec(&["logread"], None)?)?) };
    let marker = |name: &str| {
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", name)?
                .status
                .success())
        })
    };
    assert_eq!(
        lab.exec(&["uci", "get", "tunnel-detour.globals.observability"], None)?,
        b"0\n"
    );
    lab.exec(
        &["uci", "delete", "tunnel-detour.globals.observability"],
        None,
    )?;
    lab.inbound_endpoints()?;
    lab.configure_dnsmasq()?;
    let pid = lab.ready(None)?;
    lab.spawn_inbound_probe("dns_server")?;
    marker("dns-endpoint-ready")?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.spawn_inbound_probe("dns_holding")?;
    marker("dns-holding-ready")?;
    assert_diagnostics_off(&raw()?, FIELDS);
    assert_diagnostics_off(&status()?["status"], FIELDS);
    assert!(!logs()?.contains("DNS traffic diagnostics enabled"));

    lab.change("set tunnel-detour.globals.observability='1'\nset tunnel-detour.globals.observability_epoch='fedcba9876543210fedcba9876543210'")?;
    wait(|| {
        Ok(raw()?["observability"] == true && logs()?.contains("DNS traffic diagnostics enabled"))
    })?;
    assert_eq!(
        raw()?["connections"],
        json!({}),
        "traffic admitted without consent was imported"
    );
    let forwarding = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.lookup("selected.example.net")?;
    lab.spawn_inbound_probe("dns_reloading")?;
    marker("dns-reloading-ready")?;
    wait(|| {
        Ok(raw()?["connections"]
            .as_object()
            .is_some_and(|entries| entries.len() == 1))
    })?;
    assert_eq!(status()?["status"]["process_id"], pid);
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, forwarding);
    pause_for_luci_review(
        "TUNNEL_DETOUR_LUCI_DNS_DIAGNOSTICS_REVIEW",
        json!({"url":lab.http,"container":lab.name}),
    )?;
    apply_coalesced_luci_revocation(&lab, pid, "tunnel-detour", "globals", "status", FIELDS)?;
    assert_eq!(raw()?["connections"], json!({}));
    assert_eq!(raw()?["dns_queries"], 0);
    lab.lookup("selected.example.net")?;
    wait(|| {
        Ok(raw()?["dns_queries"]
            .as_u64()
            .is_some_and(|count| count > 0))
    })?;
    apply_coalesced_revocation(&lab, pid, "tunnel-detour", "globals", "status", FIELDS)?;
    assert_eq!(raw()?["connections"], json!({}));
    assert_eq!(raw()?["dns_queries"], 0);

    let applied_port =
        String::from_utf8(lab.exec(&["uci", "get", "tunnel-detour.globals.dns_port"], None)?)?;
    let applied_port: u16 = applied_port.trim().parse()?;
    lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.globals.observability='0'\nset tunnel-detour.globals.real_upstream='invalid'\nset tunnel-detour.globals.dns_port='invalid'\ndelete tunnel-detour.globals.enabled\ncommit tunnel-detour\n"))?;
    assert_eq!(
        raw()?["observability"],
        true,
        "stale snapshot control was not exercised"
    );
    let pending = status()?;
    assert_diagnostics_off(&pending["status"], FIELDS);
    assert_eq!(pending["observability_revocation_pending"], true);
    lab.ubus(
        "service",
        "event",
        json!({"type":"config.change","data":{"package":"tunnel-detour"}}),
    )?;
    wait(|| Ok(raw()?["observability"] == false && raw()?["configuration_applied"] == false))?;
    assert_diagnostics_off(&raw()?, FIELDS);
    assert_eq!(status()?["status"]["process_id"], pid);

    lab.change(&format!("set tunnel-detour.globals.enabled='1'\nset tunnel-detour.globals.real_upstream='127.0.0.1:15353'\nset tunnel-detour.globals.dns_port='{applied_port}'\nset tunnel-detour.globals.observability='1'"))?;
    wait(|| Ok(raw()?["observability"] == true && raw()?["configuration_applied"] == true))?;
    for name in ["dns-holding", "dns-reloading"] {
        lab.exec(&["touch", &format!("/tmp/inbound-test/check-{name}")], None)?;
        marker(&format!("{name}-complete"))?;
    }
    // A fresh session completes in this epoch. Neither earlier session may be counted.
    assert!(lab.inbound_probe("dns_once")?.status.success());
    wait(|| Ok(raw()?["completed_connections"] == 1))?;
    assert_eq!(raw()?["connections"], json!({}));
    assert_eq!(raw()?["process_id"], pid);

    lab.exec(
        &["uci", "batch"],
        Some(b"set tunnel-detour.globals.observability='0'\nset tunnel-detour.globals.enabled='off'\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "reload"], None)?;
    wait(|| {
        // Keep the daemon disabled across any previously queued reload and
        // wait for its final write before installing the legacy fixture.
        Ok(status()?["running"] == false
            && !lab
                .raw(&["kill", "-0", &pid.to_string()], None)?
                .status
                .success())
    })?;
    lab.exec(&["tee", FILE], Some(br#"{"phase":"stopped","connections":{"old":{"domain":"private.example.test"}},"dns_queries":17,"last_error":"filtered_destination"}"#))?;
    lab.exec(&["chmod", "600", FILE], None)?;
    assert_eq!(
        raw()?["dns_queries"],
        17,
        "legacy snapshot was not installed"
    );
    let legacy = status()?["status"].clone();
    assert_diagnostics_off(&legacy, FIELDS);
    assert!(legacy.get("last_error").is_none());
    assert_eq!(
        raw()?["dns_queries"],
        17,
        "the RPC must redact a genuinely stale snapshot"
    );
    lab.exec(
        &["uci", "batch"],
        Some(b"set tunnel-detour.globals.enabled='1'\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
    lab.ready(Some(pid))?;
    assert_diagnostics_off(&raw()?, FIELDS);
    assert!(!logs()?.contains("private.example.test"));
    let running = status()?["status"]["process_id"]
        .as_u64()
        .ok_or("missing restarted DNS PID")?;
    fill_status_quota(&lab, "/var/run/tunnel-detour")?;
    lab.exec(
        &["uci", "batch"],
        Some(b"delete tunnel-detour.selected\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "reload"], None)?;
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|answer| answer.contains("203.0.113.2") && !answer.contains("198.18.0.1")))
    })?;
    release_status_quota(&lab, "/var/run/tunnel-detour")?;
    let applied = lab.ready(Some(running))?;
    assert_diagnostics_off(&raw()?, FIELDS);
    fill_status_quota(&lab, "/var/run/tunnel-detour")?;
    lab.exec(
        &["uci", "batch"],
        Some(b"set tunnel-detour.globals.enabled='off'\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "reload"], None)?;
    wait(|| {
        Ok(status()?["running"] == false
            && !lab
                .raw(&["kill", "-0", &applied.to_string()], None)?
                .status
                .success())
    })?;
    release_status_quota(&lab, "/var/run/tunnel-detour")?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r156_inbound_observability_revokes_relay_diagnostics_without_retiring_sessions() -> TestResult {
    const FILE: &str = "/var/run/tunnel-detour/inbound/status.json";
    let lab = Lab::create(true)?;
    mount_status_quota(&lab, "/var/run/tunnel-detour/inbound")?;
    let raw =
        || -> TestResult<Value> { Ok(serde_json::from_slice(&lab.exec(&["cat", FILE], None)?)?) };
    let status = || lab.ubus("tunnel-detour", "inbound_status", json!({}));
    let marker = |namespace: &str, name: &str| -> TestResult {
        wait(|| {
            Ok(lab
                .inbound_marker(namespace, "test", name)?
                .status
                .success())
        })
        .map_err(|error| format!("relay marker {name}: {error}; state: {:?}", status()).into())
    };
    assert_eq!(
        lab.exec(&["uci", "get", "tunnel-detour.inbound.observability"], None)?,
        b"0\n"
    );
    lab.exec(
        &["uci", "delete", "tunnel-detour.inbound.observability"],
        None,
    )?;
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    marker("td-in-lan", "relay-endpoint-ready")?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| Ok(status()?["status"]["applied"] == true)).map_err(|error| {
        let exits = lab
            .raw(&["logread", "-e", "Tunnel Detour daemon exited"], None)
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
        format!(
            "initial inbound readiness: {error}; status: {:?}; daemon exits: {exits:?}",
            status()
        )
    })?;
    let pid = raw()?["process_id"].clone();
    let revision = raw()?["revision"].clone();
    assert!(lab.inbound_probe("relay_client")?.status.success());
    assert_diagnostics_off(&raw()?, &["relay"]);
    assert_diagnostics_off(&status()?["status"], &["relay"]);
    assert!(
        !String::from_utf8(lab.exec(&["logread"], None)?)?.contains("inbound publications ready")
    );

    lab.change("set tunnel-detour.inbound.observability='1'\nset tunnel-detour.inbound.observability_epoch='fedcba9876543210fedcba9876543210'")?;
    wait(|| Ok(raw()?["observability"] == true))
        .map_err(|error| format!("first inbound opt-in: {error}; state: {:?}", status()))?;
    lab.spawn_inbound_probe("relay_holding")?;
    marker("td-in-wan", "relay-client-ready")?;
    wait(|| {
        Ok(raw()?["relay"]["connections"]
            .as_array()
            .is_some_and(|sessions| sessions.len() == 1))
    })
    .map_err(|error| format!("initial observed relay: {error}; state: {:?}", status()))?;
    assert_eq!(raw()?["revision"], revision);
    assert!(
        String::from_utf8(lab.exec(&["logread"], None)?)?
            .contains("inbound traffic diagnostics enabled")
    );
    apply_coalesced_luci_revocation(
        &lab,
        pid.as_u64().ok_or("missing inbound PID")?,
        "tunnel-detour-inbound",
        "inbound",
        "inbound_status",
        &["relay"],
    )?;
    assert_eq!(raw()?["relay"]["connections"], json!([]));
    assert_eq!(raw()?["relay"]["completed"], 0);
    assert!(lab.inbound_probe("relay_client")?.status.success());
    wait(|| Ok(raw()?["relay"]["completed"] == 1))?;
    apply_coalesced_revocation(
        &lab,
        pid.as_u64().ok_or("missing inbound PID")?,
        "tunnel-detour-inbound",
        "inbound",
        "inbound_status",
        &["relay"],
    )?;
    assert_eq!(raw()?["relay"]["connections"], json!([]));
    assert_eq!(raw()?["relay"]["completed"], 0);

    lab.change("set tunnel-detour.inbound.observability='invalid'\nset tunnel-detour.inbound.relay_port='invalid'")?;
    wait(|| Ok(raw()?["observability"] == false && raw()?["last_error"].is_string()))
        .map_err(|error| format!("invalid inbound candidate: {error}; state: {:?}", status()))?;
    assert_diagnostics_off(&raw()?, &["relay"]);
    assert_diagnostics_off(&status()?["status"], &["relay"]);
    assert_eq!(raw()?["process_id"], pid);

    lab.change(
        "delete tunnel-detour.inbound.relay_port\nset tunnel-detour.inbound.observability='1'",
    )?;
    wait(|| Ok(raw()?["observability"] == true && raw()?["applied"] == true))
        .map_err(|error| format!("repair inbound candidate: {error}; state: {:?}", status()))?;
    assert_eq!(raw()?["relay"]["connections"], json!([]));
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    marker("td-in-wan", "relay-client-complete")?;
    assert!(lab.inbound_probe("relay_client")?.status.success());
    wait(|| Ok(raw()?["relay"]["completed"] == 1))
        .map_err(|error| format!("fresh relay completion: {error}; state: {:?}", status()))?;
    assert_eq!(raw()?["process_id"], pid);
    let before_limits = raw()?["revision"].clone();
    lab.change("set tunnel-detour.inbound.relay_connections='3'")?;
    wait(|| {
        let state = raw()?;
        Ok(state["revision"] != before_limits && state["applied"] == true)
    })?;
    assert_eq!(raw()?["process_id"], pid);
    assert_eq!(raw()?["observability"], true);
    assert_eq!(raw()?["relay"]["completed"], 1);
    let hold_observed_relay = || -> TestResult {
        for name in [
            "relay-client-ready",
            "relay-client-release",
            "relay-client-complete",
        ] {
            lab.exec(&["rm", &format!("/tmp/inbound-test/{name}")], None)?;
        }
        lab.spawn_inbound_probe("relay_holding")?;
        marker("td-in-wan", "relay-client-ready")?;
        wait(|| {
            Ok(raw()?["relay"]["connections"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1))
        })
    };
    hold_observed_relay()?;
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    marker("td-in-wan", "relay-client-complete")?;
    wait(|| Ok(raw()?["relay"]["completed"] == 2))?;

    // The management web server owns port 80. This candidate parses, and its
    // operational validation must reject it before rewriting the live policy.
    hold_observed_relay()?;
    let previous = raw()?;
    lab.change("set tunnel-detour.inbound.relay_port='80'")?;
    wait(|| {
        let state = raw()?;
        Ok(state["port_conflict"]["location"] == "relay_listener"
            && state["port_conflict"]["port"] == 80)
    })?;
    assert_diagnostics_off(&raw()?, &["relay"]);
    let rejected = status()?;
    assert_eq!(rejected["observability_requested"], true);
    assert_eq!(rejected["observability_revocation_pending"], false);
    let state = &rejected["status"];
    assert_eq!(state["applied"], false);
    assert_eq!(state["phase"], "ready");
    assert_eq!(state["process_id"], pid);
    assert_eq!(state["revision"], previous["revision"]);
    assert_eq!(state["public_addresses"], previous["public_addresses"]);
    assert_eq!(state["publications"], previous["publications"]);
    assert_diagnostics_off(state, &["relay"]);
    assert!(lab.inbound_probe("relay_client")?.status.success());
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    marker("td-in-wan", "relay-client-complete")?;
    lab.change("delete tunnel-detour.inbound.relay_port")?;
    wait(|| Ok(raw()?["applied"] == true && raw()?["observability"] == true))?;
    let restored = raw()?;
    assert_eq!(restored["process_id"], pid);
    assert_eq!(restored["relay"]["connections"], json!([]));
    assert_eq!(restored["relay"]["completed"], 0);

    lab.change("delete tunnel-detour.inbound.enabled")?;
    wait(|| Ok(raw()?["last_error"].is_string()))?;
    assert_eq!(raw()?["process_id"], pid);
    assert!(lab.inbound_probe("relay_client")?.status.success());
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    wait(|| Ok(raw()?["applied"] == true))?;
    let journal: Value = serde_json::from_slice(
        &lab.exec(&["cat", "/etc/tunnel-detour/inbound/state.json"], None)?,
    )?;
    assert!(journal["control"].get("observability").is_none());
    assert!(journal["control"].get("observability_epoch").is_none());
    lab.change("set tunnel-detour.inbound.observability='0'")?;
    wait(|| Ok(raw()?["observability"] == false))?;
    assert_diagnostics_off(&raw()?, &["relay"]);
    assert_diagnostics_off(&status()?["status"], &["relay"]);
    assert_eq!(raw()?["process_id"], pid);
    lab.exec(
        &["uci", "batch"],
        Some(b"set tunnel-detour.inbound.enabled='off'\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
    wait(|| Ok(status()?["running"] == false))?;
    let denied = lab.inbound_probe("native_wan_dispatch_restricted")?;
    assert!(
        denied.status.success(),
        "the UCI off alias left the WAN publication active: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r159b_inbound_revocation_purges_an_unwritable_snapshot_without_retiring_sessions() -> TestResult
{
    const DIRECTORY: &str = "/tmp/inbound-status-quota";
    const STATUS: &str = "/tmp/inbound-status-quota/status.json";
    const FILLER: &str = "/tmp/inbound-status-quota/filler";
    const READY: &str = "/tmp/snapshot-inode-held";
    const RELEASE: &str = "/tmp/snapshot-inode-release";
    const CLOSED: &str = "/tmp/snapshot-inode-closed";

    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    lab.exec(&["mkdir", "-m", "700", DIRECTORY], None)?;
    lab.exec(
        &[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "mode=0700,nr_inodes=4",
            "tmpfs",
            DIRECTORY,
        ],
        None,
    )?;
    let status =
        || -> TestResult<Value> { Ok(serde_json::from_slice(&lab.exec(&["cat", STATUS], None)?)?) };
    let mut config = lab.inbound_configuration();
    config["status_file"] = json!(STATUS);
    config["observability"] = json!(true);
    config["lan_networks"] = json!(["2001:db8:1::/64", "192.0.2.0/24"]);
    config["rules"][0]["protocol"] = json!("tcp");
    config["rules"][0]["destination"] = json!("192.0.2.2:8080");
    lab.start_inbound(&config)?;
    lab.spawn_inbound_probe("relay_holding")?;
    wait(|| {
        Ok(status().is_ok_and(|status| {
            status["relay"]["connections"]
                .as_array()
                .is_some_and(|sessions| sessions.len() == 1)
        }))
    })?;
    let before = status()?;
    let pid = before["process_id"]
        .as_u64()
        .filter(|pid| *pid > 1)
        .ok_or("missing active controller")?
        .to_string();

    lab.exec(&["kill", "-STOP", &pid], None)?;
    let prepared = (|| -> TestResult {
        wait(|| {
            Ok(lab
                .raw(
                    &[
                        "grep",
                        "-q",
                        "^State:[[:space:]]*T",
                        &format!("/proc/{pid}/status"),
                    ],
                    None,
                )?
                .status
                .success())
        })?;
        // The directory and writer lock occupy two slots. Keep the previous
        // snapshot and any interrupted replacement allocated in the other two,
        // even after they are unlinked.
        let holder = lab
            .background_command(&[
                "sh",
                "-c",
                "exec 3<\"$1\"; held=1\n\
                 for file in \"${1%/*}\"/.[!.]*; do\n\
                     test -f \"$file\" || continue\n\
                     exec 4<\"$file\"; held=2\n\
                 done\n\
                 printf '%s' \"$held\" > \"$2\" || exit 1\n\
                 for second in $(seq 1 45); do\n\
                     if test -e \"$3\"; then\n\
                         exec 3<&- 4<&-; touch \"$4\"; exit $?\n\
                     fi\n\
                     sleep 1\n\
                 done\n\
                 exit 1",
                "snapshot-inode-holder",
                STATUS,
                READY,
                RELEASE,
                CLOSED,
            ])?
            .spawn()?;
        lab.background.borrow_mut().push(holder);
        wait(|| Ok(lab.raw(&["test", "-s", READY], None)?.status.success()))?;
        if lab.exec(&["cat", READY], None)? == b"1" {
            lab.exec(&["touch", FILLER], None)?;
        }
        let refused = lab.raw(&["touch", "/tmp/inbound-status-quota/probe"], None)?;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("No space left on device"));
        config["observability"] = json!(false);
        lab.exec(
            &["tee", "/tmp/inbound-config.json"],
            Some(&serde_json::to_vec(&config)?),
        )?;
        lab.exec(&["kill", "-HUP", &pid], None)?;
        Ok(())
    })();
    let resumed = lab.exec(&["kill", "-CONT", &pid], None);
    prepared?;
    resumed?;

    let unpublished = || -> TestResult<bool> {
        Ok(lab
            .raw(&["test", "!", "-e", STATUS], None)?
            .status
            .success())
    };
    wait(unpublished)?;
    assert!(lab.inbound_probe("relay_client")?.status.success());
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-complete")?
            .status
            .success())
    })?;
    assert!(
        unpublished()?,
        "the snapshot reappeared before the fault was removed"
    );
    lab.exec(&["rm", "-f", FILLER], None)?;
    lab.exec(&["touch", RELEASE], None)?;
    wait(|| Ok(lab.raw(&["test", "-e", CLOSED], None)?.status.success()))?;
    wait(|| {
        Ok(status().is_ok_and(|status| {
            status["process_id"] == before["process_id"]
                && status["applied"] == true
                && status["phase"] == "ready"
                && status["observability"] == false
                && status.get("relay").is_none()
        }))
    })?;
    assert_eq!(status()?["publications"], before["publications"]);
    lab.exec(&["kill", "-TERM", &pid], None)?;
    wait(|| Ok(status().is_ok_and(|status| status["phase"] == "stopped")))?;
    lab.exec(&["umount", DIRECTORY], None)?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r055_wan_loss_blocks_native_and_relay_replies_without_vpn_fallback_and_offline_stop_cleans_owned_state()
-> TestResult {
    for relay in [false, true] {
        inbound_wan_loss(relay)?;
    }
    Ok(())
}

fn inbound_wan_loss(relay: bool) -> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.prepare_inbound_uci()?;
    if relay {
        lab.spawn_inbound_probe("relay_server")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
                .status
                .success())
        })?;
        lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'")?;
    }
    lab.change("set tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["phase"] == "ready")
    })?;
    lab.spawn_inbound_probe(if relay {
        "relay_wan_failure"
    } else {
        "wan_failure"
    })?;
    wait(|| {
        Ok(lab
            .raw(&["test", "-e", "/tmp/inbound-test/wan-failure-ready"], None)?
            .status
            .success())
    })?;
    let vpn_packets = || -> TestResult<u64> {
        let links: Value = serde_json::from_slice(
            &lab.exec(&["ip", "-j", "-s", "link", "show", "tdvpn0"], None)?,
        )?;
        links[0]["stats64"]["tx"]["packets"]
            .as_u64()
            .ok_or_else(|| "missing VPN packet count".into())
    };
    let before = vpn_packets()?;
    let dns = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.exec(&["ip", "link", "set", "tdwan0", "down"], None)?;
    // The backend sends real TCP bytes on the previously established publication while
    // WAN is unavailable. Observing route text alone would not prove packet isolation.
    lab.exec(
        &[
            "touch",
            if relay {
                "/tmp/inbound-test/push-from-relay-server"
            } else {
                "/tmp/inbound-test/push-from-server"
            },
        ],
        None,
    )?;
    wait(|| {
        Ok(lab
            .raw(&["test", "-e", "/tmp/inbound-test/server-pushed"], None)?
            .status
            .success())
    })?;
    lab.exec(&["touch", "/tmp/inbound-test/check-wan"], None)?;
    wait(|| {
        Ok(lab
            .raw(
                &["test", "-e", "/tmp/inbound-test/wan-failure-observed"],
                None,
            )?
            .status
            .success())
    })?;
    assert_eq!(
        vpn_packets()?,
        before,
        "publication reply bytes escaped through the ordinary VPN device"
    );
    let selected = lab.raw(
        &[
            "ip",
            "-j",
            "-6",
            "route",
            "get",
            "2001:db8:3::2",
            "mark",
            "1413742593",
        ],
        None,
    )?;
    if selected.status.success() {
        let route: Value = serde_json::from_slice(&selected.stdout)?;
        assert_eq!(
            route[0]["dev"], "tdwan0",
            "a link-down route may remain selected but must never fall back to VPN"
        );
    } else {
        assert!(
            String::from_utf8_lossy(&selected.stderr).contains("unreachable"),
            "unexpected routing failure: {}",
            String::from_utf8_lossy(&selected.stderr)
        );
    }
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| {
        Ok(!lab
            .raw(
                &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
                None,
            )?
            .status
            .success())
    })?;
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns);
    assert!(
        !lab.ubus("uci", "get", json!({"config":"firewall"}))?["values"]
            .as_object()
            .ok_or("missing firewall")?
            .contains_key("td_in_sample_0")
    );
    let priorities: Value =
        serde_json::from_slice(&lab.exec(&["ip", "-j", "-6", "rule", "show"], None)?)?;
    assert!(
        !priorities
            .as_array()
            .ok_or("missing priorities")?
            .iter()
            .any(|rule| rule["priority"] == 100)
    );
    assert!(
        lab.ubus("system", "board", json!({}))?["kernel"].is_string(),
        "router administration must remain available"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r054_changed_and_disabled_publications_close_their_flows_while_other_publications_keep_their_connections()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let accelerated = lab.vm.is_some();
    if accelerated {
        enable_software_flow_offload(&lab)?;
    }
    let mut config = lab.inbound_configuration();
    let mut stable = config["rules"][0].clone();
    stable["id"] = json!("stable");
    stable["name"] = json!("Unaffected publication");
    stable["protocol"] = json!("tcp_udp");
    stable["public_port"] = json!(18081);
    config["rules"]
        .as_array_mut()
        .ok_or("missing rules")?
        .push(stable);
    let controller_index = lab.background.borrow().len();
    lab.start_inbound(&config)?;
    let foreign_set = accelerated.then(|| large_foreign_set(&lab)).transpose()?;
    let state = || -> TestResult<Value> {
        Ok(serde_json::from_slice(
            &lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?,
        )?)
    };
    let initial = state()?["admissions"].clone();
    let marker = |name: &str| -> TestResult {
        let result = wait(|| {
            Ok(lab
                .raw(&["test", "-e", &format!("/tmp/inbound-test/{name}")], None)?
                .status
                .success())
        });
        if result.is_err() {
            for arguments in [
                vec!["nft", "list", "table", "inet", "tunnel_detour_inbound"],
                vec!["ip", "-j", "-N", "-6", "route", "show", "table", "41900"],
                vec!["conntrack", "-L", "--family", "ipv6"],
                vec!["cat", "/tmp/inbound-test/status.json"],
            ] {
                let output = lab.raw(&arguments, None)?;
                eprintln!(
                    "missing marker {name}: {arguments:?}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        result
    };
    if accelerated {
        observe_inbound_forward(&lab)?;
    }
    lab.spawn_inbound_probe("holding")?;
    marker("holding-ready")?;
    let is_offloaded = |mark: &str, protocol: &str| -> TestResult<bool> {
        let output = lab.exec(
            &[
                "conntrack",
                "-L",
                "--family",
                "ipv6",
                "--proto",
                protocol,
                "--mark",
                mark,
            ],
            None,
        )?;
        Ok(String::from_utf8_lossy(&output)
            .lines()
            .any(|line| line.contains("[OFFLOAD]")))
    };
    let forwarded_packets = || inbound_forwarded_packets(&lab);
    if accelerated {
        wait(|| {
            Ok(is_offloaded("1413742593", "tcp")?
                && is_offloaded("1413742594", "tcp")?
                && is_offloaded("1413742593", "udp")?
                && is_offloaded("1413742594", "udp")?)
        })
        .map_err(|error| {
            format!(
                "flow acceleration did not engage: {error}; conntrack: {}; flowtable: {}",
                String::from_utf8_lossy(
                    &lab.exec(&["conntrack", "-L", "--family", "ipv6"], None)
                        .unwrap_or_default()
                ),
                String::from_utf8_lossy(
                    &lab.exec(&["nft", "list", "table", "inet", "fw4"], None)
                        .unwrap_or_default()
                )
            )
        })?;
        let before = forwarded_packets()?;
        assert!(
            before > 0,
            "the forward probe missed the initial native traffic"
        );
        assert!(
            lab.inbound_marker("td-in-wan", "touch", "check-fastpath")?
                .status
                .success()
        );
        marker("holding-fastpath-checked")?;
        assert_eq!(
            forwarded_packets()?,
            before,
            "verified TCP payload must use the fastpath instead of traversing the ordinary forward guard"
        );
    }
    config["rules"][0]["destination"] = json!("[2001:db8:1::2]:8081");
    lab.reload_inbound(&config)?;
    if let Some(fingerprint) = &foreign_set {
        assert_eq!(foreign_set_fingerprint(&lab)?, *fingerprint);
    }
    assert_ne!(state()?["admissions"]["sample"], initial["sample"]);
    assert_eq!(state()?["admissions"]["stable"], initial["stable"]);
    assert!(
        lab.inbound_marker("td-in-wan", "touch", "check-change")?
            .status
            .success()
    );
    marker("holding-changed")?;
    config["rules"][0]["destination"] = json!("[2001:db8:1::2]:8080");
    lab.reload_inbound(&config)?;
    let changed = state()?["admissions"].clone();
    assert_ne!(changed["sample"], initial["sample"]);
    assert!(
        lab.inbound_marker("td-in-wan", "touch", "check-reenable")?
            .status
            .success()
    );
    marker("holding-reenabled")?;
    let fresh = lab.inbound_probe("client")?;
    assert!(
        fresh.status.success(),
        "new flows failed after destination restoration: {}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    config["rules"][0]["enabled"] = json!(false);
    lab.reload_inbound(&config)?;
    assert!(state()?["admissions"].get("sample").is_none());
    assert_eq!(state()?["admissions"]["stable"], initial["stable"]);
    assert!(
        lab.inbound_marker("td-in-wan", "touch", "check-disable")?
            .status
            .success()
    );
    marker("holding-disabled")?;
    config["rules"][0]["enabled"] = json!(true);
    lab.reload_inbound(&config)?;
    assert_ne!(state()?["admissions"]["sample"], changed["sample"]);
    assert!(
        lab.inbound_marker("td-in-wan", "touch", "check-final")?
            .status
            .success()
    );
    marker("holding-complete")?;
    assert_eq!(state()?["admissions"]["stable"], initial["stable"]);
    if accelerated {
        wait(|| Ok(is_offloaded("1413742594", "tcp")? && is_offloaded("1413742594", "udp")?))?;
        let defaults = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
        assert!(
            defaults["values"]
                .as_object()
                .ok_or("missing firewall configuration")?
                .values()
                .any(|section| section[".type"] == "defaults" && section["flow_offloading"] == "1"),
            "reconciliation must preserve enabled acceleration"
        );
    }
    assert!(
        lab.inbound_marker("td-in-wan", "touch", "release-holding")?
            .status
            .success()
    );
    marker("holding-released")?;
    if let Some(fingerprint) = foreign_set {
        let backend_bytes = || -> TestResult<[u64; 2]> {
            let counts = lab.exec(&["cat", "/tmp/inbound-test/r054-backend-counts"], None)?;
            Ok(serde_json::from_slice(&counts)?)
        };
        lab.exec(&["touch", "/tmp/inbound-test/r054-count-backend"], None)?;
        wait(|| {
            Ok(lab
                .raw(
                    &["test", "-e", "/tmp/inbound-test/r054-backend-counts"],
                    None,
                )?
                .status
                .success())
        })?;
        let zero = backend_bytes()?;
        lab.spawn_inbound_probe("holding_for_stop")?;
        marker("holding-stop-ready")?;
        wait(|| Ok(is_offloaded("1413742594", "tcp")? && is_offloaded("1413742594", "udp")?))?;
        let delivered = backend_bytes()?;
        assert!(
            delivered[0] > zero[0] && delivered[1] > zero[1],
            "observer must detect real TCP and UDP payload"
        );
        // Keep nftables writes and all other reads working. Losing the offload
        // inventory must not leave either new or accelerated flows admitted.
        let failed = || -> TestResult {
            let current: Value = serde_json::from_slice(
                &lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?,
            )?;
            let pid = current["process_id"]
                .as_u64()
                .ok_or("missing inbound PID")?;
            lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
            let guard_closed = || -> TestResult<bool> {
                let guard = lab.exec(
                    &[
                        "nft",
                        "-s",
                        "list",
                        "chain",
                        "inet",
                        "tunnel_detour_inbound",
                        "tag",
                    ],
                    None,
                )?;
                Ok(!String::from_utf8(guard)?.contains("ct mark set"))
            };
            wait(guard_closed)?;
            wait(
                || Ok(!is_offloaded("1413742594", "tcp")? && !is_offloaded("1413742594", "udp")?),
            )?;
            lab.exec(&["test", "-e", "/tmp/r054-offload-inspection-failed"], None)?;
            let mut controller = lab.background.borrow_mut().remove(controller_index);
            wait(|| Ok(controller.try_wait()?.is_some()))?;
            let result = controller.wait_with_output()?;
            assert_eq!(result.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&result.stderr).contains("kernel_conflict"));
            Ok(())
        };
        lab.with_command_fault(
            "nft",
            "r054-inspection",
            r#"if [ "$*" = '--json list flowtables' ]; then
  touch /tmp/r054-offload-inspection-failed
  exit 1
fi"#,
            failed,
        )?;
        assert!(
            lab.inbound_marker("td-in-wan", "touch", "check-failed-stop")?
                .status
                .success()
        );
        marker("holding-stop-closed")?;
        assert!(lab.inbound_probe("native_stable_closed")?.status.success());
        assert_eq!(
            backend_bytes()?,
            delivered,
            "no old or fresh probe bytes may reach the backend after containment"
        );
        assert_eq!(foreign_set_fingerprint(&lab)?, fingerprint);
        verify_second_retirement_fault(&lab, &config)?;
    } else {
        lab.stop_inbound()?;
    }
    Ok(())
}

fn verify_second_retirement_fault(lab: &Lab, config: &Value) -> TestResult {
    lab.exec(
        &[
            "rm",
            "-f",
            "/tmp/inbound-test/holding-stop-ready",
            "/tmp/inbound-test/holding-stop-closed",
            "/tmp/inbound-test/check-failed-stop",
            "/tmp/r054-offload-inspection-failed",
        ],
        None,
    )?;
    let controller_index = lab.background.borrow().len();
    lab.start_inbound(config)?;
    let status: Value =
        serde_json::from_slice(&lab.exec(&["cat", "/tmp/inbound-test/state.json"], None)?)?;
    let generation = status["admissions"]["stable"]
        .as_u64()
        .ok_or("missing stable generation")?;
    let mark = (0x5444_0000_u64 | generation).to_string();
    let entries = |mark: &str| {
        lab.exec(
            &["conntrack", "-L", "--family", "ipv6", "--mark", mark],
            None,
        )
    };
    lab.spawn_inbound_probe("holding_for_stop")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "holding-stop-ready")?
            .status
            .success())
    })?;
    wait(|| {
        let listing = String::from_utf8(entries(&mark)?)?;
        Ok(["tcp", "udp"].iter().all(|protocol| {
            listing
                .lines()
                .any(|line| line.starts_with(protocol) && line.contains("[OFFLOAD]"))
        }))
    })?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"table inet lab_control {\n chain mark_control {\n type filter hook prerouting priority -102;\n ip6 daddr 2001:db8:2::1 udp dport 18085 ct mark set 0x43430001\n }\n}\n"),
    )?;
    start_unmarked_router_server(lab)?;
    assert!(
        lab.inbound_probe("unmarked_router_client")?
            .status
            .success()
    );
    let foreign_mark = 0x4343_0001_u32.to_string();
    assert!(
        !entries(&foreign_mark)?.is_empty(),
        "the control flow must actually carry an unrelated mark"
    );
    let guard = || {
        lab.exec(
            &[
                "nft",
                "-s",
                "-a",
                "list",
                "table",
                "inet",
                "tunnel_detour_inbound",
            ],
            None,
        )
    };
    let previous = guard()?;
    let result = lab.with_command_fault(
        "nft",
        "r054-containment",
        r#"case "$*" in
  '--json list flowtables') touch /tmp/r054-offload-inspection-failed; exit 1 ;;
  '--file -') cat >/dev/null; touch /tmp/r054-guard-write-failed; exit 1 ;;
esac"#,
        || {
            let state: Value = serde_json::from_slice(
                &lab.exec(&["cat", "/tmp/inbound-test/status.json"], None)?,
            )?;
            let pid = state["process_id"].as_u64().ok_or("missing inbound PID")?;
            lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
            let mut child = lab.background.borrow_mut().remove(controller_index);
            wait(|| Ok(child.try_wait()?.is_some()))?;
            Ok(child.wait_with_output()?)
        },
    )?;
    lab.exec(&["test", "-e", "/tmp/r054-offload-inspection-failed"], None)?;
    lab.exec(&["test", "-e", "/tmp/r054-guard-write-failed"], None)?;
    assert_eq!(result.status.code(), Some(1));
    let errors = String::from_utf8(result.stderr)?;
    assert!(
        errors.contains("initial=\"kernel_conflict\"") && errors.contains("conntrack=\"purged\""),
        "{errors}"
    );
    assert!(
        errors.contains("inbound emergency containment could not be fully verified")
            && errors.contains("guard=\"kernel_command_failed\""),
        "{errors}"
    );
    assert_eq!(
        guard()?,
        previous,
        "the fixture must prevent the guard update, not claim it succeeded"
    );
    assert!(
        entries(&mark)?.is_empty(),
        "owned IPv6 conntrack state must be purged despite the guard failure"
    );
    assert!(
        !entries(&foreign_mark)?.is_empty(),
        "purging the package prefix must preserve the independent flow"
    );
    lab.inbound_marker("td-in-wan", "touch", "unmarked-router-stop")?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r053_inbound_refuses_foreign_ipv6_routing_tables_priorities_and_firewall_ownership_without_mutation()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    let config = lab.inbound_configuration();
    lab.exec(
        &["tee", "/tmp/inbound-config.json"],
        Some(&serde_json::to_vec(&config)?),
    )?;
    let rejected = || -> TestResult<String> {
        let before = lab.exec(&["nft", "-j", "-a", "list", "ruleset"], None)?;
        let routing = lab.exec(&["ip", "-j", "-6", "route", "show", "table", "all"], None)?;
        let priorities = lab.exec(&["ip", "-j", "-6", "rule", "show"], None)?;
        let firewall = lab.exec(&["uci", "export", "firewall"], None)?;
        let attempt = lab.raw(
            &[
                "/usr/bin/tunnel-detour",
                "--inbound-config",
                "/tmp/inbound-config.json",
            ],
            None,
        )?;
        assert!(!attempt.status.success(), "foreign ownership was adopted");
        // Ignore counters and handles when checking the foreign kernel firewall: ordinary
        // management traffic may increment counters while the read-only check is running.
        let normalize = |bytes: &[u8]| -> TestResult<Value> {
            let mut value: Value = serde_json::from_slice(bytes)?;
            fn strip(value: &mut Value) {
                match value {
                    Value::Object(object) => {
                        object.remove("counter");
                        for value in object.values_mut() {
                            strip(value);
                        }
                    }
                    Value::Array(array) => {
                        for value in array {
                            strip(value);
                        }
                    }
                    _ => {}
                }
            }
            strip(&mut value);
            Ok(value)
        };
        assert_eq!(
            normalize(&before)?,
            normalize(&lab.exec(&["nft", "-j", "-a", "list", "ruleset"], None)?)?
        );
        assert_eq!(
            lab.exec(&["ip", "-j", "-6", "route", "show", "table", "all"], None)?,
            routing
        );
        assert_eq!(
            lab.exec(&["ip", "-j", "-6", "rule", "show"], None)?,
            priorities
        );
        assert_eq!(lab.exec(&["uci", "export", "firewall"], None)?, firewall);
        Ok(String::from_utf8(attempt.stderr)?)
    };
    if lab.vm.is_some() {
        lab.exec(
            &["nft", "-f", "-"],
            Some(b"table inet unrelated {\n flowtable unrelated { hook ingress priority 10; devices = { tdwan0 }; }\n}\n"),
        )?;
        assert!(rejected()?.contains("kernel_conflict"));
        return Ok(());
    }
    for priority in ["50", "100"] {
        lab.exec(
            &[
                "ip", "-6", "rule", "add", "priority", priority, "lookup", "41999",
            ],
            None,
        )?;
        rejected()?;
        lab.exec(
            &[
                "ip", "-6", "rule", "del", "priority", priority, "lookup", "41999",
            ],
            None,
        )?;
    }
    // Even the project's protocol tag is insufficient authority on a cold start.
    lab.exec(
        &[
            "ip",
            "-6",
            "route",
            "add",
            "unreachable",
            "default",
            "proto",
            "242",
            "table",
            "41900",
        ],
        None,
    )?;
    rejected()?;
    lab.exec(
        &[
            "ip",
            "-6",
            "route",
            "del",
            "unreachable",
            "default",
            "proto",
            "242",
            "table",
            "41900",
        ],
        None,
    )?;
    for owner in ["foreign-owner", "tunnel-detour:inbound:v1"] {
        lab.exec(
            &["nft", "--file", "-"],
            Some(
                format!("table inet tunnel_detour_inbound {{ comment \"{owner}\"; }}\n").as_bytes(),
            ),
        )?;
        rejected()?;
        lab.exec(
            &["nft", "delete", "table", "inet", "tunnel_detour_inbound"],
            None,
        )?;
    }
    lab.exec(&["uci", "batch"], Some(b"set firewall.td_in_sample_0=redirect\nset firewall.td_in_sample_0.name='Administrator-owned section'\nset firewall.td_in_sample_0.src='wan'\nset firewall.td_in_sample_0.dest='lan'\nset firewall.td_in_sample_0.src_dport='18080'\nset firewall.td_in_sample_0.dest_ip='2001:db8:1::2'\nset firewall.td_in_sample_0.dest_port='8080'\nset firewall.td_in_sample_0.family='ipv6'\nset firewall.td_in_sample_0.proto='tcp'\ncommit firewall\n"))?;
    rejected()?;
    // A different section name sharing a public endpoint also requires explicit review.
    lab.exec(
        &[
            "uci",
            "rename",
            "firewall.td_in_sample_0=administrator_rule",
        ],
        None,
    )?;
    lab.exec(&["uci", "commit", "firewall"], None)?;
    rejected()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan() -> TestResult
{
    if let Ok(role) = env::var("TUNNEL_DETOUR_INBOUND_PROBE") {
        return inbound_endpoint_probe(&role);
    }
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "fd00:1234::1/64",
            "dev",
            "tdlan0",
            "nodad",
        ],
        None,
    )?;
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-lan",
            "-6",
            "addr",
            "add",
            "fd00:1234::2/64",
            "dev",
            "peer0",
            "nodad",
        ],
        None,
    )?;
    lab.spawn_inbound_probe("ula_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "ula-endpoint-ready")?
            .status
            .success())
    })?;
    lab.inbound_wireguard()?;
    let baseline = lab.inbound_probe("vpn_client")?;
    assert!(
        baseline.status.success(),
        "ordinary LAN traffic must traverse real WireGuard: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let encrypted = lab.inbound_vpn_transfer()?;
    assert!(
        encrypted.iter().all(|bytes| *bytes > 0),
        "both directions of the ordinary flow must use encrypted transport"
    );
    let plaintext = lab.inbound_vpn_plaintext()?;
    let dns = lab.exec(&["uci", "export", "dhcp"], None)?;
    let firewall = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"add chain inet fw4 dstnat_wan\nadd rule inet fw4 dstnat_wan ip6 daddr 2001:db8:2::1 udp dport 18085 redirect to :18086 comment \"lab unrelated redirect\"\n"),
    )?;
    let dormant_chain = || {
        lab.exec(
            &[
                "nft",
                "-s",
                "-a",
                "list",
                "chain",
                "inet",
                "fw4",
                "dstnat_wan",
            ],
            None,
        )
    };
    let dormant = dormant_chain()?;
    start_unmarked_router_server(&lab)?;
    let classifier = instrument_wan_classifier(&lab)?;
    let unmarked_probe = || -> TestResult {
        let [before, reference_before] = classifier_counts(&lab)?;
        assert_eq!(
            before, reference_before,
            "no extra observations before the probe"
        );
        let logged_before = lab
            .vm
            .is_some()
            .then(|| classifier_log_count(&lab))
            .transpose()?;
        let result = lab.inbound_probe("unmarked_router_client")?;
        assert!(
            result.status.success(),
            "unmarked traffic must still reach the original router port: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let [after, reference_after] = classifier_counts(&lab)?;
        assert!(
            after > before,
            "the original classifier must count the ordinary datagram"
        );
        assert_eq!(
            after, reference_after,
            "the NAT dispatch must not duplicate the original counter"
        );
        if let Some(previous) = logged_before {
            assert_eq!(
                classifier_log_count(&lab)?,
                previous + 1,
                "the guest kernel must record exactly one observation of the ordinary probe"
            );
        }
        assert_eq!(live_wan_classifier(&lab)?, classifier);
        Ok(())
    };
    unmarked_probe()?;
    let mut configuration = lab.inbound_configuration();
    configuration["lan_networks"] = json!(["2001:db8:1::/64", "fd00:1234::/64"]);
    let mut ula = configuration["rules"][0].clone();
    ula["id"] = json!("ula");
    ula["name"] = json!("ULA destination");
    ula["public_port"] = json!(18082);
    ula["destination"] = json!("[fd00:1234::2]:8080");
    configuration["rules"]
        .as_array_mut()
        .ok_or("missing publications")?
        .push(ula);
    lab.start_inbound(&configuration)?;
    let base: Value = serde_json::from_slice(&lab.exec(
        &[
            "nft", "-j", "-s", "-a", "list", "chain", "inet", "fw4", "dstnat",
        ],
        None,
    )?)?;
    let dispatch = base["nftables"]
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|entry| {
                let rule = &entry["rule"];
                let expr = rule["expr"].as_array()?;
                (rule["comment"] == "tunnel-detour:inbound-dispatch:v1"
                    && expr.last()?["jump"]["target"] == "dstnat_wan")
                    .then_some(expr)
            })
        })
        .ok_or("missing package WAN dispatch")?;
    assert!(
        dispatch
            .iter()
            .all(|statement| statement.get("log").is_none() && statement.get("counter").is_none()),
        "the live package dispatch must not copy the administrator's logging or counters"
    );
    unmarked_probe()?;
    let probe = lab.inbound_probe("client")?;
    if !probe.status.success() {
        for arguments in [
            vec!["nft", "list", "ruleset"],
            vec!["conntrack", "-L", "--family", "ipv6"],
            vec!["ip", "-6", "route", "show", "table", "all"],
            vec!["ip", "-6", "rule", "show"],
            vec!["ip", "-6", "address", "show"],
        ] {
            let result = lab.raw(&arguments, None)?;
            eprintln!(
                "{arguments:?}: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
    assert!(
        probe.status.success(),
        "{} {}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    let ula_probe = lab.inbound_probe("ula_client")?;
    assert!(
        ula_probe.status.success(),
        "ULA traffic did not reach the distinct ULA endpoint: {}",
        String::from_utf8_lossy(&ula_probe.stderr)
    );
    assert_eq!(
        lab.inbound_vpn_plaintext()?,
        plaintext,
        "native publication traffic must not enter the WireGuard tunnel"
    );
    let unmarked: Value = serde_json::from_slice(
        &lab.exec(&["ip", "-j", "-6", "route", "get", "2001:db8:3::2"], None)?,
    )?;
    assert_eq!(
        unmarked[0]["dev"], "tdvpn0",
        "ordinary traffic must retain the VPN default"
    );
    let marked: Value = serde_json::from_slice(&lab.exec(
        &[
            "ip",
            "-j",
            "-6",
            "route",
            "get",
            "2001:db8:3::2",
            "mark",
            "1413742593",
        ],
        None,
    )?)?;
    assert_eq!(marked[0]["dev"], "tdwan0");
    let current = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    for (name, original) in firewall["values"]
        .as_object()
        .ok_or("missing firewall fixture")?
    {
        assert_eq!(
            &current["values"][name], original,
            "foreign firewall section changed"
        );
    }
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns);
    lab.stop_inbound()?;
    unmarked_probe()?;
    assert_eq!(dormant_chain()?, dormant);
    lab.inbound_marker("td-in-wan", "touch", "unmarked-router-stop")?;
    let after = lab.ubus("uci", "get", json!({"config":"firewall"}))?;
    assert_eq!(
        after["values"]
            .as_object()
            .ok_or("missing final firewall")?
            .len(),
        firewall["values"]
            .as_object()
            .ok_or("missing initial firewall")?
            .len()
    );
    Ok(())
}

fn live_wan_classifier(lab: &Lab) -> TestResult<Value> {
    let rules: Value = serde_json::from_slice(&lab.exec(
        &[
            "nft", "-j", "-s", "-a", "list", "chain", "inet", "fw4", "input",
        ],
        None,
    )?)?;
    rules["nftables"]
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|entry| {
                let rule = &entry["rule"];
                (rule["expr"].as_array()?.last()?["jump"]["target"] == "input_wan")
                    .then(|| rule.clone())
            })
        })
        .ok_or_else(|| "missing original WAN input classifier".into())
}

fn instrument_wan_classifier(lab: &Lab) -> TestResult<Value> {
    let mut classifier = live_wan_classifier(lab)?;
    let handle = classifier["handle"]
        .as_u64()
        .ok_or("missing classifier handle")?;
    let expr = classifier["expr"]
        .as_array_mut()
        .ok_or("missing classifier expression")?;
    let jump = expr.pop().ok_or("missing classifier jump")?;
    let mut reference = expr.clone();
    reference.push(json!({"counter":"r052_reference"}));
    let logging = if lab.vm.is_some() {
        // Only the guest has its own kernel log; its image has no NFLOG backend.
        json!({"log":{"prefix":"r052 original classifier"}})
    } else {
        json!({"log":{"prefix":"r052 original classifier","group":64}})
    };
    expr.extend([json!({"counter":"r052_original"}), logging.clone(), jump]);
    let batch = json!({"nftables":[
        {"add":{"counter":{"family":"inet","table":"fw4","name":"r052_original"}}},
        {"add":{"counter":{"family":"inet","table":"fw4","name":"r052_reference"}}},
        {"insert":{"rule":{"family":"inet","table":"fw4","chain":"input","handle":handle,"expr":reference}}},
        {"replace":{"rule":classifier}}
    ]});
    lab.exec(
        &["nft", "-j", "-f", "-"],
        Some(&serde_json::to_vec(&batch)?),
    )?;
    let live = live_wan_classifier(lab)?;
    assert_eq!(live["handle"], handle);
    assert!(
        live["expr"]
            .as_array()
            .is_some_and(|items| items.contains(&logging))
    );
    Ok(live)
}

fn classifier_log_count(lab: &Lab) -> TestResult<u64> {
    if lab.vm.is_none() {
        return Err("the classifier kernel-log probe requires an isolated guest".into());
    }
    let count = lab.exec(
        &[
            "sh",
            "-c",
            "set -o pipefail; dmesg | awk '/r052 original classifier.*DPT=18085([[:space:]]|$)/ { count++ } END { print count+0 }'",
        ],
        None,
    )?;
    Ok(String::from_utf8(count)?.trim().parse()?)
}

fn classifier_counts(lab: &Lab) -> TestResult<[u64; 2]> {
    let listings: Value =
        serde_json::from_slice(&lab.exec(&["nft", "-j", "list", "counters", "inet"], None)?)?;
    let items = listings["nftables"]
        .as_array()
        .ok_or("missing counter listing")?;
    let packets = |name: &str| {
        items
            .iter()
            .find_map(|entry| {
                let counter = &entry["counter"];
                (counter["name"] == name && counter["table"] == "fw4")
                    .then(|| counter["packets"].as_u64())
                    .flatten()
            })
            .ok_or("missing classifier packet count")
    };
    Ok([packets("r052_original")?, packets("r052_reference")?])
}

fn start_unmarked_router_server(lab: &Lab) -> TestResult {
    // The fixture's WAN input policy rejects by default. Allow just the
    // isolated control source and both destinations so the reply can identify
    // whether an unexpected redirect changed the selected socket.
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"insert rule inet fw4 input_wan ip6 saddr 2001:db8:2::2 ip6 daddr 2001:db8:2::1 udp dport { 18085, 18086 } accept comment \"lab router control sockets\"\n"),
    )?;
    lab.spawn_inbound_probe("unmarked_router_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "unmarked-router-ready")?
            .status
            .success())
    })
}

fn inbound_endpoint_probe(role: &str) -> TestResult {
    use std::net::{TcpListener, TcpStream, UdpSocket};
    if env::var("TUNNEL_DETOUR_OPENWRT_LAB").as_deref() != Ok("1")
        && !std::path::Path::new("/etc/openwrt_release").exists()
    {
        return Err("inbound probes require the isolated OpenWrt laboratory".into());
    }
    match role {
        "unmarked_router_server" => {
            let original = UdpSocket::bind("[2001:db8:2::1]:18085")?;
            let redirected = UdpSocket::bind("[2001:db8:2::1]:18086")?;
            original.set_nonblocking(true)?;
            redirected.set_nonblocking(true)?;
            File::create("/tmp/inbound-test/unmarked-router-ready")?;
            let end = Instant::now() + Duration::from_secs(300);
            while Instant::now() < end
                && !std::path::Path::new("/tmp/inbound-test/unmarked-router-stop").exists()
            {
                for (socket, response) in [
                    (&original, &b"original"[..]),
                    (&redirected, &b"redirected"[..]),
                ] {
                    match socket.recv_from(&mut [0; 32]) {
                        Ok((_, peer)) => {
                            socket.send_to(response, peer)?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        "unmarked_router_client" => {
            let socket = UdpSocket::bind("[2001:db8:2::2]:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.connect("[2001:db8:2::1]:18085")?;
            socket.send(b"unmarked test")?;
            let mut bytes = [0; 32];
            let count = socket.recv(&mut bytes)?;
            assert_eq!(&bytes[..count], b"original");
        }
        "native_tcp_redirect_missing"
        | "native_wan_dispatch_restricted"
        | "native_stable_closed"
        | "native_candidate_closed" => {
            let port = match role {
                "native_stable_closed" => 18081,
                "native_candidate_closed" => 18083,
                _ => 18080,
            };
            match socket_addr_tcp("[2001:db8:3::2]:0", &format!("[2001:db8:2::1]:{port}")) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream_closed(&mut stream)?;
                }
                Err(error)
                    if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::PermissionDenied
                        )
                    }) => {}
                Err(error) => return Err(error),
            }
            let udp = inbound_udp(port)?;
            if role == "native_tcp_redirect_missing" {
                udp_echo(&udp, b"independent native UDP without TCP DNAT")?;
            } else {
                udp_closed(&udp)?;
            }
        }
        "cache_guard_lock" | "observability_lock" => {
            let name = role.replace('_', "-");
            File::create(format!("/tmp/{name}-ready"))?;
            wait_for(Duration::from_secs(15), || {
                Ok(std::path::Path::new(&format!("/tmp/{name}-release")).exists())
            })?;
        }
        "relay_capacity" => {
            let mut first = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")?;
            let mut second = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")?;
            File::create("/tmp/inbound-test/relay-capacity-ready")?;
            wait_file("check-relay-capacity")?;
            let mut excess = socket_addr_tcp("[2001:db8:3::2]:0", "[2001:db8:2::1]:18080")?;
            excess.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream_closed(&mut excess)?;
            stream_echo(
                &mut first,
                b"admitted first session survives capacity refusal",
            )?;
            stream_echo(
                &mut second,
                b"admitted second session survives capacity refusal",
            )?;
            File::create("/tmp/inbound-test/relay-capacity-rejected")?;
            wait_file("check-relay-new-limit")?;
            stream_closed(&mut first)?;
            stream_closed(&mut second)?;
            let mut fresh = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8081")?;
            let mut excess = socket_addr_tcp("[2001:db8:3::2]:0", "[2001:db8:2::1]:18080")?;
            excess.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream_closed(&mut excess)?;
            stream_echo(&mut fresh, b"reduced limit and new target are active")?;
            File::create("/tmp/inbound-test/relay-capacity-reconfigured")?;
            wait_file("check-relay-capacity-stop")?;
            stream_closed(&mut fresh)?;
            File::create("/tmp/inbound-test/relay-capacity-complete")?;
        }
        "relay_lifecycle" | "relay_lifecycle_fixture_failure" => {
            let mut original = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")
                .map_err(|error| format!("initial IPv4 relay: {error}"))?;
            if role == "relay_lifecycle_fixture_failure" {
                stream_echo(&mut original, b"fixture control echo")?;
                return Err("r079 synthetic initial probe failure after confirmed echo".into());
            }
            let mut stable = inbound_stream(18081)
                .map_err(|error| format!("initial native TCP publication: {error}"))?;
            let udp = inbound_udp(18081)?;
            stream_echo(&mut original, b"original relay before change")
                .map_err(|error| format!("IPv4 relay echo before retarget: {error}"))?;
            for _ in 0..3 {
                stream_echo(&mut stable, b"native stream before relay change")
                    .map_err(|error| format!("native TCP echo before relay retarget: {error}"))?;
                udp_echo(&udp, b"native UDP before relay change")
                    .map_err(|error| format!("native UDP echo before relay retarget: {error}"))?;
            }
            File::create("/tmp/inbound-test/relay-lifecycle-ready")?;
            if env::var("TUNNEL_DETOUR_EXPECT_OFFLOAD").as_deref() == Ok("1") {
                wait_file("check-relay-fastpath")?;
                stream_echo(
                    &mut stable,
                    b"native payload with mixed relay policy uses acceleration",
                )?;
                udp_echo(
                    &udp,
                    b"native UDP with mixed relay policy uses acceleration",
                )?;
                File::create("/tmp/inbound-test/relay-fastpath-checked")?;
            }
            wait_file("check-relay-retarget")?;
            stream_closed(&mut original)?;
            stream_echo(&mut stable, b"same native stream after relay target change")?;
            udp_echo(&udp, b"same native UDP after relay target change")?;
            let mut changed = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8081")?;
            stream_echo(&mut changed, b"new relay reaches the new fixed target")?;
            File::create("/tmp/inbound-test/relay-lifecycle-retargeted")?;
            wait_file("check-relay-disabled")?;
            stream_closed(&mut original)?;
            stream_closed(&mut changed)?;
            stream_echo(&mut stable, b"native stream survives relay disable")?;
            udp_echo(&udp, b"native UDP survives relay disable")?;
            File::create("/tmp/inbound-test/relay-lifecycle-disabled")?;
            wait_file("check-relay-restored")?;
            stream_closed(&mut original)?;
            stream_closed(&mut changed)?;
            stream_echo(&mut stable, b"native stream survives relay reenable")?;
            udp_echo(&udp, b"native UDP survives relay reenable")?;
            let mut fresh = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8081")?;
            stream_echo(
                &mut fresh,
                b"only a fresh relay session may use the restored rule",
            )?;
            File::create("/tmp/inbound-test/relay-lifecycle-restored")?;
            wait_file("check-relay-stopped")?;
            stream_closed(&mut fresh)?;
            File::create("/tmp/inbound-test/relay-lifecycle-complete")?;
        }
        "relay_direct_wan" => {
            blocked_inbound_tcp("[2001:db8:3::2]:0", "[2001:db8:2::1]:10537")?;
        }
        "lan_public_relay_blocked" => {
            blocked_inbound_tcp("[2001:db8:1::2]:0", "[2001:db8:2::1]:18080")?;
        }
        "lan_public_relay_internal" => {
            blocked_inbound_tcp("[2001:db8:1::2]:0", "[2001:db8:1::1]:10537")?;
            // A v6-only listener must not create an implicit IPv4 entry point either.
            let result =
                TcpStream::connect_timeout(&"192.0.2.1:10537".parse()?, Duration::from_secs(2));
            assert!(
                matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionRefused),
                "the capture socket was reachable over IPv4"
            );
        }
        "relay_direct_router" => {
            blocked_inbound_tcp("[::1]:0", "[::1]:10537")?;
        }
        "transport_start_refused" => {
            let mut stream = socket_addr_tcp("[2001:db8:3::2]:0", "[2001:db8:2::1]:18080")?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream_closed(&mut stream)?;
        }
        "relay_client"
        | "relay_recovery_client"
        | "relay_holding"
        | "lan_public_relay_client"
        | "updated_relay_client"
        | "transport_crash_holding"
        | "relay_crash_holding" => {
            let source = if role == "lan_public_relay_client" {
                "[2001:db8:1::2]:0"
            } else {
                "[2001:db8:3::2]:0"
            };
            let mut stream = if matches!(role, "updated_relay_client" | "relay_crash_holding") {
                relay_test_endpoint(source, "[2001:db8:2::10]:18080", "192.0.2.2:8080")?
            } else if role == "relay_recovery_client" {
                relay_test_stream(source, 18080, "192.0.2.2:8081")?
            } else {
                relay_test_stream(source, 18080, "192.0.2.2:8080")?
            };
            let bytes: Vec<_> = (0_u8..=255).collect();
            stream_echo(&mut stream, &bytes)?;
            if matches!(role, "relay_crash_holding" | "transport_crash_holding") {
                File::create("/tmp/inbound-test/relay-crash-ready")?;
                wait_file("check-relay-crash")?;
                stream_closed(&mut stream)?;
                File::create("/tmp/inbound-test/relay-crash-closed")?;
            }
            if role == "relay_holding" {
                std::fs::write(
                    "/tmp/inbound-test/relay-client-endpoint",
                    stream.local_addr()?.to_string(),
                )?;
                File::create("/tmp/inbound-test/relay-client-ready")?;
                // Control-plane scenarios can take multiple bounded steps while
                // the same client must stay connected through every step.
                wait_file_for("relay-client-release", 90)?;
                stream_echo(
                    &mut stream,
                    b"the observed original session is still active",
                )?;
                File::create("/tmp/inbound-test/relay-client-complete")?;
            }
        }
        "router_ports" => {
            let tcp = TcpListener::bind("127.0.0.1:18080")?;
            tcp.set_nonblocking(true)?;
            let udp = UdpSocket::bind("127.0.0.1:18081")?;
            udp.set_nonblocking(true)?;
            let inactive = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            inactive.set_only_v6(true)?;
            inactive.bind(&"[::1]:18082".parse::<std::net::SocketAddr>()?.into())?;
            File::create("/tmp/inbound-test/router-ports-ready")?;
            let deadline = Instant::now() + Duration::from_secs(120);
            while Instant::now() < deadline {
                match tcp.accept() {
                    Ok((mut stream, _)) => stream.write_all(b"router service retained")?,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                let mut packet = [0; 64];
                match udp.recv_from(&mut packet) {
                    Ok((_, peer)) => {
                        udp.send_to(b"router service retained", peer)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        "router_ports_control" => {
            let mut tcp =
                TcpStream::connect_timeout(&"127.0.0.1:18080".parse()?, Duration::from_secs(2))?;
            tcp.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut response = Vec::new();
            tcp.read_to_end(&mut response)?;
            assert_eq!(response, b"router service retained");
            let udp = UdpSocket::bind("127.0.0.1:0")?;
            udp.set_read_timeout(Some(Duration::from_secs(2)))?;
            udp.send_to(b"check retained UDP service", "127.0.0.1:18081")?;
            let mut packet = [0; 64];
            let (length, _) = udp.recv_from(&mut packet)?;
            assert_eq!(&packet[..length], b"router service retained");
        }
        "guard_baseline" => {
            stream_echo(
                &mut inbound_stream(19080)?,
                b"previous publication remains active",
            )?;
            udp_echo(&inbound_udp(19080)?, b"previous UDP remains active")?;
        }
        "lan_public_denied" => {
            assert!(
                socket_addr_tcp("[2001:db8:1::2]:0", "[2001:db8:2::1]:18080").is_err(),
                "WAN-only publication accepted a LAN connection"
            );
            let udp = lan_public_udp()?;
            udp_closed(&udp)?;
        }
        "lan_public_client" => {
            let mut stream = lan_public_stream()?;
            stream_echo(&mut stream, b"LAN TCP via the public endpoint")?;
            lan_public_udp_echo(&lan_public_udp()?, b"LAN UDP via the public endpoint")?;
        }
        "lan_public_holding" => {
            let mut stream = lan_public_stream()?;
            let udp = lan_public_udp()?;
            for _ in 0..4 {
                stream_echo(&mut stream, b"LAN TCP before mode change")?;
                lan_public_udp_echo(&udp, b"LAN UDP before mode change")?;
            }
            File::create("/tmp/inbound-test/lan-public-ready")?;
            if env::var("TUNNEL_DETOUR_EXPECT_OFFLOAD").as_deref() == Ok("1") {
                wait_file("check-lan-public-fastpath")?;
                for _ in 0..8 {
                    stream_echo(&mut stream, b"accelerated LAN TCP")?;
                    lan_public_udp_echo(&udp, b"accelerated LAN UDP")?;
                }
                File::create("/tmp/inbound-test/lan-public-fastpath-checked")?;
            }
            wait_file("check-lan-public-disabled")?;
            stream_closed(&mut stream)?;
            udp_closed(&udp)?;
            File::create("/tmp/inbound-test/lan-public-closed")?;
            wait_file("check-lan-public-restored")?;
            stream_closed(&mut stream)?;
            udp_closed(&udp)?;
            File::create("/tmp/inbound-test/lan-public-complete")?;
        }
        "other_control" => {
            let mut stream = socket_addr_tcp("[2001:db8:1::2]:0", "[2001:db8:1::3]:8080")?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let expected = format!(
                "peer={}\nlocal=[2001:db8:1::3]:8080\n",
                stream.local_addr()?
            );
            let mut header = vec![0; expected.len()];
            stream.read_exact(&mut header)?;
            assert_eq!(header, expected.as_bytes());
            stream_echo(&mut stream, b"a real unselected LAN endpoint")?;
        }
        "protocol_matrix" => {
            let mut tcp = inbound_stream(18080)?;
            stream_echo(&mut tcp, b"allowed TCP publication")?;
            let udp = inbound_udp(18081)?;
            udp_echo(&udp, b"allowed UDP publication")?;
            for port in [18081, 18082] {
                match socket_addr_tcp("[2001:db8:3::2]:0", &format!("[2001:db8:2::1]:{port}")) {
                    Err(error)
                        if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                            matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionRefused
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::PermissionDenied
                            )
                        }) => {}
                    Err(error) => return Err(error),
                    Ok(_) => return Err("an unpublished TCP endpoint accepted a connection".into()),
                }
            }
            for port in [18080, 18082] {
                udp_closed(&inbound_udp(port)?)?;
            }
            match socket_addr_tcp("[2001:db8:3::2]:0", "[2001:db8:1::3]:8080") {
                Err(error)
                    if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::PermissionDenied
                        )
                    }) => {}
                Err(error) => return Err(error),
                Ok(_) => return Err("publishing one host opened another LAN endpoint".into()),
            }
            for source in ["2001:db8:1::9", "2001:db8:ffff::1", "fd00:1234::9"] {
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                socket.set_freebind_v6(true)?;
                let address: std::net::SocketAddr = format!("[{source}]:28081").parse()?;
                socket.bind(&address.into())?;
                let destination: std::net::SocketAddr = "[2001:db8:2::1]:18081".parse()?;
                socket.send_to(
                    b"a forbidden WAN source must not reach LAN",
                    &destination.into(),
                )?;
            }
            udp_echo(&udp, b"valid control after the forged packets")?;
        }
        "context_holding" | "relay_context_holding" => {
            let relay = role == "relay_context_holding";
            let mut stream = if relay {
                relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")?
            } else {
                inbound_stream(18080)?
            };
            let udp = if relay {
                None
            } else {
                Some(inbound_udp(18080)?)
            };
            stream_echo(&mut stream, b"authorized before LAN change")?;
            if let Some(udp) = &udp {
                udp_echo(udp, b"authorized UDP before LAN change")?;
            }
            File::create("/tmp/inbound-test/context-ready")?;
            wait_file("check-context")?;
            stream_closed(&mut stream)?;
            if let Some(udp) = &udp {
                udp_closed(udp)?;
            }
            File::create("/tmp/inbound-test/context-closed")?;
            wait_file("check-context-restored")?;
            stream_closed(&mut stream)?;
            if let Some(udp) = &udp {
                udp_closed(udp)?;
            }
            File::create("/tmp/inbound-test/context-complete")?;
        }
        "cached_client4" => {
            let mut stream =
                TcpStream::connect_timeout(&"198.18.0.1:80".parse()?, Duration::from_secs(3))?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            let expected = format!("peer={}\n", stream.local_addr()?);
            let mut header = vec![0; expected.len()];
            stream.read_exact(&mut header)?;
            assert_eq!(header, expected.as_bytes());
            stream_echo(
                &mut stream,
                b"cached synthetic identity must never escape through VPN",
            )?;
        }
        "vpn_client" | "vpn_client4" => {
            let source = if role == "vpn_client4" {
                "192.0.2.2:0"
            } else {
                "[2001:db8:1::2]:0"
            };
            let destination = if role == "vpn_client4" {
                "198.51.100.40:18090"
            } else {
                "[2001:db8:4::2]:18090"
            };
            let socket = UdpSocket::bind(source)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let payload = b"ordinary LAN traffic through real WireGuard";
            socket.send_to(payload, destination)?;
            let mut response = [0; 256];
            let (length, peer) = socket.recv_from(&mut response)?;
            assert_eq!(peer, destination.parse()?);
            let mut expected = format!("peer={}\n", socket.local_addr()?).into_bytes();
            expected.extend_from_slice(payload);
            assert_eq!(&response[..length], expected);
        }
        "updated_client" => {
            for port in [18082, 18083] {
                let mut stream = inbound_stream(port)?;
                stream_echo(
                    &mut stream,
                    b"traffic through a recovered native publication",
                )?;
            }
        }
        "dns_rejected" => {
            let mut stream =
                TcpStream::connect_timeout(&"198.18.0.1:80".parse()?, Duration::from_secs(3))?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            match stream.read(&mut [0; 1]) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                other => {
                    return Err(format!(
                        "a new DNS-proxy connection was not closed while fenced: {other:?}"
                    )
                    .into());
                }
            }
        }
        "dns_rejected6" => {
            let address = "[2001:2::c612:2]:80".parse()?;
            match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::PermissionDenied
                    ) => {}
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    match stream.read(&mut [0; 1]) {
                        Ok(0) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                            ) => {}
                        other => {
                            return Err(
                                format!("cached IPv6 identity was not fenced: {other:?}").into()
                            );
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        "dns_holding" | "dns_reloading" | "dns_once" | "dns_once6" => {
            let stem = if role == "dns_reloading" {
                "dns-reloading"
            } else {
                "dns-holding"
            };
            let mut stream = std::net::TcpStream::connect_timeout(
                &if role == "dns_once6" {
                    "[2001:2::c612:2]:80"
                } else {
                    "198.18.0.1:80"
                }
                .parse()?,
                Duration::from_secs(3),
            )?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let mut header = Vec::new();
            while header.last() != Some(&b'\n') && header.len() < 128 {
                let mut byte = [0];
                stream.read_exact(&mut byte)?;
                header.push(byte[0]);
            }
            assert!(
                String::from_utf8(header)?.starts_with(if role == "dns_once6" {
                    "peer=[2001:db8:2::1]:"
                } else {
                    "peer=203.0.113.1:"
                }),
                "the DNS exception must use WAN"
            );
            stream_echo(
                &mut stream,
                b"DNS proxy connection before configuration changes",
            )?;
            if matches!(role, "dns_once" | "dns_once6") {
                return Ok(());
            }
            File::create(format!("/tmp/inbound-test/{stem}-ready"))?;
            let hold_seconds = if env::var("TUNNEL_DETOUR_LUCI_REVIEW").as_deref() == Ok("1") {
                300
            } else {
                100
            };
            wait_for(Duration::from_secs(hold_seconds), || {
                Ok(std::path::Path::new(&format!("/tmp/inbound-test/check-{stem}")).exists())
            })?;
            stream_echo(
                &mut stream,
                b"same DNS proxy connection after configuration changes",
            )?;
            File::create(format!("/tmp/inbound-test/{stem}-complete"))?;
        }
        "independent" => {
            let mut stream = inbound_stream(18080)?;
            stream_echo(&mut stream, b"native connection before DNS changes")?;
            File::create("/tmp/inbound-test/independent-ready")?;
            wait_file("check-independent")?;
            stream_echo(&mut stream, b"same native connection after DNS changes")?;
            File::create("/tmp/inbound-test/independent-complete")?;
        }
        "wan_failure" | "relay_wan_failure" => {
            let mut stream = if role == "relay_wan_failure" {
                relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")?
            } else {
                inbound_stream(18080)?
            };
            stream_echo(&mut stream, b"working before WAN loss")?;
            File::create("/tmp/inbound-test/wan-failure-ready")?;
            wait_file("check-wan")?;
            let mut response = [0; 128];
            match stream.read(&mut response) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::ConnectionReset
                    ) => {}
                _ => return Err("reply bytes reached the client during WAN loss".into()),
            }
            File::create("/tmp/inbound-test/wan-failure-observed")?;
        }
        "holding_for_stop" => {
            let mut tcp = inbound_stream(18081)?;
            let udp = inbound_udp(18081)?;
            for _ in 0..8 {
                stream_echo(&mut tcp, b"TCP works before failed stop")?;
                udp_echo(&udp, b"UDP works before failed stop")?;
            }
            File::create("/tmp/inbound-test/holding-stop-ready")?;
            wait_file("check-failed-stop")?;
            match tcp.write_all(b"retired TCP fastpath must not deliver") {
                Ok(()) => match tcp.read(&mut [0; 1]) {
                    Ok(0) => {}
                    Ok(_) => return Err("a retired TCP tuple forwarded payload".into()),
                    Err(error)
                        if tcp_peer_closed(&error)
                            || error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(error) => return Err(error.into()),
                },
                Err(error) if tcp_peer_closed(&error) => {}
                Err(error) => return Err(error.into()),
            }
            udp_closed(&udp)?;
            File::create("/tmp/inbound-test/holding-stop-closed")?;
        }
        "holding" => {
            let mut affected = inbound_stream(18080)?;
            let mut stable = inbound_stream(18081)?;
            let affected_udp = inbound_udp(18080)?;
            let stable_udp = inbound_udp(18081)?;
            stream_echo(&mut affected, b"initial affected")?;
            stream_echo(&mut stable, b"initial stable")?;
            for _ in 0..2 {
                udp_echo(&affected_udp, b"initial affected UDP")?;
                udp_echo(&stable_udp, b"initial stable UDP")?;
            }
            File::create("/tmp/inbound-test/holding-ready")?;
            if env::var("TUNNEL_DETOUR_EXPECT_OFFLOAD").as_deref() == Ok("1") {
                wait_file("check-fastpath")?;
                for _ in 0..8 {
                    stream_echo(&mut affected, b"accelerated affected payload")?;
                    stream_echo(&mut stable, b"accelerated stable payload")?;
                    udp_echo(&affected_udp, b"accelerated affected UDP")?;
                    udp_echo(&stable_udp, b"accelerated stable UDP")?;
                }
                File::create("/tmp/inbound-test/holding-fastpath-checked")?;
            }
            wait_file("check-change")?;
            stream_closed(&mut affected)?;
            udp_closed(&affected_udp)?;
            stream_echo(&mut stable, b"stable after destination change")?;
            udp_echo(&stable_udp, b"stable UDP after destination change")?;
            File::create("/tmp/inbound-test/holding-changed")?;
            wait_file("check-reenable")?;
            stream_closed(&mut affected)?;
            udp_closed(&affected_udp)?;
            stream_echo(&mut stable, b"stable after destination restoration")?;
            udp_echo(&stable_udp, b"stable UDP after destination restoration")?;
            let mut current = inbound_stream(18080)?;
            let current_udp = inbound_udp(18080)?;
            stream_echo(&mut current, b"new destination generation")?;
            udp_echo(&current_udp, b"new UDP destination generation")?;
            File::create("/tmp/inbound-test/holding-reenabled")?;
            wait_file("check-disable")?;
            stream_closed(&mut current)?;
            udp_closed(&current_udp)?;
            stream_echo(
                &mut stable,
                b"stable after another publication was disabled",
            )?;
            udp_echo(
                &stable_udp,
                b"stable UDP after another publication was disabled",
            )?;
            File::create("/tmp/inbound-test/holding-disabled")?;
            wait_file("check-final")?;
            stream_closed(&mut current)?;
            udp_closed(&current_udp)?;
            let mut fresh = inbound_stream(18080)?;
            stream_echo(&mut fresh, b"fresh connection after reenable")?;
            udp_echo(&inbound_udp(18080)?, b"fresh UDP connection after reenable")?;
            stream_echo(
                &mut stable,
                b"same stable connection throughout all changes",
            )?;
            udp_echo(&stable_udp, b"same stable UDP tuple throughout all changes")?;
            File::create("/tmp/inbound-test/holding-complete")?;
            wait(|| {
                if std::path::Path::new("/tmp/inbound-test/release-holding").exists() {
                    return Ok(true);
                }
                stream_echo(&mut stable, b"surviving connection relearns acceleration")?;
                udp_echo(&stable_udp, b"surviving UDP tuple relearns acceleration")?;
                Ok(false)
            })?;
            File::create("/tmp/inbound-test/holding-released")?;
        }
        "server" | "dns_server" | "dns_server6" | "dns_other_server" | "vpn_server"
        | "vpn_server4" | "cached_server4" | "ula_server" | "other_server" | "relay_server"
        | "relay_other_server" => {
            let endpoint = if role == "cached_server4" {
                "198.18.0.1:80"
            } else if role == "vpn_server4" {
                "198.51.100.40:18090"
            } else if role == "relay_server" {
                "192.0.2.2:8080"
            } else if role == "relay_other_server" {
                "192.0.2.2:8081"
            } else if role == "other_server" {
                "[2001:db8:1::3]:8080"
            } else if role == "ula_server" {
                "[fd00:1234::2]:8080"
            } else if role == "vpn_server" {
                "[2001:db8:4::2]:18090"
            } else if role == "dns_server6" {
                "[2001:db8:3::2]:80"
            } else if role == "dns_server" {
                "203.0.113.2:80"
            } else if role == "dns_other_server" {
                "203.0.113.3:80"
            } else {
                "[2001:db8:1::2]:8080"
            };
            let tcp = TcpListener::bind(endpoint)?;
            let udp = UdpSocket::bind(endpoint)?;
            if matches!(role, "vpn_server" | "vpn_server4" | "cached_server4") {
                // The VPN target cannot be reached through the peer's plain WAN NIC,
                // even though Linux normally accepts local addresses on any interface.
                socket2::SockRef::from(&tcp).bind_device(Some(b"wgpeer0"))?;
                socket2::SockRef::from(&udp).bind_device(Some(b"wgpeer0"))?;
            }
            tcp.set_nonblocking(true)?;
            udp.set_nonblocking(true)?;
            File::create(if role == "cached_server4" {
                "/tmp/inbound-test/cached-endpoint-ready"
            } else if role == "vpn_server4" {
                "/tmp/inbound-test/vpn4-endpoint-ready"
            } else if role == "relay_server" {
                "/tmp/inbound-test/relay-endpoint-ready"
            } else if role == "relay_other_server" {
                "/tmp/inbound-test/relay-other-endpoint-ready"
            } else if role == "other_server" {
                "/tmp/inbound-test/other-endpoint-ready"
            } else if role == "ula_server" {
                "/tmp/inbound-test/ula-endpoint-ready"
            } else if role == "vpn_server" {
                "/tmp/inbound-test/vpn-endpoint-ready"
            } else if role == "dns_server6" {
                "/tmp/inbound-test/dns6-endpoint-ready"
            } else if role == "dns_server" {
                "/tmp/inbound-test/dns-endpoint-ready"
            } else if role == "dns_other_server" {
                "/tmp/inbound-test/dns-other-endpoint-ready"
            } else {
                "/tmp/inbound-test/endpoint-ready"
            })?;
            let deadline = Instant::now()
                + Duration::from_secs(match env::var("TUNNEL_DETOUR_LUCI_REVIEW").as_deref() {
                    Ok("2") => 720,
                    Ok("1") => 300,
                    _ if env::var("TUNNEL_DETOUR_EXPECT_OFFLOAD").as_deref() == Ok("1") => 300,
                    _ => 120,
                });
            let mut streams: Vec<TcpStream> = Vec::new();
            let mut pushed = false;
            let mut previous_active = usize::MAX;
            let mut measured = [0_u64; 2];
            let mut published = None;
            while Instant::now() < deadline {
                let measure = role == "server"
                    && std::path::Path::new("/tmp/inbound-test/r054-count-backend").exists();
                let push = if role == "relay_server" {
                    "/tmp/inbound-test/push-from-relay-server"
                } else {
                    "/tmp/inbound-test/push-from-server"
                };
                if !pushed && std::path::Path::new(push).exists() {
                    assert!(
                        !streams.is_empty(),
                        "WAN failure must exercise an established backend connection"
                    );
                    for stream in &mut streams {
                        stream.write_all(b"native reply during WAN failure")?;
                    }
                    File::create("/tmp/inbound-test/server-pushed")?;
                    pushed = true;
                }
                match tcp.accept() {
                    Ok((mut stream, peer)) if streams.len() < 32 => {
                        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                        let mut greeting = format!("peer={peer}\n");
                        if matches!(
                            role,
                            "ula_server" | "other_server" | "relay_server" | "relay_other_server"
                        ) {
                            greeting.push_str(&format!("local={}\n", stream.local_addr()?));
                        }
                        // The worker-refusal case may close a new connection
                        // before the backend can send its greeting.
                        match stream.write_all(greeting.as_bytes()) {
                            Ok(()) => {
                                stream.set_nonblocking(true)?;
                                streams.push(stream);
                            }
                            Err(error) if tcp_peer_closed(&error) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Ok(_) => return Err("fixture connection capacity exceeded".into()),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                let mut index = 0;
                while index < streams.len() {
                    let mut buffer = [0; 256];
                    match streams[index].read(&mut buffer) {
                        Ok(0) => {
                            streams.swap_remove(index);
                        }
                        Ok(length) => {
                            if measure {
                                measured[0] += u64::try_from(length)?;
                            }
                            match streams[index].write_all(&buffer[..length]) {
                                Ok(()) => index += 1,
                                Err(error) if tcp_peer_closed(&error) => {
                                    streams.swap_remove(index);
                                }
                                Err(error) => return Err(error.into()),
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            index += 1;
                        }
                        Err(error) if tcp_peer_closed(&error) => {
                            streams.swap_remove(index);
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut buffer = [0; 256];
                match udp.recv_from(&mut buffer) {
                    Ok((length, peer)) => {
                        if measure {
                            measured[1] += u64::try_from(length)?;
                        }
                        let mut response = format!("peer={peer}\n").into_bytes();
                        if role == "ula_server" {
                            response.extend_from_slice(
                                format!("local={}\n", udp.local_addr()?).as_bytes(),
                            );
                        }
                        response.extend_from_slice(&buffer[..length]);
                        udp.send_to(&response, peer)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                if measure && published != Some(measured) {
                    std::fs::write(
                        "/tmp/inbound-test/r054-backend-counts.tmp",
                        serde_json::to_vec(&measured)?,
                    )?;
                    std::fs::rename(
                        "/tmp/inbound-test/r054-backend-counts.tmp",
                        "/tmp/inbound-test/r054-backend-counts",
                    )?;
                    published = Some(measured);
                }
                if matches!(role, "relay_server" | "relay_other_server")
                    && previous_active != streams.len()
                {
                    let name = if role == "relay_server" {
                        "relay-server-active"
                    } else {
                        "relay-other-server-active"
                    };
                    std::fs::write(
                        format!("/tmp/inbound-test/{name}"),
                        streams.len().to_string(),
                    )?;
                    previous_active = streams.len();
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        "client" | "updated_address_client" | "ula_client" | "owned_port_client" => {
            let destination = if role == "updated_address_client" {
                "[2001:db8:2::10]:18080"
            } else if role == "owned_port_client" {
                "[2001:db8:2::1]:10536"
            } else if role == "ula_client" {
                "[2001:db8:2::1]:18082"
            } else {
                "[2001:db8:2::1]:18080"
            };
            let socket = socket_addr_tcp("[2001:db8:3::2]:0", destination)?;
            let expected_peer = format!("peer={}\n", socket.local_addr()?);
            let mut stream = socket;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let mut peer = vec![0; expected_peer.len()];
            stream.read_exact(&mut peer)?;
            assert_eq!(
                peer,
                expected_peer.as_bytes(),
                "native forwarding must preserve the public client address"
            );
            if role == "ula_client" {
                let expected = b"local=[fd00:1234::2]:8080\n";
                let mut local = vec![0; expected.len()];
                stream.read_exact(&mut local)?;
                assert_eq!(local, expected);
            }
            let payload = b"native TCP payload\0\xff";
            stream.write_all(payload)?;
            let mut response = vec![0; payload.len()];
            stream.read_exact(&mut response)?;
            assert_eq!(response, payload);
            let udp = UdpSocket::bind("[2001:db8:3::2]:0")?;
            udp.set_read_timeout(Some(Duration::from_secs(3)))?;
            udp.connect(destination)?;
            udp.send(b"native UDP payload\0\xff")?;
            let mut buffer = [0; 512];
            let length = udp.recv(&mut buffer)?;
            let mut expected = format!("peer={}\n", udp.local_addr()?).into_bytes();
            if role == "ula_client" {
                expected.extend_from_slice(b"local=[fd00:1234::2]:8080\n");
            }
            expected.extend_from_slice(b"native UDP payload\0\xff");
            assert_eq!(&buffer[..length], expected);
        }
        _ => return Err("unknown inbound fixture role".into()),
    }
    Ok(())
}

fn wait_file(name: &str) -> TestResult {
    wait_file_for(name, 30)
}

fn wait_file_for(name: &str, default_seconds: u64) -> TestResult {
    let seconds = if env::var("TUNNEL_DETOUR_LUCI_REVIEW").as_deref() == Ok("1") {
        240
    } else {
        default_seconds
    };
    wait_for(Duration::from_secs(seconds), || {
        Ok(std::path::Path::new(&format!("/tmp/inbound-test/{name}")).exists())
    })
}

fn observe_inbound_forward(lab: &Lab) -> TestResult {
    // Scope measurement to the fixture's marked publications at the normal
    // forward hook. The production guard owns no packet counters.
    lab.exec(&["nft", "-f", "-"], Some(b"table inet inbound_forward_probe {\n counter forwarded {}\n chain observe { type filter hook forward priority -2; policy accept;\n  meta nfproto ipv6 meta l4proto { tcp, udp } ct mark & 0xffff0000 == 1413742592 counter name forwarded\n }\n}\n"))?;
    Ok(())
}

fn inbound_forwarded_packets(lab: &Lab) -> TestResult<u64> {
    let listing: Value = serde_json::from_slice(&lab.exec(
        &[
            "nft",
            "-j",
            "list",
            "counter",
            "inet",
            "inbound_forward_probe",
            "forwarded",
        ],
        None,
    )?)?;
    listing["nftables"]
        .as_array()
        .ok_or("missing nftables listing")?
        .iter()
        .find_map(|entry| entry["counter"]["packets"].as_u64())
        .ok_or_else(|| "missing isolated forwarded packet count".into())
}

fn lan_public_stream() -> TestResult<std::net::TcpStream> {
    let mut stream = socket_addr_tcp("[2001:db8:1::2]:0", "[2001:db8:2::1]:18080")?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut header = Vec::new();
    while header.last() != Some(&b'\n') && header.len() < 128 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = String::from_utf8(header)?;
    let peer: std::net::SocketAddr = header
        .trim()
        .strip_prefix("peer=")
        .ok_or("missing LAN peer header")?
        .parse()?;
    assert_eq!(
        peer.ip(),
        "2001:db8:1::1".parse::<std::net::IpAddr>()?,
        "LAN return must use the explicit router source"
    );
    Ok(stream)
}

fn lan_public_udp() -> TestResult<std::net::UdpSocket> {
    let udp = std::net::UdpSocket::bind("[2001:db8:1::2]:0")?;
    udp.set_read_timeout(Some(Duration::from_secs(2)))?;
    udp.set_write_timeout(Some(Duration::from_secs(2)))?;
    udp.connect("[2001:db8:2::1]:18080")?;
    Ok(udp)
}

fn lan_public_udp_echo(udp: &std::net::UdpSocket, payload: &[u8]) -> TestResult {
    udp.send(payload)?;
    let mut response = [0; 512];
    let length = udp.recv(&mut response)?;
    let split = response[..length]
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("missing LAN UDP peer header")?;
    let header = std::str::from_utf8(&response[..split])?;
    let peer: std::net::SocketAddr = header
        .strip_prefix("peer=")
        .ok_or("missing LAN UDP peer")?
        .parse()?;
    assert_eq!(peer.ip(), "2001:db8:1::1".parse::<std::net::IpAddr>()?);
    assert_eq!(&response[split + 1..length], payload);
    Ok(())
}

fn inbound_stream(port: u16) -> TestResult<std::net::TcpStream> {
    let mut stream = socket_addr_tcp("[2001:db8:3::2]:0", &format!("[2001:db8:2::1]:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let peer = format!("peer={}\n", stream.local_addr()?);
    let mut header = vec![0; peer.len()];
    stream.read_exact(&mut header)?;
    assert_eq!(header, peer.as_bytes());
    Ok(stream)
}

fn stream_echo(stream: &mut std::net::TcpStream, bytes: &[u8]) -> TestResult {
    stream.write_all(bytes)?;
    let mut response = vec![0; bytes.len()];
    stream.read_exact(&mut response)?;
    assert_eq!(response, bytes);
    Ok(())
}

fn inbound_udp(port: u16) -> TestResult<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind("[2001:db8:3::2]:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.connect(format!("[2001:db8:2::1]:{port}"))?;
    Ok(socket)
}

fn udp_echo(socket: &std::net::UdpSocket, bytes: &[u8]) -> TestResult {
    socket.send(bytes)?;
    let mut response = [0; 512];
    let length = socket.recv(&mut response)?;
    let mut expected = format!("peer={}\n", socket.local_addr()?).into_bytes();
    expected.extend_from_slice(bytes);
    assert_eq!(&response[..length], expected);
    Ok(())
}

fn udp_closed(socket: &std::net::UdpSocket) -> TestResult {
    let rejected = |error: &std::io::Error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::PermissionDenied
        )
    };
    let mut sent = false;
    // Drain any pending ICMP error and actually send another datagram on the retained
    // conntrack tuple. Merely observing a previous socket error would not prove rejection.
    for _ in 0..2 {
        match socket.send(b"retired UDP conntrack must remain rejected") {
            Ok(_) => sent = true,
            Err(error) if rejected(&error) => continue,
            Err(error) => return Err(error.into()),
        }
        match socket.recv(&mut [0; 512]) {
            Err(error)
                if rejected(&error)
                    || matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("a retired UDP tuple forwarded payload".into()),
        }
    }
    if !sent {
        return Err("the retired UDP tuple was not exercised".into());
    }
    Ok(())
}

fn tcp_peer_closed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
    )
}

fn stream_closed(stream: &mut std::net::TcpStream) -> TestResult {
    if let Err(error) = stream.write_all(b"retired connection must be rejected") {
        if tcp_peer_closed(&error) {
            return Ok(());
        }
        return Err(error.into());
    }
    match stream.read(&mut [0; 1]) {
        Ok(0) => Ok(()),
        Err(error) if tcp_peer_closed(&error) => Ok(()),
        _ => Err("retired connection was not closed promptly".into()),
    }
}

fn relay_test_stream(
    source: &str,
    public_port: u16,
    target: &str,
) -> TestResult<std::net::TcpStream> {
    relay_test_endpoint(source, &format!("[2001:db8:2::1]:{public_port}"), target)
}

fn relay_test_endpoint(
    source: &str,
    public: &str,
    target: &str,
) -> TestResult<std::net::TcpStream> {
    let mut stream = socket_addr_tcp(source, public)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut line = || -> TestResult<String> {
        let mut bytes = Vec::new();
        for _ in 0..128 {
            let mut byte = [0; 1];
            stream.read_exact(&mut byte)?;
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(String::from_utf8(bytes)?);
            }
        }
        Err("oversized fixture endpoint header".into())
    };
    let peer = line()?;
    let peer: std::net::SocketAddrV4 = peer
        .strip_prefix("peer=")
        .ok_or("missing IPv4 source")?
        .trim()
        .parse()?;
    assert_eq!(
        peer.ip().to_string(),
        "192.0.2.1",
        "the IPv4 server must see the relay's LAN source"
    );
    assert_eq!(line()?, format!("local={target}\n"));
    Ok(stream)
}

fn blocked_inbound_tcp(source: &str, destination: &str) -> TestResult {
    match socket_addr_tcp(source, destination) {
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::PermissionDenied
                )
            }) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err("an unauthorized TCP endpoint accepted a connection".into()),
    }
}

fn socket_addr_tcp(source: &str, destination: &str) -> TestResult<std::net::TcpStream> {
    // The fixture uses the system curl client elsewhere; this small helper needs an
    // explicit IPv6 source to prove return-path policy beyond the connected WAN subnet.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    let source: std::net::SocketAddr = source.parse()?;
    let destination: std::net::SocketAddr = destination.parse()?;
    socket.bind(&source.into())?;
    socket.connect_timeout(&destination.into(), Duration::from_secs(3))?;
    Ok(socket.into())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r051_inbound_preflight_checks_live_lan_wan_and_private_paths_without_changing_dns_or_firewall()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.exec(&["mkdir", "-m", "700", "/tmp/inbound-test"], None)?;
    for arguments in [
        vec![
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "tdlan0",
            "nodad",
        ],
        vec![
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:2::1/64",
            "dev",
            "tdwan0",
            "nodad",
        ],
        vec![
            "ip",
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8:2::2",
            "dev",
            "tdwan0",
        ],
    ] {
        lab.exec(&arguments, None)?;
    }
    let configuration = json!({
        "lan_device":"tdlan0", "lan_networks":["2001:db8:1::/64"], "router_addresses":[],
        "wan":{"device":"tdwan0","addresses":["2001:db8:2::1"],"gateway":"2001:db8:2::2","route_table":41900,"mark_prefix":1413742592_u32,"rule_priority":100},
        "state_file":"/tmp/inbound-test/state.json", "status_file":"/tmp/inbound-test/status.json",
        "rules":[{"id":"sample","name":"Native preflight","enabled":true,"protocol":"tcp_udp","public_port":18080,"destination":"[2001:db8:1::2]:8080"}]
    });
    let dns = lab.exec(&["uci", "export", "dhcp"], None)?;
    let firewall = lab.exec(&["uci", "export", "firewall"], None)?;
    let routes = lab.exec(&["ip", "-j", "-6", "route", "show", "table", "all"], None)?;
    let run = |value: &Value| -> TestResult<Output> {
        lab.exec(
            &["tee", "/tmp/inbound-config.json"],
            Some(&serde_json::to_vec(value)?),
        )?;
        lab.raw(
            &[
                "/usr/bin/tunnel-detour",
                "--check-inbound-config",
                "/tmp/inbound-config.json",
            ],
            None,
        )
    };
    let valid = run(&configuration)?;
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&valid.stdout)?,
        json!({"valid":true,"checked":"network_and_paths"})
    );
    for (field, value) in [
        ("destination", json!("[2001:db8:1::1]:8080")),
        ("scope", json!(["2001:db8::/32"])),
        ("address", json!(["2001:db8:2::99"])),
        ("gateway", json!("2001:db8:2::99")),
        ("lan_source", json!(["2001:db8:1::99"])),
    ] {
        let mut invalid = configuration.clone();
        match field {
            "destination" => invalid["rules"][0][field] = value,
            "scope" => invalid["lan_networks"] = value,
            "address" => invalid["wan"]["addresses"] = value,
            "lan_source" => {
                invalid["lan_router_addresses"] = value;
                invalid["rules"][0]["access"] = json!("wan_and_lan");
            }
            _ => invalid["wan"][field] = value,
        }
        assert!(
            !run(&invalid)?.status.success(),
            "accepted mismatched live network {field}"
        );
    }
    lab.exec(
        &[
            "ln",
            "-s",
            "/tmp/inbound-test/state.json",
            "/tmp/inbound-test/status.json",
        ],
        None,
    )?;
    assert!(
        !run(&configuration)?.status.success(),
        "status symlinks must fail before activation"
    );
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dns);
    assert_eq!(lab.exec(&["uci", "export", "firewall"], None)?, firewall);
    assert_eq!(
        lab.exec(&["ip", "-j", "-6", "route", "show", "table", "all"], None)?,
        routes
    );
    assert!(
        !lab.raw(&["test", "-e", "/tmp/inbound-test/state.json"], None)?
            .status
            .success()
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r121_native_dns_frontends_deliver_sanitized_https_hints_and_the_client_reaches_the_verified_origin()
-> TestResult {
    use hickory_proto::{
        op::{Message, Query},
        rr::{
            Name, RData, RecordType,
            rdata::svcb::{SvcParamKey as Key, SvcParamValue as Param},
        },
    };
    const TEST: &str = "r121_native_dns_frontends_deliver_sanitized_https_hints_and_the_client_reaches_the_verified_origin";
    if env::var("TUNNEL_DETOUR_HTTPS_PROBE").as_deref() == Ok("1") {
        if !std::path::Path::new("/etc/openwrt_release").is_file() {
            return Err("HTTPS probe requires the native laboratory".into());
        }
        let mut query = Message::query();
        query.metadata.id = 0x7654;
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("selected.example.net.")?,
            RecordType::HTTPS,
        ));
        let packet = query.to_vec()?;
        for tcp in [false, true] {
            let bytes = if tcp {
                let mut socket = std::net::TcpStream::connect_timeout(
                    &"127.0.0.1:53".parse()?,
                    Duration::from_secs(3),
                )?;
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                socket.set_write_timeout(Some(Duration::from_secs(3)))?;
                socket.write_all(&u16::try_from(packet.len())?.to_be_bytes())?;
                socket.write_all(&packet)?;
                let mut prefix = [0; 2];
                socket.read_exact(&mut prefix)?;
                let mut bytes = vec![0; usize::from(u16::from_be_bytes(prefix))];
                socket.read_exact(&mut bytes)?;
                bytes
            } else {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
                socket.connect("127.0.0.1:53")?;
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                socket.send(&packet)?;
                let mut bytes = vec![0; 65535];
                let length = socket.recv(&mut bytes)?;
                bytes.truncate(length);
                bytes
            };
            let response = Message::from_vec(&bytes)?;
            assert_eq!(response.metadata.id, query.metadata.id);
            assert_eq!(response.queries, query.queries);
            assert_eq!(
                response.answers.len(),
                1,
                "frontend lost the supported HTTPS record"
            );
            let RData::HTTPS(binding) = &response.answers[0].data else {
                return Err("unexpected HTTPS data type".into());
            };
            assert!(binding.0.target_name.is_root());
            assert!(!response.metadata.authentic_data);
            let mut hint = None;
            for (key, value) in &binding.0.svc_params {
                match (key, value) {
                    (Key::Ipv4Hint, Param::Ipv4Hint(hints)) => {
                        assert_eq!(
                            hints
                                .0
                                .iter()
                                .map(|value| value.0.to_string())
                                .collect::<Vec<_>>(),
                            ["198.18.0.1"]
                        );
                        hint = hints.0.first().map(|value| value.0);
                    }
                    (Key::Ipv6Hint, _) => {
                        return Err("IPv4 compatibility mode published an IPv6 hint".into());
                    }
                    (Key::Alpn, Param::Alpn(protocols)) => assert_eq!(protocols.0, ["http/1.1"]),
                    _ => {}
                }
            }
            std::fs::write(
                "/tmp/https-binding-hint",
                hint.ok_or("missing rewritten hint")?.to_string(),
            )?;
        }
        return Ok(());
    }
    for adguard in [false, true] {
        let lab = Lab::create(!adguard)?;
        lab.dnsmasq_endpoints()?;
        lab.exec(&["tee","-a","/etc/tunnel-detour-lab-unbound.conf"],Some(b"    local-data: \"selected.example.net. 0 IN HTTPS 1 . alpn=h3,http/1.1 port=443 ipv4hint=203.0.113.2 ipv6hint=2001:db8:2::2\"\n"))?;
        lab.exec(&["/etc/init.d/tunnel-detour-lab", "restart"], None)?;
        if adguard {
            lab.configure()?;
            lab.change("set tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
        } else {
            lab.configure_dnsmasq()?;
        }
        lab.ready(None)?;
        lab.exec(
            &[
                "env",
                "TUNNEL_DETOUR_HTTPS_PROBE=1",
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                TEST,
                "--nocapture",
            ],
            None,
        )?;
        let hint = String::from_utf8(lab.exec(&["cat", "/tmp/https-binding-hint"], None)?)?;
        let body = lab.exec(
            &[
                "ip",
                "netns",
                "exec",
                "td-dns-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "5",
                "--cacert",
                "/tmp/native-origin/cert.pem",
                "--resolve",
                &format!("selected.example.net:443:{}", hint.trim()),
                "https://selected.example.net/route.txt",
            ],
            None,
        )?;
        assert_eq!(
            body, b"native-wan-dnsmasq",
            "native hint path did not reach the controlled TLS origin"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r042_existing_dnsmasq_without_adguard_preserves_local_dns_and_routes_selected_https_through_wan()
-> TestResult {
    let lab = Lab::create(true)?;
    // Stock OpenWrt uses an anonymous dnsmasq section. Other native scenarios keep
    // their named instance so both forms exercise the same ownership adapter.
    let configuration = String::from_utf8(lab.exec(&["uci", "export", "dhcp"], None)?)?;
    assert!(
        configuration.contains("config dnsmasq 'main'"),
        "the fixture must start with its named instance"
    );
    lab.exec(
        &["uci", "import", "dhcp"],
        Some(
            configuration
                .replace("config dnsmasq 'main'", "config dnsmasq")
                .as_bytes(),
        ),
    )?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    lab.exec(&["/etc/init.d/dnsmasq", "restart"], None)?;
    lab.dnsmasq_endpoints()?;
    let before = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.configure_dnsmasq()?;
    lab.ready(None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["dns_integration"],
        "dnsmasq"
    );
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|reply| reply.contains("198.18.0.1")))
    })?;
    let ordinary = lab.lookup("ordinary.example.net")?;
    assert!(
        ordinary.contains("203.0.113.2"),
        "ordinary DNS: {ordinary}; {}",
        String::from_utf8_lossy(&lab.exec(&["logread", "-e", "dnsmasq"], None)?)
    );
    assert!(
        lab.lookup("nested.selected.example.net")?
            .contains("203.0.113.2")
    );
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    assert!(
        String::from_utf8(lab.exec(
            &[
                "ip",
                "netns",
                "exec",
                "td-dns-client",
                "nslookup",
                "selected.example.net",
                "192.0.2.1",
            ],
            None
        )?)?
        .contains("198.18.0.1")
    );
    let body = lab
        .exec(
            &[
                "ip",
                "netns",
                "exec",
                "td-dns-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "5",
                "--cacert",
                "/tmp/native-origin/cert.pem",
                "--resolve",
                "selected.example.net:443:198.18.0.1",
                "https://selected.example.net/route.txt",
            ],
            None,
        )
        .map_err(|error| {
            format!(
                "{error}; transport diagnostics: {}",
                String::from_utf8_lossy(
                    &lab.exec(&["logread", "-e", "transport worker"], None)
                        .unwrap_or_default()
                )
            )
        })?;
    assert_eq!(body, b"native-wan-dnsmasq");
    lab.change("set tunnel-detour.globals.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
    wait(|| Ok(lab.exec(&["uci", "export", "dhcp"], None)? == before))?;
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|reply| reply.contains("203.0.113.2")))
    })?;
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    Ok(())
}

impl Drop for Lab {
    fn drop(&mut self) {
        let terminated_by_cleanup: Vec<bool> = self
            .background
            .get_mut()
            .iter_mut()
            .map(|child| match child.try_wait() {
                Ok(status) => status.is_none(),
                Err(error) => {
                    eprintln!("owned exec supervision failed: {error}");
                    false
                }
            })
            .collect();
        if let Some(vm) = &mut self.vm
            && let Err(error) = vm.stop()
        {
            eprintln!("owned VM cleanup failed: {error}");
        }
        if self.container_created
            && let Err(error) = checked("docker", &["stop", "--time", "3", &self.name], None)
        {
            eprintln!("owned container cleanup failed: {error}");
        }
        if self.container_created {
            // A never-started template also needs removal after setup failure.
            // --rm handles successful starts; explicit removal covers both paths.
            match output("docker", &["rm", "--force", &self.name], None) {
                Ok(result)
                    if result.status.success()
                        || String::from_utf8_lossy(&result.stderr)
                            .contains("No such container")
                        || String::from_utf8_lossy(&result.stderr)
                            .contains("removal of container")
                            && String::from_utf8_lossy(&result.stderr)
                                .contains("already in progress") => {}
                Ok(result) => eprintln!(
                    "owned container removal failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                ),
                Err(error) => eprintln!("owned container removal failed: {error}"),
            }
            // Docker stop can return before --rm has finished detaching its network.
            if let Err(error) = wait(|| {
                Ok(
                    !output("docker", &["container", "inspect", &self.name], None)?
                        .status
                        .success(),
                )
            }) {
                eprintln!("owned container removal failed: {error}");
            }
        }
        for (child, terminated) in self
            .background
            .get_mut()
            .iter_mut()
            .zip(terminated_by_cleanup)
        {
            match child.wait() {
                Ok(status) if terminated && matches!(status.code(), Some(143 | 255)) => {}
                Ok(status) if !status.success() => {
                    let mut errors = String::new();
                    if let Some(stderr) = child.stderr.take()
                        && let Err(error) = stderr.take(8192).read_to_string(&mut errors)
                    {
                        eprintln!("owned exec diagnostic failed: {error}");
                    }
                    eprintln!("owned exec exited {status}: {errors}");
                }
                Err(error) => eprintln!("owned exec cleanup failed: {error}"),
                _ => {}
            }
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
fn r043_dnsmasq_preflight_rejects_unsupported_filters_conflicts_loops_and_pending_changes_without_writes()
-> TestResult {
    let lab = Lab::create(true)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["dns_integration"],
        Value::Null,
        "new installs must not select a frontend automatically"
    );
    lab.prepare_dnsmasq()?;
    wait(|| Ok(lab.ubus("tunnel-detour", "check", json!({}))?["valid"] == true))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        json!({"connected":false,"error":"adguard_integration_disabled"})
    );
    let baseline = lab.exec(&["uci", "export", "dhcp"], None)?;
    for change in [
        "set dhcp.main.dnssec='1'",
        "set dhcp.main.addnhosts='/tmp/custom-filter'",
        "add_list dhcp.main.server='/selected.example.net/127.0.0.1#15353'",
        "set dhcp.overlap=domain\nset dhcp.overlap.name='selected.example.net'\nset dhcp.overlap.ip='203.0.113.2'",
    ] {
        lab.exec(
            &["uci", "batch"],
            Some(format!("{change}\ncommit dhcp\n").as_bytes()),
        )?;
        let before = lab.exec(&["uci", "export", "dhcp"], None)?;
        assert_eq!(
            lab.ubus("tunnel-detour", "check", json!({}))?,
            json!({"valid":false,"error":"dnsmasq_integration_failed"}),
            "preflight accepted {change}"
        );
        assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, before);
        lab.exec(&["uci", "import", "dhcp"], Some(&baseline))?;
        lab.exec(&["uci", "commit", "dhcp"], None)?;
    }
    lab.exec(
        &["tee", "/etc/ethers"],
        Some(b"02:00:00:00:00:02 selected.example.net\n"),
    )?;
    lab.exec(&["uci", "set", "dhcp.main.readethers=1"], None)?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "check", json!({}))?["valid"],
        false,
        "ethers names must not bypass local-name conflict detection"
    );
    lab.exec(&["uci", "import", "dhcp"], Some(&baseline))?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:53::1/128",
            "dev",
            "lo",
            "nodad",
        ],
        None,
    )?;
    for resolver in ["127.0.0.1:53", "[::1]:53", "[2001:db8:53::1]:53"] {
        lab.exec(
            &[
                "uci",
                "set",
                &format!("tunnel-detour.globals.real_upstream={resolver}"),
            ],
            None,
        )?;
        lab.exec(&["uci", "commit", "tunnel-detour"], None)?;
        let before = lab.exec(&["uci", "export", "tunnel-detour"], None)?;
        assert_eq!(
            lab.ubus("tunnel-detour", "check", json!({}))?,
            json!({"valid":false,"error":"dnsmasq_integration_failed"}),
            "router-local DNS resolver was not refused as a loop: {resolver}"
        );
        assert_eq!(lab.exec(&["uci", "export", "tunnel-detour"], None)?, before);
        assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, baseline);
    }
    lab.prepare_dnsmasq()?;
    lab.exec(&["uci", "set", "dhcp.main.logqueries=1"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "check", json!({}))?["valid"],
        false
    );
    assert!(!lab.exec(&["uci", "changes", "dhcp"], None)?.is_empty());
    lab.exec(&["uci", "revert", "dhcp"], None)?;
    assert!(
        !lab.raw(
            &["test", "-e", "/etc/tunnel-detour/leases.json.dnsmasq.json"],
            None
        )?
        .status
        .success(),
        "read-only checks created ownership"
    );
    lab.exec(
        &["tee", "/etc/dnsmasq.conf"],
        Some(b"address=/selected.example.net/203.0.113.2\n"),
    )?;
    assert_eq!(
        lab.ubus("tunnel-detour", "check", json!({}))?["valid"],
        false
    );
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, baseline);
    lab.exec(&["rm", "/etc/dnsmasq.conf"], None)?;
    lab.exec(&["mkfifo", "/etc/dnsmasq.conf"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "check", json!({}))?["valid"],
        false,
        "opaque FIFO configuration must be rejected without blocking DNS management"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r044_dnsmasq_recovers_pending_reload_and_uninstalls_offline_preserving_foreign_servers()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.configure_dnsmasq()?;
    let first = lab.ready(None)?;
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
    let path = "/etc/tunnel-detour/leases.json.dnsmasq.json";
    let mut journal: Value = serde_json::from_slice(&lab.exec(&["cat", path], None)?)?;
    assert!(
        !journal["managed"]
            .as_array()
            .ok_or("missing ownership")?
            .is_empty()
    );
    journal["pending"] = json!(true);
    lab.exec(&["tee", path], Some(&serde_json::to_vec(&journal)?))?;
    lab.exec(
        &["uci", "batch"],
        Some(b"add_list dhcp.main.server='/foreign.example.net/127.0.0.1#15353'\ncommit dhcp\n"),
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
    lab.ready(Some(first))?;
    let recovered: Value = serde_json::from_slice(&lab.exec(&["cat", path], None)?)?;
    assert_eq!(recovered["pending"], false);
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
    lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.selected.pattern='invalid * pattern'\nset tunnel-detour.globals.lan_network='unavailable'\ncommit tunnel-detour\n"))?;
    lab.exec(&["ifdown", "wan"], None)?;
    lab.exec(&["/usr/bin/tunnel-detour", "--uninstall"], None)?;
    let dns = lab.ubus("uci", "get", json!({"config":"dhcp"}))?;
    assert_eq!(
        dns["values"]["main"]["server"],
        json!(["127.0.0.1#15353", "/foreign.example.net/127.0.0.1#15353"])
    );
    wait(|| {
        Ok(lab
            .lookup("router.lan")
            .is_ok_and(|reply| reply.contains("192.0.2.1")))
    })?;
    for path in [
        path,
        "/etc/tunnel-detour/leases.json.dnsmasq.json.lock",
        "/etc/tunnel-detour/leases.json",
        "/etc/config/tunnel-detour",
    ] {
        assert!(
            !lab.raw(&["test", "-e", path], None)?.status.success(),
            "retained {path}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r046_legacy_adguard_migrates_idempotently_and_mode_handover_preserves_previous_ownership_on_failure()
-> TestResult {
    let lab = Lab::create_profile(true, true)?;
    lab.configure_adguard(15354)?;
    let dnsmasq_before = lab.exec(&["uci", "export", "dhcp"], None)?;
    let adguard_before = lab.api("dns_info", None, true)?["upstream_dns"].clone();
    lab.change("delete tunnel-detour.globals.dns_integration\nset tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
    let first = lab.ready(None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["dns_integration"],
        "adguard"
    );
    let path = "/etc/tunnel-detour/leases.json.adguard.json";
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false))?;
    let mut legacy: Value = serde_json::from_slice(&lab.exec(&["cat", path], None)?)?;
    legacy["version"] = json!(1);
    legacy
        .as_object_mut()
        .ok_or("invalid journal")?
        .remove("control");
    lab.exec(&["tee", path], Some(&serde_json::to_vec(&legacy)?))?;
    let upstreams = lab.api("dns_info", None, true)?["upstream_dns"].clone();
    lab.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
    let migrated = lab.ready(Some(first))?;
    let saved: Value = serde_json::from_slice(&lab.exec(&["cat", path], None)?)?;
    assert_eq!(saved["version"], 3);
    assert_eq!(
        lab.api("dns_info", None, true)?["upstream_dns"],
        upstreams,
        "migration must not duplicate forwards"
    );
    lab.change("set tunnel-detour.globals.dns_integration='dnsmasq'\nset tunnel-detour.globals.adguard_url='unused-invalid-endpoint'")?;
    let independent = lab.ready(Some(migrated))?;
    assert_eq!(
        lab.api("dns_info", None, true)?["upstream_dns"],
        adguard_before
    );
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|reply| reply.contains("198.18.0.1")))
    })?;
    let owned_dnsmasq = lab.exec(&["uci", "export", "dhcp"], None)?;
    let wrong = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin","password":"wrong-draft-password"}),
    )?;
    lab.change(&format!("set tunnel-detour.globals.dns_integration='adguard'\nset tunnel-detour.globals.adguard_url='http://127.0.0.1:13000'\nset tunnel-detour.globals.adguard_credentials_revision='{}'", wrong["revision"].as_str().ok_or("missing credential draft")?))?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["status"]["phase"] == "failed"))?;
    assert_eq!(
        lab.exec(&["uci", "export", "dhcp"], None)?,
        owned_dnsmasq,
        "a failed replacement must not clear previous forwarding ownership"
    );
    let stored = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin","password":lab.password}),
    )?;
    lab.change(&format!(
        "set tunnel-detour.globals.adguard_credentials_revision='{}'",
        stored["revision"]
            .as_str()
            .ok_or("missing credentials revision")?
    ))?;
    lab.ready(Some(independent))?;
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dnsmasq_before);
    assert_eq!(lab.api("dns_info", None, true)?["upstream_dns"], upstreams);
    lab.exec(&["killall", "-TERM", "AdGuardHome"], None)?;
    wait(|| Ok(!lab.raw(&["pidof", "AdGuardHome"], None)?.status.success()))?;
    lab.change("set tunnel-detour.globals.dns_integration='dnsmasq'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "status", json!({}))?["status"]["phase"] == "failed"))?;
    let retained: Value = serde_json::from_slice(&lab.exec(&["cat", path], None)?)?;
    assert!(
        !retained["managed"]
            .as_array()
            .ok_or("missing recovery ownership")?
            .is_empty(),
        "unreachable old API must retain recovery state"
    );
    assert_eq!(
        lab.exec(&["uci", "export", "dhcp"], None)?,
        dnsmasq_before,
        "unreachable old API must not activate an independent fallback"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r047_dnsmasq_alias_rewrites_rebind_protection_and_lost_forwarding_guard_cached_fake_ips()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.dnsmasq_endpoints()?;
    lab.prepare_dnsmasq()?;
    lab.exec(
        &["uci", "set", "tunnel-detour.globals.observability=1"],
        None,
    )?;
    lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.selected.pattern='alias.example.net'\ncommit tunnel-detour\nset dhcp.rewritten=domain\nset dhcp.rewritten.name='rewritten.example.net'\nset dhcp.rewritten.ip='192.0.2.1'\ncommit dhcp\n"))?;
    lab.exec(&["/etc/init.d/dnsmasq", "reload", "main"], None)?;
    lab.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
    let first = lab.ready(None)?;
    wait(|| {
        Ok(lab
            .lookup("alias.example.net")
            .is_ok_and(|reply| reply.contains("198.18.0.1")))
    })?;
    let attempt = |name: &str, address: &str| {
        lab.raw(
            &[
                "ip",
                "netns",
                "exec",
                "td-dns-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--max-time",
                "3",
                "--resolve",
                &format!("{name}:443:{address}"),
                "--cacert",
                "/tmp/native-origin/cert.pem",
                &format!("https://{name}/route.txt"),
            ],
            None,
        )
    };
    assert!(
        !attempt("alias.example.net", "198.18.0.1")?.status.success(),
        "an upstream alias must not bypass a local rewrite"
    );
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "status", json!({}))?["status"]["last_request_error"]
                == "dnsmasq_integration_failed",
        )
    })?;
    lab.change("set tunnel-detour.selected.pattern='selected.example.net'")?;
    let direct = lab.ready(Some(first))?;
    wait(|| {
        Ok(lab
            .lookup("selected.example.net")
            .is_ok_and(|reply| reply.contains("198.18.0.2")))
    })?;
    let baseline = attempt("selected.example.net", "198.18.0.2")?;
    assert!(
        baseline.status.success(),
        "the control connection must reach the TLS origin"
    );
    assert_eq!(baseline.stdout, b"native-wan-dnsmasq");
    // The native frontend blocks the laboratory's documentation-address origin unless
    // its explicit rebind allowlist applies. Fake-IP must not conceal that protection.
    lab.exec(&["uci", "delete", "dhcp.main.rebind_domain"], None)?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    lab.exec(&["/etc/init.d/dnsmasq", "reload", "main"], None)?;
    wait(|| {
        Ok(lab
            .lookup("ordinary.example.net")
            .is_ok_and(|reply| !reply.contains("203.0.113.2")))
    })?;
    assert!(
        !attempt("selected.example.net", "198.18.0.2")?
            .status
            .success(),
        "synthetic answers must not bypass the native rebind policy"
    );
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "status", json!({}))?["status"]["last_request_error"]
                == "forbidden_destination",
        )
    })?;
    lab.exec(
        &["uci", "add_list", "dhcp.main.rebind_domain=example.net"],
        None,
    )?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    lab.exec(&["/etc/init.d/dnsmasq", "reload", "main"], None)?;
    lab.exec(&["/etc/init.d/tunnel-detour", "restart"], None)?;
    lab.ready(Some(direct))?;
    assert_eq!(
        attempt("selected.example.net", "198.18.0.2")?.stdout,
        b"native-wan-dnsmasq",
        "restoring the explicit rebind allowance must restore the control path"
    );
    lab.exec(
        &[
            "uci",
            "del_list",
            "dhcp.main.server=/selected.example.net/127.0.0.1#10535",
        ],
        None,
    )?;
    lab.exec(&["uci", "commit", "dhcp"], None)?;
    assert!(
        !attempt("selected.example.net", "198.18.0.2")?
            .status
            .success(),
        "cached identities must fail closed after owned forwarding disappears"
    );
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "status", json!({}))?["status"]["last_request_error"]
                == "dnsmasq_integration_failed",
        )
    })?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r105_cold_firewall_start_protects_cached_synthetic_addresses_when_invalid_configuration_prevents_the_daemon_starting()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.inbound_endpoints()?;
    lab.inbound_wireguard()?;
    lab.inbound_ipv4_wireguard()?;
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-wan",
            "addr",
            "add",
            "198.18.0.1/32",
            "dev",
            "wgpeer0",
        ],
        None,
    )?;
    lab.spawn_inbound_probe("cached_server4")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "cached-endpoint-ready")?
            .status
            .success())
    })?;
    // Prove this synthetic address really is reachable via the ordinary tunnel
    // before the package owns any lease. Its reserved designation is no guard.
    let before = lab.inbound_probe("cached_client4")?;
    assert!(
        before.status.success(),
        "unprotected control failed: {}",
        String::from_utf8_lossy(&before.stderr)
    );
    lab.configure_dnsmasq()?;
    lab.ready(None)?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.spawn_inbound_probe("dns_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "dns-endpoint-ready")?
            .status
            .success())
    })?;
    lab.exec(&["fw4", "reload"], None)?;
    let captured = lab.inbound_probe("dns_once")?;
    assert!(
        captured.status.success(),
        "persistent cache guards blocked a valid WAN proxy path: {}",
        String::from_utf8_lossy(&captured.stderr)
    );
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    assert!(
        !lab.inbound_probe("cached_client4")?.status.success(),
        "warm stop must retain the guard"
    );
    // Simulate kernel state loss at boot, then run the actual platform firewall
    // before the service. No administrator-owned table or route is flushed.
    lab.exec(&["nft", "delete", "table", "inet", "tunnel_detour"], None)?;
    for chain in ["tunnel_detour_cache_forward", "tunnel_detour_cache_output"] {
        lab.exec(
            &["nft", "-f", "-"],
            Some(
                format!("flush chain inet fw4 {chain}\ndelete chain inet fw4 {chain}\n").as_bytes(),
            ),
        )?;
    }
    lab.exec(
        &["uci", "batch"],
        Some(b"set tunnel-detour.selected.pattern='invalid * rule'\ncommit tunnel-detour\n"),
    )?;
    lab.exec(&["fw4", "reload"], None)?;
    let _startup = lab.raw(&["/etc/init.d/tunnel-detour", "start"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["running"],
        false
    );
    let cached = lab.inbound_probe("cached_client4")?;
    assert!(
        !cached.status.success(),
        "cold startup sent a cached synthetic connection through WireGuard"
    );
    let ordinary = lab.inbound_probe("vpn_client4")?;
    assert!(
        ordinary.status.success(),
        "ordinary WireGuard traffic was damaged: {}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    assert!(lab.lookup("router.example.net")?.contains("192.0.2.1"));
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r106_native_cache_guard_refuses_foreign_unsafe_files_and_foreign_chain_names_without_overwriting_them()
-> TestResult {
    let lab = Lab::create(true)?;
    lab.prepare_dnsmasq()?;
    let path = "/etc/nftables.d/tunnel-detour-cache-guard.nft";
    let refused = || -> TestResult {
        let result = lab.raw_with_deadline(&["/usr/bin/tunnel-detour", "--uci"], None, "8")?;
        assert_eq!(
            result.status.code(),
            Some(1),
            "unsafe guard input hung or activated: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !lab.raw(&["nft", "list", "table", "inet", "tunnel_detour"], None)?
                .status
                .success(),
            "refused guard input changed the live proxy firewall"
        );
        Ok(())
    };
    let foreign = b"# foreign administrator contents\n";
    lab.exec(&["tee", path], Some(foreign))?;
    for mode in ["600", "644"] {
        lab.exec(&["chmod", mode, path], None)?;
        refused()?;
        assert_eq!(lab.exec(&["cat", path], None)?, foreign);
    }
    lab.exec(&["rm", path], None)?;
    lab.exec(&["tee", "/tmp/foreign-cache-guard"], Some(foreign))?;
    lab.exec(&["ln", "-s", "/tmp/foreign-cache-guard", path], None)?;
    refused()?;
    assert!(lab.raw(&["test", "-L", path], None)?.status.success());
    assert_eq!(
        lab.exec(&["cat", "/tmp/foreign-cache-guard"], None)?,
        foreign
    );
    lab.exec(&["rm", path], None)?;
    lab.exec(&["mkfifo", "-m", "600", path], None)?;
    refused()?;
    assert!(lab.raw(&["test", "-p", path], None)?.status.success());
    lab.exec(&["rm", path], None)?;
    let oversized = vec![b'x'; 4097];
    lab.exec(&["tee", path], Some(&oversized))?;
    lab.exec(&["chmod", "600", path], None)?;
    refused()?;
    assert_eq!(lab.exec(&["cat", path], None)?, oversized);
    lab.exec(&["rm", path], None)?;
    lab.exec(&["mv", "/etc/nftables.d", "/etc/nftables.d.saved"], None)?;
    lab.exec(&["mkdir", "-m", "700", "/tmp/foreign-nftables.d"], None)?;
    lab.exec(
        &["ln", "-s", "/tmp/foreign-nftables.d", "/etc/nftables.d"],
        None,
    )?;
    refused()?;
    assert!(
        !lab.raw(&["test", "-e", path], None)?.status.success(),
        "a symlinked parent received a guard file"
    );
    lab.exec(&["rm", "/etc/nftables.d"], None)?;
    lab.exec(&["mv", "/etc/nftables.d.saved", "/etc/nftables.d"], None)?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(b"add chain inet fw4 tunnel_detour_cache_forward { comment \"foreign owner\"; }\n"),
    )?;
    let before = lab.exec(
        &[
            "nft",
            "-j",
            "-a",
            "list",
            "chain",
            "inet",
            "fw4",
            "tunnel_detour_cache_forward",
        ],
        None,
    )?;
    refused()?;
    let uninstall = lab.raw(&["/usr/bin/tunnel-detour", "--uninstall"], None)?;
    assert!(
        !uninstall.status.success(),
        "uninstall adopted a foreign chain"
    );
    assert_eq!(
        lab.exec(
            &[
                "nft",
                "-j",
                "-a",
                "list",
                "chain",
                "inet",
                "fw4",
                "tunnel_detour_cache_forward"
            ],
            None
        )?,
        before
    );
    assert!(!lab.raw(&["test", "-e", path], None)?.status.success());
    lab.exec(
        &[
            "nft",
            "delete",
            "chain",
            "inet",
            "fw4",
            "tunnel_detour_cache_forward",
        ],
        None,
    )?;
    // Hold the platform's actual flock while Rust tries to preserve the guard.
    // Successful interoperation must refuse within its own five-second bound,
    // before writing a file or admitting DNS, then release the helper normally.
    let child = lab
        .background_command(&[
            "env",
            "TUNNEL_DETOUR_INBOUND_PROBE=cache_guard_lock",
            "flock",
            "-x",
            "/var/run/fw4.lock",
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            "r052_native_tcp_udp_publications_preserve_client_identity_and_return_through_wan",
        ])?
        .spawn()?;
    let child_index = lab.background.borrow().len();
    lab.background.borrow_mut().push(child);
    wait(|| {
        Ok(lab
            .raw(&["test", "-e", "/tmp/cache-guard-lock-ready"], None)?
            .status
            .success())
    })?;
    let started = Instant::now();
    refused()?;
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "the native flock was not respected"
    );
    assert!(!lab.raw(&["test", "-e", path], None)?.status.success());
    lab.exec(&["touch", "/tmp/cache-guard-lock-release"], None)?;
    wait(|| {
        Ok(lab.background.borrow_mut()[child_index]
            .try_wait()?
            .is_some())
    })?;
    assert!(
        lab.background.borrow_mut()[child_index].wait()?.success(),
        "the native lock holder failed"
    );
    let fingerprint = large_foreign_set(&lab)?;
    lab.exec(&["/etc/init.d/tunnel-detour", "start"], None)?;
    lab.ready(None)?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    assert_eq!(foreign_set_fingerprint(&lab)?, fingerprint);
    let include = format!("table inet fw4 {{\n include \"{path}\"\n}}\n");
    lab.exec(&["nft", "-f", "-"], Some(include.as_bytes()))?;
    lab.exec(
        &[
            "nft",
            "list",
            "chain",
            "inet",
            "fw4",
            "tunnel_detour_cache_forward",
        ],
        None,
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour", "stop"], None)?;
    lab.exec(&["/usr/bin/tunnel-detour", "--uninstall"], None)?;
    assert!(!lab.raw(&["test", "-e", path], None)?.status.success());
    assert!(
        !lab.raw(
            &[
                "nft",
                "list",
                "chain",
                "inet",
                "fw4",
                "tunnel_detour_cache_forward"
            ],
            None
        )?
        .status
        .success()
    );
    assert_eq!(foreign_set_fingerprint(&lab)?, fingerprint);
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r030_uci_changes_reconcile_through_procd_and_uninstall_removes_owned_configuration_without_live_wan()
-> TestResult {
    let lab = Lab::new()?;
    lab.configure()?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["enabled"],
        false
    );
    lab.change("set tunnel-detour.selected=exception\nset tunnel-detour.selected.pattern='selected.example.net'\nset tunnel-detour.selected.enabled='1'\nset tunnel-detour.globals.enabled='1'")?;
    let first = lab.ready(None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["enabled"],
        true
    );
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.change("set tunnel-detour.selected.enabled='0'")?;
    let second = lab.ready(Some(first))?;
    assert!(lab.lookup("selected.example.net")?.contains("203.0.113.2"));
    lab.change("set tunnel-detour.selected.enabled='1'")?;
    let third = lab.ready(Some(second))?;
    assert!(lab.lookup("selected.example.net")?.contains("198.18.0.1"));
    lab.change("set tunnel-detour.globals.enabled='0'")?;
    wait(|| {
        Ok(
            lab.ubus("tunnel-detour", "status", json!({}))?["running"] == false
                && lab.api("dns_info", None, true)?["upstream_dns"]
                    == json!(["tcp://127.0.0.1:15353"]),
        )
    })
    .map_err(|error| format!("global disable: {error}"))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "status", json!({}))?["enabled"],
        false
    );
    assert!(lab.lookup("selected.example.net")?.contains("203.0.113.2"));
    lab.change("set tunnel-detour.globals.enabled='1'")?;
    lab.ready(Some(third))?;
    lab.exec(&["fw4", "reload"], None)?;
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
        "/etc/nftables.d/tunnel-detour-cache-guard.nft",
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
    for chain in ["tunnel_detour_cache_forward", "tunnel_detour_cache_output"] {
        assert!(
            !lab.raw(&["nft", "list", "chain", "inet", "fw4", chain], None)?
                .status
                .success(),
            "uninstall retained {chain}"
        );
    }
    assert!(lab.lookup("router.example.net")?.contains("192.0.2.1"));
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
fn r039_adguard_connection_test_checks_applied_and_draft_local_credentials_without_mutating_settings()
-> TestResult {
    let lab = Lab::new()?;
    lab.configure()?;
    let dns = lab.api("dns_info", None, true)?;
    let filters = lab.api("filtering/status", None, true)?;
    let configuration = lab.exec(&["uci", "export", "tunnel-detour"], None)?;
    let probe = lab.ubus("tunnel-detour", "test_adguard", json!({}))?;
    assert_eq!(
        probe,
        json!({"connected":true,"health":{"dns_running":true,"protection_enabled":true}})
    );
    assert_eq!(lab.api("dns_info", None, true)?, dns);
    assert_eq!(lab.api("filtering/status", None, true)?, filters);

    // R136b: a real, private tmpfs makes the credential write fail with ENOSPC.
    // Only this disposable container's secret directory is overlaid. On failure
    // Lab teardown removes the entire mount namespace; no host mount is involved.
    let credentials = "/etc/tunnel-detour/adguard-credentials.json";
    let pristine = lab.exec(&["sha256sum", credentials], None)?;
    lab.exec(&["mkdir", "-m", "700", "/tmp/td-credential-backup"], None)?;
    for name in ["adguard-credentials.json", "adguard-credentials.json.lock"] {
        lab.exec(
            &[
                "cp",
                "-p",
                &format!("/etc/tunnel-detour/{name}"),
                "/tmp/td-credential-backup/",
            ],
            None,
        )?;
    }
    lab.exec(
        &[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "size=16384,nr_inodes=64,mode=0700",
            "tmpfs",
            "/etc/tunnel-detour",
        ],
        None,
    )?;
    for name in ["adguard-credentials.json", "adguard-credentials.json.lock"] {
        lab.exec(
            &[
                "cp",
                "-p",
                &format!("/tmp/td-credential-backup/{name}"),
                "/etc/tunnel-detour/",
            ],
            None,
        )?;
    }
    let fill_credentials_store = || -> TestResult {
        let filled = lab.raw(
            &[
                "dd",
                "if=/dev/zero",
                "of=/etc/tunnel-detour/test-filler",
                "bs=4096",
                "count=5",
            ],
            None,
        )?;
        assert!(!filled.status.success());
        assert!(
            String::from_utf8_lossy(&filled.stderr).contains("No space left on device"),
            "the fixture did not reach actual ENOSPC"
        );
        Ok(())
    };
    fill_credentials_store()?;
    let draft =
        serde_json::to_vec(&json!({"username":"lab-admin", "password":"discarded-fs-draft"}))?;
    let reject_full_draft = || -> TestResult {
        let failed = lab.raw(
            &["/usr/bin/tunnel-detour", "call", "set_credentials"],
            Some(&draft),
        )?;
        assert!(
            !failed.status.success(),
            "full storage accepted a credential draft"
        );
        assert!(
            failed.stdout.is_empty(),
            "failed persistence returned a successful receipt"
        );
        assert!(!String::from_utf8_lossy(&failed.stderr).contains("discarded-fs-draft"));
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains("adguard_credentials_storage_failed")
        );
        Ok(())
    };
    reject_full_draft()?;
    assert_eq!(
        lab.exec(&["sha256sum", credentials], None)?,
        pristine,
        "ENOSPC replaced the applied credentials"
    );
    assert_eq!(lab.ubus("tunnel-detour", "test_adguard", json!({}))?, probe);
    lab.exec(&["rm", "/etc/tunnel-detour/test-filler"], None)?;
    let recovered = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin", "password":"discarded-fs-draft"}),
    )?;
    assert_eq!(
        recovered["saved"], true,
        "credential writes did not recover after freeing space"
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        probe,
        "a recovered draft changed the applied credentials"
    );

    // A failed first write can leave only its lock. Explicit replacement must
    // repair that state without treating unknown applied credentials as empty.
    let old_revision = lab.raw(
        &[
            "uci",
            "-q",
            "get",
            "tunnel-detour.globals.adguard_credentials_revision",
        ],
        None,
    )?;
    let old_revision = match old_revision.status.code() {
        Some(0) => Some(String::from_utf8(old_revision.stdout)?.trim().to_owned()),
        Some(1) => None,
        _ => return Err("could not inspect the fixture's applied credential revision".into()),
    };
    lab.exec(
        &[
            "rm",
            credentials,
            "/etc/tunnel-detour/adguard-credentials.json.lock",
        ],
        None,
    )?;
    fill_credentials_store()?;
    reject_full_draft()?;
    assert!(
        !lab.raw(&["test", "-e", credentials], None)?
            .status
            .success()
    );
    assert!(
        lab.raw(
            &[
                "test",
                "-f",
                "/etc/tunnel-detour/adguard-credentials.json.lock"
            ],
            None
        )?
        .status
        .success()
    );
    lab.exec(&["rm", "/etc/tunnel-detour/test-filler"], None)?;
    let repaired = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin", "password":lab.password}),
    )?;
    assert_eq!(
        repaired["saved"], true,
        "first-write failure permanently poisoned credential storage"
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "credentials_status", json!({}))?,
        json!({"configured":false,"error":"adguard_credentials_unavailable"})
    );
    let revision = repaired["revision"]
        .as_str()
        .ok_or("missing repaired credential revision")?;
    lab.exec(
        &[
            "uci",
            "set",
            &format!("tunnel-detour.globals.adguard_credentials_revision={revision}"),
        ],
        None,
    )?;
    lab.exec(&["uci", "commit", "tunnel-detour"], None)?;
    assert_eq!(lab.ubus("tunnel-detour", "test_adguard", json!({}))?, probe);
    match old_revision {
        Some(revision) => {
            lab.exec(
                &[
                    "uci",
                    "set",
                    &format!("tunnel-detour.globals.adguard_credentials_revision={revision}"),
                ],
                None,
            )?;
        }
        None => {
            lab.exec(
                &[
                    "uci",
                    "delete",
                    "tunnel-detour.globals.adguard_credentials_revision",
                ],
                None,
            )?;
        }
    }
    lab.exec(&["uci", "commit", "tunnel-detour"], None)?;
    lab.exec(&["umount", "/etc/tunnel-detour"], None)?;
    assert_eq!(lab.exec(&["sha256sum", credentials], None)?, pristine);
    lab.exec(&["rm", "-r", "/tmp/td-credential-backup"], None)?;
    assert_eq!(
        lab.exec(&["uci", "export", "tunnel-detour"], None)?,
        configuration
    );

    for (url, username, password, expected) in [
        (
            "http://127.0.0.1:13000",
            "lab-admin",
            lab.password.as_str(),
            None,
        ),
        (
            "http://127.0.0.1:13000",
            "lab-admin",
            "incorrect-draft-password",
            Some("adguard_authentication_failed"),
        ),
        (
            "http://192.0.2.2:13000",
            "lab-admin",
            lab.password.as_str(),
            Some("adguard_endpoint_invalid"),
        ),
    ] {
        let draft = lab.ubus(
            "tunnel-detour",
            "test_adguard",
            json!({"api_url":url,"username":username,"password":password}),
        )?;
        if let Some(error) = expected {
            assert_eq!(draft, json!({"connected":false,"error":error}));
        } else {
            assert_eq!(draft, probe);
        }
    }
    // A partial draft must be rejected rather than using the stored password.
    let partial = lab.ubus(
        "tunnel-detour",
        "test_adguard",
        json!({"api_url":"http://127.0.0.1:13000"}),
    )?;
    assert_eq!(partial["connected"], false);
    assert_eq!(
        lab.exec(&["uci", "export", "tunnel-detour"], None)?,
        configuration
    );
    assert_eq!(lab.api("dns_info", None, true)?, dns);
    assert_eq!(lab.api("filtering/status", None, true)?, filters);

    assert_eq!(lab.ubus("tunnel-detour", "test_adguard", json!({"api_url":"http://127.0.0.1:13000","username":"","password":"","use_saved_credentials":true}))?, probe);
    let replacement = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin","password":"incorrect-lab-password"}),
    )?;
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        probe,
        "staging changed applied credentials before the UCI revision committed"
    );
    lab.exec(&["uci", "batch"], Some(format!("set tunnel-detour.globals.adguard_credentials_revision='{}'\ncommit tunnel-detour\n", replacement["revision"].as_str().ok_or("missing credential draft")?).as_bytes()))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        json!({"connected":false,"error":"adguard_authentication_failed"})
    );

    lab.exec(
        &[
            "uci",
            "set",
            "tunnel-detour.globals.adguard_url=http://192.0.2.2:13000",
        ],
        None,
    )?;
    lab.exec(&["uci", "commit", "tunnel-detour"], None)?;
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        json!({"connected":false,"error":"adguard_endpoint_invalid"})
    );

    lab.exec(
        &[
            "uci",
            "set",
            "tunnel-detour.globals.adguard_url=http://127.0.0.1:13000",
        ],
        None,
    )?;
    lab.exec(&["uci", "commit", "tunnel-detour"], None)?;
    lab.exec(&["killall", "-TERM", "AdGuardHome"], None)?;
    wait(|| Ok(!lab.raw(&["pidof", "AdGuardHome"], None)?.status.success()))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "test_adguard", json!({}))?,
        json!({"connected":false,"error":"adguard_unreachable"})
    );
    lab.exec(&["uci", "batch"], Some(b"set tunnel-detour.globals.adguard_credentials_revision='missing-reference'\ncommit tunnel-detour\n"))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "credentials_status", json!({}))?,
        json!({"configured":false,"error":"adguard_credentials_unavailable"})
    );
    let repaired = lab.ubus(
        "tunnel-detour",
        "set_credentials",
        json!({"username":"lab-admin","password":lab.password}),
    )?;
    assert_eq!(
        lab.ubus("tunnel-detour", "credentials_status", json!({}))?,
        json!({"configured":false,"error":"adguard_credentials_unavailable"}),
        "repair changed the applied reference before commit"
    );
    lab.exec(&["uci", "batch"], Some(format!("set tunnel-detour.globals.adguard_credentials_revision='{}'\ncommit tunnel-detour\n", repaired["revision"].as_str().ok_or("missing repaired revision")?).as_bytes()))?;
    assert_eq!(
        lab.ubus("tunnel-detour", "credentials_status", json!({}))?,
        json!({"configured":true})
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r016_allocator_refuses_foreign_owned_private_snapshots_locks_and_directories() -> TestResult {
    let lab = Lab::create(true)?;
    lab.exec(
        &["sh", "-c", "cat > /tmp/state-boundary-probe"],
        Some(&std::fs::read(env!("CARGO_BIN_EXE_state-boundary-probe"))?),
    )?;
    lab.exec(&["chmod", "755", "/tmp/state-boundary-probe"], None)?;
    assert_eq!(
        lab.exec(
            &[
                "env",
                "TUNNEL_DETOUR_STATE_LAB=1",
                "/tmp/state-boundary-probe"
            ],
            None
        )?,
        b"foreign-owned snapshot, lock and parent refused; state preserved\n"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r080_isolated_transport_retains_unacknowledged_output_and_aborts_it_on_retirement() -> TestResult
{
    let lab = Lab::create(true)?;
    lab.exec(
        &["sh", "-c", "cat > /tmp/transport-boundary-probe"],
        Some(&std::fs::read(env!(
            "CARGO_BIN_EXE_transport-boundary-probe"
        ))?),
    )?;
    lab.exec(&["chmod", "755", "/tmp/transport-boundary-probe"], None)?;
    lab.exec(
        &[
            "env",
            "TUNNEL_DETOUR_TRANSPORT_LAB=1",
            "/tmp/transport-boundary-probe",
            "--acknowledgements",
        ],
        None,
    )?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r133_isolated_transport_cannot_mutate_router_control_and_worker_crashes_close_only_their_connection()
-> TestResult {
    let lab = Lab::create(true)?;
    let configuration = lab.exec(&["uci", "export", "tunnel-detour"], None)?;
    let routes = lab
        .raw(&["ip", "-j", "route", "show", "table", "201"], None)?
        .stdout;
    lab.exec(
        &["mkdir", "-m", "700", "/tmp/transport-boundary-root"],
        None,
    )?;
    lab.exec(
        &["sh", "-c", "cat > /tmp/transport-boundary-probe"],
        Some(&std::fs::read(env!(
            "CARGO_BIN_EXE_transport-boundary-probe"
        ))?),
    )?;
    lab.exec(&["chmod", "755", "/tmp/transport-boundary-probe"], None)?;
    let report: Value = serde_json::from_slice(&lab.exec(
        &[
            "sh",
            "-c",
            "TUNNEL_DETOUR_TRANSPORT_LAB=1 /tmp/transport-boundary-probe /tmp/transport-boundary-root & wait $!",
        ],
        None,
    )?)?;
    assert_eq!(
        report,
        json!({"uci_write_denied":true,"ubus_denied":true,"filesystem_write_denied":true,"root_recovery_denied":true,"route_write_denied":true,"nft_write_denied":true,"new_network_socket_denied":true,"process_signal_denied":true,"async_signal_denied":true,"socket_reconfiguration_denied":true})
    );
    assert_eq!(
        lab.exec(&["uci", "export", "tunnel-detour"], None)?,
        configuration
    );
    assert_eq!(
        lab.raw(&["ip", "-j", "route", "show", "table", "201"], None)?
            .stdout,
        routes
    );
    assert!(
        !lab.raw(&["nft", "list", "table", "inet", "td_boundary_probe"], None)?
            .status
            .success()
    );
    assert_eq!(
        lab.exec(
            &[
                "env",
                "TUNNEL_DETOUR_TRANSPORT_LAB=1",
                "/tmp/transport-boundary-probe",
                "--thread-lifetime",
                "/tmp/transport-boundary-root"
            ],
            None
        )?,
        b"creator thread exited; the controller process retained both TCP directions\n"
    );
    assert_eq!(
        lab.exec(
            &[
                "env",
                "TUNNEL_DETOUR_TRANSPORT_LAB=1",
                "/tmp/transport-boundary-probe",
                "--inherited-descriptor",
                "/tmp/transport-boundary-root"
            ],
            None,
        )?,
        b"unexpected inherited descriptor refused before copying\n"
    );
    assert_eq!(
        lab.exec(
            &[
                "env",
                "TUNNEL_DETOUR_TRANSPORT_LAB=1",
                "/tmp/transport-boundary-probe",
                "--filter-unavailable",
                "/tmp/transport-boundary-root",
            ],
            None,
        )?,
        b"unavailable syscall filter refused before copying in either direction\n"
    );
    lab.inbound_endpoints()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.enabled='1'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    lab.spawn_inbound_probe("transport_crash_holding")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-crash-ready")?
            .status
            .success())
    })?;
    let processes = String::from_utf8(lab.exec(&["ps", "w"], None)?)?;
    let worker = processes
        .lines()
        .find(|line| line.contains("--transport-worker"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or("missing isolated transport process")?;
    let status = String::from_utf8(lab.exec(&["cat", &format!("/proc/{worker}/status")], None)?)?;
    for (field, expected) in [
        ("Uid:", "65534\t65534\t65534\t65534"),
        ("Gid:", "65534\t65534\t65534\t65534"),
        ("CapEff:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapInh:", "0000000000000000"),
        ("NoNewPrivs:", "1"),
        ("Seccomp:", "2"),
    ] {
        assert_eq!(
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .map(str::trim),
            Some(expected),
            "incorrect transport boundary {field}"
        );
    }
    lab.exec(&["kill", "-KILL", worker], None)?;
    lab.inbound_marker("td-in-wan", "touch", "check-relay-crash")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-crash-closed")?
            .status
            .success())
    })
    .map_err(|error| format!("worker crash did not close the held relay: {error}"))?;
    let fresh = lab.inbound_probe("relay_client")?;
    assert!(
        fresh.status.success(),
        "controller did not recover a fresh authorized connection: {}",
        String::from_utf8_lossy(&fresh.stderr)
    );
    assert_eq!(
        lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"],
        true
    );
    // R133f: test a real worker startup refusal after the daemon is ready. The
    // worker validates the shared chroot before touching either TCP direction.
    const START_FAILURE: &str = "transport_worker_failed";
    let transport_root = "/var/run/tunnel-detour/transport";
    let moved_root = "/var/run/tunnel-detour/worker-start-refusal.example.test";
    let inbound_status = || lab.ubus("tunnel-detour", "inbound_status", json!({}));
    let pid = inbound_status()?["status"]["process_id"]
        .as_u64()
        .ok_or("missing inbound process identifier")?;
    let check_health = |degraded: bool| -> TestResult {
        wait(|| {
            let status = &inbound_status()?["status"];
            assert_eq!(status["process_id"], pid);
            assert_eq!(status["applied"], true);
            assert_eq!(status["observability"], false);
            assert!(status.get("relay").is_none());
            let expected = if degraded {
                json!([START_FAILURE])
            } else {
                json!([])
            };
            Ok(status["degraded"] == expected)
        })
    };
    let health_log = || -> TestResult<Vec<String>> {
        let log = String::from_utf8(lab.exec(&["logread"], None)?)?;
        assert!(!log.contains("transport worker initialization details"));
        Ok(log
            .lines()
            .filter(|line| line.contains(START_FAILURE))
            .map(str::to_owned)
            .collect())
    };
    let workers_drained = || -> TestResult {
        wait(|| {
            Ok(!lab
                .raw(&["ps", "w"], None)?
                .stdout
                .windows(b"--transport-worker".len())
                .any(|part| part == b"--transport-worker"))
        })
    };
    check_health(false)?;
    assert!(
        health_log()?.is_empty(),
        "a worker crash is not a startup refusal"
    );
    lab.spawn_inbound_probe("relay_holding")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-ready")?
            .status
            .success())
    })?;
    // A missing directory supplies a real OS errno to the optional event.
    lab.exec(&["mv", transport_root, moved_root], None)?;
    for _ in 0..3 {
        let refused = lab.inbound_probe("transport_start_refused")?;
        assert!(
            refused.status.success(),
            "unsafe worker start left a usable stream: {}",
            String::from_utf8_lossy(&refused.stderr)
        );
    }
    check_health(true)?;
    let warnings = health_log()?;
    assert_eq!(warnings.len(), 1, "worker refusal warnings were repeated");
    for detail in ["errno", "example.test", "2001:db8:", "192.0.2."] {
        assert!(
            !warnings[0].contains(detail),
            "health warning exposed {detail}"
        );
    }
    assert!(lab.ubus("system", "info", json!({}))?["uptime"].is_u64());
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    lab.inbound_marker("td-in-wan", "touch", "relay-client-release")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-wan", "test", "relay-client-complete")?
            .status
            .success())
    })
    .map_err(|error| format!("older relay did not complete during new worker refusals: {error}"))?;
    workers_drained()?;
    // The earlier worker delivered traffic and exited while the fault remained.
    // Observe management for two status ticks so its completion cannot clear health.
    let observe_until = Instant::now() + Duration::from_secs(2);
    wait(|| {
        assert_eq!(
            inbound_status()?["status"]["degraded"],
            json!([START_FAILURE])
        );
        Ok(Instant::now() >= observe_until)
    })?;
    lab.exec(&["mv", moved_root, transport_root], None)?;
    let recovered = lab.inbound_probe("relay_client")?;
    assert!(
        recovered.status.success(),
        "removing the worker startup fault did not restore relay traffic: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    check_health(false)?;
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    workers_drained()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r031_real_rpcd_read_only_permissions_allow_status_and_validation_but_deny_writes_and_commands()
-> TestResult {
    let lab = Lab::new()?;
    let credential = secret()?;
    let legacy = format!(
        "set tunnel-detour.globals.adguard_username='lab-admin'\nset tunnel-detour.globals.adguard_password='{credential}'\ncommit tunnel-detour\n"
    );
    lab.exec(&["uci", "batch"], Some(legacy.as_bytes()))?;
    for _ in 0..2 {
        lab.exec(
            &["/usr/bin/tunnel-detour", "--migrate-adguard-credentials"],
            None,
        )?;
    }
    assert!(
        lab.exec(
            &["ls", "-ln", "/etc/tunnel-detour/adguard-credentials.json"],
            None
        )?
        .starts_with(b"-rw-------")
    );
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
        ("uci", "get", json!({"config":"tunnel-detour"}), 0),
        ("tunnel-detour", "credentials_status", json!({}), 0),
        (
            "tunnel-detour",
            "set_credentials",
            json!({"username":"other","password":"synthetic"}),
            6,
        ),
        (
            "file",
            "read",
            json!({"path":"/etc/tunnel-detour/adguard-credentials.json"}),
            6,
        ),
        ("tunnel-detour", "status", json!({}), 0),
        ("tunnel-detour", "inbound_status", json!({}), 0),
        (
            "tunnel-detour",
            "inbound_devices",
            json!({"network":"lan"}),
            0,
        ),
        ("network.interface", "dump", json!({}), 0),
        ("luci-rpc", "getDHCPLeases", json!({"family":4}), 0),
        ("luci-rpc", "getHostHints", json!({}), 6),
        ("uci", "get", json!({"config":"network"}), 6),
        (
            "tunnel-detour",
            "validate",
            json!({"patterns":"***.example.net"}),
            0,
        ),
        ("tunnel-detour", "check", json!({}), 6),
        ("tunnel-detour", "check_inbound", json!({}), 6),
        (
            "tunnel-detour",
            "inbound_port_usage",
            json!({"port":18080}),
            6,
        ),
        ("tunnel-detour", "restart_inbound", json!({}), 6),
        ("tunnel-detour", "test_adguard", json!({}), 6),
        (
            "tunnel-detour",
            "preview_upstream",
            json!({"api_url":"http://127.0.0.1:13000","username":"","password":"","real_upstream":"192.0.2.53","import_current":false}),
            6,
        ),
        (
            "tunnel-detour",
            "test_adguard",
            json!({"api_url":"http://127.0.0.1:13000","username":"","password":""}),
            6,
        ),
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
        let encoded = serde_json::to_string(&reply)?;
        assert!(
            !encoded.contains(&credential),
            "a read-only response exposed stored credentials"
        );
        if object == "uci" && method == "get" && expected == 0 {
            assert!(!encoded.contains("adguard_password"));
            assert!(!encoded.contains("adguard_username"));
        }
        assert_eq!(
            status,
            Some(expected),
            "unexpected access for {object}/{method}"
        );
    }
    Ok(())
}
