//! Acceptance tests use real Linux namespaces, nftables, WireGuard, Unbound, HTTP, and TLS.
//! Run only through `cargo xtask test-network`; no host-network mutation is authorized here.

use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

fn output(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
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

fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, Box<dyn Error>> {
    let result = output(program, args, input)?;
    if !result.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(result.stdout)
}

fn wait_until(mut condition: impl FnMut() -> Result<bool, Box<dyn Error>>) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("laboratory readiness deadline expired".into())
}

struct Lab {
    directory: TempDir,
    namespaces: Vec<String>,
    devices: Vec<String>,
    children: Vec<Child>,
    service: Option<Child>,
    config: Value,
    adguard_auth: Option<(String, String)>,
    adguard_bind: String,
    adguard_dns_bind: String,
    foreign_route_created: bool,
}

impl Lab {
    fn new() -> Result<Self, Box<dyn Error>> {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("use cargo xtask test-network".into());
        }
        let links: Vec<Value> =
            serde_json::from_slice(&command("ip", &["-j", "link", "show"], None)?)?;
        if links.len() != 1 || links[0]["ifname"] != "lo" {
            return Err("laboratory requires an isolated namespace with only loopback".into());
        }
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let config = json!({
            "dns_listen":"127.0.0.1:10535", "proxy_listen":"0.0.0.0:10536",
            "real_upstream":"10.254.0.2:5353", "state_file":path.join("state/leases.json"),
            "status_file":path.join("run/status.json"), "fake_range":"198.18.0.0/28",
            "lan_device":"lan0", "lan_networks":["192.0.2.0/24"],
            "wan":{"device":"wan0","gateway":null,"route_table":41872,"mark":21572,"rule_priority":11000},
            "rules":[{"pattern":"selected.example.test","enabled":true}]
            ,"limits":{"max_mappings":14}
        });
        let mut lab = Self {
            directory,
            namespaces: vec![],
            devices: vec![],
            children: vec![],
            service: None,
            config,
            adguard_auth: None,
            adguard_bind: "127.0.0.1".into(),
            adguard_dns_bind: "0.0.0.0".into(),
            foreign_route_created: false,
        };
        for name in ["td-client", "td-wan", "td-vpn"] {
            command("ip", &["netns", "add", name], None)?;
            lab.namespaces.push(name.into());
            command("ip", &["-n", name, "link", "set", "lo", "up"], None)?;
        }
        lab.link(
            "lan0",
            "lan-peer",
            "td-client",
            "192.0.2.1/24",
            "192.0.2.2/24",
        )?;
        lab.link(
            "wan0",
            "wan-peer",
            "td-wan",
            "203.0.113.1/24",
            "203.0.113.2/24",
        )?;
        lab.link(
            "underlay0",
            "underlay-peer",
            "td-vpn",
            "198.51.100.1/24",
            "198.51.100.2/24",
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-client",
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
            ],
            None,
        )?;
        command(
            "ip",
            &["-n", "td-wan", "addr", "add", "203.0.113.3/32", "dev", "lo"],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-wan",
                "route",
                "add",
                "default",
                "via",
                "203.0.113.1",
            ],
            None,
        )?;
        command(
            "ip",
            &["-n", "td-vpn", "addr", "add", "203.0.113.2/32", "dev", "lo"],
            None,
        )?;
        lab.wireguard()?;
        command(
            "ip",
            &["route", "add", "203.0.113.2/32", "dev", "wg0"],
            None,
        )?;
        command("ip", &["route", "add", "default", "dev", "wg0"], None)?;
        if fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
            return Err(
                "laboratory requires forwarding enabled in its own network namespace".into(),
            );
        }
        command(
            "nft",
            &["-f", "-"],
            Some(
                br#"table inet lab_firewall {
 chain forward { type filter hook forward priority 0; policy drop;
  ct state established,related accept
  iifname "lan0" oifname "wg0" accept
 }
}
"#,
            ),
        )?;
        for (namespace, role) in [("td-wan", "wan"), ("td-vpn", "vpn")] {
            let root = lab.directory.path().join(role);
            fs::create_dir(&root)?;
            fs::write(root.join("route.txt"), role)?;
            lab.spawn(
                "ip",
                &[
                    "netns",
                    "exec",
                    namespace,
                    "busybox",
                    "httpd",
                    "-f",
                    "-p",
                    "203.0.113.2:80",
                    "-h",
                    root.to_str().ok_or("invalid fixture path")?,
                ],
                role,
            )?;
        }
        let root = lab.directory.path().join("router");
        fs::create_dir(&root)?;
        fs::write(root.join("route.txt"), "router")?;
        lab.spawn(
            "busybox",
            &[
                "httpd",
                "-f",
                "-p",
                "192.0.2.1:8080",
                "-h",
                root.to_str().ok_or("invalid fixture path")?,
            ],
            "router",
        )?;
        let unbound = lab.directory.path().join("unbound.conf");
        fs::write(
            &unbound,
            "server:\n interface: 10.254.0.2@5353\n username: \"\"\n chroot: \"\"\n directory: \"/tmp\"\n pidfile: \"\"\n use-syslog: no\n do-daemonize: no\n module-config: \"iterator\"\n access-control: 0.0.0.0/0 allow\n local-zone: \"example.test.\" static\n local-data: \"selected.example.test. 60 IN A 203.0.113.2\"\n local-data: \"other.example.test. 60 IN A 203.0.113.2\"\n local-data: \"alias.example.test. 60 IN CNAME selected.example.test.\"\n local-data: \"private.example.test. 60 IN A 192.0.2.1\"\n",
        )?;
        lab.spawn(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "unbound",
                "-d",
                "-c",
                unbound.to_str().ok_or("invalid fixture path")?,
            ],
            "unbound",
        )?;
        wait_until(|| Ok(lab.query_upstream().is_ok()))?;
        Ok(lab)
    }

    fn enable_ipv6(&mut self) -> TestResult {
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:1::1/64",
                "dev",
                "lan0",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-client",
                "-6",
                "addr",
                "add",
                "2001:db8:1::2/64",
                "dev",
                "lan-peer",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-client",
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8:1::1",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "-6",
                "addr",
                "add",
                "2001:db8:2::2/128",
                "dev",
                "lo",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "-6",
                "route",
                "add",
                "2001:db8:1::/64",
                "dev",
                "wg-peer",
            ],
            None,
        )?;
        command("ip", &["-6", "route", "add", "default", "dev", "wg0"], None)?;
        let root = self.directory.path().join("vpn");
        self.spawn(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "busybox",
                "httpd",
                "-f",
                "-p",
                "[2001:db8:2::2]:80",
                "-h",
                root.to_str().ok_or("invalid fixture path")?,
            ],
            "vpn-v6",
        )?;
        Ok(())
    }

    /// A /128 WAN source keeps the ordinary shared destination on the tunnel;
    /// only the package's marked IPv6 table selects the independent WAN origin.
    fn prepare_ipv6_wan(&mut self) -> TestResult {
        self.enable_ipv6()?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "fd00:1234::1/64",
                "dev",
                "lan0",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-client",
                "-6",
                "addr",
                "add",
                "fd00:1234::2/64",
                "dev",
                "lan-peer",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "-6",
                "route",
                "add",
                "fd00:1234::/64",
                "dev",
                "wg-peer",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:2::1/128",
                "dev",
                "wan0",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-wan",
                "-6",
                "addr",
                "add",
                "2001:db8:2::2/64",
                "dev",
                "wan-peer",
                "nodad",
            ],
            None,
        )?;
        let root = self.directory.path().join("wan-v6");
        fs::create_dir(&root)?;
        fs::write(root.join("route.txt"), "wan6")?;
        self.spawn(
            "ip",
            &[
                "netns",
                "exec",
                "td-wan",
                "busybox",
                "httpd",
                "-f",
                "-p",
                "[2001:db8:2::2]:80",
                "-h",
                root.to_str().ok_or("invalid WAN fixture path")?,
            ],
            "wan-v6",
        )?;
        self.config["ipv6"] = json!({"lan_networks":["2001:db8:1::/64", "fd00:1234::/64"],"wan":{"device":"wan0","source":"2001:db8:2::1","gateway":null}});
        Ok(())
    }

    /// Select an IPv6 resolver over the existing real WireGuard tunnel. Its
    /// unique record distinguishes it from the still-running IPv4 resolver.
    fn use_ipv6_resolver(&mut self) -> TestResult {
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:3::1/126",
                "dev",
                "wg0",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "-6",
                "addr",
                "add",
                "2001:db8:3::2/126",
                "dev",
                "wg-peer",
                "nodad",
            ],
            None,
        )?;
        let public = String::from_utf8(command("wg", &["show", "wg0", "public-key"], None)?)?;
        command(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "wg",
                "set",
                "wg-peer",
                "peer",
                public.trim(),
                "allowed-ips",
                "10.254.0.1/32,192.0.2.0/24,2001:db8:1::/64,fd00:1234::/64,2001:db8:3::1/128",
            ],
            None,
        )?;
        command(
            "ip",
            &["-6", "route", "replace", "default", "dev", "wg0"],
            None,
        )?;
        let configuration = self.directory.path().join("unbound-ipv6.conf");
        let mut contents = fs::read_to_string(self.directory.path().join("unbound.conf"))?
            .replace(
                "interface: 10.254.0.2@5353",
                "interface: 2001:db8:3::2@5353",
            )
            .replace(
                "access-control: 0.0.0.0/0 allow",
                "access-control: ::/0 allow",
            );
        contents.push_str(" local-data: \"ipv6-resolver.example.test. 0 IN A 203.0.113.3\"\n");
        fs::write(&configuration, contents)?;
        self.spawn(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "unbound",
                "-d",
                "-c",
                configuration.to_str().ok_or("IPv6 resolver path")?,
            ],
            "unbound-ipv6",
        )?;
        wait_until(|| {
            Ok(Self::query_at("[2001:db8:3::2]:5353", "ipv6-resolver.example.test", RecordType::A, true)
            .is_ok_and(|reply| reply.answers.iter().any(|record| matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(203, 0, 113, 3)))))
        })?;
        self.config["real_upstream"] = json!("[2001:db8:3::2]:5353");
        Ok(())
    }

    fn link(
        &mut self,
        root: &str,
        peer: &str,
        namespace: &str,
        root_address: &str,
        peer_address: &str,
    ) -> TestResult {
        command(
            "ip",
            &["link", "add", root, "type", "veth", "peer", "name", peer],
            None,
        )?;
        self.devices.push(root.into());
        command("ip", &["link", "set", peer, "netns", namespace], None)?;
        command("ip", &["addr", "add", root_address, "dev", root], None)?;
        command("ip", &["link", "set", root, "up"], None)?;
        command(
            "ip",
            &["-n", namespace, "addr", "add", peer_address, "dev", peer],
            None,
        )?;
        command("ip", &["-n", namespace, "link", "set", peer, "up"], None)?;
        Ok(())
    }

    fn wireguard(&mut self) -> TestResult {
        let mut public = Vec::new();
        let mut private_paths = Vec::new();
        for role in ["router", "vpn"] {
            let private = command("wg", &["genkey"], None)?;
            public.push(
                String::from_utf8(command("wg", &["pubkey"], Some(&private))?)?
                    .trim()
                    .to_owned(),
            );
            let path = self.directory.path().join(format!("{role}.key"));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&private)?;
            private_paths.push(path);
        }
        command("ip", &["link", "add", "wg0", "type", "wireguard"], None)?;
        self.devices.push("wg0".into());
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "link",
                "add",
                "wg-peer",
                "type",
                "wireguard",
            ],
            None,
        )?;
        command(
            "wg",
            &[
                "set",
                "wg0",
                "listen-port",
                "51820",
                "private-key",
                private_paths[0].to_str().ok_or("key path")?,
                "peer",
                &public[1],
                "endpoint",
                "198.51.100.2:51820",
                "allowed-ips",
                "0.0.0.0/0,::/0",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "wg",
                "set",
                "wg-peer",
                "listen-port",
                "51820",
                "private-key",
                private_paths[1].to_str().ok_or("key path")?,
                "peer",
                &public[0],
                "endpoint",
                "198.51.100.1:51820",
                "allowed-ips",
                "10.254.0.1/32,192.0.2.0/24,2001:db8:1::/64,fd00:1234::/64",
            ],
            None,
        )?;
        command("ip", &["addr", "add", "10.254.0.1/30", "dev", "wg0"], None)?;
        command("ip", &["link", "set", "wg0", "up"], None)?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "addr",
                "add",
                "10.254.0.2/30",
                "dev",
                "wg-peer",
            ],
            None,
        )?;
        command(
            "ip",
            &["-n", "td-vpn", "link", "set", "wg-peer", "up"],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "route",
                "add",
                "192.0.2.0/24",
                "dev",
                "wg-peer",
            ],
            None,
        )?;
        Ok(())
    }

    fn spawn(&mut self, program: &str, args: &[&str], name: &str) -> TestResult {
        let log = File::create(self.directory.path().join(format!("{name}.log")))?;
        self.children.push(
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        Ok(())
    }

    fn query_upstream(&self) -> Result<(), Box<dyn Error>> {
        std::net::TcpStream::connect_timeout(
            &"10.254.0.2:5353".parse::<SocketAddr>()?,
            Duration::from_secs(1),
        )?;
        Ok(())
    }

    fn start(&mut self) -> TestResult {
        let path = self.directory.path().join("config.json");
        fs::write(&path, serde_json::to_vec(&self.config)?)?;
        let log = File::create(self.directory.path().join("service.log"))?;
        self.service = Some(
            Command::new("/opt/tunnel-detour")
                .arg("--config")
                .arg(&path)
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        wait_until(|| {
            let child = self.service.as_mut().ok_or("service is absent")?;
            if let Some(status) = child.try_wait()? {
                let ipv6 = if self.config["ipv6"].is_object() {
                    let routes = output(
                        "ip",
                        &["-j", "-N", "-6", "route", "show", "table", "41872"],
                        None,
                    )?;
                    let rules = output(
                        "ip",
                        &["-j", "-N", "-6", "rule", "show", "pref", "11000"],
                        None,
                    )?;
                    format!(
                        "; IPv6 routes: {} {}; rules: {} {}",
                        String::from_utf8_lossy(&routes.stdout),
                        String::from_utf8_lossy(&routes.stderr),
                        String::from_utf8_lossy(&rules.stdout),
                        String::from_utf8_lossy(&rules.stderr)
                    )
                } else {
                    String::new()
                };
                return Err(format!(
                    "service exited with {status}: {}{ipv6}",
                    fs::read_to_string(self.directory.path().join("service.log"))?
                )
                .into());
            }
            let pid = child.id();
            match self.status() {
                Ok(status) => Ok(status["phase"] == "ready"
                    && status["process_id"].as_u64() == Some(u64::from(pid))),
                Err(_) => Ok(false),
            }
        })
    }

    fn status(&self) -> Result<Value, Box<dyn Error>> {
        let path = self.config["status_file"]
            .as_str()
            .ok_or("missing status path")?;
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn api(&self, operation: &str, body: Option<Value>) -> Result<Value, Box<dyn Error>> {
        let url = format!("http://{}:13000/control/{operation}", self.adguard_bind);
        let auth = self
            .adguard_auth
            .as_ref()
            .map(|(user, password)| format!("{user}:{password}"));
        let mut args = vec![
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "5",
        ];
        if let Some(auth) = &auth {
            args.extend(["--user", auth]);
        }
        let expects_json = body.is_none();
        let bytes = body.map(|body| serde_json::to_vec(&body)).transpose()?;
        if bytes.is_some() {
            args.extend([
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ]);
        }
        args.push(&url);
        let response = command("curl", &args, bytes.as_deref())
            .map_err(|error| format!("AdGuard {operation}: {error}"))?;
        // Some mutation endpoints return an empty body or a plain-text acknowledgement.
        if !expects_json
            && (operation == "filtering/remove_url"
                || response.is_empty()
                || response
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .eq(b"OK".iter().copied()))
        {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&response)
                .map_err(|error| format!("AdGuard {operation} JSON response: {error}").into())
        }
    }

    fn start_adguard(&mut self) -> TestResult {
        let root = self.directory.path().join("adguard");
        fs::create_dir(&root)?;
        let config = root.join("AdGuardHome.yaml");
        let web_address = format!("{}:13000", self.adguard_bind);
        let arguments = [
            "--no-check-update",
            "--web-addr",
            &web_address,
            "-w",
            root.to_str().ok_or("AdGuard work path")?,
            "-c",
            config.to_str().ok_or("AdGuard config path")?,
        ];
        let child_index = self.children.len();
        self.spawn("AdGuardHome", &arguments, "adguard")?;
        wait_until(|| Ok(self.api("install/get_addresses", None).is_ok()))?;
        let password = format!(
            "Lab!{}",
            String::from_utf8(command("openssl", &["rand", "-hex", "24"], None)?)?.trim()
        );
        self.api("install/configure", Some(json!({"web":{"ip":self.adguard_bind,"port":13000},"dns":{"ip":self.adguard_dns_bind,"port":10534},"username":"lab-admin","password":password})))?;
        self.adguard_auth = Some(("lab-admin".into(), password.clone()));
        wait_until(|| Ok(self.api("status", None).is_ok()))?;
        self.api("dns_config", Some(json!({"upstream_dns":["tcp://10.254.0.2:5353", "[/unrelated.test/]tcp://10.254.0.2:5353"],"bootstrap_dns":["10.254.0.2:5353"],"fallback_dns":[],"upstream_dns_file":"","cache_optimistic":false,"blocking_mode":"null_ip"})))?;
        let subscriptions = self.api("filtering/status", None)?;
        for subscription in subscriptions["filters"]
            .as_array()
            .ok_or("missing laboratory filter subscriptions")?
        {
            self.api(
                "filtering/remove_url",
                Some(json!({"url":subscription["url"]})),
            )?;
        }
        assert!(
            self.api("filtering/status", None)?["filters"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        command(
            "kill",
            &["-TERM", &self.children[child_index].id().to_string()],
            None,
        )?;
        wait_until(|| Ok(self.children[child_index].try_wait()?.is_some()))?;
        let settings = fs::read_to_string(&config)?;
        if !settings.contains("    whois: true\n") {
            return Err("unexpected laboratory WHOIS configuration".into());
        }
        fs::write(
            &config,
            settings.replace("    whois: true\n", "    whois: false\n"),
        )?;
        self.spawn("AdGuardHome", &arguments, "adguard")?;
        wait_until(|| Ok(self.api("status", None).is_ok()))?;
        self.api(
            "filtering/set_rules",
            Some(json!({"rules":["||blocked.example.test^"]})),
        )?;
        self.api(
            "rewrite/add",
            Some(json!({"domain":"router.example.test","answer":"192.0.2.1"})),
        )?;
        self.config["adguard"] = json!({"api_url":format!("http://{web_address}/"),"username":"lab-admin","password":password});
        Ok(())
    }

    fn enable_adguard_dot(&self) -> TestResult {
        let key = self.directory.path().join("dns-tls.key");
        let certificate = self.directory.path().join("dns-tls.crt");
        command(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=dns.example.test",
                "-addext",
                "subjectAltName=DNS:dns.example.test,IP:192.0.2.1,IP:2001:db8:1::1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
                key.to_str().ok_or("invalid DNS TLS key path")?,
                "-out",
                certificate
                    .to_str()
                    .ok_or("invalid DNS TLS certificate path")?,
            ],
            None,
        )?;
        let mut settings = self.api("tls/status", None)?;
        settings["enabled"] = json!(true);
        settings["server_name"] = json!("dns.example.test");
        settings["force_https"] = json!(false);
        settings["port_https"] = json!(0);
        settings["port_dns_over_tls"] = json!(853);
        settings["port_dns_over_quic"] = json!(0);
        settings["strict_sni_check"] = json!(false);
        settings["serve_plain_dns"] = json!(true);
        settings["certificate_chain"] = json!("");
        settings["private_key"] = json!("");
        settings["certificate_path"] = json!(certificate);
        settings["private_key_path"] = json!(key);
        let validation = self.api("tls/validate", Some(settings.clone()))?;
        assert_eq!(validation["valid_cert"], true);
        assert_eq!(validation["valid_key"], true);
        assert_eq!(validation["valid_pair"], true);
        self.api("tls/configure", Some(settings))?;
        wait_until(|| Ok(self.api("status", None).is_ok()))?;
        Ok(())
    }

    fn query_dot(
        &self,
        name: &str,
        kind: RecordType,
        ipv6: bool,
    ) -> Result<Message, Box<dyn Error>> {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(format!("{name}."))?, kind));
        let packet = query.to_vec()?;
        let certificate = self.directory.path().join("dns-tls.crt");
        let address = if ipv6 {
            "[2001:db8:1::1]:853"
        } else {
            "192.0.2.1:853"
        };
        let ip = if ipv6 { "2001:db8:1::1" } else { "192.0.2.1" };
        let mut child = Command::new("ip")
            .args([
                "netns",
                "exec",
                "td-client",
                "timeout",
                "7",
                "openssl",
                "s_client",
                "-quiet",
                "-no_ign_eof",
                "-connect",
                address,
                "-CAfile",
            ])
            .arg(certificate)
            .args(["-verify_return_error", "-verify_ip", ip])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("missing DNS TLS client stdin")?;
        let response = (|| -> Result<Vec<u8>, Box<dyn Error>> {
            input.write_all(&u16::try_from(packet.len())?.to_be_bytes())?;
            input.write_all(&packet)?;
            input.flush()?;
            let mut output = child.stdout.take().ok_or("missing DNS TLS client stdout")?;
            let mut length = [0; 2];
            output.read_exact(&mut length)?;
            let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
            output.read_exact(&mut response)?;
            Ok(response)
        })();
        drop(input);
        let result = child.wait_with_output()?;
        if !result.status.success() {
            return Err(format!(
                "DNS TLS client failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        let response = Message::from_vec(&response?)?;
        assert_eq!(response.metadata.id, query.metadata.id);
        assert_eq!(response.queries, query.queries);
        Ok(response)
    }

    fn start_tls(&mut self) -> TestResult {
        let key = self.directory.path().join("tls.key");
        let certificate = self.directory.path().join("tls.crt");
        command(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=selected.example.test",
                "-addext",
                "subjectAltName=DNS:selected.example.test,DNS:other.example.test,DNS:tls4.example.test,DNS:tls6.example.test,DNS:tls-alias.example.test",
                "-keyout",
                key.to_str().ok_or("key path")?,
                "-out",
                certificate.to_str().ok_or("certificate path")?,
            ],
            None,
        )?;
        let mut origins = vec![
            ("td-wan", "wan", "203.0.113.2:443"),
            ("td-vpn", "vpn", "203.0.113.2:443"),
        ];
        if self.config["ipv6"].is_object() {
            origins.extend([
                ("td-wan", "wan-v6", "[2001:db8:2::2]:443"),
                ("td-vpn", "vpn", "[2001:db8:2::2]:443"),
            ]);
        }
        for (index, (namespace, role, endpoint)) in origins.into_iter().enumerate() {
            let root = self.directory.path().join(role);
            let log = File::create(
                self.directory
                    .path()
                    .join(format!("tls-{role}-{index}.log")),
            )?;
            self.children.push(
                Command::new("ip")
                    .args([
                        "netns",
                        "exec",
                        namespace,
                        "openssl",
                        "s_server",
                        "-quiet",
                        "-WWW",
                        "-accept",
                        endpoint,
                        "-cert",
                        certificate.to_str().ok_or("certificate path")?,
                        "-key",
                        key.to_str().ok_or("key path")?,
                    ])
                    .current_dir(root)
                    .stdin(Stdio::null())
                    .stdout(log.try_clone()?)
                    .stderr(log)
                    .spawn()?,
            );
            let endpoint: SocketAddr = endpoint.parse()?;
            let host = match endpoint.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let expected = fs::read(self.directory.path().join(role).join("route.txt"))?;
            wait_until(|| {
                let reply = output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        namespace,
                        "curl",
                        "--noproxy",
                        "*",
                        "--silent",
                        "--show-error",
                        "--fail",
                        "--max-time",
                        "1",
                        "--cacert",
                        certificate.to_str().ok_or("TLS certificate path")?,
                        "--resolve",
                        &format!("selected.example.test:443:{host}"),
                        "https://selected.example.test/route.txt",
                    ],
                    None,
                )?;
                Ok(reply.status.success() && reply.stdout == expected)
            })?;
        }
        Ok(())
    }

    fn query(&self, name: &str, kind: RecordType, tcp: bool) -> Result<Message, Box<dyn Error>> {
        let address = if self.config["adguard"].is_object() {
            "127.0.0.1:10534"
        } else {
            "127.0.0.1:10535"
        };
        Self::query_at(address, name, kind, tcp)
    }

    fn query_at(
        address: &str,
        name: &str,
        kind: RecordType,
        tcp: bool,
    ) -> Result<Message, Box<dyn Error>> {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name)?, kind));
        let bytes = query.to_vec()?;
        let endpoint: SocketAddr = address.parse()?;
        let response = if tcp {
            use std::io::Read;
            let mut socket =
                std::net::TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))?;
            socket.set_read_timeout(Some(Duration::from_secs(7)))?;
            socket.set_write_timeout(Some(Duration::from_secs(7)))?;
            socket.write_all(&u16::try_from(bytes.len())?.to_be_bytes())?;
            socket.write_all(&bytes)?;
            let mut length = [0; 2];
            socket.read_exact(&mut length)?;
            let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
            socket.read_exact(&mut response)?;
            response
        } else {
            let socket = UdpSocket::bind(if endpoint.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })?;
            socket.connect(endpoint)?;
            socket.set_read_timeout(Some(Duration::from_secs(7)))?;
            socket.send(&bytes)?;
            let mut response = vec![0; 65535];
            let length = socket.recv(&mut response)?;
            response.truncate(length);
            response
        };
        let response = Message::from_vec(&response)?;
        assert_eq!(response.metadata.id, query.metadata.id);
        Ok(response)
    }

    fn address(&self, name: &str) -> Result<Ipv4Addr, Box<dyn Error>> {
        let response = self.query(name, RecordType::A, false)?;
        match response.answers.first().map(|answer| &answer.data) {
            Some(RData::A(ip)) => Ok(ip.0),
            _ => Err("DNS response did not contain an A record".into()),
        }
    }

    fn address_family(&self, name: &str, ipv6: bool) -> Result<IpAddr, Box<dyn Error>> {
        let reply = self.query(
            name,
            if ipv6 {
                RecordType::AAAA
            } else {
                RecordType::A
            },
            false,
        )?;
        match reply.answers.first().map(|record| &record.data) {
            Some(RData::A(address)) if !ipv6 => Ok(address.0.into()),
            Some(RData::AAAA(address)) if ipv6 => Ok(address.0.into()),
            _ => Err("DNS omitted the requested address family".into()),
        }
    }

    fn http_from(
        &self,
        name: &str,
        address: IpAddr,
        source: &str,
    ) -> Result<Output, Box<dyn Error>> {
        let address = match address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        output(
            "ip",
            &[
                "netns",
                "exec",
                "td-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "8",
                "--interface",
                source,
                "--resolve",
                &format!("{name}:80:{address}"),
                &format!("http://{name}/route.txt"),
            ],
            None,
        )
    }

    fn exception_wan_syns(&self) -> Result<u64, Box<dyn Error>> {
        let values: Value = serde_json::from_slice(&command(
            "nft",
            &[
                "-j",
                "list",
                "counter",
                "inet",
                "lab_ipv6_filter",
                "wan_syns",
            ],
            None,
        )?)?;
        values["nftables"]
            .as_array()
            .ok_or("missing counter inventory")?
            .iter()
            .find_map(|value| value["counter"]["packets"].as_u64())
            .ok_or("missing SYN counter".into())
    }

    fn http(&self, name: &str, ip: Ipv4Addr, port: u16) -> Result<Output, Box<dyn Error>> {
        output(
            "ip",
            &[
                "netns",
                "exec",
                "td-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "--resolve",
                &format!("{name}:{port}:{ip}"),
                &format!("http://{name}:{port}/route.txt"),
            ],
            None,
        )
    }

    fn https_from(
        &self,
        name: &str,
        address: IpAddr,
        source: &str,
    ) -> Result<Output, Box<dyn Error>> {
        let host = match address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let certificate = self.directory.path().join("tls.crt");
        output(
            "ip",
            &[
                "netns",
                "exec",
                "td-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "8",
                "--interface",
                source,
                "--cacert",
                certificate.to_str().ok_or("TLS certificate path")?,
                "--resolve",
                &format!("{name}:443:{host}"),
                &format!("https://{name}/route.txt"),
            ],
            None,
        )
    }

    fn stop(&mut self) -> TestResult {
        if let Some(child) = self.service.as_mut() {
            let pid = rustix::process::Pid::from_raw(i32::try_from(child.id())?)
                .ok_or("invalid service process ID")?;
            rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
            wait_until(|| Ok(child.try_wait()?.is_some()))?;
            let mut child = self.service.take().ok_or("missing stopped service")?;
            if !child.wait()?.success() {
                return Err(format!(
                    "service shutdown failed: {}",
                    fs::read_to_string(self.directory.path().join("service.log"))?
                )
                .into());
            }
        }
        Ok(())
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        // Cleanup is confined to this disposable container and exact objects created by this fixture.
        if let Some(child) = self.service.as_mut() {
            terminate(child);
        }
        for child in &mut self.children {
            terminate(child);
        }
        for table in [
            "tunnel_detour",
            "lab_firewall",
            "lab_relay_ingress",
            "lab_relay_failure",
            "lab_dns_egress",
            "lab_ipv6_filter",
        ] {
            cleanup("nft", &["delete", "table", "inet", table]);
        }
        for family in ["-4", "-6"] {
            cleanup(
                "ip",
                &[
                    family, "rule", "del", "priority", "11000", "protocol", "242",
                ],
            );
            cleanup(
                "ip",
                &[family, "route", "flush", "table", "41872", "proto", "242"],
            );
        }
        if self.foreign_route_created {
            cleanup(
                "ip",
                &["-4", "route", "flush", "table", "41872", "proto", "99"],
            );
        }
        for device in self.devices.iter().rev() {
            cleanup("ip", &["link", "del", device]);
        }
        for namespace in self.namespaces.iter().rev() {
            cleanup("ip", &["netns", "del", namespace]);
        }
    }
}

fn terminate(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {
            if let Err(error) = child.kill() {
                eprintln!("fixture process cleanup failed: {error}");
            }
        }
        Err(error) => eprintln!("fixture process status failed: {error}"),
    }
    if let Err(error) = child.wait() {
        eprintln!("fixture process wait failed: {error}");
    }
}

fn cleanup(program: &str, args: &[&str]) {
    // Absence is expected after partial setup or normal service cleanup; never touch other objects.
    if let Err(error) = output(program, args, None) {
        eprintln!("fixture object cleanup could not execute: {error}");
    }
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r112_adguard_ipv6_disable_is_preserved_at_startup_and_blocks_cached_identities_before_any_wan_dial()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    lab.start_adguard()?;
    let baseline = lab.api("dns_info", None)?;
    lab.api("dns_config", Some(json!({"disable_ipv6":true})))?;
    assert!(
        lab.start().is_err(),
        "IPv6 startup bypassed AdGuard's disabled family"
    );
    let mut failed = lab.service.take().ok_or("missing refused IPv6 process")?;
    assert!(!failed.wait()?.success());
    let unchanged = lab.api("dns_info", None)?;
    assert_eq!(unchanged["disable_ipv6"], true);
    assert_eq!(unchanged["upstream_dns"], baseline["upstream_dns"]);
    wait_until(|| Ok(lab.status()?["last_error"] == "adguard_ipv6_disabled"))?;
    assert_eq!(
        lab.address("router.example.test")?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    lab.api("dns_config", Some(json!({"disable_ipv6":false})))?;
    lab.start()?;
    let cached = lab.address_family("selected.example.test", true)?;
    assert_eq!(cached, "2001:2::c612:1".parse::<IpAddr>()?);
    command("nft", &["-f", "-"], Some(b"table inet lab_ipv6_filter { counter wan_syns {}\n chain observe { type filter hook output priority 300; policy accept; oifname \"wan0\" tcp dport 80 tcp flags & (syn | ack) == syn counter name wan_syns; }\n}\n"))?;
    assert_eq!(
        lab.http_from("selected.example.test", cached, "fd00:1234::2")?
            .stdout,
        b"wan"
    );
    let before = lab.exception_wan_syns()?;
    assert!(
        before > 0,
        "the observation point missed the successful WAN control"
    );
    lab.api("dns_config", Some(json!({"disable_ipv6":true})))?;
    assert!(
        !lab.http_from("selected.example.test", cached, "fd00:1234::2")?
            .status
            .success(),
        "cached Fake-IP bypassed AdGuard's family switch"
    );
    assert_eq!(
        lab.exception_wan_syns()?,
        before,
        "a disabled family caused a WAN attempt"
    );
    assert_eq!(
        lab.api("dns_info", None)?["disable_ipv6"],
        true,
        "the package silently changed AdGuard"
    );
    wait_until(|| Ok(lab.status()?["last_error"] == "adguard_ipv6_disabled"))?;
    lab.api("dns_config", Some(json!({"disable_ipv6":false})))?;
    assert_eq!(
        lab.http_from("selected.example.test", cached, "fd00:1234::2")?
            .stdout,
        b"wan"
    );
    assert!(lab.exception_wan_syns()? > before);
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r113_adguard_ipv6_client_alias_and_address_filters_prevent_wan_dials_and_persistent_client_overrides_are_respected()
-> TestResult {
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
    lab.prepare_ipv6_wan()?;
    let path = lab.directory.path().join("unbound.conf");
    fs::OpenOptions::new().append(true).open(path)?.write_all(b" local-data: \"ipv6-origin.example.test. 0 IN AAAA 2001:db8:2::2\"\n local-data: \"ipv6-alias.example.test. 0 IN CNAME ipv6-origin.example.test.\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(Lab::query_at(
            "10.254.0.2:5353",
            "ipv6-origin.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .iter()
        .any(|record| matches!(record.data, RData::AAAA(_))))
    })?;
    lab.start_adguard()?;
    let name = "ipv6-alias.example.test";
    lab.config["rules"] = json!([{"pattern":name,"enabled":true}]);
    lab.start()?;
    let cached = lab.address_family(name, true)?;
    command("nft", &["-f", "-"], Some(b"table inet lab_ipv6_filter { counter wan_syns {}\n chain observe { type filter hook output priority 300; policy accept; oifname \"wan0\" tcp dport 80 tcp flags & (syn | ack) == syn counter name wan_syns; }\n}\n"))?;
    assert_eq!(lab.http_from(name, cached, "fd00:1234::2")?.stdout, b"wan6");
    for (rule, target, kind) in [
        (
            "||ipv6-origin.example.test^$dnstype=CNAME,client=fd00:1234::/64",
            "ipv6-origin.example.test",
            "CNAME",
        ),
        (
            "||ipv6-origin.example.test^$dnstype=AAAA,client=fd00:1234::/64",
            "ipv6-origin.example.test",
            "AAAA",
        ),
        (
            "/2001:db8:2::2/$dnstype=AAAA,client=fd00:1234::/64",
            "2001:db8:2::2",
            "AAAA",
        ),
        (
            "/2001:2::c612:1/$dnstype=AAAA,client=fd00:1234::/64",
            "2001:2::c612:1",
            "AAAA",
        ),
    ] {
        lab.api("filtering/set_rules", Some(json!({"rules":[rule]})))?;
        wait_until(|| {
            Ok(lab.api(
                &format!("filtering/check_host?name={target}&qtype={kind}&client=fd00:1234::2"),
                None,
            )?["reason"]
                == "FilteredBlackList")
        })?;
        let before = lab.exception_wan_syns()?;
        assert!(
            !lab.http_from(name, cached, "fd00:1234::2")?
                .status
                .success(),
            "a client-specific rule was bypassed: {rule}"
        );
        assert_eq!(
            lab.exception_wan_syns()?,
            before,
            "a filtered client reached WAN: {rule}"
        );
        wait_until(|| Ok(lab.status()?["last_error"] == "filtered_destination"))?;
        assert_eq!(
            lab.http_from(name, cached, "2001:db8:1::2")?.stdout,
            b"wan6",
            "another IPv6 client inherited the filter"
        );
        let fake4 = lab.address_family(name, false)?;
        assert_eq!(
            lab.http_from(name, fake4, "192.0.2.2")?.stdout,
            b"wan6",
            "the IPv4 client inherited the IPv6 filter"
        );
    }
    // Keep the blocking rule active: only this persistent client's explicit
    // filtering override allows its cached connection to reach the same origin.
    lab.api("clients/add", Some(json!({"name":"Unfiltered fixture", "ids":["fd00:1234::2"], "use_global_settings":false, "filtering_enabled":false, "parental_enabled":false, "safebrowsing_enabled":false, "use_global_blocked_services":true, "upstreams":[]})))?;
    assert_eq!(lab.api("filtering/status", None)?["enabled"], true);
    assert_eq!(
        lab.http_from(name, cached, "fd00:1234::2")?.stdout,
        b"wan6",
        "a persistent IPv6 client's override was ignored"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r111_ipv4_and_ipv6_clients_reach_ipv4_only_ipv6_only_and_dual_stack_origins_through_wan_with_either_resolver_transport()
-> TestResult {
    for resolver_ipv6 in [false, true] {
        let mut lab = Lab::new()?;
        let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
        lab.prepare_ipv6_wan()?;
        if resolver_ipv6 {
            // The second matrix profile has physically separate WAN devices.
            // IPv4 still uses wan0; its IPv6 source and peer move to wan6.
            command(
                "ip",
                &[
                    "link",
                    "add",
                    "wan6",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    "wan6-peer",
                    "netns",
                    "td-wan",
                ],
                None,
            )?;
            lab.devices.push("wan6".into());
            for args in [
                vec!["link", "set", "wan6", "up"],
                vec!["-n", "td-wan", "link", "set", "wan6-peer", "up"],
                vec!["-6", "addr", "del", "2001:db8:2::1/128", "dev", "wan0"],
                vec![
                    "-n",
                    "td-wan",
                    "-6",
                    "addr",
                    "del",
                    "2001:db8:2::2/64",
                    "dev",
                    "wan-peer",
                ],
                vec![
                    "-6",
                    "addr",
                    "add",
                    "2001:db8:2::1/128",
                    "dev",
                    "wan6",
                    "nodad",
                ],
                vec![
                    "-n",
                    "td-wan",
                    "-6",
                    "addr",
                    "add",
                    "2001:db8:2::2/64",
                    "dev",
                    "wan6-peer",
                    "nodad",
                ],
            ] {
                command("ip", &args, None)?;
            }
            lab.config["ipv6"]["wan"]["device"] = json!("wan6");
        }
        let records = " local-data: \"ipv4-only.example.test. 0 IN A 203.0.113.2\"\n local-data: \"ipv6-only.example.test. 0 IN AAAA 2001:db8:2::2\"\n local-data: \"dual.example.test. 0 IN A 203.0.113.2\"\n local-data: \"dual.example.test. 0 IN AAAA 2001:db8:2::2\"\n local-data: \"other.example.test. 0 IN AAAA 2001:db8:2::2\"\n";
        let path = lab.directory.path().join("unbound.conf");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(records.as_bytes())?;
        let resolver = rustix::process::Pid::from_raw(i32::try_from(resolver)?)
            .ok_or("invalid resolver PID")?;
        rustix::process::kill_process(resolver, rustix::process::Signal::HUP)?;
        wait_until(|| {
            Ok(Lab::query_at("10.254.0.2:5353", "ipv6-only.example.test", RecordType::AAAA, true)?.answers.iter().any(|record| matches!(&record.data, RData::AAAA(address) if address.0.to_string()=="2001:db8:2::2")))
        })?;
        if resolver_ipv6 {
            lab.use_ipv6_resolver()?;
        }
        let names = [
            "ipv4-only.example.test",
            "ipv6-only.example.test",
            "dual.example.test",
        ];
        lab.config["rules"] = json!(
            names
                .iter()
                .map(|name| json!({"pattern":name,"enabled":true}))
                .collect::<Vec<_>>()
        );
        lab.start()?;
        for source in ["192.0.2.2", "2001:db8:1::2", "fd00:1234::2"] {
            let client_ipv6 = source.contains(':');
            let kind = if client_ipv6 {
                RecordType::AAAA
            } else {
                RecordType::A
            };
            for (index, name) in names.iter().enumerate() {
                let answer = lab.query(name, kind, false)?;
                let address = match answer.answers.first().map(|record| &record.data) {
                    Some(RData::A(value)) if !client_ipv6 => value.0.to_string(),
                    Some(RData::AAAA(value)) if client_ipv6 => format!("[{}]", value.0),
                    _ => {
                        return Err(
                            format!("missing synthetic family for {source} and {name}").into()
                        );
                    }
                };
                assert_eq!(
                    address,
                    if client_ipv6 {
                        format!("[2001:2::c612:{}]", index + 1)
                    } else {
                        format!("198.18.0.{}", index + 1)
                    }
                );
                let reply = output(
                    "ip",
                    &[
                        "netns",
                        "exec",
                        "td-client",
                        "curl",
                        "--noproxy",
                        "*",
                        "--silent",
                        "--show-error",
                        "--fail",
                        "--max-time",
                        "8",
                        "--interface",
                        source,
                        "--resolve",
                        &format!("{name}:80:{address}"),
                        &format!("http://{name}/route.txt"),
                    ],
                    None,
                )?;
                assert!(
                    reply.status.success(),
                    "source={source}, name={name}, resolver6={resolver_ipv6}: {}; {}",
                    String::from_utf8_lossy(&reply.stderr),
                    fs::read_to_string(lab.directory.path().join("service.log"))?
                );
                let expected = if index == 1 || (index == 2 && client_ipv6) {
                    b"wan6".as_slice()
                } else {
                    b"wan".as_slice()
                };
                assert_eq!(
                    reply.stdout, expected,
                    "wrong WAN family or path for {source} and {name}"
                );
            }
            let address = if client_ipv6 {
                "[2001:db8:2::2]"
            } else {
                "203.0.113.2"
            };
            let ordinary = command(
                "ip",
                &[
                    "netns",
                    "exec",
                    "td-client",
                    "curl",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "3",
                    "--interface",
                    source,
                    "--resolve",
                    &format!("other.example.test:80:{address}"),
                    "http://other.example.test/route.txt",
                ],
                None,
            )?;
            assert_eq!(
                ordinary, b"vpn",
                "shared origin bypassed the tunnel for {source}"
            );
        }
        for kind in [RecordType::HTTPS, RecordType::SVCB] {
            assert!(
                lab.query("dual.example.test", kind, true)?
                    .answers
                    .is_empty(),
                "unimplemented service records escaped suppression"
            );
        }
        lab.stop()?;
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r110_ipv6_routing_claims_refuse_foreign_objects_retry_after_conflict_and_release_without_adopting_later_users()
-> TestResult {
    if env::var("TUNNEL_DETOUR_IPV6_ROUTE_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("route probe requires the isolated network laboratory".into());
        }
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(true)?;
        socket.bind_device(Some(b"wan0"))?;
        socket.set_mark(21572)?;
        socket.bind(&"[2001:db8:2::1]:0".parse::<SocketAddr>()?.into())?;
        socket.connect_timeout(
            &"[2001:db8:2::2]:80".parse::<SocketAddr>()?.into(),
            Duration::from_secs(3),
        )?;
        let mut stream: TcpStream = socket.into();
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.write_all(b"GET /route.txt HTTP/1.0\r\nHost: selected.example.test\r\n\r\n")?;
        let mut reply = Vec::new();
        stream.take(65536).read_to_end(&mut reply)?;
        assert!(
            reply.ends_with(b"wan6"),
            "the owned marked route did not reach the WAN origin"
        );
        return Ok(());
    }
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    let rule = [
        "-6", "rule", "add", "priority", "11000", "fwmark", "21572", "table", "41872", "protocol",
        "242",
    ];
    let route = [
        "-6",
        "route",
        "add",
        "unreachable",
        "default",
        "metric",
        "32767",
        "proto",
        "242",
        "table",
        "41872",
    ];
    let snapshot = || -> Result<(Value, Value), Box<dyn Error>> {
        Ok((
            serde_json::from_slice(&command(
                "ip",
                &["-j", "-N", "-6", "route", "show", "table", "41872"],
                None,
            )?)?,
            serde_json::from_slice(&command(
                "ip",
                &["-j", "-N", "-6", "rule", "show", "pref", "11000"],
                None,
            )?)?,
        ))
    };
    command("ip", &route, None)?;
    command("ip", &rule, None)?;
    let foreign = snapshot()?;
    assert!(
        lab.start().is_err(),
        "cold startup adopted matching foreign IPv6 tags"
    );
    let mut failed = lab.service.take().ok_or("missing refused process")?;
    assert!(!failed.wait()?.success());
    assert_eq!(snapshot()?, foreign, "refusal modified a foreign object");
    assert!(
        !output("nft", &["list", "table", "inet", "tunnel_detour"], None)?
            .status
            .success()
    );
    command(
        "ip",
        &[
            "-6", "rule", "del", "priority", "11000", "fwmark", "21572", "table", "41872",
            "protocol", "242",
        ],
        None,
    )?;
    command(
        "ip",
        &[
            "-6",
            "route",
            "del",
            "unreachable",
            "default",
            "metric",
            "32767",
            "proto",
            "242",
            "table",
            "41872",
        ],
        None,
    )?;
    // Correcting the collision needs no manual removal of a journal or lock.
    lab.start()?;
    let cached = lab.address("selected.example.test")?;
    let probe = Command::new(env::current_exe()?).args(["--ignored", "--exact", "r110_ipv6_routing_claims_refuse_foreign_objects_retry_after_conflict_and_release_without_adopting_later_users", "--nocapture"])
        .env("TUNNEL_DETOUR_IPV6_ROUTE_PROBE", "1").output()?;
    assert!(
        probe.status.success(),
        "marked route probe failed: {} {}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    command(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            "2001:db8:2::99/128",
            "dev",
            "wan0",
            "nodad",
        ],
        None,
    )?;
    command(
        "ip",
        &[
            "-6",
            "route",
            "change",
            "default",
            "dev",
            "wan0",
            "src",
            "2001:db8:2::99",
            "metric",
            "10",
            "proto",
            "242",
            "table",
            "41872",
        ],
        None,
    )?;
    let foreign_source = snapshot()?;
    assert!(
        lab.stop().is_err(),
        "cleanup accepted a different explicit source hint"
    );
    assert_eq!(
        lab.status()?["last_error"],
        "kernel_conflict",
        "cleanup failure lost its actionable status cause"
    );
    assert_eq!(
        snapshot()?,
        foreign_source,
        "cleanup mutated the foreign source hint"
    );
    command(
        "ip",
        &[
            "-6",
            "route",
            "change",
            "default",
            "dev",
            "wan0",
            "src",
            "2001:db8:2::1",
            "metric",
            "10",
            "proto",
            "242",
            "table",
            "41872",
        ],
        None,
    )?;
    lab.start()?;
    assert_eq!(lab.address("selected.example.test")?, cached);
    command(
        "ip",
        &[
            "-6",
            "route",
            "add",
            "2001:db8:bad::/64",
            "dev",
            "lo",
            "proto",
            "242",
            "table",
            "41872",
        ],
        None,
    )?;
    let modified = snapshot()?;
    assert!(
        lab.stop().is_err(),
        "shutdown deleted a foreign prefix with the same tag"
    );
    assert_eq!(snapshot()?, modified);
    command(
        "ip",
        &[
            "-6",
            "route",
            "del",
            "2001:db8:bad::/64",
            "dev",
            "lo",
            "proto",
            "242",
            "table",
            "41872",
        ],
        None,
    )?;
    lab.start()?;
    assert_eq!(lab.address("selected.example.test")?, cached);
    lab.stop()?;
    let empty = snapshot()?;
    assert_eq!(
        empty,
        (json!([]), json!([])),
        "successful stop retained an IPv6 policy"
    );
    // Once released, the IPv4-only mode does not inspect or remove a new owner.
    command("ip", &route, None)?;
    command("ip", &rule, None)?;
    let later = snapshot()?;
    lab.config["ipv6"] = Value::Null;
    lab.start()?;
    assert_eq!(
        lab.http("selected.example.test", cached, 80)?.stdout,
        b"wan"
    );
    assert_eq!(snapshot()?, later);
    lab.stop()?;
    assert_eq!(snapshot()?, later);
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r120_real_https_dns_hints_keep_hostname_identity_and_origin_tls_over_wan_while_alternate_targets_remain_suppressed()
-> TestResult {
    use hickory_proto::rr::rdata::svcb::{SvcParamKey as Key, SvcParamValue as Value};
    for adguard in [false, true] {
        let mut lab = Lab::new()?;
        let resolver = lab.children.last().ok_or("missing resolver")?.id();
        lab.prepare_ipv6_wan()?;
        let path = lab.directory.path().join("unbound.conf");
        let records = " local-data: \"tls4.example.test. 0 IN A 203.0.113.2\"\n local-data: \"tls6.example.test. 0 IN AAAA 2001:db8:2::2\"\n local-data: \"tls4.example.test. 0 IN HTTPS 1 . alpn=h3,http/1.1 port=443 ipv4hint=203.0.113.2 ipv6hint=2001:db8:2::2\"\n local-data: \"tls6.example.test. 0 IN HTTPS 1 . alpn=h3,http/1.1 port=443 ipv4hint=203.0.113.2 ipv6hint=2001:db8:2::2\"\n local-data: \"other.example.test. 0 IN HTTPS 1 . alpn=h3,http/1.1 port=443 ipv4hint=203.0.113.2 ipv6hint=2001:db8:2::2\"\n";
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(records.as_bytes())?;
        let resolver = rustix::process::Pid::from_raw(i32::try_from(resolver)?)
            .ok_or("invalid resolver PID")?;
        rustix::process::kill_process(resolver, rustix::process::Signal::HUP)?;
        wait_until(|| {
            Ok(!Lab::query_at(
                "10.254.0.2:5353",
                "tls4.example.test",
                RecordType::HTTPS,
                true,
            )?
            .answers
            .is_empty())
        })?;
        lab.config["rules"] = json!([{"pattern":"tls4.example.test","enabled":true},{"pattern":"tls6.example.test","enabled":true}]);
        if adguard {
            lab.start_adguard()?;
        }
        lab.start_tls()?;
        lab.start()?;
        for (index, name, body) in [
            (1, "tls4.example.test", b"wan".as_slice()),
            (2, "tls6.example.test", b"wan6".as_slice()),
        ] {
            let expected4: IpAddr = format!("198.18.0.{index}").parse()?;
            let expected6: IpAddr = format!("2001:2::c612:{index}").parse()?;
            for tcp in [false, true] {
                let response = lab.query(name, RecordType::HTTPS, tcp)?;
                assert_eq!(
                    response.answers.len(),
                    1,
                    "missing supported HTTPS binding in frontend={adguard}, TCP={tcp}"
                );
                assert!(!response.metadata.authentic_data);
                assert!(response.additionals.is_empty() && response.authorities.is_empty());
                let RData::HTTPS(binding) = &response.answers[0].data else {
                    return Err("missing HTTPS record".into());
                };
                let mut hints = Vec::new();
                for (key, value) in &binding.0.svc_params {
                    match (key, value) {
                        (Key::Ipv4Hint, Value::Ipv4Hint(values)) => {
                            hints.extend(values.0.iter().map(|address| IpAddr::V4(address.0)))
                        }
                        (Key::Ipv6Hint, Value::Ipv6Hint(values)) => {
                            hints.extend(values.0.iter().map(|address| IpAddr::V6(address.0)))
                        }
                        (Key::Alpn, Value::Alpn(protocols)) => assert_eq!(
                            protocols.0,
                            ["http/1.1"],
                            "HTTP/3 was advertised without its safe datapath"
                        ),
                        _ => {}
                    }
                }
                assert_eq!(
                    hints,
                    [expected4, expected6],
                    "real hints escaped the selected hostname identity"
                );
                if tcp {
                    for hint in hints {
                        let source = if hint.is_ipv6() {
                            "2001:db8:1::2"
                        } else {
                            "192.0.2.2"
                        };
                        let reply = lab.https_from(name, hint, source)?;
                        assert!(
                            reply.status.success(),
                            "hint-based HTTPS failed origin TLS: {}",
                            String::from_utf8_lossy(&reply.stderr)
                        );
                        assert_eq!(
                            reply.stdout, body,
                            "hint escaped the intended WAN origin family"
                        );
                    }
                }
            }
            assert_eq!(lab.address_family(name, false)?, expected4);
            assert_eq!(lab.address_family(name, true)?, expected6);
        }
        let ordinary = lab.query("other.example.test", RecordType::HTTPS, true)?;
        let RData::HTTPS(binding) = &ordinary
            .answers
            .first()
            .ok_or("ordinary HTTPS metadata disappeared")?
            .data
        else {
            return Err("ordinary HTTPS data changed type".into());
        };
        assert!(binding.0.svc_params.iter().any(|(_,value)| matches!(value,Value::Alpn(protocols) if protocols.0.iter().any(|protocol| protocol=="h3"))));
        assert!(binding.0.svc_params.iter().any(|(_,value)| matches!(value,Value::Ipv4Hint(hints) if hints.0.iter().any(|address| address.0==Ipv4Addr::new(203,0,113,2)))));
        let changed = fs::read_to_string(&path)?.replace(
            "tls4.example.test. 0 IN HTTPS 1 .",
            "tls4.example.test. 0 IN HTTPS 1 alternate.example.test.",
        );
        fs::write(&path, changed)?;
        rustix::process::kill_process(resolver, rustix::process::Signal::HUP)?;
        wait_until(|| {
            Ok(lab
                .query("tls4.example.test", RecordType::HTTPS, true)?
                .answers
                .is_empty())
        })?;
        assert_eq!(
            lab.https_from("tls4.example.test", "198.18.0.1".parse()?, "192.0.2.2")?
                .stdout,
            b"wan",
            "suppressed alternate endpoint broke the original TCP fallback"
        );
        assert!(
            lab.query("tls4.example.test", RecordType::SVCB, true)?
                .answers
                .is_empty()
        );
        lab.stop()?;
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r114_dual_stack_blackholes_fall_back_with_bounded_owned_dials_and_shutdown_cancels_pending_sockets()
-> TestResult {
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing resolver")?.id();
    lab.prepare_ipv6_wan()?;
    fs::OpenOptions::new().append(true).open(lab.directory.path().join("unbound.conf"))?
        .write_all(b" local-data: \"fallback.example.test. 0 IN A 203.0.113.2\"\n local-data: \"fallback.example.test. 0 IN AAAA 2001:db8:2::2\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(!Lab::query_at(
            "10.254.0.2:5353",
            "fallback.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .is_empty())
    })?;
    lab.config["rules"] = json!([{"pattern":"fallback.example.test","enabled":true}]);
    lab.config["limits"]["connect_timeout_seconds"] = json!(2);
    lab.start()?;
    let cached4 = lab.address_family("fallback.example.test", false)?;
    let cached6 = lab.address_family("fallback.example.test", true)?;
    command("nft", &["-f", "-"], Some(b"table inet lab_ipv6_filter {\n chain drop_dials {\n type filter hook output priority -2; policy accept;\n }\n}\n"))?;
    for (family, address, source, body) in [
        ("ip6", cached6, "2001:db8:1::2", b"wan".as_slice()),
        ("ip", cached4, "192.0.2.2", b"wan6".as_slice()),
    ] {
        let destination = if family == "ip6" {
            "2001:db8:2::2"
        } else {
            "203.0.113.2"
        };
        let rule = format!(
            "flush chain inet lab_ipv6_filter drop_dials\nadd rule inet lab_ipv6_filter drop_dials oifname wan0 {family} daddr {destination} tcp dport 80 counter drop\n"
        );
        command("nft", &["-f", "-"], Some(rule.as_bytes()))?;
        let started = std::time::Instant::now();
        let response = lab.http_from("fallback.example.test", address, source)?;
        assert!(
            response.status.success(),
            "fallback failed: {}",
            String::from_utf8_lossy(&response.stderr)
        );
        assert_eq!(
            response.stdout, body,
            "fallback used the wrong family or VPN"
        );
        assert!(
            started.elapsed() < Duration::from_millis(1800),
            "the blackholed first family serialized fallback until its deadline"
        );
        let rules: Value = serde_json::from_slice(&command(
            "nft",
            &[
                "-j",
                "list",
                "chain",
                "inet",
                "lab_ipv6_filter",
                "drop_dials",
            ],
            None,
        )?)?;
        assert!(
            rules["nftables"]
                .as_array()
                .ok_or("invalid rules")?
                .iter()
                .any(
                    |entry| entry["rule"]["expr"]
                        .as_array()
                        .is_some_and(|expressions| expressions
                            .iter()
                            .any(|expression| expression["counter"]["packets"]
                                .as_u64()
                                .is_some_and(|packets| packets > 0)))
                ),
            "preferred-family SYN never reached the controlled blackhole"
        );
        let pending = command(
            "ss",
            &["-Htn", "state", "syn-sent", "dport", "=", ":80"],
            None,
        )?;
        assert!(
            pending.is_empty(),
            "a losing dial remained after successful fallback"
        );
    }
    command("nft", &["-f", "-"], Some(b"flush chain inet lab_ipv6_filter drop_dials\nadd rule inet lab_ipv6_filter drop_dials oifname wan0 tcp dport 80 counter drop\n"))?;
    let started = std::time::Instant::now();
    assert!(
        !lab.http_from("fallback.example.test", cached6, "2001:db8:1::2")?
            .status
            .success()
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "both-family blackhole exceeded the overall connection deadline"
    );
    assert!(
        command(
            "ss",
            &["-Htn", "state", "syn-sent", "dport", "=", ":80"],
            None
        )?
        .is_empty(),
        "deadline left a pending dial"
    );
    let log = File::create(lab.directory.path().join("cancel-dials.log"))?;
    let probe_index = lab.children.len();
    lab.children.push(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                "td-client",
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "5",
                "--interface",
                "2001:db8:1::2",
                "--resolve",
                "fallback.example.test:80:[2001:2::c612:1]",
                "http://fallback.example.test/route.txt",
            ])
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    wait_until(|| {
        Ok(!command(
            "ss",
            &["-Htn", "state", "syn-sent", "dport", "=", ":80"],
            None,
        )?
        .is_empty())
    })?;
    lab.stop()?;
    let probe = lab
        .children
        .get_mut(probe_index)
        .ok_or("missing cancellation probe")?;
    wait_until(|| Ok(probe.try_wait()?.is_some()))?;
    assert!(
        !probe.wait()?.success(),
        "shutdown admitted a blackholed pending connection"
    );
    assert!(
        command(
            "ss",
            &["-Htn", "state", "syn-sent", "dport", "=", ":80"],
            None
        )?
        .is_empty(),
        "shutdown left an unowned dial"
    );
    assert_eq!(
        lab.http("other.example.test", Ipv4Addr::new(203, 0, 113, 2), 80)?
            .stdout,
        b"vpn"
    );
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r109_ipv6_preflight_requires_actual_lan_and_preferred_wan_assignments_and_fences_exception_work_after_deprecation()
-> TestResult {
    if env::var("TUNNEL_DETOUR_IPV6_CONTEXT_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let mut stream =
            TcpStream::connect_timeout(&"[2001:2::c612:2]:80".parse()?, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.write_all(b"GET /route.txt HTTP/1.1\r\nHost: context6.example.test\r\n")?;
        return match stream.read(&mut [0; 1]) {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            other => {
                Err(format!("deprecation did not close the active IPv6 session: {other:?}").into())
            }
        };
    }
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing resolver")?.id();
    lab.prepare_ipv6_wan()?;
    fs::OpenOptions::new()
        .append(true)
        .open(lab.directory.path().join("unbound.conf"))?
        .write_all(b" local-data: \"context6.example.test. 0 IN AAAA 2001:db8:2::2\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(!Lab::query_at(
            "10.254.0.2:5353",
            "context6.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .is_empty())
    })?;
    lab.config["rules"]
        .as_array_mut()
        .ok_or("missing rules")?
        .push(json!({"pattern":"context6.example.test","enabled":true}));
    let settings = lab.config["ipv6"].clone();
    for (field, value) in [
        ("source", json!("2001:db8:2::99")),
        ("lan", json!(["2001:db8:99::/64"])),
    ] {
        let mut invalid = settings.clone();
        if field == "source" {
            invalid["wan"]["source"] = value;
        } else {
            invalid["lan_networks"] = value;
        }
        lab.config["ipv6"] = invalid;
        let error = lab
            .start()
            .err()
            .ok_or("an unassigned IPv6 context was accepted")?;
        assert!(
            error
                .to_string()
                .contains("selected IPv6 LAN or preferred WAN source is unavailable"),
            "unexpected startup failure: {error}"
        );
        let mut child = lab
            .service
            .take()
            .ok_or("missing failed IPv6 preflight process")?;
        assert!(!child.wait()?.success());
        assert!(
            !lab.directory.path().join("state/leases.json").exists(),
            "failed preflight wrote lease state"
        );
    }
    lab.config["ipv6"] = settings;
    lab.start()?;
    let cached = lab.address("selected.example.test")?;
    assert_eq!(
        lab.http("selected.example.test", cached, 80)?.stdout,
        b"wan"
    );
    let cached6 = lab.address_family("context6.example.test", true)?;
    assert_eq!(cached6.to_string(), "2001:2::c612:2");
    let log = File::create(lab.directory.path().join("context-probe.log"))?;
    let probe_index = lab.children.len();
    lab.children.push(Command::new("ip").args(["netns", "exec", "td-client"])
        .arg(env::current_exe()?).args(["--ignored", "--exact", "r109_ipv6_preflight_requires_actual_lan_and_preferred_wan_assignments_and_fences_exception_work_after_deprecation", "--nocapture"])
        .env("TUNNEL_DETOUR_IPV6_CONTEXT_PROBE", "1").stdout(log.try_clone()?).stderr(log).spawn()?);
    wait_until(|| {
        Ok(lab.status()?["connections"]
            .as_object()
            .ok_or("invalid connections")?
            .values()
            .any(|connection| connection["destination"] == "[2001:db8:2::2]:80"))
    })?;
    // A real pending DNS job must not replace the source-loss cause with its
    // later timeout while shutdown drains it. Observe both admission and a SYN
    // at the isolated resolver boundary before deprecating the WAN source.
    command(
        "nft",
        &["-f", "-"],
        Some(
            br#"table inet lab_pending_dns {
 chain output { type filter hook output priority -20; policy accept;
  ip daddr 10.254.0.2 tcp dport 5353 counter drop
 }
}
"#,
        ),
    )?;
    let before_queries = lab.status()?["dns_queries"]
        .as_u64()
        .ok_or("missing DNS admission count")?;
    let before_failures = lab.status()?["failures"]
        .as_u64()
        .ok_or("missing failure count")?;
    let pending_dns = UdpSocket::bind("127.0.0.1:0")?;
    let mut question = Message::query();
    question.add_query(Query::query(
        Name::from_ascii("pending.example.test.")?,
        RecordType::A,
    ));
    pending_dns.send_to(&question.to_vec()?, "127.0.0.1:10535")?;
    wait_until(|| {
        let counters: Value = serde_json::from_slice(&command(
            "nft",
            &["-j", "list", "table", "inet", "lab_pending_dns"],
            None,
        )?)?;
        Ok(lab.status()?["dns_queries"]
            .as_u64()
            .is_some_and(|count| count > before_queries)
            && counters["nftables"]
                .as_array()
                .ok_or("invalid pending-DNS counter listing")?
                .iter()
                .filter_map(|object| object["rule"]["expr"].as_array())
                .flatten()
                .any(|expression| {
                    expression["counter"]["packets"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
                }))
    })?;
    command(
        "ip",
        &[
            "-6",
            "addr",
            "change",
            "2001:db8:2::1/128",
            "dev",
            "wan0",
            "preferred_lft",
            "0",
            "valid_lft",
            "600",
        ],
        None,
    )?;
    wait_until(|| {
        Ok(lab
            .service
            .as_mut()
            .ok_or("missing running IPv6 context process")?
            .try_wait()?
            .is_some())
    })?;
    let mut child = lab
        .service
        .take()
        .ok_or("missing terminated IPv6 context process")?;
    assert!(
        !child.wait()?.success(),
        "loss of the preferred source was hidden"
    );
    assert_eq!(lab.status()?["last_error"], "ipv6_path_unavailable");
    assert_eq!(
        lab.status()?["failures"].as_u64(),
        Some(
            before_failures
                .checked_add(2)
                .ok_or("failure count overflow")?
        ),
        "both source loss and the drained DNS timeout must remain counted"
    );
    command("nft", &["delete", "table", "inet", "lab_pending_dns"], None)?;
    let probe = lab
        .children
        .get_mut(probe_index)
        .ok_or("missing context probe")?;
    wait_until(|| Ok(probe.try_wait()?.is_some()))?;
    assert!(
        probe.wait()?.success(),
        "{}",
        fs::read_to_string(lab.directory.path().join("context-probe.log"))?
    );
    assert!(
        !lab.http_from("context6.example.test", cached6, "2001:db8:1::2")?
            .status
            .success()
    );
    assert!(
        !lab.http("selected.example.test", cached, 80)?
            .status
            .success(),
        "a failed IPv6 context opened cached exception fallback"
    );
    assert_eq!(
        lab.http("other.example.test", Ipv4Addr::new(203, 0, 113, 2), 80)?
            .stdout,
        b"vpn"
    );
    command(
        "ip",
        &[
            "-6",
            "addr",
            "change",
            "2001:db8:2::1/128",
            "dev",
            "wan0",
            "preferred_lft",
            "forever",
            "valid_lft",
            "forever",
        ],
        None,
    )?;
    lab.start()?;
    assert_eq!(lab.address("selected.example.test")?, cached);
    assert_eq!(
        lab.http("selected.example.test", cached, 80)?.stdout,
        b"wan"
    );
    assert_eq!(lab.address_family("context6.example.test", true)?, cached6);
    assert_eq!(
        lab.http_from("context6.example.test", cached6, "2001:db8:1::2")?
            .stdout,
        b"wan6"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r108_ipv4_only_mode_fences_cached_and_unknown_paired_ipv6_addresses_on_forward_and_output_without_blocking_other_ranges()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.enable_ipv6()?;
    let root = lab.directory.path().join("vpn");
    for (index, address) in ["2001:2::c612:1", "2001:2::c612:e", "2001:2::c612:10"]
        .into_iter()
        .enumerate()
    {
        command(
            "ip",
            &[
                "-n",
                "td-vpn",
                "-6",
                "addr",
                "add",
                &format!("{address}/128"),
                "dev",
                "lo",
                "nodad",
            ],
            None,
        )?;
        lab.spawn(
            "ip",
            &[
                "netns",
                "exec",
                "td-vpn",
                "busybox",
                "httpd",
                "-f",
                "-p",
                &format!("[{address}]:80"),
                "-h",
                root.to_str().ok_or("invalid VPN fixture path")?,
            ],
            &format!("cached-v6-{index}"),
        )?;
    }
    let fetch = |client: bool, address: &str| -> Result<Output, Box<dyn Error>> {
        let mut arguments = if client {
            vec!["netns", "exec", "td-client", "curl"]
        } else {
            Vec::new()
        };
        let url = format!("http://[{address}]/route.txt");
        arguments.extend([
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "2",
            "--interface",
            if client {
                "2001:db8:1::2"
            } else {
                "2001:db8:1::1"
            },
            &url,
        ]);
        output(if client { "ip" } else { "curl" }, &arguments, None)
    };
    for client in [false, true] {
        for address in ["2001:2::c612:1", "2001:2::c612:e", "2001:2::c612:10"] {
            wait_until(|| {
                let reply = fetch(client, address)?;
                Ok(reply.status.success() && reply.stdout == b"vpn")
            })?;
        }
    }
    lab.start()?;
    assert_eq!(
        lab.address("selected.example.test")?,
        Ipv4Addr::new(198, 18, 0, 1)
    );
    for stopped in [false, true] {
        if stopped {
            lab.stop()?;
        }
        for client in [false, true] {
            for address in ["2001:2::c612:1", "2001:2::c612:e"] {
                assert!(
                    !fetch(client, address)?.status.success(),
                    "paired IPv6 escaped on client={client}, stopped={stopped}, address={address}"
                );
            }
            let outside = fetch(client, "2001:2::c612:10")?;
            assert!(
                outside.status.success(),
                "the guard blocked another synthetic subnet"
            );
            assert_eq!(outside.stdout, b"vpn");
            let ordinary = fetch(client, "2001:db8:2::2")?;
            assert!(ordinary.status.success(), "ordinary IPv6 lost its tunnel");
            assert_eq!(ordinary.stdout, b"vpn");
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r020_shared_real_ip_keeps_selected_traffic_on_wan_and_other_traffic_on_wireguard() -> TestResult
{
    let mut lab = Lab::new()?;
    lab.enable_ipv6()?;
    lab.start()?;
    let selected = lab.address("selected.example.test")?;
    let other = lab.address("other.example.test")?;
    assert_eq!(selected, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(other, Ipv4Addr::new(203, 0, 113, 2));
    let response = lab.http("selected.example.test", selected, 80)?;
    assert!(
        response.status.success(),
        "{}; service log: {}",
        String::from_utf8_lossy(&response.stderr),
        fs::read_to_string(lab.directory.path().join("service.log"))?
    );
    assert_eq!(response.stdout, b"wan");
    let response = lab.http("other.example.test", other, 80)?;
    assert!(response.status.success());
    assert_eq!(response.stdout, b"vpn");
    let ipv6 = command(
        "ip",
        &[
            "netns",
            "exec",
            "td-client",
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "5",
            "--resolve",
            "other.example.test:80:[2001:db8:2::2]",
            "http://other.example.test/route.txt",
        ],
        None,
    )?;
    assert_eq!(
        ipv6, b"vpn",
        "ordinary IPv6 must retain its WireGuard route"
    );
    assert!(
        !lab.http("unrelated.test", Ipv4Addr::new(203, 0, 113, 3), 80)?
            .status
            .success()
    );
    let response = lab.query("selected.example.test", RecordType::A, true)?;
    assert_eq!(
        response.answers[0].data,
        RData::A(hickory_proto::rr::rdata::A(selected))
    );
    for kind in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
        assert!(
            lab.query("selected.example.test", kind, false)?
                .answers
                .is_empty()
        );
    }
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r021_stop_and_restart_preserve_router_administration_and_cached_synthetic_identity() -> TestResult
{
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    lab.start()?;
    let before = lab.address("selected.example.test")?;
    let before6 = lab.address_family("selected.example.test", true)?;
    assert_eq!(
        lab.http_from("selected.example.test", before6, "2001:db8:1::2")?
            .stdout,
        b"wan"
    );
    lab.stop()?;
    assert!(
        !lab.http_from("selected.example.test", before6, "2001:db8:1::2")?
            .status
            .success()
    );
    assert!(
        !lab.http("selected.example.test", before, 80)?
            .status
            .success()
    );
    let administration = lab.http("router.example.test", Ipv4Addr::new(192, 0, 2, 1), 8080)?;
    assert!(administration.status.success());
    assert_eq!(administration.stdout, b"router");
    lab.start()?;
    assert_eq!(lab.address("selected.example.test")?, before);
    assert_eq!(lab.address_family("selected.example.test", true)?, before6);
    assert_eq!(
        lab.http_from("selected.example.test", before6, "2001:db8:1::2")?
            .stdout,
        b"wan"
    );
    assert_eq!(
        lab.http("selected.example.test", before, 80)?.stdout,
        b"wan"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r022_private_and_router_local_destinations_cannot_pivot_through_the_exception_proxy()
-> TestResult {
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
    lab.prepare_ipv6_wan()?;
    let denied6 = [
        "::1",
        "2001:db8:1::1",
        "fd00:1234::1",
        "2001:db8:2::1",
        "fe80::1",
        "ff02::1",
        "::ffff:192.0.2.1",
        "2002:c000:0201::1",
        "2001:0::1",
    ];
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(lab.directory.path().join("unbound.conf"))?;
    for (index, address) in denied6.iter().enumerate() {
        writeln!(
            file,
            " local-data: \"denied6-{index}.example.test. 0 IN AAAA {address}\""
        )?;
    }
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(!Lab::query_at(
            "10.254.0.2:5353",
            "denied6-0.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .is_empty())
    })?;
    lab.config["rules"] = json!([{"pattern":"private.example.test","enabled":true}]);
    for index in 0..denied6.len() {
        lab.config["rules"]
            .as_array_mut()
            .ok_or("missing rules")?
            .push(json!({"pattern":format!("denied6-{index}.example.test"),"enabled":true}));
    }
    lab.start()?;
    let address = lab.address("private.example.test")?;
    assert!(
        !lab.http("private.example.test", address, 80)?
            .status
            .success()
    );
    wait_until(|| Ok(lab.status()?["last_error"] == "forbidden_destination"))?;
    let root = lab.directory.path().join("router-wan");
    fs::create_dir(&root)?;
    fs::write(root.join("route.txt"), "router-wan")?;
    lab.spawn(
        "busybox",
        &[
            "httpd",
            "-f",
            "-p",
            "203.0.113.1:80",
            "-h",
            root.to_str().ok_or("router WAN fixture path")?,
        ],
        "router-wan",
    )?;
    let path = lab.directory.path().join("unbound.conf");
    fs::write(
        &path,
        fs::read_to_string(&path)?.replace(
            "private.example.test. 60 IN A 192.0.2.1",
            "private.example.test. 60 IN A 203.0.113.1",
        ),
    )?;
    let resolver =
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?;
    rustix::process::kill_process(resolver, rustix::process::Signal::HUP)?;
    wait_until(|| {
        if lab
            .http("private.example.test", address, 80)?
            .status
            .success()
        {
            return Err("a public router-local address was reachable through the WAN proxy".into());
        }
        Ok(lab.status()?["last_error"] != "forbidden_destination")
    })?;
    command("nft", &["-f", "-"], Some(b"table inet lab_ipv6_filter {\n counter forbidden_syns {}\n chain observe {\n type filter hook output priority 300; policy accept;\n meta mark 21572 tcp dport 80 tcp flags & (syn | ack) == syn counter name forbidden_syns;\n }\n}\n"))?;
    for (index, denied) in denied6.iter().enumerate() {
        let name = format!("denied6-{index}.example.test");
        let address = lab.address_family(&name, true)?;
        let failures = lab.status()?["failures"]
            .as_u64()
            .ok_or("invalid failure counter")?;
        assert!(
            !lab.http_from(&name, address, "2001:db8:1::2")?
                .status
                .success(),
            "forbidden IPv6 destination was reachable: {}",
            denied
        );
        wait_until(|| {
            let status = lab.status()?;
            Ok(status["last_error"] == "forbidden_destination"
                && status["failures"]
                    .as_u64()
                    .is_some_and(|current| current > failures))
        })?;
    }
    let counters: Value = serde_json::from_slice(&command(
        "nft",
        &[
            "-j",
            "list",
            "counter",
            "inet",
            "lab_ipv6_filter",
            "forbidden_syns",
        ],
        None,
    )?)?;
    assert_eq!(
        counters["nftables"][1]["counter"]["packets"], 0,
        "a forbidden IPv6 target received a WAN dial"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r023_wan_failure_never_falls_back_to_wireguard_or_opens_general_forwarding() -> TestResult {
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
    lab.prepare_ipv6_wan()?;
    fs::OpenOptions::new()
        .append(true)
        .open(lab.directory.path().join("unbound.conf"))?
        .write_all(b" local-data: \"selected.example.test. 0 IN AAAA 2001:db8:2::2\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(!Lab::query_at(
            "10.254.0.2:5353",
            "selected.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .is_empty())
    })?;
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    let address6 = lab.address_family("selected.example.test", true)?;
    assert_eq!(
        lab.http_from("selected.example.test", address6, "2001:db8:1::2")?
            .stdout,
        b"wan6"
    );
    command("ip", &["link", "set", "wan0", "down"], None)?;
    assert!(
        !lab.http_from("selected.example.test", address6, "2001:db8:1::2")?
            .status
            .success(),
        "IPv6 WAN loss fell back to WireGuard"
    );
    assert!(
        !lab.http("selected.example.test", address, 80)?
            .status
            .success()
    );
    assert_eq!(
        lab.http("other.example.test", Ipv4Addr::new(203, 0, 113, 2), 80)?
            .stdout,
        b"vpn"
    );
    assert_eq!(
        lab.http_from(
            "other.example.test",
            "2001:db8:2::2".parse()?,
            "2001:db8:1::2"
        )?
        .stdout,
        b"vpn"
    );
    assert_eq!(
        lab.http("router.example.test", Ipv4Addr::new(192, 0, 2, 1), 8080)?
            .stdout,
        b"router"
    );
    wait_until(|| {
        Ok(lab
            .service
            .as_mut()
            .ok_or("missing failed service")?
            .try_wait()?
            .is_some())
    })
    .map_err(|error| {
        format!(
            "WAN loss did not stop the service: {error}; {:?}",
            lab.status()
        )
    })?;
    let mut failed = lab.service.take().ok_or("missing failed service")?;
    assert!(!failed.wait()?.success(), "lost WAN6 context was hidden");
    command("ip", &["link", "set", "wan0", "up"], None)?;
    // This fixture has no netifd. The kernel removed its manually assigned
    // global IPv6 address on link-down; restore the network's source explicitly.
    command(
        "ip",
        &[
            "-6",
            "addr",
            "replace",
            "2001:db8:2::1/128",
            "dev",
            "wan0",
            "nodad",
        ],
        None,
    )?;
    wait_until(|| {
        let interfaces: Value = serde_json::from_slice(&command(
            "ip",
            &["-j", "-6", "addr", "show", "dev", "wan0"],
            None,
        )?)?;
        Ok(interfaces[0]["addr_info"]
            .as_array()
            .is_some_and(|addresses| {
                addresses.iter().any(|entry| {
                    entry["local"] == "2001:db8:2::1"
                        && entry["tentative"] != true
                        && entry["preferred_life_time"]
                            .as_u64()
                            .is_some_and(|lifetime| lifetime > 0)
                })
            }))
    })
    .map_err(|error| {
        format!(
            "restored WAN source not ready: {error}; {:?}",
            command("ip", &["-j", "-6", "addr", "show", "dev", "wan0"], None)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        )
    })?;
    lab.start()?;
    assert_eq!(lab.address_family("selected.example.test", true)?, address6);
    assert_eq!(
        lab.http_from("selected.example.test", address6, "2001:db8:1::2")?
            .stdout,
        b"wan6"
    );
    assert_eq!(
        lab.http("selected.example.test", address, 80)?.stdout,
        b"wan"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r024_https_preserves_the_origin_certificate_and_tls_without_proxy_certificates() -> TestResult {
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
    lab.prepare_ipv6_wan()?;
    fs::OpenOptions::new().append(true).open(lab.directory.path().join("unbound.conf"))?.write_all(b" local-data: \"tls4.example.test. 0 IN A 203.0.113.2\"\n local-data: \"tls6.example.test. 0 IN AAAA 2001:db8:2::2\"\n local-data: \"tls-alias.example.test. 0 IN CNAME tls-hop1.example.test.\"\n local-data: \"tls-hop1.example.test. 0 IN CNAME tls-hop2.example.test.\"\n local-data: \"tls-hop2.example.test. 0 IN CNAME tls6.example.test.\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(Lab::query_at(
            "10.254.0.2:5353",
            "tls6.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .iter()
        .any(|record| matches!(record.data, RData::AAAA(_))))
    })?;
    lab.config["rules"] = json!([{"pattern":"tls4.example.test","enabled":true},{"pattern":"tls6.example.test","enabled":true}]);
    lab.start_tls()?;
    lab.start()?;
    for source in ["192.0.2.2", "2001:db8:1::2", "fd00:1234::2"] {
        for (name, expected) in [
            ("tls4.example.test", b"wan".as_slice()),
            ("tls6.example.test", b"wan6".as_slice()),
        ] {
            let address = lab.address_family(name, source.contains(':'))?;
            let response = lab.https_from(name, address, source)?;
            assert!(
                response.status.success(),
                "origin TLS validation failed for {source} and {name}: {}",
                String::from_utf8_lossy(&response.stderr)
            );
            assert_eq!(response.stdout, expected);
        }
    }
    lab.stop()?;
    // Real AdGuard control calls share the connection's finite DNS deadline.
    // An explicit loopback delay reproduces a slower control API without
    // weakening filtering or depending on the host's password-hash speed.
    lab.start_adguard()?;
    lab.config["rules"]
        .as_array_mut()
        .ok_or("missing TLS rules")?
        .push(json!({"pattern":"tls-alias.example.test","enabled":true}));
    lab.start()?;
    let identity = lab.address_family("tls-alias.example.test", true)?;
    command(
        "tc",
        &[
            "qdisc", "add", "dev", "lo", "root", "netem", "delay", "150ms",
        ],
        None,
    )?;
    let delayed = lab.https_from("tls-alias.example.test", identity, "fd00:1234::2");
    let cleanup = command("tc", &["qdisc", "del", "dev", "lo", "root"], None);
    cleanup?;
    let delayed = delayed?;
    assert!(
        delayed.status.success(),
        "bounded dual-stack filtering did not complete before the TLS client deadline: {}",
        String::from_utf8_lossy(&delayed.stderr)
    );
    assert_eq!(delayed.stdout, b"wan6");
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r025_adguard_reconciliation_adds_and_removes_only_owned_upstreams_preserving_filters_and_local_names()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.adguard_bind = "192.0.2.1".into();
    lab.start_adguard()?;
    let baseline = lab.api("dns_info", None)?["upstream_dns"].clone();
    let rewrites = lab.api("rewrite/list", None)?;
    let filters = lab.api("filtering/status", None)?["user_rules"].clone();
    lab.config["rules"] = json!([{"pattern":"selected.example.test","enabled":true},{"pattern":"blocked.example.test","enabled":true}]);
    lab.start()?;
    let synthetic = lab.address("selected.example.test")?;
    assert_eq!(synthetic, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(lab.address("blocked.example.test")?, Ipv4Addr::UNSPECIFIED);
    assert_eq!(
        lab.address("router.example.test")?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    lab.stop()?;
    assert_eq!(
        lab.address("router.example.test")?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    lab.config["rules"] = json!([]);
    lab.start()?;
    assert_eq!(
        lab.address("selected.example.test")?,
        Ipv4Addr::new(203, 0, 113, 2)
    );
    assert!(
        !lab.http("selected.example.test", synthetic, 80)?
            .status
            .success()
    );
    assert_eq!(lab.api("dns_info", None)?["upstream_dns"], baseline);
    assert_eq!(lab.api("rewrite/list", None)?, rewrites);
    assert_eq!(lab.api("filtering/status", None)?["user_rules"], filters);
    lab.stop()?;
    lab.config["adguard"]["api_url"] = json!("http://192.0.2.2:13000/");
    let failure = lab
        .start()
        .err()
        .ok_or("an API hosted on another LAN machine was accepted")?;
    assert!(
        failure
            .to_string()
            .contains("AdGuard control endpoint must belong to this router")
    );
    assert_eq!(lab.api("dns_info", None)?["upstream_dns"], baseline);
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r093_real_adguard_upstream_adoption_is_explicit_conflicts_need_fresh_review_and_release_preserves_foreign_dns()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.use_ipv6_resolver()?;
    lab.adguard_dns_bind = "::".into();
    lab.start_adguard()?;
    let initial = vec!["10.254.0.2:5353", "[/unrelated.test/]tcp://10.254.0.2:5353"];
    lab.api("dns_config", Some(json!({"upstream_dns": initial})))?;
    let baseline = lab.api("dns_info", None)?;
    let rewrites = lab.api("rewrite/list", None)?;
    let filters = lab.api("filtering/status", None)?;
    lab.config["manage_adguard_upstream"] = json!(true);
    assert!(
        lab.start().is_err(),
        "adoption without preview was accepted"
    );
    let mut failed = lab.service.take().ok_or("missing failed process")?;
    assert!(!failed.wait()?.success());
    assert_eq!(
        lab.api("dns_info", None)?["upstream_dns"],
        baseline["upstream_dns"]
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let approve = |configuration: &Value| -> Result<Value, Box<dyn Error>> {
        let configuration =
            tunnel_detour_service::ServiceConfig::from_json(&serde_json::to_vec(configuration)?)?;
        Ok(
            runtime.block_on(tunnel_detour_service::preview_adguard_upstream(
                &configuration,
                false,
            ))?,
        )
    };
    let mut recursive = lab.config.clone();
    recursive["real_upstream"] = json!("[::1]:10534");
    assert!(Lab::query_at("[::1]:10534", "other.example.test", RecordType::A, true)?.answers.iter().any(|record| matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(203, 0, 113, 2))), "the alleged IPv6 loop endpoint is not the real AdGuard listener");
    let refusal = approve(&recursive)
        .err()
        .ok_or("the IPv6 AdGuard listener was accepted as its own resolver")?;
    assert!(
        refusal.to_string().contains("DNS loop"),
        "IPv6 loop refused for another reason: {refusal}"
    );
    assert_eq!(
        lab.api("dns_info", None)?["upstream_dns"],
        baseline["upstream_dns"]
    );
    let first = approve(&lab.config)?;
    assert_eq!(
        first["proposed_general"],
        json!(["tcp://[2001:db8:3::2]:5353"])
    );
    assert_eq!(
        lab.api("dns_info", None)?["upstream_dns"],
        baseline["upstream_dns"],
        "preview mutated AdGuard"
    );
    lab.config["adguard_upstream_approval"] = first["receipt"].clone();
    lab.start()?;
    assert_eq!(lab.status()?["applied_resolver"], "[2001:db8:3::2]:5353");
    assert_eq!(
        lab.address("ipv6-resolver.example.test")?,
        Ipv4Addr::new(203, 0, 113, 3),
        "AdGuard did not use the adopted IPv6 TCP upstream"
    );
    let synthetic = lab.address("selected.example.test")?;
    assert_eq!(synthetic, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(
        lab.http("selected.example.test", synthetic, 80)?.stdout,
        b"wan"
    );
    let managed = lab.api("dns_info", None)?;
    assert_eq!(managed["bootstrap_dns"], baseline["bootstrap_dns"]);
    assert_eq!(managed["fallback_dns"], baseline["fallback_dns"]);
    assert!(
        managed["upstream_dns"]
            .as_array()
            .ok_or("upstream list missing")?
            .contains(&json!("tcp://[2001:db8:3::2]:5353"))
    );
    lab.stop()?;
    // Restore the exact pre-adoption list outside Tunnel Detour. The old receipt
    // cannot silently reauthorize an overwrite even though its snapshot matches.
    lab.api("dns_config", Some(json!({"upstream_dns":initial})))?;
    assert!(
        lab.start().is_err(),
        "a consumed preview repaired a foreign edit automatically"
    );
    let mut failed = lab.service.take().ok_or("missing failed process")?;
    assert!(!failed.wait()?.success());
    assert_eq!(
        lab.api("dns_info", None)?["upstream_dns"],
        baseline["upstream_dns"]
    );
    let fresh = approve(&lab.config)?;
    assert_ne!(fresh["receipt"], first["receipt"]);
    lab.config["adguard_upstream_approval"] = fresh["receipt"].clone();
    lab.start()?;
    lab.stop()?;
    let mut with_foreign = lab.api("dns_info", None)?["upstream_dns"]
        .as_array()
        .ok_or("missing upstream list")?
        .clone();
    with_foreign.push(json!("[/later.example.test/]tcp://10.254.0.2:5353"));
    lab.api("dns_config", Some(json!({"upstream_dns":with_foreign})))?;
    lab.config["manage_adguard_upstream"] = json!(false);
    lab.start()?;
    let released = lab.api("dns_info", None)?;
    let released_lines = released["upstream_dns"]
        .as_array()
        .ok_or("missing upstream list")?;
    assert!(released_lines.contains(&json!(initial[0])));
    assert!(!released_lines.contains(&json!("tcp://[2001:db8:3::2]:5353")));
    assert!(released_lines.contains(&json!("[/later.example.test/]tcp://10.254.0.2:5353")));
    assert_eq!(released["bootstrap_dns"], baseline["bootstrap_dns"]);
    assert_eq!(lab.api("rewrite/list", None)?, rewrites);
    assert_eq!(lab.api("filtering/status", None)?, filters);
    assert_eq!(
        lab.address("router.example.test")?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(
        lab.http("selected.example.test", synthetic, 80)?.stdout,
        b"wan"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r094_real_dns_cannot_fall_back_to_wan_when_the_inspected_vpn_path_disappears() -> TestResult {
    for ipv6 in [false, true] {
        resolver_path_stays_pinned(ipv6)
            .map_err(|error| format!("resolver pinning, IPv6={ipv6}: {error}"))?;
    }
    Ok(())
}

fn resolver_path_stays_pinned(ipv6: bool) -> TestResult {
    let mut lab = Lab::new()?;
    let (family, payload, address, host_route, vpn_subnet, gateway, allow) = if ipv6 {
        lab.use_ipv6_resolver()?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:4::1/64",
                "dev",
                "wan0",
                "nodad",
            ],
            None,
        )?;
        command(
            "ip",
            &[
                "-n",
                "td-wan",
                "-6",
                "addr",
                "add",
                "2001:db8:4::2/64",
                "dev",
                "wan-peer",
                "nodad",
            ],
            None,
        )?;
        (
            "-6",
            "ip6",
            "2001:db8:3::2",
            "2001:db8:3::2/128",
            "2001:db8:3::/126",
            "2001:db8:4::2",
            "::/0",
        )
    } else {
        (
            "-4",
            "ip",
            "10.254.0.2",
            "10.254.0.2/32",
            "10.254.0.0/30",
            "203.0.113.2",
            "0.0.0.0/0",
        )
    };
    let endpoint = SocketAddr::new(address.parse()?, 5353).to_string();
    lab.start_adguard()?;
    lab.api(
        "dns_config",
        Some(json!({"upstream_dns":[format!("tcp://{endpoint}")]})),
    )?;
    let wan_config = lab.directory.path().join("wan-dns.conf");
    fs::write(
        &wan_config,
        format!(
            "server:\n interface: {address}@5353\n username: \"\"\n chroot: \"\"\n directory: \"/tmp\"\n pidfile: \"\"\n use-syslog: no\n do-daemonize: no\n module-config: \"iterator\"\n access-control: {allow} allow\n local-zone: \"example.test.\" static\n local-data: \"wan-probe.example.test. 0 IN A 203.0.113.3\"\n"
        ),
    )?;
    let mut loop_address = vec![
        "-n", "td-wan", family, "addr", "add", host_route, "dev", "lo",
    ];
    if ipv6 {
        loop_address.push("nodad");
    }
    command("ip", &loop_address, None)?;
    lab.spawn(
        "ip",
        &[
            "netns",
            "exec",
            "td-wan",
            "unbound",
            "-d",
            "-c",
            wan_config.to_str().ok_or("fixture path")?,
        ],
        "wan-dns",
    )?;
    let wan_route = [
        family, "route", "add", host_route, "via", gateway, "dev", "wan0",
    ];
    command("ip", &wan_route, None)?;
    wait_until(|| {
        Ok(
            std::net::TcpStream::connect_timeout(&endpoint.parse()?, Duration::from_millis(100))
                .is_ok(),
        )
    })?;
    for tcp in [false, true] {
        let control = Lab::query_at(&endpoint, "wan-probe.example.test", RecordType::A, tcp)
            .map_err(|error| format!("WAN control query to {endpoint}, TCP={tcp}: {error}"))?;
        assert!(control.answers.iter().any(|record| matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(203,0,113,3))), "the WAN control resolver was not reachable before activation: {endpoint}, TCP={tcp}");
    }
    command(
        "ip",
        &[
            family, "route", "del", host_route, "via", gateway, "dev", "wan0",
        ],
        None,
    )?;
    command("nft", &["-f", "-"], Some(format!(r#"table inet lab_dns_egress {{
 counter vpn {{}}
 counter attempted_wan {{}}
 counter escaped_wan {{}}
 chain before_guard {{ type filter hook output priority -20; policy accept;
  {payload} daddr {address} meta l4proto {{ tcp, udp }} th dport 5353 oifname "wan0" counter name attempted_wan
 }}
 chain after_guard {{ type filter hook output priority 0; policy accept;
  {payload} daddr {address} meta l4proto {{ tcp, udp }} th dport 5353 oifname "wan0" counter name escaped_wan
  {payload} daddr {address} meta l4proto {{ tcp, udp }} th dport 5353 oifname "wg0" counter name vpn
 }}
}}
"#).as_bytes()))?;
    let packets = |name: &str| -> Result<u64, Box<dyn Error>> {
        let listing: Value = serde_json::from_slice(&command(
            "nft",
            &["-j", "list", "counter", "inet", "lab_dns_egress", name],
            None,
        )?)?;
        listing["nftables"]
            .as_array()
            .ok_or("counter list")?
            .iter()
            .find_map(|item| item["counter"]["packets"].as_u64())
            .ok_or_else(|| "counter packets missing".into())
    };
    // The published version's owned table predates resolver guards. Its upgrade
    // must retain the ordinary routing policy while installing the new owner.
    command(
        "nft",
        &["-f", "-"],
        Some(
            br#"table inet tunnel_detour {
 comment "tunnel-detour:v1"
 chain output_guard { type filter hook output priority -5; policy accept;
  ip daddr 198.18.0.0/15 reject with icmpx type admin-prohibited
 }
}
"#,
        ),
    )?;
    lab.start()?;
    assert_eq!(
        lab.address("other.example.test")
            .map_err(|error| format!("initial ordinary DNS: {error}"))?,
        Ipv4Addr::new(203, 0, 113, 2)
    );
    let synthetic = lab.address("selected.example.test")?;
    assert_eq!(
        lab.http("selected.example.test", synthetic, 80)?.stdout,
        b"wan"
    );
    assert!(packets("vpn")? > 0);
    command("ip", &wan_route, None)?;
    command(
        "ip",
        &[family, "route", "del", vpn_subnet, "dev", "wg0"],
        None,
    )?;
    command(
        "ip",
        &[family, "route", "del", "default", "dev", "wg0"],
        None,
    )?;
    let route: Value = serde_json::from_slice(&command(
        "ip",
        &["-j", family, "route", "get", address],
        None,
    )?)?;
    assert_eq!(
        route[0]["dev"], "wan0",
        "the failed-path control did not select WAN"
    );
    // A device-bound socket can form a direct route on an up WireGuard
    // device. Make that path unavailable before requiring DNS failure.
    command("ip", &["link", "set", "wg0", "down"], None)?;
    lab.api("cache_clear", Some(json!({})))?;
    let response = lab.query("wan-probe.example.test", RecordType::A, false);
    assert!(
        response.is_err()
            || response
                .as_ref()
                .is_ok_and(|reply| reply.metadata.response_code
                    == hickory_proto::op::ResponseCode::ServFail),
        "AdGuard reached the WAN control resolver after VPN loss"
    );
    assert!(
        !lab.http("selected.example.test", synthetic, 80)?
            .status
            .success(),
        "the destination resolver escaped its bound VPN path"
    );
    for tcp in [false, true] {
        assert!(
            Lab::query_at(&endpoint, "wan-probe.example.test", RecordType::A, tcp).is_err(),
            "a router DNS socket bypassed the pinned path"
        );
    }
    assert!(packets("attempted_wan")? > 0, "the guard was not exercised");
    assert_eq!(packets("escaped_wan")?, 0, "real DNS escaped on WAN");
    assert_eq!(
        lab.address("router.example.test")?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(
        output(
            "ip",
            &[
                "netns",
                "exec",
                "td-client",
                "curl",
                "--noproxy",
                "*",
                "--fail",
                "--silent",
                "--max-time",
                "2",
                "http://192.0.2.1:8080/route.txt"
            ],
            None
        )?
        .stdout,
        b"router"
    );
    lab.stop()?;
    assert!(
        lab.start().is_err(),
        "cold startup accepted a WAN-only resolver path"
    );
    let mut failed = lab.service.take().ok_or("missing failed startup")?;
    assert!(!failed.wait()?.success());
    // A replacement with a valid local route but unavailable control API must
    // retain the old resolver's guard throughout failed startup and recovery.
    let original_api = lab.config["adguard"]["api_url"].clone();
    lab.config["real_upstream"] = json!("127.0.0.1:15353");
    lab.config["adguard"]["api_url"] = json!("http://127.0.0.1:13001");
    assert!(lab.start().is_err());
    let mut failed = lab.service.take().ok_or("missing control failure")?;
    assert!(!failed.wait()?.success());
    for tcp in [false, true] {
        assert!(Lab::query_at(&endpoint, "wan-probe.example.test", RecordType::A, tcp).is_err());
    }
    assert_eq!(
        packets("escaped_wan")?,
        0,
        "failed activation removed the preceding DNS guard"
    );
    let protected = command(
        "nft",
        &[
            "-j",
            "list",
            "chain",
            "inet",
            "tunnel_detour",
            "resolver_guard",
        ],
        None,
    )?;
    lab.config["real_upstream"] = json!("127.0.0.1:15354");
    assert!(
        lab.start().is_err(),
        "an unresolved third endpoint replaced the protected pair"
    );
    let mut failed = lab.service.take().ok_or("missing recovery refusal")?;
    assert!(!failed.wait()?.success());
    let refused = lab.status()?;
    assert_eq!(refused["last_error"], "resolver_recovery_required");
    assert_eq!(
        refused["recovery_resolvers"],
        json!([endpoint, "127.0.0.1:15353"])
    );
    assert_eq!(
        command(
            "nft",
            &[
                "-j",
                "list",
                "chain",
                "inet",
                "tunnel_detour",
                "resolver_guard"
            ],
            None
        )?,
        protected
    );
    lab.config["real_upstream"] = json!(endpoint);
    lab.config["adguard"]["api_url"] = original_api;
    command(
        "ip",
        &[
            family, "route", "del", host_route, "via", gateway, "dev", "wan0",
        ],
        None,
    )?;
    command("ip", &["link", "set", "wg0", "up"], None)?;
    if ipv6 {
        let addresses: Value = serde_json::from_slice(&command(
            "ip",
            &["-j", "-6", "addr", "show", "dev", "wg0"],
            None,
        )?)?;
        eprintln!("IPv6 WireGuard addresses before restoring fixture configuration: {addresses}");
        // Link-up does not restore IPv6 addresses flushed by link-down. Restore
        // the owned VPN address as well as its routes, as netifd would.
        command(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                "2001:db8:3::1/126",
                "dev",
                "wg0",
                "nodad",
            ],
            None,
        )?;
    }
    command(
        "ip",
        &[family, "route", "replace", vpn_subnet, "dev", "wg0"],
        None,
    )?;
    command(
        "ip",
        &[family, "route", "add", "default", "dev", "wg0"],
        None,
    )?;
    let restored = Lab::query_at(&endpoint, "other.example.test", RecordType::A, true)
        .map_err(|error| format!("restored VPN resolver transport: {error}"))?;
    assert!(restored.answers.iter().any(|record| matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(203, 0, 113, 2))), "restored VPN resolver returned the WAN control answer");
    lab.api("cache_clear", Some(json!({})))?;
    lab.start()?;
    assert_eq!(
        lab.address("other.example.test")
            .map_err(|error| format!("recovered ordinary DNS: {error}"))?,
        Ipv4Addr::new(203, 0, 113, 2)
    );
    assert_eq!(
        lab.http("selected.example.test", synthetic, 80)?.stdout,
        b"wan"
    );
    assert_eq!(packets("escaped_wan")?, 0);
    let recovered: Value = serde_json::from_slice(&command(
        "nft",
        &[
            "-j",
            "list",
            "chain",
            "inet",
            "tunnel_detour",
            "resolver_guard",
        ],
        None,
    )?)?;
    assert_eq!(
        recovered["nftables"]
            .as_array()
            .ok_or("missing guard rules")?
            .iter()
            .filter(|object| object.get("rule").is_some())
            .count(),
        2,
        "recovery retained the retired replacement resolver"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r037_adguard_dns_over_tls_on_ipv4_and_ipv6_preserves_fake_ip_filtering_and_management_access()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.enable_ipv6()?;
    lab.adguard_bind = "192.0.2.1".into();
    lab.adguard_dns_bind = "::".into();
    lab.start_adguard()?;
    assert_eq!(lab.api("status", None)?["version"], "v0.107.79");
    let baseline = lab.api("dns_info", None)?["upstream_dns"].clone();
    lab.enable_adguard_dot()?;
    lab.config["rules"] = json!([{"pattern":"selected.example.test","enabled":true},{"pattern":"blocked.example.test","enabled":true}]);
    lab.start()?;
    for ipv6 in [false, true] {
        let selected = lab.query_dot("selected.example.test", RecordType::A, ipv6)?;
        assert!(
            matches!(selected.answers.first().map(|answer|&answer.data),Some(RData::A(address)) if address.0==Ipv4Addr::new(198,18,0,1))
        );
        for kind in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let response = lab.query_dot("selected.example.test", kind, ipv6)?;
            assert_eq!(
                response.metadata.response_code,
                hickory_proto::op::ResponseCode::NoError
            );
            assert!(response.answers.is_empty());
        }
        let blocked = lab.query_dot("blocked.example.test", RecordType::A, ipv6)?;
        assert!(
            matches!(blocked.answers.first().map(|answer|&answer.data),Some(RData::A(address)) if address.0.is_unspecified())
        );
        let other = lab.query_dot("other.example.test", RecordType::A, ipv6)?;
        assert!(
            matches!(other.answers.first().map(|answer|&answer.data),Some(RData::A(address)) if address.0==Ipv4Addr::new(203,0,113,2))
        );
    }
    let tls = lab.api("tls/status", None)?;
    assert_eq!(tls["enabled"], true);
    assert_eq!(tls["port_dns_over_tls"], 853);
    assert!(matches!(tls["port_https"].as_u64(), None | Some(0)));
    assert!(matches!(tls["port_dns_over_quic"].as_u64(), None | Some(0)));
    assert_eq!(tls["force_https"], false);
    assert_eq!(
        lab.address("selected.example.test")?,
        Ipv4Addr::new(198, 18, 0, 1)
    );
    assert_eq!(
        lab.http("selected.example.test", Ipv4Addr::new(198, 18, 0, 1), 80)?
            .stdout,
        b"wan"
    );
    lab.stop()?;
    lab.config["rules"] = json!([]);
    lab.start()?;
    let response = lab.query_dot("selected.example.test", RecordType::A, false)?;
    assert!(
        matches!(response.answers.first().map(|answer|&answer.data),Some(RData::A(address)) if address.0==Ipv4Addr::new(203,0,113,2))
    );
    assert_eq!(lab.api("dns_info", None)?["upstream_dns"], baseline);
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r026_real_dns_aliases_and_addresses_remain_subject_to_adguard_filtering_before_wan_connect()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.start_adguard()?;
    lab.config["rules"] = json!([{"pattern": "alias.example.test", "enabled": true}]);
    lab.start()?;
    let synthetic = lab.address("alias.example.test")?;
    assert_eq!(lab.api("status", None)?["protection_enabled"], true);
    assert_eq!(lab.api("filtering/status", None)?["enabled"], true);
    assert_eq!(
        String::from_utf8(lab.http("alias.example.test", synthetic, 80)?.stdout)?,
        "wan"
    );
    lab.api(
        "filtering/set_rules",
        Some(json!({"rules": ["||selected.example.test^$dnstype=CNAME"]})),
    )?;
    wait_until(|| {
        Ok(lab.api(
            "filtering/check_host?name=selected.example.test&qtype=CNAME&client=192.0.2.2",
            None,
        )?["reason"]
            == "FilteredBlackList")
    })?;
    assert!(
        !lab.http("alias.example.test", synthetic, 80)?
            .status
            .success(),
        "blocked CNAME target reached WAN"
    );
    lab.api(
        "filtering/set_rules",
        Some(json!({"rules": ["||203.0.113.2^$dnstype=A"]})),
    )?;
    wait_until(|| {
        Ok(lab.api(
            "filtering/check_host?name=203.0.113.2&qtype=A&client=192.0.2.2",
            None,
        )?["reason"]
            == "FilteredBlackList")
    })?;
    assert!(
        !lab.http("alias.example.test", synthetic, 80)?
            .status
            .success(),
        "blocked real A address reached WAN"
    );
    lab.api(
        "filtering/set_rules",
        Some(json!({"rules":[format!("||{synthetic}^$dnstype=A")]})),
    )?;
    wait_until(|| {
        Ok(lab.api(
            &format!("filtering/check_host?name={synthetic}&qtype=A&client=192.0.2.2"),
            None,
        )?["reason"]
            == "FilteredBlackList")
    })?;
    assert!(
        !lab.http("alias.example.test", synthetic, 80)?
            .status
            .success(),
        "a cached synthetic A address bypassed filtering"
    );
    lab.api(
        "filtering/config",
        Some(json!({"enabled": false, "interval": 24})),
    )?;
    assert_eq!(
        String::from_utf8(lab.http("alias.example.test", synthetic, 80)?.stdout)?,
        "wan",
        "disabling AdGuard filtering must be respected"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r027_quic_datagrams_receive_an_explicit_rejection_while_tcp_fallback_still_reaches_wan()
-> TestResult {
    if let Ok(family) = env::var("TUNNEL_DETOUR_QUIC_PROBE") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let ipv6 = family == "6";
        let socket = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" })?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect(if ipv6 {
            "[2001:2::c612:1]:443"
        } else {
            "198.18.0.1:443"
        })?;
        socket.send(b"synthetic UDP transport probe")?;
        return match socket.recv(&mut [0; 1]) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(format!("expected an ICMP port rejection, received {error}").into()),
            Ok(_) => Err("the synthetic QUIC destination replied instead of rejecting UDP".into()),
        };
    }
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    lab.start_tls()?;
    lab.start()?;
    assert_eq!(
        lab.address("selected.example.test")?,
        Ipv4Addr::new(198, 18, 0, 1)
    );
    let executable = env::current_exe()?;
    for family in ["4", "6"] {
        let result = Command::new("ip").args(["netns", "exec", "td-client"])
        .arg(&executable).args(["--ignored", "--exact", "r027_quic_datagrams_receive_an_explicit_rejection_while_tcp_fallback_still_reaches_wan", "--nocapture"])
        .env("TUNNEL_DETOUR_QUIC_PROBE", family).output()?;
        assert!(
            result.status.success(),
            "client UDP rejection failed: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        let ipv6 = family == "6";
        let address = lab.address_family("selected.example.test", ipv6)?;
        let fallback = lab.https_from(
            "selected.example.test",
            address,
            if ipv6 { "2001:db8:1::2" } else { "192.0.2.2" },
        )?;
        assert!(
            fallback.status.success(),
            "TCP fallback did not validate origin TLS"
        );
        assert_eq!(fallback.stdout, b"wan");
    }
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r028_startup_refuses_foreign_firewall_or_routing_objects_without_changing_them() -> TestResult {
    let mut lab = Lab::new()?;
    command("nft", &["-f", "-"], Some(b"table inet tunnel_detour {\n comment \"foreign owner\"\n chain sentinel {\n ip saddr 192.0.2.0/24 counter\n }\n}\n"))?;
    let before = command(
        "nft",
        &["-j", "list", "table", "inet", "tunnel_detour"],
        None,
    )?;
    assert!(
        lab.start().is_err(),
        "service replaced a foreign firewall table"
    );
    assert_eq!(
        command(
            "nft",
            &["-j", "list", "table", "inet", "tunnel_detour"],
            None
        )?,
        before
    );
    command("nft", &["delete", "table", "inet", "tunnel_detour"], None)?;
    command(
        "ip",
        &[
            "-4",
            "route",
            "add",
            "unreachable",
            "default",
            "table",
            "41872",
            "proto",
            "99",
        ],
        None,
    )?;
    lab.foreign_route_created = true;
    let before = command(
        "ip",
        &["-j", "-N", "-4", "route", "show", "table", "41872"],
        None,
    )?;
    assert!(
        lab.start().is_err(),
        "service replaced a foreign routing table"
    );
    assert_eq!(
        command(
            "ip",
            &["-j", "-N", "-4", "route", "show", "table", "41872"],
            None
        )?,
        before
    );
    // This protocol belongs only to this test and must not escape its disposable namespace.
    command(
        "ip",
        &["-4", "route", "flush", "table", "41872", "proto", "99"],
        None,
    )?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r029_invalid_or_missing_adguard_ownership_state_cannot_remove_foreign_upstreams() -> TestResult {
    let mut lab = Lab::new()?;
    lab.start_adguard()?;
    lab.start()?;
    lab.stop()?;
    let baseline = lab.api("dns_info", None)?["upstream_dns"].clone();
    let state = lab.config["state_file"]
        .as_str()
        .ok_or("missing state path")?;
    let journal = format!("{state}.adguard.json");
    let original = fs::read(&journal)?;
    fs::write(
        &journal,
        serde_json::to_vec(&json!({"version":1, "managed":["tcp://10.254.0.2:5353"]}))?,
    )?;
    assert!(lab.start().is_err(), "invalid ownership state was accepted");
    assert_eq!(lab.api("dns_info", None)?["upstream_dns"], baseline);
    fs::remove_file(&journal)?;
    assert!(
        lab.start().is_err(),
        "missing ownership state was silently reset"
    );
    assert_eq!(lab.api("dns_info", None)?["upstream_dns"], baseline);
    fs::write(&journal, original)?;
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
    lab.start()?;
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r033_only_authorized_lan_sources_reach_the_proxy_and_dns_is_private_to_loopback() -> TestResult {
    if let Ok(role) = env::var("TUNNEL_DETOUR_SOURCE_PROBE") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let address: SocketAddr = match role.as_str() {
            "lan" => "192.0.2.1:10535",
            "lan6" => "[2001:db8:1::1]:10535",
            "wan6" => "[2001:db8:2::1]:10536",
            _ => "203.0.113.1:10536",
        }
        .parse()?;
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err(),
            "private service port accepted a remote TCP connection"
        );
        if matches!(role.as_str(), "lan" | "lan6") {
            let socket = UdpSocket::bind(if role == "lan6" {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.connect(address)?;
            let mut query = Message::query();
            query.add_query(Query::query(
                Name::from_ascii("selected.example.test.")?,
                RecordType::A,
            ));
            socket.send(&query.to_vec()?)?;
            match socket.recv(&mut [0; 512]) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(error) => {
                    return Err(format!("private DNS port did not reject UDP: {error}").into());
                }
                Ok(_) => {
                    return Err("the private DNS listener answered a remote LAN request".into());
                }
            }
        }
        return Ok(());
    }
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    lab.config["trusted_clients"] =
        json!(["192.0.2.2/32", "2001:db8:1::2/128", "fd00:1234::2/128"]);
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    assert_eq!(
        lab.http_from("selected.example.test", address.into(), "192.0.2.2")?
            .stdout,
        b"wan"
    );
    command(
        "ip",
        &[
            "-n",
            "td-client",
            "addr",
            "add",
            "192.0.2.3/24",
            "dev",
            "lan-peer",
        ],
        None,
    )?;
    assert!(
        !lab.http_from("selected.example.test", address.into(), "192.0.2.3")?
            .status
            .success(),
        "a non-trusted client in the selected LAN reached WAN"
    );
    for (namespace, role) in [
        ("td-client", "lan"),
        ("td-wan", "wan"),
        ("td-client", "lan6"),
        ("td-wan", "wan6"),
    ] {
        let probe = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "r033_only_authorized_lan_sources_reach_the_proxy_and_dns_is_private_to_loopback",
                "--nocapture",
            ])
            .env("TUNNEL_DETOUR_SOURCE_PROBE", role)
            .output()?;
        assert!(
            probe.status.success(),
            "source probe failed: {}",
            String::from_utf8_lossy(&probe.stdout)
        );
    }
    command("ip", &["addr", "add", "192.0.3.1/24", "dev", "lan0"], None)?;
    command(
        "ip",
        &[
            "-n",
            "td-client",
            "addr",
            "add",
            "192.0.3.2/24",
            "dev",
            "lan-peer",
        ],
        None,
    )?;
    let denied = output(
        "ip",
        &[
            "netns",
            "exec",
            "td-client",
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--fail",
            "--max-time",
            "2",
            "--interface",
            "192.0.3.2",
            "--resolve",
            &format!("selected.example.test:80:{address}"),
            "http://selected.example.test/route.txt",
        ],
        None,
    )?;
    assert!(
        !denied.status.success(),
        "a LAN address outside the authorized subnets reached WAN"
    );
    command(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            "2001:db8:99::1/64",
            "dev",
            "lan0",
            "nodad",
        ],
        None,
    )?;
    command(
        "ip",
        &[
            "-n",
            "td-client",
            "-6",
            "addr",
            "add",
            "2001:db8:99::2/64",
            "dev",
            "lan-peer",
            "nodad",
        ],
        None,
    )?;
    let address6 = lab.address_family("selected.example.test", true)?;
    assert!(
        !lab.http_from("selected.example.test", address6, "2001:db8:99::2")?
            .status
            .success(),
        "an unauthorized IPv6 LAN source reached WAN"
    );
    let direct = output(
        "ip",
        &[
            "netns",
            "exec",
            "td-client",
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--fail",
            "--max-time",
            "2",
            "http://[2001:db8:1::1]:10536/route.txt",
        ],
        None,
    )?;
    assert!(
        !direct.status.success(),
        "direct IPv6 proxy use bypassed original-destination authorization"
    );
    for source in ["2001:db8:1::2", "fd00:1234::2"] {
        assert_eq!(
            lab.http_from("selected.example.test", address6, source)?
                .stdout,
            b"wan"
        );
    }
    assert_eq!(
        lab.http("selected.example.test", address, 80)?.stdout,
        b"wan"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r034_connection_limits_and_descriptor_failure_preserve_isolation_recovery_and_other_services()
-> TestResult {
    if env::var("TUNNEL_DETOUR_RESOURCE_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let mut streams = Vec::new();
        for address in ["198.18.0.1:80", "[2001:2::c612:1]:80"] {
            let address: SocketAddr = address.parse()?;
            let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
            stream.set_read_timeout(Some(Duration::from_secs(15)))?;
            stream.write_all(b"GET /route.txt HTTP/1.1\r\nHost: selected.example.test\r\n")?;
            streams.push(stream);
        }
        for mut stream in streams {
            match stream.read(&mut [0; 1]) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) => {}
                other => {
                    return Err(format!(
                        "an active relay was not closed during shutdown: {other:?}"
                    )
                    .into());
                }
            }
        }
        return Ok(());
    }
    let mut lab = Lab::new()?;
    lab.prepare_ipv6_wan()?;
    lab.config["limits"]["connections"] = json!(2);
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    let spawn_probe = |lab: &mut Lab, name: &str| -> Result<usize, Box<dyn Error>> {
        let log = File::create(lab.directory.path().join(name))?;
        let index = lab.children.len();
        lab.children.push(Command::new("ip").args(["netns", "exec", "td-client"]).arg(env::current_exe()?)
            .args(["--ignored", "--exact", "r034_connection_limits_and_descriptor_failure_preserve_isolation_recovery_and_other_services", "--nocapture"])
            .env("TUNNEL_DETOUR_RESOURCE_PROBE", "1").stdout(log.try_clone()?).stderr(log).spawn()?);
        Ok(index)
    };
    let probe_index = spawn_probe(&mut lab, "resource-probe.log")?;
    wait_until(|| {
        Ok(lab.status()?["connections"]
            .as_object()
            .ok_or("invalid connection status")?
            .len()
            == 2)
    })?;
    for (ipv6, source) in [(false, "192.0.2.2"), (true, "2001:db8:1::2")] {
        let target = lab.address_family("selected.example.test", ipv6)?;
        assert!(
            !lab.http_from("selected.example.test", target, source)?
                .status
                .success(),
            "an additional relay exceeded the shared IPv4/IPv6 connection bound"
        );
    }
    wait_until(|| Ok(lab.status()?["last_error"] == "capacity_exhausted"))?;
    assert_eq!(
        lab.address("selected.example.test")?,
        address,
        "DNS must remain responsive at the connection limit"
    );
    assert_eq!(
        lab.http("other.example.test", Ipv4Addr::new(203, 0, 113, 2), 80)?
            .stdout,
        b"vpn"
    );
    assert_eq!(
        lab.http("router.example.test", Ipv4Addr::new(192, 0, 2, 1), 8080)?
            .stdout,
        b"router"
    );
    lab.stop()?;
    let probe = lab
        .children
        .get_mut(probe_index)
        .ok_or("resource probe is absent")?;
    wait_until(|| Ok(probe.try_wait()?.is_some()))?;
    assert!(
        probe.wait()?.success(),
        "resource probe failed: {}",
        fs::read_to_string(lab.directory.path().join("resource-probe.log"))?
    );
    assert!(
        lab.status()?["connections"]
            .as_object()
            .ok_or("invalid final status")?
            .is_empty()
    );

    // Exhaust only the owned controller's descriptors, never the fixture,
    // another daemon or the host. Existing sockets stay open; new opens fail.
    lab.start()?;
    let cached = [
        (
            lab.address_family("selected.example.test", false)?,
            "192.0.2.2",
        ),
        (
            lab.address_family("selected.example.test", true)?,
            "2001:db8:1::2",
        ),
    ];
    let probe_index = spawn_probe(&mut lab, "descriptor-probe.log")?;
    wait_until(|| {
        Ok(lab.status()?["connections"]
            .as_object()
            .ok_or("invalid active descriptor probe")?
            .len()
            == 2)
    })?;
    let state = lab.config["state_file"]
        .as_str()
        .ok_or("missing state path")?;
    let durable = fs::read(state)?;
    let child = lab.service.as_mut().ok_or("missing controller")?;
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id())?)
        .ok_or("invalid controller PID")?;
    rustix::process::prlimit(
        Some(pid),
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    wait_until(|| Ok(child.try_wait()?.is_some()))?;
    let mut child = lab.service.take().ok_or("missing failed controller")?;
    assert!(
        !child.wait()?.success(),
        "descriptor exhaustion was silently reported as a healthy stop"
    );
    let probe = lab
        .children
        .get_mut(probe_index)
        .ok_or("missing descriptor probe")?;
    wait_until(|| Ok(probe.try_wait()?.is_some()))?;
    assert!(
        probe.wait()?.success(),
        "descriptor failure left a stream open"
    );
    assert_eq!(
        fs::read(state)?,
        durable,
        "descriptor failure damaged durable identities"
    );
    for (target, source) in cached {
        assert!(
            !lab.http_from("selected.example.test", target, source)?
                .status
                .success(),
            "cached identity escaped after the controller lost its descriptors"
        );
    }
    assert_eq!(
        lab.http("other.example.test", Ipv4Addr::new(203, 0, 113, 2), 80)?
            .stdout,
        b"vpn"
    );
    assert_eq!(
        lab.http("router.example.test", Ipv4Addr::new(192, 0, 2, 1), 8080)?
            .stdout,
        b"router"
    );
    lab.start()?;
    for ((target, source), ipv6) in cached.into_iter().zip([false, true]) {
        assert_eq!(lab.address_family("selected.example.test", ipv6)?, target);
        assert_eq!(
            lab.http_from("selected.example.test", target, source)?
                .stdout,
            b"wan"
        );
    }
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r035_real_ip_changes_take_effect_for_cached_fake_ips_without_firewall_rule_updates() -> TestResult
{
    let mut lab = Lab::new()?;
    let resolver = lab.children.last().ok_or("missing initial resolver")?.id();
    lab.prepare_ipv6_wan()?;
    fs::OpenOptions::new()
        .append(true)
        .open(lab.directory.path().join("unbound.conf"))?
        .write_all(b" local-data: \"selected.example.test. 0 IN AAAA 2001:db8:2::2\"\n")?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?,
        rustix::process::Signal::HUP,
    )?;
    wait_until(|| {
        Ok(!Lab::query_at(
            "10.254.0.2:5353",
            "selected.example.test",
            RecordType::AAAA,
            true,
        )?
        .answers
        .is_empty())
    })?;
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    let address6 = lab.address_family("selected.example.test", true)?;
    assert_eq!(
        lab.http_from("selected.example.test", address6, "2001:db8:1::2")?
            .stdout,
        b"wan6"
    );
    assert_eq!(
        lab.http("selected.example.test", address, 80)?.stdout,
        b"wan"
    );
    let firewall = command(
        "nft",
        &["-j", "list", "table", "inet", "tunnel_detour"],
        None,
    )?;
    let root = lab.directory.path().join("changed");
    fs::create_dir(&root)?;
    fs::write(root.join("route.txt"), "changed")?;
    lab.spawn(
        "ip",
        &[
            "netns",
            "exec",
            "td-wan",
            "busybox",
            "httpd",
            "-f",
            "-p",
            "203.0.113.3:80",
            "-h",
            root.to_str().ok_or("changed fixture path")?,
        ],
        "changed",
    )?;
    command(
        "ip",
        &[
            "-n",
            "td-wan",
            "-6",
            "addr",
            "add",
            "2001:db8:2::3/64",
            "dev",
            "wan-peer",
            "nodad",
        ],
        None,
    )?;
    lab.spawn(
        "ip",
        &[
            "netns",
            "exec",
            "td-wan",
            "busybox",
            "httpd",
            "-f",
            "-p",
            "[2001:db8:2::3]:80",
            "-h",
            root.to_str().ok_or("changed IPv6 fixture path")?,
        ],
        "changed6",
    )?;
    let path = lab.directory.path().join("unbound.conf");
    let original = fs::read_to_string(&path)?;
    let updated = original
        .replace(
            "selected.example.test. 60 IN A 203.0.113.2",
            "selected.example.test. 60 IN A 203.0.113.3",
        )
        .replace(
            "selected.example.test. 0 IN AAAA 2001:db8:2::2",
            "selected.example.test. 0 IN AAAA 2001:db8:2::3",
        );
    assert_ne!(
        original, updated,
        "the real DNS fixture must change its selected A record"
    );
    fs::write(&path, updated)?;
    let resolver =
        rustix::process::Pid::from_raw(i32::try_from(resolver)?).ok_or("invalid resolver PID")?;
    rustix::process::kill_process(resolver, rustix::process::Signal::HUP)?;
    wait_until(|| Ok(lab.http("selected.example.test", address, 80)?.stdout == b"changed"))?;
    wait_until(|| {
        Ok(lab
            .http_from("selected.example.test", address6, "2001:db8:1::2")?
            .stdout
            == b"changed")
    })?;
    assert_eq!(lab.address_family("selected.example.test", true)?, address6);
    assert_eq!(
        command(
            "nft",
            &["-j", "list", "table", "inet", "tunnel_detour"],
            None
        )?,
        firewall,
        "real-IP changes must not require changing firewall rules"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated network laboratory"]
fn r081_relay_connect_blackholes_and_peer_resets_release_capacity_without_retrying_or_detaching_work()
-> TestResult {
    const NAME: &str = "r081_relay_connect_blackholes_and_peer_resets_release_capacity_without_retrying_or_detaching_work";
    if env::var("TUNNEL_DETOUR_RELAY_RESET_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the isolated network laboratory".into());
        }
        let listener = std::net::TcpListener::bind("192.0.2.2:18081")?;
        listener.set_nonblocking(true)?;
        fs::write(env::var("TUNNEL_DETOUR_RELAY_RESET_READY")?, b"ready")?;
        wait_until(|| match listener.accept() {
            Ok((stream, _)) => {
                socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                drop(stream);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        })?;
        return Ok(());
    }
    let mut lab = Lab::new()?;
    command(
        "nft",
        &["-f", "-"],
        Some(
            br#"table inet lab_relay_failure {
 counter dials {}
 chain count { type filter hook output priority 0; policy accept;
  oifname "lan0" ip daddr 192.0.2.2 tcp dport 18081 tcp flags & (syn|ack) == syn counter name dials
 }
 chain blackhole { type filter hook output priority 1; policy accept;
  oifname "lan0" ip daddr 192.0.2.2 tcp dport 18081 drop
 }
}
"#,
        ),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}, time::timeout};
        use tunnel_detour_service::{RelayAdmission, RelayError, RelayLimits, RelayOutcome, RelaySessions};
        let ingress = TcpListener::bind("[::1]:0").await?;
        let admission = RelayAdmission {
            publication: "failure".parse()?, generation: 1, target: "192.0.2.2:18081".parse()?,
            lan_device: "lan0".into(), reply_device: "lo".into(),
        };
        let mut sessions = RelaySessions::new(RelayLimits::new(1, Duration::from_millis(150), Duration::from_secs(3))?);
        let mut first = TcpStream::connect(ingress.local_addr()?).await?;
        let (incoming, _) = ingress.accept().await?;
        sessions.admit(incoming, admission.clone())?;
        let result = timeout(Duration::from_secs(2), sessions.next_completion()).await??;
        assert_eq!(result.outcome, RelayOutcome::ConnectTimeout);
        assert!(sessions.connections().is_empty());
        let closed = timeout(Duration::from_secs(1), first.read(&mut [0; 1])).await?;
        assert!(matches!(closed, Ok(0)) || closed.is_err(), "a timed-out connection stayed open");
        command("nft", &["flush", "chain", "inet", "lab_relay_failure", "blackhole"], None)?;
        let ready = lab.directory.path().join("reset-ready");
        let log = File::create(lab.directory.path().join("reset.log"))?;
        let mut reset = Command::new("ip");
        reset.args(["netns", "exec", "td-client"]).arg(env::current_exe()?).args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("TUNNEL_DETOUR_RELAY_RESET_PROBE", "1").env("TUNNEL_DETOUR_RELAY_RESET_READY", &ready)
            .stdout(log.try_clone()?).stderr(log);
        let child = lab.children.len();
        lab.children.push(reset.spawn()?);
        wait_until(|| Ok(ready.exists()))?;
        let mut second = TcpStream::connect(ingress.local_addr()?).await?;
        let (incoming, _) = ingress.accept().await?;
        sessions.admit(incoming, admission)?;
        let result = timeout(Duration::from_secs(2), sessions.next_completion()).await??;
        assert!(matches!(result.outcome, RelayOutcome::ConnectFailed | RelayOutcome::TransferFailed));
        assert!(matches!(result.error, Some(RelayError::Io(ref error)) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted)), "the peer-reset cause was not preserved: {:?}", result.error);
        let closed = timeout(Duration::from_secs(1), second.read(&mut [0; 1])).await?;
        assert!(matches!(closed, Ok(0)) || closed.is_err(), "a reset target left the client open");
        assert!(sessions.connections().is_empty());
        sessions.shutdown().await?;
        wait_until(|| Ok(lab.children[child].try_wait()?.is_some()))?;
        assert!(lab.children[child].wait()?.success(), "the reset endpoint did not finish its single connection");
        let counters: Value = serde_json::from_slice(&command("nft", &["-j", "list", "counter", "inet", "lab_relay_failure", "dials"], None)?)?;
        assert_eq!(counters["nftables"][1]["counter"]["packets"], 2, "timeouts and resets must not start hidden reconnects");
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated network laboratory"]
fn r075_redirected_tcp_identity_uses_the_exact_kernel_generation_even_when_a_new_connection_reuses_the_public_endpoint()
-> TestResult {
    let mut lab = Lab::new()?;
    lab.enable_ipv6()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, time::timeout};
        use tunnel_detour_service::{RelayAdmission, RelayCapture, RelayLimits, RelayOutcome, RelaySessions};
        let listener = TcpListener::bind("[::]:19537").await?;
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let std::net::SocketAddr::V4(target) = origin.local_addr()? else { return Err("IPv4 origin required".into()); };
        command("nft", &["-f", "-"], Some(br#"table inet lab_relay_ingress {
 chain tag { type filter hook prerouting priority -101; policy accept;
  iifname "lan0" meta nfproto ipv6 tcp dport 18080 ct state new ct mark 0 ct mark set 0x54440001
 }
 chain capture { type nat hook prerouting priority -100; policy accept;
  iifname "lan0" ip6 daddr 2001:db8:1::1 tcp dport 18080 redirect to :19537
 }
}

"#))?;
        command("nft", &["-f", "-"], Some(format!("add counter inet lab_relay_ingress backend_syn\nadd chain inet lab_relay_ingress dial {{ type filter hook output priority 0; policy accept; }}\nadd rule inet lab_relay_ingress dial ip daddr 127.0.0.1 tcp dport {} tcp flags & (syn|ack) == syn counter name backend_syn\n", target.port()).as_bytes()))?;
        let mut streams = Vec::new();
        let mut clients = Vec::new();
        for (port, mark) in [(42001_u16, 0x54440001_u32), (42002, 0x54440002)] {
            if port == 42002 {
                // Only new admissions change. The first accepted socket deliberately
                // remains open with queued HTTP bytes while the same public port changes.
                command("nft", &["-f", "-"], Some(b"flush chain inet lab_relay_ingress tag\nadd rule inet lab_relay_ingress tag iifname \"lan0\" meta nfproto ipv6 tcp dport 18080 ct state new ct mark 0 ct mark set 0x54440002\n"))?;
            }
            let name = format!("relay-identity-{port}");
            let index = lab.children.len();
            lab.spawn("ip", &["netns", "exec", "td-client", "curl", "--noproxy", "*", "--silent", "--show-error", "--fail", "--max-time", "8", "--local-port", &port.to_string(), &format!("http://[2001:db8:1::1]:18080/{port}")], &name)?;
            clients.push((index, name));
            let (stream, _) = timeout(Duration::from_secs(3), listener.accept()).await??;
            assert_eq!(stream.local_addr()?.port(), 19537);
            let identity = tunnel_detour_service::inspect_relay_ingress(&stream).await?;
            assert_eq!(identity.original_source, format!("[2001:db8:1::2]:{port}").parse()?);
            assert_eq!(identity.original_destination, "[2001:db8:1::1]:18080".parse()?);
            assert_eq!(identity.mark, mark, "authorization must use this connection's kernel generation");
            streams.push(stream);
        }
        assert_eq!(tunnel_detour_service::inspect_relay_ingress(&streams[0]).await?.mark, 0x54440001, "the pending old socket must not acquire the new publication generation");
        assert_eq!(tunnel_detour_service::inspect_relay_ingress(&streams[1]).await?.mark, 0x54440002);
        let mut sessions = RelaySessions::new(RelayLimits::new(1, Duration::from_secs(2), Duration::from_secs(5))?);
        for stream in streams {
            // Both pending sockets are offered the current policy. The old socket
            // must be rejected before a single SYN reaches the selected backend.
            sessions.enqueue_captured(stream, RelayAdmission {
                publication: "current".parse()?, generation: 2, target,
                lan_device: "lo".into(), reply_device: "lan0".into(),
            }, RelayCapture { mark: 0x54440002, public: "[2001:db8:1::1]:18080".parse()? })?;
        }
        assert!(sessions.connections().iter().any(|connection|connection.client.port()==42002 && connection.queued),"the current socket must exercise queued kernel verification");
        let stale=timeout(Duration::from_secs(3),sessions.next_completion()).await??;
        assert_eq!(stale.connection.client.port(),42001);
        assert_eq!(stale.outcome,RelayOutcome::IdentityRejected);
        let current=async {
            let completion=timeout(Duration::from_secs(3),sessions.next_completion()).await??;
            assert_eq!(completion.connection.client.port(),42002);
            assert_eq!(completion.outcome,RelayOutcome::Complete);
            Ok::<(),Box<dyn Error>>(())
        };
        let server=async {
        let (mut stream, _) = timeout(Duration::from_secs(3), origin.accept()).await??;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            if request.len() >= 2048 { return Err("oversized laboratory request".into()); }
            let mut byte = [0; 1];
            timeout(Duration::from_secs(2), stream.read_exact(&mut byte)).await??;
            request.extend(byte);
        }
        assert!(request.starts_with(b"GET /42002 HTTP/1.1\r\n"), "only the current generation may reach the backend");
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await?;
        stream.shutdown().await?;
        assert_eq!(timeout(Duration::from_secs(2), stream.read(&mut [0; 1])).await??, 0);
            Ok::<(),Box<dyn Error>>(())
        };
        tokio::try_join!(current,server)?;
        let counters: serde_json::Value = serde_json::from_slice(&command("nft", &["-j", "list", "counter", "inet", "lab_relay_ingress", "backend_syn"], None)?)?;
        assert_eq!(counters["nftables"][1]["counter"]["packets"], 1, "stale acceptance must not dial a LAN target at all");
        sessions.shutdown().await?;
        for (client, (index, name)) in clients.into_iter().enumerate() {
            wait_until(|| Ok(lab.children[index].try_wait()?.is_some()))?;
            assert_eq!(lab.children[index].wait()?.success(), client == 1);
            if client == 1 { assert_eq!(fs::read(lab.directory.path().join(format!("{name}.log")))?, b"OK"); }
        }
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}
