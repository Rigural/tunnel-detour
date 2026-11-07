//! Acceptance tests use real Linux namespaces, nftables, WireGuard, Unbound, HTTP, and TLS.
//! Run only through `cargo xtask test-network`; no host-network mutation is authorized here.

use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
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
                "10.254.0.1/32,192.0.2.0/24,2001:db8:1::/64",
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
                return Err(format!(
                    "service exited with {status}: {}",
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
        let response = command("curl", &args, bytes.as_deref())?;
        // Mutation endpoints legitimately return an empty successful HTTP body.
        if !expects_json
            && (response.is_empty()
                || response
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .eq(b"OK".iter().copied()))
        {
            Ok(Value::Null)
        } else {
            Ok(serde_json::from_slice(&response)?)
        }
    }

    fn start_adguard(&mut self) -> TestResult {
        let root = self.directory.path().join("adguard");
        fs::create_dir(&root)?;
        let config = root.join("AdGuardHome.yaml");
        let web_address = format!("{}:13000", self.adguard_bind);
        self.spawn(
            "AdGuardHome",
            &[
                "--no-check-update",
                "--web-addr",
                &web_address,
                "-w",
                root.to_str().ok_or("AdGuard work path")?,
                "-c",
                config.to_str().ok_or("AdGuard config path")?,
            ],
            "adguard",
        )?;
        wait_until(|| Ok(self.api("install/get_addresses", None).is_ok()))?;
        let password = format!(
            "Lab!{}",
            String::from_utf8(command("openssl", &["rand", "-hex", "24"], None)?)?.trim()
        );
        self.api("install/configure", Some(json!({"web":{"ip":self.adguard_bind,"port":13000},"dns":{"ip":"0.0.0.0","port":10534},"username":"lab-admin","password":password})))?;
        self.adguard_auth = Some(("lab-admin".into(), password.clone()));
        wait_until(|| Ok(self.api("status", None).is_ok()))?;
        self.api("dns_config", Some(json!({"upstream_dns":["tcp://10.254.0.2:5353", "[/unrelated.test/]tcp://10.254.0.2:5353"],"fallback_dns":[],"upstream_dns_file":"","cache_optimistic":false,"blocking_mode":"null_ip"})))?;
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
                "subjectAltName=DNS:selected.example.test,DNS:other.example.test",
                "-keyout",
                key.to_str().ok_or("key path")?,
                "-out",
                certificate.to_str().ok_or("certificate path")?,
            ],
            None,
        )?;
        for (namespace, role) in [("td-wan", "wan"), ("td-vpn", "vpn")] {
            let root = self.directory.path().join(role);
            let log = File::create(self.directory.path().join(format!("tls-{role}.log")))?;
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
                        "203.0.113.2:443",
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
        }
        Ok(())
    }

    fn query(&self, name: &str, kind: RecordType, tcp: bool) -> Result<Message, Box<dyn Error>> {
        let address = if self.config["adguard"].is_object() {
            "127.0.0.1:10534"
        } else {
            "127.0.0.1:10535"
        };
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name)?, kind));
        let bytes = query.to_vec()?;
        let response = if tcp {
            use std::io::Read;
            let mut socket = std::net::TcpStream::connect(address)?;
            socket.set_read_timeout(Some(Duration::from_secs(7)))?;
            socket.write_all(&u16::try_from(bytes.len())?.to_be_bytes())?;
            socket.write_all(&bytes)?;
            let mut length = [0; 2];
            socket.read_exact(&mut length)?;
            let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
            socket.read_exact(&mut response)?;
            response
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(address)?;
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

    fn https(&self, name: &str, address: Ipv4Addr) -> Result<Output, Box<dyn Error>> {
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
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "--cacert",
                certificate.to_str().ok_or("certificate path")?,
                "--resolve",
                &format!("{name}:443:{address}"),
                &format!("https://{name}/route.txt"),
            ],
            None,
        )
    }

    fn stop(&mut self) -> TestResult {
        if let Some(mut child) = self.service.take() {
            let pid = rustix::process::Pid::from_raw(i32::try_from(child.id())?)
                .ok_or("invalid service process ID")?;
            rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
            wait_until(|| Ok(child.try_wait()?.is_some()))?;
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
        for table in ["tunnel_detour", "lab_firewall"] {
            cleanup("nft", &["delete", "table", "inet", table]);
        }
        cleanup(
            "ip",
            &["-4", "rule", "del", "priority", "11000", "protocol", "242"],
        );
        cleanup(
            "ip",
            &["-4", "route", "flush", "table", "41872", "proto", "242"],
        );
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
    lab.start()?;
    let before = lab.address("selected.example.test")?;
    lab.stop()?;
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
    lab.config["rules"] = json!([{"pattern":"private.example.test","enabled":true}]);
    lab.start()?;
    let address = lab.address("private.example.test")?;
    assert!(
        !lab.http("private.example.test", address, 80)?
            .status
            .success()
    );
    wait_until(|| Ok(lab.status()?["last_error"] == "forbidden_destination"))?;
    let resolver = lab
        .children
        .last()
        .ok_or("resolver fixture is absent")?
        .id();
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
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r023_wan_failure_never_falls_back_to_wireguard_or_opens_general_forwarding() -> TestResult {
    let mut lab = Lab::new()?;
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    command("ip", &["link", "set", "wan0", "down"], None)?;
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
    command("ip", &["link", "set", "wan0", "up"], None)?;
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
    lab.start_tls()?;
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    let response = lab.https("selected.example.test", address)?;
    assert!(
        response.status.success(),
        "origin TLS validation failed: {}",
        String::from_utf8_lossy(&response.stderr)
    );
    assert_eq!(response.stdout, b"wan");
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
    if env::var("TUNNEL_DETOUR_QUIC_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect("198.18.0.1:443")?;
        socket.send(b"synthetic UDP transport probe")?;
        return match socket.recv(&mut [0; 1]) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(format!("expected an ICMP port rejection, received {error}").into()),
            Ok(_) => Err("the synthetic QUIC destination replied instead of rejecting UDP".into()),
        };
    }
    let mut lab = Lab::new()?;
    lab.start_tls()?;
    lab.start()?;
    assert_eq!(
        lab.address("selected.example.test")?,
        Ipv4Addr::new(198, 18, 0, 1)
    );
    let executable = env::current_exe()?;
    let result = Command::new("ip").args(["netns", "exec", "td-client"])
        .arg(executable).args(["--ignored", "--exact", "r027_quic_datagrams_receive_an_explicit_rejection_while_tcp_fallback_still_reaches_wan", "--nocapture"])
        .env("TUNNEL_DETOUR_QUIC_PROBE", "1").output()?;
    assert!(
        result.status.success(),
        "client UDP rejection failed: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(
        String::from_utf8(
            lab.https("selected.example.test", Ipv4Addr::new(198, 18, 0, 1))?
                .stdout
        )?,
        "wan"
    );
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
        let address: SocketAddr = if role == "lan" {
            "192.0.2.1:10535"
        } else {
            "203.0.113.1:10536"
        }
        .parse()?;
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err(),
            "private service port accepted a remote TCP connection"
        );
        if role == "lan" {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
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
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    for (namespace, role) in [("td-client", "lan"), ("td-wan", "wan")] {
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
    assert_eq!(
        lab.http("selected.example.test", address, 80)?.stdout,
        b"wan"
    );
    lab.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r034_connection_exhaustion_stays_bounded_preserves_dns_and_vpn_and_shutdown_drains_active_relays()
-> TestResult {
    if env::var("TUNNEL_DETOUR_RESOURCE_PROBE").as_deref() == Ok("1") {
        if env::var("TUNNEL_DETOUR_NETWORK_LAB").as_deref() != Ok("1") {
            return Err("probe requires the network laboratory".into());
        }
        let address: SocketAddr = "198.18.0.1:80".parse()?;
        let mut streams = Vec::new();
        for _ in 0..2 {
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
    lab.config["limits"]["connections"] = json!(2);
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    let log = File::create(lab.directory.path().join("resource-probe.log"))?;
    let probe_index = lab.children.len();
    lab.children.push(Command::new("ip").args(["netns", "exec", "td-client"]).arg(env::current_exe()?)
        .args(["--ignored", "--exact", "r034_connection_exhaustion_stays_bounded_preserves_dns_and_vpn_and_shutdown_drains_active_relays", "--nocapture"])
        .env("TUNNEL_DETOUR_RESOURCE_PROBE", "1").stdout(log.try_clone()?).stderr(log).spawn()?);
    wait_until(|| {
        Ok(lab.status()?["connections"]
            .as_object()
            .ok_or("invalid connection status")?
            .len()
            == 2)
    })?;
    assert!(
        !lab.http("selected.example.test", address, 80)?
            .status
            .success(),
        "a third relay exceeded the configured connection bound"
    );
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
    Ok(())
}

#[test]
#[ignore = "requires the isolated Docker network laboratory"]
fn r035_real_ip_changes_take_effect_for_cached_fake_ips_without_firewall_rule_updates() -> TestResult
{
    let mut lab = Lab::new()?;
    lab.start()?;
    let address = lab.address("selected.example.test")?;
    assert_eq!(
        lab.http("selected.example.test", address, 80)?.stdout,
        b"wan"
    );
    let firewall = command(
        "nft",
        &["-j", "list", "table", "inet", "tunnel_detour"],
        None,
    )?;
    let resolver = lab
        .children
        .last()
        .ok_or("resolver fixture is absent")?
        .id();
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
    let path = lab.directory.path().join("unbound.conf");
    let original = fs::read_to_string(&path)?;
    let updated = original.replace(
        "selected.example.test. 60 IN A 203.0.113.2",
        "selected.example.test. 60 IN A 203.0.113.3",
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
