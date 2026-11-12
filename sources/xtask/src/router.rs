use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tunnel_detour_core::{DomainPattern, MatchScope};

mod ipv6_probe;
mod path_probe;

const ASKPASS: &str = "TUNNEL_DETOUR_SSH_ASKPASS";
const ACCESS: &str = "TUNNEL_DETOUR_SSH_ACCESS_FILE";

fn access(path: &Path) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("access input must be a regular file".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("access input exceeds its size bound".into());
    }
    let content = String::from_utf8(bytes).map_err(|_| "access input must be UTF-8")?;
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line.split_once('=').ok_or("invalid access input line")?;
        let key = key.trim();
        let value = value.trim();
        let value = if value.starts_with(['\'', '"']) {
            if value.len() < 2 || value.as_bytes().first() != value.as_bytes().last() {
                return Err("unclosed access input quote".into());
            }
            &value[1..value.len() - 1]
        } else {
            value
        };
        if values.insert(key.to_string(), value.to_string()).is_some() {
            return Err("duplicate access input field".into());
        }
    }
    Ok(values)
}

pub(crate) fn askpass() -> Option<ExitCode> {
    if env::var_os(ASKPASS).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return None;
    }
    let result = (|| -> Result<(), Box<dyn Error>> {
        let path = env::var_os(ACCESS).ok_or("missing access input")?;
        let values = access(Path::new(&path))?;
        let password = values.get("password").ok_or("missing SSH password")?;
        std::io::stdout().lock().write_all(password.as_bytes())?;
        std::io::stdout().lock().write_all(b"\n")?;
        Ok(())
    })();
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

pub(crate) struct Router {
    host: String,
    username: String,
    access: PathBuf,
    directory: PathBuf,
    credentials: BTreeMap<String, String>,
}

impl Router {
    fn open(host: &str, input: &Path, resume: Option<&Path>) -> Result<Self, Box<dyn Error>> {
        if host.is_empty()
            || host.starts_with('-')
            || !host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
        {
            return Err("invalid SSH host".into());
        }
        let values = access(input)?;
        let username = values
            .get("username")
            .ok_or("missing SSH username")?
            .clone();
        if username.is_empty()
            || username.starts_with('-')
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("invalid SSH username".into());
        }
        if !values.contains_key("password") {
            return Err("missing SSH password".into());
        }
        let state = match env::var_os("XDG_STATE_HOME") {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(env::var_os("HOME").ok_or("HOME is unavailable")?)
                .join(".local/state"),
        };
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let directory = resume.map(Path::to_path_buf).unwrap_or_else(|| {
            state
                .join("tunnel-detour/router-validation")
                .join(format!("{epoch}-{}", std::process::id()))
        });
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        let directory = directory.canonicalize()?;
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        if directory.starts_with(workspace)
            || fs::metadata(&directory)?.permissions().mode() & 0o077 != 0
        {
            return Err(
                "validation data requires a private directory outside the workspace".into(),
            );
        }
        let private_access = directory.join("access.env");
        if resume.is_none() {
            write_private(&private_access, &fs::read(input)?)?;
        }
        let identity_path = directory.join("session.json");
        let identity = json!({"host":host,"username":username});
        if identity_path.exists() {
            let previous: Value = serde_json::from_slice(&fs::read(&identity_path)?)?;
            if previous != identity {
                return Err("validation session belongs to another SSH destination".into());
            }
        } else {
            write_private(&identity_path, &serde_json::to_vec(&identity)?)?;
        }
        Ok(Self {
            host: host.into(),
            username,
            access: private_access,
            directory,
            credentials: values,
        })
    }

    fn ssh(&self) -> Result<Command, Box<dyn Error>> {
        let mut command = Command::new("ssh");
        command
            .args([
                "-T",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ControlMaster=no",
                "-l",
                &self.username,
            ])
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("SSH_ASKPASS", env::current_exe()?)
            .env(ASKPASS, "1")
            .env(ACCESS, &self.access)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }

    fn capture(&self, name: &str, script: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut child = self.ssh()?.arg(&self.host).arg("sh -s").spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing SSH stdin")?
            .write_all(script.as_bytes())?;
        let result = child.wait_with_output()?;
        self.record(&format!("{name}.stdout"), &result.stdout)?;
        self.record(&format!("{name}.stderr"), &result.stderr)?;
        if !result.status.success() {
            return Err(format!("router probe {name} failed with {}; details are in the private validation directory", result.status).into());
        }
        Ok(result.stdout)
    }

    fn secret_output(&self, script: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut child = self.ssh()?.arg(&self.host).arg("sh -s").spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing SSH stdin")?
            .write_all(script.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err("private router operation failed; output withheld".into());
        }
        Ok(output.stdout)
    }

    fn adguard(&self) -> Result<(), Box<dyn Error>> {
        let (username, password) = match (
            self.credentials.get("adguard_username"),
            self.credentials.get("adguard_password"),
        ) {
            (Some(username), Some(password)) => (username.clone(), password.clone()),
            (None, None) => {
                // Inspect protected storage without copying secrets into arguments
                // or requiring a second manually maintained access-file copy.
                let configuration: Value = serde_json::from_slice(
                    &self
                        .secret_output("ubus -S call uci get '{\"config\":\"tunnel-detour\"}'\n")?,
                )?;
                let globals = &configuration["values"]["globals"];
                let stored = self.applied_credentials(globals)?;
                (
                    stored["username"]
                        .as_str()
                        .ok_or("missing applied AdGuard username")?
                        .to_owned(),
                    stored["password"]
                        .as_str()
                        .ok_or("missing applied AdGuard password")?
                        .to_owned(),
                )
            }
            _ => return Err("provide both AdGuard access fields or neither".into()),
        };
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let stderr = self
            .directory
            .join(format!("ssh-forward-{}.stderr", std::process::id()));
        let stderr = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(stderr)?;
        let mut command = self.ssh()?;
        let listeners = String::from_utf8(self.capture("adguard-listeners", "netstat -lntp\n")?)?;
        let endpoints: Vec<_> = listeners
            .lines()
            .filter(|line| line.starts_with("tcp ") && line.contains("AdGuardHome"))
            .filter_map(|line| line.split_whitespace().nth(3))
            .filter_map(|value| value.parse::<std::net::SocketAddrV4>().ok())
            .filter(|endpoint| ![53, 853, 5443].contains(&endpoint.port()))
            .collect();
        let [endpoint] = endpoints.as_slice() else {
            return Err("expected one IPv4 AdGuard HTTP listener".into());
        };
        let destination = if endpoint.ip().is_unspecified() {
            format!("127.0.0.1:{}", endpoint.port())
        } else {
            endpoint.to_string()
        };
        command.args([
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            &format!("127.0.0.1:{port}:{destination}"),
        ]);
        command
            .arg(&self.host)
            .arg("printf 'ready\\n'; cat >/dev/null")
            .stderr(stderr);
        drop(listener);
        let mut tunnel = Tunnel(command.spawn()?);
        let mut ready = String::new();
        BufReader::new(tunnel.0.stdout.take().ok_or("missing SSH forward output")?)
            .read_line(&mut ready)?;
        if ready != "ready\n" {
            return Err("SSH forward did not become ready; see private validation data".into());
        }
        let resolver = String::from_utf8(
            self.secret_output("uci -q get tunnel-detour.globals.real_upstream || true\n")?,
        )?;
        let resolver = resolver.trim();
        let current_real = resolver.parse::<std::net::SocketAddrV4>().ok().or_else(|| {
            resolver
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|ip| std::net::SocketAddrV4::new(ip, 53))
        });
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(Duration::from_secs(15)).build()?;
            for endpoint in ["status", "dns_info", "filtering/status", "clients"] {
                let mut response = client.get(format!("http://127.0.0.1:{port}/control/{endpoint}")).basic_auth(&username, Some(&password)).send().await.map_err(|_| "AdGuard API request failed over SSH")?;
                if !response.status().is_success() {
                    return Err(format!("AdGuard API {endpoint} returned HTTP {}", response.status()).into());
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| "AdGuard API response failed")? {
                    if bytes.len() + chunk.len() > 2 * 1024 * 1024 { return Err("AdGuard API response exceeds bound".into()); }
                    bytes.extend_from_slice(&chunk);
                }
                let data: Value = serde_json::from_slice(&bytes)?;
                self.record(&format!("api-{}.json", endpoint.replace('/', "-")), &bytes)?;
                match endpoint {
                    "status" => println!("{}", json!({"adguard_authenticated":true,"version":data["version"],"running":data["running"],"protection_enabled":data["protection_enabled"]})),
                    "dns_info" => {
                        let baseline: Value = serde_json::from_slice(&fs::read(self.directory.join("api-dns_info.json"))?)?;
                        let mut unowned = data.clone();
                        if let Ok(plan) = self.acceptance_plan()
                            && let Some(hostname) = plan["hostname"].as_str() {
                                let owned = format!("[/{hostname}/]127.0.0.1:10535");
                                if let Some(upstreams) = unowned["upstream_dns"].as_array_mut() { upstreams.retain(|line| line.as_str()!=Some(owned.as_str())); }
                        }
                        let schemes: Vec<_> = baseline["upstream_dns"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|value|value.split_once("://").map_or("plain",|(scheme,_)|scheme)).collect();
                        let matches_primary = baseline["upstream_dns"].as_array().into_iter().flatten().filter_map(Value::as_str).any(|value| {
                            let value = value.strip_prefix("tcp://").unwrap_or(value);
                            value.parse::<std::net::SocketAddrV4>().ok().or_else(||value.parse::<std::net::Ipv4Addr>().ok().map(|ip|std::net::SocketAddrV4::new(ip,53))).is_some_and(|address| Some(address)==current_real)
                        });
                        println!("{}",json!({"real_resolver_matches_configured_adguard_primary":matches_primary}));
                        println!("{}", json!({"dns_settings_match_initial_snapshot":baseline == data,"unowned_dns_settings_unchanged":unowned==baseline,"original_upstream_protocols":schemes,"upstream_count":data["upstream_dns"].as_array().map(Vec::len),"fallback_count":data["fallback_dns"].as_array().map(Vec::len),"file_upstreams":data["upstream_dns_file"].as_str().is_some_and(|value| !value.is_empty()),"bootstrap_count":data["bootstrap_dns"].as_array().map(Vec::len)}));
                    },
                    "filtering/status" => println!("{}", json!({"filtering_enabled":data["enabled"],"filter_count":data["filters"].as_array().map(Vec::len)})),
                    _ => (),
                }
            }
            Ok::<_, Box<dyn Error>>(())
        })
    }

    fn applied_credentials(&self, globals: &Value) -> Result<Value, Box<dyn Error>> {
        if globals.get("adguard_username").is_some() || globals.get("adguard_password").is_some() {
            return Ok(
                json!({"username":globals["adguard_username"],"password":globals["adguard_password"]}),
            );
        }
        let stored: Value = serde_json::from_slice(&self.secret_output("if test -f /etc/tunnel-detour/adguard-credentials.json; then cat /etc/tunnel-detour/adguard-credentials.json; else printf '%s' '{\"current\":{\"revision\":null,\"value\":{\"username\":\"\",\"password\":\"\"}},\"pending\":null}'; fi\n")?)?;
        let revision = globals
            .get("adguard_credentials_revision")
            .and_then(Value::as_str);
        let selected = [&stored["current"], &stored["pending"]]
            .into_iter()
            .find(|version| version.is_object() && version["revision"].as_str() == revision)
            .ok_or("applied credentials revision is unavailable")?;
        Ok(selected["value"].clone())
    }

    fn configure_disabled(&self, target: &str) -> Result<(), Box<dyn Error>> {
        let target = reqwest::Url::parse(target).map_err(|_| "invalid HTTPS acceptance target")?;
        if target.scheme() != "https"
            || !target.username().is_empty()
            || target.password().is_some()
            || target.host_str().is_none()
            || target.port().is_some()
        {
            return Err("acceptance target must be an HTTPS hostname using port 443".into());
        }
        let hostname = target.host_str().ok_or("missing target hostname")?;
        let dns: Value =
            serde_json::from_slice(&fs::read(self.directory.join("api-dns_info.json"))?)?;
        let upstream = dns["upstream_dns"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(dns["bootstrap_dns"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .filter_map(|value| {
                let value = value.strip_prefix("tcp://").unwrap_or(value);
                value.parse::<std::net::SocketAddrV4>().ok().or_else(|| {
                    value
                        .parse::<std::net::Ipv4Addr>()
                        .ok()
                        .map(|ip| std::net::SocketAddrV4::new(ip, 53))
                })
            })
            .find(|address| {
                !address.ip().is_loopback()
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast()
            })
            .ok_or("no explicit IPv4 DNS candidate exists in current AdGuard settings")?;
        let interfaces: Value = serde_json::from_slice(
            &self.capture("test-interfaces", "ubus -S call network.interface dump\n")?,
        )?;
        let vpn_devices: Vec<_> = interfaces["interface"]
            .as_array()
            .ok_or("invalid interface inventory")?
            .iter()
            .filter(|interface| interface["proto"] == "wireguard" && interface["up"] == true)
            .filter_map(|interface| interface["l3_device"].as_str())
            .collect();
        let route: Value = serde_json::from_slice(&self.capture(
            "real-dns-route",
            &format!("ip -j -4 route get {}\n", upstream.ip()),
        )?)?;
        if !route.as_array().is_some_and(|routes| {
            routes.len() == 1
                && routes[0]["dev"]
                    .as_str()
                    .is_some_and(|device| vpn_devices.contains(&device))
        }) {
            return Err("the selected real resolver does not currently use WireGuard".into());
        }
        let resolution = Command::new("dig")
            .args([
                "+tcp",
                &format!("@{}", upstream.ip()),
                "-p",
                &upstream.port().to_string(),
                hostname,
                "A",
                "+tries=1",
                "+time=5",
                "+short",
            ])
            .output()?;
        self.record("candidate-real-dns.stdout", &resolution.stdout)?;
        self.record("candidate-real-dns.stderr", &resolution.stderr)?;
        if !resolution.status.success()
            || !String::from_utf8_lossy(&resolution.stdout)
                .lines()
                .any(|line| line.parse::<std::net::Ipv4Addr>().is_ok())
        {
            return Err(
                "the DNS candidate did not return an IPv4 acceptance destination over TCP".into(),
            );
        }
        let listeners = fs::read_to_string(self.directory.join("listeners.stdout"))?;
        let endpoints: Vec<_> = listeners
            .lines()
            .filter(|line| line.starts_with("tcp ") && line.contains("AdGuardHome"))
            .filter_map(|line| line.split_whitespace().nth(3))
            .filter_map(|value| value.parse::<std::net::SocketAddrV4>().ok())
            .filter(|endpoint| ![53, 853, 5443].contains(&endpoint.port()))
            .collect();
        let [endpoint] = endpoints.as_slice() else {
            return Err("expected one IPv4 AdGuard HTTP listener".into());
        };
        let endpoint = if endpoint.ip().is_unspecified() {
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, endpoint.port())
        } else {
            *endpoint
        };
        let username = self
            .credentials
            .get("adguard_username")
            .ok_or("missing AdGuard username")?;
        let password = self
            .credentials
            .get("adguard_password")
            .ok_or("missing AdGuard password")?;
        let staging = format!("/tmp/tunnel-detour-config-{}", std::process::id());
        self.record("private-uci-stage.txt", staging.as_bytes())?;
        self.capture("create-private-uci-stage", &format!("set -e\numask 077\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 0\nmkdir {}\nmkdir {}\ncp /etc/config/tunnel-detour {}\n",quote(&staging),quote(&format!("{staging}/delta")),quote(&format!("{staging}/tunnel-detour"))))?;
        let api_url = format!("http://{endpoint}");
        let upstream_text = upstream.to_string();
        let mut batch = String::new();
        for (key, value) in [
            ("enabled", "0"),
            ("real_upstream", upstream_text.as_str()),
            ("adguard_url", api_url.as_str()),
            ("adguard_username", username.as_str()),
            ("adguard_password", password.as_str()),
        ] {
            batch.push_str(&format!(
                "set tunnel-detour.globals.{key}={}\n",
                quote(value)
            ));
        }
        batch.push_str("commit tunnel-detour\n");
        let marker = "TUNNEL_DETOUR_CONFIG_INPUT";
        if batch.lines().any(|line| line == marker) {
            return Err("invalid private configuration delimiter".into());
        }
        self.capture(
            "stage-private-uci",
            &format!(
                "set -e\nuci -c {} -t {} batch <<'{marker}'\n{batch}{marker}\n",
                quote(&staging),
                quote(&format!("{staging}/delta"))
            ),
        )?;
        for (key, value) in [
            ("adguard_username", username),
            ("adguard_password", password),
        ] {
            let actual = self.secret_output(&format!(
                "uci -c {} -t {} get tunnel-detour.globals.{key}\n",
                quote(&staging),
                quote(&format!("{staging}/delta"))
            ))?;
            if actual.strip_suffix(b"\n") != Some(value.as_bytes()) {
                return Err("UCI did not preserve the literal access value; active configuration is unchanged".into());
            }
        }
        self.capture("backup-package-config", "cat /etc/config/tunnel-detour\n")?;
        self.capture("apply-disabled-private-config", &format!("set -e\nchmod 600 {}\nmv {} /etc/config/tunnel-detour\n/usr/bin/tunnel-detour --migrate-adguard-credentials\n/usr/bin/tunnel-detour --check-uci\n",quote(&format!("{staging}/tunnel-detour")),quote(&format!("{staging}/tunnel-detour"))))?;
        self.record("acceptance-plan.json", &serde_json::to_vec(&json!({"url":target.as_str(),"hostname":hostname,"real_upstream":upstream.to_string(),"adguard_url":api_url,"remote_staging":staging}))?)?;
        self.management("configured-disabled")?;
        println!(
            "Own configuration prepared and validated while disabled; credentials preserved literally, and the selected real DNS route uses WireGuard."
        );
        Ok(())
    }

    fn preflight(&self) -> Result<(), Box<dyn Error>> {
        let board: Value = serde_json::from_slice(
            &self.capture("preflight-board", "ubus -S call system board\n")?,
        )?;
        if board["board_name"] != "openwrt,one"
            || board["release"]["version"] != "25.12.6"
            || board["release"]["target"] != "mediatek/filogic"
        {
            return Err("router does not match the supported hardware and firmware".into());
        }
        let dependencies = self.capture("preflight-dependencies", "for name in libc libgcc1 procd rpcd ubus uci ip-full nftables-json kmod-nft-nat luci-base; do if apk info -e \"$name\" >/dev/null 2>&1; then printf '%s present\\n' \"$name\"; else printf '%s missing\\n' \"$name\"; fi; done\n")?;
        let dependencies = String::from_utf8(dependencies)?;
        println!("{dependencies}");
        if dependencies.contains(" missing") {
            return Err("offline installation requires all dependencies already installed".into());
        }
        self.capture("preflight-absent", "test ! -e /usr/bin/tunnel-detour && test ! -e /etc/config/tunnel-detour && ! apk info -e tunnel-detour >/dev/null 2>&1\n")?;
        self.capture("apk-add-help", "apk add --help; test $? -le 1\n")?;
        println!("Hardware, firmware and clean installation preflight passed.");
        Ok(())
    }

    fn acceptance_plan(&self) -> Result<Value, Box<dyn Error>> {
        Ok(serde_json::from_slice(&fs::read(
            self.directory.join("acceptance-plan.json"),
        )?)?)
    }

    fn start_test(&self) -> Result<(), Box<dyn Error>> {
        let plan = self.acceptance_plan()?;
        let hostname = plan["hostname"]
            .as_str()
            .ok_or("missing acceptance hostname")?;
        self.management("before-exception")?;
        self.capture("before-exception-network", "uci export network\n")?;
        self.capture("before-exception-firewall", "uci export firewall\n")?;
        self.capture("before-exception-nft", "nft -j list ruleset\n")?;
        self.capture(
            "before-exception-routes",
            "ip -4 rule show\nip -4 route show table all\n",
        )?;
        self.capture(
            "before-exception-config.backup",
            "cat /etc/config/tunnel-detour\n",
        )?;
        self.capture("start-exception", &format!("set -e\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 0\nif uci -q get tunnel-detour.hardware_acceptance >/dev/null; then exit 1; fi\nuci batch <<'TUNNEL_DETOUR_TEST_RULE'\nset tunnel-detour.hardware_acceptance=exception\nset tunnel-detour.hardware_acceptance.pattern={}\nset tunnel-detour.hardware_acceptance.enabled='1'\nset tunnel-detour.globals.enabled='1'\ncommit tunnel-detour\nTUNNEL_DETOUR_TEST_RULE\n/etc/init.d/tunnel-detour start\n", quote(hostname)))?;
        let result = (|| -> Result<(), Box<dyn Error>> {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                let status: Value = serde_json::from_slice(&self.capture(
                    "acceptance-start-status",
                    "ubus -S call tunnel-detour status '{}'\n",
                )?)?;
                if status["running"] == true && status["status"]["phase"] == "ready" {
                    break;
                }
                if status["status"]["phase"] == "failed" || std::time::Instant::now() >= deadline {
                    return Err(
                        "the exception service did not become ready; see private status records"
                            .into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            self.management("exception-active")?;
            println!(
                "One exact-hostname acceptance rule is active; SSH, LuCI and ordinary client DNS remain reachable."
            );
            Ok(())
        })();
        if result.is_err() {
            self.stop_test()?;
        }
        result
    }

    fn stop_test(&self) -> Result<(), Box<dyn Error>> {
        self.capture("stop-exception", "set -e\nuci set tunnel-detour.globals.enabled=0\nif uci -q get tunnel-detour.hardware_acceptance >/dev/null; then uci delete tunnel-detour.hardware_acceptance; fi\nuci commit tunnel-detour\n/etc/init.d/tunnel-detour stop\n/usr/bin/tunnel-detour --cleanup-disabled\n")?;
        self.management("exception-removed")?;
        println!("The temporary acceptance rule has been removed and the package is disabled.");
        Ok(())
    }

    fn probe_test(&self) -> Result<(), Box<dyn Error>> {
        let plan = self.acceptance_plan()?;
        let hostname = plan["hostname"]
            .as_str()
            .ok_or("missing acceptance hostname")?;
        let url = plan["url"].as_str().ok_or("missing acceptance URL")?;
        let mut fake = None;
        for kind in ["A", "AAAA", "HTTPS"] {
            let output = Command::new("dig")
                .args([
                    &format!("@{}", self.host),
                    hostname,
                    kind,
                    "+tries=1",
                    "+time=5",
                    "+short",
                ])
                .output()?;
            self.record(&format!("acceptance-dns-{kind}.stdout"), &output.stdout)?;
            self.record(&format!("acceptance-dns-{kind}.stderr"), &output.stderr)?;
            if !output.status.success() {
                return Err("acceptance DNS query failed".into());
            }
            let text = String::from_utf8(output.stdout)?;
            if kind == "A" {
                fake = text
                    .lines()
                    .filter_map(|line| line.parse::<std::net::Ipv4Addr>().ok())
                    .find(|address| {
                        address.octets()[0] == 198 && matches!(address.octets()[1], 18 | 19)
                    });
                if fake.is_none() {
                    return Err(
                        "the selected hostname did not receive a synthetic IPv4 address".into(),
                    );
                }
            } else if !text.trim().is_empty() {
                return Err(
                    "the selected hostname still has an alternate-address DNS response".into(),
                );
            }
        }
        let fake = fake.ok_or("missing synthetic IPv4 address")?;
        let body_path = self.directory.join("acceptance-https.body");
        let headers_path = self.directory.join("acceptance-https.headers");
        for path in [&body_path, &headers_path] {
            write_private(path, b"")?;
        }
        let output = Command::new("curl")
            .args([
                "--noproxy",
                "*",
                "--proto",
                "=https",
                "--ipv4",
                "--http1.1",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "20",
                "--max-filesize",
                "2097152",
                "--resolve",
                &format!("{hostname}:443:{fake}"),
                "--dump-header",
            ])
            .arg(&headers_path)
            .arg("--output")
            .arg(&body_path)
            .args(["--write-out", "%{http_code}\n%{remote_ip}\n", url])
            .output()?;
        self.record("acceptance-https.stdout", &output.stdout)?;
        self.record("acceptance-https.stderr", &output.stderr)?;
        let code = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .and_then(|line| line.parse::<u16>().ok());
        println!(
            "{}",
            json!({"synthetic_ipv4_received":true,"selected_aaaa_and_https_suppressed":true,"tls_verification_succeeded":output.status.success(),"http_status":code})
        );
        self.capture(
            "acceptance-status-after-client",
            "ubus -S call tunnel-detour status '{}'\n",
        )?;
        if !output.status.success() {
            return Err("HTTPS acceptance connection failed; see private records".into());
        }
        self.management("after-client-acceptance")?;
        Ok(())
    }

    fn probe_active(&self) -> Result<(), Box<dyn Error>> {
        let status: Value = serde_json::from_slice(
            &self.capture("active-status", "ubus -S call tunnel-detour status '{}'\n")?,
        )?;
        if status["running"] != true || status["status"]["phase"] != "ready" {
            return Err("the service must be ready before testing an existing exception".into());
        }
        let configuration: Value = serde_json::from_slice(&self.capture(
            "active-configuration",
            "ubus -S call uci get '{\"config\":\"tunnel-detour\"}'\n",
        )?)?;
        let values = configuration["values"]
            .as_object()
            .ok_or("missing active configuration")?;
        let patterns: Vec<DomainPattern> = values
            .values()
            .filter(|value| value[".type"] == "exception" && value["enabled"] != "0")
            .filter_map(|value| value["pattern"].as_str())
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        let pattern = patterns
            .iter()
            .min_by_key(|pattern| match pattern.scope {
                MatchScope::Exact => 0,
                MatchScope::DomainAndSubdomains => 1,
                MatchScope::DirectSubdomains => 2,
                MatchScope::AllSubdomains => 3,
            })
            .ok_or("an existing enabled rule is required for this read-only probe")?;
        let hostname = match pattern.scope {
            MatchScope::Exact | MatchScope::DomainAndSubdomains => pattern.domain.to_string(),
            MatchScope::DirectSubdomains | MatchScope::AllSubdomains => {
                format!("www.{}", pattern.domain)
            }
        };
        if !pattern.matches(&hostname.parse()?) {
            return Err("the probe hostname is not selected by the existing rule".into());
        }
        let url = reqwest::Url::parse(&format!("https://{hostname}/"))?;
        if url.host_str() != Some(hostname.as_str())
            || !hostname
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err("the existing test hostname is invalid".into());
        }
        let interfaces: Value = serde_json::from_slice(
            &self.capture("active-interfaces", "ubus -S call network.interface dump\n")?,
        )?;
        let vpn_devices: Vec<_> = interfaces["interface"]
            .as_array()
            .ok_or("missing interface inventory")?
            .iter()
            .filter(|interface| interface["proto"] == "wireguard" && interface["up"] == true)
            .filter_map(|interface| interface["l3_device"].as_str())
            .collect();
        let ordinary_route: Value = serde_json::from_slice(
            &self.capture("active-ordinary-route", "ip -j -4 route get 192.0.2.123\n")?,
        )?;
        if !ordinary_route[0]["dev"]
            .as_str()
            .is_some_and(|device| vpn_devices.contains(&device))
        {
            return Err(
                "ordinary IPv4 traffic does not select an active WireGuard interface".into(),
            );
        }
        println!("Ordinary IPv4 routing still selects WireGuard.");
        let mut url = url;
        for hop in 0..3 {
            let hostname = url.host_str().ok_or("the probe URL has no hostname")?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some_and(|port| port != 443)
                || !patterns
                    .iter()
                    .any(|pattern| hostname.parse().is_ok_and(|name| pattern.matches(&name)))
            {
                return Err("the redirect is outside the existing HTTPS exception rules; no request was sent".into());
            }
            write_private(
                &self.directory.join("acceptance-plan.json"),
                &serde_json::to_vec(&json!({"hostname":hostname,"url":url.as_str()}))?,
            )?;
            self.probe_test()?;
            let headers = fs::read_to_string(self.directory.join("acceptance-https.headers"))?;
            let code = headers
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or("missing HTTP response status")?;
            if (200..300).contains(&code) {
                return Ok(());
            }
            if !(300..400).contains(&code) {
                return Err("the selected website returned an unsuccessful HTTP response; see private records".into());
            }
            let location = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.trim())
                .ok_or("the HTTP redirect has no destination")?;
            url = url.join(location)?;
            for name in [
                "acceptance-plan.json",
                "acceptance-https.body",
                "acceptance-https.headers",
            ] {
                fs::rename(
                    self.directory.join(name),
                    self.directory.join(format!("redirect-{hop}-{name}")),
                )?;
            }
        }
        Err("the website exceeded the bounded redirect allowance".into())
    }

    fn windows_dns(&self) -> Result<(), Box<dyn Error>> {
        let plan = self.acceptance_plan()?;
        let hostname = plan["hostname"]
            .as_str()
            .ok_or("missing acceptance hostname")?;
        let hostname = format!("'{}'", hostname.replace('\'', "''"));
        let script = format!(
            "$ErrorActionPreference='Stop'; $r=@{{servers=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses); a=@(Resolve-DnsName -Name {hostname} -Type A -DnsOnly -ErrorAction SilentlyContinue | Select-Object Type,IPAddress); aaaa=@(Resolve-DnsName -Name {hostname} -Type AAAA -DnsOnly -ErrorAction SilentlyContinue | Select-Object Type,IPAddress)}}; $r | ConvertTo-Json -Depth 6 -Compress"
        );
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .output()?;
        self.record("windows-dns.json", &output.stdout)?;
        self.record("windows-dns.stderr", &output.stderr)?;
        if !output.status.success() {
            return Err("Windows DNS inspection failed; see private records".into());
        }
        let data: Value = serde_json::from_slice(
            output
                .stdout
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&output.stdout),
        )?;
        let a: Vec<_> = data["a"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["IPAddress"].as_str())
            .filter_map(|value| value.parse::<std::net::Ipv4Addr>().ok())
            .collect();
        let ipv6_count = data["aaaa"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry["IPAddress"]
                    .as_str()
                    .is_some_and(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
            })
            .count();
        println!(
            "{}",
            json!({"windows_a_count":a.len(),"windows_uses_synthetic_ipv4":a.iter().any(|ip|ip.octets()[0]==198 && matches!(ip.octets()[1],18|19)),"windows_aaaa_count":ipv6_count})
        );
        Ok(())
    }

    fn inspect_test(&self) -> Result<(), Box<dyn Error>> {
        let plan = self.acceptance_plan()?;
        let status: Value = serde_json::from_slice(&self.capture(
            "inspect-active-status",
            "ubus -S call tunnel-detour status '{}'\n",
        )?)?;
        let headers = fs::read_to_string(self.directory.join("acceptance-https.headers"))?;
        let location = headers.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.trim())
        });
        let redirect = location.and_then(|value| {
            reqwest::Url::parse(plan["url"].as_str()?)
                .ok()?
                .join(value)
                .ok()
        });
        println!(
            "{}",
            json!({"running":status["running"],"phase":status["status"]["phase"],"completed_connections":status["status"]["completed_connections"],"last_error":status["status"]["last_error"],"redirect_same_hostname":redirect.as_ref().is_some_and(|url|url.host_str()==plan["hostname"].as_str()),"redirect_to_domain_root":redirect.as_ref().is_some_and(|url|url.host_str()==plan["hostname"].as_str().and_then(|name|name.strip_prefix("www.")))})
        );
        Ok(())
    }

    fn audit_test(&self) -> Result<(), Box<dyn Error>> {
        let network = self.capture("active-audit-network", "uci export network\n")?;
        let firewall = self.capture("active-audit-firewall", "uci export firewall\n")?;
        let nft = self.capture("active-audit-nft", "nft -j list ruleset\n")?;
        let routes = self.capture(
            "active-audit-routes",
            "ip -4 rule show\nip -4 route show table all\n",
        )?;
        fn foreign_nft(bytes: &[u8]) -> Result<Value, Box<dyn Error>> {
            let mut data = normalized_nft(bytes)?;
            data["nftables"]
                .as_array_mut()
                .ok_or("invalid nftables listing")?
                .retain(|entry| {
                    !entry.as_object().is_some_and(|objects| {
                        objects.values().any(|object| {
                            object["table"] == "tunnel_detour"
                                || (object["name"] == "tunnel_detour" && object["family"] == "inet")
                        })
                    })
                });
            Ok(data)
        }
        let foreign_routes = String::from_utf8(routes)?
            .lines()
            .filter(|line| !line.starts_with("11000:") && !line.contains("table 41872"))
            .collect::<Vec<_>>()
            .join("\n");
        let original_routes =
            fs::read_to_string(self.directory.join("before-exception-routes.stdout"))?
                .lines()
                .collect::<Vec<_>>()
                .join("\n");
        let unchanged = network
            == fs::read(self.directory.join("before-exception-network.stdout"))?
            && firewall == fs::read(self.directory.join("before-exception-firewall.stdout"))?;
        let nft_unchanged = foreign_nft(&nft)?
            == foreign_nft(&fs::read(
                self.directory.join("before-exception-nft.stdout"),
            )?)?;
        let routing_unchanged = foreign_routes == original_routes;
        self.management("active-audit")?;
        println!(
            "{}",
            json!({"foreign_network_and_firewall_config_unchanged":unchanged,"foreign_nft_rules_unchanged_ignoring_counters":nft_unchanged,"foreign_ipv4_routing_unchanged":routing_unchanged})
        );
        if !unchanged || !nft_unchanged || !routing_unchanged {
            return Err(
                "active acceptance audit differs from the baseline; inspect private records".into(),
            );
        }
        Ok(())
    }

    fn finish_active(&self) -> Result<(), Box<dyn Error>> {
        self.audit_test()?;
        self.capture("persist-requested-exception", "set -e\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 1\nif uci -q get tunnel-detour.hardware_acceptance >/dev/null; then\n if uci -q get tunnel-detour.exception_1 >/dev/null; then exit 1; fi\n uci rename tunnel-detour.hardware_acceptance=exception_1\n uci commit tunnel-detour\nfi\n/etc/init.d/tunnel-detour enable\n")?;
        self.cleanup_remote()?;
        println!("The requested exception is retained and enabled for boot.");
        Ok(())
    }

    fn cleanup_remote(&self) -> Result<(), Box<dyn Error>> {
        let directories = self.capture(
            "private-uci-stage-inventory",
            "find /tmp -maxdepth 1 -type d -name 'tunnel-detour-config-*' -print\n",
        )?;
        for directory in String::from_utf8(directories)?.lines() {
            if !directory
                .strip_prefix("/tmp/tunnel-detour-config-")
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                return Err("unexpected private staging directory name".into());
            }
            let files = self.capture(
                "private-uci-stage-files",
                &format!(
                    "find {} -mindepth 1 -maxdepth 2 -type f -print\n",
                    quote(directory)
                ),
            )?;
            for file in String::from_utf8(files)?.lines() {
                if file != format!("{directory}/tunnel-detour")
                    && file != format!("{directory}/delta/tunnel-detour")
                {
                    return Err(
                        "unexpected file in private configuration staging; cleanup stopped".into(),
                    );
                }
                self.capture(
                    "remove-private-stage-file",
                    &format!(
                        "set -e\ntest -f {}\ntest ! -L {}\nrm -- {}\n",
                        quote(file),
                        quote(file),
                        quote(file)
                    ),
                )?;
            }
            self.capture(
                "remove-private-stage-directories",
                &format!(
                    "set -e\nrmdir -- {}\nrmdir -- {}\n",
                    quote(&format!("{directory}/delta")),
                    quote(directory)
                ),
            )?;
        }
        self.cleanup_uploaded_packages()?;
        self.capture(
            "cleanup-service-status",
            "ubus -S call tunnel-detour status '{}'\n",
        )?;
        self.management("after-cleanup")?;
        println!(
            "Private router staging and uploaded APK copies have been removed; running configuration was preserved."
        );
        Ok(())
    }

    fn upload(&self, local: &Path, remote: &str) -> Result<(), Box<dyn Error>> {
        let mut child = self
            .ssh()?
            .arg(&self.host)
            .arg(format!("umask 077; cat > {}", quote(remote)))
            .spawn()?;
        let transfer = std::io::copy(
            &mut fs::File::open(local)?,
            &mut child.stdin.take().ok_or("missing upload stdin")?,
        );
        let result = child.wait_with_output()?;
        self.record("upload.stderr", &result.stderr)?;
        transfer?;
        if !result.status.success() {
            return Err("router package upload failed; see private validation data".into());
        }
        let local_hash = Command::new("sha256sum").arg(local).output()?;
        if !local_hash.status.success() {
            return Err("local package hash failed".into());
        }
        let remote_hash =
            self.capture("upload-sha256", &format!("sha256sum {}\n", quote(remote)))?;
        if local_hash
            .stdout
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            != remote_hash.split(|byte| byte.is_ascii_whitespace()).next()
        {
            return Err("uploaded package hash differs".into());
        }
        Ok(())
    }

    fn management(&self, stage: &str) -> Result<(), Box<dyn Error>> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let response = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?
                .get(format!("http://{}/cgi-bin/luci/", self.host))
                .send()
                .await
                .map_err(|_| "LuCI HTTP reachability check failed")?;
            let status = response.status();
            if matches!(status.as_u16(), 401 | 403) {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|_| "LuCI login response could not be read")?;
                if bytes.len() > 131072
                    || !String::from_utf8_lossy(&bytes).contains("luci_username")
                {
                    return Err("LuCI authentication page was not recognized".into());
                }
            } else if !status.is_success() && !status.is_redirection() {
                return Err("LuCI returned an unsuccessful HTTP status".into());
            }
            Ok::<_, Box<dyn Error>>(())
        })?;
        let result = Command::new("dig")
            .args([
                &format!("@{}", self.host),
                "example.com",
                "A",
                "+tries=1",
                "+time=4",
                "+short",
            ])
            .output()?;
        self.record(&format!("{stage}-client-dns.stdout"), &result.stdout)?;
        self.record(&format!("{stage}-client-dns.stderr"), &result.stderr)?;
        if !result.status.success()
            || !String::from_utf8_lossy(&result.stdout)
                .lines()
                .any(|line| line.parse::<std::net::Ipv4Addr>().is_ok())
        {
            return Err("client DNS baseline check failed".into());
        }
        println!("{stage}: SSH, LuCI HTTP and client DNS are reachable.");
        Ok(())
    }

    fn install_disabled(&self) -> Result<(), Box<dyn Error>> {
        self.preflight()?;
        self.management("before-install")?;
        if !self
            .directory
            .join("affected-config-backup.stdout")
            .is_file()
        {
            return Err("recoverable configuration backup is required before installation".into());
        }
        let network = self.capture("before-install-network", "uci export network\n")?;
        let firewall = self.capture("before-install-firewall", "uci export firewall\n")?;
        let nft = self.capture("before-install-nft", "nft -j list ruleset\n")?;
        let routes = self.capture("before-install-routes", "ip -4 rule show\nip -4 route show table all\nip -6 rule show\nip -6 route show table all\n")?;
        let run_id = self
            .directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid validation directory")?;
        let remote = format!("/tmp/tunnel-detour-validation-{run_id}");
        self.capture(
            "package-directory",
            &format!(
                "umask 077\nmkdir -p {}\nchmod 700 {}\n",
                quote(&remote),
                quote(&remote)
            ),
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for name in ["tunnel-detour", "luci-app-tunnel-detour"] {
            let file = format!("{name}-{}-r1.apk", env!("CARGO_PKG_VERSION"));
            let destination = format!("{remote}/{file}");
            self.upload(
                &root.join("target/packages/mediatek-filogic").join(file),
                &destination,
            )?;
            files.push(quote(&destination));
        }
        let files = files.join(" ");
        let simulation = self.capture(
            "apk-install-simulation",
            &format!("apk add --simulate --allow-untrusted --no-network {files}\n"),
        )?;
        let simulation = String::from_utf8(simulation)?;
        if simulation.lines().any(|line| {
            ["Upgrading", "Downgrading", "Removing", "Reinstalling"]
                .iter()
                .any(|word| line.contains(word))
        }) || simulation
            .lines()
            .filter_map(|line| line.split_once("Installing "))
            .any(|(_, tail)| {
                !tail.starts_with("tunnel-detour (")
                    && !tail.starts_with("luci-app-tunnel-detour (")
            })
        {
            return Err(
                "APK simulation includes unrelated package changes; installation stopped".into(),
            );
        }
        self.capture(
            "apk-install",
            &format!("apk add --allow-untrusted --no-network {files}\n"),
        )?;
        self.capture("installed-disabled", "set -e\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 0\n/usr/bin/tunnel-detour --validate-patterns exact.example.test '*.example.test' '**.example.test' '***.example.test'\n/usr/bin/tunnel-detour list\nubus -S call tunnel-detour status '{}'\n")?;
        let after_network = self.capture("after-install-network", "uci export network\n")?;
        let after_firewall = self.capture("after-install-firewall", "uci export firewall\n")?;
        let after_nft = self.capture("after-install-nft", "nft -j list ruleset\n")?;
        let after_routes = self.capture("after-install-routes", "ip -4 rule show\nip -4 route show table all\nip -6 rule show\nip -6 route show table all\n")?;
        let nft_unchanged = normalized_nft(&nft)? == normalized_nft(&after_nft)?;
        let config_unchanged = network == after_network && firewall == after_firewall;
        let routes_unchanged = routes == after_routes;
        self.management("after-install")?;
        println!(
            "{}",
            json!({"installed_disabled":true,"network_and_firewall_config_unchanged":config_unchanged,"nft_rules_unchanged_ignoring_counters":nft_unchanged,"routing_unchanged":routes_unchanged})
        );
        if !config_unchanged || !nft_unchanged || !routes_unchanged {
            return Err(
                "post-install baseline differs; inspect private records before activation".into(),
            );
        }
        Ok(())
    }

    fn reinstall_active(&self) -> Result<(), Box<dyn Error>> {
        // This is a same-version acceptance deployment, not a general firmware upgrader.
        if self.directory.join("reinstall-board.stdout").exists() {
            return Err("use a fresh validation directory for each reinstallation attempt; prior recovery records must not be reused".into());
        }
        let board: Value = serde_json::from_slice(
            &self.capture("reinstall-board", "ubus -S call system board\n")?,
        )?;
        if board["board_name"] != "openwrt,one" || board["release"]["version"] != "25.12.6" {
            return Err("reinstallation requires the reference router and firmware".into());
        }
        let installed: Value = serde_json::from_slice(&self.capture("reinstall-version", "set -e\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 1\napk query --installed --from installed --fields name,version --format json tunnel-detour\n")?)?;
        if installed[0]["name"] != "tunnel-detour"
            || installed[0]["version"] != format!("{}-r1", env!("CARGO_PKG_VERSION"))
        {
            return Err("active reinstallation requires the same installed package version".into());
        }
        let expected_binary_hash = self.packaged_binary_hash()?;
        self.management("before-reinstall")?;
        let before: Value = serde_json::from_slice(&self.capture(
            "reinstall-status-before",
            "ubus -S call tunnel-detour status '{}'\n",
        )?)?;
        if before["running"] != true || before["status"]["phase"] != "ready" {
            return Err("the active service must be healthy before reinstallation".into());
        }
        let configuration =
            self.capture("reinstall-config-before", "uci export tunnel-detour\n")?;
        let options: Value = serde_json::from_slice(&self.capture(
            "reinstall-options-before",
            "ubus -S call uci get '{\"config\":\"tunnel-detour\"}'\n",
        )?)?;
        let globals = &options["values"]["globals"];
        if globals["ipv6_enabled"] == "1"
            || globals["manage_adguard_upstream"] == "1"
            || options["values"]["inbound"]["enabled"] == "1"
            || globals["dns_integration"]
                .as_str()
                .is_some_and(|mode| mode != "adguard")
        {
            return Err("this recovery path requires the existing IPv4 AdGuard profile without managed general upstreams or package-owned inbound publications".into());
        }
        let field = |name: &str| {
            globals[name]
                .as_str()
                .ok_or("missing applied AdGuard settings")
        };
        let stored_credentials = self.applied_credentials(globals)?;
        let username = stored_credentials
            .get("username")
            .map(|value| value.as_str().ok_or("invalid applied AdGuard username"))
            .transpose()?
            .filter(|value| !value.is_empty());
        let password = stored_credentials
            .get("password")
            .map(|value| value.as_str().ok_or("invalid applied AdGuard password"))
            .transpose()?
            .filter(|value| !value.is_empty());
        if username.is_some() != password.is_some() {
            return Err("the applied AdGuard credential pair is incomplete".into());
        }
        let control = json!({
            "api_url":field("adguard_url")?,
            "username":username,
            "password":password,
        });
        let ownership_bytes = self.capture(
            "reinstall-ownership-before",
            "cat /etc/tunnel-detour/leases.json.adguard.json\n",
        )?;
        let ownership: Value = serde_json::from_slice(&ownership_bytes)?;
        validate_recovery_ownership(&ownership, &ownership, &control)?;
        let table_before: Value = serde_json::from_slice(
            &self.capture("reinstall-table-before", "nft -j list tables\n")?,
        )?;
        recovery_table_present(&table_before)?;
        let firewall_before = self.capture(
            "reinstall-owned-firewall-before",
            "nft -s list table inet tunnel_detour\n",
        )?;
        let network = self.capture("reinstall-network-before", "uci export network\n")?;
        let firewall = self.capture("reinstall-firewall-before", "uci export firewall\n")?;
        // Keep live lease state out of automatic rollback: cached Fake-IPs must never lose
        // mappings allocated after this backup. Archive only the owned executable/UI payload.
        let archive = self.capture("reinstall-payload-before.tar.gz", "set -e\nset -- /usr/bin/tunnel-detour /usr/libexec/rpcd/tunnel-detour /etc/init.d/tunnel-detour /usr/share/luci/menu.d/luci-app-tunnel-detour.json /usr/share/rpcd/acl.d/luci-app-tunnel-detour.json /www/luci-static/resources/view/tunnel-detour/overview.js\nif test -f /www/luci-static/resources/view/tunnel-detour/overview.css; then set -- \"$@\" /www/luci-static/resources/view/tunnel-detour/overview.css; fi\ntar -czf - \"$@\"\n")?;
        if archive.is_empty() {
            return Err("the recoverable installed-payload archive is empty".into());
        }
        self.capture(
            "reinstall-state-before.tar.gz",
            "tar -czf - /etc/tunnel-detour /lib/apk/db/installed /etc/apk/world\n",
        )?;
        let run_id = self
            .directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid validation directory")?;
        let remote = format!("/tmp/tunnel-detour-validation-{run_id}");
        self.capture(
            "reinstall-directory",
            &format!(
                "umask 077\nmkdir -p {}\nchmod 700 {}\n",
                quote(&remote),
                quote(&remote)
            ),
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for name in ["tunnel-detour", "luci-app-tunnel-detour"] {
            let file = format!("{name}-{}-r1.apk", env!("CARGO_PKG_VERSION"));
            let destination = format!("{remote}/{file}");
            self.upload(
                &root.join("target/packages/mediatek-filogic").join(file),
                &destination,
            )?;
            files.push(quote(&destination));
        }
        let files = files.join(" ");
        let simulation = self.capture(
            "reinstall-simulation",
            &format!(
                "apk add --simulate --force-reinstall --allow-untrusted --no-network {files}\n"
            ),
        )?;
        validate_reinstallation_plan(&String::from_utf8(simulation)?)?;
        // Upload recovery before mutation, so recovery does not require a working WAN.
        let recovery = format!("{remote}/payload-before.tar.gz");
        self.upload(
            &self
                .directory
                .join("reinstall-payload-before.tar.gz.stdout"),
            &recovery,
        )?;
        self.upload(
            &self.directory.join("reinstall-ownership-before.stdout"),
            &format!("{remote}/ownership-before.json"),
        )?;
        let mut rollback = b"delete table inet tunnel_detour\n".to_vec();
        rollback.extend(&firewall_before);
        write_private(
            &self.directory.join("reinstall-firewall-preflight.nft"),
            &rollback,
        )?;
        self.upload(
            &self.directory.join("reinstall-firewall-preflight.nft"),
            &format!("{remote}/firewall-restore.nft"),
        )?;
        self.capture(
            "reinstall-recovery-firewall-check",
            &format!(
                "nft -c -f {}\n",
                quote(&format!("{remote}/firewall-restore.nft"))
            ),
        )?;
        let result = (|| -> Result<(), Box<dyn Error>> {
            self.capture("reinstall-apk", &format!("set -e\napk add --force-reinstall --allow-untrusted --no-network {files}\n/etc/init.d/tunnel-detour restart\n"))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let status: Value = serde_json::from_slice(&self.capture(
                    "reinstall-status-after",
                    "ubus -S call tunnel-detour status '{}'\n",
                )?)?;
                if status["running"] == true
                    && status["status"]["phase"] == "ready"
                    && status["status"]["process_id"] != before["status"]["process_id"]
                {
                    break;
                }
                if status["status"]["phase"] == "failed" || std::time::Instant::now() >= deadline {
                    return Err("the reinstalled service did not become ready".into());
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            if self.capture("reinstall-config-after", "uci export tunnel-detour\n")?
                != configuration
                || self.capture("reinstall-network-after", "uci export network\n")? != network
                || self.capture("reinstall-firewall-after", "uci export firewall\n")? != firewall
            {
                return Err("configuration changed during reinstallation".into());
            }
            let check: Value = serde_json::from_slice(
                &self.capture("reinstall-check", "ubus -S call tunnel-detour check '{}'\n")?,
            )?;
            let adguard: Value = serde_json::from_slice(&self.capture(
                "reinstall-adguard",
                "ubus -S call tunnel-detour test_adguard '{}'\n",
            )?)?;
            if check["valid"] != true
                || adguard["connected"] != true
                || adguard["health"]["dns_running"] != true
            {
                return Err(
                    "reinstalled configuration or local AdGuard access failed validation".into(),
                );
            }
            for name in ["overview.js", "overview.css"] {
                if self.capture(
                    "reinstall-ui",
                    &format!("cat /www/luci-static/resources/view/tunnel-detour/{name}\n"),
                )? != fs::read(root.join("sources/openwrt/luci").join(name))?
                {
                    return Err("the installed UI payload differs from the build".into());
                }
            }
            let remote_hash = self.capture(
                "reinstall-binary-hash",
                "sha256sum /usr/bin/tunnel-detour\n",
            )?;
            if expected_binary_hash
                .split(|byte| byte.is_ascii_whitespace())
                .next()
                != remote_hash.split(|byte| byte.is_ascii_whitespace()).next()
            {
                return Err("the installed runtime differs from the APK payload".into());
            }
            self.management("after-reinstall")?;
            Ok(())
        })();
        if let Err(error) = result {
            self.capture(
                "reinstall-recovery-stop",
                "/etc/init.d/tunnel-detour stop\n",
            )?;
            if self.capture("reinstall-recovery-config", "uci export tunnel-detour\n")?
                != configuration
            {
                return Err("reinstallation failed and UCI changed; recovery preserved the changed settings and requires review".into());
            }
            let current: Value = serde_json::from_slice(&self.capture(
                "reinstall-recovery-ownership",
                "cat /etc/tunnel-detour/leases.json.adguard.json\n",
            )?)?;
            validate_recovery_ownership(&ownership, &current, &control)?;
            let tables: Value = serde_json::from_slice(
                &self.capture("reinstall-recovery-tables", "nft -j list tables\n")?,
            )?;
            let mut transaction = if recovery_table_present(&tables)? {
                b"delete table inet tunnel_detour\n".to_vec()
            } else {
                Vec::new()
            };
            transaction.extend(&firewall_before);
            write_private(
                &self.directory.join("reinstall-firewall-restore.nft"),
                &transaction,
            )?;
            self.upload(
                &self.directory.join("reinstall-firewall-restore.nft"),
                &format!("{remote}/firewall-restore.nft"),
            )?;
            self.capture("reinstall-recovery", &format!("set -e\numask 077\nnft -c -f {firewall}\ntest ! -e /etc/tunnel-detour/leases.json.adguard.json.restore\ntest ! -L /etc/tunnel-detour/leases.json.adguard.json.restore\ncp {journal} /etc/tunnel-detour/leases.json.adguard.json.restore\nchmod 600 /etc/tunnel-detour/leases.json.adguard.json.restore\nsync\nmv /etc/tunnel-detour/leases.json.adguard.json.restore /etc/tunnel-detour/leases.json.adguard.json\nsync\ntar -xzf {payload} -C /\nnft -f {firewall}\n/etc/init.d/rpcd reload\n/etc/init.d/tunnel-detour start\n", firewall=quote(&format!("{remote}/firewall-restore.nft")), journal=quote(&format!("{remote}/ownership-before.json")), payload=quote(&recovery)))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let status: Value = serde_json::from_slice(&self.capture(
                    "reinstall-recovery-status",
                    "ubus -S call tunnel-detour status '{}'\n",
                )?)?;
                if status["running"] == true && status["status"]["phase"] == "ready" {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err("previous payload restored but readiness needs review".into());
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            self.management("after-recovery")?;
            return Err(format!("reinstallation failed ({error}); previous runtime, owned firewall and DNS ownership recovered without reverting live leases or UCI; package metadata, new-only guards and private backups remain for review").into());
        }
        println!(
            "Active package reinstallation passed: a new process is ready, configuration is preserved, and SSH, LuCI and DNS remain reachable."
        );
        Ok(())
    }

    fn verify_disabled(&self) -> Result<(), Box<dyn Error>> {
        let status: Value = serde_json::from_slice(&self.capture("verify-disabled-status", "set -e\ntest \"$(uci -q get tunnel-detour.globals.enabled)\" = 0\npermissions=$(ls -ld /etc/config/tunnel-detour)\ncase \"$permissions\" in '-rw------- '*) ;; *) exit 1 ;; esac\nubus -S call tunnel-detour status '{}'\n")?)?;
        if status["running"] != false {
            return Err("the service unexpectedly reports itself running".into());
        }
        self.capture("verify-disabled-kernel", "set -e\nif nft list table inet tunnel_detour >/dev/null 2>&1; then exit 1; fi\ntest -z \"$(ip -4 route show table 41872 2>/dev/null)\"\ntest ! -d /etc/tunnel-detour\n")?;
        let binary = self.capture(
            "verify-installed-hash",
            "sha256sum /usr/bin/tunnel-detour\n",
        )?;
        let local = self.packaged_binary_hash()?;
        if local.split(|byte| byte.is_ascii_whitespace()).next()
            != binary.split(|byte| byte.is_ascii_whitespace()).next()
        {
            return Err("installed ARM binary differs from the inspected APK payload".into());
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let runtime = tokio::runtime::Runtime::new()?;
        let asset = runtime.block_on(async {
            let response = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?
                .get(format!(
                    "http://{}/luci-static/resources/view/tunnel-detour/overview.js",
                    self.host
                ))
                .send()
                .await
                .map_err(|_| "installed LuCI asset request failed")?;
            if !response.status().is_success() {
                return Err("installed LuCI asset is unavailable".into());
            }
            Ok::<_, Box<dyn Error>>(
                response
                    .bytes()
                    .await
                    .map_err(|_| "installed LuCI asset could not be read")?
                    .to_vec(),
            )
        })?;
        if asset != fs::read(root.join("sources/openwrt/luci/overview.js"))? {
            return Err("installed LuCI asset differs from the package source".into());
        }
        self.management("verified-disabled")?;
        println!(
            "Disabled ARM binary, rpcd status, private UCI permissions and served LuCI asset verified; no owned firewall/routing state exists."
        );
        self.cleanup_uploaded_packages()?;
        Ok(())
    }

    fn packaged_binary_hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sdk = PathBuf::from(env::var_os("TUNNEL_DETOUR_PACKAGE_SDK").ok_or(
            "package verification requires TUNNEL_DETOUR_PACKAGE_SDK for APK payload inspection",
        )?);
        let extracted = tempfile::tempdir()?;
        let extraction = Command::new(sdk.join("staging_dir/host/bin/apk"))
            .args([
                "extract",
                "--allow-untrusted",
                "--no-chown",
                "--destination",
            ])
            .arg(extracted.path())
            .arg(root.join(format!(
                "target/packages/mediatek-filogic/tunnel-detour-{}-r1.apk",
                env!("CARGO_PKG_VERSION")
            )))
            .output()?;
        self.record("verify-local-apk-extract.stdout", &extraction.stdout)?;
        self.record("verify-local-apk-extract.stderr", &extraction.stderr)?;
        if !extraction.status.success() {
            return Err("local APK payload inspection failed".into());
        }
        let local = Command::new("sha256sum")
            .arg(extracted.path().join("usr/bin/tunnel-detour"))
            .output()?;
        if !local.status.success() {
            return Err("APK binary hash failed".into());
        }
        Ok(local.stdout)
    }

    fn cleanup_uploaded_packages(&self) -> Result<(), Box<dyn Error>> {
        let run_id = self
            .directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid validation directory")?;
        let remote = format!("/tmp/tunnel-detour-validation-{run_id}");
        let mut files: Vec<_> = ["tunnel-detour", "luci-app-tunnel-detour"]
            .iter()
            .map(|name| {
                quote(&format!(
                    "{remote}/{name}-{}-r1.apk",
                    env!("CARGO_PKG_VERSION")
                ))
            })
            .collect();
        files.push(quote(&format!("{remote}/payload-before.tar.gz")));
        files.push(quote(&format!("{remote}/ownership-before.json")));
        files.push(quote(&format!("{remote}/firewall-restore.nft")));
        self.capture(
            "remove-uploaded-packages",
            &format!(
                "set -e\nif test -d {}; then\nfor file in {}; do\n if test -e \"$file\" || test -L \"$file\"; then\n  test -f \"$file\"\n  test ! -L \"$file\"\n  rm -- \"$file\"\n fi\ndone\nrmdir -- {}\nfi\n",
                quote(&remote),
                files.join(" "),
                quote(&remote)
            ),
        )?;
        Ok(())
    }

    fn record(&self, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        for attempt in 0..1000 {
            let name = if attempt == 0 {
                name.to_string()
            } else {
                format!("{name}.{attempt}")
            };
            match write_private(&self.directory.join(name), bytes) {
                Ok(()) => return Ok(()),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) => {
                }
                Err(error) => return Err(error),
            }
        }
        Err("validation record capacity exhausted".into())
    }

    fn details(&self) -> Result<(), Box<dyn Error>> {
        let services: Value =
            serde_json::from_slice(&fs::read(self.directory.join("services.stdout"))?)?;
        for (name, service) in services.as_object().ok_or("service inventory is invalid")? {
            if !name.to_lowercase().contains("adguard") {
                continue;
            }
            for instance in service["instances"]
                .as_object()
                .ok_or("AdGuard instance is absent")?
                .values()
            {
                let args = instance["command"]
                    .as_array()
                    .ok_or("AdGuard arguments are absent")?;
                let binary = args
                    .first()
                    .and_then(Value::as_str)
                    .ok_or("AdGuard executable is absent")?;
                let config = args
                    .windows(2)
                    .find(|pair| matches!(pair[0].as_str(), Some("-c" | "--config")))
                    .and_then(|pair| pair[1].as_str())
                    .ok_or("AdGuard config path is absent")?;
                println!(
                    "{}",
                    json!({"adguard_binary":binary, "adguard_config":config})
                );
                let version =
                    self.capture("adguard-version", &format!("{} --version\n", quote(binary)))?;
                println!(
                    "AdGuard version: {}",
                    String::from_utf8_lossy(&version).trim()
                );
                self.capture("adguard-config", &format!("cat {}\n", quote(config)))?;
                let archive = self.capture(
                    "affected-config-backup",
                    &format!(
                        "tar -czf - /etc/config/network /etc/config/firewall {}\n",
                        quote(config)
                    ),
                )?;
                println!(
                    "Recoverable configuration backup saved ({} bytes).",
                    archive.len()
                );
            }
        }
        let listeners = fs::read_to_string(self.directory.join("listeners.stdout"))?;
        let mut ports = std::collections::BTreeSet::new();
        for line in listeners
            .lines()
            .filter(|line| line.contains("AdGuardHome"))
        {
            if let Some(port) = line
                .split_whitespace()
                .nth(3)
                .and_then(|value| value.rsplit_once(':'))
                .and_then(|(_, port)| port.parse::<u16>().ok())
            {
                ports.insert(port);
            }
        }
        println!("{}", json!({"adguard_listening_ports":ports}));
        let packages = fs::read_to_string(self.directory.join("packages.stdout"))?;
        let selected: Vec<_> = packages
            .lines()
            .filter(|name| {
                [
                    "ip-full-",
                    "nftables-json-",
                    "dnsmasq-",
                    "pbr-",
                    "adguardhome-",
                    "tunnel-detour-",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            })
            .collect();
        println!("{}", json!({"selected_packages":selected}));
        let routes = fs::read_to_string(self.directory.join("routes.stdout"))?;
        let devices: Vec<_> = routes
            .lines()
            .filter(|line| line.starts_with("default "))
            .filter_map(|line| {
                line.split_once(" dev ")
                    .and_then(|(_, tail)| tail.split_whitespace().next())
            })
            .collect();
        println!("{}", json!({"default_route_devices":devices}));
        Ok(())
    }

    fn inspect_active(&self) -> Result<(), Box<dyn Error>> {
        self.capture("active-dependencies", "for name in libc libgcc1 procd rpcd ubus uci ip-full nftables-json kmod-nft-nat conntrack firewall4 kmod-inet-diag luci-base; do if apk info -e \"$name\" >/dev/null 2>&1; then printf '%s present\\n' \"$name\"; else printf '%s missing\\n' \"$name\"; fi; done\n")?;
        for (name, script) in [
            (
                "active-package-versions",
                "apk query --installed --from installed --fields name,version --format json tunnel-detour luci-app-tunnel-detour\n",
            ),
            (
                "active-configuration",
                "ubus -S call uci get '{\"config\":\"tunnel-detour\"}'\n",
            ),
            ("active-runtime", "ubus -S call tunnel-detour status '{}'\n"),
            ("active-ipv6-addresses", "ip -j -6 address show\n"),
            (
                "active-routes",
                "ip -4 rule show\nip -4 route show table all\nip -6 rule show\nip -6 route show table all\n",
            ),
            ("active-uci-pending", "uci changes\n"),
            ("active-init", "cat /etc/init.d/tunnel-detour\n"),
            ("active-fw4-include", "fw4 print\n"),
            ("active-fw4-check", "fw4 check\n"),
            ("active-payload-hash", "sha256sum /usr/bin/tunnel-detour\n"),
        ] {
            self.capture(name, script)?;
        }
        self.management("active-preflight")?;
        println!(
            "Active package, dependencies, IPv6, pending UCI changes and firewall include inspected; private records retained. No router settings changed."
        );
        Ok(())
    }

    fn inspect_path(&self) -> Result<(), Box<dyn Error>> {
        for (name, script) in [
            ("path-kernel", "uname -r\n"),
            ("path-firewall", "nft --json list ruleset\n"),
            ("path-links", "ip -details -json -statistics link show\n"),
            ("path-addresses", "ip -json -6 address show\n"),
            ("path-routes", "ip -json -6 route show table all\n"),
            ("path-rules", "ip -json -6 rule show\n"),
            ("path-neighbors", "ip -json -6 neighbor show\n"),
            ("path-interfaces", "ubus -S call network.interface dump\n"),
            ("path-wg-handshake", "wg show all latest-handshakes\n"),
            ("path-wg-transfer", "wg show all transfer\n"),
            (
                "path-tools",
                "for tool in tcpdump tc nstat ss; do if command -v \"$tool\" >/dev/null 2>&1; then printf '%s available\\n' \"$tool\"; else printf '%s unavailable\\n' \"$tool\"; fi; done\n",
            ),
            (
                "path-tc",
                "if command -v tc >/dev/null 2>&1; then tc -json qdisc show; for device in /sys/class/net/*; do device=${device##*/}; printf '\\nDEVICE %s\\n' \"$device\"; tc -json filter show dev \"$device\" ingress; done; else printf 'tc unavailable\\n'; fi\n",
            ),
            ("path-ipv6-counters", "cat /proc/net/snmp6\n"),
            ("path-sockets", "netstat -lntp\n"),
            (
                "path-runtime",
                "ubus -S call tunnel-detour inbound_status '{}'\nubus -S call tunnel-detour status '{}'\n",
            ),
            ("path-log", "logread -e tunnel-detour -l 40\n"),
        ] {
            self.capture(name, script)?;
        }
        self.management("path-management")?;
        println!("Read-only packet-path inventory retained privately; no router settings changed.");
        Ok(())
    }

    fn inspect(&self) -> Result<(), Box<dyn Error>> {
        let board: Value =
            serde_json::from_slice(&self.capture("board", "ubus -S call system board\n")?)?;
        println!(
            "{}",
            json!({"model":board["model"], "board":board["board_name"], "release":board["release"]["version"], "target":board["release"]["target"]})
        );
        for (name, script) in [
            ("network", "uci export network\n"),
            ("firewall", "uci export firewall\n"),
            ("interfaces", "ubus -S call network.interface dump\n"),
            ("services", "ubus -S call service list\n"),
            ("firewall-rules", "nft -j list ruleset\n"),
            ("routes", "ip -4 rule show\nip -4 route show table all\n"),
            ("packages", "apk info -v\n"),
            ("listeners", "netstat -lntup\n"),
            (
                "adguard-config-paths",
                "find /etc -maxdepth 3 -iname '*adguard*' -print\n",
            ),
            ("capacity", "df -Pk / /tmp\nfree\n"),
        ] {
            self.capture(name, script)?;
        }
        let interfaces: Value =
            serde_json::from_slice(&fs::read(self.directory.join("interfaces.stdout"))?)?;
        let summary: Vec<_> = interfaces["interface"].as_array().ok_or("interface inventory is absent")?.iter().map(|interface| json!({"interface":interface["interface"], "protocol":interface["proto"], "up":interface["up"], "device":interface["l3_device"], "ipv4_count":interface["ipv4-address"].as_array().map_or(0,Vec::len)})).collect();
        println!("{}", json!({"interfaces":summary}));
        let services: Value =
            serde_json::from_slice(&fs::read(self.directory.join("services.stdout"))?)?;
        let adguard: Vec<_> = services
            .as_object()
            .ok_or("service inventory is invalid")?
            .keys()
            .filter(|name| name.to_lowercase().contains("adguard"))
            .collect();
        println!("{}", json!({"adguard_services":adguard}));
        println!("Private validation directory: {}", self.directory.display());
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

struct Tunnel(Child);

fn normalized_nft(bytes: &[u8]) -> Result<Value, Box<dyn Error>> {
    fn normalize(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for key in ["handle", "packets", "bytes", "expires"] {
                    fields.remove(key);
                }
                for field in fields.values_mut() {
                    normalize(field);
                }
            }
            Value::Array(values) => {
                for value in values {
                    normalize(value);
                }
            }
            _ => (),
        }
    }
    let mut value = serde_json::from_slice(bytes)?;
    normalize(&mut value);
    Ok(value)
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            eprintln!("SSH tunnel termination failed: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("SSH tunnel reap failed: {error}");
        }
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn recovery_table_present(listing: &Value) -> Result<bool, Box<dyn Error>> {
    let objects = listing["nftables"]
        .as_array()
        .ok_or("invalid firewall recovery inventory")?;
    let tables: Vec<_> = objects
        .iter()
        .filter_map(|object| object.get("table"))
        .filter(|table| table["family"] == "inet" && table["name"] == "tunnel_detour")
        .collect();
    match tables.as_slice() {
        [] => Ok(false),
        [table]
            if matches!(
                table["comment"].as_str(),
                Some("tunnel-detour:v1" | "tunnel-detour:v2")
            ) =>
        {
            Ok(true)
        }
        _ => Err("firewall recovery refuses an unrecognized table owner".into()),
    }
}

fn validate_recovery_ownership(
    previous: &Value,
    current: &Value,
    control: &Value,
) -> Result<(), Box<dyn Error>> {
    for journal in [previous, current] {
        let object = journal.as_object().ok_or("invalid DNS recovery journal")?;
        let version = journal["version"]
            .as_u64()
            .ok_or("missing DNS journal version")?;
        let managed = journal["managed"]
            .as_array()
            .ok_or("missing DNS ownership list")?;
        let names = managed
            .iter()
            .map(|line| line.as_str().ok_or("invalid DNS ownership entry"))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        if !matches!(version, 1 | 3)
            || managed.len() > 4096
            || names.len() != managed.len()
            || names
                .iter()
                .any(|line| line.is_empty() || line.len() > 4096)
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "version" | "managed" | "control" | "upstream" | "last_upstream_approval"
                )
            })
            || (version == 1 && object.len() != 2)
            || (version == 3 && &journal["control"] != control)
            || !journal["upstream"].is_null()
            || !journal["last_upstream_approval"].is_null()
        {
            return Err(
                "DNS recovery requires unchanged domain-only ownership and the original local API"
                    .into(),
            );
        }
    }
    if previous["managed"] != current["managed"]
        || (previous["version"] == 3 && previous != current)
    {
        return Err("DNS recovery refuses changed or pending ownership".into());
    }
    Ok(())
}

fn validate_reinstallation_plan(plan: &str) -> Result<(), Box<dyn Error>> {
    let mut packages = std::collections::BTreeSet::new();
    let version = format!("{}-r1", env!("CARGO_PKG_VERSION"));
    for line in plan
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with('('))
    {
        let (_, change) = line
            .split_once(") ")
            .ok_or("invalid APK transaction line")?;
        let (operation, package) = change.split_once(' ').ok_or("invalid APK package change")?;
        let (name, versions) = package
            .split_once(" (")
            .ok_or("invalid APK package version")?;
        let versions = versions
            .strip_suffix(')')
            .ok_or("invalid APK version boundary")?;
        let same_version = match operation {
            "Reinstalling" => versions == version,
            // apk-tools distinguishes changed content at the same version
            // from reinstalling the identical package object.
            "Replacing" => versions == format!("{version} -> {version}"),
            _ => false,
        };
        if !same_version
            || !matches!(name, "tunnel-detour" | "luci-app-tunnel-detour")
            || !packages.insert(name)
        {
            return Err(
                "APK simulation includes unexpected package changes; reinstallation stopped".into(),
            );
        }
    }
    if packages != std::collections::BTreeSet::from(["tunnel-detour", "luci-app-tunnel-detour"]) {
        return Err("APK simulation must include exactly the two owned packages".into());
    }
    Ok(())
}

pub(crate) fn run(
    host: &str,
    input: &Path,
    resume: Option<&Path>,
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    let router = Router::open(host, input, resume)?;
    println!(
        "Private validation directory: {}",
        router.directory.display()
    );
    match phase {
        "inspect" => router.inspect(),
        "inspect-active" => router.inspect_active(),
        "inspect-path" => router.inspect_path(),
        "probe-path" => path_probe::run(&router),
        "details" => router.details(),
        "adguard" => router.adguard(),
        "preflight" => router.preflight(),
        "install-disabled" => router.install_disabled(),
        "reinstall-active" => router.reinstall_active(),
        "verify-disabled" => router.verify_disabled(),
        "start-test" => router.start_test(),
        "stop-test" => router.stop_test(),
        "probe-test" => router.probe_test(),
        "probe-active" => router.probe_active(),
        "probe-ipv6-windows" => router.probe_ipv6_windows(),
        "windows-dns" => router.windows_dns(),
        "inspect-test" => router.inspect_test(),
        "audit-test" => router.audit_test(),
        "finish-active" => router.finish_active(),
        "clean-router" => router.cleanup_remote(),
        _ => Err("unknown router test phase".into()),
    }
}

pub(crate) fn configure(
    host: &str,
    input: &Path,
    resume: &Path,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    Router::open(host, input, Some(resume))?.configure_disabled(target)
}

#[cfg(test)]
mod tests {
    use super::{
        recovery_table_present, validate_recovery_ownership, validate_reinstallation_plan,
    };
    use serde_json::json;

    #[test]
    fn r122_hardware_recovery_accepts_only_unchanged_domain_ownership_and_known_firewall_generations()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = json!({"version":1,"managed":["[/selected.example.test/]127.0.0.1:10535"]});
        let control = json!({"api_url":"http://127.0.0.1:13000","username":null,"password":null});
        let migrated = json!({"version":3,"managed":original["managed"],"control":control});
        validate_recovery_ownership(&original, &original, &control)?;
        validate_recovery_ownership(&original, &migrated, &control)?;
        validate_recovery_ownership(&migrated, &migrated, &control)?;
        for (key, value) in [
            ("managed", json!([])),
            ("managed", json!(["[/other.example.test/]127.0.0.1:10535"])),
            (
                "managed",
                json!([
                    "[/selected.example.test/]127.0.0.1:10535",
                    "[/selected.example.test/]127.0.0.1:10535"
                ]),
            ),
            (
                "control",
                json!({"api_url":"http://127.0.0.1:13001","username":null,"password":null}),
            ),
            ("upstream", json!({"pending":["tcp://192.0.2.53"]})),
            ("last_upstream_approval", json!("unreviewed")),
            ("unknown", json!(true)),
            ("version", json!(2)),
        ] {
            let mut changed = migrated.clone();
            changed[key] = value;
            assert!(
                validate_recovery_ownership(&original, &changed, &control).is_err(),
                "accepted changed ownership field {key}"
            );
        }
        for owner in ["tunnel-detour:v1", "tunnel-detour:v2"] {
            assert!(recovery_table_present(
                &json!({"nftables":[{"table":{"family":"inet","name":"tunnel_detour","comment":owner}}]})
            )?);
        }
        assert!(!recovery_table_present(&json!({"nftables":[]}))?);
        assert!(recovery_table_present(&json!({"nftables":[{"table":{"family":"inet","name":"tunnel_detour","comment":"foreign"}}]})).is_err());
        Ok(())
    }

    #[test]
    fn r040_hardware_reinstallation_rejects_foreign_removal_unknown_or_incomplete_apk_transactions()
    {
        let version = format!("{}-r1", env!("CARGO_PKG_VERSION"));
        let owned = format!(
            "(1/2) Reinstalling tunnel-detour ({version})\n(2/2) Reinstalling luci-app-tunnel-detour ({version})\nOK: 81 MiB in 147 packages\n"
        );
        let replacement = format!(
            "(1/2) Replacing tunnel-detour ({version} -> {version})\n(2/2) Replacing luci-app-tunnel-detour ({version} -> {version})\nOK: 81 MiB in 147 packages\n"
        );
        assert!(validate_reinstallation_plan(&owned).is_ok());
        assert!(validate_reinstallation_plan(&replacement).is_ok());
        for plan in [
            format!("{owned}(3/3) Upgrading firewall4 (1-r1 -> 1-r2)\n"),
            format!("{owned}(3/3) Removing adguardhome (1-r1)\n"),
            owned.replace("Reinstalling tunnel-detour", "Removing tunnel-detour"),
            owned.replace("Reinstalling tunnel-detour", "Unexpected tunnel-detour"),
            owned.replace("Reinstalling tunnel-detour", "Installing tunnel-detour"),
            replacement.replace(
                &format!("{version} -> {version}"),
                &format!("0.0.0-r1 -> {version}"),
            ),
            replacement.replace(
                &format!("{version} -> {version}"),
                &format!("{version} -> 99.0.0-r1"),
            ),
            format!("(1/1) Reinstalling tunnel-detour ({version})\n"),
            "OK: nothing to do\n".into(),
        ] {
            assert!(
                validate_reinstallation_plan(&plan).is_err(),
                "unsafe transaction was accepted"
            );
        }
    }
}
