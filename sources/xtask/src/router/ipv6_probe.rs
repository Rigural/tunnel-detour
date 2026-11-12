//! An authorized Windows LAN client, with the router observed while TLS is held open.

use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tunnel_detour_core::{DomainName, DomainPattern};

use super::Router;

const CLIENT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
$control=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
$tls=$null
try {
  if (!$client.ConnectAsync('@ADDRESS@',443).Wait(5000)) { throw 'IPv6 connect timeout' }
  $tls=[Net.Security.SslStream]::new($client.GetStream(),$false)
  $tls.ReadTimeout=10000
  $tls.WriteTimeout=10000
  if (!$tls.AuthenticateAsClientAsync('@HOST@').Wait(10000)) { throw 'TLS timeout' }
  [Console]::Out.WriteLine((@{phase='tls_ready';local=$client.Client.LocalEndPoint.ToString();remote=$client.Client.RemoteEndPoint.ToString();protocol=$tls.SslProtocol.ToString()} | ConvertTo-Json -Compress))
  if (!$control.ConnectAsync('127.0.0.1',@PORT@).Wait(5000)) { throw 'Observation channel timeout' }
  $control.GetStream().ReadTimeout=10000
  if ($control.GetStream().ReadByte() -ne 1) { throw 'Observation was not acknowledged' }
  $request=[Text.Encoding]::ASCII.GetBytes("GET @TARGET@ HTTP/1.1`r`nHost: @HOST@`r`nUser-Agent: Tunnel-Detour-Acceptance`r`nConnection: close`r`n`r`n")
  $tls.Write($request,0,$request.Length)
  $watch=[Diagnostics.Stopwatch]::StartNew()
  $buffer=New-Object byte[] 8192
  $header=New-Object byte[] 32768
  $headerSize=0
  $headerDone=$false
  $total=0
  while ($true) {
    $remaining=20000-$watch.ElapsedMilliseconds
    if ($remaining -le 0) { throw 'HTTP deadline expired' }
    $read=$tls.ReadAsync($buffer,0,$buffer.Length)
    if (!$read.Wait([int]$remaining)) { throw 'HTTP read timeout' }
    $count=$read.Result
    if ($count -eq 0) { break }
    $total+=$count
    if ($total -gt 2097152) { throw 'HTTP response exceeds the probe bound' }
    for ($i=0; !$headerDone -and $i -lt $count; $i++) {
      if ($headerSize -eq $header.Length) { throw 'HTTP headers exceed the probe bound' }
      $header[$headerSize]=$buffer[$i]
      $headerSize++
      if ($headerSize -ge 4 -and $header[$headerSize-4] -eq 13 -and $header[$headerSize-3] -eq 10 -and $header[$headerSize-2] -eq 13 -and $header[$headerSize-1] -eq 10) { $headerDone=$true }
    }
  }
  if (!$headerDone) { throw 'Incomplete HTTP headers' }
  [Console]::Out.WriteLine((@{phase='http_complete';headers=[Text.Encoding]::ASCII.GetString($header,0,$headerSize);received_bytes=$total} | ConvertTo-Json -Compress))
} catch {
  [Console]::Error.WriteLine($_.Exception.ToString())
  exit 1
} finally {
  if ($null -ne $tls) { $tls.Dispose() }
  $client.Dispose()
  $control.Dispose()
}
"#;

impl Router {
    /// Uses the hostname already selected by `probe-active`; no configuration is changed.
    pub(super) fn probe_ipv6_windows(&self) -> Result<(), Box<dyn Error>> {
        let plan = self.acceptance_plan()?;
        let hostname: DomainName = plan["hostname"]
            .as_str()
            .ok_or("missing probe hostname")?
            .parse()?;
        let url = reqwest::Url::parse(plan["url"].as_str().ok_or("missing probe URL")?)?;
        if url.scheme() != "https"
            || url.host_str() != Some(hostname.as_str())
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some_and(|port| port != 443)
        {
            return Err("invalid IPv6 acceptance URL".into());
        }
        let options: Value = serde_json::from_slice(&self.capture(
            "ipv6-probe-options",
            "ubus -S call uci get '{\"config\":\"tunnel-detour\"}'\n",
        )?)?;
        if options["values"]["globals"]["ipv6_enabled"] != "1" {
            return Err(
                "enable the separately authorized IPv6 exception mode before this probe".into(),
            );
        }
        let selected = options["values"]
            .as_object()
            .ok_or("missing applied rules")?
            .values()
            .filter(|rule| rule[".type"] == "exception" && rule["enabled"] != "0")
            .filter_map(|rule| rule["pattern"].as_str())
            .map(str::parse::<DomainPattern>)
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|pattern| pattern.matches(&hostname));
        if !selected {
            return Err("the IPv6 probe hostname is not currently excepted".into());
        }
        let applied: Value = serde_json::from_slice(&self.capture(
            "ipv6-probe-readiness",
            "ubus -S call tunnel-detour status '{}'\n",
        )?)?;
        if applied["running"] != true
            || applied["status"]["phase"] != "ready"
            || applied["status"]["ipv6_wan_source"]
                .as_str()
                .and_then(|source| source.parse::<Ipv6Addr>().ok())
                .is_none()
        {
            return Err(
                "wait for the applied IPv6 configuration to become ready before probing".into(),
            );
        }
        let mut answers = Vec::new();
        for kind in ["A", "AAAA", "HTTPS"] {
            let result = Command::new("dig")
                .args([
                    &format!("@{}", self.host),
                    hostname.as_str(),
                    kind,
                    "+short",
                    "+tries=1",
                    "+time=5",
                ])
                .output()?;
            self.record(&format!("ipv6-dns-{kind}.stdout"), &result.stdout)?;
            self.record(&format!("ipv6-dns-{kind}.stderr"), &result.stderr)?;
            if !result.status.success() {
                return Err("IPv6 acceptance DNS failed".into());
            }
            answers.push(String::from_utf8(result.stdout)?);
        }
        let a: Vec<Ipv4Addr> = answers[0]
            .lines()
            .filter_map(|line| line.parse().ok())
            .collect();
        let aaaa: Vec<Ipv6Addr> = answers[1]
            .lines()
            .filter_map(|line| line.parse().ok())
            .collect();
        let ([ipv4], [ipv6]) = (a.as_slice(), aaaa.as_slice()) else {
            return Err(
                "the selected hostname needs exactly one synthetic address in each family".into(),
            );
        };
        if ipv4.octets()[0] != 198
            || !matches!(ipv4.octets()[1], 18 | 19)
            || u128::from(*ipv6)
                != (u128::from("2001:2::".parse::<Ipv6Addr>()?) | u128::from(u32::from(*ipv4)))
        {
            return Err("DNS did not preserve the paired synthetic identity".into());
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        // Request targets are literal HTTP bytes, never PowerShell expressions.
        if target
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'`' | b'$'))
        {
            return Err("unsupported acceptance request target".into());
        }
        let script = CLIENT
            .replace("@ADDRESS@", &ipv6.to_string())
            .replace("@HOST@", hostname.as_str())
            .replace("@PORT@", &listener.local_addr()?.port().to_string())
            .replace("@TARGET@", &target);
        let stderr_path = self
            .directory
            .join(format!("ipv6-windows-{}.stderr", std::process::id()));
        super::write_private(&stderr_path, b"")?;
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(File::options().write(true).open(&stderr_path)?))
            .spawn()?;
        let result = (|| -> Result<(u16, bool), Box<dyn Error>> {
            let mut reader =
                BufReader::new(child.stdout.take().ok_or("missing IPv6 client output")?);
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err("the Windows IPv6 client ended before TLS readiness; see its private error record".into());
            }
            let ready: Value = serde_json::from_str(line.trim_start_matches('\u{feff}'))?;
            self.record("ipv6-client-ready.json", line.as_bytes())?;
            let client: SocketAddr = ready["local"]
                .as_str()
                .ok_or("missing IPv6 client identity")?
                .parse()?;
            let remote: SocketAddr = ready["remote"]
                .as_str()
                .ok_or("missing synthetic peer")?
                .parse()?;
            if ready["phase"] != "tls_ready"
                || !client.is_ipv6()
                || remote != SocketAddr::new((*ipv6).into(), 443)
            {
                return Err(
                    "the client did not prove an authenticated IPv6 synthetic connection".into(),
                );
            }
            let state: Value = serde_json::from_slice(&self.capture(
                "ipv6-live-status",
                "ubus -S call tunnel-detour status '{}'\n",
            )?)?;
            let connection = state["status"]["connections"]
                .as_object()
                .ok_or("missing active connections")?
                .values()
                .find(|connection| {
                    connection["domain"].as_str() == Some(hostname.as_str())
                        && connection["client"]
                            .as_str()
                            .and_then(|value| value.parse::<SocketAddr>().ok())
                            == Some(client)
                })
                .ok_or("the IPv6 client is absent from actual relay state")?;
            let destination: SocketAddr = connection["destination"]
                .as_str()
                .ok_or("missing WAN destination")?
                .parse()?;
            let pid = state["status"]["process_id"]
                .as_u64()
                .filter(|pid| *pid <= u64::from(u32::MAX))
                .ok_or("invalid service process")?;
            self.capture(
                "ipv6-live-sockets",
                &format!("netstat -ntp | awk '$7 ~ /^{pid}\\// {{ print }}'\n"),
            )?;
            self.record(
                "ipv6-observed-connection.json",
                &serde_json::to_vec(connection)?,
            )?;
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut channel = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            channel.set_write_timeout(Some(Duration::from_secs(2)))?;
            channel.write_all(&[1])?;
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err("the Windows IPv6 client ended before HTTP completion; see its private error record".into());
            }
            let completed: Value = serde_json::from_str(&line)?;
            self.record("ipv6-client-http.json", line.as_bytes())?;
            if completed["phase"] != "http_complete" {
                return Err("IPv6 HTTP transfer did not complete".into());
            }
            let code = completed["headers"]
                .as_str()
                .and_then(|headers| headers.lines().next())
                .and_then(|line| line.split_whitespace().nth(1))
                .ok_or("missing IPv6 HTTP status")?
                .parse::<u16>()?;
            if !(200..400).contains(&code) {
                return Err("the verified IPv6 origin returned an unsuccessful HTTP status; see private records".into());
            }
            Ok((code, destination.is_ipv6()))
        })();
        if result.is_err() && child.try_wait()?.is_none() {
            child.kill()?;
        }
        let exit = child.wait()?;
        let (code, backend_ipv6) = result?;
        if !exit.success() {
            return Err("the Windows IPv6 client failed; see private records".into());
        }
        println!(
            "{}",
            json!({"client_ipv6":true,"paired_dns_identity":true,"verified_origin_tls":true,"http_status":code,"backend_ipv6":backend_ipv6,"https_metadata_present":!answers[2].trim().is_empty()})
        );
        Ok(())
    }
}
