//! Bounded passive SYN-header capture for separately authorized router diagnostics.
//! No routes, addresses, interfaces, firewall rules or package state are changed.
#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    net::Ipv6Addr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Capture(Child);
impl Drop for Capture {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("capture cleanup signal: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("capture cleanup wait: {error}");
                }
            }
            Err(error) => eprintln!("capture cleanup inspection: {error}"),
        }
    }
}

/// Capture selected TCP handshake headers using a verified tcpdump binary.
/// The capture child is stopped and joined within the requested finite lifetime.
pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (pppoe, args) = match args {
        [option, device, rest @ ..] if option == "--pppoe" => (Some(device.as_str()), rest),
        _ => (None, args),
    };
    let [binary, libraries, address, port, seconds, output] = args else {
        return Err("usage: packet-observer [--pppoe <ethernet-device>] <tcpdump-path> <library-directory> <IPv6-target> <TCP-port> <1-90-seconds> <new-private-directory>".into());
    };
    let address: Ipv6Addr = address.parse()?;
    let port: std::num::NonZeroU16 = port.parse()?;
    let seconds: u64 = seconds.parse()?;
    if seconds == 0
        || seconds > 90
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_loopback()
        || !Path::new(binary).is_absolute()
        || !Path::new(libraries).is_absolute()
        || !Path::new(output).is_absolute()
        || pppoe.is_some_and(|device| {
            device.is_empty()
                || device.len() > 15
                || !device
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        })
    {
        return Err("invalid capture scope or lifetime".into());
    }
    fs::DirBuilder::new().mode(0o700).create(output)?;
    let directory = Path::new(output);
    let private = |name: &str| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))
    };
    // This diagnostic originates ordinary TCP SYNs without extension headers or
    // Fast Open data. Capture only these handshake headers, never application data.
    let mut command = Command::new(binary);
    command.env("LD_LIBRARY_PATH", libraries);
    let filter = if pppoe.is_some() {
        command.args(["-Q", "in", "-e"]);
        format!(
            "pppoes and ip6 and ip6[6] = 6 and tcp dst port {port} and dst host {address} and (ip6[53] & 18 = 2)"
        )
    } else {
        format!("ip6 and ip6[6] = 6 and tcp port {port} and host {address} and (ip6[53] & 2 != 0)")
    };
    let child = command
        .args([
            "-nn",
            "-p",
            "-q",
            "-tt",
            "-l",
            "-i",
            pppoe.unwrap_or("any"),
            "-s",
            "96",
            "-c",
            "128",
            &filter,
        ])
        .stdin(Stdio::null())
        .stdout(private("headers.txt")?)
        .stderr(private("capture.stderr")?)
        .spawn()?;
    let mut capture = Capture(child);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    let mut stopped = false;
    loop {
        if let Some(status) = capture.0.try_wait()? {
            if !status.success() {
                return Err(
                    format!("passive capture exited: {status}; inspect private stderr").into(),
                );
            }
            break;
        }
        if !ready {
            let stderr = fs::read_to_string(directory.join("capture.stderr"))?;
            if stderr.contains("listening on") {
                let mut marker = private("ready")?;
                use std::io::Write;
                marker.write_all(b"SYN headers only; no configuration changes\n")?;
                ready = true;
            } else if Instant::now() >= ready_deadline {
                return Err("passive capture did not become ready".into());
            }
        }
        if Instant::now() >= deadline
            || directory.join("stop").exists()
            || fs::metadata(directory.join("headers.txt"))?.len() > 128 * 1024
            || fs::metadata(directory.join("capture.stderr"))?.len() > 16 * 1024
        {
            capture.0.kill()?;
            capture.0.wait()?;
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        return Err("capture ended before readiness".into());
    }
    let mut marker = private("finished")?;
    use std::io::Write;
    writeln!(marker, "ready=true bounded_stop={stopped}")?;
    Ok(())
}
