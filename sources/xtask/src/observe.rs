//! Bounded, loopback-only observation of the synthetic external-path laboratory.

use serde_json::{Value, json};
use std::{
    error::Error,
    fs::{DirBuilder, File, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_BYTES: u64 = 512 * 1024;
const MAX_EVENTS: usize = 64;
const SLOTS: usize = 32;

fn millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("observation output has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.persist(path)?;
    Ok(())
}

fn sample(argv: &[String]) -> Result<Value> {
    let (program, args) = argv.split_first().ok_or("missing snapshot command")?;
    // The controlled fixture itself bounds every command and its complete JSON.
    // This outer deadline and read bound also protect against a broken fixture.
    let mut child = Command::new("timeout")
        .args(["--kill-after=1", "12", program])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("snapshot stdout missing")?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_BYTES {
        child.kill()?;
        child.wait()?;
        return Err("snapshot output exceeded its bound or could not be read".into());
    }
    let status = child.wait()?;
    read?;
    if !status.success() {
        return Err(format!("snapshot command failed: {status}").into());
    }
    let text = String::from_utf8(bytes)?;
    let payload = text
        .lines()
        .find_map(|line| line.split_once("TD_SNAPSHOT=").map(|(_, value)| value))
        .ok_or("snapshot marker missing")?;
    Ok(serde_json::from_str(payload)?)
}

struct Event {
    phase: String,
    time_ms: u64,
    terminal: bool,
    ack: Option<mpsc::SyncSender<()>>,
}

/// Owns the sampler and HTTP viewer. Its input is a controlled synthetic fixture,
/// never an arbitrary router command or a production configuration capture.
pub struct Observer {
    directory: PathBuf,
    events: mpsc::SyncSender<Event>,
    sampler: Option<JoinHandle<std::result::Result<(), String>>>,
    server: Option<JoinHandle<std::result::Result<(), String>>>,
    stopped: Arc<AtomicBool>,
}

impl Observer {
    /// Private artifact directory for acceptance checks on captured observations.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Create a fresh private artifact directory and a read-only loopback viewer.
    /// The snapshot argv must be bounded and produce the controlled marker above.
    pub fn start(directory: &Path, argv: Vec<String>, context: Value) -> Result<Self> {
        if !directory.is_absolute() {
            return Err("observation directory must be absolute and new".into());
        }
        DirBuilder::new().mode(0o700).create(directory)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let url = format!("http://{address}/");
        atomic(
            &directory.join("session.json"),
            &serde_json::to_vec(&json!({
                "schema":1,"environment":"synthetic-external-lab","url":url,"context":context,
                "interval_ms":2000,"atomic_snapshot":false,"rolling_slots":SLOTS,"max_events":MAX_EVENTS,
                "max_sample_bytes":MAX_BYTES
            }))?,
        )?;
        let (events, receiver) = mpsc::sync_channel::<Event>(MAX_EVENTS);
        let stopped = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stopped);
        let server_directory = directory.to_path_buf();
        let server = thread::spawn(move || {
            serve(listener, &server_directory, &server_stop, None).map_err(|e| e.to_string())
        });
        let sampler_directory = directory.to_path_buf();
        let sampler = thread::spawn(move || {
            record(&sampler_directory, &argv, receiver).map_err(|e| e.to_string())
        });
        println!("Laboratory observation: {url}");
        println!("Artifacts: {}", directory.display());
        Ok(Self {
            directory: directory.to_path_buf(),
            events,
            sampler: Some(sampler),
            server: Some(server),
            stopped,
        })
    }

    /// Record an explicit scenario boundary. Overflow fails visibly instead of
    /// silently omitting events from an apparently complete timeline.
    pub fn phase(&self, phase: &str) -> Result<()> {
        if phase.is_empty() || phase.len() > 160 || phase.contains(['\n', '\r']) {
            return Err("invalid observation phase".into());
        }
        let (ack, completed) = mpsc::sync_channel(1);
        self.events.try_send(Event {
            phase: phase.into(),
            time_ms: millis()?,
            terminal: false,
            ack: Some(ack),
        })?;
        completed.recv_timeout(Duration::from_secs(16))?;
        Ok(())
    }

    /// Keep the healthy fixture available, with a finite lifetime. `release`
    /// ends the hold; it does not skip the remaining owning-test assertions.
    pub fn hold(&self, seconds: u64) -> Result<()> {
        if seconds > 900 {
            return Err("laboratory hold exceeds 900 seconds".into());
        }
        self.phase("interactive-ready")?;
        let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
        while std::time::Instant::now() < deadline && !self.directory.join("release").exists() {
            thread::sleep(Duration::from_millis(200));
        }
        self.phase("interactive-finished")
    }

    fn close(&mut self, phase: &str) -> Result<()> {
        let event_result = self.events.send(Event {
            phase: phase.into(),
            time_ms: millis()?,
            terminal: true,
            ack: None,
        });
        let sampled = self.sampler.take().map(|thread| thread.join());
        self.stopped.store(true, Ordering::Release);
        let served = self.server.take().map(|thread| thread.join());
        event_result?;
        for result in [sampled, served].into_iter().flatten() {
            result
                .map_err(|_| "observation worker panicked")?
                .map_err(|error| format!("observation failed: {error}"))?;
        }
        Ok(())
    }

    /// Capture terminal state and join both workers before the laboratory is removed.
    pub fn finish(mut self, passed: bool) -> Result<()> {
        self.close(if passed { "passed" } else { "failed" })
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if self.sampler.is_some()
            && let Err(error) = self.close("aborted")
        {
            eprintln!("laboratory observation cleanup: {error}");
        }
    }
}

fn record(directory: &Path, argv: &[String], receiver: mpsc::Receiver<Event>) -> Result<()> {
    let mut timeline = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("events.jsonl"))?;
    let mut events = Vec::new();
    let mut phase = "starting".to_string();
    let mut sequence = 0usize;
    loop {
        let event = match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(event) => Some(event),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("observation owner disconnected".into());
            }
        };
        let checkpoint = event.is_some();
        let terminal = event.as_ref().is_some_and(|event| event.terminal);
        let mut ack = None;
        if let Some(event) = event {
            if events.len() >= MAX_EVENTS {
                return Err("observation event capacity exhausted".into());
            }
            phase = event.phase;
            ack = event.ack;
            let value = json!({"phase":phase,"time_ms":event.time_ms});
            writeln!(timeline, "{value}")?;
            timeline.flush()?;
            events.push(value);
        }
        let started = millis()?;
        let observation = match sample(argv) {
            Ok(value) => json!({"ok":true,"data":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        let state = json!({"schema":1,"environment":"synthetic-external-lab","sequence":sequence,
            "phase":phase,"terminal":terminal,"started_ms":started,"finished_ms":millis()?,
            "atomic_snapshot":false,"events":events,"observation":observation});
        let bytes = serde_json::to_vec(&state)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("recorded observation exceeds its size bound".into());
        }
        atomic(
            &directory.join(format!("sample-{:02}.json", sequence % SLOTS)),
            &bytes,
        )?;
        if checkpoint {
            atomic(
                &directory.join(format!("event-{:02}.json", events.len())),
                &bytes,
            )?;
        }
        atomic(&directory.join("state.json"), &bytes)?;
        if let Some(ack) = ack {
            ack.send(())?;
        }
        sequence = sequence
            .checked_add(1)
            .ok_or("observation sequence overflow")?;
        if terminal {
            return Ok(());
        }
    }
}

fn response(mut stream: TcpStream, directory: &Path, port: u16) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut bytes = [0u8; 4096];
    let count = stream.read(&mut bytes)?;
    let request = std::str::from_utf8(&bytes[..count])?;
    let lines = request.lines().collect::<Vec<_>>();
    let first = lines.first().copied().unwrap_or("");
    let host = format!("127.0.0.1:{port}");
    let authorized = lines.iter().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, value)| name.eq_ignore_ascii_case("host") && value.trim() == host)
    });
    let (status, kind, body) = if !authorized {
        (
            "403 Forbidden",
            "text/plain",
            b"Loopback host required\n".to_vec(),
        )
    } else if first == "GET / HTTP/1.1" {
        (
            "200 OK",
            "text/html; charset=utf-8",
            include_bytes!("observe.html").to_vec(),
        )
    } else if let Some(name) = first
        .strip_prefix("GET /")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .filter(|name| {
            matches!(*name, "state.json" | "session.json")
                || name
                    .strip_prefix("event-")
                    .and_then(|s| s.strip_suffix(".json"))
                    .is_some_and(|n| {
                        n.len() == 2
                            && n.bytes().all(|b| b.is_ascii_digit())
                            && n.parse::<usize>()
                                .is_ok_and(|n| (1..=MAX_EVENTS).contains(&n))
                    })
        })
    {
        match File::open(directory.join(name)) {
            Ok(file) => {
                let mut data = Vec::new();
                file.take(MAX_BYTES + 1).read_to_end(&mut data)?;
                if data.len() as u64 > MAX_BYTES {
                    return Err("viewer state exceeds its size bound".into());
                }
                ("200 OK", "application/json", data)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
                if name == "state.json" {
                    "503 Service Unavailable"
                } else {
                    "404 Not Found"
                },
                "application/json",
                b"{\"phase\":\"unavailable\"}".to_vec(),
            ),
            Err(error) => return Err(error.into()),
        }
    } else {
        (
            "404 Not Found",
            "text/plain",
            b"Read-only viewer\n".to_vec(),
        )
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

fn serve(
    listener: TcpListener,
    directory: &Path,
    stop: &AtomicBool,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    let port = listener.local_addr()?.port();
    while !stop.load(Ordering::Acquire)
        && deadline.is_none_or(|deadline| std::time::Instant::now() < deadline)
    {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = response(stream, directory, port) {
                    eprintln!("observation viewer request: {error}");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Release only an identified observation session. The owner still performs cleanup.
pub fn release(directory: &Path) -> Result<()> {
    session(directory)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("release"))?;
    Ok(())
}

fn session(directory: &Path) -> Result<Value> {
    let path = directory.join("session.json");
    if !directory.symlink_metadata()?.is_dir() || !path.symlink_metadata()?.is_file() {
        return Err("observation session must be a regular file in a real directory".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("observation session exceeds its size bound".into());
    }
    let session: Value = serde_json::from_slice(&bytes)?;
    if session["environment"] != "synthetic-external-lab" || session["schema"] != 1 {
        return Err("not a synthetic laboratory observation session".into());
    }
    Ok(session)
}

/// Serve retained synthetic observations without starting a network laboratory.
pub fn view(directory: &Path, seconds: u64) -> Result<()> {
    session(directory)?;
    if seconds == 0 || seconds > 900 {
        return Err("viewer duration must be 1–900 seconds".into());
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    println!(
        "Retained laboratory observation: http://{}/",
        listener.local_addr()?
    );
    serve(
        listener,
        directory,
        &AtomicBool::new(false),
        Some(std::time::Instant::now() + Duration::from_secs(seconds)),
    )
}
