//! Isolated OpenWrt kernel laboratory. Docker contains QEMU and SSH; no guest traffic
//! can reach the host network. The management network exists only inside that container.

use std::{
    error::Error,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tempfile::TempDir;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const DRIVER: &str = "tunnel-detour-openwrt-vm-driver:local";
const KERNEL: &str = "https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/openwrt-25.12.6-x86-64-generic-kernel.bin";
const KERNEL_SHA256: &str = "8f70595f3a6eec3112e007450a1a600153904deffa52ab368712342583cb387c";

fn checked(mut command: Command) -> Result<Vec<u8>> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "VM laboratory command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn docker(args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command.args(args);
    command
}

struct OwnedContainer(String);
impl Drop for OwnedContainer {
    fn drop(&mut self) {
        match docker(&["rm", "--force", &self.0]).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "VM build-container cleanup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!("VM build-container cleanup failed: {error}"),
        }
    }
}

pub const DHCPV6_WAN_IMAGE: &str = "tunnel-detour-openwrt-dhcpv6-wan-lab:local";

/// Build the disposable guest disk from the same native fixture as Docker acceptance.
/// The downloaded kernel is pinned independently; no production configuration is an input.
pub fn prepare(
    root: &Path,
    target: &Path,
    binary: &Path,
    fixture: &Path,
    wan_dhcpv6: bool,
) -> Result<(PathBuf, PathBuf)> {
    let fixture_image = if wan_dhcpv6 {
        DHCPV6_WAN_IMAGE
    } else {
        "tunnel-detour-openwrt-dnsmasq-lab:local"
    };
    checked(docker(&[
        "build",
        "--tag",
        DRIVER,
        "--file",
        "sources/tests/vm/Dockerfile",
        root.to_str().ok_or("invalid repository path")?,
    ]))?;
    let directory = target.join("openwrt-vm");
    fs::create_dir_all(&directory)?;
    let kernel = directory.join("kernel.bin");
    let download_needed = !kernel.exists();
    let candidate = if download_needed {
        directory.join("kernel.part")
    } else {
        kernel.clone()
    };
    if download_needed {
        let mut download = Command::new("curl");
        download
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "10",
                "--max-time",
                "180",
                "--output",
            ])
            .arg(&candidate)
            .arg(KERNEL);
        checked(download)?;
    }
    let mut digest = Command::new("sha256sum");
    digest.arg(&candidate);
    if std::str::from_utf8(&checked(digest)?)?
        .split_whitespace()
        .next()
        != Some(KERNEL_SHA256)
    {
        return Err("OpenWrt VM kernel failed the pinned SHA-256 check".into());
    }
    if download_needed {
        fs::rename(candidate, &kernel)?;
    }
    let mut executable_digest = Command::new("sha256sum");
    executable_digest.args([binary, fixture]);
    let inputs = format!(
        "guest-v2:{}:{}",
        String::from_utf8(checked(docker(&[
            "image",
            "inspect",
            fixture_image,
            "--format",
            "{{.Id}}"
        ]))?)?,
        String::from_utf8(checked(executable_digest)?)?
    );
    let marker = directory.join(if wan_dhcpv6 {
        "inputs-dhcpv6-wan"
    } else {
        "inputs"
    });
    let image = directory.join(if wan_dhcpv6 {
        "root-dhcpv6-wan.ext4"
    } else {
        "root.ext4"
    });
    if image.is_file() && fs::read_to_string(&marker).is_ok_and(|value| value == inputs) {
        return Ok((kernel, image));
    }
    let temporary = tempfile::tempdir()?;
    let export_name = format!("tunnel-detour-vm-export-{}", std::process::id());
    checked(docker(&[
        "create",
        "--name",
        &export_name,
        "--network",
        "none",
        fixture_image,
    ]))?;
    let export = OwnedContainer(export_name);
    let archive = temporary.path().join("root.tar");
    checked(docker(&[
        "export",
        "--output",
        archive.to_str().ok_or("invalid archive path")?,
        &export.0,
    ]))?;
    let builder_name = format!("tunnel-detour-vm-build-{}", std::process::id());
    checked(docker(&[
        "run",
        "--detach",
        "--name",
        &builder_name,
        "--network",
        "none",
        "--mount",
        &format!("type=bind,src={},dst=/outputs", directory.display()),
        DRIVER,
        "sleep",
        "infinity",
    ]))?;
    let builder = OwnedContainer(builder_name);
    checked(docker(&["exec", &builder.0, "mkdir", "-p", "/tmp/rootfs"]))?;
    checked(docker(&[
        "cp",
        archive.to_str().ok_or("invalid archive")?,
        &format!("{}:/tmp/root.tar", builder.0),
    ]))?;
    checked(docker(&[
        "exec",
        &builder.0,
        "tar",
        "--extract",
        "--file",
        "/tmp/root.tar",
        "--directory",
        "/tmp/rootfs",
        "--numeric-owner",
    ]))?;
    for (source, destination) in [
        (binary, "/tmp/rootfs/usr/bin/tunnel-detour"),
        (
            fixture,
            "/tmp/rootfs/usr/libexec/tunnel-detour-test-fixture",
        ),
    ] {
        checked(docker(&[
            "cp",
            source.to_str().ok_or("invalid executable")?,
            &format!("{}:{destination}", builder.0),
        ]))?;
    }
    // The VM has no external network. Disable time synchronization rather than retaining
    // an unused background client; synthetic DNS is served by the existing local fixture.
    // Docker export retains its container marker. Remove it so procd mounts the real
    // proc/dev filesystems and initializes kernel modules during an ordinary guest boot.
    checked(docker(&[
        "exec",
        &builder.0,
        "rm",
        "-f",
        "/tmp/rootfs/etc/rc.d/S98sysntpd",
        "/tmp/rootfs/.dockerenv",
    ]))?;
    checked(docker(&[
        "exec",
        &builder.0,
        "mke2fs",
        "-q",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-F",
        "-m",
        "0",
        "-d",
        "/tmp/rootfs",
        "/outputs/root.part",
        "131072",
    ]))?;
    checked(docker(&[
        "exec",
        &builder.0,
        "chmod",
        "644",
        "/outputs/root.part",
    ]))?;
    fs::rename(directory.join("root.part"), &image)?;
    fs::write(marker, inputs)?;
    Ok((kernel, image))
}

/// Per-guest credentials and disk live outside the repository and disappear after cleanup.
pub struct VmTransport {
    directory: TempDir,
    name: String,
    created: bool,
}

impl VmTransport {
    /// Prepare a fresh SSH identity and guest disk, then start an isolated emulator.
    pub fn start(name: String) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("tunnel-detour-vm-")
            .tempdir()?;
        let key = directory.path().join("identity");
        let mut generate = Command::new("ssh-keygen");
        generate
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "tunnel-detour-lab",
                "-f",
            ])
            .arg(&key);
        checked(generate)?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        let source = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_VM_IMAGE").ok_or("VM image was not prepared")?,
        );
        let kernel = PathBuf::from(
            std::env::var_os("TUNNEL_DETOUR_VM_KERNEL").ok_or("VM kernel was not prepared")?,
        );
        fs::copy(source, directory.path().join("root.ext4"))?;
        let mut guest = Self {
            directory,
            name,
            created: false,
        };
        let mount = format!(
            "type=bind,src={},dst=/lab",
            guest.directory.path().display()
        );
        checked(docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            &mount,
            DRIVER,
            "debugfs",
            "-w",
            "-R",
            "rm /etc/dropbear/authorized_keys",
            "/lab/root.ext4",
        ]))?;
        // This short-lived editor only modifies the disposable disk; no host mounts or routes.
        checked(docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            &mount,
            DRIVER,
            "debugfs",
            "-w",
            "-R",
            "write /lab/identity.pub /etc/dropbear/authorized_keys",
            "/lab/root.ext4",
        ]))?;
        checked(docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            &mount,
            DRIVER,
            "debugfs",
            "-w",
            "-R",
            "set_inode_field /etc/dropbear/authorized_keys mode 0100600",
            "/lab/root.ext4",
        ]))?;
        let installed = checked(docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            &mount,
            DRIVER,
            "debugfs",
            "-R",
            "cat /etc/dropbear/authorized_keys",
            "/lab/root.ext4",
        ]))?;
        if installed != fs::read(guest.directory.path().join("identity.pub"))? {
            return Err("VM SSH identity was not installed in the disposable disk".into());
        }
        let mut create = docker(&[
            "create",
            "--rm",
            "--name",
            &guest.name,
            "--label",
            "tunnel-detour.task=local-validation",
            "--network",
            "none",
            "--dns",
            "127.0.0.1",
            "--mount",
            &mount,
            "--mount",
            &format!("type=bind,src={},dst=/kernel,readonly", kernel.display()),
            DRIVER,
        ]);
        create.args(Self::emulator());
        checked(create)?;
        guest.created = true;
        checked(docker(&["start", &guest.name]))?;
        Ok(guest)
    }

    fn emulator() -> Vec<String> {
        let mut args = [
            "qemu-system-x86_64",
            "-machine",
            "q35",
            "-accel",
            "tcg",
            "-m",
            "512",
            "-smp",
            "2",
            "-object",
            "rng-random,id=entropy,filename=/dev/urandom",
            "-device",
            "virtio-rng-pci,rng=entropy",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-kernel",
            "/kernel",
            "-append",
            "root=/dev/vda rootwait rw console=ttyS0,115200 init=/sbin/init",
            "-drive",
            "file=/lab/root.ext4,if=virtio,format=raw,snapshot=on",
        ]
        .map(str::to_owned)
        .to_vec();
        args.extend(["-serial", "file:/lab/serial-0.log", "-netdev",
            "user,id=management,restrict=on,ipv6=off,net=10.203.0.0/24,host=10.203.0.1,dns=10.203.0.3,hostfwd=tcp:127.0.0.1:10022-10.203.0.2:22",
            "-device", "virtio-net-pci,netdev=management,mac=02:00:00:00:00:01"].map(str::to_owned));
        args
    }

    /// Docker arguments for a bounded guest command. Every argument is quoted for the
    /// remote shell, and no production credentials or SSH trust settings are consulted.
    pub fn arguments(&self, args: &[&str]) -> Result<Vec<String>> {
        if args.is_empty() || args.iter().any(|value| value.contains('\0')) {
            return Err("invalid VM command".into());
        }
        let remote = args
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let value = if index == 0 && *value == "ip" {
                    "/sbin/ip"
                } else {
                    value
                };
                format!("'{}'", value.replace('\'', "'\"'\"'"))
            })
            .collect::<Vec<_>>()
            .join(" ");
        Ok([
            "exec",
            "-i",
            &self.name,
            "timeout",
            "--kill-after=2",
            "180",
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-p",
            "10022",
            "-i",
            "/lab/identity",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ServerAliveInterval=2",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "LogLevel=ERROR",
            "root@127.0.0.1",
            &remote,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect())
    }

    /// Read bounded boot diagnostics only after a failed guest readiness check.
    pub fn diagnostics(&self) -> Result<String> {
        let mut value = String::new();
        let mut file = fs::File::open(self.directory.path().join("serial-0.log"))?;
        file.seek(SeekFrom::Start(
            file.metadata()?.len().saturating_sub(16384),
        ))?;
        file.take(16384).read_to_string(&mut value)?;
        Ok(value)
    }

    /// Construct the same owned command transport for supervised background fixtures.
    pub fn command(&self, args: &[&str]) -> Result<Command> {
        let mut command = docker(&[]);
        command
            .args(self.arguments(args)?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        Ok(command)
    }

    /// Stop the owned emulator before awaiting SSH children or deleting its private disk.
    pub fn stop(&mut self) -> Result<()> {
        if self.created {
            checked(docker(&["stop", "--time", "3", &self.name]))?;
            self.created = false;
        }
        Ok(())
    }
}

impl Drop for VmTransport {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("VM cleanup failed: {error}");
        }
    }
}
