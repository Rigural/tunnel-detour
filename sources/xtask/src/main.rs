use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

mod package;
mod router;

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let cargo = env::var_os("CARGO").ok_or("Cargo did not provide its executable path")?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let mut command = Command::new(&cargo);
    command.current_dir(&root);
    match arguments.as_slice() {
        [
            task,
            host_option,
            host,
            access_option,
            access,
            run_option,
            directory,
            phase,
            target,
        ] if task == "test-router"
            && host_option == "--host"
            && access_option == "--access"
            && run_option == "--run"
            && phase == "configure-disabled" =>
        {
            return router::configure(
                host.to_str().ok_or("SSH host must be UTF-8")?,
                Path::new(access),
                Path::new(directory),
                target.to_str().ok_or("test target must be UTF-8")?,
            );
        }
        [task, host_option, host, access_option, access, phase]
            if task == "test-router" && host_option == "--host" && access_option == "--access" =>
        {
            return router::run(
                host.to_str().ok_or("SSH host must be UTF-8")?,
                Path::new(access),
                None,
                phase.to_str().ok_or("router phase must be UTF-8")?,
            );
        }
        [
            task,
            host_option,
            host,
            access_option,
            access,
            run_option,
            directory,
            phase,
        ] if task == "test-router"
            && host_option == "--host"
            && access_option == "--access"
            && run_option == "--run" =>
        {
            return router::run(
                host.to_str().ok_or("SSH host must be UTF-8")?,
                Path::new(access),
                Some(Path::new(directory)),
                phase.to_str().ok_or("router phase must be UTF-8")?,
            );
        }
        [task] if task == "build" => {
            command.args(["build", "--workspace", "--locked"]);
        }
        [task] if task == "test" => {
            command.args(["test", "--workspace", "--locked"]);
        }
        [task, option, sdk] if task == "package" && option == "--sdk" => {
            return package::build(&root, &cargo, Path::new(sdk));
        }
        [task] if task == "test-network" => return network_tests(command, &root, None),
        [task] if task == "test-openwrt" => return openwrt_tests(&cargo, &root, None),
        [task, filter] if task == "test-openwrt" => {
            return openwrt_tests(&cargo, &root, Some(filter));
        }
        [task, filter] if task == "test-network" => {
            return network_tests(command, &root, Some(filter));
        }
        [] => {
            println!(concat!(
                "cargo xtask build         Build the workspace\n",
                "cargo xtask test          Run local tests\n",
                "cargo xtask test-network  Run isolated Linux network acceptance tests in Docker\n",
                "cargo xtask test-openwrt  Run native OpenWrt management acceptance in Docker ",
                "(requires the x86_64-unknown-linux-musl Rust target and host curl/OpenSSL)\n",
                "cargo xtask package --sdk <directory>  Build ARM64 APKs with the OpenWrt 25.12.6 ",
                "mediatek/filogic SDK (requires Docker, Rust 1.96 and its aarch64-unknown-linux-musl ",
                "target); output: target/packages/mediatek-filogic\n",
                "cargo xtask test-router --host <host> --access <private-env> ",
                "[--run <private-directory>] <phase> [target-url]\n",
                "  Authorized hardware phase only. Requires OpenSSH and host dig/curl/sha256sum; ",
                "private records and backups stay outside the repository. ",
                "No WAN, WireGuard or global firewall restart.\n",
                "  Inspection phases: inspect, details, adguard, preflight, verify-disabled, ",
                "windows-dns, inspect-test, audit-test.\n",
                "  install-disabled installs only the two local APKs, offline, ",
                "with dependencies already present.\n",
                "  verify-disabled also requires TUNNEL_DETOUR_PACKAGE_SDK ",
                "for exact APK payload inspection.\n",
                "  configure-disabled <https-url> prepares own settings and a private test plan; ",
                "--run is required.\n",
                "  start-test activates one exact-hostname rule; probe-test checks DNS and HTTPS ",
                "with the origin certificate; stop-test disables the package and removes the temporary rule.\n",
                "  finish-active retains the successful rule and boot startup when explicitly requested.\n",
                "  clean-router removes only private UCI staging and this run's uploaded APK copies; ",
                "it preserves the running configuration.\n",
                "  windows-dns additionally requires Windows PowerShell through WSL."
            ));
            return Ok(());
        }
        _ => {
            return Err(
                "expected build, test, test-network, test-openwrt, package --sdk <directory>, or test-router (run without arguments for usage)"
                    .into(),
            );
        }
    }
    let status = command.status()?;
    if !status.success() {
        return Err(format!("task failed with {status}").into());
    }
    Ok(())
}

fn openwrt_tests(
    cargo: &std::ffi::OsStr,
    root: &Path,
    filter: Option<&std::ffi::OsStr>,
) -> Result<(), Box<dyn Error>> {
    checked(Command::new(cargo).current_dir(root).args([
        "build",
        "--package",
        "tunnel-detour-service",
        "--locked",
        "--target",
        "x86_64-unknown-linux-musl",
    ]))?;
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "test",
            "--package",
            "xtask",
            "--test",
            "openwrt",
            "--no-run",
            "--locked",
            "--message-format=json",
        ])
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err("OpenWrt test compilation failed".into());
    }
    let mut executable = None;
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let artifact: serde_json::Value = serde_json::from_slice(line)?;
        if artifact["reason"] == "compiler-artifact" && artifact["target"]["name"] == "openwrt" {
            executable = artifact["executable"].as_str().map(PathBuf::from);
        }
    }
    let executable = executable.ok_or("Cargo did not report the OpenWrt test executable")?;
    let metadata = Command::new(cargo)
        .current_dir(root)
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"])
        .output()?;
    if !metadata.status.success() {
        return Err("Cargo metadata failed".into());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let binary = Path::new(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing Cargo target directory")?,
    )
    .join("x86_64-unknown-linux-musl/debug/tunnel-detour");
    checked(Command::new("docker").current_dir(root).args([
        "build",
        "--tag",
        "tunnel-detour-openwrt-lab:local",
        "--file",
        "sources/tests/openwrt/Dockerfile",
        ".",
    ]))?;
    let mut command = Command::new(executable);
    command
        .current_dir(root)
        .args(["--ignored", "--test-threads=1", "--nocapture"])
        .env("TUNNEL_DETOUR_OPENWRT_LAB", "1")
        .env("TUNNEL_DETOUR_OPENWRT_BINARY", binary);
    if let Some(filter) = filter {
        command.arg(filter);
    }
    checked(&mut command)
}

fn checked(command: &mut Command) -> Result<(), Box<dyn Error>> {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("command failed with {status}").into());
    }
    Ok(())
}

fn network_tests(
    mut cargo: Command,
    root: &Path,
    filter: Option<&std::ffi::OsStr>,
) -> Result<(), Box<dyn Error>> {
    let output = cargo
        .args([
            "test",
            "-p",
            "tunnel-detour-service",
            "--test",
            "network",
            "--no-run",
            "--locked",
            "--message-format=json",
        ])
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err("network test compilation failed".into());
    }
    let mut executable: Option<PathBuf> = None;
    let mut service: Option<PathBuf> = None;
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let artifact: serde_json::Value = serde_json::from_slice(line)?;
        if artifact["reason"] != "compiler-artifact" {
            continue;
        }
        if let Some(path) = artifact["executable"].as_str() {
            if artifact["target"]["name"] == "network" && artifact["profile"]["test"] == true {
                executable = Some(path.into());
            }
            if artifact["target"]["name"] == "tunnel-detour" && artifact["profile"]["test"] == false
            {
                service = Some(path.into());
            }
        }
    }
    let executable = executable.ok_or("Cargo did not report the network test executable")?;
    let service = service.ok_or("Cargo did not report the service executable")?;
    checked(Command::new("docker").current_dir(root).args([
        "build",
        "-t",
        "tunnel-detour-lab:local",
        "sources/tests/lab",
    ]))?;
    let mut docker = Command::new("docker");
    docker
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "SYS_ADMIN",
            "--security-opt",
            "apparmor=unconfined",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--sysctl",
            "net.ipv4.conf.all.rp_filter=0",
            "--sysctl",
            "net.ipv4.conf.default.rp_filter=0",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=1",
            "--sysctl",
            "net.ipv6.conf.all.disable_ipv6=0",
            "--sysctl",
            "net.ipv6.conf.default.disable_ipv6=0",
        ])
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/opt/network-tests,readonly",
            executable.display()
        ))
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/opt/tunnel-detour,readonly",
            service.display()
        ))
        .args([
            "-e",
            "TUNNEL_DETOUR_NETWORK_LAB=1",
            "tunnel-detour-lab:local",
            "/opt/network-tests",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ]);
    if let Some(filter) = filter {
        docker.arg(filter);
    }
    checked(&mut docker)
}

fn main() -> ExitCode {
    if let Some(result) = router::askpass() {
        return result;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
