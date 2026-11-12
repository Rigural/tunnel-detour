use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

mod benchmark;
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
            before_option,
            before,
            before_source_option,
            before_source,
            after_option,
            after,
            output_option,
            output,
        ] if task == "benchmark-policy"
            && before_option == "--before"
            && before_source_option == "--before-source"
            && after_option == "--after"
            && output_option == "--output" =>
        {
            return benchmark::policy::run(
                &cargo,
                &root,
                Path::new(output),
                Path::new(before),
                Path::new(after),
                Path::new(before_source),
            );
        }
        [task, resume, prior, option, output]
            if task == "benchmark-app" && resume == "--resume-matrix" && option == "--output" =>
        {
            return benchmark::application::resume_matrix(
                &cargo,
                &root,
                Path::new(prior),
                Path::new(output),
            );
        }
        [
            task,
            before_option,
            before,
            after_option,
            after,
            input_option,
            input,
            output_option,
            output,
        ] if task == "benchmark-api"
            && before_option == "--before"
            && after_option == "--after"
            && input_option == "--input"
            && output_option == "--output" =>
        {
            return benchmark::api::run(
                &cargo,
                &root,
                Path::new(output),
                Path::new(before),
                Path::new(after),
                Path::new(input),
            );
        }
        [
            task,
            mode,
            before_option,
            before,
            after_option,
            after,
            output_option,
            output,
        ] if task == "benchmark-relay"
            && (mode == "--compare-ten" || mode == "--compare-duplex32")
            && before_option == "--before"
            && after_option == "--after"
            && output_option == "--output" =>
        {
            return benchmark::transport_compare::run(
                &cargo,
                &root,
                Path::new(output),
                Path::new(before),
                Path::new(after),
                mode == "--compare-duplex32",
            );
        }
        [task, mode, option, output]
            if task == "benchmark-relay" && mode == "--audit-ten" && option == "--output" =>
        {
            return benchmark::transport_compare::audit(Path::new(output));
        }
        [task, mode, option, output]
            if task == "benchmark-app"
                && matches!(
                    mode.to_str(),
                    Some("--pilot" | "--churn-pilot" | "--matrix" | "--soak-pilot" | "--soak")
                )
                && option == "--output" =>
        {
            let mode = match mode.to_str() {
                Some("--pilot") => benchmark::application::Mode::Pilot,
                Some("--churn-pilot") => benchmark::application::Mode::ChurnPilot,
                Some("--matrix") => benchmark::application::Mode::Matrix,
                Some("--soak-pilot") => benchmark::application::Mode::SoakPilot,
                Some("--soak") => benchmark::application::Mode::Soak,
                _ => return Err("unsupported application benchmark mode".into()),
            };
            return benchmark::application::run(&cargo, &root, Path::new(output), mode, 20);
        }
        [task, mode, rate_option, rate, option, output]
            if task == "benchmark-app" && rate_option == "--http-qps" && option == "--output" =>
        {
            let mode = match mode.to_str() {
                Some("--pilot") => benchmark::application::Mode::Pilot,
                Some("--churn-pilot") => benchmark::application::Mode::ChurnPilot,
                Some("--matrix") => benchmark::application::Mode::Matrix,
                Some("--soak-pilot") => benchmark::application::Mode::SoakPilot,
                Some("--soak") => benchmark::application::Mode::Soak,
                _ => return Err("unsupported application benchmark mode".into()),
            };
            let rate = rate.to_str().ok_or("HTTP rate must be UTF-8")?.parse()?;
            return benchmark::application::run(&cargo, &root, Path::new(output), mode, rate);
        }
        [task, option, directory, duration_option, seconds]
            if task == "lab-external" && option == "--output" && duration_option == "--seconds" =>
        {
            let seconds: u64 = seconds.to_str().ok_or("duration must be UTF-8")?.parse()?;
            if seconds > 900 {
                return Err("laboratory duration must be between 0 and 900 seconds".into());
            }
            let directory = Path::new(directory);
            if !directory.is_absolute() || directory.exists() {
                return Err("use a new absolute observation directory".into());
            }
            return openwrt_tests_observed(
                &cargo,
                &root,
                Some(std::ffi::OsStr::new("r124")),
                false,
                Some((directory, seconds)),
            );
        }
        [task, option, directory, duration_option, seconds, profile]
            if task == "lab-external"
                && option == "--output"
                && duration_option == "--seconds"
                && matches!(
                    profile.to_str(),
                    Some("--kernel" | "--pppoe" | "--pppoe-dhcpv6" | "--dhcp")
                ) =>
        {
            let seconds: u64 = seconds.to_str().ok_or("duration must be UTF-8")?.parse()?;
            let directory = Path::new(directory);
            if seconds > 900 || !directory.is_absolute() || directory.exists() {
                return Err("use a new absolute directory and 0–900 seconds".into());
            }
            return openwrt_tests_observed(
                &cargo,
                &root,
                Some(std::ffi::OsStr::new(match profile.to_str() {
                    Some("--dhcp") => "r129",
                    Some("--pppoe-dhcpv6") => "r128",
                    Some("--pppoe") => "r127",
                    _ => "r124",
                })),
                true,
                Some((directory, seconds)),
            );
        }
        [task, directory] if task == "lab-release" => {
            return xtask::observe::release(Path::new(directory));
        }
        [task, directory, option, seconds] if task == "lab-view" && option == "--seconds" => {
            return xtask::observe::view(
                Path::new(directory),
                seconds.to_str().ok_or("duration must be UTF-8")?.parse()?,
            );
        }
        [task, mode, rest @ ..] if task == "benchmark-relay" && mode == "--resume-campaign" => {
            return benchmark::resume::run(&cargo, &root, rest);
        }
        [task, mode, profile, option, output]
            if task == "benchmark-relay"
                && (mode == "--integrated-pilot" || mode == "--integrated-matrix")
                && (profile == "--with-dns" || profile == "--with-dns-load")
                && option == "--output" =>
        {
            return benchmark::integrated::run(
                &cargo,
                &root,
                Path::new(output),
                mode == "--integrated-matrix",
                if profile == "--with-dns-load" {
                    benchmark::integrated::DnsProfile::Load
                } else {
                    benchmark::integrated::DnsProfile::Idle
                },
            );
        }
        [task, mode, option, output]
            if task == "benchmark-relay"
                && (mode == "--integrated-pilot" || mode == "--integrated-matrix")
                && option == "--output" =>
        {
            return benchmark::integrated::run(
                &cargo,
                &root,
                Path::new(output),
                mode == "--integrated-matrix",
                benchmark::integrated::DnsProfile::Disabled,
            );
        }
        [task, mode, option, output]
            if task == "benchmark-relay" && mode == "--churn-reference" && option == "--output" =>
        {
            return benchmark::churn_reference(&cargo, &root, Path::new(output));
        }
        [
            task,
            mode,
            load_option,
            load,
            count_option,
            count,
            output_option,
            output,
        ] if task == "benchmark-relay"
            && mode == "--pilot"
            && load_option == "--workload"
            && count_option == "--connections"
            && output_option == "--output" =>
        {
            return benchmark::pilot_case(
                &cargo,
                &root,
                Path::new(output),
                load.to_str().ok_or("workload must be UTF-8")?,
                count
                    .to_str()
                    .ok_or("connection count must be UTF-8")?
                    .parse()?,
            );
        }
        [task, mode, option, output]
            if task == "benchmark-relay"
                && mode == "--operational-pilot"
                && option == "--output" =>
        {
            return benchmark::operational(&cargo, &root, Path::new(output));
        }
        [task, mode, option, output]
            if task == "benchmark-relay" && mode == "--observer-pilot" && option == "--output" =>
        {
            return benchmark::observer_pilot(&cargo, &root, Path::new(output));
        }
        [task, mode, option, output]
            if task == "benchmark-relay"
                && mode == "--observer-campaign"
                && option == "--output" =>
        {
            return benchmark::observer_campaign(&cargo, &root, Path::new(output));
        }
        [task, mode, option, output]
            if task == "benchmark-relay"
                && mode == "--observer-analysis"
                && option == "--output" =>
        {
            return benchmark::observer_analysis::analyze(&cargo, &root, Path::new(output));
        }
        [task, mode, option, output]
            if task == "benchmark-relay" && mode == "--campaign" && option == "--output" =>
        {
            return benchmark::campaign(&cargo, &root, Path::new(output));
        }
        [task, mode, policy_option, policy, option, output]
            if task == "benchmark-relay"
                && mode == "--campaign"
                && policy_option == "--observation"
                && option == "--output" =>
        {
            return benchmark::campaign_with_observation(
                &cargo,
                &root,
                Path::new(output),
                policy.to_str().ok_or("observation must be UTF-8")?,
            );
        }
        [
            task,
            mode,
            worker_option,
            worker,
            image_option,
            image,
            policy_option,
            policy,
            output_option,
            output,
        ] if task == "benchmark-relay"
            && (mode == "--endpoint-reference" || mode == "--campaign")
            && worker_option == "--worker"
            && image_option == "--image"
            && policy_option == "--observation"
            && output_option == "--output" =>
        {
            let run = if mode == "--campaign" {
                benchmark::frozen_campaign
            } else {
                benchmark::frozen_endpoint_reference
            };
            return run(
                &cargo,
                &root,
                Path::new(output),
                Path::new(worker),
                image.to_str().ok_or("local image must be UTF-8")?,
                policy.to_str().ok_or("observation must be UTF-8")?,
            );
        }
        [
            task,
            mode,
            worker_option,
            worker,
            image_option,
            image,
            output_option,
            output,
        ] if task == "benchmark-relay"
            && (mode == "--endpoint-reference" || mode == "--campaign")
            && worker_option == "--worker"
            && image_option == "--image"
            && output_option == "--output" =>
        {
            let run = if mode == "--campaign" {
                benchmark::frozen_campaign
            } else {
                benchmark::frozen_endpoint_reference
            };
            return run(
                &cargo,
                &root,
                Path::new(output),
                Path::new(worker),
                image.to_str().ok_or("local image must be UTF-8")?,
                "full",
            );
        }
        [task, mode, option, output]
            if task == "benchmark-relay"
                && mode == "--endpoint-reference"
                && option == "--output" =>
        {
            return benchmark::endpoint_reference(&cargo, &root, Path::new(output));
        }
        [task, pilot, option, output]
            if task == "benchmark-relay" && pilot == "--matrix-pilot" && option == "--output" =>
        {
            return benchmark::matrix_pilot(&cargo, &root, Path::new(output));
        }
        [
            task,
            pilot,
            workload_option,
            workload,
            output_option,
            output,
        ] if task == "benchmark-relay"
            && pilot == "--pilot"
            && workload_option == "--workload"
            && output_option == "--output" =>
        {
            return benchmark::pilot_workload(
                &cargo,
                &root,
                Path::new(output),
                workload.to_str().ok_or("workload must be UTF-8")?,
            );
        }
        [task, pilot, option, output]
            if task == "benchmark-relay" && pilot == "--pilot" && option == "--output" =>
        {
            return benchmark::pilot(&cargo, &root, Path::new(output));
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
        [task, option, directory, tag_option, tag]
            if task == "package" && option == "--download-sdk" && tag_option == "--release-tag" =>
        {
            return package::download_and_build(
                &root,
                &cargo,
                Path::new(directory),
                tag.to_str().ok_or("release tag must be UTF-8")?,
            );
        }
        [task] if task == "test-network" => return network_tests(command, &root, None),
        [task] if task == "test-openwrt" => return openwrt_tests(&cargo, &root, None, false),
        [task] if task == "test-openwrt-flow" => {
            return openwrt_tests(&cargo, &root, Some(std::ffi::OsStr::new("r054")), true);
        }
        [task, filter] if task == "test-openwrt-flow" => {
            return openwrt_tests(&cargo, &root, Some(filter), true);
        }
        [task, filter] if task == "test-openwrt" => {
            return openwrt_tests(&cargo, &root, Some(filter), false);
        }
        [task, filter] if task == "test-network" => {
            return network_tests(command, &root, Some(filter));
        }
        [] => {
            println!(concat!(
                "cargo xtask build         Build the workspace\n",
                "cargo xtask lab-external --output /new/absolute/directory --seconds 600 [--kernel|--pppoe|--pppoe-dhcpv6|--dhcp]  Observe the isolated external-path lab; hold the healthy fixture for 0–900 seconds\n",
                "cargo xtask lab-release /observation/directory  End the interactive hold and finish acceptance/cleanup\n",
                "cargo xtask lab-view /observation/directory --seconds 600  View retained synthetic observations without starting the lab\n",
                "cargo xtask test          Run local tests\n",
                "cargo xtask test-network  Run isolated Linux network acceptance tests in Docker\n",
                "cargo xtask test-openwrt  Run native OpenWrt management acceptance in Docker ",
                "(requires the x86_64-unknown-linux-musl Rust target and host curl/OpenSSL)\n",
                "cargo xtask benchmark-relay --pilot --output <new-directory>  Validate relay/socat instrumentation in a short isolated pilot\n",
                "cargo xtask benchmark-relay --compare-ten --before <frozen-results> --after <current-worker> --output <new-directory>  Compare ten representative old/current Rust pairs with identical load actors\n",
                "cargo xtask benchmark-api --before <frozen-api-fuzzer> --after <current-api-fuzzer> --input <synthetic-json> --output <new-directory>  Compare seven paired instrumented parser replays\n",
                "cargo xtask benchmark-policy --before <frozen-policy-worker> --before-source <original-checkout> --after <current-policy-worker> --output <new-directory>  Confirm warm core policy with seven fresh-process pairs\n",
                "cargo xtask benchmark-app --pilot|--churn-pilot|--matrix|--soak-pilot|--soak [--http-qps N] --output <new-directory>  Observe synthetic DNS/Fake-IP HTTP/WireGuard workloads with native frontends\n",
                "cargo xtask benchmark-app --resume-matrix <prior-directory> --output <new-continuation>  Audit the original frozen prefix and collect only unmeasured rows\n",
                "cargo xtask benchmark-relay --observer-pilot --output <new-directory>  Qualify full and boundary-only observation with the same verified workload\n",
                "cargo xtask benchmark-relay --observer-campaign --output <new-directory>  Collect seven paired observation treatments; statistical analysis remains separate\n",
                "cargo xtask benchmark-relay --observer-analysis --output <existing-directory>  Validate complete raw observer inputs and write a paired analysis without replacing observations\n",
                "cargo xtask benchmark-relay --matrix-pilot --output <new-directory>  Qualify all latency and bulk loads\n",
                "cargo xtask benchmark-relay --operational-pilot --output <new-directory>  Qualify idle/resume, overload, slow consumers and churn\n",
                "cargo xtask benchmark-relay --endpoint-reference --output <new-directory>  Measure the direct endpoint ceiling without a relay\n",
                "  Add --worker <frozen-binary> --image <local-image> before --output to reuse the campaign's exact generator without rebuilding.\n",
                "  Frozen endpoint references also accept --observation boundary-only before --output.\n",
                "cargo xtask benchmark-relay --campaign --output <new-directory>  Run the reproducible paired relay/socat campaign\n",
                "  Add --observation boundary-only before --output for primary timing/CPU runs without periodic sampling; collect resource profiles separately.\n",
                "  Add --worker <frozen-binary> --image <local-image> before --observation/--output to reuse the qualified cohort without rebuilding.\n",
                "cargo xtask benchmark-relay --resume-campaign --output <existing-directory> --image <local-image> [--image-proof <export-proof.json>] [--verify-only]  Validate a complete prefix and continue with its frozen worker; no rebuilds or raw overwrites\n",
                "  --retain-failed-cases preserves reviewed failures, skips their coordinates and excludes incomplete groups from estimates; the campaign remains failed.\n",
                "cargo xtask benchmark-relay --integrated-pilot --output <new-directory>  Qualify whole OpenWrt inbound-controller accounting\n",
                "cargo xtask benchmark-relay --integrated-matrix --output <new-directory>  Observe all primary loads through the production UCI/procd controller; no paired comparison\n",
                "  Add --with-dns before --output to include the active DNS-exception process with the existing synthetic dnsmasq frontend.\n",
                "cargo xtask test-openwrt-flow  Verify inbound software offloading with a pinned kernel in isolated QEMU ",
                "(native-test prerequisites plus host ssh-keygen/sha256sum; caches: target/openwrt-vm)\n",
                "cargo xtask package --sdk <directory>  Build ARM64 APKs with the OpenWrt 25.12.6 ",
                "mediatek/filogic SDK (requires Docker, Rust 1.96 and its aarch64-unknown-linux-musl ",
                "target); output: target/packages/mediatek-filogic\n",
                "cargo xtask package --download-sdk <temporary-directory> --release-tag <vX.Y.Z>\n",
                "  Verify release versions, download the pinned SDK, build and inspect APKs, and emit SHA256SUMS.\n",
                "cargo xtask test-router --host <host> --access <private-env> ",
                "[--run <private-directory>] <phase> [target-url]\n",
                "  Authorized hardware phase only. Requires OpenSSH and host dig/curl/sha256sum; ",
                "private records and backups stay outside the repository. ",
                "No WAN, WireGuard or global firewall restart.\n",
                "  Inspection phases: inspect, inspect-active, inspect-path, details, adguard, preflight, verify-disabled, ",
                "windows-dns, inspect-test, audit-test.\n",
                "  probe-path observes TCP SYN headers along the existing WireGuard and WAN path; ",
                "requires verified extracted tools and SDK-built helpers (see README).\n",
                "  install-disabled installs only the two local APKs, offline, ",
                "with dependencies already present.\n",
                "  reinstall-active replaces an already-active same-version installation offline, ",
                "preserving configuration and retaining private recovery payloads; requires ",
                "TUNNEL_DETOUR_PACKAGE_SDK to verify the actual APK payload.\n",
                "  probe-active checks DNS and verified HTTPS for an existing rule without ",
                "changing configuration; omit --run to use fresh private probe records.\n",
                "  probe-ipv6-windows reuses probe-active's --run plan with a native Windows LAN client; ",
                "requires PowerShell, dig and already-applied IPv6 mode. It verifies paired DNS, origin TLS and the observed relay.\n",
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
    virtual_kernel: bool,
) -> Result<(), Box<dyn Error>> {
    openwrt_tests_observed(cargo, root, filter, virtual_kernel, None)
}

fn openwrt_tests_observed(
    cargo: &std::ffi::OsStr,
    root: &Path,
    filter: Option<&std::ffi::OsStr>,
    virtual_kernel: bool,
    observation: Option<(&Path, u64)>,
) -> Result<(), Box<dyn Error>> {
    let filter_text = filter.and_then(std::ffi::OsStr::to_str).unwrap_or_default();
    let wan_dhcpv6 = ["r128", "r129"].iter().any(|id| filter_text.contains(id));
    if !virtual_kernel
        && (filter_text.contains("r127") || wan_dhcpv6 || filter_text.contains("r146"))
    {
        return Err("use cargo xtask test-openwrt-flow for r127/r128/r129 negotiated WAN scenarios or r146 guest cgroup faults".into());
    }
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
            "--target",
            "x86_64-unknown-linux-musl",
            "--no-run",
            "--locked",
            "--message-format=json-render-diagnostics",
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
    // Native fixtures share a reserved Docker management subnet. Serialize their
    // lifetimes across xtask processes; dropping the descriptor releases a crashed run.
    // The --network=none kernel VM does not use that subnet and remains independent.
    let _native_lock = if virtual_kernel {
        None
    } else {
        let path = Path::new(
            metadata["target_directory"]
                .as_str()
                .ok_or("missing Cargo target directory")?,
        )
        .join("openwrt-native.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        file.lock()?;
        Some(file)
    };
    let binary = Path::new(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing Cargo target directory")?,
    )
    .join("x86_64-unknown-linux-musl/debug/tunnel-detour");
    for (stage, image) in [
        ("adguard-lab", "tunnel-detour-openwrt-lab:local"),
        ("dnsmasq-lab", "tunnel-detour-openwrt-dnsmasq-lab:local"),
        (
            "transition-lab",
            "tunnel-detour-openwrt-transition-lab:local",
        ),
    ] {
        checked(Command::new("docker").current_dir(root).args([
            "build",
            "--target",
            stage,
            "--tag",
            image,
            "--file",
            "sources/tests/openwrt/Dockerfile",
            ".",
        ]))?;
    }
    if wan_dhcpv6 {
        checked(Command::new("docker").current_dir(root).args([
            "build",
            "--target",
            "dhcpv6-wan-lab",
            "--tag",
            xtask::vm::DHCPV6_WAN_IMAGE,
            "--file",
            "sources/tests/openwrt/Dockerfile",
            ".",
        ]))?;
    }
    // A concurrent Cargo invocation can replace these artifacts while a long laboratory
    // run is active. Snapshot both files: current_exe must remain an executable path,
    // and a later container must use the same runtime as the first one.
    let snapshot = tempfile::tempdir()?;
    let fixture_snapshot = snapshot.path().join("openwrt-fixture");
    let binary_snapshot = snapshot.path().join("tunnel-detour");
    std::fs::copy(&executable, &fixture_snapshot)?;
    std::fs::copy(&binary, &binary_snapshot)?;
    let mut command = Command::new(&fixture_snapshot);
    command
        .current_dir(root)
        .args(["--ignored", "--test-threads=1", "--nocapture"])
        .env("TUNNEL_DETOUR_OPENWRT_LAB", "1")
        .env("TUNNEL_DETOUR_OPENWRT_BINARY", &binary_snapshot);
    if let Some((directory, seconds)) = observation {
        command
            .env("TUNNEL_DETOUR_LAB_OBSERVE", directory)
            .env("TUNNEL_DETOUR_LAB_HOLD_SECONDS", seconds.to_string());
    }
    if virtual_kernel {
        let target = Path::new(
            metadata["target_directory"]
                .as_str()
                .ok_or("missing Cargo target directory")?,
        );
        let (kernel, image) = xtask::vm::prepare(
            root,
            target,
            &binary_snapshot,
            &fixture_snapshot,
            wan_dhcpv6,
        )?;
        command
            .env("TUNNEL_DETOUR_VM_KERNEL", kernel)
            .env("TUNNEL_DETOUR_VM_IMAGE", image);
    } else {
        // Guest-only faults must never run against host cgroups. Keep native
        // acceptance separate; R146 remains owned by the explicit QEMU run.
        command.args(["--skip", "r127_tagged_pppoe", "--skip", "r146_guest_cgroup"]);
    }
    if !wan_dhcpv6 {
        command.args(["--skip", "r128_netifd", "--skip", "r129_netifd"]);
    }
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
            "--message-format=json-render-diagnostics",
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
    let snapshot = tempfile::tempdir()?;
    let executable_snapshot = snapshot.path().join("network-fixture");
    let service_snapshot = snapshot.path().join("tunnel-detour");
    std::fs::copy(executable, &executable_snapshot)?;
    std::fs::copy(service, &service_snapshot)?;
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
            executable_snapshot.display()
        ))
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/opt/tunnel-detour,readonly",
            service_snapshot.display()
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
