use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::checked;

const TARGET: &str = "aarch64-unknown-linux-musl";
const COMPILER: &str =
    "toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc";

pub(crate) fn build(root: &Path, cargo: &OsStr, sdk: &Path) -> Result<(), Box<dyn Error>> {
    let sdk = sdk.canonicalize()?;
    if !fs::read_to_string(sdk.join("include/version.mk"))?.contains("25.12.6") {
        return Err("packaging requires the OpenWrt 25.12.6 SDK".into());
    }
    let linker = sdk.join("staging_dir").join(COMPILER);
    if !linker.is_file()
        || !sdk
            .join("target/linux/mediatek/filogic/target.mk")
            .is_file()
    {
        return Err(
            "packaging requires the mediatek/filogic SDK with its Cortex-A53 compiler".into(),
        );
    }
    let metadata = Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--locked",
            "--format-version=1",
            "--filter-platform",
            TARGET,
        ])
        .output()?;
    if !metadata.status.success() {
        return Err("Cargo metadata failed".into());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing target directory")?,
    );
    let rustc = Command::new("rustc")
        .current_dir(root)
        .args(["--print", "sysroot"])
        .output()?;
    if !rustc.status.success() {
        return Err("Rust sysroot lookup failed".into());
    }
    let sysroot = PathBuf::from(String::from_utf8(rustc.stdout)?.trim());
    let cargo_home = match env::var_os("CARGO_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env::var_os("HOME").ok_or("HOME is unavailable")?).join(".cargo"),
    };
    let rustup_home = sysroot
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid Rust sysroot")?;
    let mut flags = vec![
        "-C".to_owned(),
        "target-feature=-crt-static".into(),
        "-C".into(),
        "target-cpu=cortex-a53".into(),
    ];
    for (path, public) in [
        (root, "/usr/src/tunnel-detour"),
        (cargo_home.as_path(), "/usr/src/cargo"),
        (rustup_home, "/usr/src/rust"),
        (sdk.as_path(), "/usr/src/openwrt-sdk"),
    ] {
        flags.push(format!("--remap-path-prefix={}={public}", path.display()));
    }
    checked(
        Command::new(cargo)
            .current_dir(root)
            .args([
                "build",
                "--package",
                "tunnel-detour-service",
                "--release",
                "--locked",
                "--target",
                TARGET,
            ])
            .env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", &linker)
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"))
            .env("STAGING_DIR", sdk.join("staging_dir")),
    )?;

    let package = sdk.join("package/tunnel-detour");
    let marker = package.join(".tunnel-detour-xtask");
    if package.exists() && !marker.is_file() {
        return Err("SDK already has a tunnel-detour package not owned by this task".into());
    }
    fs::create_dir_all(&package)?;
    fs::write(&marker, "tunnel-detour SDK staging v1\n")?;
    // Explicit inputs keep ignored local context and router configuration out of SDK packages.
    for name in [
        "Makefile",
        "files/tunnel-detour.init",
        "files/tunnel-detour.config",
        "luci/overview.js",
        "luci/menu.json",
        "luci/acl.json",
    ] {
        let destination = package.join(name);
        fs::create_dir_all(destination.parent().ok_or("invalid package destination")?)?;
        fs::copy(root.join("sources/openwrt").join(name), destination)?;
    }
    fs::copy(root.join("LICENSE"), package.join("LICENSE"))?;
    fs::copy(
        target.join(TARGET).join("release/tunnel-detour"),
        package.join("service-binary"),
    )?;
    licenses(&metadata, &package.join("THIRD-PARTY-LICENSES"))?;
    checked(Command::new("docker").current_dir(root).args([
        "build",
        "--tag",
        "tunnel-detour-sdk:local",
        "sources/xtask/sdk",
    ]))?;
    sdk_make(&sdk, &["defconfig", "V=s"])?;
    sdk_make(&sdk, &["package/tunnel-detour/clean", "V=s"])?;
    sdk_make(&sdk, &["package/tunnel-detour/compile", "V=s"])?;
    let artifacts = target.join("packages/mediatek-filogic");
    fs::create_dir_all(&artifacts)?;
    let names = [
        format!("tunnel-detour-{}-r1.apk", env!("CARGO_PKG_VERSION")),
        format!(
            "luci-app-tunnel-detour-{}-r1.apk",
            env!("CARGO_PKG_VERSION")
        ),
    ];
    for name in names {
        let mut found = Vec::new();
        find(&sdk.join("bin/packages"), &name, &mut found)?;
        if found.len() != 1 {
            return Err(format!("expected one generated {name}, found {}", found.len()).into());
        }
        let source = found.first().ok_or("missing generated APK")?;
        fs::copy(source, artifacts.join(&name))?;
        println!("Generated {}", artifacts.join(name).display());
    }
    checked(
        Command::new(cargo)
            .current_dir(root)
            .args([
                "test",
                "--package",
                "xtask",
                "--test",
                "package",
                "--locked",
                "--",
                "--ignored",
                "--nocapture",
            ])
            .env("TUNNEL_DETOUR_PACKAGE_SDK", &sdk)
            .env("TUNNEL_DETOUR_PACKAGE_DIRECTORY", &artifacts),
    )?;
    Ok(())
}

fn sdk_make(sdk: &Path, arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(sdk)?;
    let mut command = Command::new("docker");
    command
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            &format!("{}:{}", metadata.uid(), metadata.gid()),
            "--mount",
        ])
        .arg(format!("type=bind,src={},dst=/sdk", sdk.display()))
        .args(["tunnel-detour-sdk:local", "make"])
        .args(arguments)
        .args([
            "CONFIG_PACKAGE_tunnel-detour=m",
            "CONFIG_PACKAGE_luci-app-tunnel-detour=m",
        ]);
    // This SDK hard-enables prebuilt kernel packages in Config-build.in. Their runtime
    // dependency names remain in our APK, but packaging this userspace program does not
    // require repacking every SDK kernel module. Override only those make selections.
    for line in fs::read_to_string(sdk.join("Config-build.in"))?.lines() {
        if let Some(name) = line.strip_prefix("config PACKAGE_kmod-") {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err("invalid SDK kernel package identifier".into());
            }
            command.arg(format!("CONFIG_PACKAGE_kmod-{name}="));
        }
    }
    checked(&mut command)
}

fn find(directory: &Path, name: &str, found: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            find(&entry.path(), name, found)?;
        } else if kind.is_file() && entry.file_name() == name {
            found.push(entry.path());
        }
    }
    Ok(())
}

fn licenses(metadata: &serde_json::Value, destination: &Path) -> Result<(), Box<dyn Error>> {
    let mut notices = String::from("Third-party source notices included with this build.\n\n");
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing Cargo packages")?;
    let root = packages
        .iter()
        .find(|package| package["name"] == "tunnel-detour-service")
        .and_then(|package| package["id"].as_str())
        .ok_or("missing service package")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("missing dependency graph")?;
    let mut pending = vec![root];
    let mut included = std::collections::BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !included.insert(id) {
            continue;
        }
        let node = nodes
            .iter()
            .find(|node| node["id"] == id)
            .ok_or("missing dependency node")?;
        for dependency in node["deps"].as_array().ok_or("missing dependency edges")? {
            if dependency["dep_kinds"]
                .as_array()
                .ok_or("missing dependency kinds")?
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
            {
                pending.push(
                    dependency["pkg"]
                        .as_str()
                        .ok_or("missing dependency identifier")?,
                );
            }
        }
    }
    for package in metadata["packages"]
        .as_array()
        .ok_or("missing Cargo packages")?
    {
        if package["source"].is_null()
            || !included.contains(package["id"].as_str().ok_or("missing package identifier")?)
        {
            continue;
        }
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("missing crate manifest")?,
        );
        let directory = manifest.parent().ok_or("invalid crate manifest path")?;
        notices.push_str(&format!(
            "{} {} — {}\n",
            package["name"].as_str().ok_or("missing crate name")?,
            package["version"].as_str().ok_or("missing crate version")?,
            package["license"]
                .as_str()
                .unwrap_or("See upstream license file")
        ));
        let mut files = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
            if entry.file_type()?.is_file()
                && ["LICENSE", "COPYING", "NOTICE"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            {
                files.push(entry.path());
            }
        }
        if let Some(file) = package["license_file"].as_str() {
            files.push(directory.join(file));
        }
        files.sort();
        files.dedup();
        if files.is_empty() {
            return Err(format!(
                "{} is missing distributable license notices",
                package["name"]
            )
            .into());
        }
        for file in files {
            let name = file
                .file_name()
                .ok_or("invalid license file name")?
                .to_string_lossy();
            notices.push_str(&format!(
                "\n--- {name} ---\n{}\n",
                fs::read_to_string(&file)?
            ));
        }
        notices.push('\n');
    }
    fs::write(destination, notices)?;
    Ok(())
}
