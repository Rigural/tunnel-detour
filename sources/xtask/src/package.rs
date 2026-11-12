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
const SDK_NAME: &str = "openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64";
const SDK_SHA256: &str = "1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e";

fn validate_version(tag: Option<&str>, makefile: &str) -> Result<(), Box<dyn Error>> {
    let version = env!("CARGO_PKG_VERSION");
    let package_versions: Vec<_> = makefile
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PKG_VERSION:="))
        .map(str::trim)
        .collect();
    if package_versions != [version] {
        return Err("Cargo and OpenWrt package versions must match".into());
    }
    if let Some(tag) = tag
        && tag != format!("v{version}")
    {
        return Err("release tag must be v followed by the exact Cargo package version".into());
    }
    Ok(())
}

pub(crate) fn download_and_build(
    root: &Path,
    cargo: &OsStr,
    directory: &Path,
    tag: &str,
) -> Result<(), Box<dyn Error>> {
    validate_version(
        Some(tag),
        &fs::read_to_string(root.join("sources/openwrt/Makefile"))?,
    )?;
    fs::create_dir_all(directory)?;
    let staging = tempfile::Builder::new()
        .prefix("openwrt-sdk-")
        .tempdir_in(directory)?;
    let archive = staging.path().join("sdk.tar.zst");
    let url = format!(
        "https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/{SDK_NAME}.tar.zst"
    );
    checked(
        Command::new("curl")
            .args([
                "--fail",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "20",
                "--max-time",
                "600",
                "--retry",
                "3",
                "--retry-max-time",
                "900",
                "--output",
            ])
            .arg(&archive)
            .arg(url),
    )?;
    let digest = Command::new("sha256sum").arg(&archive).output()?;
    if !digest.status.success()
        || String::from_utf8(digest.stdout)?.split_whitespace().next() != Some(SDK_SHA256)
    {
        return Err("downloaded OpenWrt SDK failed the pinned SHA-256 check".into());
    }
    checked(
        Command::new("tar")
            .args(["--zstd", "--extract", "--no-same-owner", "--file"])
            .arg(&archive)
            .arg("--directory")
            .arg(staging.path()),
    )?;
    build(root, cargo, &staging.path().join(SDK_NAME))
}

pub(crate) fn build(root: &Path, cargo: &OsStr, sdk: &Path) -> Result<(), Box<dyn Error>> {
    validate_version(
        None,
        &fs::read_to_string(root.join("sources/openwrt/Makefile"))?,
    )?;
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
        "files/tunnel-detour-inbound.init",
        "files/tunnel-detour.config",
        "luci/overview.js",
        "luci/inbound.js",
        "luci/overview.css",
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
    for name in &names {
        let mut found = Vec::new();
        find(&sdk.join("bin/packages"), name, &mut found)?;
        if found.len() != 1 {
            return Err(format!("expected one generated {name}, found {}", found.len()).into());
        }
        let source = found.first().ok_or("missing generated APK")?;
        fs::copy(source, artifacts.join(name))?;
        println!("Generated {}", artifacts.join(name).display());
    }
    let sbom = source_sbom(&metadata)?;
    fs::write(
        artifacts.join("SOURCE-SBOM.spdx.json"),
        serde_json::to_vec_pretty(&sbom)?,
    )?;
    let revision = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    let commit = revision
        .status
        .success()
        .then(|| String::from_utf8_lossy(&revision.stdout).trim().to_owned());
    let state = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()?;
    let clean = state.status.success() && state.stdout.is_empty();
    fs::write(
        artifacts.join("build-info.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"), "source_commit": commit, "source_tree_clean": clean,
            "target": TARGET, "sdk": SDK_NAME, "sdk_archive_sha256": SDK_SHA256
        }))?,
    )?;
    let checksums = Command::new("sha256sum")
        .current_dir(&artifacts)
        .args(&names)
        .args(["SOURCE-SBOM.spdx.json", "build-info.json"])
        .output()?;
    if !checksums.status.success() {
        return Err("APK checksum generation failed".into());
    }
    fs::write(artifacts.join("SHA256SUMS"), checksums.stdout)?;
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

fn production_dependencies(
    metadata: &serde_json::Value,
) -> Result<std::collections::BTreeSet<&str>, Box<dyn Error>> {
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
    Ok(included)
}

/// SPDX describes the service's target-specific Cargo source graph, not the router's
/// firmware, SDK, system libraries or dependencies installed separately by APK.
fn source_sbom(metadata: &serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let included = production_dependencies(metadata)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing Cargo packages")?;
    let ids = packages
        .iter()
        .filter(|p| p["id"].as_str().is_some_and(|id| included.contains(id)))
        .map(|p| {
            Ok((
                p["id"].as_str().ok_or("missing crate id")?,
                format!(
                    "SPDXRef-{}-{}",
                    p["name"].as_str().ok_or("missing crate name")?,
                    p["version"].as_str().ok_or("missing crate version")?
                ),
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, Box<dyn Error>>>()?;
    let mut output = Vec::new();
    let mut relationships = Vec::new();
    for package in packages {
        let id = package["id"].as_str().ok_or("missing crate identifier")?;
        let Some(spdx) = ids.get(id) else {
            continue;
        };
        let name = package["name"].as_str().ok_or("missing crate name")?;
        let version = package["version"].as_str().ok_or("missing crate version")?;
        let (download, checksums) = if package["source"].is_null() {
            ("NOASSERTION".into(), Vec::new())
        } else {
            if package["source"] != "registry+https://github.com/rust-lang/crates.io-index" {
                return Err("SBOM requires an explicit adapter for this Cargo source".into());
            }
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .ok_or("missing manifest")?,
            );
            let directory = manifest.parent().ok_or("missing crate directory")?;
            let digest = match fs::read(directory.join(".cargo-checksum.json")) {
                Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)?["package"]
                    .as_str()
                    .ok_or("missing vendored crate checksum")?
                    .to_owned(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Pinned Cargo's registry extraction retains .cargo-ok; source
                    // archive checksums come from its actual downloaded .crate.
                    let index = directory.parent().ok_or("missing registry index")?;
                    let registry = index
                        .parent()
                        .and_then(Path::parent)
                        .ok_or("missing Cargo registry")?;
                    let archive = registry
                        .join("cache")
                        .join(index.file_name().ok_or("missing index name")?)
                        .join(format!("{name}-{version}.crate"));
                    let output = Command::new("sha256sum").arg(archive).output()?;
                    if !output.status.success() {
                        return Err("Cargo source archive checksum failed".into());
                    }
                    String::from_utf8(output.stdout)?
                        .split_whitespace()
                        .next()
                        .ok_or("missing archive digest")?
                        .to_owned()
                }
                Err(error) => return Err(error.into()),
            };
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("invalid crate archive checksum".into());
            }
            (
                format!("https://crates.io/api/v1/crates/{name}/{version}/download"),
                vec![serde_json::json!({"algorithm":"SHA256", "checksumValue":digest})],
            )
        };
        output.push(serde_json::json!({"SPDXID":spdx,"name":name,"versionInfo":version,
            "downloadLocation":download,"checksums":checksums,"filesAnalyzed":false,"licenseDeclared":package["license"].as_str().unwrap_or("NOASSERTION"),
            "licenseConcluded":"NOASSERTION","copyrightText":"NOASSERTION"}));
        if name == "tunnel-detour-service" {
            relationships.push(serde_json::json!({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":spdx}));
        }
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .ok_or("missing nodes")?
            .iter()
            .find(|node| node["id"] == id)
            .ok_or("missing node")?;
        for dependency in node["deps"].as_array().ok_or("missing edges")? {
            if dependency["dep_kinds"]
                .as_array()
                .ok_or("missing kinds")?
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
            {
                let target = ids
                    .get(dependency["pkg"].as_str().ok_or("missing dependency id")?)
                    .ok_or("missing dependency")?;
                relationships.push(serde_json::json!({"spdxElementId":spdx,"relationshipType":"DEPENDS_ON","relatedSpdxElement":target}));
            }
        }
    }
    let timestamp = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()?;
    if !timestamp.status.success() {
        return Err("SBOM timestamp unavailable".into());
    }
    let timestamp = String::from_utf8(timestamp.stdout)?.trim().to_owned();
    Ok(
        serde_json::json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
        "name":format!("Tunnel Detour {} Rust source dependencies", env!("CARGO_PKG_VERSION")),
        "documentNamespace":format!("https://spdx.org/spdxdocs/tunnel-detour-{}-{}", env!("CARGO_PKG_VERSION"), timestamp.replace([':', '-'], "")),
        "creationInfo":{"created":timestamp,"creators":["Tool: tunnel-detour-xtask"],"comment":"Target-specific normal and build Cargo source dependencies. Does not inventory firmware, SDK, system libraries or separately installed APK dependencies."},
        "packages":output,"relationships":relationships}),
    )
}

fn licenses(metadata: &serde_json::Value, destination: &Path) -> Result<(), Box<dyn Error>> {
    let mut notices = String::from("Third-party source notices included with this build.\n\n");
    let included = production_dependencies(metadata)?;
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

#[cfg(test)]
mod tests {
    use super::{source_sbom, validate_version};

    #[test]
    fn r132_source_inventory_includes_production_edges_and_omits_development_and_local_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let metadata = serde_json::json!({"packages":[
            {"id":"path+file:///private/controller","name":"tunnel-detour-service","version":"0.1.0","source":null,"license":"GPL-3.0-only"},
            {"id":"path+file:///private/core","name":"tunnel-detour-core","version":"0.1.0","source":null,"license":"GPL-3.0-only"},
            {"id":"path+file:///private/dev","name":"test-fixture-only","version":"0.1.0","source":null},
            {"id":"path+file:///private/build","name":"synthetic-build-dependency","version":"0.1.0","source":null}
        ], "resolve":{"nodes":[
            {"id":"path+file:///private/controller","deps":[
                {"pkg":"path+file:///private/core","dep_kinds":[{"kind":null}]},
                {"pkg":"path+file:///private/build","dep_kinds":[{"kind":"build"}]},
                {"pkg":"path+file:///private/dev","dep_kinds":[{"kind":"dev"}]}
            ]}, {"id":"path+file:///private/core","deps":[]}, {"id":"path+file:///private/build","deps":[]}
        ]}});
        let sbom = source_sbom(&metadata)?;
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        let names: Vec<_> = sbom["packages"]
            .as_array()
            .ok_or("missing packages")?
            .iter()
            .map(|value| value["name"].as_str().ok_or("missing name"))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            names,
            [
                "tunnel-detour-service",
                "tunnel-detour-core",
                "synthetic-build-dependency"
            ]
        );
        let serialized = serde_json::to_string(&sbom)?;
        assert!(!serialized.contains("/private/"));
        assert!(!serialized.contains("test-fixture-only"));
        assert_eq!(
            sbom["relationships"],
            serde_json::json!([
                {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-tunnel-detour-service-0.1.0"},
                {"spdxElementId":"SPDXRef-tunnel-detour-service-0.1.0","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-tunnel-detour-core-0.1.0"},
                {"spdxElementId":"SPDXRef-tunnel-detour-service-0.1.0","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-synthetic-build-dependency-0.1.0"}
            ])
        );
        Ok(())
    }

    #[test]
    fn r038_release_tag_and_openwrt_version_must_match_the_cargo_version() {
        let version = env!("CARGO_PKG_VERSION");
        let makefile = format!("PKG_VERSION:={version}\n");
        assert!(validate_version(Some(&format!("v{version}")), &makefile).is_ok());
        for tag in [version, "v999.999.999", "v0.1.0\nmalformed"] {
            assert!(validate_version(Some(tag), &makefile).is_err());
        }
        assert!(
            validate_version(Some(&format!("v{version}")), "PKG_VERSION:=999.999.999\n").is_err()
        );
        assert!(validate_version(None, &format!("{makefile}PKG_VERSION:=999.999.999\n")).is_err());
    }
}
