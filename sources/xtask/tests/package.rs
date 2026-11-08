//! Inspect the actual SDK-generated APKs, including their extracted payload and lifecycle hooks.

use serde_json::Value;
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn command(program: &Path, arguments: &[&std::ffi::OsStr]) -> TestResult<Vec<u8>> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        return Err(format!(
            "APK inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

#[test]
#[ignore = "runs automatically after cargo xtask package generates the target APKs"]
fn r032_sdk_apks_have_the_required_architecture_license_owned_hooks_and_public_payload_only()
-> TestResult {
    let sdk = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_PACKAGE_SDK")
            .ok_or("use cargo xtask package --sdk <directory>")?,
    );
    let directory = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_PACKAGE_DIRECTORY").ok_or("missing package output directory")?,
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let apk = sdk.join("staging_dir/host/bin/apk");
    let version = format!("{}-r1", env!("CARGO_PKG_VERSION"));
    let service_files = [
        "etc/config/tunnel-detour",
        "etc/init.d/tunnel-detour",
        "lib/apk/packages/tunnel-detour.conffiles",
        "lib/apk/packages/tunnel-detour.conffiles_static",
        "lib/apk/packages/tunnel-detour.list",
        "usr/bin/tunnel-detour",
        "usr/libexec/rpcd/tunnel-detour",
        "usr/share/licenses/tunnel-detour/LICENSE",
        "usr/share/licenses/tunnel-detour/THIRD-PARTY-LICENSES",
    ];
    let luci_files = [
        "www/luci-static/resources/view/tunnel-detour/overview.js",
        "www/luci-static/resources/view/tunnel-detour/overview.css",
        "usr/share/luci/menu.d/luci-app-tunnel-detour.json",
        "usr/share/rpcd/acl.d/luci-app-tunnel-detour.json",
        "lib/apk/packages/luci-app-tunnel-detour.list",
    ];
    for (name, architecture, expected) in [
        (
            "tunnel-detour",
            "aarch64_cortex-a53",
            service_files.as_slice(),
        ),
        ("luci-app-tunnel-detour", "noarch", luci_files.as_slice()),
    ] {
        let file = directory.join(format!("{name}-{version}.apk"));
        command(
            &apk,
            &[
                "verify".as_ref(),
                "--allow-untrusted".as_ref(),
                file.as_os_str(),
            ],
        )?;
        let metadata: Value = serde_json::from_slice(&command(
            &apk,
            &[
                "adbdump".as_ref(),
                "--format".as_ref(),
                "json".as_ref(),
                file.as_os_str(),
            ],
        )?)?;
        assert_eq!(metadata["info"]["name"], name);
        assert_eq!(metadata["info"]["version"], version);
        assert_eq!(metadata["info"]["arch"], architecture);
        assert_eq!(metadata["info"]["license"], "GPL-3.0-only");
        let mut actual = BTreeSet::new();
        for directory in metadata["paths"].as_array().ok_or("APK paths are absent")? {
            let parent = directory["name"].as_str().unwrap_or("");
            assert!(
                parent.is_empty()
                    || expected
                        .iter()
                        .any(|path| path.starts_with(&format!("{parent}/"))),
                "unexpected APK directory: {parent}"
            );
            if let Some(files) = directory["files"].as_array() {
                for file in files {
                    let path = format!(
                        "{parent}/{}",
                        file["name"].as_str().ok_or("APK entry name is absent")?
                    );
                    if path == "etc/config/tunnel-detour" {
                        assert_eq!(file["acl"]["mode"], 0o600);
                    }
                    actual.insert(path);
                }
            }
        }
        assert_eq!(
            actual,
            expected.iter().map(|path| path.to_string()).collect(),
            "APK file allowlist differs for {name}"
        );
        let extracted = tempfile::tempdir()?;
        command(
            &apk,
            &[
                "extract".as_ref(),
                "--allow-untrusted".as_ref(),
                "--no-chown".as_ref(),
                "--destination".as_ref(),
                extracted.path().as_os_str(),
                file.as_os_str(),
            ],
        )?;
        let mut forbidden = vec![
            root.to_string_lossy().into_owned(),
            sdk.to_string_lossy().into_owned(),
            ".local/".into(),
            "AGENTS.md".into(),
            "CLAUDE.md".into(),
        ];
        if let Some(home) = env::var_os("CARGO_HOME") {
            forbidden.push(PathBuf::from(home).to_string_lossy().into_owned());
        } else if let Some(home) = env::var_os("HOME") {
            forbidden.push(
                PathBuf::from(home)
                    .join(".cargo")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        for path in expected {
            let path = extracted.path().join(path);
            if fs::symlink_metadata(&path)?.is_symlink() {
                assert_eq!(fs::read_link(path)?, Path::new("/usr/bin/tunnel-detour"));
                continue;
            }
            let bytes = fs::read(path)?;
            for value in &forbidden {
                assert!(
                    !bytes
                        .windows(value.len())
                        .any(|window| window == value.as_bytes()),
                    "APK contains local context or a private build path"
                );
            }
        }
        if name == "tunnel-detour" {
            let dependencies: BTreeSet<_> = metadata["info"]["depends"]
                .as_array()
                .ok_or("APK dependencies are absent")?
                .iter()
                .map(|value| value.as_str().ok_or("invalid dependency"))
                .collect::<Result<_, _>>()?;
            assert_eq!(
                dependencies,
                BTreeSet::from([
                    "ip-full",
                    "kmod-nft-nat",
                    "libc",
                    "libgcc1",
                    "nftables-json",
                    "procd",
                    "rpcd",
                    "ubus",
                    "uci"
                ])
            );
            assert!(
                metadata["scripts"]["pre-deinstall"]
                    .as_str()
                    .is_some_and(|script| script.contains("tunnel-detour --uninstall || exit 1"))
            );
            assert!(
                !metadata["scripts"]["post-upgrade"]
                    .as_str()
                    .ok_or("upgrade hook is absent")?
                    .contains("--uninstall")
            );
            let binary = extracted.path().join("usr/bin/tunnel-detour");
            let bytes = fs::read(&binary)?;
            assert!(
                bytes.starts_with(b"\x7fELF\x02\x01"),
                "service is not a little-endian 64-bit ELF"
            );
            assert_eq!(
                bytes.get(18..20),
                Some([183, 0].as_slice()),
                "service is not AArch64"
            );
            let readelf = sdk.join("staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-readelf");
            let headers = command(
                &readelf,
                &["--program-headers".as_ref(), binary.as_os_str()],
            )?;
            assert!(
                String::from_utf8(headers)?.contains("/lib/ld-musl-aarch64.so.1"),
                "service is not linked for the target musl loader"
            );
            assert_eq!(
                fs::read(
                    extracted
                        .path()
                        .join("usr/share/licenses/tunnel-detour/LICENSE")
                )?,
                fs::read(root.join("LICENSE"))?
            );
        }
    }
    Ok(())
}
