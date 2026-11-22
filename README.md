# Tunnel Detour

Domain-based VPN exceptions for OpenWrt. Selected HTTP and HTTPS traffic uses WAN,
while other traffic keeps its existing route. LuCI manages the rules and TLS passes
through without decryption.

Built for OpenWrt One on OpenWrt 25.12.6. Current version: **0.3.2**.
[Changelog](CHANGELOG.md) · [Releases](https://github.com/Rigural/tunnel-detour/releases) ·
[LuCI preview](docs/screenshots/status.jpg)

## Setup

1. Download and install both APKs from the release: `tunnel-detour` and `luci-app-tunnel-detour`.
2. In LuCI **Settings**, select the LAN, WAN and existing DNS frontend: AdGuard Home or
   dnsmasq. Set a DNS-over-TCP resolver reachable through the VPN or a local route,
   separate from Fake-IP forwarding.
3. Add names under **Exceptions**, then enable the service and **Save & Apply**.
   Clients must use the configured DNS frontend. Limit access to trusted LAN clients.

Exceptions cover TCP ports 80 and 443. IPv6 exceptions are optional, QUIC is rejected
to allow TCP fallback, and exceptions fail closed if their WAN path is unavailable.

| Rule | Matches |
| --- | --- |
| `example.test` | Exact hostname |
| `*.example.test` | One subdomain level |
| `**.example.test` | All subdomains |
| `***.example.test` | The hostname and all subdomains |

## Inbound ports

In LuCI **Inbound ports**, select the LAN and WAN and map an external port on the
router's public IPv6 address to a stable LAN address. IPv6 targets support TCP and UDP.
IPv4 targets support TCP through the relay. Replies use WAN, and publications can run
independently of DNS exceptions. Check applied configuration and test from an external
IPv6 network.

## Diagnostics

DNS and inbound traffic diagnostics are independently opt-in, including on upgrade.
Enable them in **Settings** or **Inbound ports** to show connection details and
counters in LuCI. Turning diagnostics off discards the current diagnostic period.

## Development

Use Rust 1.96. Network and OpenWrt labs require Linux and Docker. APK builds also
require the OpenWrt 25.12.6 mediatek/filogic SDK and the `aarch64-unknown-linux-musl` target.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo xtask package --sdk /path/to/openwrt-sdk
```

APK files, checksums, source SBOM and build metadata go to `target/packages/mediatek-filogic/`.

- `cargo xtask test-network` runs the isolated network suite.
- `cargo xtask test-openwrt` runs the native OpenWrt suite.
- `cargo xtask test-openwrt-flow r054` runs the selected scenario with the pinned OpenWrt
  kernel in QEMU. The first run fetches the image inputs and kernel. Lab results go to stdout.

See the [test coverage map](sources/tests/requirements.md). Tests on real router hardware
require separate SSH authorization.

Use `cargo build --locked --profile debugging` for full debug symbols. On hosts with the
optional Foundation cache, an example is
`foundation-build-cache run --flow tunnel-detour.test.workspace -- test --locked --workspace`.

## License

[GNU GPL version 3 only](LICENSE) (`GPL-3.0-only`).
