# Tunnel Detour for AdGuard Home

Domain-based VPN exceptions for OpenWrt and AdGuard Home, implemented in Rust. Selected HTTP and
HTTPS connections use WAN through DNS Fake-IP mappings and a transparent TCP relay. Other traffic
keeps its existing route. LuCI manages one exception list and the corresponding AdGuard Home
forwarding rules automatically. TLS passes through without decryption.

The initial target is OpenWrt One with OpenWrt 25.12.6, firewall4/nftables and APK packages.
Exceptions support IPv4 TCP ports 80 and 443. Selected AAAA and HTTPS/SVCB answers are suppressed,
and QUIC is rejected to allow TCP fallback. Exception traffic fails closed when its path is unavailable.

## LuCI interface

Status shows service health and active connections. Exceptions provides per-rule validation, match
examples and undo before saving. Settings groups network selection and AdGuard access, including a
connection test that uses the form values without saving them.

Screenshots use an isolated demo with synthetic domains, addresses and connection data.

![Service status and active connections](docs/screenshots/status.jpg)

<details>
<summary>Exception list and settings</summary>

![Exception scopes and matching examples](docs/screenshots/exceptions.jpg)

![Network settings and local AdGuard connection](docs/screenshots/settings.jpg)

</details>

## Domain rules

| Rule | Matches |
| --- | --- |
| `example.test` | The exact hostname |
| `*.example.test` | One subdomain level |
| `**.example.test` | All subdomain levels, excluding the root |
| `***.example.test` | The root and all subdomain levels |

Rules combine. Adding a narrower rule does not cancel a broader one.

## Configuration

Requires AdGuard Home on the router. The packages are named `tunnel-detour` and
`luci-app-tunnel-detour`.

Packages are disabled initially. In LuCI, configure LAN/WAN networks, AdGuard API access and the
real DNS upstream, then add exceptions and enable the service. The real upstream uses IPv4 DNS
over TCP and must avoid AdGuard's Fake-IP forwarding path. Changes to AdGuard's DNS servers are
not yet synchronized with this setting automatically.

## Development

All implementation and tooling live under `sources/`. Use Rust 1.96; isolated network and native
OpenWrt tests require Linux and Docker. Packaging also requires the matching mediatek/filogic SDK
and the `aarch64-unknown-linux-musl` Rust target. Native OpenWrt tests additionally require the
`x86_64-unknown-linux-musl` target and host curl/OpenSSL.

```sh
cargo xtask build
cargo xtask test
cargo xtask test-network
cargo xtask test-openwrt
cargo xtask package --sdk /path/to/openwrt-sdk
```

The package command produces runtime and LuCI APKs in `target/packages/mediatek-filogic/` and
checks their contents. Real-router acceptance is a separate, explicitly authorized SSH phase;
keep its credentials and backups private. Run `cargo xtask` for available commands and prerequisites.

After building the APKs, an authorized same-version hardware update preserves configuration and
keeps a private recovery copy. The probe checks an existing rule through DNS and verified HTTPS,
including redirects covered by existing rules; it requires host dig/curl. Private records stay
outside the repository.

```sh
TUNNEL_DETOUR_PACKAGE_SDK=/path/to/openwrt-sdk \
  cargo xtask test-router --host ROUTER --access /private/access.env reinstall-active
cargo xtask test-router --host ROUTER --access /private/access.env probe-active
```

## License

The project's original code is licensed under the GNU General Public License, version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE) for the full terms.
