# Changelog

## 0.3.1

- Update the `url` dependency to 2.5.9 to address
  [RUSTSEC-2026-0592](https://rustsec.org/advisories/RUSTSEC-2026-0592.html).

## 0.3.0

### Added

- Control DNS and inbound traffic diagnostics independently in LuCI, UCI and JSON
  configuration. Both default to off on fresh installs and upgrades. Withdrawing
  consent hides and discards the previous diagnostic period while established
  connections continue under the applied policy.
- Show pending revocation, unapplied settings and temporary status failures in
  LuCI. Keep each JSON status file under its daemon's ownership. If status
  publication fails after a purge, traffic continues while publication retries.

### Fixed

- Reject unresolved DNS referrals before connecting over WAN. Clean up Fake-IP
  firewall chains without reading unrelated nftables rules and sets.
- Repair missing inbound IPv6 redirects while preserving administrator rules in
  place. Report conflicts when rule ownership cannot be verified. If software
  flow retirement fails, attempt to block new admissions and purge owned IPv6
  connection tracking entries independently, with separate outcomes in the log.
- Report transport worker startup failures with a stable health code while
  diagnostics are off. Clear the degraded status after a subsequent worker
  confirms successful initialization.

### Development

- Use incremental Rust development builds with lightweight debug information.
  Add a full-symbol profile and document how to use Foundation's shared build cache.
- Use the exact images built for each OpenWrt laboratory run. Report a leftover
  native management network before starting any scenario.

## 0.2.0 — release candidate

- Manage exceptions through either a router-local AdGuard Home API or an existing
  dnsmasq frontend, with recoverable ownership and no automatic frontend fallback.
- Add optional IPv6 exceptions and independent IPv6 TCP/UDP publications, including
  a bounded TCP relay to IPv4 LAN destinations and explicit WAN replies.
- Keep credentials outside UCI, with write-only LuCI controls, legacy migration,
  private drafts and recovery from failed writes or uncertain API responses.
- Isolate TCP copying in unprivileged, syscall-restricted workers. Preserve queued
  output until acknowledgement and close exception traffic when its path fails.
- Bound DNS/API decoding, HTTP responses and concurrent requests; update the DNS
  and operating-system dependencies to address known advisories.
