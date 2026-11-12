# Changelog

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
