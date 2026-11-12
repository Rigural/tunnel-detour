# R117: IPv6 settings in native LuCI

Use Chrome and the disposable native laboratory, never a production-router tab.
Choose a new absolute private results path:

```sh
TUNNEL_DETOUR_LUCI_IPV6_REVIEW=/absolute/path/ipv6-review.json \
  cargo xtask test-openwrt r116
```

The test validates dnsmasq first and pauses for ten minutes in the AdGuard profile.
The JSON contains the temporary loopback URL and container name, without credentials.
Verify that the URL is reachable from the browser host before opening it.

1. In Status, confirm the applied IPv6 WAN device and source. These describe the
   running configuration, independently of unsaved Settings edits.
2. In Settings, find the labeled **Enable IPv6 exceptions** checkbox and the
   **IPv6 WAN network** selector. The selected network must match the fixture.
3. Uncheck IPv6 without saving: its WAN selector disappears. Check it again and
   confirm that the previous selection remains. The banner must distinguish edits
   from applied configuration. Keyboard and accessible labels must identify both controls.
4. Read the explanations: existing LAN prefixes and a preferred WAN source are used,
   DHCP/IPv6 announcements remain unchanged, and QUIC stays rejected.
5. Run **Check applied configuration** and confirm its visible success message.

Restore the original checkbox and network selection without saving unrelated edits.
Record observations and screenshots privately. Close the lab tab and create the
JSON path with extension `.continue` to resume traffic and cleanup assertions.
The pause alone does not count as UI acceptance.
