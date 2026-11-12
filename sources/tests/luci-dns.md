# R097: DNS management in native LuCI

Use the disposable native laboratory, with synthetic configuration and Chrome.
This scenario does not authorize production-router access.

Prepare an empty private results directory and choose a new absolute JSON path:

```sh
TUNNEL_DETOUR_LUCI_DNS_REVIEW=/absolute/path/dns-review.json \
  cargo xtask test-openwrt r095
```

The fixture first validates the dnsmasq profile, then pauses in the AdGuard profile.
The JSON contains its temporary loopback URL and container name, without credentials.
Open that URL in Chrome, enter LuCI in the disposable fixture, and select Settings.
Do not reuse a production-router tab or expose the laboratory outside loopback.

1. Check that the applied resolver and optional upstream-management state are visible.
2. Preview reapplying the resolver. The dialog must show old/new general upstreams,
   confirmation that bootstrap settings are preserved, the sole-editor limitation
   and the ten-minute expiry.
   Cancel must leave the form and saved configuration unchanged.
3. Import the current TCP resolver. Accepting must change only the draft and show
   an unsaved-edits notice. The operation must not enable another DNS transport.
4. Save & Apply. Confirm applied state without restarting the service; the remaining
   R095 assertions also verify process identity and actual traffic after the review.
5. Test the AdGuard connection. Confirm that it tests form values without saving.
6. Switch the integration to dnsmasq without saving: AdGuard management controls
   must disappear. Switch back and confirm credential retention without revealing them.

Leave the selected integration, resolver and enable flags as the fixture configured
them. An accepted review may be saved; do not save a change to another frontend.
Create the same path with extension `.continue` to resume the fixture before its
ten-minute deadline. The test then checks real connections, conflicts and cleanup.
Record manual observations separately; the pause alone is not UI acceptance.
