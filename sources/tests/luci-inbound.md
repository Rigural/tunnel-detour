# R058 / PF-09a: native inbound administration

Run against an isolated OpenWrt laboratory with the current runtime and LuCI assets.
Use an authorized administrator in Chrome. Keep DNS exceptions disabled, with no DNS
integration or real resolver configured. The LAN has `2001:db8:1::1/64`; WAN has
`2001:db8:2::1/64` and a route through gateway `2001:db8:2::2`. A configuration check
does not establish that a target server or an external Internet path is reachable.

For a live IPv4 relay row, run
`TUNNEL_DETOUR_LUCI_RELAY_REVIEW=/tmp/relay-review.json cargo xtask test-openwrt r077`.
The new JSON file supplies the disposable LuCI URL and expected original client. The
owning test waits up to four minutes while the real connection remains open. After
review, create `/tmp/relay-review.continue` to let its remaining assertions and cleanup
finish. Use fresh filenames; this mode does not target physical hardware.

1. Open **Inbound ports**. Add `Lab service`, TCP, external port `18080`, destination
   `2001:db8:1::2`, internal port `8080`, initially disabled. Save and apply. The entry
   persists after a page reload without requiring DNS configuration.
2. Add another disabled entry, then delete it and apply. Exactly the first entry remains.
3. Change the feature enable flag, edit the first publication and save the modal.
   The pending flag change survives the modal save; it must not silently revert.
4. Enable the entry and feature, then apply. The backend reports the configuration as
   applied while DNS remains stopped. LAN and Internet reachability remain unverified.
5. Expand the publication's address details. The selectable fields contain exactly
   `[2001:db8:2::1]:18080` and `2001:db8:2::1`. Wait across at least one status refresh:
   the disclosure remains expanded and the fields remain available for selection.
6. Disable and apply, then enable and apply again using only LuCI. The feature stops,
   withdraws its publication and starts again without a manual init-script invocation.
   DNS stays stopped throughout.
7. Add a known neighbor to the selected LAN. Its IPv6 address and MAC appear in the
   publication's address suggestions; selecting it fills the destination. The help
   explicitly states that suggestions do not establish stability. The DHCPv6 link
   targets the native DHCP page in another tab, preserving the publication draft.
8. Copy the address with port. Browser acknowledgement changes the button to **Copied**;
   clipboard denial leaves the address selectable with manual-copy guidance. Verify the
   pasted value separately where the browser environment permits it, including plain HTTP
   administration where the secure-context clipboard API is unavailable.
9. Save an invalid candidate while a previous publication is active. The applied-state
   message says that the saved changes were not applied and the previous configuration
   remains active. The displayed addresses belong explicitly to that previous configuration.
   Correct and apply the candidate; the warning clears. R065 owns packet-level preservation
   and the status contract for this scenario.
10. Edit an enabled publication to use the laboratory web server's occupied port. Save the
    modal: **Port unavailable** identifies the known service and transport/family. There is no
    override, no staged port change and the existing publication remains active. R068 owns the
    kernel-level service preservation and ownership checks.
11. Add an enabled entry that overlaps an existing publication. Saving shows the existing name,
    protocol and destination. **Keep existing** preserves both the old entry and the new draft.
    **Replace and save draft** disables the entire conflicting entry, retaining its settings;
    running policy changes only after **Save & Apply**. Confirm the saved state after reload.
12. Choose **Internet and LAN** for that entry. The explanation distinguishes convenient local
    access from an actual Internet test and explains the source address seen by the server.
    Apply and reload: the selection persists. Returning to **Internet only** explains that
    affected connections close. R067 owns real TCP/UDP behavior and cache retirement.
13. Enter an IPv4 LAN target. UDP and TCP + UDP are refused with a TCP-specific explanation;
    choosing TCP permits saving. The source-address explanation says that the IPv4 server sees
    the router. Suggestions include authorized IPv4 and IPv6 neighbors. Apply and reload:
    address, protocol and access mode persist. R077 owns actual traffic and original-client state.
14. Expand **Advanced relay settings**. Change the connection limit and connect timeout, save
    and apply. Both persist after a fresh page load; defaults remain visible for other limits.
    A relay capture-port conflict identifies the reserved internal port and the existing service.
15. With real relay sessions, the active table distinguishes original IPv6 clients, fixed IPv4
    targets, connecting/connected state and age. Status refresh must preserve expanded public
    address details and selection. Recent target failures show actionable notices without a
    history of client endpoints. This display requires a live laboratory session for acceptance.
16. At a 390-pixel viewport, publications and active connections show labeled rows without
    expanding the document beyond its client width. Verify the edit modal, Settings and an
    exception draft. Text/select editors remain usable, address selection survives a status
    refresh, and draft toggles retain their network selection. Restore the viewport afterward.
17. Temporarily make only the laboratory's Tunnel Detour rpcd plugin unavailable. After a
    status poll, the unavailable warning replaces the previous applied claim, preserving form
    drafts. Restore the plugin without changing publications or process identity: the next
    successful poll must restore applied state and address controls even when its response
    matches the last successful response exactly. Do not reload the page to recover it.

R052 owns packet forwarding, R054 owns connection retirement and software acceleration,
and R056 owns automatic UCI/procd lifecycle behavior. This browser scenario owns the
administration workflow, draft retention, address suggestions and honest status presentation.
Actual clipboard paste, plain-HTTP fallback, responsive layout and external reachability require
their own acceptance before making claims about them. R062 owns DHCPv6 renewal and reservation
preservation; the native administrator creates reservations explicitly.
