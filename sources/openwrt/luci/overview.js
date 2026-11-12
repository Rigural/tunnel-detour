'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require ui';
'require poll';
'require view.tunnel-detour.inbound as inbound';

const callStatus = rpc.declare({ object: 'tunnel-detour', method: 'status', expect: {} });
const callValidate = rpc.declare({ object: 'tunnel-detour', method: 'validate', params: ['patterns'], expect: {} });
const callCheck = rpc.declare({ object: 'tunnel-detour', method: 'check', expect: {} });
const callCredentialsStatus = rpc.declare({ object: 'tunnel-detour', method: 'credentials_status', expect: {} });
const callSetCredentials = rpc.declare({ object: 'tunnel-detour', method: 'set_credentials', params: ['username', 'password'], expect: {} });
const callTestAdguard = rpc.declare({ object: 'tunnel-detour', method: 'test_adguard', params: ['api_url', 'username', 'password', 'use_saved_credentials'], expect: {} });
const callPreviewUpstream = rpc.declare({ object: 'tunnel-detour', method: 'preview_upstream', params: ['api_url', 'username', 'password', 'real_upstream', 'import_current', 'use_saved_credentials'], expect: {} });
const callRestart = rpc.declare({ object: 'tunnel-detour', method: 'restart', expect: {} });
const callNetworks = rpc.declare({ object: 'network.interface', method: 'dump', expect: { interface: [] } });
// getHostHints also invokes reverse DNS. Read local lease records only.
const callDevices = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', params: ['family'], expect: { dhcp_leases: [] } });

const scopePrefixes = { exact: '', one: '*.', descendants: '**.', inclusive: '***.' };

function splitPattern(pattern) {
	pattern = pattern || '';
	for (const scope of ['inclusive', 'descendants', 'one']) {
		const prefix = scopePrefixes[scope];
		if (pattern.startsWith(prefix))
			return { scope, domain: pattern.slice(prefix.length) };
	}
	return { scope: 'exact', domain: pattern };
}

function errorMessage(code) {
	const messages = {
		uci_configuration_failed: _('Review the selected networks and required fields in Settings.'),
		invalid_configuration: _('Review the configuration in Settings, including Advanced settings.'),
		adguard_authentication_failed: _('AdGuard rejected the credentials. Check the username and password in Settings.'),
		adguard_unreachable: _('AdGuard could not be reached. Check its address in Settings and that AdGuard is running.'),
		adguard_timeout: _('AdGuard did not respond in time. Check that it is running and try again.'),
		adguard_endpoint_invalid: _('The AdGuard address must point to an HTTP endpoint on this router. Review it in Settings.'),
		adguard_response_invalid: _('The server did not return a compatible AdGuard response. Check the AdGuard address and version.'),
		adguard_integration_failed: _('AdGuard integration failed. Test its connection in Settings and check the service log.'),
		adguard_integration_disabled: _('AdGuard Home is not the selected DNS integration.'),
		adguard_upstream_approval_required: _('AdGuard upstream management needs a fresh preview. In Settings, preview the change and explicitly accept it before Save & Apply.'),
		adguard_upstream_conflict: _('AdGuard upstreams changed outside Tunnel Detour. Review Settings and explicitly preview importing or reapplying the resolver.'),
		adguard_upstream_unsupported: _('Upstream management needs explicit plaintext IP resolvers, no upstream file and no fallback list. Encrypted providers and implicit defaults are not converted automatically.'),
		resolver_route_unavailable: _('The DNS resolver has no usable route outside WAN. Restore its VPN or local route, then retry. Tunnel Detour will not send real DNS through WAN.'),
		resolver_recovery_required: _('A DNS change is still incomplete. Finish applying that resolver or restore the last applied resolver before choosing another endpoint.'),
		dnsmasq_integration_failed: _('The existing dnsmasq frontend could not be used safely. Check that one standard instance is running, without overlapping local rules, custom filters, DNSSEC or pending DHCP changes. See the service log for the specific reason.'),
		deadline_expired: _('A connection or DNS request timed out. Check the DNS resolver and WAN connection.'),
		io_error: _('A network or file operation failed. Check the WAN connection and the service log.'),
		lease_storage_error: _('Saved address mappings could not be read or written. Check available storage and the service log.'),
		dns_error: _('A DNS request failed. Check the configured DNS resolver.'),
		invalid_dns_response: _('The DNS resolver returned an invalid response. Review the resolver in Settings.'),
		no_ipv4_address: _('The destination has no usable address for the enabled WAN families.'),
		no_usable_address: _('The destination has no usable address for the enabled WAN families.'),
		ipv6_routing_state_invalid: _('IPv6 routing ownership could not be verified. Check the service log before changing its saved state.'),
		dns_alias_loop: _('The destination has a DNS alias loop. Check the domain and its DNS records.'),
		forbidden_destination: _('A private or router-local destination was blocked to protect the network.'),
		filtered_destination: _('AdGuard blocked or rewrote the destination. Review its filtering rules if this was unexpected.'),
		mapping_rule_capacity: _('This exception has reached its permanent hostname budget. Review its scope or adjust the per-rule limit in Advanced settings.'),
		adguard_credentials_unavailable: _('The selected credentials are unavailable. Enter and apply replacement credentials, or discard a superseded draft.'),
		adguard_credentials_storage_failed: _('Private credential storage is unavailable. Check free space and the service log; re-enter credentials if their saved file is missing.'),
		unauthorized_source: _('A client outside the selected LAN was rejected. Review the LAN selection in Settings.'),
		ipv6_path_unavailable: _('The selected IPv6 LAN or preferred WAN source is unavailable. Check the IPv6 connection before restarting.'),
		adguard_ipv6_disabled: _('AdGuard blocks IPv6 resolution. Review its IPv6 setting before enabling IPv6 exceptions.'),
		connection_rejected: _('An exception connection was rejected. Check the rule and try the website again.'),
		capacity_exhausted: _('The service reached its resource limit. Close unused connections and try again.'),
		state_unavailable: _('The service cannot safely use its state. Check the service log before restarting it.'),
		kernel_conflict: _('Routing or firewall rules conflict with another configuration. Check the service log.'),
		kernel_command_failed: _('Routing or firewall configuration failed. Check the selected networks and the service log.'),
		invalid_clock: _('The router clock is invalid. Correct its date and time before restarting the service.'),
		identifier_exhausted: _('The connection counter reached its limit. Restart the service.'),
		cancelled: _('The operation was cancelled. Try again if it was still needed.'),
		task_failed: _('A service task stopped unexpectedly. Check the service log before restarting it.'),
		json_error: _('Saved data could not be read. Check the service log before restarting it.')
	};
	return Object.hasOwn(messages, code) ? messages[code] : _('The operation failed. Review Settings and check the service log for details.');
}

function serviceState(result) {
	const status = result.status || {};
	let state;
	let description;
	let severity = 'notice';
	if (result.enabled === false) {
		state = _('Disabled');
		description = result.running ? _('The service is finishing its shutdown.') : _('Choose a DNS integration and enable Tunnel Detour in Settings to use exceptions.');
	}
	else if (!result.running || status.phase === 'failed') {
		state = status.phase === 'failed' ? _('Error') : _('Stopped');
		description = _('The service is enabled but is not serving exceptions. Review Settings and restart the service.');
		severity = 'warning';
	}
	else if (status.phase === 'ready') {
		state = status.configuration_applied === false ? _('Running previous configuration') : _('Running');
		description = status.configuration_applied === false ? _('The saved DNS change was not applied. Established connections and the last applied resolver remain active. Review the reported issue in Settings.') : _('The service is ready to handle exception traffic.');
		severity = status.configuration_applied === false ? 'warning' : 'success';
	}
	else {
		state = status.phase === 'stopping' ? _('Stopping') : _('Starting');
		description = _('Wait for the service to finish changing state.');
	}
	return { state, description, severity };
}

function duration(seconds) {
	seconds = Math.max(0, Math.floor(seconds));
	if (seconds < 60) return _('%ss').format(seconds);
	if (seconds < 3600) return _('%sm %ss').format(Math.floor(seconds / 60), seconds % 60);
	return _('%sh %sm').format(Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60);
}

function displayStatus(node, result, devices) {
	const status = result.status || {};
	const connections = Object.values(status.connections || {});
	const state = serviceState(result);
	const rows = connections.map(connection => {
		const ip = connection.client.startsWith('[') ? connection.client.slice(1, connection.client.indexOf(']')) : connection.client.split(':')[0];
		const name = devices.find(device => device.ipaddr === ip)?.hostname;
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td', 'data-title': _('Hostname') }, [connection.domain]),
			E('td', { 'class': 'td', 'data-title': _('Device') }, [
				name ? E('strong', {}, [name]) : [], E('div', {}, [connection.client])
			]),
			E('td', { 'class': 'td', 'data-title': _('Duration') }, [duration(Date.now() / 1000 - connection.started_at)]),
			E('td', { 'class': 'td', 'data-title': _('WAN destination') }, [connection.destination])
		]);
	});
	if (!rows.length)
		rows.push(E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': 4 }, [_('No active exception connections.')])]));
	node.replaceChildren(
		E('p', {}, [state.description]),
		E('p', {}, [_('Applied DNS integration: %s').format(result.dns_integration === 'adguard' ? 'AdGuard Home' : result.dns_integration === 'dnsmasq' ? 'dnsmasq' : _('Not selected'))]),
		status.applied_resolver ? E('p', {}, [_('Last applied resolver: %s · Interface: %s').format(status.applied_resolver, status.resolver_device || '—'), status.managed_upstream ? ' · ' + _('AdGuard upstream managed') : '']) : [],
		status.ipv6_wan_source ? E('p', {}, [_('Last applied IPv6 WAN: %s · Source: %s').format(status.ipv6_wan_device || '—', status.ipv6_wan_source)]) : [],
		status.pending_resolver ? E('p', { 'class': 'td-error' }, [_('Pending resolver: %s').format(status.pending_resolver)]) : [],
		status.recovery_resolvers?.length ? E('p', { 'class': 'td-help' }, [_('To recover the incomplete DNS change, select one of these previously protected resolvers in Settings: %s').format(status.recovery_resolvers.join(', '))]) : [],
		status.last_error && result.enabled !== false ? E('p', {}, [_('Last recorded issue: %s').format(errorMessage(status.last_error))]) : [],
		status.mapping_usage ? E('p', { 'class': status.mapping_usage.allocated * 5 >= status.mapping_usage.capacity * 4 ? 'td-error' : 'td-help' }, [
			_('Permanent Fake-IP identities: %s / %s · Per-rule limit: %s').format(status.mapping_usage.allocated, status.mapping_usage.capacity, status.mapping_usage.per_rule_limit)
		]) : [],
		E('p', {}, [_('Active connections: %s · DNS queries: %s · Completed connections: %s').format(connections.length, status.dns_queries || 0, status.completed_connections || 0)]),
		E('table', { 'class': 'table td-connections' }, [
			E('tr', { 'class': 'tr table-titles' }, [_('Hostname'), _('Device'), _('Duration'), _('WAN destination')].map(label => E('th', { 'class': 'th' }, [label]))),
			...rows
		]),
		E('p', { 'class': 'td-help' }, [_('Device names come from local DHCP leases. Devices without a known name show their IP address.')])
	);
}

// Only extract a hostname. Paths, credentials and ports never become exception patterns.
function domainInput(value) {
	value = value.trim();
	if (/^https?:\/\//i.test(value)) {
		try { return new URL(value).hostname; }
		catch (_) { return value; }
	}
	return value;
}

function scopeExamples(domain, scope) {
	domain = domain || 'example.test';
	const child = 'shop.' + domain;
	const nested = 'account.' + child;
	const matches = scope === 'exact' ? [domain] : scope === 'one' ? [child] : scope === 'descendants' ? [child, nested] : [domain, child, nested];
	const misses = scope === 'exact' ? [child] : scope === 'one' ? [domain, nested] : scope === 'descendants' ? [domain] : ['other-' + domain];
	return E('div', { 'class': 'td-examples' }, [
		E('div', {}, [_('Matches: %s').format(matches.join(', '))]),
		E('div', {}, [_('Does not match: %s').format(misses.join(', '))])
	]);
}

return view.extend({
	load() {
        return Promise.all([uci.load('tunnel-detour'), callStatus(), callNetworks(), callDevices(4).catch(() => []), uci.changes(), inbound.load(), callCredentialsStatus()]);
	},

	render(data) {
		const map = new form.Map('tunnel-detour', _('Tunnel Detour'), _('Send selected HTTP and HTTPS hostnames through WAN. Choose AdGuard Home or an existing dnsmasq frontend; other traffic keeps its existing route.'));
		map.tabbed = true;
		let currentStatus = data[1];
		let credentialsConfigured = data[6].configured === true;
		let devices = data[3];
		let pending = !!data[4]['tunnel-detour']?.length;
		let dirty = false;
		let formBaseline;
		let upstreamReceipt = uci.get('tunnel-detour', 'globals', 'adguard_upstream_approval');
		const formSnapshot = () => JSON.stringify([upstreamReceipt, ...[...map.root.querySelectorAll('input, select')].filter(field => !field.readOnly).map(field => [field.id, field.type === 'checkbox' ? field.checked : field.value])]);
		let inboundView;
		let validationGeneration = 0;
		let validationTimer;
		const removed = new Set();
		const added = new Set();
		const rowErrors = new Map();
		const normalizedPatterns = new Map();
		const rowFeedback = new Map();
		const rowExamples = new Map();
		const banner = E('div', { 'class': 'td-banner', 'role': 'status', 'aria-live': 'polite' });
		const undo = E('div', { 'class': 'td-undo', 'aria-live': 'polite' });
		const status = E('div');
		const actions = E('div', { 'class': 'td-actions' });
		let actionState;
		const openSettings = () => map.root.querySelector('.cbi-tabmenu li[data-tab="globals"] a')?.click();
		const updateState = () => {
			inboundView?.update();
			const state = serviceState(currentStatus);
			banner.className = 'td-banner alert-message ' + state.severity;
			const changes = dirty ? _('Unsaved edits — Save & Apply to activate them.') : pending ? _('Saved changes pending — Save & Apply to activate them.') : _('Applied configuration');
			const label = _('DNS exceptions: %s').format(state.state);
			if (banner.textContent !== label + changes)
				banner.replaceChildren(E('strong', {}, [label]), E('span', {}, [changes]));
			displayStatus(status, currentStatus, devices);
			const nextActionState = JSON.stringify([currentStatus.enabled, currentStatus.running, currentStatus.status?.phase, map.readonly, dirty, pending]);
			if (nextActionState === actionState) return;
			actionState = nextActionState;
			actions.replaceChildren();
			if (currentStatus.enabled === false || !currentStatus.running || currentStatus.status?.phase === 'failed')
				actions.appendChild(E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'click': openSettings }, [
					currentStatus.enabled === false ? _('Open Settings to enable') : _('Review Settings')
				]));
			if (currentStatus.enabled && !['starting', 'stopping'].includes(currentStatus.status?.phase))
				actions.appendChild(E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'disabled': (map.readonly === true || dirty || pending) || null, 'click': ui.createHandlerFn(this, async () => {
					const result = await callRestart();
					if (!result.accepted) throw new Error(_('Service restart could not be requested.'));
				}) }, [_('Restart service')]));
		};
		const markDirty = () => {
			dirty = removed.size > 0 || added.size > 0 || formSnapshot() !== formBaseline;
			updateState();
		};
		const statusSection = map.section(form.NamedSection, 'globals', 'globals', _('Status'));
		const exceptionsSection = map.section(form.TableSection, 'exception', _('Exceptions'), _('Enter a domain and choose which names it covers. Enabled rules combine; a narrower rule does not cancel a broader one.'));
		const settingsSection = map.section(form.NamedSection, 'globals', 'globals', _('Settings'));
		const group = (key, title, description, mode) => {
			const field = settingsSection.option(form.SectionValue, key, form.NamedSection, 'globals', 'globals');
			if (mode) field.depends('dns_integration', mode);
			const subsection = field.subsection;
			subsection.render = function() {
				return this.renderUCISection('globals').then(fields => E('fieldset', { 'class': 'td-settings-group' }, [E('legend', {}, [title]), description ? E('p', {}, [description]) : [], fields]));
			};
			return subsection;
		};
		let section = group('_service', _('Service and networks'));
		const serviceEnabled = section.option(form.Flag, 'enabled', _('Enable service'));
		let option = serviceEnabled;
		option.rmempty = false;
		const networks = [...new Set(data[2].map(network => network.interface).filter(name => typeof name === 'string' && name !== 'loopback'))].sort(L.naturalCompare);
		for (const field of [
			['lan_network', _('LAN network')],
			['wan_network', _('WAN network')]
		]) {
			option = section.option(form.ListValue, field[0], field[1]);
			for (const name of networks)
				option.value(name, name);
			const current = uci.get('tunnel-detour', 'globals', field[0]);
			if (current && !networks.includes(current))
				option.value(current, _('%s (unavailable)').format(current));
			option.datatype = 'uciname';
			option.rmempty = false;
		}
		const ipv6Enabled = option = section.option(form.Flag, 'ipv6_enabled', _('Enable IPv6 exceptions'), _('Allows IPv6 clients and IPv6-only destinations through the selected WAN. Uses existing LAN prefixes and a preferred stable WAN source; DHCP and IPv6 announcements stay unchanged. Losing that context closes exception connections.'));
		option.default = '0';
		option.rmempty = false;
		option = section.option(form.ListValue, 'wan6_network', _('IPv6 WAN network'), _('Select the logical interface providing Internet IPv6, often wan6. QUIC remains rejected so clients can use TCP. AdGuard must allow IPv6 resolution.'));
		option.value('', _('Choose an IPv6 WAN network…'));
		for (const name of networks)
			option.value(name, name);
		const currentWan6 = uci.get('tunnel-detour', 'globals', 'wan6_network');
		if (currentWan6 && !networks.includes(currentWan6))
			option.value(currentWan6, _('%s (unavailable)').format(currentWan6));
		option.depends('ipv6_enabled', '1');
		option.retain = true;
		option.rmempty = false;
		option.datatype = 'uciname';
		const resolverField = option = section.option(form.Value, 'real_upstream', _('DNS resolver'), _('Real DNS over TCP, separate from Fake-IP forwarding. Enter an IPv4 or IPv6 address with an optional port; use [IPv6]:port for a custom IPv6 port. Its existing VPN or local route is pinned; WAN fallback is refused. No provider is selected automatically.'));
		option.rmempty = false;
		option.depends('enabled', '1');
		option.retain = true;
		option = section.option(form.ListValue, 'dns_integration', _('DNS integration'), _('Changing integration removes the previous owned forwarding rules before activating the new frontend. Existing frontend settings are preserved; saved AdGuard credentials are retained for recovery.'));
		option.value('unconfigured', _('Choose an integration…'));
		option.value('adguard', 'AdGuard Home');
		option.value('dnsmasq', _('Existing dnsmasq'));
		option.rmempty = false;
		option.cfgvalue = () => uci.get('tunnel-detour', 'globals', 'dns_integration') ?? 'adguard';
		option.validate = (sectionId, value) => value !== 'unconfigured' || map.lookupOption('enabled', sectionId)[0]?.formvalue(sectionId) !== '1' ? true : _('Choose a DNS integration before enabling the service.');
		group('_dnsmasq', _('Existing dnsmasq'), _('Uses one running standard dnsmasq instance without installing it. DHCP, local names and other upstreams stay in place. Custom filters, DNSSEC, extra config files and overlapping rewrites are rejected to prevent silently bypassing them. Run Check applied configuration after saving.'), 'dnsmasq');
		section = group('_adguard', _('AdGuard connection'), _('Connect to AdGuard Home on this router. Filtering stays active; upstream management below is optional.'), 'adguard');
		if (data[6].error) section.description += ' ' + errorMessage(data[6].error);
		const adguardUrl = option = section.option(form.Value, 'adguard_url', _('API address'), _('HTTP address of AdGuard on this router.'));
		option.placeholder = 'http://127.0.0.1:3000';
		option.rmempty = false;
		const adguardUsername = option = section.option(form.Value, 'adguard_username', _('Username'));
		option.placeholder = credentialsConfigured ? _('Stored privately; leave empty to keep') : '';
		option.optional = true;
		option.rmempty = true;
		const adguardPassword = option = section.option(form.Value, 'adguard_password', _('Password'));
		option.description = _('Leave both credential fields empty to keep the stored values. Save prepares one private draft; Save & Apply selects it. Discard keeps the applied credentials.');
		option.optional = true;
		option.password = true;
		option.rmempty = true;
		for (const field of [adguardUrl, adguardUsername, adguardPassword]) {
			field.depends('dns_integration', 'adguard');
			field.retain = true;
		}
		for (const field of [adguardUsername, adguardPassword]) {
			field.cfgvalue = () => '';
			field.write = () => {};
			field.remove = () => {};
		}
		const clearCredentials = section.option(form.Flag, '_clear_credentials', _('Use anonymous authentication'));
		clearCredentials.depends('dns_integration', 'adguard');
		clearCredentials.cfgvalue = () => '0';
		clearCredentials.write = () => {};
		clearCredentials.remove = () => {};
		const useSavedCredentials = (username, password) => credentialsConfigured && !username && !password && clearCredentials.formvalue('globals') !== '1';
		const testResult = E('p', { 'class': 'td-test-result', 'role': 'status', 'aria-live': 'polite' });
		const testButton = E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
			const draft = [adguardUrl, adguardUsername, adguardPassword].map(field => field.formvalue('globals') || '');
			testResult.textContent = _('Testing the form values…');
			try {
				const result = await callTestAdguard(...draft, useSavedCredentials(draft[1], draft[2]));
				if ([adguardUrl, adguardUsername, adguardPassword].some((field, index) => (field.formvalue('globals') || '') !== draft[index])) {
					testResult.textContent = _('The form changed during the test. Test the current values again. Nothing was saved or applied.');
					return;
				}
				const message = !result.connected ? errorMessage(result.error) : !result.health?.dns_running ? _('Connected, but AdGuard DNS is stopped.') : !result.health.protection_enabled ? _('Connected. DNS is running, but protection is disabled.') : _('Connected. AdGuard DNS and protection are enabled.');
				testResult.textContent = message + ' ' + _('Tested the form values. Nothing was saved or applied.');
			} catch {
				testResult.textContent = _('The connection test failed. Nothing was saved or applied. Try again.');
			}
		}) }, [_('Test AdGuard connection')]);
		const testSection = section.option(form.SectionValue, '_test', form.NamedSection, 'globals', 'globals').subsection;
		testSection.render = () => Promise.resolve(E('div', { 'class': 'td-connection-test' }, [testButton, testResult, E('p', { 'class': 'td-help' }, [_('Uses the values above without saving or changing the running service.')])]));
		const manageUpstream = section.option(form.Flag, 'manage_adguard_upstream', _('Manage AdGuard upstream'), _('Use the DNS resolver above for AdGuard general queries as well as real destinations. Conditional upstreams, filtering, local names, system DNS and DHCP remain in place. First adoption and conflicts require an accepted preview.'));
		manageUpstream.default = '0';
		manageUpstream.rmempty = false;
		manageUpstream.retain = true;
		const approvalField = section.option(form.Value, 'adguard_upstream_approval');
		// Persist the administrative receipt through native form parsing, without
		// showing a token that the user does not need to edit.
		approvalField.render = () => Promise.resolve(E('span', { 'hidden': true }));
		approvalField.isActive = () => true;
		approvalField.formvalue = () => upstreamReceipt || '';
		approvalField.rmempty = true;
		const upstreamResult = E('p', { 'role': 'status', 'aria-live': 'polite' });
		const upstreamDraft = () => [adguardUrl, adguardUsername, adguardPassword, resolverField].map(field => field.formvalue('globals') || '');
		const previewUpstream = async importCurrent => {
			const draft = upstreamDraft();
			upstreamResult.textContent = _('Reading the current upstreams…');
			try {
				const result = await callPreviewUpstream(...draft, importCurrent, useSavedCredentials(draft[1], draft[2]));
				if (JSON.stringify(draft) !== JSON.stringify(upstreamDraft())) {
					upstreamResult.textContent = _('The form changed. Preview the current values again.');
					return;
				}
				if (!result.valid) {
					upstreamResult.textContent = errorMessage(result.error) + (result.recovery_resolvers?.length ? ' ' + _('Previously protected resolvers: %s').format(result.recovery_resolvers.join(', ')) : '');
					return;
				}
				upstreamResult.textContent = '';
				ui.showModal(_('Review DNS upstream management'), [
					E('p', {}, [_('Current general upstreams: %s').format(result.current_general.join(', '))]),
					E('p', {}, [_('Proposed general upstream: %s').format(result.proposed_general.join(', '))]),
					E('p', {}, [_('Tunnel Detour must be the only upstream editor while management is enabled. AdGuard has no conditional-write API: a simultaneous edit in its interface can be overwritten. Detected conflicts stop further writes until you review them.')]),
					E('p', {}, [_('A recoverable copy is kept. Bootstrap entries are preserved. This preview expires after 10 minutes. Accepting changes the form; Save & Apply activates it.')]),
					E('div', { 'class': 'right' }, [
						E('button', { 'class': 'btn', 'type': 'button', 'click': ui.hideModal }, [_('Cancel')]), ' ',
						E('button', { 'class': 'btn cbi-button-positive', 'type': 'button', 'click': () => {
							if (JSON.stringify(draft) !== JSON.stringify(upstreamDraft())) {
								ui.hideModal(); upstreamResult.textContent = _('The form changed. Preview the current values again.'); return;
							}
							resolverField.getUIElement('globals').setValue(result.resolver);
							manageUpstream.getUIElement('globals').setValue('1');
							upstreamReceipt = result.receipt;
							ui.hideModal(); markDirty();
							upstreamResult.textContent = _('Preview accepted. Save & Apply within 10 minutes to activate it.');
						} }, [_('Accept in form')])
					])
				]);
			} catch { upstreamResult.textContent = _('The upstream preview failed. No DNS settings were changed. Try again.'); }
		};
		const upstreamButtons = [
			E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'disabled': true, 'click': ui.createHandlerFn(this, () => previewUpstream(false)) }, [_('Preview / reapply resolver')]),
			E('button', { 'class': 'cbi-button', 'type': 'button', 'disabled': true, 'click': ui.createHandlerFn(this, () => previewUpstream(true)) }, [_('Import current TCP resolver')])
		];
		const upstreamSection = section.option(form.SectionValue, '_upstream_preview', form.NamedSection, 'globals', 'globals').subsection;
		upstreamSection.render = () => Promise.resolve(E('div', { 'class': 'td-connection-test' }, [...upstreamButtons, upstreamResult]));
		const advanced = settingsSection.option(form.SectionValue, '_advanced', form.NamedSection, 'globals', 'globals').subsection;
		advanced.render = function() {
			return this.renderUCISection('globals').then(fields => E('details', { 'class': 'cbi-section' }, [E('summary', {}, [_('Advanced')]), fields]));
		};
		for (const field of [['dns_port', _('Internal DNS port')], ['proxy_port', _('Transparent TCP port')]]) {
			option = advanced.option(form.Value, field[0], field[1]);
			option.datatype = 'port';
			option.rmempty = false;
		}
		for (const [name, label, fallback] of [
			['max_mappings', _('Total permanent hostname budget'), '4096'],
			['max_mappings_per_rule', _('Permanent hostname budget per rule'), '512']
		]) {
			option = advanced.option(form.Value, name, label, _('Expired identities remain reserved. Existing hostnames can renew when a budget is full.'));
			option.datatype = 'range(1,131070)';
			option.placeholder = fallback;
			option.optional = true;
		}
		option = advanced.option(form.DynamicList, 'trusted_clients', _('Trusted exception clients'), _('Optional IPv4/IPv6 CIDRs inside the selected LAN. Empty allows the whole LAN. Only trust devices that use normal DNS and hostname validation: opaque TLS does not authenticate the application hostname to Tunnel Detour. Changing this list closes existing exception connections.'));
		option.datatype = 'cidr';
		option.optional = true;

		section = exceptionsSection;
		section.anonymous = true;
		section.addremove = true;
		option = section.option(form.Flag, 'enabled', _('Enabled'));
		option.default = '1';
		option.rmempty = false;
		const rulesSection = section;
		const allSections = section.cfgsections.bind(section);
		section.cfgsections = () => allSections().filter(id => !removed.has(id));
		const labelRow = row => {
			const id = row.dataset.sid;
			const number = allSections().indexOf(id) + 1;
			row.hidden = removed.has(id);
			for (const [selector, label] of [
				['input[type="text"]', _('Domain for exception %s')],
				['select', _('Scope for exception %s')],
				['input[type="checkbox"]', _('Enable exception %s')]
			]) row.querySelector(selector)?.setAttribute('aria-label', label.format(number));
			row.querySelector('input[type="text"]')?.setAttribute('aria-describedby', domainOption.cbid(id) + '-feedback');
		};
		section.handleAdd = async function() {
			// Add a native LuCI row without saving or replacing other draft fields.
			if (allSections().length >= 256)
				throw new Error(_('The exception limit is 256. Save removed rules before adding more.'));
			const id = uci.add('tunnel-detour', 'exception');
			added.add(id);
			try {
				const fields = await this.renderUCISection(id);
				const row = E('tr', { 'id': 'cbi-tunnel-detour-' + id, 'class': 'tr cbi-section-table-row', 'data-sid': id, 'data-section-id': id }, [
					...fields.childNodes, this.renderRowActions(id)
				]);
				const body = map.root.querySelector('#cbi-tunnel-detour-exception tbody');
				body.querySelector('.placeholder')?.remove();
				body.appendChild(row); labelRow(row);
				row.querySelector('input[type="text"]')?.focus();
				markDirty(); scheduleValidation();
			} catch (error) {
				uci.remove('tunnel-detour', id);
				added.delete(id);
				throw error;
			}
		};
		const updateUndo = () => {
			undo.replaceChildren(...[...removed].map(id => E('div', {}, [
				_('Removed %s.').format(domainInput(domainOption.formvalue(id) || domainOption.cfgvalue(id))), ' ',
				E('button', { 'class': 'cbi-button', 'type': 'button', 'click': () => {
					removed.delete(id);
					map.findElement('data-sid', id)?.removeAttribute('hidden');
					updateUndo(); markDirty(); scheduleValidation();
				} }, [_('Undo')]), ' ', _('Not saved yet.')
			])));
		};
		section.handleRemove = id => {
			removed.add(id);
			map.findElement('data-sid', id)?.setAttribute('hidden', '');
			updateUndo(); markDirty(); scheduleValidation();
		};
		const domainOption = section.option(form.Value, '_domain', _('Domain'));
		domainOption.placeholder = 'example.test';
		domainOption.rmempty = false;
		domainOption.cfgvalue = id => splitPattern(uci.get('tunnel-detour', id, 'pattern')).domain;
		const renderDomain = domainOption.renderWidget;
		domainOption.renderWidget = function(id, ...args) {
			const feedback = E('div', { 'id': this.cbid(id) + '-feedback', 'class': 'td-rule-feedback', 'aria-live': 'polite' });
			rowFeedback.set(id, feedback);
			return Promise.resolve(renderDomain.call(this, id, ...args)).then(widget => E('div', { 'class': 'td-domain' }, [widget, feedback]));
		};
		const scopeOption = section.option(form.ListValue, '_scope', _('Scope'));
		scopeOption.value('exact', _('This domain only'));
		scopeOption.value('one', _('One subdomain level'));
		scopeOption.value('descendants', _('All subdomains, excluding this domain'));
		scopeOption.value('inclusive', _('This domain and all subdomains'));
		scopeOption.rmempty = false;
		scopeOption.default = 'exact';
		scopeOption.cfgvalue = id => splitPattern(uci.get('tunnel-detour', id, 'pattern')).scope;
		const renderScope = scopeOption.renderWidget;
		scopeOption.renderWidget = function(id, ...args) {
			const examples = E('div');
			rowExamples.set(id, examples);
			return Promise.resolve(renderScope.call(this, id, ...args)).then(widget => E('div', {}, [widget, examples]));
		};
		const rulePattern = id => {
			const current = splitPattern(uci.get('tunnel-detour', id, 'pattern'));
			const domain = domainOption.formvalue(id) ?? current.domain;
			const scope = scopeOption.formvalue(id) ?? current.scope;
			if (!Object.hasOwn(scopePrefixes, scope))
				throw new Error(_('Select a valid scope for the domain.'));
			return scopePrefixes[scope] + domainInput(domain);
		};
		domainOption.write = scopeOption.write = id => uci.set('tunnel-detour', id, 'pattern', normalizedPatterns.get(id) || rulePattern(id));
		const validateRows = async () => {
			const generation = ++validationGeneration;
			const ids = rulesSection.cfgsections();
			const patterns = ids.map(rulePattern);
			for (const id of ids) {
				const pattern = splitPattern(rulePattern(id));
				rowExamples.get(id)?.replaceChildren(scopeExamples(pattern.domain, pattern.scope));
			}
			const result = await callValidate(patterns.join('\n'));
			if (generation !== validationGeneration) return null;
			rowErrors.clear();
			normalizedPatterns.clear();
			ids.forEach((id, index) => {
				const row = result.rows?.[index];
				const error = !domainInput(domainOption.formvalue(id) || '') ? _('Enter a domain.') : row?.error === 'duplicate' ? _('This domain and scope already exist. Remove the duplicate or change its scope.') : row?.error ? _('Enter a valid hostname, or paste an HTTP or HTTPS URL.') : null;
				if (error) rowErrors.set(id, error);
				if (row?.pattern) normalizedPatterns.set(id, row.pattern);
				const feedback = rowFeedback.get(id);
				if (feedback) {
					feedback.classList.toggle('td-error', !!error);
					feedback.textContent = error || _('Will save: %s').format(row?.pattern || patterns[index]);
				}
				const input = map.findElement('id', domainOption.cbid(id))?.querySelector('input[type="text"]');
				input?.setAttribute('aria-invalid', String(!!error));
				input?.classList.toggle('td-input-invalid', !!error);
			});
			return { ...result, valid: result.valid && !rowErrors.size };
		};
		const scheduleValidation = () => {
			++validationGeneration;
			clearTimeout(validationTimer);
			validationTimer = setTimeout(() => validateRows().catch(() => {
				for (const id of rulesSection.cfgsections()) {
					const feedback = rowFeedback.get(id);
					if (feedback) feedback.textContent = _('Validation unavailable. Try again before saving.');
				}
			}), 300);
		};
		const parse = map.parse.bind(map);
		map.parse = async function() {
			clearTimeout(validationTimer);
			const result = await validateRows();
			if (!result?.valid)
				throw new Error(result?.error || _('Review the highlighted domain rules.'));
			await parse();
			const username = adguardUsername.formvalue('globals') || '';
			const password = adguardPassword.formvalue('globals') || '';
			const clear = clearCredentials.formvalue('globals') === '1';
			if (clear && (username || password))
				throw new Error(_('Clear stored credentials or enter replacements.'));
			if (username || password || clear) {
				const result = await callSetCredentials(username, password);
				if (!result.saved || !result.revision)
					throw new Error(_('Credentials could not be saved.'));
				uci.set('tunnel-detour', 'globals', 'adguard_credentials_revision', result.revision);
				credentialsConfigured = !clear;
				adguardUsername.getUIElement('globals').setValue('');
				adguardPassword.getUIElement('globals').setValue('');
				clearCredentials.getUIElement('globals').setValue('0');
			}
			for (const id of removed) uci.remove('tunnel-detour', id);
		};
		const save = map.save.bind(map);
		map.save = (...args) => save(...args).then(async node => {
			dirty = false; removed.clear(); added.clear(); updateUndo();
			pending = !!(await uci.changes())['tunnel-detour']?.length;
			updateState();
			return node;
		});
		const reset = map.reset.bind(map);
		map.reset = () => {
			upstreamReceipt = uci.get('tunnel-detour', 'globals', 'adguard_upstream_approval');
			for (const id of added) uci.remove('tunnel-detour', id);
			added.clear(); removed.clear(); rowErrors.clear(); normalizedPatterns.clear();
			dirty = false; updateUndo();
			return reset();
		};
		const checks = E('div', { 'class': 'cbi-section' }, [
			E('p', { 'class': 'td-help' }, [_('Checks the applied configuration, selected DNS frontend, networks and ports without changing them. Unsaved form values are not included.')]),
			E('button', { 'class': 'cbi-button cbi-button-action', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
				const result = await callCheck();
				ui.addNotification(null, E('p', {}, [result.valid ? _('Applied configuration and selected DNS frontend passed their checks.') : errorMessage(result.error)]));
			}) }, [_('Check applied configuration')])
		]);
		const checkSection = settingsSection.option(form.SectionValue, '_checks', form.NamedSection, 'globals', 'globals').subsection;
		checkSection.render = () => Promise.resolve(checks);
		inboundView = inbound.attach(map, networks, data[5], () => map.readonly === true || dirty || pending, errorMessage);
		statusSection.render = () => Promise.resolve(E('div', { 'class': 'cbi-section', 'data-tab': 'status', 'data-tab-title': _('Status') }, [
			E('h3', {}, [_('Status and active connections')]), status, actions
		]));
		// LuCI re-renders this map after staging changes or adding a row.
		const renderContents = map.renderContents.bind(map);
		map.renderContents = () => {
			rowFeedback.clear(); rowExamples.clear();
			return renderContents().then(node => {
				for (const [field, label] of [[serviceEnabled, _('Enable service')], [ipv6Enabled, _('Enable IPv6 exceptions')], [manageUpstream, _('Manage AdGuard upstream')], [clearCredentials, _('Use anonymous authentication')]]) {
					const control = map.findElement('id', field.cbid('globals'));
					(control?.matches('input[type="checkbox"]') ? control : control?.querySelector('input[type="checkbox"]'))?.setAttribute('aria-label', label);
				}
				for (const button of [testButton, ...upstreamButtons, ...checks.querySelectorAll('button')])
					button.disabled = map.readonly === true;
				for (const row of node.querySelectorAll('#cbi-tunnel-detour-exception [data-sid]')) labelRow(row);
				formBaseline = formSnapshot();
				updateState(); scheduleValidation();
				return node;
			});
		};
		poll.add(() => Promise.all([callStatus(), uci.changes()]).then(([result, changes]) => {
			currentStatus = result; pending = !!changes['tunnel-detour']?.length; updateState();
		}).catch(() => {
			banner.className = 'td-banner alert-message warning';
			banner.textContent = _('Service status unavailable. Retrying automatically; form edits have not been applied.');
		}), 3);
		poll.add(() => callDevices(4).then(result => { devices = result; }).catch(() => { devices = []; }), 30);
		poll.add(() => inboundView.poll(), 3);
		return map.render().then(node => {
			node.addEventListener('input', () => { markDirty(); scheduleValidation(); testResult.textContent = ''; });
			node.addEventListener('change', () => { markDirty(); scheduleValidation(); testResult.textContent = ''; });
			const content = E('div', { 'class': 'tunnel-detour' }, [
				E('link', { 'rel': 'stylesheet', 'href': L.resource('view/tunnel-detour/overview.css') + '?v=' + L.env.resource_version }),
				banner, node
			]);
			const renderRules = rulesSection.renderContents.bind(rulesSection);
			rulesSection.renderContents = (...args) => { const result = renderRules(...args); result.appendChild(undo); return result; };
			node.querySelector('#cbi-tunnel-detour-exception').appendChild(undo);
			return content;
		});
	}
});
