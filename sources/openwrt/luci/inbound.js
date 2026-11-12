'use strict';
'require baseclass';
'require form';
'require rpc';
'require ui';
'require uci';

const callStatus = rpc.declare({ object: 'tunnel-detour', method: 'inbound_status', expect: {} });
const callCheck = rpc.declare({ object: 'tunnel-detour', method: 'check_inbound', expect: {} });
const callRestart = rpc.declare({ object: 'tunnel-detour', method: 'restart_inbound', expect: {} });
const callDevices = rpc.declare({ object: 'tunnel-detour', method: 'inbound_devices', params: ['network'], expect: {} });
const callPortUsage = rpc.declare({ object: 'tunnel-detour', method: 'inbound_port_usage', params: ['port'], expect: {} });
const callLeases = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', params: ['family'], expect: { dhcp6_leases: [] } });
const callLeases4 = rpc.declare({ object: 'luci-rpc', method: 'getDHCPLeases', params: ['family'], expect: { dhcp_leases: [] } });

function protocolLabel(value) {
	return { tcp: 'TCP', udp: 'UDP', tcp_udp: 'TCP + UDP' }[value] || '—';
}

function endpoint(address, port) {
	return (address.includes(':') ? '[' + address + ']' : address) + ':' + port;
}

function portUses(uses) {
	return E('ul', {}, (uses || []).map(use => E('li', {}, [
		use.protocol.toUpperCase() + ' · IPv' + use.family + ' · ' + (use.services?.map(name => ({ uhttpd: _('uHTTPd (router web server)'), dropbear: _('Dropbear (SSH)'), dnsmasq: _('dnsmasq (DNS/DHCP)'), AdGuardHome: _('AdGuard Home') }[name] || name)).join(', ') || _('Service unidentified')),
		use.tunnel_detour ? ' · ' + _('Owned by Tunnel Detour') : ' · ' + _('Reserved by another router service')
	])));
}

function copyControl(value, label) {
	const input = E('input', { 'type': 'text', 'readonly': true, 'value': value, 'click': event => event.target.select() });
	const button = E('button', { 'type': 'button', 'class': 'cbi-button', 'aria-label': _('Copy %s').format(label), 'click': ui.createHandlerFn(null, async () => {
		let copied = false;
		if (navigator.clipboard?.writeText) {
			try { await navigator.clipboard.writeText(value); copied = true; }
			catch (_) { /* Keep the selectable-field fallback available. */ }
		}
		if (!copied) {
			// Plain HTTP router administration lacks the secure-context clipboard API.
			input.focus(); input.select();
			try { copied = document.execCommand('copy'); }
			catch (_) { copied = false; }
		}
		if (copied) button.textContent = _('Copied');
		else ui.addNotification(null, E('p', {}, [_('Clipboard access is unavailable. Select the address field and copy it.')]));
	}) }, [_('Copy')]);
	return E('div', { 'class': 'td-copy-address', 'role': 'group', 'aria-label': label }, [E('label', {}, [label, input]), button]);
}

return baseclass.extend({
	load: () => Promise.all([callStatus().catch(() => ({ unavailable: true })), Promise.all([callLeases(6).catch(() => []), callLeases4(4).catch(() => [])])]),

	attach(map, networks, initial, busy, errorMessage) {
		const issue = code => ({
			inbound_configuration_failed: _('Review the selected LAN and WAN, destination, protocol and ports. IPv4 targets support TCP only.'),
			inbound_local_port_conflict: _('The external port is already used by a router service. Choose another port.'),
			inbound_relay_port_conflict: _('The internal relay port is already used by a router service. Choose a free relay port in Advanced relay settings.'),
			inbound_port_inspection_failed: _('Router port ownership could not be verified. No new publication was applied. Check the service log and the installed socket-diagnostics module.'),
			inbound_operation_failed: _('Inbound state could not be applied safely. Review the service log and any conflicting firewall changes.'),
			uci_configuration_failed: _('Select active LAN and WAN networks. WAN needs a global IPv6 address and a gateway; the destination must belong to LAN.')
		}[code] || errorMessage(code));
		let current = initial[0];
		let renderedState;
		let renderedRelay;
		const status = E('div', { 'class': 'td-inbound-status', 'aria-live': 'polite' });
		const relayStatus = E('div', { 'class': 'td-inbound-relay', 'aria-live': 'off', 'aria-label': _('Active IPv4 relay connections') });
		const updateRelay = state => {
			const relay = state.relay || {};
			const signature = JSON.stringify({ relay, publications: state.publications });
			if (signature === renderedRelay) return;
			renderedRelay = signature;
			const rules = new Map((state.publications || []).map(rule => [rule.id, rule.name]));
			const active = relay.connections || [];
			relayStatus.replaceChildren();
			if (!active.length && !relay.rejected && !(relay.notices || []).length && !(state.publications || []).some(rule => rule.enabled && !rule.destination.startsWith('['))) return;
			relayStatus.appendChild(E('h4', {}, [_('IPv4 relay connections (%s)').format(active.length)]));
			relayStatus.appendChild(E('p', {}, [_('The IPv4 server sees the router as its source. The original IPv6 client is shown below. Connection state does not prove that application login or gameplay succeeds.')]));
			const columns = [_('Publication'), _('Original IPv6 client'), _('LAN target'), _('State'), _('Age')];
			if (active.length) relayStatus.appendChild(E('div', { 'class': 'table-responsive' }, [E('table', { 'class': 'table td-connections' }, [
				E('tr', { 'class': 'tr table-titles' }, columns.map(label => E('th', { 'class': 'th' }, [label]))),
				...active.map(connection => E('tr', { 'class': 'tr' }, [rules.get(connection.publication) || connection.publication, connection.client, connection.target, connection.queued ? _('Waiting for capacity') : connection.connected ? _('Connected') : _('Connecting'), _('%s s').format(connection.age_seconds)].map((value,index) => E('td', { 'class': 'td', 'data-title':columns[index] }, [value]))))
			]) ]));
			else relayStatus.appendChild(E('p', {}, [_('No active IPv4 relay connections.')]));
			if (relay.rejected) relayStatus.appendChild(E('p', {}, [_('Rejected connections since start: %s. Possible causes include capacity limits or a retired publication.').format(relay.rejected)]));
			for (const notice of relay.notices || []) relayStatus.appendChild(E('p', { 'class': 'alert-message warning' }, [
				(rules.get(notice.publication) || notice.publication) + ': ' + ({ admission_timeout: _('The relay stayed busy for 250 ms. Retry or review the connection limit.'), admission_failed: _('The waiting connection could not be admitted. Retry and check the network if it persists.'), connect_timeout: _('The LAN server did not respond in time. Check its address, port and host firewall.'), connect_failed: _('The LAN connection failed. Check that the server is running on the configured address and port.'), transfer_failed: _('The connection was interrupted. Check the server and network path.') }[notice.outcome] || _('The connection could not be completed.'))
			]));
		};
		const update = () => {
			for (const button of controls.querySelectorAll('button')) button.disabled = busy();
			const { relay, ...stable } = current.status || {};
			updateRelay(current.status || {});
			const signature = JSON.stringify({ ...current, status: stable });
			if (signature === renderedState) return;
			renderedState = signature;
			if (current.unavailable) {
				status.replaceChildren(E('p', { 'class': 'alert-message warning' }, [_('Inbound status unavailable. Form edits have been preserved.')]));
				return;
			}
			const state = current.status || {};
			const applied = current.enabled && current.running && state.phase === 'ready' && state.applied === true;
			const retained = current.enabled && current.running && state.phase === 'ready' && state.last_error;
			const expanded = new Set(Array.from(status.querySelectorAll('details[data-publication][open]')).map(row => row.dataset.publication));
			status.replaceChildren(
				E('p', {}, [E('strong', {}, [current.enabled ? applied ? _('Configuration applied') : retained ? _('Saved changes not applied — previous configuration remains active') : _('Enabled — configuration not confirmed') : _('Inbound ports disabled')])]),
				E('p', {}, [_('LAN reachability: not verified. Internet reachability: not verified. A stopped server or its host firewall can prevent connections even when the router configuration is correct.')])
			);
			if (state.last_error) status.appendChild(E('p', { 'class': 'alert-message warning' }, [issue(state.last_error)]));
			if (state.port_conflict) status.appendChild(E('div', { 'class': 'alert-message warning', 'role': 'alert' }, [
				E('strong', {}, [(state.port_conflict.location === 'relay_listener' ? _('Internal relay port %s is reserved by another router service.') : _('Port %s is reserved by another router service.')).format(state.port_conflict.port)]),
				portUses(state.port_conflict.uses)
			]));
			if (retained) status.appendChild(E('p', {}, [_('The addresses below belong to the previous active configuration. Correct the saved settings and apply again.')]));
			if (applied || retained) for (const rule of state.publications || []) {
				if (!rule.enabled) continue;
				const row = E('details', { 'data-publication': rule.id, 'open': expanded.has(rule.id) ? '' : null }, [E('summary', {}, [rule.name + ' · ' + protocolLabel(rule.protocol) + ' · ' + rule.public_port])]);
				for (const address of state.public_addresses || []) {
					row.appendChild(copyControl('[' + address + ']:' + rule.public_port, _('Address with port')));
					row.appendChild(copyControl(address, _('Address without port')));
				}
				status.appendChild(row);
			}
			status.appendChild(relayStatus);
		};
		const controls = E('div', { 'class': 'td-actions' }, [
			E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(null, async () => {
				const result = await callCheck();
				if (result.port_conflict) ui.showModal(_('Port unavailable'), [
					E('p', {}, [(result.port_conflict.location === 'relay_listener' ? _('Internal relay port %s is reserved. Choose a free relay port in Advanced relay settings; that service will not be replaced.') : _('Port %s is reserved by another router service. Choose another external port; that service will not be replaced.')).format(result.port_conflict.port)]),
					portUses(result.port_conflict.uses),
					E('div', { 'class': 'button-row' }, [E('button', { 'type': 'button', 'class': 'cbi-button', 'click': ui.hideModal }, [_('Close')])])
				]);
				else ui.addNotification(null, E('p', {}, [result.valid ? _('Saved inbound configuration passed its checks. Reachability from Internet has not been tested.') : issue(result.error)]));
			}) }, [_('Check applied inbound configuration')]),
			E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(null, async () => {
				if (!(await callRestart()).accepted) throw new Error(_('Inbound restart could not be requested.'));
			}) }, [_('Restart inbound ports')])
		]);
		const section = map.section(form.NamedSection, 'inbound', 'inbound', _('Inbound ports'), _('Publish ports from the router’s public IPv6 to a LAN device: native TCP/UDP for IPv6 targets, or a TCP relay for IPv4 targets. IPv4 servers see the router’s address instead of the player’s original IP. Replies use WAN; ordinary traffic keeps its existing route. Internet clients need IPv6. DNS exceptions can remain disabled.'));
		section.addbtntitle = _('Set up inbound ports');
		// The named section is initialized only by the explicit setup action on older installs.
		const renderSection = section.render.bind(section);
		section.render = (...args) => {
			section.addremove = !uci.get('tunnel-detour', 'inbound');
			return renderSection(...args);
		};
		let option = section.option(form.Flag, 'enabled', _('Enable inbound ports'));
		const flags = [option];
		let lanOption;
		option.default = '0'; option.rmempty = false;
		for (const [key, label, fallback] of [['lan_network', _('LAN network'), 'lan'], ['wan_network', _('WAN network'), 'wan']]) {
			option = section.option(form.ListValue, key, label);
			option.default = fallback; option.rmempty = false;
			if (key === 'lan_network') lanOption = option;
			for (const name of networks) option.value(name, name);
			const selected = uci.get('tunnel-detour', 'inbound', key);
			if (selected && !networks.includes(selected)) option.value(selected, _('%s (unavailable)').format(selected));
		}
		const runtime = section.option(form.DummyValue, '_inbound_runtime', _('Applied state'));
		runtime.renderWidget = () => E('div', {}, [status, E('p', { 'class': 'td-help' }, [_('Checks and restarts use saved configuration. Save & Apply any edits first. Restarting closes inbound connections. These actions do not test a server from Internet.')]), controls]);
		const publications = section.option(form.SectionValue, '_publications', form.GridSection, 'inbound_port', _('Publications')).subsection;
		publications.anonymous = true; publications.addremove = true; publications.sortable = false;
		publications.nodescriptions = true;
		publications.modaltitle = _('Publication');
		publications.addbtntitle = _('Add publication');
		const savePublication = publications.handleModalSave;
		publications.handleModalSave = async function(...args) {
			const modalMap = args[0];
			const id = modalMap.section;
			const field = key => modalMap.lookupOption(key, id)?.[0]?.formvalue(id) ?? uci.get('tunnel-detour', id, key);
			const notice = (title, children) => {
				const root = this.getActiveModalMap();
				root.querySelector('.td-publication-notice')?.remove();
				const heading = E('h4', { 'tabindex': '-1' }, [title]);
				const panel = E('div', { 'class': 'td-publication-notice alert-message warning', 'role': 'alert' }, [heading, ...children]);
				root.prepend(panel); heading.focus();
				return panel;
			};
			const save = async approved => {
					if (field('destination_address') && !field('destination_address').includes(':') && field('protocol') !== 'tcp') {
						notice(_('TCP required for IPv4 targets'), [E('p', {}, [_('Choose TCP or enter an IPv6 LAN target. The IPv6-to-IPv4 relay does not support UDP.')])]);
						return;
					}
				const port = Number(field('public_port'));
				const transports = value => value === 'tcp_udp' ? ['tcp', 'udp'] : [value];
				let conflicts = [];
				if (field('enabled') === '1' && Number.isInteger(port) && port > 0 && port <= 65535) {
					const usage = await callPortUsage(port);
					if (!usage.available) {
						notice(_('Port unavailable'), [
							E('p', {}, [usage.error ? issue(usage.error) : _('Port %s is reserved by another router service. Choose another external port; that service will not be replaced.').format(port)]),
							portUses(usage.uses)
						]);
						return;
					}
					conflicts = uci.sections('tunnel-detour', 'inbound_port').filter(other => other['.name'] !== id && other.enabled === '1' && Number(other.public_port) === port && transports(other.protocol).some(protocol => transports(field('protocol')).includes(protocol)));
				}
				const signature = JSON.stringify({ candidate: ['enabled', 'name', 'protocol', 'access', 'public_port', 'destination_address', 'destination_port'].map(field), conflicts });
				if (conflicts.length && approved !== signature) {
					const panel = notice(_('Replace Tunnel Detour publications?'), [
						E('p', {}, [_('These Tunnel Detour publications already use this external port. Saving creates a draft. Save & Apply will disable their entire entries and close their current connections; their settings remain in the list.')]),
						E('ul', {}, conflicts.map(other => E('li', {}, [other.name + ' · ' + protocolLabel(other.protocol) + ' · ' + other.public_port + ' → ' + endpoint(other.destination_address, other.destination_port)])))
					]);
					panel.appendChild(E('div', { 'class': 'button-row' }, [
						E('button', { 'type': 'button', 'class': 'cbi-button', 'click': () => panel.remove() }, [_('Keep existing publications')]),
						E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(null, () => save(signature)) }, [_('Replace and save draft')])
					]));
					return;
				}
				// Native modal saves reload the parent map. Preserve its other drafts first.
				await map.parse();
				const previous = conflicts.map(other => ({ id: other['.name'], enabled: other.enabled }));
				for (const other of conflicts) uci.set('tunnel-detour', other['.name'], 'enabled', '0');
				try { return await savePublication.apply(this, args); }
				catch (error) {
					for (const other of previous) uci.set('tunnel-detour', other.id, 'enabled', other.enabled);
					throw error;
				}
			};
			return save(null);
		};
		let destinationOption;
		const renderPublication = publications.renderMoreOptionsModal;
		publications.renderMoreOptionsModal = async function(...args) {
			const selected = lanOption.formvalue('inbound') || lanOption.cfgvalue('inbound');
			const result = await callDevices(selected).catch(() => ({ devices: [], error: 'unavailable' }));
			destinationOption.keylist = []; destinationOption.vallist = [];
			const names = new Map();
			for (const lease of initial[1][0]) for (const address of lease.ip6addrs || (lease.ip6addr ? [lease.ip6addr] : [])) {
				if (typeof address === 'string' && lease.hostname) names.set(address.split('/')[0], lease.hostname);
			}
			for (const lease of initial[1][1]) if (lease.ipaddr && lease.hostname) names.set(lease.ipaddr, lease.hostname);
			for (const device of result.devices || []) destinationOption.value(device.address, (names.get(device.address) || device.mac) + ' · ' + device.address);
			if (result.error) ui.addNotification(null, E('p', {}, [_('Known device addresses are unavailable for the selected LAN. Enter a verified stable LAN address manually.')]));
			return renderPublication.apply(this, args);
		};
		option = publications.option(form.Flag, 'enabled', _('Enabled'));
		flags.push(option);
		option.default = '0'; option.rmempty = false;
		option = publications.option(form.Value, 'name', _('Name'));
		option.rmempty = false;
		option.validate = (_, value) => value && new TextEncoder().encode(value).length <= 80 && !/[\x00-\x1f\x7f]/.test(value) ? true : _('Enter a name of 1–80 bytes without control characters.');
		option = publications.option(form.ListValue, 'protocol', _('Protocol'));
		for (const [key, label] of [['tcp', 'TCP'], ['udp', 'UDP'], ['tcp_udp', 'TCP + UDP']]) option.value(key, label);
		option.default = 'tcp'; option.rmempty = false;
		option.textvalue = id => protocolLabel(uci.get('tunnel-detour', id, 'protocol'));
		option = publications.option(form.ListValue, 'access', _('Public-address access'), _('Internet only: local devices use the server’s LAN address and internal port. Internet and LAN: use the same public address everywhere; local connections pass through the router and the server sees the router as their source. Changing mode closes this publication’s current connections. Test from an external network separately — a successful LAN connection does not prove Internet access.'));
		option.value('wan_only', _('Internet only'));
		option.value('wan_and_lan', _('Internet and LAN'));
		option.default = 'wan_only'; option.rmempty = false;
		option.textvalue = id => uci.get('tunnel-detour', id, 'access') === 'wan_and_lan' ? _('Internet and LAN') : _('Internet only');
		option = publications.option(form.Value, 'public_port', _('External port'));
		option.datatype = 'port'; option.rmempty = false;
		option.validate = (_, value) => /^\d{1,5}$/.test(value) && Number(value) > 0 && Number(value) <= 65535 ? true : _('Enter one port between 1 and 65535.');
		option = publications.option(form.Value, 'destination_address', _('LAN address'), _('Select or enter a stable IPv4 or IPv6 address of the target device. IPv4 requires TCP and uses the router as source. Lease records are suggestions; they do not prove stability. A reservation is never created automatically.'));
		destinationOption = option;
		option.datatype = 'ipaddr("nomask")'; option.rmempty = false;
		option = publications.option(form.DummyValue, '_reservation_help', _('Address stability'));
		option.modalonly = true;
		option.renderWidget = () => E('div', {}, [E('p', {}, [_('Use the native DHCP page to create an IPv4 or DHCPv6 reservation explicitly. SLAAC and IPv6 privacy addresses require a stable address configured on the device.')]), E('a', { 'href': L.url('admin/network/dhcp'), 'target': '_blank', 'rel': 'noopener' }, [_('Open DHCP reservations in another tab')])]);
		option = publications.option(form.Value, 'destination_port', _('Internal port'));
		option.datatype = 'port'; option.rmempty = false;
		option.validate = (_, value) => /^\d{1,5}$/.test(value) && Number(value) > 0 && Number(value) <= 65535 ? true : _('Enter one port between 1 and 65535.');
		const advanced = section.option(form.DummyValue, '_relay_advanced', _('Advanced relay settings'));
		const advancedFields = [];
		for (const [key, label, fallback, maximum, help] of [
			['relay_port', _('Internal capture port'), 10537, 65535, _('Local capture port used by the relay. A port occupied by another router service is refused.')],
			['relay_connections', _('Maximum relay connections'), 32, 256, _('Shared limit across IPv4 publications, including TCP sessions finishing their close. Up to 32 extra connections can wait for 250 ms before being refused. Higher limits leave less TCP buffer space per connection; lower limits may improve speed on high-latency links.')],
			['relay_connect_timeout', _('LAN connect timeout (seconds)'), 5, 30, _('Maximum wait for the IPv4 server to accept a connection.')],
			['relay_idle_timeout', _('Inactivity timeout (seconds)'), 3600, 86400, _('Connections with no progress close after this interval. Active connections have no total lifetime limit.')]
		]) {
			const field = section.option(form.Value, key, label, help);
			field.default = String(fallback); field.rmempty = false;
			field.datatype = 'and(uinteger,range(1,' + maximum + '))';
			const render = field.render.bind(field);
			field.render = () => E('span', { 'hidden': '' });
			advancedFields.push(render);
		}
		advanced.renderWidget = async id => E('details', {}, [E('summary', {}, [_('Show limits and internal port')]), E('p', {}, [_('These settings affect IPv4 relay publications only. Applying a change closes their active connections; native IPv6 publications keep running.')]), ...(await Promise.all(advancedFields.map((render, index) => render(index, id))))]);
		for (const field of flags) {
			const render = field.renderWidget;
			field.renderWidget = function(...args) {
				return Promise.resolve(render.apply(this, args)).then(node => {
					for (const input of node.querySelectorAll('input[type="checkbox"]')) input.setAttribute('aria-label', this.title);
					return node;
				});
			};
		}
		update();
		return {
			update,
			poll: () => callStatus().then(result => { current = result; update(); }).catch(() => {
				current = { unavailable: true };
				update();
			})
		};
	}
});
