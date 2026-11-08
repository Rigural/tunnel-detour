'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require ui';
'require poll';

const callStatus = rpc.declare({ object: 'tunnel-detour', method: 'status', expect: {} });
const callValidate = rpc.declare({ object: 'tunnel-detour', method: 'validate', params: ['patterns'], expect: {} });
const callCheck = rpc.declare({ object: 'tunnel-detour', method: 'check', expect: {} });
const callTestAdguard = rpc.declare({ object: 'tunnel-detour', method: 'test_adguard', params: ['api_url', 'username', 'password'], expect: {} });
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
		deadline_expired: _('A connection or DNS request timed out. Check the DNS resolver and WAN connection.'),
		io_error: _('A network or file operation failed. Check the WAN connection and the service log.'),
		lease_storage_error: _('Saved address mappings could not be read or written. Check available storage and the service log.'),
		dns_error: _('A DNS request failed. Check the configured DNS resolver.'),
		invalid_dns_response: _('The DNS resolver returned an invalid response. Review the resolver in Settings.'),
		no_ipv4_address: _('The destination has no usable IPv4 address. This version supports IPv4 exceptions.'),
		dns_alias_loop: _('The destination has a DNS alias loop. Check the domain and its DNS records.'),
		forbidden_destination: _('A private or router-local destination was blocked to protect the network.'),
		filtered_destination: _('AdGuard blocked or rewrote the destination. Review its filtering rules if this was unexpected.'),
		unauthorized_source: _('A client outside the selected LAN was rejected. Review the LAN selection in Settings.'),
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
		description = result.running ? _('The service is finishing its shutdown.') : _('Enable Tunnel Detour for AdGuard Home in Settings to use exceptions.');
	}
	else if (!result.running || status.phase === 'failed') {
		state = status.phase === 'failed' ? _('Error') : _('Stopped');
		description = _('The service is enabled but is not serving exceptions. Review Settings and restart the service.');
		severity = 'warning';
	}
	else if (status.phase === 'ready') {
		state = _('Running');
		description = _('The service is ready to handle exception traffic.');
		severity = 'success';
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
		const ip = connection.client.split(':')[0];
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
		status.last_error && result.enabled !== false ? E('p', {}, [_('Last recorded issue: %s').format(errorMessage(status.last_error))]) : [],
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
		return Promise.all([uci.load('tunnel-detour'), callStatus(), callNetworks(), callDevices(4).catch(() => []), uci.changes()]);
	},

	render(data) {
		const map = new form.Map('tunnel-detour', _('Tunnel Detour for AdGuard Home'), _('Send selected HTTP and HTTPS hostnames through WAN using AdGuard Home integration. Other traffic keeps its existing route.'));
		map.tabbed = true;
		let currentStatus = data[1];
		let devices = data[3];
		let pending = !!data[4]['tunnel-detour']?.length;
		let dirty = false;
		let formBaseline;
		const formSnapshot = () => JSON.stringify([...map.root.querySelectorAll('input, select')].map(field => [field.id, field.type === 'checkbox' ? field.checked : field.value]));
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
			const state = serviceState(currentStatus);
			banner.className = 'td-banner alert-message ' + state.severity;
			const changes = dirty ? _('Unsaved edits — Save & Apply to activate them.') : pending ? _('Saved changes pending — Save & Apply to activate them.') : _('Applied configuration');
			if (banner.textContent !== state.state + changes)
				banner.replaceChildren(E('strong', {}, [state.state]), E('span', {}, [changes]));
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
		const group = (key, title, description) => {
			const subsection = settingsSection.option(form.SectionValue, key, form.NamedSection, 'globals', 'globals').subsection;
			subsection.render = function() {
				return this.renderUCISection('globals').then(fields => E('fieldset', { 'class': 'td-settings-group' }, [E('legend', {}, [title]), description ? E('p', {}, [description]) : [], fields]));
			};
			return subsection;
		};
		let section = group('_service', _('Service and networks'));
		let option = section.option(form.Flag, 'enabled', _('Enable service'));
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
		option = section.option(form.Value, 'real_upstream', _('DNS resolver'), _('Resolver for real destination addresses, separate from AdGuard. IPv4 address with optional :port; uses the router’s existing route.'));
		option.rmempty = false;
		section = group('_adguard', _('AdGuard connection'), _('Connect to AdGuard Home on this router. Other AdGuard settings stay unchanged.'));
		const adguardUrl = option = section.option(form.Value, 'adguard_url', _('API address'), _('HTTP address of AdGuard on this router.'));
		option.rmempty = false;
		const adguardUsername = option = section.option(form.Value, 'adguard_username', _('Username'));
		option.optional = true;
		option.rmempty = true;
		const adguardPassword = option = section.option(form.Value, 'adguard_password', _('Password'));
		option.optional = true;
		option.password = true;
		option.rmempty = true;
		const testResult = E('p', { 'class': 'td-test-result', 'role': 'status', 'aria-live': 'polite' });
		const testButton = E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
			const draft = [adguardUrl, adguardUsername, adguardPassword].map(field => field.formvalue('globals') || '');
			testResult.textContent = _('Testing the form values…');
			try {
				const result = await callTestAdguard(...draft);
				if ([adguardUrl, adguardUsername, adguardPassword].some((field, index) => (field.formvalue('globals') || '') !== draft[index])) {
					testResult.textContent = _('The form changed during the test. Test the current values again. Nothing was saved or applied.');
					return;
				}
				const message = !result.connected ? errorMessage(result.error) : !result.health?.dns_running ? _('Connected, but AdGuard DNS is stopped.') : !result.health.protection_enabled ? _('Connected. DNS is running, but protection is disabled.') : _('Connected. AdGuard DNS and protection are enabled.');
				testResult.textContent = message + ' ' + _('Tested the form values. Nothing was saved or applied.');
			} catch (_) {
				testResult.textContent = _('The connection test failed. Nothing was saved or applied. Try again.');
			}
		}) }, [_('Test AdGuard connection')]);
		const testSection = section.option(form.SectionValue, '_test', form.NamedSection, 'globals', 'globals').subsection;
		testSection.render = () => Promise.resolve(E('div', { 'class': 'td-connection-test' }, [testButton, testResult, E('p', { 'class': 'td-help' }, [_('Uses the values above without saving or changing the running service.')])]));
		const advanced = settingsSection.option(form.SectionValue, '_advanced', form.NamedSection, 'globals', 'globals').subsection;
		advanced.render = function() {
			return this.renderUCISection('globals').then(fields => E('details', { 'class': 'cbi-section' }, [E('summary', {}, [_('Advanced')]), fields]));
		};
		for (const field of [['dns_port', _('Internal DNS port')], ['proxy_port', _('Transparent TCP port')]]) {
			option = advanced.option(form.Value, field[0], field[1]);
			option.datatype = 'port';
			option.rmempty = false;
		}

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
			for (const id of added) uci.remove('tunnel-detour', id);
			added.clear(); removed.clear(); rowErrors.clear(); normalizedPatterns.clear();
			dirty = false; updateUndo();
			return reset();
		};
		const checks = E('div', { 'class': 'cbi-section' }, [
			E('p', { 'class': 'td-help' }, [_('Checks the configuration currently applied to the service, including networks and ports.')]),
			E('button', { 'class': 'cbi-button cbi-button-action', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
				const result = await callCheck();
				ui.addNotification(null, E('p', {}, [result.valid ? _('Applied configuration is valid. Use the AdGuard connection test to verify access.') : errorMessage(result.error)]));
			}) }, [_('Check applied configuration')])
		]);
		const checkSection = settingsSection.option(form.SectionValue, '_checks', form.NamedSection, 'globals', 'globals').subsection;
		checkSection.render = () => Promise.resolve(checks);
		statusSection.render = () => Promise.resolve(E('div', { 'class': 'cbi-section', 'data-tab': 'status', 'data-tab-title': _('Status') }, [
			E('h3', {}, [_('Status and active connections')]), status, actions
		]));
		// LuCI re-renders this map after staging changes or adding a row.
		const renderContents = map.renderContents.bind(map);
		map.renderContents = () => {
			rowFeedback.clear(); rowExamples.clear();
			return renderContents().then(node => {
				for (const button of [testButton, ...checks.querySelectorAll('button')])
					button.disabled = map.readonly === true;
				for (const row of node.querySelectorAll('[data-sid]')) labelRow(row);
				formBaseline = formSnapshot();
				updateState(); scheduleValidation();
				return node;
			});
		};
		poll.add(() => Promise.all([callStatus(), uci.changes()]).then(([result, changes]) => {
			currentStatus = result; pending = !!changes['tunnel-detour']?.length; updateState();
		}).catch(() => {
			banner.className = 'td-banner alert-message warning';
			banner.textContent = _('Service status unavailable. Refresh to try again; form edits have not been applied.');
		}), 3);
		poll.add(() => callDevices(4).then(result => { devices = result; }).catch(() => { devices = []; }), 30);
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
