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
const callRestart = rpc.declare({ object: 'tunnel-detour', method: 'restart', expect: {} });

function displayStatus(node, result) {
	const status = result.status || {};
	const connections = Object.values(status.connections || {});
	const phase = result.running ? (status.phase || _('Starting')) : _('Stopped');
	const rows = connections.map(connection => E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td' }, [connection.domain]),
		E('td', { 'class': 'td' }, [connection.client]),
		E('td', { 'class': 'td' }, [connection.destination])
	]));
	if (!rows.length)
		rows.push(E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': 3 }, [_('No active exception connections.')])]));
	node.replaceChildren(
		E('p', {}, [_('Service: %s').format(phase)]),
		E('p', {}, [_('Last error: %s').format(status.last_error || _('None'))]),
		E('p', {}, [_('DNS queries: %s · Completed connections: %s').format(status.dns_queries || 0, status.completed_connections || 0)]),
		E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, [E('th', { 'class': 'th' }, [_('Hostname')]), E('th', { 'class': 'th' }, [_('Client')]), E('th', { 'class': 'th' }, [_('WAN destination')])]),
			...rows
		])
	);
}

return view.extend({
	load() {
		return Promise.all([uci.load('tunnel-detour'), callStatus()]);
	},

	render(data) {
		const map = new form.Map('tunnel-detour', _('Tunnel Detour'), _('Send selected HTTP and HTTPS hostnames through WAN. Other traffic keeps its existing route.'));
		let section = map.section(form.NamedSection, 'globals', 'globals', _('Settings'));
		let option = section.option(form.Flag, 'enabled', _('Enable'));
		option.rmempty = false;
		for (const field of [
			['lan_network', _('LAN network'), 'lan'],
			['wan_network', _('WAN network'), 'wan']
		]) {
			option = section.option(form.Value, field[0], field[1]);
			option.placeholder = field[2];
			option.datatype = 'uciname';
			option.rmempty = false;
		}
		option = section.option(form.Value, 'real_upstream', _('Real DNS upstream'), _('IPv4 address, optionally followed by :port. Use a resolver separate from AdGuard. Queries follow the existing router route.'));
		option.rmempty = false;
		option = section.option(form.Value, 'adguard_url', _('AdGuard control URL'), _('Local IPv4 loopback HTTP endpoint.'));
		option.rmempty = false;
		option = section.option(form.Value, 'adguard_username', _('AdGuard username'));
		option.optional = true;
		option.rmempty = true;
		option = section.option(form.Value, 'adguard_password', _('AdGuard password'));
		option.optional = true;
		option.password = true;
		option.rmempty = true;
		for (const field of [['dns_port', _('Internal DNS port')], ['proxy_port', _('Transparent TCP port')]]) {
			option = section.option(form.Value, field[0], field[1]);
			option.datatype = 'port';
			option.rmempty = false;
		}

		section = map.section(form.TableSection, 'exception', _('Exceptions'), _('One rule per row. example.test matches exactly; *.example.test matches one subdomain level; **.example.test matches all subdomain levels; ***.example.test also includes the root. Rules combine; a narrower rule does not cancel a broader rule.'));
		section.anonymous = true;
		section.addremove = true;
		option = section.option(form.Flag, 'enabled', _('Enabled'));
		option.default = '1';
		option.rmempty = false;
		option = section.option(form.Value, 'pattern', _('Domain rule'));
		option.placeholder = '***.example.test';
		option.rmempty = false;

		const rulesSection = section;
		const patternOption = option;
		const parse = map.parse.bind(map);
		map.parse = async function() {
			const lines = rulesSection.cfgsections().map(id => patternOption.formvalue(id) ?? uci.get('tunnel-detour', id, 'pattern')).filter(pattern => pattern != null).join('\n');
			const result = await callValidate(lines);
			if (!result.valid)
				throw new Error(result.error || _('Invalid domain rules.'));
			return parse();
		};

		const status = E('div', { 'class': 'cbi-section' });
		displayStatus(status, data[1]);
		poll.add(() => callStatus().then(result => displayStatus(status, result)).catch(() => {
			status.replaceChildren(E('p', {}, [_('Service status could not be read.')]));
		}), 3);

		const actions = E('div', { 'class': 'cbi-section' }, [
			E('button', { 'class': 'cbi-button cbi-button-action', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
				const result = await callCheck();
				ui.addNotification(null, E('p', {}, [result.valid ? _('Applied configuration is valid. This does not check AdGuard connectivity.') : _('Configuration check failed: %s').format(result.error)]));
			}) }, [_('Check applied configuration')]),
			' ',
			E('button', { 'class': 'cbi-button cbi-button-action', 'disabled': true, 'click': ui.createHandlerFn(this, async () => {
				const result = await callRestart();
				if (!result.accepted)
					throw new Error(_('Service restart could not be requested.'));
			}) }, [_('Restart service')])
		]);
		return map.render().then(node => {
			for (const button of actions.querySelectorAll('button'))
				button.disabled = map.readonly === true;
			return E('div', {}, [node, E('h3', {}, [_('Status and active connections')]), status, actions]);
		});
	}
});
