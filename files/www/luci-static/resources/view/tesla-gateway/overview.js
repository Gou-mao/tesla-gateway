'use strict';

'require view';
'require fs';
'require ui';
'require poll';

var INIT = '/etc/init.d/tesla-gateway';
var CONFIG = '/etc/tesla-gateway/config.yaml';
var STATS = '/var/run/tesla-gateway/stats.json';
var NFT = '/usr/sbin/nft';

function readStats() {
	return L.resolveDefault(fs.read(STATS), null).then(function(raw) {
		if (raw == null)
			return null;

		try {
			return JSON.parse(String(raw));
		}
		catch (e) {
			return null;
		}
	});
}

function formatNumber(value) {
	if (value == null || value === '')
		return _('—');

	var num = Number(value);

	if (!isFinite(num))
		return _('—');

	return num.toLocaleString();
}

function formatBytes(value) {
	if (value == null || value === '')
		return _('—');

	var num = Number(value);

	if (!isFinite(num) || num < 0)
		return _('—');

	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var i = 0;

	while (num >= 1024 && i < units.length - 1) {
		num /= 1024;
		i++;
	}

	return (i === 0 ? num.toFixed(0) : num.toFixed(1)) + ' ' + units[i];
}

function formatUptime(value) {
	if (value == null || value === '')
		return _('—');

	var sec = Math.floor(Number(value));

	if (!isFinite(sec) || sec < 0)
		return _('—');

	var days = Math.floor(sec / 86400);
	var hours = Math.floor((sec % 86400) / 3600);
	var minutes = Math.floor((sec % 3600) / 60);
	var seconds = sec % 60;
	var parts = [];

	if (days > 0)
		parts.push(days + 'd');
	if (hours > 0 || days > 0)
		parts.push(hours + 'h');
	if (minutes > 0 || hours > 0 || days > 0)
		parts.push(minutes + 'm');

	parts.push(seconds + 's');

	return parts.join(' ');
}

function getServiceState(result) {
	if (!result)
		return { running: null, text: _('未知') };

	var out = String(result.stdout || '') + '\n' + String(result.stderr || '');
	out = out.trim();

	/* procd/rc.common prints "not running" when the service is stopped. */
	if (/\bnot\s+running\b/i.test(out))
		return { running: false, text: _('已停止') };

	if (/\brunning\b/i.test(out))
		return { running: true, text: _('运行中') };

	return {
		running: result.code === 0,
		text: result.code === 0 ? _('运行中') : _('已停止')
	};
}

function getNftState(result) {
	if (!result)
		return { text: _('未知'), cls: '', title: _('无法执行 nft 状态检查') };

	var out = (String(result.stdout || '') + '\n' + String(result.stderr || '')).trim();

	if (result.code === 0 && /\btable\s+ip\s+teslagateway\b/.test(out))
		return { text: _('已生效'), cls: 'success', title: _('nft 表存在') };

	if (/no such file|does not exist|not found|not exist/i.test(out))
		return { text: _('未下发'), cls: 'warning', title: out };

	return {
		text: _('未生效'),
		cls: 'warning',
		title: out || (_('nft 退出码 ') + result.code)
	};
}

function commandFailure(result) {
	var detail = '';

	if (result) {
		detail = (String(result.stderr || '') + '\n' + String(result.stdout || '')).trim();
		if (detail)
			return detail;
	}

	return _('命令失败，退出码 ') + (result && result.code != null ? result.code : '?');
}

function tableRow(label, value) {
	return E('tr', [
		E('td', { 'class': 'td', 'style': 'width: 34%;' }, [ label ]),
		E('td', { 'class': 'td' }, [ value ])
	]);
}

function table(rows) {
	return E('table', { 'class': 'table' }, [
		E('tbody', rows)
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			readStats(),
			L.resolveDefault(fs.exec(INIT, [ 'status' ]), null),
			L.resolveDefault(fs.read(CONFIG), null),
			L.resolveDefault(fs.exec(NFT, [ 'list', 'table', 'ip', 'teslagateway' ]), null)
		]);
	},

	render: function(data) {
		var stats = data[0];
		var status = data[1];
		var config = data[2];
		var nft = data[3];
		var refs = {};
		var actionState = { busy: false, running: null };
		var root = null;
		var refreshing = false;

		refs.badge = E('span', { 'class': 'label' }, [ _('读取中…') ]);
		refs.version = E('span', {}, [ _('—') ]);
		refs.pid = E('span', {}, [ _('—') ]);
		refs.uptime = E('span', {}, [ _('—') ]);
		refs.dns = E('span', {}, [ _('—') ]);
		refs.proxy = E('span', {}, [ _('—') ]);
		refs.nft = E('span', { 'class': 'label' }, [ _('—') ]);
		refs.updated = E('span', {}, [ _('—') ]);
		refs.queries = E('span', {}, [ _('—') ]);
		refs.hits = E('span', {}, [ _('—') ]);
		refs.misses = E('span', {}, [ _('—') ]);
		refs.entries = E('span', {}, [ _('—') ]);
		refs.upstream = E('span', {}, [ _('—') ]);
		refs.active = E('span', {}, [ _('—') ]);
		refs.total = E('span', {}, [ _('—') ]);
		refs.c2u = E('span', {}, [ _('—') ]);
		refs.u2c = E('span', {}, [ _('—') ]);
		refs.prefixes = E('code', {}, [ _('—') ]);

		var textarea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': 22,
			'spellcheck': 'false',
			'wrap': 'off',
			'style': 'width: 100%; min-height: 24em; font-family: monospace; font-size: 12px;'
		}, [ config != null ? config : '' ]);

		var startBtn = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-apply important'
		}, [ _('启动') ]);
		var stopBtn = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-reset'
		}, [ _('停止') ]);
		var restartBtn = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-action'
		}, [ _('重启') ]);
		var saveBtn = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-apply important'
		}, [ _('保存并重启') ]);

		function syncButtons() {
			startBtn.disabled = actionState.busy || actionState.running === true;
			stopBtn.disabled = actionState.busy || actionState.running === false;
			restartBtn.disabled = actionState.busy;
			saveBtn.disabled = actionState.busy || config == null;
		}

		function applyLive(currentStats, currentStatus, currentNft) {
			var state = getServiceState(currentStatus);
			var nftState = getNftState(currentNft);
			var dns = currentStats && currentStats.dns ? currentStats.dns : {};
			var proxy = currentStats && currentStats.proxy ? currentStats.proxy : {};
			var listeners = currentStats && currentStats.listeners ? currentStats.listeners : {};

			actionState.running = state.running;

			refs.badge.textContent = state.text;
			refs.badge.className = 'label' +
				(state.running === true ? ' success' :
				 state.running === false ? ' danger' : '');

			refs.version.textContent = currentStats && currentStats.version
				? currentStats.version : _('—');
			refs.pid.textContent = currentStats && currentStats.pid != null
				? String(currentStats.pid) : _('—');
			refs.uptime.textContent = currentStats && currentStats.uptime_sec != null
				? formatUptime(currentStats.uptime_sec) : _('—');

			refs.dns.textContent = currentStats
				? (listeners.dns || _('禁用')) : _('—');
			refs.proxy.textContent = currentStats
				? (listeners.proxy || _('禁用')) : _('—');

			refs.nft.textContent = nftState.text;
			refs.nft.className = 'label' + (nftState.cls ? ' ' + nftState.cls : '');

			if (nftState.title)
				refs.nft.title = nftState.title;
			else
				refs.nft.removeAttribute('title');

			refs.queries.textContent = formatNumber(dns.queries);
			refs.hits.textContent = formatNumber(dns.cache_hits);
			refs.misses.textContent = formatNumber(dns.cache_misses);
			refs.entries.textContent = formatNumber(dns.cache_entries);
			refs.upstream.textContent = formatNumber(dns.upstream_queries);

			refs.active.textContent = formatNumber(proxy.active_conns);
			refs.total.textContent = formatNumber(proxy.total_conns);
			refs.c2u.textContent = formatBytes(proxy.bytes_client_to_upstream);
			refs.u2c.textContent = formatBytes(proxy.bytes_upstream_to_client);

			if (!currentStats || !Array.isArray(currentStats.mapped_prefixes))
				refs.prefixes.textContent = _('—');
			else if (currentStats.mapped_prefixes.length === 0)
				refs.prefixes.textContent = _('无（未配置映射）');
			else
				refs.prefixes.textContent = currentStats.mapped_prefixes.join(', ');

			refs.updated.textContent = _('最后更新：') + new Date().toLocaleTimeString();

			syncButtons();
		}

		function reloadSoon(delay) {
			window.setTimeout(function() {
				window.location.reload();
			}, delay);
		}

		function runAction(action, doneText) {
			if (actionState.busy)
				return Promise.resolve();

			actionState.busy = true;
			syncButtons();

			return fs.exec(INIT, [ action ]).then(function(result) {
				if (!result || result.code !== 0)
					throw new Error(commandFailure(result));

				ui.addNotification(null, E('p', {}, [ doneText ]), 'success');
				reloadSoon(900);
			}).catch(function(err) {
				actionState.busy = false;
				syncButtons();
				ui.addNotification(null, E('p', {}, [
					_('操作失败：') + (err && err.message ? err.message : err)
				]), 'danger');
			});
		}

		function saveConfig() {
			if (actionState.busy)
				return Promise.resolve();

			var saved = false;

			actionState.busy = true;
			syncButtons();

			return fs.write(CONFIG, textarea.value).then(function() {
				saved = true;
				return fs.exec(INIT, [ 'restart' ]);
			}).then(function(result) {
				if (!result || result.code !== 0)
					throw new Error(commandFailure(result));

				ui.addNotification(null, E('p', {}, [
					_('配置已保存，服务正在重启。')
				]), 'success');
				reloadSoon(1200);
			}).catch(function(err) {
				actionState.busy = false;
				syncButtons();
				ui.addNotification(null, E('p', {}, [
					(saved ? _('配置已保存，但重启失败：') : _('保存失败：')) +
					(err && err.message ? err.message : err)
				]), 'danger');
			});
		}

		startBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			runAction('start', _('服务已启动。'));
		});

		stopBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			runAction('stop', _('服务已停止。'));
		});

		restartBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			runAction('restart', _('服务已重启。'));
		});

		saveBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			saveConfig();
		});

		function stopPolling() {
			window.setTimeout(function() {
				poll.remove(refresh);
			}, 0);
		}

		function refresh() {
			if (refreshing)
				return Promise.resolve();

			if (!root || !document.body.contains(root)) {
				stopPolling();
				return Promise.resolve();
			}

			refreshing = true;

			return Promise.all([
				readStats(),
				L.resolveDefault(fs.exec(INIT, [ 'status' ]), null),
				L.resolveDefault(fs.exec(NFT, [ 'list', 'table', 'ip', 'teslagateway' ]), null)
			]).then(function(result) {
				if (root && document.body.contains(root))
					applyLive(result[0], result[1], result[2]);
				else
					stopPolling();
			}).catch(function() {
				/* Keep the last known values when a poll fails. */
			}).then(function() {
				refreshing = false;
			});
		}

		var statusTable = table([
			tableRow(_('运行状态'), refs.badge),
			tableRow(_('版本'), refs.version),
			tableRow(_('PID'), refs.pid),
			tableRow(_('运行时间'), refs.uptime),
			tableRow(_('DNS 监听'), refs.dns),
			tableRow(_('代理监听'), refs.proxy),
			tableRow(_('nft 规则'), refs.nft)
		]);

		root = E('div', {}, [
			E('h2', {}, [ _('Tesla Gateway') ]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('服务状态') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('通过 /etc/init.d/tesla-gateway 控制服务，状态每 4 秒自动刷新。')
				]),
				E('div', {
					'class': 'cbi-page-actions',
					'style': 'margin: 1em 0;'
				}, [ startBtn, ' ', stopBtn, ' ', restartBtn ]),
				statusTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('DNS 统计') ]),
				table([
					tableRow(_('查询总数'), refs.queries),
					tableRow(_('缓存命中'), refs.hits),
					tableRow(_('缓存未命中'), refs.misses),
					tableRow(_('缓存条目'), refs.entries),
					tableRow(_('上游查询'), refs.upstream)
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('代理统计') ]),
				table([
					tableRow(_('活动连接'), refs.active),
					tableRow(_('连接总数'), refs.total),
					tableRow(_('客户端 → 上游'), refs.c2u),
					tableRow(_('上游 → 客户端'), refs.u2c)
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('映射前缀') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('来自 stats.json 的 mapped_prefixes（Tesla 所见网段）。')
				]),
				E('div', {}, [ refs.prefixes ])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('配置') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('编辑 /etc/tesla-gateway/config.yaml。保存后会自动重启服务。')
				]),
				config == null
					? E('p', { 'class': 'alert-message warning' }, [
						_('无法读取配置文件，保存前请确认权限。')
					])
					: '',
				textarea,
				E('div', {
					'class': 'cbi-page-actions',
					'style': 'margin-top: 1em;'
				}, [ saveBtn ])
			])
		]);

		applyLive(stats, status, nft);

		poll.add(refresh, 4);

		return root;
	}
});
