'use strict';

'require view';
'require fs';
'require ui';
'require poll';
'require uci';

var INIT = '/etc/init.d/tesla-gateway';
var CONFIG = '/etc/tesla-gateway/config.yaml';
var STATS = '/var/run/tesla-gateway/stats.json';
var NFT = '/usr/sbin/nft';
var TG_BIN = '/usr/sbin/tesla-gateway';

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

function loadUCI() {
	return Promise.all([
		uci.load('dhcp').then(function() { return true; }).catch(function() { return false; }),
		uci.load('network').then(function() { return true; }).catch(function() { return false; })
	]).then(function(loaded) {
		return { dhcp: loaded[0], network: loaded[1] };
	});
}

function uciGet(config, section, option) {
	try {
		return uci.get(config, section, option);
	}
	catch (e) {
		return null;
	}
}

function firstValue(value) {
	if (Array.isArray(value))
		return value.length ? value[0] : null;
	return value;
}

function asList(value) {
	if (value == null || value === '')
		return [];

	if (Array.isArray(value))
		return value.map(function(item) { return String(item); });

	return String(value).split(/\s+/).filter(function(item) { return item !== ''; });
}

function uniqueValues(values) {
	var result = [];

	values.forEach(function(value) {
		if (result.indexOf(value) < 0)
			result.push(value);
	});

	return result;
}

function getDhcpOptionValues(options, number) {
	var wanted = String(number);
	var values = [];

	asList(options).forEach(function(entry) {
		asList(entry).forEach(function(part) {
			var text = part.trim();
			var comma = text.indexOf(',');
			var colon = text.indexOf(':');
			var sep = comma >= 0 ? comma : colon;

			if (sep < 0 || text.slice(0, sep).trim() !== wanted)
				return;

			text.slice(sep + 1).split(',').forEach(function(value) {
				value = value.trim();
				if (value)
					values.push(value);
			});
		});
	});

	return uniqueValues(values);
}

function parseIPv4(value) {
	if (value == null)
		return null;

	var parts = String(value).trim().split('.');

	if (parts.length !== 4)
		return null;

	var octets = [];

	for (var i = 0; i < parts.length; i++) {
		if (!/^\d{1,3}$/.test(parts[i]))
			return null;

		var octet = Number(parts[i]);

		if (octet < 0 || octet > 255)
			return null;

		octets.push(octet);
	}

	return octets;
}

function isIPv4Text(value) {
	var text = String(value == null ? '' : value).trim();

	/* Reject leading zeros so the frontend matches netip.ParseAddr in Go. */
	if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(text))
		return false;

	return parseIPv4(text) != null;
}

function isIPv6Text(value) {
	var text = String(value == null ? '' : value).trim();
	var zone = text.indexOf('%');

	if (zone >= 0) {
		if (zone === 0 || zone === text.length - 1 || text.indexOf('%', zone + 1) >= 0)
			return false;

		text = text.slice(0, zone);
	}

	if (text.indexOf(':') < 0 || !/^[0-9A-Fa-f:.]+$/.test(text))
		return false;

	function countGroups(part) {
		if (part === '')
			return 0;

		var groups = part.split(':');
		var count = 0;

		for (var i = 0; i < groups.length; i++) {
			var group = groups[i];

			if (group === '')
				return -1;

			if (group.indexOf('.') >= 0) {
				if (i !== groups.length - 1 || !isIPv4Text(group))
					return -1;

				count += 2;
			}
			else {
				if (!/^[0-9A-Fa-f]{1,4}$/.test(group))
					return -1;

				count++;
			}
		}

		return count;
	}

	var halves = text.split('::');

	if (halves.length > 2)
		return false;

	var head = countGroups(halves[0]);

	if (head < 0)
		return false;

	if (halves.length === 2) {
		var tail = countGroups(halves[1]);

		if (tail < 0)
			return false;

		return head + tail <= 7;
	}

	return head === 8;
}

function normalizeUpstreamValue(value) {
	var text = String(value == null ? '' : value).trim();
	var lower = text.toLowerCase();

	return (lower === 'dhcp' || lower === 'auto') ? lower : text;
}

function isValidUpstreamValue(value) {
	var text = normalizeUpstreamValue(value);

	if (text === 'dhcp' || text === 'auto')
		return true;

	return isIPv4Text(text) || isIPv6Text(text);
}

function upstreamKey(value) {
	var text = normalizeUpstreamValue(value).toLowerCase();

	/* dhcp and auto are aliases and must not be stored twice. */
	return (text === 'auto' || text === 'dhcp') ? 'dhcp' : text;
}

function parseCIDR(value) {
	var parts = String(value == null ? '' : value).trim().split('/');

	if (parts.length > 2)
		return null;

	var octets = parseIPv4(parts[0]);

	if (!octets)
		return null;

	var bits = null;

	if (parts.length === 2) {
		if (!/^\d{1,2}$/.test(parts[1]))
			return null;

		bits = Number(parts[1]);

		if (bits < 0 || bits > 32)
			return null;
	}

	return { octets: octets, bits: bits };
}

function netmaskToBits(value) {
	var octets = parseIPv4(value);

	if (!octets)
		return null;

	var bits = 0;
	var zeroSeen = false;

	for (var i = 0; i < octets.length; i++) {
		for (var bit = 7; bit >= 0; bit--) {
			var one = ((octets[i] >> bit) & 1) === 1;

			if (one) {
				if (zeroSeen)
					return null;
				bits++;
			}
			else {
				zeroSeen = true;
			}
		}
	}

	return bits;
}

function ipv4ToInt(octets) {
	return octets[0] * 16777216 + octets[1] * 65536 + octets[2] * 256 + octets[3];
}

function intToIPv4(value) {
	value = Math.floor(value);

	return [
		Math.floor(value / 16777216) % 256,
		Math.floor(value / 65536) % 256,
		Math.floor(value / 256) % 256,
		value % 256
	].join('.');
}

function positiveInt(value, fallback) {
	var number = Number(value);

	if (!isFinite(number) || number <= 0)
		return fallback;

	return Math.floor(number);
}

function formatLease(value) {
	if (value == null || value === '')
		return _('—');

	var text = String(value).trim();

	return text === '0' ? _('永久') : text;
}

function computeDHCPInfo() {
	var ipValue = firstValue(uciGet('network', 'lan', 'ipaddr'));
	var netmaskValue = firstValue(uciGet('network', 'lan', 'netmask'));
	var parsed = parseCIDR(ipValue);
	var bits = parsed && parsed.bits != null ? parsed.bits : netmaskToBits(netmaskValue);
	var gateway = parsed ? intToIPv4(ipv4ToInt(parsed.octets)) : '';
	var start = positiveInt(uciGet('dhcp', 'lan', 'start'), 100);
	var limit = positiveInt(uciGet('dhcp', 'lan', 'limit'), 150);
	var pool = _('—');

	if (bits == null)
		bits = 24;

	if (parsed) {
		var ip = ipv4ToInt(parsed.octets);
		var block = Math.pow(2, 32 - bits);
		var network = Math.floor(ip / block) * block;
		var broadcast = network + block - 1;
		var first = network + start;
		var last = first + limit - 1;
		var lastUsable = bits >= 31 ? broadcast : broadcast - 1;

		if (first >= network && first <= lastUsable) {
			if (last > lastUsable)
				last = lastUsable;

			pool = intToIPv4(first) + ' – ' + intToIPv4(last);
		}
	}

	var options = uciGet('dhcp', 'lan', 'dhcp_option');
	var dnsValues = getDhcpOptionValues(options, 6);
	var routerValues = getDhcpOptionValues(options, 3);

	return {
		gateway: gateway || _('—'),
		pool: pool,
		lease: formatLease(uciGet('dhcp', 'lan', 'leasetime')),
		dns: dnsValues.length
			? dnsValues.join(', ')
			: (gateway ? _('本机 ') + gateway + _('（默认）') : _('本机（默认）')),
		router: routerValues.length
			? routerValues.join(', ')
			: (gateway || _('—'))
	};
}

function cidrWildcard(octets, bits) {
	if (bits % 8 !== 0)
		return null;

	var fixed = bits / 8;
	var parts = [];

	for (var i = 0; i < fixed; i++)
		parts.push(String(octets[i]));

	for (var j = fixed; j < 4; j++)
		parts.push('X');

	return parts.join('.');
}

function explainMapping(from, to) {
	var source = parseCIDR(from);
	var target = parseCIDR(to);

	if (source && target && source.bits != null && target.bits != null &&
	    source.bits === target.bits) {
		var sourceText = cidrWildcard(source.octets, source.bits);
		var targetText = cidrWildcard(target.octets, target.bits);

		if (sourceText && targetText &&
		    (sourceText.indexOf('X') >= 0 || targetText.indexOf('X') >= 0))
			return sourceText + _(' 在 Tesla 上访问时显示为 ') + targetText;
	}

	return String(from) + _(' 内的地址在 Tesla 上显示为 ') +
		String(to) + _(' 内的对应地址');
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

function formatStrategy(value) {
	if (value == null || value === '')
		return _('—');

	if (value === 'prefix')
		return _('prefix（前缀替换）');

	return String(value);
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
			L.resolveDefault(fs.exec(NFT, [ 'list', 'table', 'ip', 'teslagateway' ]), null),
			loadUCI()
		]);
	},

	render: function(data) {
		var stats = data[0];
		var status = data[1];
		var config = data[2];
		var nft = data[3];
		var uciState = data[4];
		var refs = {};
		var actionState = { busy: false, running: null };
		var upstreamItems = [];
		var upstreamInitialized = false;
		var upstreamDirty = false;
		var upstreamPending = null;
		var root = null;
		var refreshing = false;

		refs.badge = E('span', { 'class': 'label' }, [ _('读取中…') ]);
		refs.version = E('span', {}, [ _('—') ]);
		refs.pid = E('span', {}, [ _('—') ]);
		refs.uptime = E('span', {}, [ _('—') ]);
		refs.proxy = E('span', {}, [ _('—') ]);
		refs.nft = E('span', { 'class': 'label' }, [ _('—') ]);
		refs.updated = E('span', {}, [ _('—') ]);
		refs.mappings = E('tbody', {});
		refs.dhcpWarning = E('p', {
			'class': 'alert-message warning',
			'style': 'display: none;'
		}, [ _('未能读取 UCI 的 dhcp/network 配置，以下 DHCP 信息可能不完整。') ]);
		refs.dhcpGateway = E('span', {}, [ _('—') ]);
		refs.dhcpPool = E('span', {}, [ _('—') ]);
		refs.dhcpLease = E('span', {}, [ _('—') ]);
		refs.dhcpDNS = E('span', {}, [ _('—') ]);
		refs.dhcpRouter = E('span', {}, [ _('—') ]);
		refs.dnsListen = E('span', {}, [ _('—') ]);
		refs.dnsUpstreamList = E('div', {});
		refs.dnsUpstreamError = E('div', {
			'style': 'display: none; color: #d9534f; margin-top: .35em;'
		});
		refs.dnsUpstreamInput = E('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'placeholder': _('IPv4 / IPv6 或 dhcp'),
			'style': 'flex: 1; min-width: 12em;'
		});
		refs.dnsUpstreamAdd = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-add',
			'style': 'margin-left: .4em;'
		}, [ _('添加') ]);
		refs.dnsUpstreamSave = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-apply important'
		}, [ _('保存') ]);
		refs.dnsUpstream = E('div', {}, [
			E('p', {
				'class': 'cbi-value-description',
				'style': 'margin: 0 0 .5em;'
			}, [ _('按从上到下的顺序尝试上游，序号即优先级。') ]),
			refs.dnsUpstreamList,
			refs.dnsUpstreamError,
			E('div', {
				'style': 'display: flex; align-items: center; gap: .4em; margin-top: .5em;'
			}, [ refs.dnsUpstreamInput, refs.dnsUpstreamAdd ]),
			E('div', { 'style': 'margin-top: .5em;' }, [ refs.dnsUpstreamSave ])
		]);
		refs.dnsUpstreamEffective = E('span', {}, [ _('—') ]);
		refs.mappingStrategy = E('span', {}, [ _('—') ]);
		refs.queries = E('span', {}, [ _('—') ]);
		refs.hits = E('span', {}, [ _('—') ]);
		refs.misses = E('span', {}, [ _('—') ]);
		refs.entries = E('span', {}, [ _('—') ]);
		refs.active = E('span', {}, [ _('—') ]);
		refs.total = E('span', {}, [ _('—') ]);
		refs.c2u = E('span', {}, [ _('—') ]);
		refs.u2c = E('span', {}, [ _('—') ]);

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
			refs.dnsUpstreamInput.disabled = actionState.busy;
			refs.dnsUpstreamAdd.disabled = actionState.busy;
			refs.dnsUpstreamSave.disabled = actionState.busy;
		}

		function renderMappings(mappings) {
			while (refs.mappings.firstChild)
				refs.mappings.removeChild(refs.mappings.firstChild);

			if (mappings == null) {
				refs.mappings.appendChild(E('tr', [
					E('td', { 'class': 'td', 'colspan': '4' }, [
						_('无法读取 stats.json，暂时无法显示映射。')
					])
				]));
				return;
			}

			if (mappings.length === 0) {
				refs.mappings.appendChild(E('tr', [
					E('td', { 'class': 'td', 'colspan': '4' }, [
						_('未配置映射。请在下方设置中填写 mappings。')
					])
				]));
				return;
			}

			mappings.forEach(function(mapping) {
				var from = mapping && mapping.from ? String(mapping.from) : '—';
				var to = mapping && mapping.to ? String(mapping.to) : '—';

				refs.mappings.appendChild(E('tr', [
					E('td', { 'class': 'td' }, [ E('code', {}, [ from ]) ]),
					E('td', { 'class': 'td', 'style': 'text-align: center;' }, [ '⇄' ]),
					E('td', { 'class': 'td' }, [ E('code', {}, [ to ]) ]),
					E('td', { 'class': 'td' }, [ explainMapping(from, to) ])
				]));
			});
		}

		function setUpstreamError(message) {
			if (message) {
				refs.dnsUpstreamError.textContent = message;
				refs.dnsUpstreamError.style.display = '';
			}
			else {
				refs.dnsUpstreamError.textContent = '';
				refs.dnsUpstreamError.style.display = 'none';
			}
		}

		function sameUpstreamList(left, right) {
			if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length)
				return false;

			for (var i = 0; i < left.length; i++) {
				if (String(left[i]) !== String(right[i]))
					return false;
			}

			return true;
		}

		function renderUpstreamEditor() {
			while (refs.dnsUpstreamList.firstChild)
				refs.dnsUpstreamList.removeChild(refs.dnsUpstreamList.firstChild);

			if (!upstreamItems.length) {
				refs.dnsUpstreamList.appendChild(E('div', {
					'class': 'cbi-value-description',
					'style': 'font-style: italic;'
				}, [ _('列表为空。请输入 IP 或 dhcp 后点击「添加」。') ]));
			}

			upstreamItems.forEach(function(value, index) {
				var upBtn = E('button', {
					'type': 'button',
					'class': 'cbi-button cbi-button-neutral',
					'title': _('上移'),
					'style': 'margin-left: .35em; padding: 0 .45em;'
				}, [ '↑' ]);
				var downBtn = E('button', {
					'type': 'button',
					'class': 'cbi-button cbi-button-neutral',
					'title': _('下移'),
					'style': 'margin-left: .35em; padding: 0 .45em;'
				}, [ '↓' ]);
				var deleteBtn = E('button', {
					'type': 'button',
					'class': 'cbi-button cbi-button-reset',
					'title': _('删除'),
					'style': 'margin-left: .35em;'
				}, [ _('删除') ]);

				upBtn.disabled = actionState.busy || index === 0;
				downBtn.disabled = actionState.busy || index === upstreamItems.length - 1;
				deleteBtn.disabled = actionState.busy;

				upBtn.addEventListener('click', function(ev) {
					ev.preventDefault();
					moveUpstreamItem(index, -1);
				});
				downBtn.addEventListener('click', function(ev) {
					ev.preventDefault();
					moveUpstreamItem(index, 1);
				});
				deleteBtn.addEventListener('click', function(ev) {
					ev.preventDefault();
					removeUpstreamItem(index);
				});

				refs.dnsUpstreamList.appendChild(E('div', {
					'style': 'display: flex; align-items: center; padding: .25em 0; border-bottom: 1px solid rgba(0, 0, 0, .06);'
				}, [
					E('span', {
						'style': 'min-width: 2em; color: #666;'
					}, [ String(index + 1) + '.' ]),
					E('code', {
						'style': 'flex: 1; word-break: break-all;'
					}, [ value ]),
					upBtn,
					downBtn,
					deleteBtn
				]));
			});
		}

		function moveUpstreamItem(index, offset) {
			var target = index + offset;

			if (actionState.busy || target < 0 || target >= upstreamItems.length)
				return;

			var item = upstreamItems[index];
			upstreamItems[index] = upstreamItems[target];
			upstreamItems[target] = item;
			upstreamDirty = true;
			upstreamPending = null;
			setUpstreamError('');
			renderUpstreamEditor();
		}

		function removeUpstreamItem(index) {
			if (actionState.busy)
				return;

			upstreamItems.splice(index, 1);
			upstreamDirty = true;
			upstreamPending = null;
			setUpstreamError(upstreamItems.length ? '' : _('DNS 上游列表不能为空，请至少添加一项。'));
			renderUpstreamEditor();
		}

		function addUpstreamItem() {
			if (actionState.busy)
				return;

			var value = normalizeUpstreamValue(refs.dnsUpstreamInput.value);

			if (!value) {
				setUpstreamError(_('请输入 IP 地址或 dhcp/auto。'));
				return;
			}

			if (!isValidUpstreamValue(value)) {
				setUpstreamError(_('无效的 DNS 上游：') + value +
					_('（请输入 IPv4/IPv6 地址或 dhcp/auto）'));
				return;
			}

			for (var i = 0; i < upstreamItems.length; i++) {
				if (upstreamKey(upstreamItems[i]) === upstreamKey(value)) {
					setUpstreamError(_('该上游已在列表中。'));
					return;
				}
			}

			upstreamItems.push(value);
			upstreamDirty = true;
			upstreamPending = null;
			refs.dnsUpstreamInput.value = '';
			setUpstreamError('');
			renderUpstreamEditor();
			refs.dnsUpstreamInput.focus();
		}

		function validateUpstreamItems() {
			if (!upstreamItems.length) {
				setUpstreamError(_('DNS 上游列表不能为空，请至少添加一项。'));
				return false;
			}

			for (var i = 0; i < upstreamItems.length; i++) {
				if (!isValidUpstreamValue(upstreamItems[i])) {
					setUpstreamError(_('第 ') + (i + 1) + _(' 项无效：') +
						upstreamItems[i] + _('（须为 IPv4/IPv6 地址或 dhcp/auto）'));
					return false;
				}
			}

			setUpstreamError('');
			return true;
		}

		function syncUpstreamFromStats(list) {
			var next = Array.isArray(list)
				? list.map(function(item) { return String(item); })
				: [];

			if (!upstreamInitialized) {
				upstreamInitialized = true;

				if (upstreamDirty)
					return;

				upstreamItems = next;
				upstreamPending = null;
				renderUpstreamEditor();
				return;
			}

			if (upstreamDirty) {
				if (upstreamPending != null && sameUpstreamList(next, upstreamPending)) {
					upstreamItems = next;
					upstreamDirty = false;
					upstreamPending = null;
					setUpstreamError('');
					renderUpstreamEditor();
				}
				return;
			}

			if (!sameUpstreamList(upstreamItems, next)) {
				upstreamItems = next;
				renderUpstreamEditor();
			}
		}

		function saveUpstream() {
			if (actionState.busy)
				return Promise.resolve();

			if (!validateUpstreamItems())
				return Promise.resolve();

			var values = [];
			var seen = {};

			upstreamItems.forEach(function(item) {
				var value = normalizeUpstreamValue(item);
				var key = upstreamKey(value);

				if (Object.prototype.hasOwnProperty.call(seen, key))
					return;

				seen[key] = true;
				values.push(value);
			});

			var written = false;
			var restarted = false;

			actionState.busy = true;
			syncButtons();

			return fs.exec(TG_BIN, [
				'--config', CONFIG,
				'--set-upstream', values.join(',')
			]).then(function(result) {
				if (!result || result.code !== 0)
					throw new Error(commandFailure(result));

				written = true;
				return fs.exec(INIT, [ 'restart' ]);
			}).then(function(result) {
				if (!result || result.code !== 0)
					throw new Error(commandFailure(result));

				restarted = true;
				upstreamItems = values.slice();
				upstreamPending = values.slice();
				upstreamDirty = true;
				setUpstreamError('');
				renderUpstreamEditor();
				ui.addNotification(null, E('p', {}, [
					_('DNS 上游已保存，服务正在重启。')
				]), 'success');
				return refresh();
			}).catch(function(err) {
				var message = err && err.message ? err.message : String(err);
				var prefix = written
					? (restarted ? _('配置已写入，但刷新数据失败：') : _('配置已写入，但重启失败：'))
					: _('保存失败：');

				actionState.busy = false;
				syncButtons();
				setUpstreamError(prefix + message);
				ui.addNotification(null, E('p', {}, [
					_('保存 DNS 上游失败：') + message
				]), 'danger');
			}).then(function() {
				actionState.busy = false;
				syncButtons();
			});
		}

		function applyDHCP() {
			var info = computeDHCPInfo();

			refs.dhcpGateway.textContent = info.gateway;
			refs.dhcpPool.textContent = info.pool;
			refs.dhcpLease.textContent = info.lease;
			refs.dhcpDNS.textContent = info.dns;
			refs.dhcpRouter.textContent = info.router;

			if (!uciState || !uciState.dhcp || !uciState.network)
				refs.dhcpWarning.style.display = '';
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
			refs.proxy.textContent = currentStats
				? (listeners.proxy || _('禁用')) : _('—');

			refs.nft.textContent = nftState.text;
			refs.nft.className = 'label' + (nftState.cls ? ' ' + nftState.cls : '');

			if (nftState.title)
				refs.nft.title = nftState.title;
			else
				refs.nft.removeAttribute('title');

			renderMappings(currentStats && Array.isArray(currentStats.mappings)
				? currentStats.mappings : (currentStats ? [] : null));

			var upstream = currentStats && Array.isArray(currentStats.dns_upstream)
				? currentStats.dns_upstream : [];
			var upstreamEffective = currentStats && Array.isArray(currentStats.dns_upstream_effective)
				? currentStats.dns_upstream_effective : [];

			refs.dnsListen.textContent = currentStats
				? (currentStats.dns_listen || listeners.dns || _('禁用'))
				: _('—');
			if (currentStats && Array.isArray(currentStats.dns_upstream))
				syncUpstreamFromStats(upstream);
			refs.dnsUpstreamEffective.textContent = currentStats
				? (upstreamEffective.length
					? upstreamEffective.join(', ')
					: _('无（dhcp 未解析到地址）'))
				: _('—');
			refs.mappingStrategy.textContent = currentStats
				? formatStrategy(currentStats.mapping_strategy)
				: _('—');

			refs.queries.textContent = formatNumber(dns.queries);
			refs.hits.textContent = formatNumber(dns.cache_hits);
			refs.misses.textContent = formatNumber(dns.cache_misses);
			refs.entries.textContent = formatNumber(dns.cache_entries);
			refs.active.textContent = formatNumber(proxy.active_conns);
			refs.total.textContent = formatNumber(proxy.total_conns);
			refs.c2u.textContent = formatBytes(proxy.bytes_client_to_upstream);
			refs.u2c.textContent = formatBytes(proxy.bytes_upstream_to_client);
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

		refs.dnsUpstreamAdd.addEventListener('click', function(ev) {
			ev.preventDefault();
			addUpstreamItem();
		});

		refs.dnsUpstreamSave.addEventListener('click', function(ev) {
			ev.preventDefault();
			saveUpstream();
		});

		refs.dnsUpstreamInput.addEventListener('keydown', function(ev) {
			if (ev.key === 'Enter' || ev.keyCode === 13) {
				ev.preventDefault();
				addUpstreamItem();
			}
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
			tableRow(_('代理监听'), refs.proxy),
			tableRow(_('nft 转发规则'), refs.nft)
		]);

		var mappingTable = E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', {}, [
					E('th', { 'class': 'th' }, [ _('真实网段') ]),
					E('th', { 'class': 'th', 'style': 'width: 2em; text-align: center;' }, [ '⇄' ]),
					E('th', { 'class': 'th' }, [ _('Tesla 可见网段') ]),
					E('th', { 'class': 'th' }, [ _('白话说明') ])
				])
			]),
			refs.mappings
		]);

		var dhcpTable = table([
			tableRow(_('网关（br-lan）'), refs.dhcpGateway),
			tableRow(_('地址池'), refs.dhcpPool),
			tableRow(_('租期'), refs.dhcpLease),
			tableRow(_('下发的 DNS'), refs.dhcpDNS),
			tableRow(_('下发网关'), refs.dhcpRouter)
		]);

		var dnsTable = table([
			tableRow(_('监听地址'), refs.dnsListen),
			tableRow(_('DNS 上游（配置）'), refs.dnsUpstream),
			tableRow(_('上游服务器（实际生效）'), refs.dnsUpstreamEffective),
			tableRow(_('映射策略'), refs.mappingStrategy)
		]);

		var statsTable = table([
			tableRow(_('DNS 查询总数'), refs.queries),
			tableRow(_('缓存命中'), refs.hits),
			tableRow(_('缓存未命中'), refs.misses),
			tableRow(_('缓存条目'), refs.entries),
			tableRow(_('活动连接'), refs.active),
			tableRow(_('连接总数'), refs.total),
			tableRow(_('客户端 → 上游'), refs.c2u),
			tableRow(_('上游 → 客户端'), refs.u2c)
		]);

		root = E('div', {}, [
			E('h2', {}, [ _('Tesla Gateway') ]),
			E('p', { 'class': 'cbi-value-description' }, [
				_('这里展示实际生效的转发关系，以及 DHCP / DNS 下发给客户端的内容；运行统计放在页面末尾。')
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('状态') ]),
				E('div', {
					'class': 'cbi-page-actions',
					'style': 'margin: 1em 0;'
				}, [ startBtn, ' ', stopBtn, ' ', restartBtn ]),
				statusTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('转发映射 —— 什么变成什么') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('左侧是家庭网络里的真实地址，右侧是 Tesla 看到的映射地址；中间一一对应转发。')
				]),
				mappingTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('DHCP 下发') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('根据 LuCI 当前的 dhcp/network 配置计算，客户端续租后生效。')
				]),
				refs.dhcpWarning,
				dhcpTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('DNS') ]),
				dnsTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('统计') ]),
				E('p', { 'class': 'cbi-value-description' }, [
					refs.updated
				]),
				statsTable
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('设置') ]),
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

		applyDHCP();
		renderUpstreamEditor();
		applyLive(stats, status, nft);

		poll.add(refresh, 4);

		return root;
	}
});
