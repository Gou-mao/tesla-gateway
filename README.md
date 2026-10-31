# Tesla Gateway

[![ci](https://github.com/Gou-mao/tesla-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Gou-mao/tesla-gateway/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](https://go.dev)

运行在 OpenWrt（aarch64，本文以 UFI003 4G 模块为例）上的纯 Go「智能 DNS + L3/L4 透明网关」。**Tesla 车机浏览器（车机内置浏览器）无法访问 RFC1918 私网地址**，本项目让它在浏览器里只看到
`100.64.x.x` 这样的映射地址，网关按配置的 `from → to` 前缀把连接还原到真实内网
（`192.168.x`、`10.x`、其它 `100.6x` 等）。新增内网设备只需增加一条映射，无需为每个
服务配置反向代理。

> **硬不变量：Gateway 永不修改 TLS / 应用层，无 inspection。**
> 本项目是纯 L4 字节管道：不解密、不终止 TLS，不修改 SNI、Host、证书或任何应用层
> payload；只做地址翻译和 TCP 转发。

## 架构

```
Tesla ──WiFi──► UFI003 (OpenWrt) ──► LAN 192.168.1.0/24
                    │
                    ├─ dnsmasq：仅 DHCP（port=0）
                    ├─ tg-dns :53 UDP+TCP ─ Resolver 链 → mapping.Translate
                    ├─ tg-proxy :16464     ─ SO_ORIGINAL_DST → mapping.Reverse
                    └─ nft table ip teslagateway：只 redirect 配置的 to 段（排除本地段）
```

数据流示例：

1. Tesla 查询 `nas.home`，`tg-dns` 得到真实地址 `192.168.1.251`，改写为 `100.64.1.251`。
2. Tesla 连接 `100.64.1.251:443`，nft 将目标在映射 set 内的 TCP 流量 redirect 到 `:16464`。
3. `tg-proxy` 读取 `SO_ORIGINAL_DST`，`mapping.Reverse` 得到 `192.168.1.251:443`，用 splice
   或 `io.Copy` 原样转发。

## 目录结构

```
tesla-gateway/
├── cmd/tg/main.go                 # 配置、启动、SIGHUP、优雅退出、nft 接线
├── internal/
│   ├── mapping/                   # 唯一的地址翻译入口（Engine）
│   ├── dns/                       # DNS server、rewrite、LRU/TTL/负缓存、resolver 链
│   ├── proxy/                     # TCPProxy、SO_ORIGINAL_DST、splice/io.Copy
│   ├── netlink/nft.go             # 生成并下发 nft set + redirect
│   ├── config/config.go           # YAML 配置与校验
│   └── logx/                      # 结构化 JSON 日志
├── files/etc/init.d/tesla-gateway # procd 服务脚本
├── files/etc/tesla-gateway/config.yaml # UFI003 样例配置
├── files/usr/share/luci/menu.d/luci-app-tesla-gateway.json   # LuCI 菜单
├── files/usr/share/rpcd/acl.d/luci-app-tesla-gateway.json    # LuCI ACL
├── files/www/luci-static/resources/view/tesla-gateway/overview.js # LuCI 页面
├── files/usr/libexec/ts-addr-sync.sh   # Tailscale 共存：动态补 tun 地址 + 100.64/10 路由
├── scripts/install-tailscale-coexist.sh # Tailscale 共存设备部署脚本
├── configs/config.example.yaml    # 开发机样例配置
├── scripts/deploy.sh              # 示例 scp 部署脚本（不硬编码密码）
├── docs/DESIGN.md                 # 设计文档
├── docs/TAILSCALE-COEXIST.md      # 保留 100.64 LAN 同时跑 Tailscale 的完整方案
└── Makefile
```

## 构建

要求 Go 1.22+。目标机是 OpenWrt aarch64，使用静态编译，无 CGO。

```sh
# 本机开发构建（输出 dist/tesla-gateway）
make build

# UFI003 / OpenWrt 交叉编译
make build-arm64
# 等价于：
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/tesla-gateway ./cmd/tg
```

测试：

```sh
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
# 或 make test（vet + race）
```

## 配置

默认路径 `/etc/tesla-gateway/config.yaml`，完整样例见
`files/etc/tesla-gateway/config.yaml`。关键字段：

| 字段 | 说明 |
|---|---|
| `mappings[].from` / `to` | 真实网段 → Tesla 所见映射网段，前缀长度必须相等 |
| `dns.listen` | 模式 B 下为 `0.0.0.0:53` |
| `dns.resolvers` | 依次尝试 `hosts`、`lease`、`system` |
| `dns.upstream` | 有序上游优先级列表：IPv4/IPv6 地址或 `dhcp`（别名 `auto`），失败自动切换 |
| `dns.clamp_ttl` / `cache_max` | TTL 上限、缓存条数上限 |
| `proxy.tcp_listen` | 透明代理监听，默认 `:16464` |
| `proxy.apply_nft` | `true` 时启动后自动下发 nft，退出时清理；默认 `false`，本地开发不碰防火墙 |
| `proxy.local_client_prefix` | 本地 Tesla 客户端网段，默认 `100.64.0.0/24`，会从 nft redirect set 中减去 |
| `proxy.keepalive` / `max_conns` | 上游 keepalive、并发连接上限 |

`proxy.apply_nft: true` 时，`tcp_listen` 必须是可解析的 `host:port`（端口为数字），
且不能为空。`local_client_prefix` 解析失败或映射段全部被本地段覆盖时，进程启动失败并退出。

### 上游 DNS 顺序与 `dhcp` 动态源

`dns.upstream` 是**有序优先级列表**，顺序即尝试顺序：当前一项超时、拒绝或返回
SERVFAIL/REFUSED 时自动切到下一项。列表至少要有 1 个有效项，每项只能是 IPv4/IPv6
地址或关键字 `dhcp`（别名 `auto`）；主机名、带端口的地址或其它关键字会在加载配置时
直接报错。纯 IP 列表的既有行为不变。

`dhcp` 项会在**原位置**展开为当前上游接口通过 DHCP 拿到的 DNS 数组，例如：

```yaml
dns:
  upstream: ["dhcp", "223.5.5.5", "119.29.29.29"]
```

LuCI 的 DNS 区块把这份列表显示为可编辑的有序列表：用 `↑` / `↓` 调整优先级、
`删除` 移除、底部输入框添加，然后点「保存」。保存时页面先执行
`/usr/sbin/tesla-gateway --config /etc/tesla-gateway/config.yaml --set-upstream "..."`，
由该命令完成校验、去重和原子行替换（只改 `upstream:` 那一行，保留其余内容），
成功后页面再重启服务。该命令行模式改完配置即退出，不会启动 daemon；参数非法时
向 stderr 报错并以非 0 退出。

在 OpenWrt 上，网关执行 `ubus call network.interface dump`，从 `interface[]` 中选择
`up=true` 且带 `dns-server` 的接口；优先使用有默认路由（`target=0.0.0.0/0`，例如
`stawan`/`modem`）的接口，没有默认路由时回退到第一个可用接口。展开结果按原数组顺序
插入该位置，并缓存约 10 秒，避免每次查询都启动 `ubus`。如果拿不到地址（非 OpenWrt
开发机没有 `ubus`、接口未启用、没有 `dns-server`），该项会被跳过并继续尝试后面的
上游。实际选中的上游 IP 及其来源（`custom` / `dhcp`）会写入结构化日志。

## 部署

### 1. 构建并推送

```sh
make build-arm64
./scripts/deploy.sh root@192.168.1.1
```

`scripts/deploy.sh` 只是示例：host 可通过第一个参数或 `TESLA_GATEWAY_HOST` 覆盖，密码不
硬编码，使用 SSH key 或交互输入。脚本只安装并 `enable`，不会自动启动，因为模式 B 切换
前 dnsmasq 仍占用 `:53`；完成下面步骤后再 `start`。也可以手动执行：

```sh
ssh root@192.168.1.1 'mkdir -p /etc/tesla-gateway'

scp -O dist/tesla-gateway root@192.168.1.1:/usr/sbin/tesla-gateway
scp -O files/etc/init.d/tesla-gateway root@192.168.1.1:/etc/init.d/tesla-gateway
scp -O files/etc/tesla-gateway/config.yaml root@192.168.1.1:/etc/tesla-gateway/config.yaml

ssh root@192.168.1.1 '
  chmod 0755 /usr/sbin/tesla-gateway /etc/init.d/tesla-gateway
  chmod 0644 /etc/tesla-gateway/config.yaml
'
```

> OpenWrt 通常运行 Dropbear，OpenSSH 9+ 的 `scp` 需要 `-O` 使用旧 SCP 协议。
> 如果本机 `scp` 不支持，请去掉 `-O` 或使用 `sftp`。

### 2. 开启转发

```sh
ssh root@192.168.1.1 '
  sysctl -w net.ipv4.ip_forward=1
  grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
'
```

WAN/模组区域的 `masq=1` 保持 OpenWrt 默认，不要关闭。

### 3. DNS 模式 B 切换（dnsmasq 只做 DHCP）

OpenWrt 默认由 dnsmasq 占用 `:53`。模式 B 要让 `tg-dns` 监听 53，必须把 dnsmasq 的 DNS
功能关掉、只保留 DHCP：

```sh
# 1) dnsmasq 只做 DHCP
uci set dhcp.@dnsmasq[0].port='0'
uci commit dhcp

# 2) 重启 dnsmasq，释放 53 端口
/etc/init.d/dnsmasq restart

# 3) 确认配置里 dns.listen 为 0.0.0.0:53，然后启动网关
/etc/init.d/tesla-gateway enable
/etc/init.d/tesla-gateway start
```

也可以直接编辑 `/etc/config/dhcp`，在 `config dnsmasq` 段加入：

```
option port '0'
```

DHCP 仍由 dnsmasq 提供；确保 DHCP option 6（DNS 服务器）指向网关本身（默认即
`100.64.0.1`）。Tesla 客户端拿到 `100.64.0.x/24`，网关 `100.64.0.1`，**保持 /24，不要
改成 /16**（否则客户端会 ARP 虚拟地址而失效）。

服务脚本安装：

```sh
chmod +x /etc/init.d/tesla-gateway && /etc/init.d/tesla-gateway enable && /etc/init.d/tesla-gateway start
```

`reload` 会向进程发送 SIGHUP，仅热加载 DNS 配置；监听地址、代理参数、映射和 nft 变更
需要重启服务：

```sh
/etc/init.d/tesla-gateway reload
/etc/init.d/tesla-gateway restart
```

### 4. nft 说明

`apply_nft: true` 时，程序在 TCP proxy 启动成功后生成并下发：

```nft
table ip teslagateway {
    set mapped {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 100.64.1.0/24 }
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr @mapped tcp dport 1-65535 redirect to :16464
    }
}
```

- set 元素来自 `engine.MappedPrefixes()`，并**减去** `local_client_prefix`。
  例如映射段 `100.64.0.0/16` 减去本地 `100.64.0.0/24` 后会写入
  `100.64.1.0/24`、`100.64.2.0/23`、…、`100.64.128.0/17`，绝不会整段拦截本地客户端。
- **只拦配置的 `to` 段**，不会拦整个 `100.64.0.0/10`，避免误伤 Tailscale 等其它地址。
- 只 redirect TCP；不做任何 payload 改写。
- `Apply` 是幂等的：每次先确保表存在、删除旧表，再原子添加新规则；重复启动不会叠加规则。
- 进程收到 SIGINT/SIGTERM 时执行 `nft delete table ip teslagateway`，表不存在视为成功。
- `apply_nft: false`（默认）时完全不执行 nft 命令，适合本地开发。

目标固件需带 nftables 与 NAT 支持；如果 `nft` 不存在，先安装
`opkg update && opkg install nftables kmod-nft-nat`。

查看规则：

```sh
nft list table ip teslagateway
nft list set ip teslagateway mapped
```

### 5. 验证

在 Tesla 或局域网客户端上：

```sh
# 应返回 100.64.1.251 之类的映射地址
dig @100.64.0.1 nas.home

# 应能访问真实内网服务（示例映射 192.168.1.0/24 → 100.64.1.0/24）
curl -v http://100.64.1.251/

# 在路由器上确认 DNS 监听和 nft 规则
netstat -lntup | grep ':53'
nft list table ip teslagateway

# 查看结构化日志
logread -f | grep tesla-gateway
```

如果 `dig` 返回真实 `192.168.x.x`，说明请求没有经过 `tg-dns`（dnsmasq 仍占用 53 或客户端
未使用网关 DNS）；如果 TCP 能连但 80/443 无响应，检查 nft 是否下发、`ip_forward` 和
`proxy.tcp_listen` 端口。

## LuCI 界面

LuCI 插件是三个静态文件，不需要 opkg，也不修改 Go 程序：

| 仓库文件 | 设备路径 |
|---|---|
| `files/usr/share/luci/menu.d/luci-app-tesla-gateway.json` | `/usr/share/luci/menu.d/` |
| `files/usr/share/rpcd/acl.d/luci-app-tesla-gateway.json` | `/usr/share/rpcd/acl.d/` |
| `files/www/luci-static/resources/view/tesla-gateway/overview.js` | `/www/luci-static/resources/view/tesla-gateway/` |

安装（在仓库根目录执行，host 换成设备地址）：

```sh
ssh root@192.168.1.1 'mkdir -p /www/luci-static/resources/view/tesla-gateway'

scp -O files/usr/share/luci/menu.d/luci-app-tesla-gateway.json \
  root@192.168.1.1:/usr/share/luci/menu.d/
scp -O files/usr/share/rpcd/acl.d/luci-app-tesla-gateway.json \
  root@192.168.1.1:/usr/share/rpcd/acl.d/
scp -O files/www/luci-static/resources/view/tesla-gateway/overview.js \
  root@192.168.1.1:/www/luci-static/resources/view/tesla-gateway/

ssh root@192.168.1.1 '
  chmod 0644 \
    /usr/share/luci/menu.d/luci-app-tesla-gateway.json \
    /usr/share/rpcd/acl.d/luci-app-tesla-gateway.json \
    /www/luci-static/resources/view/tesla-gateway/overview.js
  rm -f /tmp/luci-indexcache*
  /etc/init.d/rpcd restart
'
```

浏览器打开 **LuCI → 服务 → Tesla Gateway**（即
`/cgi-bin/luci/admin/services/tesla-gateway`）。页面按「状态 → 转发映射 →
DHCP 下发 → DNS → 统计 → 设置」排列：转发映射直接回答「什么网段变成什么
网段」，DHCP 区块由 LuCI 的 `dhcp` / `network` UCI 配置算出网关、地址池、
租期以及实际下发的 option 3 / option 6，DNS 区块同时展示可编辑的配置 `dns.upstream`
（可能包含 `dhcp` 关键字）和只读的当前实际生效 IP 列表 `dns_upstream_effective`。
列表中的 `dhcp` / `auto` 项后会用灰色小字显示当前解析到的地址与来源接口
（例如 `（192.168.1.1，来自 stawan）`；没有解析结果时显示 `（未解析到地址）`）。
服务状态、`stats.json` 统计和 nft 表状态每 4 秒刷新；页面提供启动 /
停止 / 重启按钮，以及 `/etc/tesla-gateway/config.yaml` 文本编辑和「保存并
重启」。

`stats.json` 同时包含静态配置语义和动态统计：`mappings`（`from` / `to`
CIDR 原样字符串）、`mapping_strategy`、`dns_listen`、`dns_upstream`
（配置原样，含 `dhcp` 关键字）、`dns_upstream_effective`（当前实际解析出的
IP 列表，DHCP 源随缓存刷新）、`dns_dhcp_servers` / `dns_dhcp_interface`
（DHCP 源解析到的 DNS 地址数组和来源接口名，无结果时分别为 `[]` / `""`），
以及 `dns` / `proxy` 计数器。静态字段每次写
文件时与最新动态快照合并，供 LuCI 一次读取。

ACL 说明：

- `menu.d` 的 `depends.acl` 要求当前登录用户拥有 `luci-app-tesla-gateway`
  ACL 组；root 默认可读写全部 ACL，普通委派账号需要在
  `/etc/config/rpcd` 的 login 段授予该组。
- read 段的 `"uci": [ "dhcp", "network" ]` 用于页面读取 DHCP 地址池和
  option 3 / 6；如果移除，DHCP 区块会显示权限不足或默认值。
- `fs.read` / `fs.write` 由 rpcd 的 `file` 对象按 ACL 里的**真实文件路径**检查。
  `fs.exec` 不是给 `ubus.file` 授权，而是给要执行的**可执行文件路径**加
  `"exec"`，例如：
  `"/etc/init.d/tesla-gateway": [ "exec" ]`、`"/usr/sbin/nft": [ "exec" ]`、
  `"/usr/sbin/tesla-gateway": [ "exec" ]`。
  本项目的 read 段放行 init.d / nft / tesla-gateway 的 exec，write 段再次
  放行 init.d 和 tesla-gateway 的 exec，以覆盖「查看状态」「启动 / 停止 /
  重启」以及「保存 DNS 上游顺序」几类调用。
- OpenWrt 的 `/var` 通常指向 `/tmp`，较新的 rpcd 会先 `realpath()` 再复检
  ACL 目标路径。因此 ACL 同时列出 `/var/run/tesla-gateway/stats.json`、
  `/tmp/run/tesla-gateway/stats.json` 和 `/tmp/tesla-gateway/stats.json`；
  设备上只会命中实际存在的那一个，多列不影响安全。
- 只读 ACL 用户也拥有 init.d 的 `exec` 后，就能执行该脚本的
  start/stop/restart（`exec` 权限无法按参数细分）。如果要做严格的只读委派，
  应把 init.d 的 `exec` 只保留在 write 段；此时页面仍可读统计，但运行状态会
  显示为「未知」。
- 修改 menu 或 ACL 后必须清缓存并重启 rpcd；只改 view 通常刷新浏览器即可。

若页面菜单不出现或按钮报权限错误，检查：

```sh
logread -f | grep rpcd
ls -l /usr/share/luci/menu.d/luci-app-tesla-gateway.json \
      /usr/share/rpcd/acl.d/luci-app-tesla-gateway.json \
      /www/luci-static/resources/view/tesla-gateway/overview.js
```

## Tailscale 共存（可选）

本项目 LAN 必须是 `100.64.0.0/24`（Tesla 限制），而 Tailscale 默认把整个
`100.64.0.0/10` 当作自己的地址池，其 anti-spoof 规则会误伤 LAN（含 DNS 到
`100.64.0.1:53`）。若需在同一台设备上同时跑 Tailscale，按
[docs/TAILSCALE-COEXIST.md](docs/TAILSCALE-COEXIST.md) 操作：`netfilter-mode=off`
去掉 anti-spoof，再用 `files/usr/libexec/ts-addr-sync.sh`（cron 每分钟幂等）动态
补回 off 模式不再自动配置的 tun 地址与 `100.64.0.0/10` 路由（节点 IP 变自动跟、
peer 增删零维护），并把 `tailscale0` 放入 wan 区（masq + lan→wan forward）。
一键部署：`scripts/install-tailscale-coexist.sh`。

## 回滚

```sh
# 1) 停止并禁用网关服务
/etc/init.d/tesla-gateway stop
/etc/init.d/tesla-gateway disable

# 2) 删除本项目的 nft 表（不存在时忽略错误）
nft delete table ip teslagateway 2>/dev/null || true

# 3) 恢复 dnsmasq 的 DNS 功能
uci delete dhcp.@dnsmasq[0].port
# 或显式恢复：uci set dhcp.@dnsmasq[0].port='53'
uci commit dhcp
/etc/init.d/dnsmasq restart

# 4) 可选：删除二进制与配置
rm -f /usr/sbin/tesla-gateway /etc/init.d/tesla-gateway
rm -rf /etc/tesla-gateway
```

回滚后客户端应重新从 dnsmasq 获取 DNS，Tesla 不再看到 `100.64.x.x` 映射地址。

## 安全边界

- 纯 Go 单二进制，`CGO_ENABLED=0`，不依赖 Caddy/Nginx 或任何反向代理软件。
- 所有地址翻译只经过 `internal/mapping.Engine`，各模块不自行改写地址。
- DNS 与代理共享 mapping，但各自独立运行。
- **无 TLS 解密、无 TLS termination、无 SNI/Host 改写、无应用层 inspection。**
  如果将来需要 HTTPS 审计，应作为另一个产品实现，不得加入本项目。

## License

本项目以 **MIT** 协议开源，见 [LICENSE](LICENSE)。

第三方依赖均为宽松许可：`github.com/miekg/dns`（BSD-3-Clause）、
`golang.org/x/sys` / `golang.org/x/net`（BSD-3-Clause）、`gopkg.in/yaml.v3`
（Apache-2.0 / MIT）。使用时请各自遵循其许可证并保留版权声明。
