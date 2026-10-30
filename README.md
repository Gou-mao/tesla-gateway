# Tesla Gateway

UFI003（OpenWrt / aarch64）上的纯 Go「智能 DNS + L3/L4 透明网关」。Tesla 只看到
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
├── configs/config.example.yaml    # 开发机样例配置
├── scripts/deploy.sh              # 示例 scp 部署脚本（不硬编码密码）
├── docs/DESIGN.md                 # 设计文档
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
| `dns.upstream` | 上游 DNS，失败自动切换 |
| `dns.clamp_ttl` / `cache_max` | TTL 上限、缓存条数上限 |
| `proxy.tcp_listen` | 透明代理监听，默认 `:16464` |
| `proxy.apply_nft` | `true` 时启动后自动下发 nft，退出时清理；默认 `false`，本地开发不碰防火墙 |
| `proxy.local_client_prefix` | 本地 Tesla 客户端网段，默认 `100.64.0.0/24`，会从 nft redirect set 中减去 |
| `proxy.keepalive` / `max_conns` | 上游 keepalive、并发连接上限 |

`proxy.apply_nft: true` 时，`tcp_listen` 必须是可解析的 `host:port`（端口为数字），
且不能为空。`local_client_prefix` 解析失败或映射段全部被本地段覆盖时，进程启动失败并退出。

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
