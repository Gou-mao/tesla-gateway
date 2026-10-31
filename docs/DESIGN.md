# Tesla Gateway 设计文档 v0.3（OpenWrt / UFI003）

目标平台：OpenWrt 25.12.6 · aarch64（UFI003 / MSM8916）· Go（静态编译）· 允许成熟纯 Go 库（禁止反代软件 Caddy/Nginx）

> v0.3 变更（据二次评审，已定稿开工）：
> ①DNS 用 `miekg/dns`（凡协议解析优先成熟库）②EDNS0/DNSSEC 位/TCP+UDP/Truncated→TCP 全支持 ③AAAA **透传**（勿返 NOTIMP，避免 Happy Eyeballs 卡顿）④缓存 = LRU+TTL+负缓存+到期重查 ⑤代理走 `unix.Splice`(build tag linux，回退 io.Copy) ⑥`mapping.Validate()` 启动即校验重叠/冲突，fail-fast ⑦结构化 JSON 日志 ⑧**硬不变量：Gateway 永不修改 TLS payload** ⑨新增 **Resolver Provider** 接口（与 MappingStrategy 并列的关键抽象）⑩nft 只拦配置的 `to` 段（勿误伤 Tailscale）。
> 其余沿用 v0.2。

---

## 0. 一句话

UFI003(OpenWrt) 上一个纯 Go「**智能 DNS + L3/L4 透明网关**」：Tesla 车机浏览器只见 `100.64.x.x`，背后按**可插拔映射策略**自动翻译到任意真实内网（`192.168.x`/`10.x`/`100.6x`/…）。新增内网设备**零配置**可访问。不用反向代理软件。

## 1. 背景与目标

- Tesla 车机浏览器无法访问 RFC1918（`192.168`/`10.x`/`172.16-31`）；放行 `100.64.0.0/10`（RFC6598）。
- 不为每服务配反代；新增内网设备自动可访问 = 项目最大价值。
- 纯 L4：不解密 TLS、不改 Host/SNI/应用层；HTTP/2、WebSocket、QUIC(未来UDP)、长连接透明。
- 自己实现 DNS 映射 + 映射引擎 + 透明代理；**不依赖 Caddy/Nginx**（是网关不是反代）。协议编解码用成熟纯 Go 库，不重复造轮子。
- Phase 1：DNS 映射 + TCP Proxy + OpenWrt 跑起来；无 Web UI。

## 2. Mapping Engine（核心，单点真相）

**只有一处** `Translate/Reverse`；DNS、TCP、UDP、未来 IPv6 全调用它。模块**禁止**自写映射。

### 2.1 可插拔策略

```go
type MappingStrategy interface {
    Translate(a netip.Addr) (netip.Addr, bool)    // 真实 → mapped
    Reverse(a netip.Addr) (netip.Addr, bool)      // mapped → 真实
    IsMapped(a netip.Addr) bool
    Validate() error                              // ★启动校验(重叠/冲突/等长)
}
```
**v1 `PrefixMappingStrategy`**：CIDR 前缀替换、保主机位、双射可逆（`from`/`to` 掩码长度相等）。
未来：`19818MappingStrategy`（Tesla 若限 100.64/10 改 `198.18.0.0/15`）、`CustomMappingStrategy`，其它模块零改动。

### 2.2 `Validate()` 必须 fail-fast

启动即校验，不通过**直接退出**（拒绝运行时随机匹配）：
- 每个 `from`/`to` 前缀长度相等；
- `from` 集合内部**互不重叠**；`to` 集合内部**互不重叠**；
- `to` 段**不得**落在本地客户端段 `100.64.0.0/24`；
- `to` 段不得与"真实在用网段"重叠（配置声明）。

### 2.3 规则来源：纯配置 `from/to`（不写死网段）

```yaml
mappings:
  - { from: "192.168.1.0/24", to: "100.64.1.0/24" }
  # - { from: "100.68.0.0/16", to: "100.65.0.0/16" }   # Tailscale 侧
  # - { from: "10.243.0.0/16",  to: "100.66.0.0/16" }  # ZeroTier 侧
```
`PrefixMappingStrategy` 编译为 `netip.Prefix` 对，**最长前缀匹配**。

## 3. 架构与数据流

```
 Tesla ─WiFi─► UFI003(OpenWrt) ─► LAN 192.168.1.0/24
                     │            └► (未来) Tailscale/ZeroTier
   ┌─────────────────┴──────────────────────────────┐
   │ dnsmasq: 仅 DHCP (port=0)                        │
   │ [tg-dns]:53 UDP+TCP(模式B) ─ Resolver链 → Mapping.Translate │
   │ [tg-proxy] Proxy接口→TCPProxy(nat) ─ Mapping.Reverse        │
   │      ▲ nft: dst∈配置to段(除本地) redirect                    │
   └──────────────────────────────────────────────────┘
```

**流 A（nas.home:443）**：Tesla 查 → tg-dns → Resolver 链得 `192.168.1.251` → `Translate`→`100.64.1.251` → Tesla 连 `100.64.1.251:443` → /24 跨网段送网关 → nft redirect → `SO_ORIGINAL_DST`→`Reverse`→`192.168.1.251:443`→splice 转发。

## 4. 模块划分

```
tesla-gateway/
├── cmd/tg/main.go              # 配置/Validate/启动/优雅退出/SIGHUP
├── internal/
│   ├── mapping/                # ★单点
│   │   ├── strategy.go         # MappingStrategy
│   │   ├── prefix.go           # PrefixMappingStrategy + Validate
│   │   ├── engine.go           # Engine.Translate/Reverse/IsMapped/MappedPrefixes
│   │   └── *_test.go
│   ├── dns/
│   │   ├── server.go           # :53 UDP+TCP；Truncated→TCP；并发
│   │   ├── resolver.go         # ★Resolver 接口(Provider 抽象)
│   │   ├── resolvers/          # hosts.go, lease.go, system.go(上游); 预留 mesh/mdns/static
│   │   ├── rewrite.go          # A:Translate; AAAA透传; 保 TTL/CNAME/多A; EDNS0/DNSSEC位透传
│   │   └── cache.go            # LRU+TTL+负缓存+到期重查
│   ├── proxy/
│   │   ├── proxy.go            # Proxy 接口
│   │   ├── tcp.go              # TCPProxy(nat)
│   │   ├── origdst_linux.go    # SO_ORIGINAL_DST
│   │   ├── relay_linux.go      # unix.Splice (build tag linux)
│   │   ├── relay_other.go      # io.Copy 回退 (build tag !linux)
│   │   └── udp.go              # UDPProxy stub(预留)
│   ├── netlink/nft.go          # 由 MappedPrefixes() 生成 nft set+redirect
│   ├── config/config.go        # yaml+校验
│   └── logx/logx.go            # ★结构化 JSON 日志
```
扩展预留（只留接口）：`internal/discovery/`（mDNS/Bonjour/UPnP/SMB）、`internal/admin/`（WebUI/API）。

## 5. 功能一：智能 DNS（tg-dns，模式 B）

**监听** `0.0.0.0:53` **UDP + TCP**（模式 B；dnsmasq `port=0` 只留 DHCP）。
**DNS 库**：`miekg/dns`（报文/EDNS0/DNSSEC 位/TCP 编解码）。

### 5.1 Resolver Provider 链（关键抽象）

```go
type Resolver interface {
    Name() string
    Lookup(ctx context.Context, q dns.Question) ([]dns.RR, bool, error) // 命中/未命中/错误
}
```
按序组合（ChainResolver）：
1. `hosts`（`/etc/hosts`）、`lease`（`/tmp/dhcp.leases`）——本地名
2. `static`（可选配置的静态记录）
3. `system`（上游 DNS：`223.5.5.5`,`119.29.29.29`… 失败切换）
4. 预留：`tailscale`(MagicDNS)、`zerotier`、`mdns`、`bonjour`
→ 命中即用；未命中留待下一个；不命中则查 system。
**MappingStrategy 与 Resolver 无关**：Resolver 只产出**真实**记录，映射在出口统一 `Translate`。

### 5.2 改写（`rewrite.go`）

- 逐条 **A**：`Translate(ip)` 命中则替换，否则原样。
- **AAAA：原样透传**（本版不映射 v6；绝不返 NOTIMP，避免 Happy Eyeballs 等 A 导致卡顿；`drop_aaaa:true` 可选丢弃）。
- **保留**：TTL（`clamp_ttl` 上限，默认 300s）、CNAME（链尾 A 同改）、**多 A**（逐条）。
- **EDNS0 完整支持**；DNSSEC 标志(`DO/AD/CD`)与 OPT 原样透传；不破坏压缩指针。

### 5.3 传输

- UDP 与 **TCP** 均实现；UDP 应答 `TC=1`(截断) 时客户端/我方自动切 TCP 重查；我方对上游同样支持 TC→TCP。

### 5.4 缓存（`cache.go`）

- **LRU + TTL**（不可用 `map[string]Answer`）。
- 存**真实**应答，出口再改写（规则变更免清缓存）。
- **Negative Cache**（NXDOMAIN/NODATA，遵循 SOA minimum，默认 ≤30s）。
- TTL 到期自动重查；容量上限 `cache_max`。

## 6. 功能二：Proxy（v1 TCP，接口面向 UDP）

```go
type Proxy interface { Start(ctx) error; Stop() error; Name() string }
// v1 TCPProxy；预留 UDPProxy（QUIC/HTTP3/DoQ 单独实现，不动核心）
```

**TCPProxy（nat）**：`accept` → `SO_ORIGINAL_DST` → `mapping.Reverse` → `net.Dial`(KeepAlive 15s/3, 超时, 连接数上限) → **relay** → 清理。
**relay**：优先 `unix.Splice`(build tag linux) 实现内核态零拷贝（避免 K→U→K 两次拷贝）；非 linux 回退 `io.Copy`；处理半关闭(`CloseWrite`)、空闲超时(默认不限)。
**绝不修改任何字节** → TLS/SNI/Host 端到端。

### 6.1 ★硬不变量：永不触碰 TLS / 应用层

Gateway 是纯 L4 字节管道：
- **永不**修改 TLS record / 解密 / 注入 / 终止 / inspection；
- SNI、Host、证书链原样端到端；
- 若将来要"HTTPS 解密/审计"，那是**另一个产品**，不得在本项目内加（防维护者误加 TLS Inspection，明确写死）。

### 6.2 源 IP

v1 `proxy_mode: nat`（服务端见网关 IP `100.64.0.1`，对 QNAP/Homepage/TeslaMate/Navidrome/打印机/NVR 足够）；预留 `tproxy`。

## 7. 解耦

DNS 与 Proxy 仅共享 `mapping.Engine`；不共享表/缓存。Resolver 与 MappingStrategy 正交。

## 8. OpenWrt 集成

- dnsmasq `port=0`（仅 DHCP）；tg-dns 监听 53。
- nft：`netlink/nft.go` 由 `engine.MappedPrefixes()` 生成 set+`redirect`；**只拦配置 `to` 段**（排除 `100.64.0.0/24`）；启停幂等。
- `ip_forward=1`；wan 区(含 stawan/modem)`masq=1` 保留。
- `procd` `/etc/init.d/tesla-gateway`（respawn、自启、SIGHUP 重载）。
- 构建 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`；SSH(`root@192.168.1.1`) scp 到 `/usr/sbin/`。

## 9. 关键接口

```go
// mapping
func (e *Engine) Translate(netip.Addr) (netip.Addr, bool)
func (e *Engine) Reverse(netip.Addr) (netip.Addr, bool)
func (e *Engine) IsMapped(netip.Addr) bool
func (e *Engine) MappedPrefixes() []netip.Prefix
// dns
type Resolver interface { Name() string; Lookup(ctx, dns.Question) ([]dns.RR, bool, error) }
// proxy
type OrigDst func(net.Conn) (netip.AddrPort, error)
type Relay   func(a, b net.Conn)
```
全用 `net/netip`；DNS 用 `miekg/dns`。

## 10. 配置样例（/etc/tesla-gateway/config.yaml）

```yaml
mapping_strategy: prefix
mappings:
  - { from: "192.168.1.0/24", to: "100.64.1.0/24" }
dns:
  listen: "0.0.0.0:53"
  resolvers: [hosts, lease, system]        # 依序; 预留 tailscale/zerotier/mdns
  # 有序优先级：IPv4/IPv6 或 dhcp（别名 auto，按当前上游接口 DHCP DNS 原地展开）
  upstream: ["dhcp", "223.5.5.5","119.29.29.29"]
  clamp_ttl: 300
  cache_max: 4096
  drop_aaaa: false
proxy:
  mode: nat
  tcp_listen: ":16464"
  keepalive: 15s
  max_conns: 1024
  idle_timeout: 0
log:
  format: json
  level: info
```

## 11. 性能

Go epoll；每连接 2 goroutine；splice 零拷贝；DNS 缓存+in-flight 去重；buffer 池化；常驻 <30MB，空闲 CPU≈0。

## 12. 扩展性

| 能力 | 预留点 | 改核心？ |
|---|---|---|
| Tesla 限 100.64/10 | `19818MappingStrategy` | 否 |
| IPv6 映射 | mapping v6 + rewrite AAAA | 否 |
| QUIC/HTTP3/DoQ | `UDPProxy` | 否 |
| .home/MagicDNS/mDNS 无缝 | 多挂 `Resolver` | 否 |
| WireGuard/Nebula/Headscale | 加一条 `from/to` | 否 |
| WebUI/发现类 | `admin`/`discovery` | 否 |

## 13. Phase 1 范围

1. `mapping`（Strategy+Prefix+Engine+`Validate`+单测）
2. `tg-dns`（模式B；Resolver 链 hosts/lease/system；A 改写；AAAA 透传；EDNS0/DNSSEC/TCP/TC→TCP；LRU+TTL+负缓存）
3. `TCPProxy`（nat；SO_ORIGINAL_DST；splice）
4. nft 由 `MappedPrefixes()` 生成 + procd
5. 跑通：Tesla 能开 `http(s)://100.64.1.251`
**不做**：WebUI、UDP(留 stub)、IPv6 映射、发现类。

## 14. 风险 / 待确认

1. ~~DNS 库~~ → **定：`miekg/dns`**；凡协议解析优先成熟纯 Go 库。
2. 源 IP：v1 不保留（定）。
3. 映射网段具体值由用户给，代码不写死。
4. Tesla 非 80/443 端口需实车验证。
5. PROXY_PORT 默认 16464。

## 15. DHCP / 子网掩码结论（不变）

DHCP 发 `100.64.0.100–249`，掩码 **/24**，网关 `100.64.0.1`；**保持 /24 禁止 /16**（改 /16 客户端会 ARP 虚拟地址→失效）。本地 `100.64.0.0/24` 与映射段严格分离。

## 16. 给 dsh（编码 agent）的硬约束

- 纯 Go 单二进制，`CGO_ENABLED=0 GOOS=linux GOARCH=arm64`。
- **不依赖 Caddy/Nginx/反代**；协议解析优先成熟纯 Go 库（DNS 用 `miekg/dns`）。
- **所有 IP 翻译只经 `mapping.Engine`**；模块内禁止私自映射。
- **`MappingStrategy` 可插拔**（v1 `PrefixMappingStrategy`）+ **`Validate()` 启动 fail-fast**。
- **`Proxy` 接口**（v1 只 `TCPProxy`，`UDPProxy` stub）。
- **`Resolver` Provider 接口**（v1: hosts/lease/system，Chain 依序）。
- **DNS 硬要求**：EDNS0；DNSSEC 位透传；UDP+TCP；TC→TCP；**AAAA 透传**（不 NOTIMP）。
- **缓存**：LRU+TTL+负缓存，禁 `map`；到期重查。
- **relay**：`unix.Splice`(linux build tag)+`io.Copy` 回退；半关闭。
- **硬不变量：永不修改 TLS/应用层**（无 inspection）。
- **nft 只拦配置 `to` 段**（排除本地），不拦整段 `100.64/10`。
- **日志结构化 JSON**（module/host/real/mapped/latency_ms），禁 fmt.Println。
- 配置驱动 + `SIGHUP` 热重载；`procd` 托管。
- 交付：单元测试(mapping/rewrite/cache)、`/etc/init.d` 脚本、README(编译+部署)、样例配置。
