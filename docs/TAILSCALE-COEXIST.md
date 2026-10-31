# Tailscale + 100.64.0.0/24 LAN 共存（UFI003）

本文记录在 UFI003（msm8916-openwrt 25.12.6，内核 6.12.112，tailscale 1.104.1-r1）
上，**保留 Tesla Gateway 必需的 `100.64.0.0/24` LAN** 同时跑通 Tailscale 的完整结论与做法。

## 背景 / 约束

- Tesla 车机内置浏览器**拒绝 RFC1918 私网地址**，所以本网关 LAN 必须是 `100.64.0.0/24`（RFC 6598）。
  这是项目的硬前提，**不能换成 192.168/10/172.16**。
- Tailscale 把整个 `100.64.0.0/10` 视为自己的地址池 → 与我们的 LAN 重叠。

## 问题现象

启用 Tailscale（默认设置）后：

1. `tailscale status` 正常、能拿到 `100.x` 地址；
2. 但 **LAN 客户端 / AP 设备全部断网（含 DNS 到 `100.64.0.1:53`）**；
3. `nft` 里出现 tailscaled 的 `ts-input` / `ts-forward` 链，含：
   - `iifname != "tailscale0*" ip saddr 100.64.0.0/10 drop`（入站：打死 LAN→路由器）
   - `oifname "tailscale0*" ip saddr 100.64.0.0/10 drop`（出向：打死 LAN→tailnet 转发）

即 Tailscale 的 **anti-spoof 规则**误伤了我们整个 `100.64/10` 的 LAN。

## 取证结论（关键）

- 该 anti-spoof 规则在 `priority filter(0)`，**每次 `tailscale up` / netmap 变化都重建**；
  nftables 语义下**别的 chain 里的 `accept` 无法覆盖他链的 `drop`** → 防火墙层绕不过。
- `tailscale up/set --netfilter-mode=off`（`on/nodivert/off` 是 **CLI pref**，不是 tailscaled 守护参数）
  可以 **去掉 anti-spoof**（`nft ... 100.64.0.0/10` 计数归 0），LAN 恢复。
- 但 `off` 模式下 tailscaled **不再配置 tun 地址、也不写路由**（"configure yourself"）——
  官方静态二进制与 OpenWrt 包行为**完全一致**（同一份 1.104.1 代码），所以**不是打包问题**。
- 本内核 **`CONFIG_IP_ADVANCED_ROUTER` 未开启**（无 policy routing / `ip rule` 不可用）。
  Tailscale 会自动**退化到 main 表 /32 路由**，数据面仍可通 → 内核缺 policy routing 不是硬阻塞。

## 方案（保留 100.64 LAN + netfilter-mode=off + 补齐缺失步骤）

1. `tailscale set --netfilter-mode=off`（pref 持久化在 `/etc/tailscale` state）。
2. `ts-addr-sync.sh`（`files/usr/libexec/`）**动态**补齐 off 模式缺的两步：
   - 读 `tailscale ip -4/-6` 把**当前** tailnet IP 用 `ip addr replace` 写到 `tailscale0`
     （节点 IP 变了自动跟；重登/重建节点无需手动改）
   - `ip route replace 100.64.0.0/10 dev tailscale0`：一条覆盖**全部** peer 的路由
     （peer 增删零维护；LAN `100.64.0.0/24` 更具体，仍走 br-lan，不受影响）
3. **cron 每分钟幂等 reconcile**（`/usr/libexec/ts-addr-sync.sh`）兜住 daemon 重启 / IP 变更 / 开机时序。
4. fw4：把 `tailscale0` 加进 **wan 区**（`masq=1` + lan→wan forward）→ LAN 客户端可经隧道访问 tailnet。

部署脚本：`scripts/install-tailscale-coexist.sh`（在设备上跑，幂等）。

## 实测（UFI003，已通过）

- `tailscale0 = 100.78.25.13/32`，`100.64.0.0/10 dev tailscale0` 在；LAN `/24` 在
- `nft ... 100.64.0.0/10` 计数 = 0（无反欺骗）
- 设备 → tailnet peer：ICMP + **TCP 均通**（`wget http://<peer>:8099/` → `TESLA_GATEWAY_E2E_OK`）
- **重启后自动恢复**：daemon 自启 → 连上 → cron 自动补地址/路由，网关/DNS 正常

## 注意 / 限制

- 这是"Tailscale 与 100.64 LAN 共存"的**折中**：不是官方 off 模式的常规用法，而是补齐了 off
  模式不管的地址/路由。升级 tailscale 包后请复查 `ts-addr-sync.sh` 是否仍适用。
- 内核缺 policy routing（`CONFIG_IP_ADVANCED_ROUTER`）→ 走 main 表 fallback；若要更规范可重编内核
  开启 `CONFIG_IP_ADVANCED_ROUTER=y` + `CONFIG_IP_MULTIPLE_TABLES=y`（非必需）。
- LAN 客户端 → tailnet peer 为 **TCP/UDP 正常**（Tailscale 自身封装）；此处不涉及把 LAN 客户端的
  公网 HTTP/HTTPS 做应用层透明代理。
- macOS 侧（回程方向）`ping` 到设备可能因 macOS 防火墙丢 ICMP，但 `tailscale ping` 双向通，与本方案无关。
