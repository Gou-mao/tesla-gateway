#!/bin/sh
# tesla-gateway: keep the UFI003 LAN on 100.64.0.0/24 (required so the Tesla
# in-car browser, which blocks RFC1918, can reach LAN hosts) while running
# Tailscale with netfilter-mode=off.
#
# In netfilter-mode=off Tailscale does NOT program the tun address or routes
# (it expects the admin to manage the Linux network stack). This helper fills
# exactly those two gaps, dynamically:
#   - assigns the CURRENT tailnet IP(s) from `tailscale ip` to tailscale0
#   - ensures a single broad route 100.64.0.0/10 dev tailscale0 that covers all
#     tailnet peers (the LAN /24 stays more specific, so 100.64.0.0/24 is
#     unaffected)
# Idempotent; safe to run every minute (see cron reconcile in the install
# script). Re-run safe after a Tailscale node rebuild / IP change.
[ -e /sys/class/net/tailscale0 ] || exit 0

TB=$(command -v tailscale 2>/dev/null || echo /usr/sbin/tailscale)
V4=$($TB ip -4 2>/dev/null | head -1)
V6=$($TB ip -6 2>/dev/null | head -1)

ip link set tailscale0 up 2>/dev/null

# drop stale IPv4 addrs in 100.64/10 that are not the current one
for a in $(ip -4 -o addr show dev tailscale0 2>/dev/null | awk '{print $4}'); do
  case "$a" in
    100.*) [ "$a" = "$V4/32" ] || ip addr del "$a" dev tailscale0 2>/dev/null ;;
  esac
done
[ -n "$V4" ] && ip addr replace "$V4/32" dev tailscale0 2>/dev/null

# drop stale IPv6 fd7a:: addrs that are not the current one
for a in $(ip -6 -o addr show dev tailscale0 2>/dev/null | awk '{print $4}'); do
  case "$a" in
    fd7a:*) [ "$a" = "$V6/128" ] || ip -6 addr del "$a" dev tailscale0 2>/dev/null ;;
  esac
done
[ -n "$V6" ] && ip -6 addr replace "$V6/128" dev tailscale0 2>/dev/null

# one broad route covers every tailnet peer; LAN 100.64.0.0/24 stays more specific
ip route replace 100.64.0.0/10 dev tailscale0 2>/dev/null
exit 0
