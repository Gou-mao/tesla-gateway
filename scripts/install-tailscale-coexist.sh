#!/bin/sh
# Install the Tesla-Gateway <-> Tailscale coexistence setup on the UFI003
# (msm8916-openwrt, apk-based, kernel has no CONFIG_IP_ADVANCED_ROUTER).
#
# Run ON THE DEVICE. Expects ts-addr-sync.sh next to this script (or already
# installed at /usr/libexec/ts-addr-sync.sh). Idempotent.
#
# What it does:
#   1. install helper /usr/libexec/ts-addr-sync.sh
#   2. cron reconcile every minute
#   3. enable + start tailscale, force pref netfilter-mode=off
#   4. firewall: add tailscale0 to the wan zone (masq + lan->wan forward)
#   5. apply once now
set -e
DIR=$(dirname "$0")

# 1) helper
if [ -f "$DIR/ts-addr-sync.sh" ]; then
  mkdir -p /usr/libexec
  cp "$DIR/ts-addr-sync.sh" /usr/libexec/ts-addr-sync.sh
fi
chmod +x /usr/libexec/ts-addr-sync.sh

# 2) cron reconcile
mkdir -p /etc/crontabs
grep -q ts-addr-sync /etc/crontabs/root 2>/dev/null || \
  echo '* * * * * /usr/libexec/ts-addr-sync.sh >/dev/null 2>&1' >> /etc/crontabs/root
/etc/init.d/cron restart 2>/dev/null || /etc/init.d/crond restart 2>/dev/null || true

# 3) tailscale: enable + start, then force netfilter-mode=off
uci set tailscale.settings.enabled='1'; uci commit tailscale
/etc/init.d/tailscale enable 2>/dev/null || true
/etc/init.d/tailscale start 2>/dev/null || true
sleep 9
tailscale set --netfilter-mode=off 2>/dev/null || true

# 4) firewall: tailscale0 -> wan zone (masq + lan->wan forward)
# Find the zone section named "wan" instead of assuming it is @zone[1].
wan_section=
while IFS= read -r entry; do
  section=${entry#firewall.}
  section=${section%=zone}
  if [ "$(uci get "firewall.$section.name" 2>/dev/null || true)" = "wan" ]; then
    wan_section=$section
    break
  fi
done <<EOF
$(uci show firewall 2>/dev/null | grep '=zone$' || true)
EOF
if [ -z "$wan_section" ]; then
  echo "error: no firewall zone named 'wan' found" >&2
  exit 1
fi

have=$(uci get "firewall.$wan_section.device" 2>/dev/null | tr ' ' '\n' | grep -cx tailscale0 || true)
[ "$have" = "1" ] || { uci add_list "firewall.$wan_section.device=tailscale0"; uci commit firewall; }
/etc/init.d/firewall reload 2>/dev/null || true

# 5) apply now
/usr/libexec/ts-addr-sync.sh
echo "installed; addr=$(ip -4 addr show tailscale0 2>/dev/null | awk '/inet 100/{print $2}'); anti=$(nft list table ip filter 2>/dev/null | grep -c '100.64.0.0/10')"
