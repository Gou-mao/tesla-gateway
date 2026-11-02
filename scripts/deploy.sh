#!/bin/sh
# Example deployment helper for UFI003. Review before running.
#
# Usage:
#   ./scripts/deploy.sh [user@host]
#   TESLA_GATEWAY_HOST=root@192.168.1.1 ./scripts/deploy.sh
#
# Authentication is delegated to ssh/scp: use an SSH key or type the password
# interactively. No password is stored or hard-coded here.
#
# OpenWrt usually runs Dropbear, so OpenSSH's legacy SCP protocol is selected
# with -O. Override SCP_OPTS if the local scp does not support it.
set -eu

HOST="${1:-${TESLA_GATEWAY_HOST:-root@192.168.1.1}}"
BIN="${BIN:-dist/tesla-gateway}"
SCP_OPTS="${SCP_OPTS:--O}"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ ! -f "$BIN" ]; then
	echo "missing $BIN; run 'make build-arm64' first" >&2
	exit 1
fi
if [ ! -f files/etc/init.d/tesla-gateway ] || [ ! -f files/etc/tesla-gateway/config.yaml ] ||
   [ ! -f files/usr/libexec/tg-nft-status ]; then
	echo "missing files deliverables" >&2
	exit 1
fi

echo "deploying to $HOST"
ssh "$HOST" 'mkdir -p /etc/tesla-gateway /usr/libexec'

# shellcheck disable=SC2086
scp $SCP_OPTS "$BIN" "$HOST:/usr/sbin/tesla-gateway"
# shellcheck disable=SC2086
scp $SCP_OPTS files/etc/init.d/tesla-gateway "$HOST:/etc/init.d/tesla-gateway"
# shellcheck disable=SC2086
scp $SCP_OPTS files/etc/tesla-gateway/config.yaml "$HOST:/etc/tesla-gateway/config.yaml"
# shellcheck disable=SC2086
scp $SCP_OPTS files/usr/libexec/tg-nft-status "$HOST:/usr/libexec/tg-nft-status"

ssh "$HOST" '
	chmod 0755 /usr/sbin/tesla-gateway /etc/init.d/tesla-gateway /usr/libexec/tg-nft-status
	chmod 0644 /etc/tesla-gateway/config.yaml
	/etc/init.d/tesla-gateway enable
'

echo "installed and enabled, but not started."
echo "switch dnsmasq to DHCP-only (port=0) first, then:"
echo "  ssh $HOST /etc/init.d/tesla-gateway start"
echo "logs: ssh $HOST logread -f"
