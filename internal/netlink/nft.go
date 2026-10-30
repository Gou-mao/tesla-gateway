// Package netlink installs the nftables rules that steer mapped traffic into
// the transparent proxy. It only builds and applies nft text; no address
// translation happens here.
package netlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

const (
	// TableFamily is the nftables address family of the managed table.
	TableFamily = "ip"
	// TableName is the nftables table owned by Tesla Gateway.
	TableName = "teslagateway"

	setName = "mapped"
	chain   = "prerouting"
)

// Runner executes one nft script. It is injectable so tests and callers can
// avoid touching the real firewall.
type Runner func(ctx context.Context, script string) error

// DefaultRunner runs nft with the script on stdin: nft -f -.
func DefaultRunner(ctx context.Context, script string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return fmt.Errorf("netlink: nft -f -: %w: %s", err, detail)
		}
		return fmt.Errorf("netlink: nft -f -: %w", err)
	}
	return nil
}

// BuildRuleset renders an nftables ruleset for the mapped prefixes. Only the
// configured mapped prefixes are redirected, and localClientPrefix is
// subtracted from each prefix so local Tesla clients are never redirected.
//
// Only IPv4 prefixes are supported because the generated set is ipv4_addr.
// Invalid input, a non-positive port, or prefixes that are entirely covered by
// localClientPrefix result in an error.
func BuildRuleset(prefixes []netip.Prefix, proxyPort int, localClientPrefix netip.Prefix) (string, error) {
	if proxyPort < 1 || proxyPort > 65535 {
		return "", fmt.Errorf("netlink: invalid proxy port %d", proxyPort)
	}
	if !localClientPrefix.IsValid() {
		return "", fmt.Errorf("netlink: invalid local client prefix")
	}
	if !localClientPrefix.Addr().Is4() {
		return "", fmt.Errorf("netlink: local client prefix %s must be IPv4", localClientPrefix)
	}
	if len(prefixes) == 0 {
		return "", fmt.Errorf("netlink: no mapped prefixes to install")
	}
	local := localClientPrefix.Masked()

	elements := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for i, raw := range prefixes {
		if !raw.IsValid() {
			return "", fmt.Errorf("netlink: prefixes[%d]: invalid prefix", i)
		}
		if !raw.Addr().Is4() {
			return "", fmt.Errorf("netlink: prefixes[%d] %s: only IPv4 prefixes are supported", i, raw)
		}
		for _, p := range subtractPrefix(raw.Masked(), local) {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			elements = append(elements, p)
		}
	}
	if len(elements) == 0 {
		return "", fmt.Errorf(
			"netlink: no mapped prefixes remain after excluding local client prefix %s",
			local,
		)
	}

	sort.Slice(elements, func(i, j int) bool {
		if c := elements[i].Addr().Compare(elements[j].Addr()); c != 0 {
			return c < 0
		}
		return elements[i].Bits() < elements[j].Bits()
	})

	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n", TableFamily, TableName)
	fmt.Fprintf(&b, "\tset %s {\n", setName)
	b.WriteString("\t\ttype ipv4_addr\n")
	b.WriteString("\t\tflags interval\n")
	b.WriteString("\t\tauto-merge\n")
	b.WriteString("\t\telements = { ")
	for i, p := range elements {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.String())
	}
	b.WriteString(" }\n")
	b.WriteString("\t}\n\n")
	fmt.Fprintf(&b, "\tchain %s {\n", chain)
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\tip daddr @%s tcp dport 1-65535 redirect to :%d\n", setName, proxyPort)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// Apply installs ruleset atomically and idempotently. The generated script
// first makes sure the table exists, then deletes it, then adds the new table.
// The extra "add table" matters: deleting a missing table makes nft abort the
// whole batch, while add is idempotent.
func Apply(ctx context.Context, ruleset string, runner Runner) error {
	if strings.TrimSpace(ruleset) == "" {
		return fmt.Errorf("netlink: empty nft ruleset")
	}
	if runner == nil {
		runner = DefaultRunner
	}
	script := fmt.Sprintf(
		"# Recreate the %s table atomically; add table is idempotent so delete does not fail.\n"+
			"add table %s %s\ndelete table %s %s\n%s",
		TableName, TableFamily, TableName, TableFamily, TableName, ruleset,
	)
	if err := runner(ctx, script); err != nil {
		return fmt.Errorf("netlink: apply nft ruleset: %w", err)
	}
	return nil
}

// Cleanup removes the managed nftables table. A missing table is treated as
// success so repeated shutdowns are harmless.
func Cleanup(runner Runner) error {
	script := fmt.Sprintf("delete table %s %s\n", TableFamily, TableName)
	if runner == nil {
		return cleanupDefault(script)
	}
	if err := runner(context.Background(), script); err != nil {
		return fmt.Errorf("netlink: clean up nft table: %w", err)
	}
	return nil
}

func cleanupDefault(script string) error {
	err := DefaultRunner(context.Background(), script)
	if err == nil {
		return nil
	}
	// nft exits non-zero when the table is already absent. That is the desired
	// end state, so only genuine failures are reported.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "not exist") {
		return nil
	}
	return fmt.Errorf("netlink: clean up nft table: %w", err)
}

// subtractPrefix returns prefix minus exclude as the smallest set of CIDR
// blocks. Both prefixes are expected to be valid IPv4 prefixes.
func subtractPrefix(prefix, exclude netip.Prefix) []netip.Prefix {
	prefix = prefix.Masked()
	exclude = exclude.Masked()
	if !prefix.Overlaps(exclude) {
		return []netip.Prefix{prefix}
	}

	prefixStart, prefixEnd := prefixRange(prefix)
	excludeStart, excludeEnd := prefixRange(exclude)

	var out []netip.Prefix
	if prefixStart < excludeStart {
		hi := excludeStart - 1
		if hi > prefixEnd {
			hi = prefixEnd
		}
		out = append(out, rangePrefixes(prefixStart, hi)...)
	}
	if prefixEnd > excludeEnd {
		lo := excludeEnd + 1
		if lo < prefixStart {
			lo = prefixStart
		}
		out = append(out, rangePrefixes(lo, prefixEnd)...)
	}
	return out
}

func prefixRange(p netip.Prefix) (start, end uint64) {
	a := p.Masked().Addr().As4()
	start = uint64(binary.BigEndian.Uint32(a[:]))
	size := uint64(1) << uint(32-p.Bits())
	return start, start + size - 1
}

// rangePrefixes converts an inclusive IPv4 address range into the minimal list
// of canonical CIDR prefixes, in ascending order.
func rangePrefixes(start, end uint64) []netip.Prefix {
	var out []netip.Prefix
	for start <= end {
		hostBits := 0
		if start != 0 {
			hostBits = bits.TrailingZeros64(start)
		}
		if hostBits > 32 {
			hostBits = 32
		}
		if maxBySize := bits.Len64(end-start+1) - 1; maxBySize < hostBits {
			hostBits = maxBySize
		}

		out = append(out, netip.PrefixFrom(addrFromUint32(uint32(start)), 32-hostBits))
		start += uint64(1) << uint(hostBits)
	}
	return out
}

func addrFromUint32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
