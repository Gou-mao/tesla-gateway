package dns

import (
	"net"
	"net/netip"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/mapping"
)

// Translation records one real-to-mapped address replacement for logging.
type Translation struct {
	Real   netip.Addr
	Mapped netip.Addr
}

// RewriteOptions configures response rewriting.
type RewriteOptions struct {
	// Engine is the single source of address translation. A nil engine leaves
	// A records untouched.
	Engine *mapping.Engine
	// ClampTTL caps the TTL of every non-OPT record when greater than zero.
	ClampTTL uint32
	// DropAAAA removes AAAA records from the response when true. Otherwise
	// AAAA records are passed through untouched.
	DropAAAA bool
}

// Rewriter applies mapping and TTL policy to DNS responses. It never mutates
// the input message, so cached real answers can be rewritten per request.
type Rewriter struct {
	opts RewriteOptions
}

// NewRewriter creates a rewriter. A negative clampTTL means no clamping.
func NewRewriter(engine *mapping.Engine, clampTTL int, dropAAAA bool) *Rewriter {
	if clampTTL < 0 {
		clampTTL = 0
	}
	return &Rewriter{opts: RewriteOptions{
		Engine:   engine,
		ClampTTL: uint32(clampTTL),
		DropAAAA: dropAAAA,
	}}
}

// Options returns a copy of the rewriter's options.
func (r *Rewriter) Options() RewriteOptions {
	if r == nil {
		return RewriteOptions{}
	}
	return r.opts
}

// Rewrite returns a rewritten deep copy of msg.
func (r *Rewriter) Rewrite(msg *mdns.Msg) *mdns.Msg {
	if r == nil {
		return Rewrite(msg, RewriteOptions{})
	}
	return Rewrite(msg, r.opts)
}

// RewriteWithTranslations returns a rewritten deep copy of msg and the address
// replacements that were applied.
func (r *Rewriter) RewriteWithTranslations(msg *mdns.Msg) (*mdns.Msg, []Translation) {
	if r == nil {
		return RewriteWithTranslations(msg, RewriteOptions{})
	}
	return RewriteWithTranslations(msg, r.opts)
}

// Rewrite returns a rewritten deep copy of msg. A records are translated with
// the mapping engine, AAAA records are passed through (or dropped), CNAMEs are
// preserved, and all records keep their original TTL unless ClampTTL is set.
// OPT records and DNSSEC header flags are left untouched.
func Rewrite(msg *mdns.Msg, opts RewriteOptions) *mdns.Msg {
	out, _ := RewriteWithTranslations(msg, opts)
	return out
}

// RewriteWithTranslations is Rewrite plus a report of the real-to-mapped
// replacements. The input message is not modified.
func RewriteWithTranslations(msg *mdns.Msg, opts RewriteOptions) (*mdns.Msg, []Translation) {
	if msg == nil {
		return nil, nil
	}

	out := msg.Copy()
	var translations []Translation
	out.Answer = rewriteRRs(out.Answer, opts, &translations)
	out.Ns = rewriteRRs(out.Ns, opts, &translations)
	out.Extra = rewriteRRs(out.Extra, opts, &translations)
	return out, translations
}

func rewriteRRs(rrs []mdns.RR, opts RewriteOptions, translations *[]Translation) []mdns.RR {
	if len(rrs) == 0 {
		return rrs
	}

	out := make([]mdns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		// OPT's TTL field carries the extended rcode, version, and DO bit.
		// Never clamp or otherwise touch it.
		if rr.Header().Rrtype == mdns.TypeOPT {
			out = append(out, rr)
			continue
		}

		if opts.ClampTTL > 0 && rr.Header().Ttl > opts.ClampTTL {
			rr.Header().Ttl = opts.ClampTTL
		}

		switch record := rr.(type) {
		case *mdns.A:
			if opts.Engine != nil {
				real, ok := netip.AddrFromSlice(record.A)
				if ok {
					real = real.Unmap()
					if mapped, hit := opts.Engine.Translate(real); hit && mapped.Is4() {
						record.A = net.IP(mapped.AsSlice())
						*translations = append(*translations, Translation{
							Real:   real,
							Mapped: mapped,
						})
					}
				}
			}
		case *mdns.AAAA:
			if opts.DropAAAA {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}
