// Package dns implements the Tesla Gateway intelligent DNS service. Resolvers
// return real (unmapped) records; address mapping is applied only on the way
// out by the rewriter.
package dns

import (
	"context"

	mdns "github.com/miekg/dns"
)

// Resolver is one provider in the resolver chain. Lookup returns records, a
// hit flag, and an error. A miss (hit=false, err=nil) means the next resolver
// should be tried. A hit is terminal even when the record set is empty.
type Resolver interface {
	Name() string
	Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error)
}

// SourceResolver is implemented by resolvers that can report which provider
// produced a hit. It is used for structured query logging.
type SourceResolver interface {
	Resolver
	LookupSource(ctx context.Context, q mdns.Question) ([]mdns.RR, string, bool, error)
}

// MessageResolver is implemented by resolvers that can exchange a complete
// DNS message. The server uses it to preserve EDNS0/DNSSEC flags and to cache
// negative responses (rcode and SOA authority) correctly.
type MessageResolver interface {
	Resolver
	ExchangeMessage(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

// Question and RR aliases keep the package's public API convenient without
// hiding that messages are from github.com/miekg/dns.
type (
	Question = mdns.Question
	RR       = mdns.RR
	Msg      = mdns.Msg
)
