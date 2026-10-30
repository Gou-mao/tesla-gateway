package resolvers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
)

// ChainResolver tries resolvers in order and returns the first hit. Resolver
// errors are collected and only returned when no resolver hits.
type ChainResolver struct {
	resolvers []tgdns.Resolver
}

// NewChain creates a resolver chain. Nil resolvers are ignored.
func NewChain(resolvers ...tgdns.Resolver) *ChainResolver {
	filtered := make([]tgdns.Resolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver != nil {
			filtered = append(filtered, resolver)
		}
	}
	return &ChainResolver{resolvers: filtered}
}

// Name implements tgdns.Resolver.
func (c *ChainResolver) Name() string {
	if c == nil || len(c.resolvers) == 0 {
		return "chain"
	}
	names := make([]string, 0, len(c.resolvers))
	for _, resolver := range c.resolvers {
		names = append(names, resolver.Name())
	}
	return "chain(" + strings.Join(names, ",") + ")"
}

// Resolvers returns a copy of the chain members.
func (c *ChainResolver) Resolvers() []tgdns.Resolver {
	if c == nil {
		return nil
	}
	return append([]tgdns.Resolver(nil), c.resolvers...)
}

// Lookup implements tgdns.Resolver.
func (c *ChainResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	records, _, hit, err := c.LookupSource(ctx, q)
	return records, hit, err
}

// LookupSource implements tgdns.SourceResolver and reports the name of the
// provider that hit.
func (c *ChainResolver) LookupSource(ctx context.Context, q mdns.Question) ([]mdns.RR, string, bool, error) {
	if c == nil || len(c.resolvers) == 0 {
		return nil, "", false, nil
	}

	var errs []error
	for _, resolver := range c.resolvers {
		if err := ctx.Err(); err != nil {
			return nil, "", false, err
		}

		records, hit, err := resolver.Lookup(ctx, q)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, "", false, ctxErr
			}
			errs = append(errs, fmt.Errorf("%s: %w", resolver.Name(), err))
			continue
		}
		if hit {
			return records, resolver.Name(), true, nil
		}
	}

	return nil, "", false, errors.Join(errs...)
}

var (
	_ tgdns.Resolver       = (*ChainResolver)(nil)
	_ tgdns.SourceResolver = (*ChainResolver)(nil)
)
