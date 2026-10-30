package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tesla-gateway/internal/config"
	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/dns/resolvers"
	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/mapping"
)

func main() {
	os.Exit(run())
}

func run() int {
	bootstrap, err := logx.New(logx.Config{})
	if err != nil {
		// The default logger cannot fail, but avoid a nil dereference if the
		// logger implementation changes.
		os.Exit(1)
	}

	configPath := flag.String("config", config.DefaultPath, "path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		bootstrap.Error("failed to load configuration", logx.Fields{
			"module": "main",
			"config": *configPath,
			"error":  err.Error(),
		})
		return 1
	}

	logger, err := logx.New(logx.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: os.Stderr,
	})
	if err != nil {
		bootstrap.Error("failed to initialize logger", logx.Fields{
			"module": "main",
			"error":  err.Error(),
		})
		return 1
	}
	logger = logger.WithModule("main")

	engine := mapping.NewEngine(cfg.Strategy)
	if err := engine.Validate(); err != nil {
		logger.Error("mapping validation failed", logx.Fields{
			"error": err.Error(),
		})
		return 1
	}

	logger.Info("tesla-gateway starting", logx.Fields{
		"config":           *configPath,
		"mapping_strategy": cfg.MappingStrategy,
		"mapped_prefixes":  engine.MappedPrefixes(),
		"dns_listen":       cfg.DNS.Listen,
		"proxy_mode":       cfg.Proxy.Mode,
		"proxy_tcp_listen": cfg.Proxy.TCPListen,
	})

	if strings.TrimSpace(cfg.DNS.Listen) == "" {
		logger.Warn("dns.listen is empty; DNS service is disabled", nil)
		return 0
	}

	cache := tgdns.NewCache(cfg.DNS.CacheMax)
	runtime, err := buildDNSRuntime(cfg, engine)
	if err != nil {
		logger.Error("failed to build DNS resolver chain", logx.Fields{
			"error": err.Error(),
		})
		return 1
	}

	server, err := tgdns.NewServer(tgdns.ServerConfig{
		Listen:   cfg.DNS.Listen,
		Local:    runtime.local,
		Upstream: runtime.upstream,
		Cache:    cache,
		Rewriter: runtime.rewriter,
		Logger:   logger.WithModule("dns"),
	})
	if err != nil {
		logger.Error("failed to create DNS server", logx.Fields{
			"error": err.Error(),
		})
		return 1
	}
	if err := server.Start(); err != nil {
		logger.Error("failed to start DNS server", logx.Fields{
			"error": err.Error(),
		})
		return 1
	}
	logger.Info("DNS server started", logx.Fields{
		"listen":          server.Addr(),
		"resolvers":       cfg.DNS.Resolvers,
		"upstream":        cfg.DNS.Upstream,
		"cache_max":       cfg.DNS.CacheMax,
		"clamp_ttl":       cfg.DNS.ClampTTL,
		"drop_aaaa":       cfg.DNS.DropAAAA,
		"mapping_engine":  cfg.MappingStrategy,
		"mapped_prefixes": engine.MappedPrefixes(),
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			if err := reload(*configPath, cfg, server, cache, logger); err != nil {
				logger.Error("configuration reload failed; keeping previous configuration", logx.Fields{
					"config": *configPath,
					"error":  err.Error(),
				})
			}
			continue
		}

		logger.Info("shutting down", logx.Fields{
			"signal": sig.String(),
		})
		break
	}

	if err := server.Close(); err != nil {
		logger.Error("failed to stop DNS server", logx.Fields{
			"error": err.Error(),
		})
		return 1
	}
	logger.Info("tesla-gateway stopped", nil)
	return 0
}

type dnsRuntime struct {
	local    tgdns.Resolver
	upstream tgdns.Resolver
	rewriter *tgdns.Rewriter
}

func buildDNSRuntime(cfg *config.Config, engine *mapping.Engine) (*dnsRuntime, error) {
	names := cfg.DNS.Resolvers
	if len(names) == 0 {
		names = []string{"hosts", "lease", "system"}
	}

	local := make([]tgdns.Resolver, 0, len(names))
	var upstream tgdns.Resolver

	for _, raw := range names {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "hosts":
			local = append(local, resolvers.NewHostsResolver(cfg.DNS.HostsPath))
		case "lease":
			local = append(local, resolvers.NewLeaseResolver(cfg.DNS.LeasePath))
		case "system":
			if upstream != nil {
				return nil, fmt.Errorf("dns: resolver %q is configured more than once", raw)
			}
			system, err := resolvers.NewSystemResolver(cfg.DNS.Upstream)
			if err != nil {
				return nil, err
			}
			upstream = system
		default:
			return nil, fmt.Errorf("dns: unsupported resolver %q", raw)
		}
	}

	return &dnsRuntime{
		local:    resolvers.NewChain(local...),
		upstream: upstream,
		rewriter: tgdns.NewRewriter(engine, cfg.DNS.ClampTTL, cfg.DNS.DropAAAA),
	}, nil
}

func reload(path string, current *config.Config, server *tgdns.Server, cache *tgdns.Cache, logger *logx.Logger) error {
	next, err := config.Load(path)
	if err != nil {
		return err
	}

	engine := mapping.NewEngine(next.Strategy)
	if err := engine.Validate(); err != nil {
		return err
	}

	runtime, err := buildDNSRuntime(next, engine)
	if err != nil {
		return err
	}

	if next.DNS.Listen != current.DNS.Listen {
		logger.Warn("dns.listen changed; restart is required to move the listener", logx.Fields{
			"old": current.DNS.Listen,
			"new": next.DNS.Listen,
		})
	}
	if next.DNS.CacheMax != current.DNS.CacheMax {
		logger.Warn("dns.cache_max changed; restart is required to resize the cache", logx.Fields{
			"old": current.DNS.CacheMax,
			"new": next.DNS.CacheMax,
		})
	}

	server.Reload(runtime.local, runtime.upstream, runtime.rewriter)
	cache.Clear()
	*current = *next

	logger.Info("configuration reloaded; DNS cache cleared", logx.Fields{
		"config":    path,
		"resolvers": current.DNS.Resolvers,
		"upstream":  current.DNS.Upstream,
		"clamp_ttl": current.DNS.ClampTTL,
		"drop_aaaa": current.DNS.DropAAAA,
	})
	return nil
}
