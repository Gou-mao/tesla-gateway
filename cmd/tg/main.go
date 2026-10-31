package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"tesla-gateway/internal/config"
	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/dns/resolvers"
	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/mapping"
	"tesla-gateway/internal/netlink"
	tgproxy "tesla-gateway/internal/proxy"
	"tesla-gateway/internal/stats"
)

// version is reported in the stats file. It can be overridden at build time
// with -ldflags "-X main.version=...".
var version = "dev"

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
	runtimeStats := stats.New()

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

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	var (
		server          *tgdns.Server
		cache           *tgdns.Cache
		dnsRuntimeState atomic.Pointer[dnsRuntime]
	)
	if strings.TrimSpace(cfg.DNS.Listen) == "" {
		logger.Warn("dns.listen is empty; DNS service is disabled", nil)
	} else {
		cache = tgdns.NewCache(cfg.DNS.CacheMax)
		runtimeStats.SetCache(cache)
		runtime, err := buildDNSRuntime(cfg, engine, logger)
		if err != nil {
			logger.Error("failed to build DNS resolver chain", logx.Fields{
				"error": err.Error(),
			})
			return 1
		}

		server, err = tgdns.NewServer(tgdns.ServerConfig{
			Listen:   cfg.DNS.Listen,
			Local:    runtime.local,
			Upstream: runtime.upstream,
			Cache:    cache,
			Rewriter: runtime.rewriter,
			Logger:   logger.WithModule("dns"),
			Stats:    runtimeStats,
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
		dnsRuntimeState.Store(runtime)
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
	}

	var (
		tcpProxy   *tgproxy.TCPProxy
		nftApplied bool
	)
	if strings.TrimSpace(cfg.Proxy.TCPListen) == "" {
		logger.Warn("proxy.tcp_listen is empty; TCP transparent proxy is disabled", nil)
	} else {
		tcpProxy, err = tgproxy.NewTCPProxy(tgproxy.TCPConfig{
			Listen:      cfg.Proxy.TCPListen,
			KeepAlive:   cfg.Proxy.KeepAlive,
			MaxConns:    cfg.Proxy.MaxConns,
			IdleTimeout: cfg.Proxy.IdleTimeout,
			Stats:       runtimeStats,
		}, engine, logger)
		if err != nil {
			if server != nil {
				_ = server.Close()
			}
			logger.Error("failed to create TCP proxy", logx.Fields{
				"error": err.Error(),
			})
			return 1
		}
		if err := tcpProxy.Start(rootCtx); err != nil {
			if server != nil {
				_ = server.Close()
			}
			logger.Error("failed to start TCP proxy", logx.Fields{
				"error": err.Error(),
			})
			return 1
		}
		logger.Info("TCP proxy started", logx.Fields{
			"listen":       tcpProxy.Addr(),
			"mode":         cfg.Proxy.Mode,
			"keepalive":    cfg.Proxy.KeepAlive,
			"max_conns":    cfg.Proxy.MaxConns,
			"idle_timeout": cfg.Proxy.IdleTimeout,
		})
	}

	if cfg.Proxy.ApplyNft {
		if tcpProxy == nil {
			logger.Error("proxy.apply_nft is true but the TCP proxy is disabled; set proxy.tcp_listen", nil)
			if server != nil {
				_ = server.Close()
			}
			return 1
		}

		proxyPort, err := parseProxyPort(cfg.Proxy.TCPListen)
		if err != nil {
			logger.Error("failed to parse proxy.tcp_listen for nft", logx.Fields{
				"error": err.Error(),
			})
			_ = tcpProxy.Stop()
			if server != nil {
				_ = server.Close()
			}
			return 1
		}
		localPrefix, err := netip.ParsePrefix(cfg.Proxy.LocalClientPrefix)
		if err != nil {
			logger.Error("failed to parse proxy.local_client_prefix", logx.Fields{
				"prefix": cfg.Proxy.LocalClientPrefix,
				"error":  err.Error(),
			})
			_ = tcpProxy.Stop()
			if server != nil {
				_ = server.Close()
			}
			return 1
		}

		ruleset, err := netlink.BuildRuleset(engine.MappedPrefixes(), proxyPort, localPrefix)
		if err != nil {
			logger.Error("failed to build nft ruleset", logx.Fields{
				"error": err.Error(),
			})
			_ = tcpProxy.Stop()
			if server != nil {
				_ = server.Close()
			}
			return 1
		}
		if err := netlink.Apply(rootCtx, ruleset, nil); err != nil {
			logger.Error("failed to apply nft rules", logx.Fields{
				"error": err.Error(),
			})
			_ = tcpProxy.Stop()
			if server != nil {
				_ = server.Close()
			}
			return 1
		}
		nftApplied = true
		logger.Info("nft rules applied", logx.Fields{
			"table":               netlink.TableName,
			"proxy_port":          proxyPort,
			"local_client_prefix": localPrefix.String(),
			"mapped_prefixes":     engine.MappedPrefixes(),
		})
	}

	if server == nil && tcpProxy == nil {
		logger.Warn("no service is enabled; set dns.listen and/or proxy.tcp_listen", nil)
		return 0
	}

	var statsWriterDone <-chan struct{}
	listeners := stats.Listeners{}
	if server != nil {
		listeners.DNS = server.Addr()
	}
	if tcpProxy != nil {
		listeners.Proxy = tcpProxy.Addr()
	}

	statsWriter, err := stats.NewWriter(stats.WriterConfig{
		Path: cfg.StatsPath,
		Meta: statsMeta(cfg, version, listeners),
		EffectiveUpstream: func() []string {
			runtime := dnsRuntimeState.Load()
			if runtime == nil || runtime.system == nil {
				return nil
			}
			return runtime.system.EffectiveUpstreams()
		},
	}, runtimeStats, logger.WithModule("stats"))
	if err != nil {
		// Stats publication is best-effort; it must never prevent the gateway
		// from serving traffic.
		logger.Warn("failed to initialize stats writer; continuing without runtime stats", logx.Fields{
			"path":  cfg.StatsPath,
			"error": err.Error(),
		})
	} else {
		logger.Info("stats writer started", logx.Fields{
			"path":     statsWriter.Path(),
			"interval": statsWriter.Interval().String(),
		})
		done := make(chan struct{})
		statsWriterDone = done
		go func() {
			defer close(done)
			statsWriter.Run(rootCtx)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			if err := reload(*configPath, cfg, server, cache, tcpProxy, &dnsRuntimeState, logger); err != nil {
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

	exitCode := 0
	if nftApplied {
		if err := netlink.Cleanup(nil); err != nil {
			logger.Error("failed to clean up nft rules", logx.Fields{
				"error": err.Error(),
			})
			exitCode = 1
		} else {
			logger.Info("nft rules cleaned up", logx.Fields{
				"table": netlink.TableName,
			})
		}
	}
	if tcpProxy != nil {
		if err := tcpProxy.Stop(); err != nil {
			logger.Error("failed to stop TCP proxy", logx.Fields{
				"error": err.Error(),
			})
			exitCode = 1
		}
	}
	if server != nil {
		if err := server.Close(); err != nil {
			logger.Error("failed to stop DNS server", logx.Fields{
				"error": err.Error(),
			})
			exitCode = 1
		}
	}
	// Stop the publisher after the services are down so the final snapshot
	// reflects the drained connection counters. Run writes it on cancel.
	cancelRoot()
	if statsWriterDone != nil {
		<-statsWriterDone
	}
	logger.Info("tesla-gateway stopped", nil)
	return exitCode
}

func statsMeta(cfg *config.Config, version string, listeners stats.Listeners) stats.Meta {
	mappings := make([]stats.Mapping, 0, len(cfg.Mappings))
	for _, pair := range cfg.Mappings {
		mappings = append(mappings, stats.Mapping{
			From: pair.From,
			To:   pair.To,
		})
	}

	upstream := make([]string, 0, len(cfg.DNS.Upstream))
	upstream = append(upstream, cfg.DNS.Upstream...)

	// Static fallback for configurations without a live system resolver. When
	// DNS is running, the writer replaces this with the resolver's current
	// effective list, including any DHCP expansion.
	effective := make([]string, 0, len(cfg.DNS.Upstream))
	for _, raw := range cfg.DNS.Upstream {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "dhcp", "auto":
			continue
		default:
			effective = append(effective, strings.TrimSpace(raw))
		}
	}

	return stats.Meta{
		Version:              version,
		Listeners:            listeners,
		Mappings:             mappings,
		MappingStrategy:      cfg.MappingStrategy,
		DNSListen:            cfg.DNS.Listen,
		DNSUpstream:          upstream,
		DNSUpstreamEffective: effective,
	}
}

type dnsRuntime struct {
	local    tgdns.Resolver
	upstream tgdns.Resolver
	rewriter *tgdns.Rewriter
	system   *resolvers.SystemResolver
}

func buildDNSRuntime(cfg *config.Config, engine *mapping.Engine, logger *logx.Logger) (*dnsRuntime, error) {
	names := cfg.DNS.Resolvers
	if len(names) == 0 {
		names = []string{"hosts", "lease", "system"}
	}

	local := make([]tgdns.Resolver, 0, len(names))
	var upstream tgdns.Resolver
	var system *resolvers.SystemResolver

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
			var err error
			system, err = resolvers.NewSystemResolver(
				cfg.DNS.Upstream,
				resolvers.WithSystemLogger(logger.WithModule("dns-upstream")),
			)
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
		system:   system,
	}, nil
}

func parseProxyPort(listen string) (int, error) {
	listen = strings.TrimSpace(listen)
	_, rawPort, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("split %q: %w", listen, err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q: invalid TCP port %q", listen, rawPort)
	}
	return port, nil
}

func reload(path string, current *config.Config, server *tgdns.Server, cache *tgdns.Cache, tcpProxy *tgproxy.TCPProxy, dnsRuntimeState *atomic.Pointer[dnsRuntime], logger *logx.Logger) error {
	next, err := config.Load(path)
	if err != nil {
		return err
	}

	engine := mapping.NewEngine(next.Strategy)
	if err := engine.Validate(); err != nil {
		return err
	}

	var runtime *dnsRuntime
	if server != nil {
		runtime, err = buildDNSRuntime(next, engine, logger)
		if err != nil {
			return err
		}
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
	if next.StatsPath != current.StatsPath {
		logger.Warn("stats_path changed; restart is required to move the stats file", logx.Fields{
			"old": current.StatsPath,
			"new": next.StatsPath,
		})
	}

	// TCP proxy listeners and mapping engines are intentionally not rebuilt on
	// SIGHUP. DNS reloads in place; proxy changes require a restart.
	if tcpProxy != nil {
		if next.Proxy.TCPListen != current.Proxy.TCPListen {
			logger.Warn("proxy.tcp_listen changed; restart is required to move the listener", logx.Fields{
				"old": current.Proxy.TCPListen,
				"new": next.Proxy.TCPListen,
			})
		}
		if next.Proxy.Mode != current.Proxy.Mode ||
			next.Proxy.KeepAlive != current.Proxy.KeepAlive ||
			next.Proxy.MaxConns != current.Proxy.MaxConns ||
			next.Proxy.IdleTimeout != current.Proxy.IdleTimeout {
			logger.Warn("proxy settings changed; restart is required to apply them", logx.Fields{
				"old_mode":         current.Proxy.Mode,
				"new_mode":         next.Proxy.Mode,
				"old_keepalive":    current.Proxy.KeepAlive.String(),
				"new_keepalive":    next.Proxy.KeepAlive.String(),
				"old_max_conns":    current.Proxy.MaxConns,
				"new_max_conns":    next.Proxy.MaxConns,
				"old_idle_timeout": current.Proxy.IdleTimeout.String(),
				"new_idle_timeout": next.Proxy.IdleTimeout.String(),
			})
		}
		if next.MappingStrategy != current.MappingStrategy ||
			!reflect.DeepEqual(next.Mappings, current.Mappings) ||
			!reflect.DeepEqual(next.RealPrefixes, current.RealPrefixes) {
			logger.Warn("mapping rules changed; the TCP proxy keeps its startup mapping until restart", nil)
		}
		if next.Proxy.ApplyNft != current.Proxy.ApplyNft ||
			next.Proxy.LocalClientPrefix != current.Proxy.LocalClientPrefix {
			logger.Warn("nft settings changed; restart is required to reapply nft rules", logx.Fields{
				"old_apply_nft":           current.Proxy.ApplyNft,
				"new_apply_nft":           next.Proxy.ApplyNft,
				"old_local_client_prefix": current.Proxy.LocalClientPrefix,
				"new_local_client_prefix": next.Proxy.LocalClientPrefix,
			})
		}
	}

	if server != nil {
		server.Reload(runtime.local, runtime.upstream, runtime.rewriter)
		if dnsRuntimeState != nil {
			dnsRuntimeState.Store(runtime)
		}
		if cache != nil {
			cache.Clear()
		}
	}
	*current = *next

	logger.Info("configuration reloaded", logx.Fields{
		"config":    path,
		"resolvers": current.DNS.Resolvers,
		"upstream":  current.DNS.Upstream,
		"clamp_ttl": current.DNS.ClampTTL,
		"drop_aaaa": current.DNS.DropAAAA,
	})
	return nil
}
