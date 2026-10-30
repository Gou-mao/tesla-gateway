package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/logx"
)

const (
	defaultQueryTimeout = 10 * time.Second
	startupTimeout      = 3 * time.Second
	shutdownTimeout     = 5 * time.Second
)

// ServerConfig configures the DNS server.
type ServerConfig struct {
	// Listen is the UDP and TCP listen address, for example "0.0.0.0:53".
	Listen string
	// Local is the local resolver chain (hosts, leases, ...).
	Local Resolver
	// Upstream forwards cache misses. SystemResolver implements
	// MessageResolver so rcodes, SOA negative answers, EDNS0, and DNSSEC flags
	// survive the round trip.
	Upstream Resolver
	// Cache stores real upstream responses. A nil cache creates a default one.
	Cache *Cache
	// Rewriter applies mapping and TTL policy on output. A nil rewriter leaves
	// records unchanged.
	Rewriter *Rewriter
	// Logger receives structured query records. A nil logger gets a default
	// JSON logger with module=dns.
	Logger *logx.Logger
}

type serverRuntime struct {
	local    Resolver
	upstream Resolver
	rewriter *Rewriter
}

// Server serves DNS over UDP and TCP. It can be reloaded atomically with
// Reload while serving.
type Server struct {
	listen string
	cache  *Cache
	logger *logx.Logger

	runtime atomic.Pointer[serverRuntime]

	mu          sync.Mutex
	udp         *mdns.Server
	tcp         *mdns.Server
	udpConn     net.PacketConn
	tcpListener net.Listener
	udpAddr     net.Addr
	closed      bool
}

// NewServer creates a DNS server. Call Start to bind and serve.
func NewServer(cfg ServerConfig) (*Server, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, errors.New("dns: listen address is empty")
	}

	cache := cfg.Cache
	if cache == nil {
		cache = NewCache(0)
	}
	rewriter := cfg.Rewriter
	if rewriter == nil {
		rewriter = NewRewriter(nil, 0, false)
	}
	logger := cfg.Logger
	if logger == nil {
		var err error
		logger, err = logx.New(logx.Config{Module: "dns"})
		if err != nil {
			return nil, fmt.Errorf("dns: create logger: %w", err)
		}
	}

	s := &Server{
		listen: cfg.Listen,
		cache:  cache,
		logger: logger,
	}
	s.runtime.Store(&serverRuntime{
		local:    cfg.Local,
		upstream: cfg.Upstream,
		rewriter: rewriter,
	})
	return s, nil
}

// Reload atomically replaces the local resolver, upstream resolver, and
// rewriter. Listener changes require a restart.
func (s *Server) Reload(local, upstream Resolver, rewriter *Rewriter) {
	if s == nil {
		return
	}
	s.runtime.Store(&serverRuntime{
		local:    local,
		upstream: upstream,
		rewriter: rewriter,
	})
}

// ClearCache removes every cached response.
func (s *Server) ClearCache() {
	if s != nil && s.cache != nil {
		s.cache.Clear()
	}
}

// Cache returns the server cache.
func (s *Server) Cache() *Cache {
	if s == nil {
		return nil
	}
	return s.cache
}

// Addr returns the actual UDP listen address after Start.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpAddr != nil {
		return s.udpAddr.String()
	}
	return s.listen
}

// Start binds UDP and TCP and begins serving. When the configured port is 0,
// the TCP listener uses the port selected by the UDP listener.
func (s *Server) Start() error {
	if s == nil {
		return errors.New("dns: nil server")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("dns: server is closed")
	}
	if s.udp != nil || s.tcp != nil {
		s.mu.Unlock()
		return errors.New("dns: server already started")
	}

	udpConn, err := net.ListenPacket("udp", s.listen)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("dns: listen udp %s: %w", s.listen, err)
	}

	tcpAddr := s.listen
	if _, port, splitErr := net.SplitHostPort(s.listen); splitErr == nil && port == "0" {
		host, actualPort, splitErr := net.SplitHostPort(udpConn.LocalAddr().String())
		if splitErr != nil {
			_ = udpConn.Close()
			s.mu.Unlock()
			return fmt.Errorf("dns: resolve ephemeral port: %w", splitErr)
		}
		tcpAddr = net.JoinHostPort(host, actualPort)
	}

	tcpListener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		s.mu.Unlock()
		return fmt.Errorf("dns: listen tcp %s: %w", tcpAddr, err)
	}

	udpServer := &mdns.Server{PacketConn: udpConn, Handler: s}
	tcpServer := &mdns.Server{Listener: tcpListener, Handler: s}

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	udpErr := make(chan error, 1)
	tcpErr := make(chan error, 1)
	udpServer.NotifyStartedFunc = func() { close(udpReady) }
	tcpServer.NotifyStartedFunc = func() { close(tcpReady) }

	s.udp = udpServer
	s.tcp = tcpServer
	s.udpConn = udpConn
	s.tcpListener = tcpListener
	s.udpAddr = udpConn.LocalAddr()
	s.mu.Unlock()

	go s.serve("udp", udpServer, udpErr)
	go s.serve("tcp", tcpServer, tcpErr)

	if err := waitStarted("udp", udpReady, udpErr); err != nil {
		s.abortStart(udpServer, tcpServer, udpConn, tcpListener)
		return err
	}
	if err := waitStarted("tcp", tcpReady, tcpErr); err != nil {
		s.abortStart(udpServer, tcpServer, udpConn, tcpListener)
		return err
	}
	return nil
}

// Close gracefully stops the UDP and TCP servers and closes their listeners.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	udpServer, tcpServer := s.udp, s.tcp
	udpConn, tcpListener := s.udpConn, s.tcpListener
	s.mu.Unlock()

	return s.shutdown(udpServer, tcpServer, udpConn, tcpListener)
}

func (s *Server) serve(network string, server *mdns.Server, errCh chan<- error) {
	err := server.ActivateAndServe()
	select {
	case errCh <- err:
	default:
	}
	if err != nil && !s.isClosed() {
		s.logger.Warn("dns server stopped", logx.Fields{
			"network": network,
			"error":   err.Error(),
		})
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func waitStarted(network string, ready <-chan struct{}, errCh <-chan error) error {
	timer := time.NewTimer(startupTimeout)
	defer timer.Stop()

	select {
	case <-ready:
		return nil
	case err := <-errCh:
		if err == nil {
			err = errors.New("server stopped before it became ready")
		}
		return fmt.Errorf("dns: start %s server: %w", network, err)
	case <-timer.C:
		return fmt.Errorf("dns: start %s server: timed out after %s", network, startupTimeout)
	}
}

func (s *Server) abortStart(udp, tcp *mdns.Server, udpConn net.PacketConn, tcpListener net.Listener) {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	_ = s.shutdown(udp, tcp, udpConn, tcpListener)
}

func (s *Server) shutdown(udp, tcp *mdns.Server, udpConn net.PacketConn, tcpListener net.Listener) error {
	var errs []error

	shutdownOne := func(network string, server *mdns.Server) {
		if server == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil && !isNotStarted(err) {
			errs = append(errs, fmt.Errorf("dns: shutdown %s: %w", network, err))
		}
	}
	shutdownOne("udp", udp)
	shutdownOne("tcp", tcp)

	if udpConn != nil {
		_ = udpConn.Close()
	}
	if tcpListener != nil {
		_ = tcpListener.Close()
	}
	return errors.Join(errs...)
}

func isNotStarted(err error) bool {
	return err != nil && strings.Contains(err.Error(), "server not started")
}

// ServeDNS implements mdns.Handler.
func (s *Server) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	if s == nil || req == nil {
		return
	}

	start := time.Now()
	if req.Opcode != mdns.OpcodeQuery {
		s.writeResponse(w, req, errorReply(req, mdns.RcodeNotImplemented))
		return
	}
	if len(req.Question) != 1 {
		s.writeResponse(w, req, errorReply(req, mdns.RcodeFormatError))
		return
	}

	q := req.Question[0]
	runtime := s.runtime.Load()
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	var (
		resp         *mdns.Msg
		source       string
		queryErr     error
		translations []Translation
	)

	// 1. Local names (hosts, leases, static, ...).
	if runtime != nil && runtime.local != nil {
		var (
			records []mdns.RR
			hit     bool
			err     error
		)
		if sourced, ok := runtime.local.(SourceResolver); ok {
			records, source, hit, err = sourced.LookupSource(ctx, q)
		} else {
			records, hit, err = runtime.local.Lookup(ctx, q)
			if hit {
				source = runtime.local.Name()
			}
		}
		if err != nil {
			// Local provider errors (for example a missing optional lease file)
			// must not prevent the upstream lookup.
			queryErr = err
		}
		if hit {
			resp = localReply(req, records)
		}
	}

	// 2. Cache of real upstream responses.
	if resp == nil && s.cache != nil {
		if cached, hit := s.cache.Get(q); hit {
			resp = replyFromCached(req, cached)
			source = "cache"
			queryErr = nil
		}
	}

	// 3. Upstream system resolver.
	if resp == nil {
		queryErr = nil
		if runtime == nil || runtime.upstream == nil {
			resp = errorReply(req, mdns.RcodeServerFailure)
			source = "none"
			queryErr = errors.New("dns: no upstream resolver configured")
		} else {
			source = runtime.upstream.Name()
			if messageResolver, ok := runtime.upstream.(MessageResolver); ok {
				upstreamReq := req.Copy()
				upstreamReq.Response = false

				upstreamResp, err := messageResolver.ExchangeMessage(ctx, upstreamReq)
				if err != nil {
					queryErr = err
					resp = errorReply(req, mdns.RcodeServerFailure)
				} else if upstreamResp != nil {
					if s.cache != nil {
						s.cache.Put(q, upstreamResp)
					}
					resp = replyFromUpstream(req, upstreamResp)
				}
			} else {
				records, hit, err := runtime.upstream.Lookup(ctx, q)
				switch {
				case err != nil:
					queryErr = err
					resp = errorReply(req, mdns.RcodeServerFailure)
				case hit:
					resp = localReply(req, records)
					if s.cache != nil {
						s.cache.Put(q, resp)
					}
				default:
					resp = errorReply(req, mdns.RcodeNameError)
				}
			}
		}
	}

	if resp == nil {
		resp = errorReply(req, mdns.RcodeServerFailure)
	}

	// 4. Map A records only on the way out. Cache entries remain real.
	if runtime != nil && runtime.rewriter != nil {
		resp, translations = runtime.rewriter.RewriteWithTranslations(resp)
	} else {
		resp = resp.Copy()
	}

	if err := s.writeResponse(w, req, resp); err != nil {
		if queryErr == nil {
			queryErr = err
		}
	}

	s.logQuery(q, source, resp, translations, queryErr, time.Since(start))
}

func localReply(req *mdns.Msg, records []mdns.RR) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Compress = true
	resp.Answer = records
	ensureOPT(resp, req)
	return resp
}

func replyFromCached(req, cached *mdns.Msg) *mdns.Msg {
	resp := cached.Copy()
	applyRequestHeader(resp, req)
	resp.Compress = true
	ensureOPT(resp, req)
	return resp
}

func replyFromUpstream(req, upstream *mdns.Msg) *mdns.Msg {
	resp := upstream.Copy()
	applyRequestHeader(resp, req)
	resp.Compress = true
	ensureOPT(resp, req)
	return resp
}

func applyRequestHeader(resp, req *mdns.Msg) {
	resp.Id = req.Id
	resp.Response = true
	resp.Opcode = req.Opcode
	resp.RecursionDesired = req.RecursionDesired
	resp.CheckingDisabled = req.CheckingDisabled
	if len(req.Question) > 0 {
		resp.Question = []mdns.Question{req.Question[0]}
	}
}

func ensureOPT(resp, req *mdns.Msg) {
	if resp == nil || req == nil || resp.IsEdns0() != nil {
		return
	}
	if requestOPT := req.IsEdns0(); requestOPT != nil {
		resp.SetEdns0(requestOPT.UDPSize(), requestOPT.Do())
	}
}

func errorReply(req *mdns.Msg, rcode int) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true
	resp.Compress = true
	ensureOPT(resp, req)
	return resp
}

func (s *Server) writeResponse(w mdns.ResponseWriter, req, resp *mdns.Msg) error {
	if w == nil || resp == nil {
		return errors.New("dns: nil response writer or message")
	}

	if addr := w.LocalAddr(); addr != nil && strings.HasPrefix(addr.Network(), "udp") {
		size := mdns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
			if size < mdns.MinMsgSize {
				size = mdns.MinMsgSize
			}
		}
		if resp.Len() > size {
			resp.Truncate(size)
			if resp.Len() > size {
				resp.Truncated = true
			}
		}
	}
	return w.WriteMsg(resp)
}

func (s *Server) logQuery(q mdns.Question, source string, resp *mdns.Msg, translations []Translation, err error, latency time.Duration) {
	if s.logger == nil {
		return
	}

	fields := logx.Fields{
		"host":       strings.TrimSuffix(q.Name, "."),
		"qtype":      mdns.Type(q.Qtype).String(),
		"source":     source,
		"latency_ms": float64(latency.Microseconds()) / 1000,
	}
	if resp != nil {
		fields["rcode"] = mdns.RcodeToString[resp.Rcode]
	}
	if len(translations) > 0 {
		real := make([]string, 0, len(translations))
		mapped := make([]string, 0, len(translations))
		for _, translation := range translations {
			real = append(real, translation.Real.String())
			mapped = append(mapped, translation.Mapped.String())
		}
		fields["real"] = strings.Join(real, ",")
		fields["mapped"] = strings.Join(mapped, ",")
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	s.logger.Info("dns query", fields)
}
