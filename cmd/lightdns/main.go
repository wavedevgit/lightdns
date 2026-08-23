package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"lightdns/internal/admin"
	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/config"
	"lightdns/internal/resolver"
)

func main() {
	configPath := flag.String("config", "", "path to YAML configuration")
	statePath := flag.String("state", "lightdns.state.yaml", "writable YAML state managed by the dashboard")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	if _, statErr := os.Stat(*statePath); statErr == nil {
		cfg, err = config.Load(*statePath)
		if err != nil {
			slog.Error("dashboard state failed", "error", err)
			os.Exit(1)
		}
	} else if !os.IsNotExist(statErr) {
		slog.Error("dashboard state failed", "error", statErr)
		os.Exit(1)
	}
	loader := &blocklist.Loader{
		Files: cfg.Blocklists.Files, URLs: cfg.Blocklists.URLs,
		Block: cfg.Blocking.Denylist, Allow: cfg.Blocking.Allowlist, MaxBytes: cfg.Blocklists.DownloadSize,
		FileRoots: cfg.Blocklists.FileRoots,
	}
	matcher, err := loader.Load(context.Background())
	if err != nil {
		slog.Error("initial blocklist load failed", "error", err)
		os.Exit(1)
	}
	store := blocklist.NewStore(matcher)
	handler, err := resolver.New(resolver.Options{
		Blocklists: store,
		Cache:      cache.New(cfg.Cache.Entries, cfg.Cache.MinTTL, cfg.Cache.MaxTTL),
		Upstreams:  cfg.Upstreams, Timeout: cfg.Timeout, MaxQuestions: cfg.MaxQuestions,
		BlockMode: cfg.Blocking.Mode, BlockIPv4: cfg.Blocking.IPv4, BlockIPv6: cfg.Blocking.IPv6,
		Records: cfg.Records, DNSSEC: cfg.DNSSEC,
	})
	if err != nil {
		slog.Error("resolver setup failed", "error", err)
		os.Exit(1)
	}

	accessHandler := resolver.NewAccessHandler(handler, cfg.Access.Rate, cfg.Access.Burst, cfg.Access.MaxInFlight)
	serverOptions := func(network string) *dns.Server {
		return &dns.Server{
			Addr: cfg.Listen, Net: network, Handler: accessHandler, UDPSize: 4096,
			ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
			IdleTimeout: func() time.Duration { return 8 * time.Second }, MaxTCPQueries: 64,
		}
	}
	udpServer := serverOptions("udp")
	tcpServer := serverOptions("tcp")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	controller := admin.NewController(cfg, *statePath, handler, store)
	mux.Handle("/metrics", admin.Protect(controller, handler.MetricsHandler()))
	mux.Handle("/dns-query", admin.DoHHandler(accessHandler))
	mux.Handle("/", admin.NewServer(controller, handler))
	httpServer := &http.Server{
		Addr: cfg.HTTPListen, Handler: admin.SecurityHeaders(limitHTTP(mux, 128)),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	var dotServer *dns.Server
	if cfg.TLS.DoTListen != "" {
		certificate, loadErr := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if loadErr != nil {
			slog.Error("TLS certificate failed", "error", loadErr)
			os.Exit(1)
		}
		dotServer = &dns.Server{
			Addr: cfg.TLS.DoTListen, Net: "tcp-tls", Handler: accessHandler,
			TLSConfig:   &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
			ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
			IdleTimeout: func() time.Duration { return 8 * time.Second }, MaxTCPQueries: 64,
		}
	}

	errors := make(chan error, 4)
	go func() { errors <- udpServer.ListenAndServe() }()
	go func() { errors <- tcpServer.ListenAndServe() }()
	if cfg.HTTPListen != "" {
		if cfg.TLS.CertFile != "" {
			go func() { errors <- httpServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile) }()
		} else {
			go func() { errors <- httpServer.ListenAndServe() }()
		}
	}
	if dotServer != nil {
		go func() { errors <- dotServer.ListenAndServe() }()
	}
	slog.Info("lightdns started", "dns", cfg.Listen, "http", cfg.HTTPListen, "blocked_domains", store.Len())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go refreshBlocklists(ctx, controller)

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-errors:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server stopped", "error", err)
		}
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = udpServer.ShutdownContext(shutdownCtx)
	_ = tcpServer.ShutdownContext(shutdownCtx)
	if dotServer != nil {
		_ = dotServer.ShutdownContext(shutdownCtx)
	}
	_ = httpServer.Shutdown(shutdownCtx)
}

func limitHTTP(next http.Handler, maximum int) http.Handler {
	active := make(chan struct{}, maximum)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
			next.ServeHTTP(w, request)
		default:
			http.Error(w, "Server is busy", http.StatusServiceUnavailable)
		}
	})
}

func refreshBlocklists(ctx context.Context, controller *admin.Controller) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	lastRefresh := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			blocklists := controller.RefreshInterval()
			if blocklists.Refresh <= 0 || time.Since(lastRefresh) < blocklists.Refresh {
				continue
			}
			err := controller.ReloadBlocklists(ctx)
			if err != nil {
				slog.Warn("blocklist refresh failed; keeping previous list", "error", err)
				continue
			}
			lastRefresh = time.Now()
			slog.Info("blocklists refreshed")
		}
	}
}
