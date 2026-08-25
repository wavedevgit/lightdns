package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"lightdns/internal/admin"
	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/config"
	"lightdns/internal/database"
	"lightdns/internal/resolver"
)

func main() {
	configPath := flag.String("config", "", "path to YAML configuration")
	statePath := flag.String("state", "lightdns.state.yaml", "legacy dashboard YAML to import when initializing")
	databasePath := flag.String("database", "lightdns.db", "path to the SQLite database")
	bootstrapAdmin := flag.String("bootstrap-admin", "admin", "initial administrator username")
	bootstrapEmail := flag.String("bootstrap-email", "", "initial administrator email")
	bootstrapPasswordFile := flag.String("bootstrap-password-file", "", "file containing the initial administrator password")
	initOnly := flag.Bool("init-only", false, "initialize or migrate the database and exit")
	userCountOnly := flag.Bool("user-count-only", false, "print the number of users and exit")
	backupDatabase := flag.String("backup-database", "", "safely copy the locked database to a new backup file and exit")
	backupFile := flag.String("backup-file", "", "safely copy a regular file to a new backup file and exit")
	flag.Parse()

	ctx := context.Background()
	syscall.Umask(0077)
	lock, err := acquireDatabaseLock(*databasePath)
	if err != nil {
		slog.Error("database lock failed", "error", err)
		os.Exit(1)
	}
	defer lock.Close()
	if *backupDatabase != "" {
		if err := backupDatabaseFile(*databasePath, *backupDatabase); err != nil {
			slog.Error("database backup failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if *backupFile != "" {
		if *statePath == "" {
			slog.Error("file backup failed", "error", "-state must identify the source file")
			os.Exit(1)
		}
		if err := copyFileNoFollow(*statePath, *backupFile); err != nil {
			slog.Error("file backup failed", "error", err)
			os.Exit(1)
		}
		return
	}
	db, err := database.Open(ctx, *databasePath)
	if err != nil {
		slog.Error("database failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := os.Chmod(*databasePath, 0600); err != nil {
		slog.Error("database permissions failed", "error", err)
		os.Exit(1)
	}
	if *userCountOnly {
		count, err := db.UserCount(ctx)
		if err != nil {
			slog.Error("user count failed", "error", err)
			os.Exit(1)
		}
		fmt.Println(count)
		return
	}
	cfg, revision, err := initializeRuntime(ctx, db, *configPath, *statePath, *bootstrapAdmin, *bootstrapEmail, *bootstrapPasswordFile)
	if err != nil {
		slog.Error("runtime initialization failed", "error", err)
		os.Exit(1)
	}
	if *initOnly {
		slog.Info("database initialized", "database", *databasePath)
		return
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
	managed, err := db.AuthoritativeSnapshot(ctx)
	if err != nil {
		slog.Error("authoritative zones failed", "error", err)
		os.Exit(1)
	}
	handler.ReplaceManaged(managed)

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
	controller := admin.NewController(cfg, revision, db, handler, store)
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
	go refreshZones(ctx, controller)
	go purgeSessions(ctx, db)

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

func backupDatabaseFile(sourcePath, destinationPath string) (returnErr error) {
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(sourcePath + suffix); err == nil {
			return fmt.Errorf("database sidecar %s is present", sourcePath+suffix)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect database sidecar: %w", err)
		}
	}
	return copyFileNoFollow(sourcePath, destinationPath)
}

func copyFileNoFollow(sourcePath, destinationPath string) (returnErr error) {
	sourceFD, err := syscall.Open(sourcePath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open source database without following links: %w", err)
	}
	source := os.NewFile(uintptr(sourceFD), sourcePath)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect source database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("source database is not a regular file")
	}
	destinationFD, err := syscall.Open(destinationPath, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("create destination database without following links: %w", err)
	}
	destination := os.NewFile(uintptr(destinationFD), destinationPath)
	defer func() {
		if err := destination.Close(); returnErr == nil && err != nil {
			returnErr = fmt.Errorf("close destination database: %w", err)
		}
		if returnErr != nil {
			_ = os.Remove(destinationPath)
		}
	}()
	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("copy database: %w", err)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync database backup: %w", err)
	}
	return nil
}

func acquireDatabaseLock(path string) (*os.File, error) {
	lockPath := filepath.Dir(path)
	if value := os.Getenv("LIGHTDNS_DATABASE_LOCK_FD"); value != "" {
		fd, err := strconv.Atoi(value)
		if err != nil || fd < 3 {
			return nil, errors.New("invalid inherited database lock descriptor")
		}
		lock := os.NewFile(uintptr(fd), lockPath)
		if lock == nil {
			return nil, errors.New("inherited database lock descriptor is unavailable")
		}
		expected, err := os.Stat(lockPath)
		if err != nil {
			lock.Close()
			return nil, fmt.Errorf("inspect database lock directory: %w", err)
		}
		actual, err := lock.Stat()
		if err != nil || !os.SameFile(expected, actual) || !actual.IsDir() {
			lock.Close()
			return nil, errors.New("inherited database lock descriptor does not match the database directory")
		}
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return nil, errors.New("inherited database lock is not held")
		}
		return lock, nil
	}
	lock, err := os.Open(lockPath)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another LightDNS process is using this database")
	}
	return lock, nil
}

func initializeRuntime(ctx context.Context, db *database.Store, configPath, statePath, adminUsername, adminEmail, passwordFile string) (config.Config, int64, error) {
	cfg, revision, found, err := db.LoadConfig(ctx)
	if err != nil {
		return config.Config{}, 0, fmt.Errorf("load stored configuration: %w", err)
	}
	imported := !found
	if imported {
		importPath := configPath
		if statePath != "" {
			if _, statErr := os.Stat(statePath); statErr == nil {
				importPath = statePath
			} else if !os.IsNotExist(statErr) {
				return config.Config{}, 0, fmt.Errorf("inspect legacy state: %w", statErr)
			}
		}
		cfg, err = config.LoadSettings(importPath)
		if err != nil {
			return config.Config{}, 0, fmt.Errorf("import configuration: %w", err)
		}
		revision, err = db.SaveConfig(ctx, cfg, 0)
		if err != nil {
			return config.Config{}, 0, fmt.Errorf("save imported configuration: %w", err)
		}
	}
	userCount, err := db.UserCount(ctx)
	if err != nil {
		if imported {
			_ = db.DiscardConfig(ctx, revision)
		}
		return config.Config{}, 0, err
	}
	if userCount == 0 && passwordFile != "" {
		passwordBytes, err := os.ReadFile(passwordFile)
		if err != nil {
			if imported {
				_ = db.DiscardConfig(ctx, revision)
			}
			return config.Config{}, 0, fmt.Errorf("read bootstrap password: %w", err)
		}
		password := strings.TrimRight(string(passwordBytes), "\r\n")
		if _, err := db.CreateUser(ctx, database.CreateUserParams{Username: adminUsername, Email: adminEmail, Password: password, Role: database.RoleAdmin}); err != nil {
			if imported {
				_ = db.DiscardConfig(ctx, revision)
			}
			return config.Config{}, 0, fmt.Errorf("create bootstrap administrator: %w", err)
		}
		userCount = 1
	}
	if cfg.HTTPListen != "" && userCount == 0 {
		if imported {
			_ = db.DiscardConfig(ctx, revision)
		}
		return config.Config{}, 0, errors.New("management is enabled but no administrator exists; provide -bootstrap-password-file")
	}
	return cfg, revision, nil
}

func purgeSessions(ctx context.Context, db *database.Store) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := db.PurgeExpiredSessions(ctx); err != nil {
				slog.Warn("expired session cleanup failed", "error", err)
			}
		}
	}
}

func refreshZones(ctx context.Context, controller *admin.Controller) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := controller.ReloadZones(ctx); err != nil {
				slog.Warn("authoritative zone reconciliation failed", "error", err)
			}
		}
	}
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
