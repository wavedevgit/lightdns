package admin

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"lightdns/internal/config"
	"lightdns/internal/resolver"
)

//go:embed web/*
var webFiles embed.FS

type Server struct {
	controller *Controller
	resolver   *resolver.Resolver
	limiter    *authLimiter
	sessionsMu sync.Mutex
	sessions   map[string]time.Time
}

const (
	sessionCookie   = "lightdns_session"
	sessionLifetime = 12 * time.Hour
)

type authAttempt struct {
	count int
	reset time.Time
}

type authLimiter struct {
	mu       sync.Mutex
	attempts map[string]authAttempt
}

func NewServer(controller *Controller, dnsResolver *resolver.Resolver) http.Handler {
	server := &Server{
		controller: controller, resolver: dnsResolver,
		limiter: &authLimiter{attempts: make(map[string]authAttempt)}, sessions: make(map[string]time.Time),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", server.loginPage)
	mux.HandleFunc("POST /login", server.login)
	mux.HandleFunc("POST /logout", server.sessionOnly(server.logout))
	mux.HandleFunc("GET /api/config", server.auth(server.getConfig))
	mux.HandleFunc("PUT /api/config", server.auth(server.putConfig))
	mux.HandleFunc("GET /api/stats", server.auth(server.getStats))
	mux.HandleFunc("POST /api/blocklists/reload", server.auth(server.reloadBlocklists))
	mux.HandleFunc("GET /login.css", func(w http.ResponseWriter, request *http.Request) {
		serveWebFile(w, "login.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("GET /{$}", server.sessionOnly(server.webFile("index.html", "text/html; charset=utf-8")))
	mux.HandleFunc("GET /index.html", server.sessionOnly(server.webFile("index.html", "text/html; charset=utf-8")))
	mux.HandleFunc("GET /app.js", server.sessionOnly(server.webFile("app.js", "text/javascript; charset=utf-8")))
	mux.HandleFunc("GET /app.css", server.sessionOnly(server.webFile("app.css", "text/css; charset=utf-8")))
	mux.HandleFunc("GET /pico.min.css", server.sessionOnly(server.webFile("pico.min.css", "text/css; charset=utf-8")))
	return SecurityHeaders(mux)
}

func Protect(controller *Controller, next http.Handler) http.Handler {
	server := &Server{controller: controller, limiter: &authLimiter{attempts: make(map[string]authAttempt)}}
	return server.auth(next.ServeHTTP)
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.Snapshot())
}

func (s *Server) putConfig(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 2<<20)
	var cfg config.Config
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "Configuration is not valid JSON.")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Configuration must contain one JSON object.")
		return
	}
	rotatesToken := cfg.Admin.Token != ""
	restart, err := s.controller.Apply(request.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rotatesToken {
		s.clearSessions()
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_required": restart})
}

func (s *Server) loginPage(w http.ResponseWriter, request *http.Request) {
	if s.validSession(request) {
		http.Redirect(w, request, "/", http.StatusSeeOther)
		return
	}
	name := "login.html"
	if request.URL.Query().Has("error") {
		name = "login-error.html"
	}
	serveWebFile(w, name, "text/html; charset=utf-8")
}

func (s *Server) login(w http.ResponseWriter, request *http.Request) {
	peer := peerIP(request.RemoteAddr)
	now := time.Now()
	if retry, limited := s.limiter.limited(peer, now); limited {
		w.Header().Set("Retry-After", retry)
		http.Error(w, "Too many failed authentication attempts.", http.StatusTooManyRequests)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := request.ParseForm(); err != nil || !s.controller.Authorized(request.Form.Get("token")) {
		s.limiter.failed(peer, now)
		http.Redirect(w, request, "/login?error=1", http.StatusSeeOther)
		return
	}
	s.limiter.succeeded(peer)
	id, err := s.createSession(now)
	if err != nil {
		http.Error(w, "Could not create a session.", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", MaxAge: int(sessionLifetime.Seconds()),
		HttpOnly: true, Secure: request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, request, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, request *http.Request) {
	if request.Header.Get("X-LightDNS-Request") != "dashboard" {
		writeError(w, http.StatusForbidden, "Request confirmation is required.")
		return
	}
	if cookie, err := request.Cookie(sessionCookie); err == nil {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) webFile(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		serveWebFile(w, name, contentType)
	}
}

func serveWebFile(w http.ResponseWriter, name, contentType string) {
	data, err := webFiles.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

func (s *Server) sessionOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if !s.validSession(request) {
			http.Redirect(w, request, "/login", http.StatusSeeOther)
			return
		}
		next(w, request)
	}
}

func (s *Server) createSession(now time.Time) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(random)
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for key, expiry := range s.sessions {
		if !now.Before(expiry) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 4096 {
		for key := range s.sessions {
			delete(s.sessions, key)
			break
		}
	}
	s.sessions[id] = now.Add(sessionLifetime)
	return id, nil
}

func (s *Server) validSession(request *http.Request) bool {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	now := time.Now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	expiry, ok := s.sessions[cookie.Value]
	if !ok || !now.Before(expiry) {
		delete(s.sessions, cookie.Value)
		return false
	}
	return true
}

func (s *Server) clearSessions() {
	s.sessionsMu.Lock()
	clear(s.sessions)
	s.sessionsMu.Unlock()
}

func (s *Server) getStats(w http.ResponseWriter, _ *http.Request) {
	metrics := &s.resolver.Metrics
	queries := metrics.Queries.Load()
	hits := metrics.CacheHits.Load()
	cacheRate := float64(0)
	if queries > 0 {
		cacheRate = float64(hits) / float64(queries) * 100
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queries": queries, "blocked": metrics.Blocked.Load(), "cache_hits": hits,
		"cache_misses": metrics.CacheMisses.Load(), "cache_rate": cacheRate,
		"local_answers": metrics.LocalAnswers.Load(), "upstream_errors": metrics.UpstreamErrors.Load(),
		"servfail": metrics.Servfail.Load(), "blocked_domains": s.controller.blocks.Len(),
		"time": time.Now().UTC(),
	})
}

func (s *Server) reloadBlocklists(w http.ResponseWriter, request *http.Request) {
	if err := s.controller.ReloadBlocklists(request.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "blocked_domains": s.controller.blocks.Len()})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if s.validSession(request) {
			if request.Method != http.MethodGet && request.Header.Get("X-LightDNS-Request") != "dashboard" {
				writeError(w, http.StatusForbidden, "Request confirmation is required.")
				return
			}
			next(w, request)
			return
		}
		peer := peerIP(request.RemoteAddr)
		if retry, limited := s.limiter.limited(peer, time.Now()); limited {
			w.Header().Set("Retry-After", retry)
			writeError(w, http.StatusTooManyRequests, "Too many failed authentication attempts.")
			return
		}
		parts := strings.Fields(request.Header.Get("Authorization"))
		token := ""
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token = parts[1]
		}
		if !s.controller.Authorized(token) {
			s.limiter.failed(peer, time.Now())
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "Enter the admin token to continue.")
			return
		}
		s.limiter.succeeded(peer)
		next(w, request)
	}
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
		if request.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, request)
	})
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func (l *authLimiter) limited(peer string, now time.Time) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, ok := l.attempts[peer]
	if !ok || !now.Before(attempt.reset) || attempt.count < 5 {
		return "", false
	}
	retry := time.Until(attempt.reset).Seconds()
	if retry < 1 {
		retry = 1
	}
	return fmt.Sprintf("%.0f", retry), true
}

func (l *authLimiter) failed(peer string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.attempts) >= 4096 {
		clear(l.attempts)
	}
	attempt := l.attempts[peer]
	if !now.Before(attempt.reset) {
		attempt = authAttempt{reset: now.Add(time.Minute)}
	}
	attempt.count++
	l.attempts[peer] = attempt
}

func (l *authLimiter) succeeded(peer string) {
	l.mu.Lock()
	delete(l.attempts, peer)
	l.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
