package admin

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lightdns/internal/config"
	"lightdns/internal/database"
	"lightdns/internal/resolver"
)

//go:embed web/*
var webFiles embed.FS

const (
	sessionCookie   = "lightdns_session"
	sessionLifetime = 12 * time.Hour
)

type principalKey struct{}

type Server struct {
	controller *Controller
	resolver   *resolver.Resolver
	database   *database.Store
	limiter    *authLimiter
	authSlots  chan struct{}
}

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
		controller: controller, resolver: dnsResolver, database: controller.Database(),
		limiter: &authLimiter{attempts: make(map[string]authAttempt)}, authSlots: make(chan struct{}, 4),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", server.loginPage)
	mux.HandleFunc("POST /login", server.login)
	mux.HandleFunc("POST /logout", server.authenticated(server.logout))
	mux.HandleFunc("GET /change-password", server.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		serveWebFile(w, "password.html", "text/html; charset=utf-8")
	}))
	mux.HandleFunc("POST /change-password", server.authenticated(server.changePasswordForm))
	mux.HandleFunc("POST /api/session", server.apiLogin)
	mux.HandleFunc("GET /api/session", server.authenticated(server.getSession))
	mux.HandleFunc("DELETE /api/session", server.authenticated(server.logout))
	mux.HandleFunc("PUT /api/session/password", server.authenticated(server.changePassword))
	mux.HandleFunc("GET /api/config", server.adminOnly(server.getConfig))
	mux.HandleFunc("PUT /api/config", server.adminOnly(server.putConfig))
	mux.HandleFunc("GET /api/settings", server.adminOnly(server.getConfig))
	mux.HandleFunc("PUT /api/settings", server.adminOnly(server.putConfig))
	mux.HandleFunc("GET /api/stats", server.authenticated(server.getStats))
	mux.HandleFunc("POST /api/blocklists/reload", server.adminOnly(server.reloadBlocklists))
	server.registerManagementRoutes(mux)
	mux.HandleFunc("GET /login.css", func(w http.ResponseWriter, _ *http.Request) {
		serveWebFile(w, "login.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("GET /{$}", server.authenticated(server.webFile("index.html", "text/html; charset=utf-8")))
	mux.HandleFunc("GET /index.html", server.authenticated(server.webFile("index.html", "text/html; charset=utf-8")))
	mux.HandleFunc("GET /app.js", server.authenticated(server.webFile("app.js", "text/javascript; charset=utf-8")))
	mux.HandleFunc("GET /app.css", server.authenticated(server.webFile("app.css", "text/css; charset=utf-8")))
	mux.HandleFunc("GET /pico.min.css", server.authenticated(server.webFile("pico.min.css", "text/css; charset=utf-8")))
	return SecurityHeaders(mux)
}

func Protect(controller *Controller, next http.Handler) http.Handler {
	server := &Server{controller: controller, database: controller.Database(), limiter: &authLimiter{attempts: make(map[string]authAttempt)}}
	return server.adminOnly(next.ServeHTTP)
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, revision := s.controller.SnapshotWithRevision()
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", revision))
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) putConfig(w http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(w, request.Body, 2<<20)
	var cfg config.Config
	if err := decodeJSON(request.Body, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "Configuration is not valid JSON.")
		return
	}
	cfg.Admin.Token = ""
	if err := cfg.ValidateSettings(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	expectedRevision, ok := requiredRevision(w, request)
	if !ok {
		return
	}
	restart, err := s.controller.ApplyRevisionAudited(request.Context(), cfg, expectedRevision, currentPrincipal(request).User)
	if err != nil {
		if errors.Is(err, database.ErrConfigConflict) {
			writeError(w, http.StatusConflict, "Settings changed since they were loaded.")
			return
		}
		slog.Error("settings update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "Settings could not be saved.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_required": restart})
}

func (s *Server) loginPage(w http.ResponseWriter, request *http.Request) {
	if _, err := s.session(request); err == nil {
		http.Redirect(w, request, "/", http.StatusSeeOther)
		return
	} else if !errors.Is(err, database.ErrSessionNotFound) {
		slog.Error("session lookup failed", "error", err)
		http.Error(w, "Authentication storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	name := "login.html"
	if request.URL.Query().Has("error") {
		name = "login-error.html"
	}
	serveWebFile(w, name, "text/html; charset=utf-8")
}

func (s *Server) login(w http.ResponseWriter, request *http.Request) {
	if !sameOriginLogin(request) {
		http.Error(w, "Login origin is not valid.", http.StatusForbidden)
		return
	}
	peer := peerIP(request.RemoteAddr)
	now := time.Now()
	if retry, limited := s.limiter.limited(peer, now); limited {
		w.Header().Set("Retry-After", retry)
		http.Error(w, "Too many failed authentication attempts.", http.StatusTooManyRequests)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := request.ParseForm(); err != nil {
		http.Redirect(w, request, "/login?error=1", http.StatusSeeOther)
		return
	}
	if !s.beginAuthentication() {
		http.Error(w, "Authentication is busy. Try again.", http.StatusServiceUnavailable)
		return
	}
	created, err := s.database.CreateAuthenticatedSession(request.Context(), request.Form.Get("username"), request.Form.Get("password"), sessionLifetime)
	s.endAuthentication()
	if err != nil {
		if !errors.Is(err, database.ErrInvalidCredentials) {
			slog.Error("login storage operation failed", "error", err)
			http.Error(w, "Authentication storage is unavailable.", http.StatusServiceUnavailable)
			return
		}
		s.limiter.failed(peer, now)
		http.Redirect(w, request, "/login?error=1", http.StatusSeeOther)
		return
	}
	s.limiter.succeeded(peer)
	setSessionCookie(w, request, created.Token, sessionLifetime)
	if created.User.MustChangePassword {
		http.Redirect(w, request, "/change-password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, request, "/", http.StatusSeeOther)
}

func (s *Server) apiLogin(w http.ResponseWriter, request *http.Request) {
	if !sameOriginLogin(request) {
		writeError(w, http.StatusForbidden, "Login origin is not valid.")
		return
	}
	peer := peerIP(request.RemoteAddr)
	now := time.Now()
	if retry, limited := s.limiter.limited(peer, now); limited {
		w.Header().Set("Retry-After", retry)
		writeError(w, http.StatusTooManyRequests, "Too many failed authentication attempts.")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Login request is not valid JSON.")
		return
	}
	if !s.beginAuthentication() {
		writeError(w, http.StatusServiceUnavailable, "Authentication is busy. Try again.")
		return
	}
	created, err := s.database.CreateAuthenticatedSession(request.Context(), input.Username, input.Password, sessionLifetime)
	s.endAuthentication()
	if err != nil {
		if !errors.Is(err, database.ErrInvalidCredentials) {
			slog.Error("login storage operation failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "Authentication storage is unavailable.")
			return
		}
		s.limiter.failed(peer, now)
		writeError(w, http.StatusUnauthorized, "Invalid username or password.")
		return
	}
	s.limiter.succeeded(peer)
	setSessionCookie(w, request, created.Token, sessionLifetime)
	writeJSON(w, http.StatusCreated, userResponse(created.User))
}

func (s *Server) getSession(w http.ResponseWriter, request *http.Request) {
	writeJSON(w, http.StatusOK, userResponse(currentPrincipal(request).User))
}

func (s *Server) changePassword(w http.ResponseWriter, request *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := decodeJSON(request.Body, &input); err != nil {
		writeError(w, http.StatusBadRequest, "Password request is not valid JSON.")
		return
	}
	principal := currentPrincipal(request)
	user, err := s.database.ChangePasswordAudited(request.Context(), principal.User.PublicID, input.CurrentPassword, input.NewPassword)
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	created, err := s.database.CreateAuthenticatedSession(request.Context(), user.Username, input.NewPassword, sessionLifetime)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Password changed; sign in again.")
		return
	}
	setSessionCookie(w, request, created.Token, sessionLifetime)
	writeJSON(w, http.StatusOK, userResponse(user))
}

func (s *Server) changePasswordForm(w http.ResponseWriter, request *http.Request) {
	if !sameOriginLogin(request) {
		http.Error(w, "Password-change origin is not valid.", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 4096)
	if err := request.ParseForm(); err != nil || request.Form.Get("new_password") != request.Form.Get("confirmation") {
		http.Redirect(w, request, "/change-password?error=1", http.StatusSeeOther)
		return
	}
	principal := currentPrincipal(request)
	user, err := s.database.ChangePasswordAudited(request.Context(), principal.User.PublicID, request.Form.Get("current_password"), request.Form.Get("new_password"))
	if err != nil {
		http.Redirect(w, request, "/change-password?error=1", http.StatusSeeOther)
		return
	}
	created, err := s.database.CreateAuthenticatedSession(request.Context(), user.Username, request.Form.Get("new_password"), sessionLifetime)
	if err != nil {
		http.Error(w, "Password changed; sign in again.", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, request, created.Token, sessionLifetime)
	http.Redirect(w, request, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookie); err == nil {
		if err := s.database.DeleteSession(request.Context(), cookie.Value); err != nil {
			slog.Error("session revocation failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "Session could not be revoked.")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return s.requireRole("", next)
}

func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.requireRole(database.RoleAdmin, next)
}

func (s *Server) requireRole(role database.UserRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		principal, err := s.session(request)
		if err != nil {
			if !errors.Is(err, database.ErrSessionNotFound) {
				slog.Error("session lookup failed", "error", err)
				writeError(w, http.StatusServiceUnavailable, "Authentication storage is unavailable.")
				return
			}
			if request.URL.Path == "/" || request.URL.Path == "/index.html" || request.URL.Path == "/app.js" || request.URL.Path == "/app.css" || request.URL.Path == "/pico.min.css" {
				http.Redirect(w, request, "/login", http.StatusSeeOther)
				return
			}
			writeError(w, http.StatusUnauthorized, "Sign in to continue.")
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Header.Get("X-LightDNS-Request") != "dashboard" && request.URL.Path != "/api/session" && request.URL.Path != "/change-password" {
			writeError(w, http.StatusForbidden, "Request confirmation is required.")
			return
		}
		if principal.User.MustChangePassword && request.URL.Path != "/api/session/password" && request.URL.Path != "/change-password" && request.URL.Path != "/logout" && request.URL.Path != "/api/session" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Password change is required.", "code": "password_change_required"})
			return
		}
		if role != "" && principal.User.Role != role {
			writeError(w, http.StatusForbidden, "Administrator access is required.")
			return
		}
		ctx := context.WithValue(request.Context(), principalKey{}, principal)
		next(w, request.WithContext(ctx))
	}
}

func (s *Server) session(request *http.Request) (database.AuthenticatedSession, error) {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return database.AuthenticatedSession{}, database.ErrSessionNotFound
	}
	return s.database.SessionByToken(request.Context(), cookie.Value)
}

func currentPrincipal(request *http.Request) database.AuthenticatedSession {
	return request.Context().Value(principalKey{}).(database.AuthenticatedSession)
}

func setSessionCookie(w http.ResponseWriter, request *http.Request, token string, lifetime time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(lifetime.Seconds()),
		HttpOnly: true, Secure: request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func sameOriginLogin(request *http.Request) bool {
	source := request.Header.Get("Origin")
	if source == "" {
		source = request.Header.Get("Referer")
	}
	if source == "" {
		return false
	}
	parsed, err := url.Parse(source)
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return err == nil && parsed.Host != "" && strings.EqualFold(parsed.Scheme, scheme) && strings.EqualFold(parsed.Host, request.Host)
}

func requiredRevision(w http.ResponseWriter, request *http.Request) (int64, bool) {
	value := strings.Trim(request.Header.Get("If-Match"), "\"")
	if value == "" {
		writeError(w, http.StatusPreconditionRequired, "If-Match is required.")
		return 0, false
	}
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision <= 0 {
		writeError(w, http.StatusBadRequest, "If-Match is not a valid revision.")
		return 0, false
	}
	return revision, true
}

func (s *Server) webFile(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { serveWebFile(w, name, contentType) }
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
		slog.Error("blocklist reload failed", "error", err)
		writeError(w, http.StatusBadGateway, "Blocklists could not be reloaded.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "blocked_domains": s.controller.blocks.Len()})
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

func (s *Server) beginAuthentication() bool {
	select {
	case s.authSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) endAuthentication() {
	<-s.authSlots
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
