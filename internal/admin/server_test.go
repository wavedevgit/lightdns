package admin

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/config"
	"lightdns/internal/resolver"
)

func TestAPIAuthenticationAndSave(t *testing.T) {
	cfg := config.Default()
	cfg.Admin.Token = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	blocks := blocklist.NewStore(blocklist.New(nil, nil))
	dnsResolver, err := resolver.New(optionsFor(cfg, blocks))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "state.yaml")
	handler := NewServer(NewController(cfg, statePath, dnsResolver, blocks), dnsResolver)

	request := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("authenticated response status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEmptyAdminTokenNeverAuthorizes(t *testing.T) {
	cfg := config.Default()
	blocks := blocklist.NewStore(blocklist.New(nil, nil))
	dnsResolver, err := resolver.New(optionsFor(cfg, blocks))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(NewController(cfg, filepath.Join(t.TempDir(), "state.yaml"), dnsResolver, blocks), dnsResolver)
	request := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("empty-token status = %d, want 401", response.Code)
	}
}

func TestUnauthenticatedUsersOnlyReceiveLoginResources(t *testing.T) {
	handler := newTestAdminServer(t, "memorable")

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Sign in") {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "DNS records") || strings.Contains(response.Body.String(), "app.js") {
		t.Fatal("public login page exposes dashboard content")
	}

	for _, path := range []string{"/", "/index.html", "/app.js", "/app.css", "/pico.min.css"} {
		request = httptest.NewRequest(http.MethodGet, path, nil)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
			t.Fatalf("unauthenticated %s status=%d location=%q", path, response.Code, response.Header().Get("Location"))
		}
	}

	request = httptest.NewRequest(http.MethodGet, "/not-an-asset", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d, want 404", response.Code)
	}
}

func TestDashboardSessionLifecycle(t *testing.T) {
	handler := newTestAdminServer(t, "memorable")

	wrong := url.Values{"token": {"incorrect"}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(wrong))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 0 {
		t.Fatalf("invalid login status=%d cookies=%v", response.Code, response.Result().Cookies())
	}

	form := url.Values{"token": {"memorable"}}.Encode()
	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.TLS = &tls.ConnectionState{}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("valid login status=%d cookies=%v", response.Code, cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("session cookie flags are not secure: %#v", cookie)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "DNS records") {
		t.Fatalf("dashboard status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session API status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/blocklists/reload", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("session mutation without confirmation status=%d, want 403", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-LightDNS-Request", "dashboard")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("logged-out session status=%d, want redirect", response.Code)
	}
}

func newTestAdminServer(t *testing.T, token string) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.Admin.Token = token
	blocks := blocklist.NewStore(blocklist.New(nil, nil))
	dnsResolver, err := resolver.New(optionsFor(cfg, blocks))
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(NewController(cfg, filepath.Join(t.TempDir(), "state.yaml"), dnsResolver, blocks), dnsResolver)
}

func TestControllerAppliesRecordAndPersistsYAML(t *testing.T) {
	cfg := config.Default()
	_ = cfg.Validate()
	blocks := blocklist.NewStore(blocklist.New(nil, nil))
	dnsResolver, _ := resolver.New(resolver.Options{
		Blocklists: blocks, Cache: cache.New(100, time.Second, time.Hour),
		Upstreams: cfg.Upstreams, Timeout: cfg.Timeout, MaxQuestions: cfg.MaxQuestions,
		BlockMode: cfg.Blocking.Mode, BlockIPv4: cfg.Blocking.IPv4, BlockIPv6: cfg.Blocking.IPv6,
	})
	statePath := filepath.Join(t.TempDir(), "state.yaml")
	controller := NewController(cfg, statePath, dnsResolver, blocks)
	next := controller.Snapshot()
	next.Cache.Entries = 250
	restart, err := controller.Apply(t.Context(), next)
	if err != nil || restart {
		t.Fatalf("apply failed: restart=%v err=%v", restart, err)
	}
	loaded, err := config.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cache.Entries != 250 {
		t.Fatalf("cache entries = %d, want 250", loaded.Cache.Entries)
	}
}

func TestDoHHandler(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("local.example.", dns.TypeA)
	wire, _ := query.Pack()
	handler := DoHHandler(dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}))
	request := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/dns-message")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("DoH status=%d content-type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(response.Body.Bytes()); err != nil || !answer.Response {
		t.Fatalf("invalid DoH response: answer=%#v err=%v", answer, err)
	}
}

func TestDoHRejectsOversizedBody(t *testing.T) {
	handler := DoHHandler(dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}))
	request := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(make([]byte, 65537)))
	request.Header.Set("Content-Type", "application/dns-message")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized DoH status = %d, want 413", response.Code)
	}
}
