package admin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"lightdns/internal/blocklist"
	"lightdns/internal/config"
	"lightdns/internal/database"
	"lightdns/internal/resolver"
)

func TestPersistentDashboardSessionLifecycle(t *testing.T) {
	handler, controller, _, _ := newTestAdminServer(t)
	request := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.Header.Set("Authorization", "Bearer legacy-token")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("legacy bearer status = %d", response.Code)
	}

	wrong := url.Values{"username": {"admin"}, "password": {"incorrect password"}}.Encode()
	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(wrong))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 0 {
		t.Fatalf("invalid login status=%d cookies=%v", response.Code, response.Result().Cookies())
	}

	form := url.Values{"username": {"admin"}, "password": {"correct horse battery staple"}}.Encode()
	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://example.com")
	request.TLS = &tls.ConnectionState{}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("valid login status=%d cookies=%v", response.Code, cookies)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags: %#v", cookie)
	}

	// Reconstructing the HTTP server proves the session is stored outside process memory.
	handler = NewServer(controller, controller.resolver)
	request = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "password_hash") || strings.Contains(response.Body.String(), "token") {
		t.Fatalf("session API status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/blocklists/reload", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mutation without confirmation status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-LightDNS-Request", "dashboard")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d", response.Code)
	}
}

func TestManagementAPIAndAuthoritativeReload(t *testing.T) {
	handler, _, _, dnsResolver := newTestAdminServer(t)
	adminCookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	userBody := `{"username":"alice","password":"alice secure password","role":"user","must_change_password":false}`
	response := apiRequest(t, handler, http.MethodPost, "/api/users", userBody, adminCookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", response.Code, response.Body.String())
	}
	var user userView
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	userCookie := loginCookie(t, handler, "alice", "alice secure password")
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"example.test"}`, userCookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("create zone status=%d body=%s", response.Code, response.Body.String())
	}
	var zone zoneView
	if err := json.Unmarshal(response.Body.Bytes(), &zone); err != nil {
		t.Fatal(err)
	}
	if zone.OwnerID != user.ID || zone.Status != database.ZonePending {
		t.Fatalf("created zone = %+v", zone)
	}
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", `{"name":"www.example.test.","type":"A","value":"192.0.2.8","ttl":300}`, userCookie, zone.Revision)
	if response.Code != http.StatusCreated {
		t.Fatalf("create record status=%d body=%s", response.Code, response.Body.String())
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID, "", userCookie)
	if err := json.Unmarshal(response.Body.Bytes(), &zone); err != nil {
		t.Fatal(err)
	}
	review := `{"status":"active","reason":"","revision":` + strconv.FormatInt(zone.Revision, 10) + `}`
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/review", review, adminCookie)
	if response.Code != http.StatusOK {
		t.Fatalf("review zone status=%d body=%s", response.Code, response.Body.String())
	}

	query := new(dns.Msg)
	query.SetQuestion("www.example.test.", dns.TypeA)
	writer := &testDNSWriter{}
	dnsResolver.ServeDNS(writer, query)
	if writer.message == nil || !writer.message.Authoritative || len(writer.message.Answer) != 1 {
		t.Fatalf("authoritative response = %#v", writer.message)
	}
	query.SetQuestion("missing.example.test.", dns.TypeA)
	writer = &testDNSWriter{}
	dnsResolver.ServeDNS(writer, query)
	if writer.message.Rcode != dns.RcodeNameError || len(writer.message.Ns) != 1 {
		t.Fatalf("authoritative negative = %#v", writer.message)
	}

	response = apiRequest(t, handler, http.MethodGet, "/api/config", "", userCookie)
	if response.Code != http.StatusForbidden {
		t.Fatalf("regular user config status=%d", response.Code)
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/audit", "", adminCookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "zone.review") {
		t.Fatalf("audit status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestControllerPersistsConfigurationInSQLite(t *testing.T) {
	_, controller, db, _ := newTestAdminServer(t)
	next := controller.Snapshot()
	next.Cache.Entries = 250
	restart, err := controller.Apply(t.Context(), next)
	if err != nil || restart {
		t.Fatalf("apply failed: restart=%v err=%v", restart, err)
	}
	loaded, _, found, err := db.LoadConfig(t.Context())
	if err != nil || !found || loaded.Cache.Entries != 250 {
		t.Fatalf("stored config found=%v entries=%d err=%v", found, loaded.Cache.Entries, err)
	}
}

func TestSettingsRequireCurrentRevision(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)
	cookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	response := apiRequest(t, handler, http.MethodGet, "/api/settings", "", cookie)
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("settings status=%d etag=%q", response.Code, response.Header().Get("ETag"))
	}
	etag := response.Header().Get("ETag")
	var cfg config.Config
	if err := json.Unmarshal(response.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Cache.Entries++
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	response = apiRequest(t, handler, http.MethodPut, "/api/settings", string(body), cookie)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing revision status=%d body=%s", response.Code, response.Body.String())
	}
	revision := responseForSettingsUpdate(t, handler, cookie, string(body), etag)
	if revision.Code != http.StatusOK {
		t.Fatalf("settings update status=%d body=%s", revision.Code, revision.Body.String())
	}
	stale := responseForSettingsUpdate(t, handler, cookie, string(body), etag)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale settings status=%d body=%s", stale.Code, stale.Body.String())
	}
	audit := apiRequest(t, handler, http.MethodGet, "/api/audit", "", cookie)
	if audit.Code != http.StatusOK || !strings.Contains(audit.Body.String(), "settings.update") {
		t.Fatalf("settings audit status=%d body=%s", audit.Code, audit.Body.String())
	}
}

func responseForSettingsUpdate(t *testing.T, handler http.Handler, cookie *http.Cookie, body, etag string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-LightDNS-Request", "dashboard")
	request.Header.Set("If-Match", etag)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestUnauthenticatedUsersOnlyReceiveLoginResources(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Username") {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/", "/index.html", "/app.js", "/app.css", "/pico.min.css"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
			t.Fatalf("unauthenticated %s status=%d", path, response.Code)
		}
	}
}

func TestAuthenticationStorageFailuresReturnServiceUnavailable(t *testing.T) {
	handler, _, db, _ := newTestAdminServer(t)
	cookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"username": {"admin"}, "password": {"correct horse battery staple"}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("login storage failure status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("session storage failure status=%d", response.Code)
	}
}

func newTestAdminServer(t *testing.T) (http.Handler, *Controller, *database.Store, *resolver.Resolver) {
	t.Helper()
	cfg := config.Default()
	blocks := blocklist.NewStore(blocklist.New(nil, nil))
	dnsResolver, err := resolver.New(optionsFor(cfg, blocks))
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	revision, err := db.SaveConfig(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(t.Context(), database.CreateUserParams{
		Username: "admin", Password: "correct horse battery staple", Role: database.RoleAdmin,
	}); err != nil {
		t.Fatal(err)
	}
	controller := NewController(cfg, revision, db, dnsResolver, blocks)
	return NewServer(controller, dnsResolver), controller, db, dnsResolver
}

func loginCookie(t *testing.T, handler http.Handler, username, password string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	return cookies[0]
}

func apiRequest(t *testing.T, handler http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		request.Header.Set("X-LightDNS-Request", "dashboard")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func apiRequestAtRevision(t *testing.T, handler http.Handler, method, path, body string, cookie *http.Cookie, revision int64) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("X-LightDNS-Request", "dashboard")
	request.Header.Set("If-Match", strconv.FormatInt(revision, 10))
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type testDNSWriter struct{ message *dns.Msg }

func (w *testDNSWriter) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (w *testDNSWriter) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (w *testDNSWriter) WriteMsg(msg *dns.Msg) error    { w.message = msg.Copy(); return nil }
func (w *testDNSWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *testDNSWriter) Close() error                   { return nil }
func (w *testDNSWriter) TsigStatus() error              { return nil }
func (w *testDNSWriter) TsigTimersOnly(bool)            {}
func (w *testDNSWriter) Hijack()                        {}

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
	if response.Code != http.StatusOK {
		t.Fatalf("DoH status=%d", response.Code)
	}
}
