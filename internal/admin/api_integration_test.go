package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"lightdns/internal/config"
	"lightdns/internal/database"
)

func TestJSONSessionAPI(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)

	request := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusForbidden)
	request = httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	request.Header.Set("Origin", "https://attacker.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusForbidden)
	request = httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":`))
	request.Header.Set("Origin", "http://example.com")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusBadRequest)
	request = httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"admin","password":"correct horse battery staple","unknown":true}`))
	request.Header.Set("Origin", "http://example.com")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusBadRequest)

	request = httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"admin","password":"wrong password"}`))
	request.Header.Set("Origin", "http://example.com")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusUnauthorized)

	cookie, loggedIn := jsonLogin(t, handler, "admin", "correct horse battery staple")
	if loggedIn.Username != "admin" || loggedIn.Role != database.RoleAdmin {
		t.Fatalf("login user = %+v", loggedIn)
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", cookie)
	requireStatus(t, response, http.StatusOK)

	response = apiRequest(t, handler, http.MethodPut, "/api/session/password", `{"current_password":"wrong password","new_password":"replacement admin password"}`, cookie)
	requireStatus(t, response, http.StatusUnauthorized)
	response = apiRequest(t, handler, http.MethodPut, "/api/session/password", `{"current_password":"correct horse battery staple","new_password":"replacement admin password"}`, cookie)
	requireStatus(t, response, http.StatusOK)
	replacementCookies := response.Result().Cookies()
	if len(replacementCookies) != 1 || replacementCookies[0].Name != sessionCookie {
		t.Fatalf("replacement cookies = %#v", replacementCookies)
	}
	replacement := replacementCookies[0]
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", cookie)
	requireStatus(t, response, http.StatusUnauthorized)
	jsonLogin(t, handler, "admin", "replacement admin password")

	response = apiRequest(t, handler, http.MethodDelete, "/api/session", "", replacement)
	requireStatus(t, response, http.StatusNoContent)
	cleared := response.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge != -1 {
		t.Fatalf("logout cookies = %#v", cleared)
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", replacement)
	requireStatus(t, response, http.StatusUnauthorized)
}

func TestUserManagementAPI(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)
	adminCookie := loginCookie(t, handler, "admin", "correct horse battery staple")

	response := apiRequest(t, handler, http.MethodPost, "/api/users", `{"username":"bob","email":"bob@example.test","password":"bob initial password","role":"user","unknown":true}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPost, "/api/users", `{"username":"bob","password":"bob initial password","role":"user"}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPost, "/api/users", `{"username":"bob","email":"bob@example.test","password":"bob initial password","role":"user"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	bob := decodeBody[userView](t, response)
	if bob.ID == "" || bob.Email != "bob@example.test" || !bob.Enabled || bob.Role != database.RoleUser {
		t.Fatalf("created user = %+v", bob)
	}
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"email":"not-an-email"}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"username":"robert","email":"robert@example.test"}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	updatedBob := decodeBody[userView](t, response)
	if updatedBob.Username != "robert" || updatedBob.Email != "robert@example.test" {
		t.Fatalf("updated user = %+v", updatedBob)
	}
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"username":"bob","email":"bob@example.test"}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	bobCookie := loginCookie(t, handler, "bob", "bob initial password")

	response = apiRequest(t, handler, http.MethodGet, "/api/users", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	users := decodeBody[struct {
		Users []userView `json:"users"`
	}](t, response)
	if len(users.Users) != 2 || strings.Contains(response.Body.String(), "password_hash") {
		t.Fatalf("listed users = %+v body=%s", users.Users, response.Body.String())
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/users", "", bobCookie)
	requireStatus(t, response, http.StatusForbidden)
	response = apiRequest(t, handler, http.MethodGet, "/api/users/"+bob.ID, "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodGet, "/api/users/missing", "", adminCookie)
	requireStatus(t, response, http.StatusNotFound)

	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"enabled":false}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	if decodeBody[userView](t, response).Enabled {
		t.Fatal("disabled user remained enabled")
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", bobCookie)
	requireStatus(t, response, http.StatusUnauthorized)
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"enabled":true}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"role":"admin"}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	bobCookie = loginCookie(t, handler, "bob", "bob initial password")
	response = apiRequest(t, handler, http.MethodGet, "/api/users", "", bobCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodPatch, "/api/users/"+bob.ID, `{"role":"user"}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", bobCookie)
	requireStatus(t, response, http.StatusUnauthorized)
	bobCookie = loginCookie(t, handler, "bob", "bob initial password")

	response = apiRequest(t, handler, http.MethodPost, "/api/users/"+bob.ID+"/password-reset", `{"password":"bob temporary password","must_change_password":true}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	if !decodeBody[userView](t, response).MustChangePassword {
		t.Fatal("password reset did not require a password change")
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", bobCookie)
	requireStatus(t, response, http.StatusUnauthorized)
	bobCookie, _ = jsonLogin(t, handler, "bob", "bob temporary password")
	response = apiRequest(t, handler, http.MethodGet, "/api/stats", "", bobCookie)
	requireStatus(t, response, http.StatusForbidden)
	if !strings.Contains(response.Body.String(), "password_change_required") {
		t.Fatalf("forced-change response = %s", response.Body.String())
	}
	response = apiRequest(t, handler, http.MethodPut, "/api/session/password", `{"current_password":"bob temporary password","new_password":"bob permanent password"}`, bobCookie)
	requireStatus(t, response, http.StatusOK)
	replacementCookies := response.Result().Cookies()
	if len(replacementCookies) != 1 {
		t.Fatalf("replacement cookies = %#v", replacementCookies)
	}
	bobCookie = replacementCookies[0]
	response = apiRequest(t, handler, http.MethodPost, "/api/users/missing/password-reset", `{"password":"unused valid password"}`, adminCookie)
	requireStatus(t, response, http.StatusNotFound)

	response = apiRequest(t, handler, http.MethodDelete, "/api/users/"+bob.ID, "", adminCookie)
	requireStatus(t, response, http.StatusNoContent)
	response = apiRequest(t, handler, http.MethodGet, "/api/users/"+bob.ID, "", adminCookie)
	requireStatus(t, response, http.StatusNotFound)
	response = apiRequest(t, handler, http.MethodGet, "/api/session", "", bobCookie)
	requireStatus(t, response, http.StatusUnauthorized)
	response = apiRequest(t, handler, http.MethodDelete, "/api/users/"+loggedInUser(t, handler, adminCookie).ID, "", adminCookie)
	requireStatus(t, response, http.StatusForbidden)
	response = apiRequest(t, handler, http.MethodPost, "/api/users", `{"username":"BOB","email":"other@example.test","password":"another valid password","role":"user"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	response = apiRequest(t, handler, http.MethodGet, "/api/audit?limit=20", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	audit := decodeBody[struct {
		Events []auditView `json:"events"`
	}](t, response)
	for _, expected := range []struct {
		action  string
		actor   string
		details map[string]any
	}{
		{action: "user.create", actor: loggedInUser(t, handler, adminCookie).ID, details: map[string]any{"role": "user"}},
		{action: "user.update", actor: loggedInUser(t, handler, adminCookie).ID, details: map[string]any{"username": nil, "email": nil, "role": nil, "enabled": false}},
		{action: "user.password_reset", actor: loggedInUser(t, handler, adminCookie).ID, details: map[string]any{"must_change_password": true}},
		{action: "user.password_change", actor: bob.ID, details: map[string]any{}},
	} {
		matched := false
		for _, event := range audit.Events {
			if event.Action == expected.action && event.ActorID == expected.actor && event.TargetType == "user" && event.TargetID != nil && *event.TargetID == bob.ID && auditDetailsMatch(event.Details, expected.details) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("missing exact %s audit event: %+v", expected.action, audit.Events)
		}
	}
}

func TestZoneAndRecordManagementAPI(t *testing.T) {
	handler, _, db, dnsResolver := newTestAdminServer(t)
	adminCookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	alice, err := db.CreateUser(t.Context(), database.CreateUserParams{Username: "alice", Password: "alice secure password", Role: database.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := db.CreateUser(t.Context(), database.CreateUserParams{Username: "zone-bob", Password: "zone bob password", Role: database.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	aliceCookie := loginCookie(t, handler, alice.Username, "alice secure password")
	bobCookie := loginCookie(t, handler, bob.Username, "zone bob password")

	response := apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"Managed.Test.","owner_id":"`+alice.PublicID+`"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	zone := decodeBody[zoneView](t, response)
	if zone.Name != "managed.test" || zone.OwnerID != alice.PublicID || zone.Revision != 1 {
		t.Fatalf("created zone = %+v", zone)
	}
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"other.test","owner_id":"`+bob.PublicID+`"}`, aliceCookie)
	requireStatus(t, response, http.StatusForbidden)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"managed.test"}`, aliceCookie)
	requireStatus(t, response, http.StatusConflict)

	response = apiRequest(t, handler, http.MethodGet, "/api/zones", "", aliceCookie)
	requireStatus(t, response, http.StatusOK)
	if len(decodeBody[struct {
		Zones []zoneView `json:"zones"`
	}](t, response).Zones) != 1 {
		t.Fatalf("owner zone list = %s", response.Body.String())
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/zones", "", bobCookie)
	requireStatus(t, response, http.StatusOK)
	if len(decodeBody[struct {
		Zones []zoneView `json:"zones"`
	}](t, response).Zones) != 0 {
		t.Fatalf("other user zone list = %s", response.Body.String())
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID, "", bobCookie)
	requireStatus(t, response, http.StatusNotFound)

	recordBody := `{"name":"www.managed.test.","type":"A","value":"192.0.2.8","ttl":300}`
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", recordBody, aliceCookie)
	requireStatus(t, response, http.StatusPreconditionRequired)
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", recordBody, aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusConflict)
	review := `{"status":"active","reason":"","revision":` + strconv.FormatInt(zone.Revision, 10) + `}`
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/review", review, adminCookie)
	requireStatus(t, response, http.StatusOK)
	zone = decodeBody[zoneView](t, response)
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", `{"name":"outside.test.","type":"A","value":"192.0.2.8","ttl":300}`, aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", recordBody, aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusCreated)
	record := decodeBody[recordView](t, response)
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", `{"name":"second.managed.test.","type":"A","value":"192.0.2.10","ttl":300}`, aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusConflict)
	response = apiRequestAtRevision(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/records", `{"name":"second.managed.test.","type":"A","value":"192.0.2.10","ttl":300}`, bobCookie, zone.Revision+1)
	requireStatus(t, response, http.StatusNotFound)

	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID+"/records", "", aliceCookie)
	requireStatus(t, response, http.StatusOK)
	records := decodeBody[struct {
		Records []recordView `json:"records"`
	}](t, response)
	if len(records.Records) != 1 || records.Records[0].ID != record.ID {
		t.Fatalf("record list = %+v", records.Records)
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID+"/records", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID+"/records", "", bobCookie)
	requireStatus(t, response, http.StatusNotFound)

	updatedBody := `{"name":"www.managed.test.","type":"A","value":"192.0.2.9","ttl":60}`
	response = apiRequest(t, handler, http.MethodPut, "/api/zones/"+zone.ID+"/records/"+record.ID, updatedBody, aliceCookie)
	requireStatus(t, response, http.StatusPreconditionRequired)
	request := httptest.NewRequest(http.MethodPut, "/api/zones/"+zone.ID+"/records/"+record.ID, strings.NewReader(updatedBody))
	request.Header.Set("X-LightDNS-Request", "dashboard")
	request.Header.Set("If-Match", "invalid")
	request.AddCookie(aliceCookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequestAtRevision(t, handler, http.MethodPut, "/api/zones/"+zone.ID+"/records/"+record.ID, updatedBody, aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusConflict)
	zone = getZoneView(t, handler, aliceCookie, zone.ID)
	response = apiRequestAtRevision(t, handler, http.MethodPut, "/api/zones/"+zone.ID+"/records/"+record.ID, updatedBody, bobCookie, zone.Revision)
	requireStatus(t, response, http.StatusNotFound)
	response = apiRequestAtRevision(t, handler, http.MethodPut, "/api/zones/"+zone.ID+"/records/"+record.ID, updatedBody, adminCookie, zone.Revision)
	requireStatus(t, response, http.StatusOK)
	if decodeBody[recordView](t, response).Value != "192.0.2.9" {
		t.Fatalf("updated record = %s", response.Body.String())
	}
	zone = getZoneView(t, handler, aliceCookie, zone.ID)
	staleReview := `{"status":"active","reason":"","revision":` + strconv.FormatInt(zone.Revision-1, 10) + `}`
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/review", staleReview, adminCookie)
	requireStatus(t, response, http.StatusConflict)
	review = `{"status":"active","reason":"","revision":` + strconv.FormatInt(zone.Revision, 10) + `}`
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+zone.ID+"/review", review, adminCookie)
	requireStatus(t, response, http.StatusOK)
	zone = decodeBody[zoneView](t, response)

	query := new(dns.Msg)
	query.SetQuestion("www.managed.test.", dns.TypeA)
	writer := &testDNSWriter{}
	dnsResolver.ServeDNS(writer, query)
	if writer.message == nil || len(writer.message.Answer) != 1 || !strings.Contains(writer.message.Answer[0].String(), "192.0.2.9") {
		t.Fatalf("updated authoritative answer = %#v", writer.message)
	}

	response = apiRequest(t, handler, http.MethodDelete, "/api/zones/"+zone.ID+"/records/"+record.ID, "", aliceCookie)
	requireStatus(t, response, http.StatusPreconditionRequired)
	response = apiRequestAtRevision(t, handler, http.MethodDelete, "/api/zones/"+zone.ID+"/records/"+record.ID, "", aliceCookie, zone.Revision-1)
	requireStatus(t, response, http.StatusConflict)
	response = apiRequestAtRevision(t, handler, http.MethodDelete, "/api/zones/"+zone.ID+"/records/"+record.ID, "", bobCookie, zone.Revision)
	requireStatus(t, response, http.StatusNotFound)
	response = apiRequestAtRevision(t, handler, http.MethodDelete, "/api/zones/"+zone.ID+"/records/"+record.ID, "", aliceCookie, zone.Revision)
	requireStatus(t, response, http.StatusNoContent)
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID+"/records", "", aliceCookie)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"records":[]`) {
		t.Fatalf("records after deletion = %s", response.Body.String())
	}

	response = apiRequest(t, handler, http.MethodDelete, "/api/zones/"+zone.ID, "", bobCookie)
	requireStatus(t, response, http.StatusNotFound)
	response = apiRequest(t, handler, http.MethodDelete, "/api/zones/"+zone.ID, "", aliceCookie)
	requireStatus(t, response, http.StatusNoContent)
	response = apiRequest(t, handler, http.MethodGet, "/api/zones/"+zone.ID, "", adminCookie)
	requireStatus(t, response, http.StatusNotFound)
	response = apiRequest(t, handler, http.MethodGet, "/api/audit?limit=100", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	audit := decodeBody[struct {
		Events []auditView `json:"events"`
	}](t, response)
	actions := make(map[string]auditView)
	for index, event := range audit.Events {
		actions[event.Action] = event
		if index > 0 && audit.Events[index-1].ID <= event.ID {
			t.Fatalf("audit events are not newest-first: %+v", audit.Events)
		}
	}
	for _, expected := range []struct {
		action     string
		actor      string
		targetType string
		targetID   string
		details    map[string]any
	}{
		{action: "zone.create", actor: loggedInUser(t, handler, adminCookie).ID, targetType: "zone", targetID: zone.ID, details: map[string]any{"name": "managed.test", "owner_id": float64(alice.ID)}},
		{action: "record.create", actor: alice.PublicID, targetType: "record", targetID: record.ID, details: map[string]any{"zone_id": zone.ID, "name": "www.managed.test.", "type": "A"}},
		{action: "record.update", actor: loggedInUser(t, handler, adminCookie).ID, targetType: "record", targetID: record.ID, details: map[string]any{"zone_id": zone.ID}},
		{action: "zone.review", actor: loggedInUser(t, handler, adminCookie).ID, targetType: "zone", targetID: zone.ID, details: map[string]any{"status": "active", "reason": ""}},
		{action: "record.delete", actor: alice.PublicID, targetType: "record", targetID: record.ID, details: map[string]any{"zone_id": zone.ID}},
		{action: "zone.delete", actor: alice.PublicID, targetType: "zone", targetID: zone.ID, details: map[string]any{}},
	} {
		event, ok := actions[expected.action]
		if !ok || event.ActorID != expected.actor || event.TargetID == nil || *event.TargetID != expected.targetID || event.TargetType != expected.targetType || !auditDetailsMatch(event.Details, expected.details) {
			t.Fatalf("incorrect %s audit event: %+v", expected.action, event)
		}
	}
	if len(audit.Events) > 1 {
		response = apiRequest(t, handler, http.MethodGet, "/api/audit?limit=100&before="+strconv.FormatInt(audit.Events[0].ID, 10), "", adminCookie)
		requireStatus(t, response, http.StatusOK)
		older := decodeBody[struct {
			Events []auditView `json:"events"`
		}](t, response)
		if len(older.Events) != len(audit.Events)-1 {
			t.Fatalf("audit before pagination returned %d events, want %d", len(older.Events), len(audit.Events)-1)
		}
		for _, event := range older.Events {
			if event.ID >= audit.Events[0].ID {
				t.Fatalf("audit before pagination returned event %d", event.ID)
			}
		}
	}
}

func TestZoneLimitsAPI(t *testing.T) {
	handler, controller, _, _ := newTestAdminServer(t)
	cfg := controller.Snapshot()
	cfg.ZoneLimits = &config.ZoneLimitsConfig{MaxTotalPerUser: 2, MaxActivePerUser: 1, MaxRejectedPerUser: 1}
	if _, err := controller.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	adminCookie := loginCookie(t, handler, "admin", "correct horse battery staple")

	response := apiRequest(t, handler, http.MethodPost, "/api/users", `{"username":"quota-user","email":"quota@example.test","password":"quota user password","role":"user"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	userCookie := loginCookie(t, handler, "quota-user", "quota user password")
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"rejected-quota.test"}`, userCookie)
	requireStatus(t, response, http.StatusCreated)
	rejected := decodeBody[zoneView](t, response)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+rejected.ID+"/review", `{"status":"rejected","reason":"quota test","revision":1}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"blocked-rejected.test"}`, userCookie)
	requireStatus(t, response, http.StatusConflict)
	if !strings.Contains(response.Body.String(), "rejected zone limit") {
		t.Fatalf("rejected limit response = %s", response.Body.String())
	}

	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"active-quota.test"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	active := decodeBody[zoneView](t, response)
	if active.AppealEmail != "admin@local.invalid" {
		t.Fatalf("zone appeal email = %q", active.AppealEmail)
	}
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+active.ID+"/review", `{"status":"suspended","reason":"","revision":1}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+active.ID+"/review", `{"status":"suspended","reason":"Policy review required","revision":1}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	suspended := decodeBody[zoneView](t, response)
	if suspended.RejectionReason == nil || *suspended.RejectionReason != "Policy review required" {
		t.Fatalf("suspended zone = %+v", suspended)
	}
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+active.ID+"/review", `{"status":"active","revision":2}`, adminCookie)
	requireStatus(t, response, http.StatusOK)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"pending-quota.test"}`, adminCookie)
	requireStatus(t, response, http.StatusCreated)
	pending := decodeBody[zoneView](t, response)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones", `{"name":"blocked-total.test"}`, adminCookie)
	requireStatus(t, response, http.StatusConflict)
	response = apiRequest(t, handler, http.MethodPost, "/api/zones/"+pending.ID+"/review", `{"status":"active","revision":1}`, adminCookie)
	requireStatus(t, response, http.StatusConflict)
	if !strings.Contains(response.Body.String(), "active managed zone limit") {
		t.Fatalf("active limit response = %s", response.Body.String())
	}
}

func TestOperationalAndConfigurationAPI(t *testing.T) {
	handler, controller, db, dnsResolver := newTestAdminServer(t)
	adminCookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	user, err := db.CreateUser(t.Context(), database.CreateUserParams{Username: "operator", Password: "operator password", Role: database.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	userCookie := loginCookie(t, handler, user.Username, "operator password")
	blocklistDirectory := t.TempDir()
	blocklistPath := filepath.Join(blocklistDirectory, "domains.txt")
	if err := os.WriteFile(blocklistPath, []byte("initial.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configured := controller.Snapshot()
	configured.Blocklists.Files = []string{blocklistPath}
	configured.Blocklists.FileRoots = []string{blocklistDirectory}
	if _, err := controller.Apply(t.Context(), configured); err != nil {
		t.Fatal(err)
	}
	if !controller.blocks.Blocked("initial.example.") {
		t.Fatal("initial blocklist was not loaded")
	}
	if err := os.WriteFile(blocklistPath, []byte("reloaded.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	response := apiRequest(t, handler, http.MethodGet, "/api/stats", "", userCookie)
	requireStatus(t, response, http.StatusOK)
	if rate := decodeBody[map[string]any](t, response)["cache_rate"]; rate != float64(0) {
		t.Fatalf("zero-query cache rate = %v", rate)
	}
	dnsResolver.Metrics.Queries.Add(4)
	dnsResolver.Metrics.CacheHits.Add(2)
	dnsResolver.Metrics.CacheMisses.Add(2)
	dnsResolver.Metrics.Blocked.Add(3)
	dnsResolver.Metrics.LocalAnswers.Add(1)
	dnsResolver.Metrics.UpstreamErrors.Add(2)
	dnsResolver.Metrics.Servfail.Add(1)

	response = apiRequest(t, handler, http.MethodGet, "/api/stats", "", userCookie)
	requireStatus(t, response, http.StatusOK)
	stats := decodeBody[map[string]any](t, response)
	for key, want := range map[string]float64{
		"queries": 4, "cache_hits": 2, "cache_misses": 2, "cache_rate": 50,
		"blocked": 3, "local_answers": 1, "upstream_errors": 2, "servfail": 1, "blocked_domains": 1,
	} {
		if stats[key] != want {
			t.Fatalf("stats[%s]=%v want=%v; stats=%#v", key, stats[key], want, stats)
		}
	}
	if stats["time"] == nil {
		t.Fatalf("stats = %#v", stats)
	}
	response = apiRequest(t, handler, http.MethodPost, "/api/blocklists/reload", "", userCookie)
	requireStatus(t, response, http.StatusForbidden)
	response = apiRequest(t, handler, http.MethodPost, "/api/blocklists/reload", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	if controller.blocks.Blocked("initial.example.") || !controller.blocks.Blocked("reloaded.example.") || !strings.Contains(response.Body.String(), `"blocked_domains":1`) {
		t.Fatalf("reloaded blocklist response=%s", response.Body.String())
	}
	if err := os.Remove(blocklistPath); err != nil {
		t.Fatal(err)
	}
	response = apiRequest(t, handler, http.MethodPost, "/api/blocklists/reload", "", adminCookie)
	requireStatus(t, response, http.StatusBadGateway)
	if !controller.blocks.Blocked("reloaded.example.") {
		t.Fatal("failed reload replaced the active blocklist")
	}
	response = apiRequest(t, handler, http.MethodGet, "/api/audit", "", userCookie)
	requireStatus(t, response, http.StatusForbidden)

	configResponse := apiRequest(t, handler, http.MethodGet, "/api/config", "", adminCookie)
	settingsResponse := apiRequest(t, handler, http.MethodGet, "/api/settings", "", adminCookie)
	requireStatus(t, configResponse, http.StatusOK)
	requireStatus(t, settingsResponse, http.StatusOK)
	if configResponse.Header().Get("ETag") != settingsResponse.Header().Get("ETag") || configResponse.Body.String() != settingsResponse.Body.String() {
		t.Fatalf("configuration aliases differ: config=%s settings=%s", configResponse.Body.String(), settingsResponse.Body.String())
	}
	var cfg config.Config
	if err := json.Unmarshal(configResponse.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Cache.Entries++
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body)))
	request.Header.Set("X-LightDNS-Request", "dashboard")
	request.Header.Set("If-Match", configResponse.Header().Get("ETag"))
	request.AddCookie(adminCookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusOK)
	request = httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body)))
	request.Header.Set("X-LightDNS-Request", "dashboard")
	request.Header.Set("If-Match", "invalid")
	request.AddCookie(adminCookie)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusBadRequest)
	response = apiRequest(t, handler, http.MethodPut, "/api/config", `{"unknown":true}`, adminCookie)
	requireStatus(t, response, http.StatusBadRequest)

	response = apiRequest(t, handler, http.MethodGet, "/api/audit?limit=1", "", adminCookie)
	requireStatus(t, response, http.StatusOK)
	events := decodeBody[struct {
		Events []auditView `json:"events"`
	}](t, response)
	if len(events.Events) != 1 || events.Events[0].Action != "settings.update" {
		t.Fatalf("limited audit events = %+v", events.Events)
	}
	for _, header := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control"} {
		if response.Header().Get(header) == "" {
			t.Fatalf("missing security header %s", header)
		}
	}
}

func TestAPIRoutesRequireAuthentication(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/session"},
		{http.MethodDelete, "/api/session"},
		{http.MethodPut, "/api/session/password"},
		{http.MethodGet, "/api/config"},
		{http.MethodPut, "/api/config"},
		{http.MethodGet, "/api/settings"},
		{http.MethodPut, "/api/settings"},
		{http.MethodGet, "/api/stats"},
		{http.MethodPost, "/api/blocklists/reload"},
		{http.MethodGet, "/api/users"},
		{http.MethodPost, "/api/users"},
		{http.MethodGet, "/api/users/missing"},
		{http.MethodPatch, "/api/users/missing"},
		{http.MethodDelete, "/api/users/missing"},
		{http.MethodPost, "/api/users/missing/password-reset"},
		{http.MethodGet, "/api/zones"},
		{http.MethodPost, "/api/zones"},
		{http.MethodGet, "/api/zones/missing"},
		{http.MethodDelete, "/api/zones/missing"},
		{http.MethodPost, "/api/zones/missing/review"},
		{http.MethodGet, "/api/zones/missing/records"},
		{http.MethodPost, "/api/zones/missing/records"},
		{http.MethodPut, "/api/zones/missing/records/missing"},
		{http.MethodDelete, "/api/zones/missing/records/missing"},
		{http.MethodGet, "/api/audit"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			response := apiRequest(t, handler, test.method, test.path, `{}`, nil)
			requireStatus(t, response, http.StatusUnauthorized)
		})
	}
}

func TestAdminAPIRoutesRejectRegularUsers(t *testing.T) {
	handler, _, db, _ := newTestAdminServer(t)
	user, err := db.CreateUser(t.Context(), database.CreateUserParams{Username: "non-admin", Password: "non admin password", Role: database.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginCookie(t, handler, user.Username, "non admin password")
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/config"},
		{http.MethodPut, "/api/config"},
		{http.MethodGet, "/api/settings"},
		{http.MethodPut, "/api/settings"},
		{http.MethodPost, "/api/blocklists/reload"},
		{http.MethodGet, "/api/users"},
		{http.MethodPost, "/api/users"},
		{http.MethodGet, "/api/users/missing"},
		{http.MethodPatch, "/api/users/missing"},
		{http.MethodDelete, "/api/users/missing"},
		{http.MethodPost, "/api/users/missing/password-reset"},
		{http.MethodPost, "/api/zones/missing/review"},
		{http.MethodGet, "/api/audit"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			response := apiRequest(t, handler, test.method, test.path, `{}`, cookie)
			requireStatus(t, response, http.StatusForbidden)
		})
	}
}

func TestAPIStrictJSONDecoding(t *testing.T) {
	handler, _, _, _ := newTestAdminServer(t)
	cookie := loginCookie(t, handler, "admin", "correct horse battery staple")
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/api/session/password"},
		{http.MethodPost, "/api/users"},
		{http.MethodPatch, "/api/users/missing"},
		{http.MethodPost, "/api/users/missing/password-reset"},
		{http.MethodPost, "/api/zones"},
		{http.MethodPost, "/api/zones/missing/review"},
		{http.MethodPost, "/api/zones/missing/records"},
		{http.MethodPut, "/api/zones/missing/records/missing"},
		{http.MethodPut, "/api/config"},
		{http.MethodPut, "/api/settings"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			response := apiRequest(t, handler, test.method, test.path, `{"unknown":true}`, cookie)
			requireStatus(t, response, http.StatusBadRequest)
			response = apiRequest(t, handler, test.method, test.path, `{`, cookie)
			requireStatus(t, response, http.StatusBadRequest)
		})
	}
}

func jsonLogin(t *testing.T, handler http.Handler, username, password string) (*http.Cookie, userView) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusCreated)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie {
		t.Fatalf("login cookies = %#v", cookies)
	}
	return cookies[0], decodeBody[userView](t, response)
}

func loggedInUser(t *testing.T, handler http.Handler, cookie *http.Cookie) userView {
	t.Helper()
	response := apiRequest(t, handler, http.MethodGet, "/api/session", "", cookie)
	requireStatus(t, response, http.StatusOK)
	return decodeBody[userView](t, response)
}

func getZoneView(t *testing.T, handler http.Handler, cookie *http.Cookie, zoneID string) zoneView {
	t.Helper()
	response := apiRequest(t, handler, http.MethodGet, "/api/zones/"+zoneID, "", cookie)
	requireStatus(t, response, http.StatusOK)
	return decodeBody[zoneView](t, response)
}

func decodeBody[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response body %q: %v", response.Body.String(), err)
	}
	return value
}

func auditDetailsMatch(raw json.RawMessage, expected map[string]any) bool {
	var details map[string]any
	if json.Unmarshal(raw, &details) != nil || details == nil {
		return false
	}
	return reflect.DeepEqual(details, expected)
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
	}
}
