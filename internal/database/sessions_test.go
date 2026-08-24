package database

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionLifecycleStoresOnlyTokenHash(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_admin_session", "session-admin-2", RoleAdmin)
	userID := insertTestUser(t, store.db, "user_regular_session", "session-regular", RoleUser)

	created, err := store.createSession(t.Context(), User{ID: userID, PasswordHash: testPasswordHash, Role: RoleUser}, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawToken, err := base64.RawURLEncoding.Strict().DecodeString(created.Token)
	if err != nil || len(rawToken) != 32 {
		t.Fatalf("session token length = %d, err = %v", len(rawToken), err)
	}
	var stored []byte
	if err := store.db.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", created.Session.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, rawToken) || len(stored) != 32 {
		t.Fatalf("stored session token = %x", stored)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, stored) || bytes.Contains(encoded, []byte(testPasswordHash)) {
		t.Fatalf("session response exposed credentials: %s", encoded)
	}
	probe, err := json.Marshal(CreatedSession{
		Session: Session{TokenHash: []byte("token-hash")},
		User:    User{PasswordHash: "password-hash"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(probe, []byte("token-hash")) || bytes.Contains(probe, []byte("password-hash")) {
		t.Fatalf("JSON exposed credential fields: %s", probe)
	}

	authenticated, err := store.SessionByToken(t.Context(), created.Token)
	if err != nil || authenticated.User.ID != userID || authenticated.Session.ID != created.Session.ID {
		t.Fatalf("authenticated session = %+v, err = %v", authenticated, err)
	}
	if _, err := store.SessionByToken(t.Context(), "not-a-session-token"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("malformed token error = %v", err)
	}
	if err := store.DeleteSession(t.Context(), created.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SessionByToken(t.Context(), created.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("deleted token error = %v", err)
	}
}

func TestUserSecurityChangesRevokeRepositorySessions(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_admin_revoke1", "revoke-admin", RoleAdmin)
	userID := insertTestUser(t, store.db, "user_regular_revoke", "revoke-regular", RoleUser)
	staleUser := User{ID: userID, PasswordHash: testPasswordHash, Role: RoleUser}
	created, err := store.createSession(t.Context(), staleUser, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var publicID string
	if err := store.db.QueryRow("SELECT public_id FROM users WHERE id = ?", userID).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetUserRole(t.Context(), publicID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.createSession(t.Context(), staleUser, time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("stale role session error = %v", err)
	}
	staleUser.Role = RoleAdmin
	if _, err := store.db.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.createSession(t.Context(), staleUser, time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("stale password-change flag session error = %v", err)
	}
	staleUser.MustChangePassword = true
	if _, err := store.ResetPassword(t.Context(), publicID, "replacement secure password", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.createSession(t.Context(), staleUser, time.Hour); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("stale credential session error = %v", err)
	}
	if _, err := store.SetUserEnabled(t.Context(), publicID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SessionByToken(t.Context(), created.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("revoked token error = %v", err)
	}
	if _, err := store.createSession(t.Context(), User{ID: userID, PasswordHash: testPasswordHash, Role: RoleAdmin}, time.Hour); err == nil {
		t.Fatal("session for disabled user was created")
	}
}

func TestPurgeExpiredSessions(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_admin_expired", "expired-admin", RoleAdmin)
	user := User{ID: adminID, PasswordHash: testPasswordHash, Role: RoleAdmin}
	created, err := store.createSession(t.Context(), user, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.createSession(t.Context(), user, time.Nanosecond); err == nil {
		t.Fatal("sub-second session was created")
	}
	if _, err := store.db.Exec("UPDATE sessions SET created_at = unixepoch() - 2, expires_at = unixepoch() - 1 WHERE id = ?", created.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SessionByToken(t.Context(), created.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired token error = %v", err)
	}
	count, err := store.PurgeExpiredSessions(t.Context())
	if err != nil || count != 1 {
		t.Fatalf("purged sessions = %d, err = %v", count, err)
	}
}

func TestConcurrentSessionsHaveUniqueTokens(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_admin_parallel", "parallel-admin", RoleAdmin)
	user := User{ID: adminID, PasswordHash: testPasswordHash, Role: RoleAdmin}

	const workers = 24
	results := make(chan CreatedSession, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			created, err := store.createSession(t.Context(), user, time.Hour)
			results <- created
			errors <- err
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	tokens := make(map[string]struct{}, workers)
	for created := range results {
		tokens[created.Token] = struct{}{}
	}
	if len(tokens) != workers {
		t.Fatalf("unique session tokens = %d, want %d", len(tokens), workers)
	}
}
