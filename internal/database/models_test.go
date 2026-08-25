package database

import (
	"bytes"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestCoreModelMigrationCreatesTables(t *testing.T) {
	store := openTestStore(t)
	want := []string{"users", "sessions", "zones", "dns_records", "audit_events"}
	for _, name := range want {
		var found string
		if err := store.db.QueryRow("SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?", name).Scan(&found); err != nil {
			t.Fatalf("table %s was not created: %v", name, err)
		}
	}
}

func TestUserConstraintsAndLastAdminProtection(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.db.Exec(`INSERT INTO users (public_id, username, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user_regular_0001", "regular", testPasswordHash, RoleUser); err == nil {
		t.Fatal("non-admin first user was accepted")
	}
	adminID := insertTestUser(t, store.db, "user_admin_000001", "Admin", RoleAdmin)
	if _, err := store.db.Exec("UPDATE users SET enabled = 0 WHERE id = ?", adminID); err == nil {
		t.Fatal("last enabled admin was disabled")
	}
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", adminID); err == nil {
		t.Fatal("last enabled admin was deleted")
	}
	if _, err := store.db.Exec(`INSERT INTO users (public_id, username, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user_duplicate_01", "admin", testPasswordHash, RoleUser); err == nil {
		t.Fatal("case-insensitive duplicate username was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO users (public_id, username, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user_plaintext_001", "plaintext", "this is not a password hash", RoleUser); err == nil {
		t.Fatal("non-Argon2id password hash was accepted")
	}

	secondAdminID := insertTestUser(t, store.db, "user_admin_000002", "second-admin", RoleAdmin)
	if _, err := store.db.Exec("UPDATE users SET enabled = 0 WHERE id = ?", adminID); err != nil {
		t.Fatalf("disable admin with replacement: %v", err)
	}
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", secondAdminID); err == nil {
		t.Fatal("remaining enabled admin was deleted")
	}
}

func TestSessionsRequireHashedTokensAndCascade(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_admin_000004", "session-admin", RoleAdmin)
	userID := insertTestUser(t, store.db, "user_session_0001", "session-user", RoleUser)
	if _, err := store.db.Exec("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, unixepoch() + 3600)",
		userID, []byte("raw-token")); err == nil {
		t.Fatal("short session token hash was accepted")
	}
	tokenHash := bytes.Repeat([]byte{1}, 32)
	if _, err := store.db.Exec("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, unixepoch() + 3600)",
		userID, tokenHash); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if _, err := store.db.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", userID); err != nil {
		t.Fatalf("require password change: %v", err)
	}
	assertRowCount(t, store.db, "sessions", 0)
	if _, err := store.db.Exec("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, unixepoch() + 3600)",
		userID, tokenHash); err != nil {
		t.Fatalf("insert replacement session: %v", err)
	}
	disabledID := insertTestUser(t, store.db, "user_disabled_0001", "disabled-user", RoleUser)
	if _, err := store.db.Exec("UPDATE users SET enabled = 0 WHERE id = ?", disabledID); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if _, err := store.db.Exec("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, unixepoch() + 3600)",
		disabledID, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("session for disabled user was accepted")
	}
	if _, err := store.db.Exec("UPDATE sessions SET user_id = ? WHERE user_id = ?", disabledID, userID); err == nil {
		t.Fatal("session was reassigned to a disabled user")
	}
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		t.Fatalf("delete session owner: %v", err)
	}
	assertRowCount(t, store.db, "sessions", 0)
}

func TestZoneAndRecordConstraints(t *testing.T) {
	store := openTestStore(t)
	adminID := insertTestUser(t, store.db, "user_admin_000003", "zone-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_owner_000001", "zone-owner", RoleUser)
	zoneID := insertTestZone(t, store.db, ownerID, "zone_example_0001", "example.test")

	if _, err := store.db.Exec(`INSERT INTO zones (public_id, owner_id, name) VALUES (?, ?, ?)`,
		"zone_invalid_0001", ownerID, "Uppercase.test"); err == nil {
		t.Fatal("non-canonical zone name was accepted")
	}
	if _, err := store.db.Exec("UPDATE zones SET status = 'active', reviewed_by = ?, reviewed_at = unixepoch() WHERE id = ?", adminID, zoneID); err != nil {
		t.Fatalf("activate zone: %v", err)
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_example_01", zoneID, "www.example.test.", RecordA, "192.0.2.1", 300); err != nil {
		t.Fatalf("insert record: %v", err)
	}
	var revision int64
	if err := store.db.QueryRow("SELECT revision FROM zones WHERE id = ?", zoneID).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("zone revision after record insert = %d, err = %v", revision, err)
	}
	if _, err := store.db.Exec("UPDATE dns_records SET value = ? WHERE public_id = ?", "192.0.2.2", "record_example_01"); err != nil {
		t.Fatalf("update record: %v", err)
	}
	if err := store.db.QueryRow("SELECT revision FROM zones WHERE id = ?", zoneID).Scan(&revision); err != nil || revision != 3 {
		t.Fatalf("zone revision after record update = %d, err = %v", revision, err)
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_invalid_01", zoneID, "www.example.test.", "INVALID", "value", 300); err == nil {
		t.Fatal("unsupported record type was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_invalid_02", zoneID, "www.example.test.", RecordA, "192.0.2.2", 0); err == nil {
		t.Fatal("zero record TTL was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_invalid_03", zoneID, "outside.test.", RecordA, "192.0.2.2", 300); err == nil {
		t.Fatal("record outside its zone was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_invalid_05", zoneID, "www.example.test", RecordA, "192.0.2.2", 300); err == nil {
		t.Fatal("non-canonical record name was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_invalid_04", zoneID, "www.example.test.", RecordCNAME, "target.example.test.", 300); err == nil {
		t.Fatal("CNAME alongside an A record was accepted")
	}
	if _, err := store.db.Exec("DELETE FROM dns_records WHERE public_id = ?", "record_example_01"); err != nil {
		t.Fatalf("delete record: %v", err)
	}
	if err := store.db.QueryRow("SELECT revision FROM zones WHERE id = ?", zoneID).Scan(&revision); err != nil || revision != 4 {
		t.Fatalf("zone revision after record delete = %d, err = %v", revision, err)
	}
	if _, err := store.db.Exec(`INSERT INTO dns_records (public_id, zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?, ?)`,
		"record_example_02", zoneID, "example.test.", RecordTXT, "hello", 300); err != nil {
		t.Fatalf("insert record for cascade test: %v", err)
	}
	if _, err := store.db.Exec("DELETE FROM zones WHERE id = ?", zoneID); err != nil {
		t.Fatalf("delete zone: %v", err)
	}
	assertRowCount(t, store.db, "dns_records", 0)
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", ownerID); err != nil {
		t.Fatalf("delete former zone owner: %v", err)
	}
}

func TestZoneOwnershipAndReviewConstraints(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_admin_000005", "review-admin", RoleAdmin)
	ownerID := insertTestUser(t, store.db, "user_owner_000002", "review-owner", RoleUser)
	if _, err := store.db.Exec(`INSERT INTO zones (public_id, owner_id, name) VALUES (?, ?, ?)`,
		"zone_missing_0001", ownerID+100, "missing.test"); err == nil {
		t.Fatal("zone with missing owner was accepted")
	}
	zoneID := insertTestZone(t, store.db, ownerID, "zone_review_00001", "review.test")
	if _, err := store.db.Exec("UPDATE zones SET status = 'active' WHERE id = ?", zoneID); err == nil {
		t.Fatal("reviewed zone status without review timestamp was accepted")
	}
	if _, err := store.db.Exec("UPDATE zones SET status = 'active', reviewed_by = ?, reviewed_at = unixepoch() WHERE id = ?", ownerID, zoneID); err == nil {
		t.Fatal("zone review by a non-admin was accepted")
	}
	if _, err := store.db.Exec("UPDATE zones SET status = 'rejected', reviewed_by = (SELECT id FROM users WHERE role = 'admin'), reviewed_at = unixepoch() WHERE id = ?", zoneID); err == nil {
		t.Fatal("zone rejection without a reason was accepted")
	}
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", ownerID); err == nil {
		t.Fatal("zone owner was deleted while owning a zone")
	}
}

func TestAuditEventsRequireValidJSONAndRetainHistory(t *testing.T) {
	store := openTestStore(t)
	insertTestUser(t, store.db, "user_admin_000006", "audit-admin", RoleAdmin)
	userID := insertTestUser(t, store.db, "user_audit_000001", "audit-user", RoleUser)
	if _, err := store.db.Exec(`INSERT INTO audit_events (actor_user_id, action, target_type, details) VALUES (?, ?, ?, ?)`,
		userID, "zone.create", "zone", "not-json"); err == nil {
		t.Fatal("invalid audit details JSON was accepted")
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events (actor_user_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)`,
		userID, "zone.create", "zone", "zone_audit_000001", `{"name":"audit.test"}`); err != nil {
		t.Fatalf("insert audit event: %v", err)
	}
	if _, err := store.db.Exec("UPDATE audit_events SET action = 'zone.delete'"); err == nil {
		t.Fatal("audit event was modified")
	}
	if _, err := store.db.Exec("DELETE FROM audit_events"); err == nil {
		t.Fatal("audit event was deleted")
	}
	if _, err := store.db.Exec("UPDATE audit_events SET actor_user_id = NULL"); err == nil {
		t.Fatal("audit attribution was removed")
	}
	if _, err := store.db.Exec("DELETE FROM users WHERE id = ?", userID); err == nil {
		t.Fatal("audit actor was deleted")
	}
	var actor sql.NullInt64
	if err := store.db.QueryRow("SELECT actor_user_id FROM audit_events").Scan(&actor); err != nil || !actor.Valid || actor.Int64 != userID {
		t.Fatalf("retained audit actor = %+v, want %d, err = %v", actor, userID, err)
	}
}

const testPasswordHash = "$argon2id$v=19$m=65536,t=3,p=1$test$test"

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func insertTestUser(t *testing.T, db *sql.DB, publicID, username string, role UserRole) int64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO users (public_id, username, password_hash, role) VALUES (?, ?, ?, ?)`,
		publicID, username, testPasswordHash, role)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func insertTestZone(t *testing.T, db *sql.DB, ownerID int64, publicID, name string) int64 {
	t.Helper()
	result, err := db.Exec(`INSERT INTO zones (public_id, owner_id, name) VALUES (?, ?, ?)`, publicID, ownerID, name)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertRowCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count); err != nil || count != want {
		t.Fatalf("%s row count = %d, want %d, err = %v", table, count, want, err)
	}
}
