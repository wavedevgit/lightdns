package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOpenMigratesAndPersistsSettings(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "lightdns.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	first := store
	t.Cleanup(func() { _ = first.Close() })
	if version, err := store.SchemaVersion(ctx); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, err = %v", version, err)
	}
	if err := store.SetSetting(ctx, "resolver.timeout", `"2s"`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(ctx, "resolver.timeout", `"3s"`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	value, found, err := store.Setting(ctx, "resolver.timeout")
	if err != nil || !found || value != `"3s"` {
		t.Fatalf("setting value = %q, found = %v, err = %v", value, found, err)
	}
	if _, found, err := store.Setting(ctx, "missing"); err != nil || found {
		t.Fatalf("missing setting found = %v, err = %v", found, err)
	}
}

func TestOpenConfiguresSQLite(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var foreignKeys int
	if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, err = %v", foreignKeys, err)
	}
	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil || journalMode != "wal" {
		t.Fatalf("journal_mode = %q, err = %v", journalMode, err)
	}
	var busyTimeout int
	if err := store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil || busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, err = %v", busyTimeout, err)
	}
	store.db.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("replacement connection foreign_keys = %d, err = %v", foreignKeys, err)
	}
}

func TestConcurrentStoresWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lightdns.db")
	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	second, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	const writers = 32
	errors := make(chan error, writers)
	var group sync.WaitGroup
	for index := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			target := store
			if index%2 == 0 {
				target = second
			}
			errors <- target.SetSetting(context.Background(), fmt.Sprintf("test.%d", index), fmt.Sprint(index))
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM settings WHERE key LIKE 'test.%'").Scan(&count); err != nil || count != writers {
		t.Fatalf("settings count = %d, err = %v", count, err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lightdns.db")
	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("INSERT INTO schema_migrations (version) VALUES (?)", CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path); err == nil {
		t.Fatal("newer database schema was accepted")
	}
}

func TestOpenMigratesVersionOneDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lightdns.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT (unixepoch())) STRICT`,
		`CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL CHECK (length(key) > 0), value TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT (unixepoch())) STRICT`,
		`INSERT INTO schema_migrations (version) VALUES (1)`,
		`INSERT INTO settings (key, value) VALUES ('legacy', 'preserved')`,
	} {
		if _, err := legacy.Exec(statement); err != nil {
			_ = legacy.Close()
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if version, err := store.SchemaVersion(t.Context()); err != nil || version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, err = %v", version, err)
	}
	var value string
	var revision int64
	if err := store.db.QueryRow("SELECT value, revision FROM settings WHERE key = 'legacy'").Scan(&value, &revision); err != nil || value != "preserved" || revision != 1 {
		t.Fatalf("legacy setting value = %q, revision = %d, err = %v", value, revision, err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(t.Context(), "  "); err == nil {
		t.Fatal("empty database path was accepted")
	}
}
