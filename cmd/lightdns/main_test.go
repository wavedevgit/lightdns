package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"lightdns/internal/database"
)

func TestInitializeRuntimeImportsOnceAndBootstrapsAdmin(t *testing.T) {
	directory := t.TempDir()
	basePath := filepath.Join(directory, "config.yaml")
	statePath := filepath.Join(directory, "state.yaml")
	passwordPath := filepath.Join(directory, "password")
	if err := os.WriteFile(basePath, []byte("listen: 127.0.0.1:5300\nhttp_listen: 127.0.0.1:8080\nadmin:\n  token: legacy-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("listen: 127.0.0.1:5353\nhttp_listen: 127.0.0.1:8080\nadmin:\n  token: state-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordPath, []byte("correct horse battery staple\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(t.Context(), filepath.Join(directory, "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg, revision, err := initializeRuntime(t.Context(), store, basePath, statePath, "admin", "admin@example.test", passwordPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:5353" || cfg.Admin.Token != "" || revision != 1 {
		t.Fatalf("imported config = %+v, revision = %d", cfg, revision)
	}
	if _, err := store.CreateAuthenticatedSession(t.Context(), "admin", "correct horse battery staple", time.Hour); err != nil {
		t.Fatalf("bootstrap login: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("listen: 127.0.0.1:9999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, revision, err = initializeRuntime(t.Context(), store, basePath, statePath, "ignored", "", "")
	if err != nil || cfg.Listen != "127.0.0.1:5353" || revision != 1 {
		t.Fatalf("reloaded config listen=%q revision=%d err=%v", cfg.Listen, revision, err)
	}
}

func TestInitializeRuntimeRequiresAdminForManagement(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte("http_listen: 127.0.0.1:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := database.Open(t.Context(), filepath.Join(directory, "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, _, err := initializeRuntime(t.Context(), store, configPath, "", "admin", "", ""); err == nil {
		t.Fatal("management initialized without an administrator")
	}
}

func TestBackupDatabaseFileDoesNotFollowLinks(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "lightdns.db")
	destination := filepath.Join(directory, "backup.db")
	if err := os.WriteFile(source, []byte("database contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := backupDatabaseFile(source, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "database contents" {
		t.Fatalf("backup data=%q err=%v", data, err)
	}

	linkedSource := filepath.Join(directory, "linked.db")
	if err := os.Symlink(source, linkedSource); err != nil {
		t.Fatal(err)
	}
	linkedDestination := filepath.Join(directory, "linked-backup.db")
	if err := backupDatabaseFile(linkedSource, linkedDestination); err == nil {
		t.Fatal("symlinked source database was backed up")
	}
	if _, err := os.Stat(linkedDestination); !os.IsNotExist(err) {
		t.Fatalf("symlink backup destination exists: %v", err)
	}
}

func TestDistributionYAMLFilesParse(t *testing.T) {
	for _, path := range []string{"../../compose.yaml", "../../config.compose.yaml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document yaml.Node
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}
}
