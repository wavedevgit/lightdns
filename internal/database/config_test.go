package database

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"lightdns/internal/config"
	"lightdns/internal/records"
)

func TestConfigRoundTripWithoutAuthenticationSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lightdns.db")
	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.HTTPListen = "127.0.0.1:8080"
	cfg.Admin.Token = "not-stored-secret"
	cfg.Upstreams = nil
	cfg.Records = []records.Record{{Name: "router.example", Type: "A", Value: "192.0.2.1", TTL: 300}}
	cfg.Blocking.Denylist = []string{"ads.example"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	revision, err := store.SaveConfig(t.Context(), cfg, 0)
	if err != nil || revision != 1 {
		t.Fatalf("save revision = %d, err = %v", revision, err)
	}
	if cfg.Admin.Token != "not-stored-secret" {
		t.Fatal("saving configuration mutated the caller's authentication token")
	}
	raw, found, err := store.Setting(t.Context(), configurationKey)
	if err != nil || !found || strings.Contains(raw, "token") {
		t.Fatalf("stored config contains authentication secret or could not be read: found = %v, err = %v", found, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	loaded, loadedRevision, found, err := store.LoadConfig(t.Context())
	if err != nil || !found || loadedRevision != revision {
		t.Fatalf("load revision = %d, found = %v, err = %v", loadedRevision, found, err)
	}
	want := cfg
	want.Admin.Token = ""
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("loaded configuration differs:\n got: %#v\nwant: %#v", loaded, want)
	}
}

func TestConfigRejectsInvalidUpdate(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	revision, err := store.SaveConfig(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	invalid := cfg
	invalid.Listen = ""
	if _, err := store.SaveConfig(t.Context(), invalid, revision); err == nil {
		t.Fatal("invalid configuration was saved")
	}
	loaded, loadedRevision, found, err := store.LoadConfig(t.Context())
	if err != nil || !found || loadedRevision != revision || !reflect.DeepEqual(loaded, cfg) {
		t.Fatalf("last valid configuration was not preserved: found = %v, revision = %d, err = %v", found, loadedRevision, err)
	}
}

func TestConfigRejectsStaleUpdate(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Default()
	revision, err := store.SaveConfig(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := cfg
	first.Cache.Entries = 200
	if nextRevision, err := store.SaveConfig(t.Context(), first, revision); err != nil || nextRevision != revision+1 {
		t.Fatalf("first update revision = %d, err = %v", nextRevision, err)
	}
	second := cfg
	second.Cache.Entries = 300
	if _, err := store.SaveConfig(t.Context(), second, revision); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("stale update error = %v, want ErrConfigConflict", err)
	}
}

func TestConfigDetectsCorruptAndUnsupportedData(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := config.Default()
	if _, err := store.SaveConfig(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	valid, _, err := store.Setting(t.Context(), configurationKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{
		`{"version":`,
		`{"unknown_field":true}`,
		`{} {}`,
		`null`,
		`{"version":1,"config":null}`,
		`{"version":2,"config":{}}`,
		strings.Replace(valid, `"dnssec":true`, `"dnssec":null`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"admin":{`, `"admin":{"token":"secret",`, 1),
	} {
		if err := store.SetSetting(t.Context(), configurationKey, value); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := store.LoadConfig(t.Context()); err == nil || !found {
			t.Fatalf("invalid stored configuration %q was accepted or reported missing", value)
		}
	}
}

func TestConfigMissing(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "lightdns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, revision, found, err := store.LoadConfig(t.Context()); err != nil || found || revision != 0 {
		t.Fatalf("missing configuration found = %v, revision = %d, err = %v", found, revision, err)
	}
}
