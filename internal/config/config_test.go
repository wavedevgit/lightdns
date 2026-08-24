package config

import "testing"

func TestManagementRequiresToken(t *testing.T) {
	cfg := Default()
	cfg.HTTPListen = "127.0.0.1:8080"
	if err := cfg.Validate(); err == nil {
		t.Fatal("management listener accepted an empty token")
	}
	cfg.Admin.Token = "short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("management listener accepted a token shorter than 8 characters")
	}
	cfg.Admin.Token = "memorable"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback management listener rejected: %v", err)
	}
}

func TestPlaintextManagementRejectsNonLoopback(t *testing.T) {
	cfg := Default()
	cfg.HTTPListen = "0.0.0.0:8080"
	cfg.Admin.Token = "memorable"
	if err := cfg.Validate(); err == nil {
		t.Fatal("non-loopback plaintext management listener was accepted")
	}
}

func TestResolverCIDRsAreNotRequired(t *testing.T) {
	cfg := Default()
	cfg.Access.AllowedCIDRs = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("configuration without a resolver ACL was rejected: %v", err)
	}
}

func TestUpstreamsAreOptional(t *testing.T) {
	cfg := Default()
	cfg.Upstreams = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("local-only configuration was rejected: %v", err)
	}
}

func TestSettingsValidationDoesNotRequireLegacyToken(t *testing.T) {
	cfg := Default()
	cfg.HTTPListen = "127.0.0.1:8080"
	if err := cfg.ValidateSettings(); err != nil {
		t.Fatalf("settings validation required the legacy token: %v", err)
	}
	cfg.HTTPListen = "0.0.0.0:8080"
	if err := cfg.ValidateSettings(); err == nil {
		t.Fatal("settings validation accepted non-loopback plaintext HTTP")
	}
}
