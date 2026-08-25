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

func TestZoneLimits(t *testing.T) {
	cfg := Default()
	if limits := cfg.EffectiveZoneLimits(); limits.MaxTotalPerUser != 25 || limits.MaxActivePerUser != 10 || limits.MaxRejectedPerUser != 10 {
		t.Fatalf("default zone limits = %+v", limits)
	}
	cfg.ZoneLimits = nil
	if err := cfg.ValidateSettings(); err != nil {
		t.Fatalf("legacy configuration without zone limits was rejected: %v", err)
	}
	cfg.ZoneLimits = &ZoneLimitsConfig{MaxTotalPerUser: 5, MaxActivePerUser: 6, MaxRejectedPerUser: 2}
	if err := cfg.ValidateSettings(); err == nil {
		t.Fatal("active zone limit above total was accepted")
	}
	cfg.ZoneLimits = &ZoneLimitsConfig{MaxTotalPerUser: 5, MaxActivePerUser: 3, MaxRejectedPerUser: 0}
	if err := cfg.ValidateSettings(); err == nil {
		t.Fatal("non-positive rejected zone limit was accepted")
	}
	cfg.ZoneLimits = &ZoneLimitsConfig{MaxTotalPerUser: 5, MaxActivePerUser: 3, MaxRejectedPerUser: 2, AppealEmail: "not-an-email"}
	if err := cfg.ValidateSettings(); err == nil {
		t.Fatal("invalid appeal email was accepted")
	}
}
