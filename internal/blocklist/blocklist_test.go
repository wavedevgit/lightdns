package blocklist

import (
	"strings"
	"testing"
)

func TestParseCommonFormats(t *testing.T) {
	input := `
# hosts format
0.0.0.0 ads.example.com tracker.example.com
127.0.0.1 localhost
||adblock.example^
@@||allowed.adblock.example^
plain.example
invalid url/path
`
	blocked, allowed, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	m := New(blocked, allowed)
	for _, domain := range []string{"ads.example.com", "sub.tracker.example.com", "adblock.example", "plain.example"} {
		if !m.Blocked(domain) {
			t.Errorf("expected %q to be blocked", domain)
		}
	}
	if m.Blocked("allowed.adblock.example") || m.Blocked("unrelated.example") {
		t.Error("allowlist or unrelated domain was blocked")
	}
}

func TestParseLimitedRejectsOversizedList(t *testing.T) {
	if _, _, err := parseLimited(strings.NewReader("first.example\nsecond.example\n"), 10); err == nil {
		t.Fatal("expected oversized list to fail")
	}
}

func TestAllowlistOverridesParentBlock(t *testing.T) {
	m := New([]string{"example.com"}, []string{"service.example.com"})
	if !m.Blocked("ads.example.com") {
		t.Fatal("parent rule did not block subdomain")
	}
	if m.Blocked("api.service.example.com") {
		t.Fatal("allowlist did not override parent rule")
	}
}

func TestRemoteURLPolicyRejectsInsecureSources(t *testing.T) {
	for _, value := range []string{"http://example.com/list", "https://user:pass@example.com/list", "file:///etc/hosts"} {
		if err := validateRemoteURL(value); err == nil {
			t.Errorf("validateRemoteURL(%q) succeeded", value)
		}
	}
	if err := validateRemoteURL("https://example.com/list"); err != nil {
		t.Fatalf("valid HTTPS URL rejected: %v", err)
	}
}
