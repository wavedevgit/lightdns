package records

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLookupExactWildcardAndNODATA(t *testing.T) {
	store, err := New([]Record{
		{Name: "host.example", Type: "A", Value: "192.0.2.5", TTL: 300},
		{Name: "*.apps.example", Type: "CNAME", Value: "gateway.example.", TTL: 60},
		{Name: "example", Type: "MX", Value: "10 mail.example.", TTL: 300},
		{Name: "example", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
	})
	if err != nil {
		t.Fatal(err)
	}
	answers, known := store.Lookup(dns.Question{Name: "host.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if !known || len(answers) != 1 || answers[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("unexpected exact lookup: known=%v answers=%v", known, answers)
	}
	answers, known = store.Lookup(dns.Question{Name: "api.apps.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if !known || len(answers) != 1 || answers[0].Header().Name != "api.apps.example." {
		t.Fatalf("unexpected wildcard lookup: known=%v answers=%v", known, answers)
	}
	answers, known = store.Lookup(dns.Question{Name: "host.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if !known || len(answers) != 0 {
		t.Fatalf("expected authoritative NODATA, got known=%v answers=%v", known, answers)
	}
	if _, known = store.Lookup(dns.Question{Name: "external.example.", Qtype: dns.TypeA}); known {
		t.Fatal("unknown name should fall through")
	}
}

func TestRejectsCNAMEWithOtherData(t *testing.T) {
	_, err := New([]Record{
		{Name: "bad.example", Type: "CNAME", Value: "target.example.", TTL: 60},
		{Name: "bad.example", Type: "A", Value: "192.0.2.1", TTL: 60},
	})
	if err == nil {
		t.Fatal("expected CNAME conflict to fail")
	}
}
