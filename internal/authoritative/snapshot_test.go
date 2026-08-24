package authoritative

import (
	"testing"

	"github.com/miekg/dns"

	"lightdns/internal/records"
)

func TestSnapshotPositiveAndNegativeAnswers(t *testing.T) {
	snapshot, err := New([]ZoneInput{{Name: "example.test", Revision: 7, Records: []records.Record{
		{Name: "www.example.test.", Type: "A", Value: "192.0.2.1", TTL: 300},
		{Name: "host.branch.example.test.", Type: "TXT", Value: "hello", TTL: 60},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	positive := snapshot.Lookup(dns.Question{Name: "www.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if !positive.Managed || positive.Rcode != dns.RcodeSuccess || len(positive.Answer) != 1 {
		t.Fatalf("positive = %+v", positive)
	}
	nodata := snapshot.Lookup(dns.Question{Name: "www.example.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if nodata.Rcode != dns.RcodeSuccess || len(nodata.Answer) != 0 || len(nodata.Authority) != 1 {
		t.Fatalf("NODATA = %+v", nodata)
	}
	emptyNode := snapshot.Lookup(dns.Question{Name: "branch.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if emptyNode.Rcode != dns.RcodeSuccess || len(emptyNode.Authority) != 1 {
		t.Fatalf("empty non-terminal = %+v", emptyNode)
	}
	nxdomain := snapshot.Lookup(dns.Question{Name: "missing.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if nxdomain.Rcode != dns.RcodeNameError || len(nxdomain.Authority) != 1 {
		t.Fatalf("NXDOMAIN = %+v", nxdomain)
	}
	soa := snapshot.Lookup(dns.Question{Name: "example.test.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET})
	if len(soa.Answer) != 1 || soa.Answer[0].(*dns.SOA).Serial != 7 {
		t.Fatalf("SOA = %+v", soa)
	}
	if outside := snapshot.Lookup(dns.Question{Name: "outside.test.", Qtype: dns.TypeA}); outside.Managed {
		t.Fatalf("outside = %+v", outside)
	}
}

func TestSnapshotWildcardUsesClosestEncloser(t *testing.T) {
	snapshot, err := New([]ZoneInput{{Name: "example.test", Revision: 1, Records: []records.Record{
		{Name: "*.example.test.", Type: "A", Value: "192.0.2.1", TTL: 300},
		{Name: "host.branch.example.test.", Type: "TXT", Value: "hello", TTL: 60},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	matched := snapshot.Lookup(dns.Question{Name: "new.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if len(matched.Answer) != 1 || matched.Answer[0].Header().Name != "new.example.test." {
		t.Fatalf("wildcard match = %+v", matched)
	}
	blocked := snapshot.Lookup(dns.Question{Name: "new.branch.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if blocked.Rcode != dns.RcodeNameError || len(blocked.Answer) != 0 {
		t.Fatalf("closest encloser result = %+v", blocked)
	}
}

func TestSnapshotNestedZoneWins(t *testing.T) {
	snapshot, err := New([]ZoneInput{
		{Name: "example.test", Revision: 1},
		{Name: "child.example.test", Revision: 2, Records: []records.Record{{Name: "www.child.example.test.", Type: "A", Value: "192.0.2.2", TTL: 60}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := snapshot.Lookup(dns.Question{Name: "www.child.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if len(result.Answer) != 1 || result.Answer[0].String() == "" {
		t.Fatalf("nested result = %+v", result)
	}
}
