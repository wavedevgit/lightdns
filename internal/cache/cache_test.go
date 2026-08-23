package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheAgesTTLAndExpires(t *testing.T) {
	c := New(100, 0, time.Hour)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(req)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   []byte{192, 0, 2, 1},
	}}
	response.SetEdns0(1232, true)
	ednsTTL := response.IsEdns0().Hdr.Ttl
	now := time.Unix(1_000, 0)
	c.Set(Key(req), response, now)

	got, ok := c.Get(Key(req), now.Add(10*time.Second))
	if !ok {
		t.Fatal("expected cache hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 20 {
		t.Fatalf("TTL = %d, want 20", ttl)
	}
	if ttl := got.IsEdns0().Hdr.Ttl; ttl != ednsTTL {
		t.Fatalf("EDNS metadata changed from %#x to %#x during TTL aging", ednsTTL, ttl)
	}
	if _, ok := c.Get(Key(req), now.Add(31*time.Second)); ok {
		t.Fatal("expected expired entry to miss")
	}
}

func TestCacheHonorsSmallCapacity(t *testing.T) {
	c := New(1, time.Second, time.Hour)
	now := time.Now()
	for i := range 20 {
		message := new(dns.Msg)
		message.SetQuestion(fmt.Sprintf("%d.example.", i), dns.TypeA)
		message.Response = true
		message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: message.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
		c.Set(Key(message), message, now)
	}
	total := 0
	for i := range int(c.count) {
		total += len(c.shards[i].items)
	}
	if total != 1 {
		t.Fatalf("cache contains %d entries, want 1", total)
	}
}
