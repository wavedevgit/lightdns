package resolver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"lightdns/internal/authoritative"
	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/records"
)

type captureWriter struct{ message *dns.Msg }

func (w *captureWriter) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (w *captureWriter) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (w *captureWriter) WriteMsg(msg *dns.Msg) error    { w.message = msg.Copy(); return nil }
func (w *captureWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *captureWriter) Close() error                   { return nil }
func (w *captureWriter) TsigStatus() error              { return nil }
func (w *captureWriter) TsigTimersOnly(bool)            {}
func (w *captureWriter) Hijack()                        {}

func TestForwardCacheAndBlock(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var upstreamQueries atomic.Uint64
	var sawDNSSEC atomic.Bool
	upstream := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		upstreamQueries.Add(1)
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			sawDNSSEC.Store(true)
		}
		response := new(dns.Msg)
		response.SetReply(req)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10"),
		}}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })

	store := blocklist.NewStore(blocklist.New([]string{"ads.example"}, nil))
	r, err := New(Options{
		Blocklists: store,
		Cache:      cache.New(1000, time.Second, time.Hour),
		Upstreams:  []string{packetConn.LocalAddr().String()}, Timeout: time.Second,
		MaxQuestions: 1, BlockMode: "nxdomain", BlockIPv4: "0.0.0.0", BlockIPv6: "::",
		Records: []records.Record{{Name: "local.example", Type: "A", Value: "192.0.2.25", TTL: 300}},
		DNSSEC:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	for range 2 {
		writer := &captureWriter{}
		r.ServeDNS(writer, request)
		if writer.message == nil || writer.message.Rcode != dns.RcodeSuccess || len(writer.message.Answer) != 1 {
			t.Fatalf("unexpected forwarded response: %#v", writer.message)
		}
	}
	if got := upstreamQueries.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1", got)
	}
	if !sawDNSSEC.Load() {
		t.Fatal("forwarded request did not include the DNSSEC OK bit")
	}

	blocked := new(dns.Msg)
	blocked.SetQuestion("image.ads.example.", dns.TypeA)
	writer := &captureWriter{}
	r.ServeDNS(writer, blocked)
	if writer.message.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked rcode = %d, want NXDOMAIN", writer.message.Rcode)
	}
	if got := upstreamQueries.Load(); got != 1 {
		t.Fatalf("blocked request reached upstream; queries = %d", got)
	}

	local := new(dns.Msg)
	local.SetQuestion("local.example.", dns.TypeA)
	writer = &captureWriter{}
	r.ServeDNS(writer, local)
	if !writer.message.Authoritative || len(writer.message.Answer) != 1 {
		t.Fatalf("unexpected local response: %#v", writer.message)
	}
	if got := upstreamQueries.Load(); got != 1 {
		t.Fatalf("local request reached upstream; queries = %d", got)
	}
}

func TestManagedZoneOverridesLegacyRecordsAndBlocklists(t *testing.T) {
	store := blocklist.NewStore(blocklist.New([]string{"example.test"}, nil))
	r, err := New(Options{
		Blocklists: store, Cache: cache.New(100, time.Second, time.Hour), Timeout: time.Second,
		MaxQuestions: 1, BlockMode: "nxdomain", BlockIPv4: "0.0.0.0", BlockIPv6: "::",
		Records: []records.Record{{Name: "www.example.test.", Type: "A", Value: "192.0.2.1", TTL: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authoritative.New([]authoritative.ZoneInput{{
		Name: "example.test", Revision: 1,
		Records: []records.Record{{Name: "www.example.test.", Type: "A", Value: "192.0.2.2", TTL: 60}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r.ReplaceManaged(snapshot)

	request := new(dns.Msg)
	request.SetQuestion("www.example.test.", dns.TypeA)
	writer := &captureWriter{}
	r.ServeDNS(writer, request)
	if writer.message == nil || !writer.message.Authoritative || len(writer.message.Answer) != 1 || !strings.Contains(writer.message.Answer[0].String(), "192.0.2.2") {
		t.Fatalf("managed response = %#v", writer.message)
	}
	request.SetQuestion("missing.example.test.", dns.TypeA)
	writer = &captureWriter{}
	r.ServeDNS(writer, request)
	if writer.message.Rcode != dns.RcodeNameError || len(writer.message.Ns) != 1 {
		t.Fatalf("managed negative = %#v", writer.message)
	}
}

func TestLocalOnlyMode(t *testing.T) {
	r, err := New(Options{
		Blocklists: blocklist.NewStore(blocklist.New(nil, nil)),
		Cache:      cache.New(100, time.Second, time.Hour),
		Timeout:    time.Second, MaxQuestions: 1, BlockMode: "nxdomain",
		BlockIPv4: "0.0.0.0", BlockIPv6: "::",
		Records: []records.Record{{Name: "local.example", Type: "A", Value: "192.0.2.25", TTL: 300}},
	})
	if err != nil {
		t.Fatal(err)
	}

	local := new(dns.Msg)
	local.SetQuestion("local.example.", dns.TypeA)
	writer := &captureWriter{}
	r.ServeDNS(writer, local)
	if writer.message == nil || !writer.message.Authoritative || writer.message.Rcode != dns.RcodeSuccess || len(writer.message.Answer) != 1 {
		t.Fatalf("unexpected local-only record response: %#v", writer.message)
	}

	unknown := new(dns.Msg)
	unknown.SetQuestion("unknown.example.", dns.TypeA)
	writer = &captureWriter{}
	r.ServeDNS(writer, unknown)
	if writer.message == nil || !writer.message.Authoritative || writer.message.Rcode != dns.RcodeNameError || len(writer.message.Answer) != 0 {
		t.Fatalf("unexpected local-only unknown response: %#v", writer.message)
	}
}

func TestRejectsUnsupportedDNSOperationsAndNegotiatesEDNS(t *testing.T) {
	r, err := New(Options{
		Blocklists: blocklist.NewStore(blocklist.New(nil, nil)), Cache: cache.New(100, time.Second, time.Hour),
		Timeout: time.Second, MaxQuestions: 1, BlockMode: "nxdomain", BlockIPv4: "0.0.0.0", BlockIPv6: "::",
		Records: []records.Record{{Name: "local.example", Type: "A", Value: "192.0.2.25", TTL: 300}},
	})
	if err != nil {
		t.Fatal(err)
	}

	update := new(dns.Msg)
	update.SetUpdate("local.example.")
	writer := &captureWriter{}
	r.ServeDNS(writer, update)
	if writer.message == nil || writer.message.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("UPDATE response = %#v", writer.message)
	}

	transfer := new(dns.Msg)
	transfer.SetAxfr("local.example.")
	writer = &captureWriter{}
	r.ServeDNS(writer, transfer)
	if writer.message == nil || writer.message.Rcode != dns.RcodeRefused {
		t.Fatalf("AXFR response = %#v", writer.message)
	}

	query := new(dns.Msg)
	query.SetQuestion("local.example.", dns.TypeA)
	query.SetEdns0(4096, true)
	writer = &captureWriter{}
	r.ServeDNS(writer, query)
	opt := writer.message.IsEdns0()
	if opt == nil || opt.UDPSize() != 1232 || !opt.Do() {
		t.Fatalf("EDNS response = %#v", writer.message)
	}

	unsupportedEDNS := new(dns.Msg)
	unsupportedEDNS.SetQuestion("local.example.", dns.TypeA)
	unsupportedEDNS.SetEdns0(1232, false)
	unsupportedEDNS.IsEdns0().SetVersion(1)
	writer = &captureWriter{}
	r.ServeDNS(writer, unsupportedEDNS)
	if writer.message == nil || writer.message.Rcode != dns.RcodeBadVers || writer.message.IsEdns0() == nil || writer.message.IsEdns0().Version() != 0 {
		t.Fatalf("unsupported EDNS response = %#v", writer.message)
	}
}

func TestExchangeDoH(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		wire, _ := io.ReadAll(request.Body)
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		packed, _ := answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer server.Close()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	answer, err := exchangeDoH(context.Background(), server.Client(), server.URL, query)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Response || answer.Id != query.Id {
		t.Fatalf("unexpected DoH answer: %#v", answer)
	}
}

func TestValidateResponseRejectsMismatchedQuestion(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Question[0].Name = "attacker.example."
	if err := validateResponse(request, response); err == nil {
		t.Fatal("mismatched upstream question was accepted")
	}
	response.SetReply(request)
	response.Response = false
	if err := validateResponse(request, response); err == nil {
		t.Fatal("non-response upstream message was accepted")
	}
}

func TestAccessHandlerAllowsAnyClient(t *testing.T) {
	called := false
	handler := NewAccessHandler(dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { called = true }), 10, 10, 1)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	writer := &remoteCaptureWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}}
	handler.ServeDNS(writer, request)
	if !called {
		t.Fatal("remote client did not reach the resolver")
	}
}

type remoteCaptureWriter struct {
	captureWriter
	remote net.Addr
}

func (w *remoteCaptureWriter) RemoteAddr() net.Addr { return w.remote }

func BenchmarkBlockedQuery(b *testing.B) {
	r, _ := New(Options{
		Blocklists: blocklist.NewStore(blocklist.New([]string{"ads.example"}, nil)),
		Cache:      cache.New(1000, time.Second, time.Hour), Upstreams: []string{"127.0.0.1:1"},
		Timeout: time.Millisecond, MaxQuestions: 1, BlockMode: "nxdomain",
		BlockIPv4: "0.0.0.0", BlockIPv6: "::",
	})
	request := new(dns.Msg)
	request.SetQuestion("asset.ads.example.", dns.TypeA)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.ServeDNS(&captureWriter{}, request)
		}
	})
}
