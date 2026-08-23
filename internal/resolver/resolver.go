package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/records"
)

type Metrics struct {
	Queries        atomic.Uint64
	Blocked        atomic.Uint64
	CacheHits      atomic.Uint64
	CacheMisses    atomic.Uint64
	UpstreamErrors atomic.Uint64
	Servfail       atomic.Uint64
	LocalAnswers   atomic.Uint64
}

type Resolver struct {
	blocklists *blocklist.Store
	current    atomic.Pointer[runtimeConfig]
	next       atomic.Uint64
	group      singleflight.Group
	Metrics    Metrics
}

type runtimeConfig struct {
	cache        *cache.Cache
	upstreams    []upstream
	timeout      time.Duration
	maxQuestions int
	blockMode    string
	blockIPv4    net.IP
	blockIPv6    net.IP
	records      *records.Store
	dnssec       bool
}

type upstream struct {
	network string
	address string
	client  *http.Client
}

type Options struct {
	Blocklists   *blocklist.Store
	Cache        *cache.Cache
	Upstreams    []string
	Timeout      time.Duration
	MaxQuestions int
	BlockMode    string
	BlockIPv4    string
	BlockIPv6    string
	Records      []records.Record
	DNSSEC       bool
}

func New(options Options) (*Resolver, error) {
	if options.Blocklists == nil || options.Cache == nil {
		return nil, fmt.Errorf("blocklist store and cache are required")
	}
	r := &Resolver{blocklists: options.Blocklists}
	if err := r.Update(options); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Resolver) Update(options Options) error {
	if options.Cache == nil {
		return fmt.Errorf("cache is required")
	}
	localRecords, err := records.New(options.Records)
	if err != nil {
		return err
	}
	state := &runtimeConfig{
		cache: options.Cache, timeout: options.Timeout, maxQuestions: options.MaxQuestions,
		blockMode: options.BlockMode, blockIPv4: net.ParseIP(options.BlockIPv4),
		blockIPv6: net.ParseIP(options.BlockIPv6), records: localRecords, dnssec: options.DNSSEC,
	}
	for _, value := range options.Upstreams {
		if strings.HasPrefix(value, "https://") {
			transport := &http.Transport{
				MaxIdleConns: 64, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			}
			state.upstreams = append(state.upstreams, upstream{
				network: "https", address: value,
				client: &http.Client{Transport: transport, Timeout: options.Timeout},
			})
			continue
		}
		network := "udp"
		address := value
		if before, after, ok := strings.Cut(value, "://"); ok {
			network, address = before, after
		}
		if network != "udp" && network != "tcp" && network != "tcp-tls" {
			return fmt.Errorf("unsupported upstream protocol %q", network)
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("upstream %q must include a port: %w", value, err)
		}
		state.upstreams = append(state.upstreams, upstream{network: network, address: address})
	}
	r.current.Store(state)
	return nil
}

func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	r.Metrics.Queries.Add(1)
	state := r.current.Load()
	if len(req.Question) == 0 || len(req.Question) > state.maxQuestions {
		writeRcode(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	if answers, known := state.records.Lookup(q); known {
		r.Metrics.LocalAnswers.Add(1)
		response := new(dns.Msg)
		response.SetReply(req)
		response.Authoritative = true
		response.Answer = answers
		_ = w.WriteMsg(response)
		return
	}
	if r.blocklists.Blocked(q.Name) {
		r.Metrics.Blocked.Add(1)
		r.writeBlocked(w, req, state)
		return
	}
	if len(state.upstreams) == 0 {
		response := new(dns.Msg)
		response.SetReply(req)
		response.Authoritative = true
		response.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(response)
		return
	}
	if state.dnssec {
		if opt := req.IsEdns0(); opt != nil {
			opt.SetDo(true)
		} else {
			req.SetEdns0(1232, true)
		}
	}
	key := cache.Key(req)
	if response, ok := state.cache.Get(key, time.Now()); ok {
		r.Metrics.CacheHits.Add(1)
		response.Id = req.Id
		_ = w.WriteMsg(response)
		return
	}
	r.Metrics.CacheMisses.Add(1)
	value, err, _ := r.group.Do(key, func() (any, error) {
		if response, ok := state.cache.Get(key, time.Now()); ok {
			return response, nil
		}
		response, err := r.resolve(req.Copy(), state)
		if err == nil {
			state.cache.Set(key, response, time.Now())
		}
		return response, err
	})
	if err != nil {
		r.Metrics.Servfail.Add(1)
		writeRcode(w, req, dns.RcodeServerFailure)
		return
	}
	response := value.(*dns.Msg).Copy()
	response.Id = req.Id
	_ = w.WriteMsg(response)
}

func (r *Resolver) resolve(req *dns.Msg, state *runtimeConfig) (*dns.Msg, error) {
	clientID := req.Id
	req.Id = dns.Id()
	start := r.next.Add(1) - 1
	var lastErr error
	for offset := range state.upstreams {
		candidate := state.upstreams[(int(start)+offset)%len(state.upstreams)]
		ctx, cancel := context.WithTimeout(context.Background(), state.timeout)
		var response *dns.Msg
		var err error
		if candidate.network == "https" {
			response, err = exchangeDoH(ctx, candidate.client, candidate.address, req)
		} else {
			client := &dns.Client{Net: candidate.network, Timeout: state.timeout}
			response, _, err = client.ExchangeContext(ctx, req, candidate.address)
		}
		cancel()
		if err == nil && response != nil {
			if response.Truncated && candidate.network == "udp" {
				ctx, cancel = context.WithTimeout(context.Background(), state.timeout)
				response, _, err = (&dns.Client{Net: "tcp", Timeout: state.timeout}).ExchangeContext(ctx, req, candidate.address)
				cancel()
			}
			if err == nil && response != nil {
				if err = validateResponse(req, response); err != nil {
					lastErr = err
					r.Metrics.UpstreamErrors.Add(1)
					continue
				}
				response.Id = clientID
				return response, nil
			}
		}
		r.Metrics.UpstreamErrors.Add(1)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all upstreams returned an empty response")
	}
	return nil, lastErr
}

func exchangeDoH(ctx context.Context, client *http.Client, endpoint string, message *dns.Msg) (*dns.Msg, error) {
	wire, err := message.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned %s", response.Status)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/dns-message") {
		return nil, fmt.Errorf("DoH upstream returned unexpected content type %q", contentType)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(body) > 65536 {
		return nil, fmt.Errorf("DoH upstream response exceeds 65536 bytes")
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		return nil, err
	}
	return answer, nil
}

func validateResponse(request, response *dns.Msg) error {
	if !response.Response || response.Truncated || response.Id != request.Id || response.Opcode != request.Opcode {
		return fmt.Errorf("upstream returned an invalid DNS response header")
	}
	if len(response.Question) != len(request.Question) || len(request.Question) != 1 {
		return fmt.Errorf("upstream returned a mismatched DNS question count")
	}
	want, got := request.Question[0], response.Question[0]
	if !strings.EqualFold(dns.CanonicalName(want.Name), dns.CanonicalName(got.Name)) || want.Qtype != got.Qtype || want.Qclass != got.Qclass {
		return fmt.Errorf("upstream returned a mismatched DNS question")
	}
	return nil
}

func (r *Resolver) writeBlocked(w dns.ResponseWriter, req *dns.Msg, state *runtimeConfig) {
	response := new(dns.Msg)
	response.SetReply(req)
	response.Authoritative = true
	if state.blockMode == "nxdomain" {
		response.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(response)
		return
	}
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeA:
		response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: state.blockIPv4})
	case dns.TypeAAAA:
		response.Answer = append(response.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: state.blockIPv6})
	default:
		response.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(response)
}

func (r *Resolver) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "lightdns_queries_total %d\n", r.Metrics.Queries.Load())
		fmt.Fprintf(w, "lightdns_blocked_total %d\n", r.Metrics.Blocked.Load())
		fmt.Fprintf(w, "lightdns_cache_hits_total %d\n", r.Metrics.CacheHits.Load())
		fmt.Fprintf(w, "lightdns_cache_misses_total %d\n", r.Metrics.CacheMisses.Load())
		fmt.Fprintf(w, "lightdns_upstream_errors_total %d\n", r.Metrics.UpstreamErrors.Load())
		fmt.Fprintf(w, "lightdns_servfail_total %d\n", r.Metrics.Servfail.Load())
		fmt.Fprintf(w, "lightdns_local_answers_total %d\n", r.Metrics.LocalAnswers.Load())
		fmt.Fprintf(w, "lightdns_blocklist_domains %d\n", r.blocklists.Len())
	})
}

func writeRcode(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	response := new(dns.Msg)
	response.SetRcode(req, rcode)
	_ = w.WriteMsg(response)
}
