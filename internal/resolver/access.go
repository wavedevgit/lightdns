package resolver

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type clientBucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

type AccessHandler struct {
	next    dns.Handler
	rate    float64
	burst   float64
	active  chan struct{}
	mu      sync.Mutex
	clients map[netip.Addr]clientBucket
}

func NewAccessHandler(next dns.Handler, rate, burst, maxInFlight int) *AccessHandler {
	return &AccessHandler{
		next: next, rate: float64(rate), burst: float64(burst),
		active: make(chan struct{}, maxInFlight), clients: make(map[netip.Addr]clientBucket),
	}
}

func (h *AccessHandler) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	address, ok := sourceAddress(w.RemoteAddr())
	if !ok {
		writeRcode(w, request, dns.RcodeRefused)
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		writeRcode(w, request, dns.RcodeServerFailure)
		return
	}
	if !h.take(address, time.Now()) {
		writeRcode(w, request, dns.RcodeRefused)
		return
	}
	h.next.ServeDNS(w, request)
}

func (h *AccessHandler) take(address netip.Addr, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= 8192 {
		for candidate, bucket := range h.clients {
			if now.Sub(bucket.seen) > 10*time.Minute {
				delete(h.clients, candidate)
			}
		}
		if len(h.clients) >= 8192 {
			clear(h.clients)
		}
	}
	bucket := h.clients[address]
	if bucket.last.IsZero() {
		bucket.tokens = h.burst
		bucket.last = now
	} else {
		bucket.tokens += now.Sub(bucket.last).Seconds() * h.rate
		if bucket.tokens > h.burst {
			bucket.tokens = h.burst
		}
		bucket.last = now
	}
	bucket.seen = now
	allowed := bucket.tokens >= 1
	if allowed {
		bucket.tokens--
	}
	h.clients[address] = bucket
	return allowed
}

func sourceAddress(address net.Addr) (netip.Addr, bool) {
	if address == nil {
		return netip.Addr{}, false
	}
	switch value := address.(type) {
	case *net.UDPAddr:
		result, ok := netip.AddrFromSlice(value.IP)
		return result.Unmap(), ok
	case *net.TCPAddr:
		result, ok := netip.AddrFromSlice(value.IP)
		return result.Unmap(), ok
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}, false
	}
	result, err := netip.ParseAddr(host)
	return result.Unmap(), err == nil
}
