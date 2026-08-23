package admin

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"

	"github.com/miekg/dns"
)

func DoHHandler(dnsResolver dns.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		var wire []byte
		var err error
		switch request.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
		case http.MethodPost:
			if request.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(w, "Content-Type must be application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			wire, err = io.ReadAll(io.LimitReader(request.Body, 65537))
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(wire) > 65536 {
			http.Error(w, "DNS message is too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil || len(wire) == 0 {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
		message := new(dns.Msg)
		if err := message.Unpack(wire); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
		writer := &dohResponseWriter{remote: remoteAddress(request.RemoteAddr)}
		dnsResolver.ServeDNS(writer, message)
		if writer.message == nil {
			http.Error(w, "Resolver returned no response", http.StatusBadGateway)
			return
		}
		answer, err := writer.message.Pack()
		if err != nil {
			http.Error(w, "DNS response could not be encoded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(answer)
	}
}

type dohResponseWriter struct {
	message *dns.Msg
	remote  net.Addr
}

func (w *dohResponseWriter) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (w *dohResponseWriter) RemoteAddr() net.Addr            { return w.remote }
func (w *dohResponseWriter) WriteMsg(message *dns.Msg) error { w.message = message.Copy(); return nil }
func (w *dohResponseWriter) Write(data []byte) (int, error)  { return len(data), nil }
func (w *dohResponseWriter) Close() error                    { return nil }
func (w *dohResponseWriter) TsigStatus() error               { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)             {}
func (w *dohResponseWriter) Hijack()                         {}
func remoteAddress(address string) net.Addr {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	portNumber, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(portNumber)))
}
