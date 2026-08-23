package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type Matcher struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
}

func New(blocked, allowed []string) *Matcher {
	m := &Matcher{blocked: make(map[string]struct{}, len(blocked)), allowed: make(map[string]struct{}, len(allowed))}
	for _, domain := range blocked {
		if domain = normalize(domain); domain != "" {
			m.blocked[domain] = struct{}{}
		}
	}
	for _, domain := range allowed {
		if domain = normalize(domain); domain != "" {
			m.allowed[domain] = struct{}{}
		}
	}
	return m
}

func (m *Matcher) Blocked(name string) bool {
	name = normalize(name)
	if name == "" {
		return false
	}
	for candidate := name; candidate != ""; {
		if _, ok := m.allowed[candidate]; ok {
			return false
		}
		if _, ok := m.blocked[candidate]; ok {
			return true
		}
		index := strings.IndexByte(candidate, '.')
		if index < 0 {
			break
		}
		candidate = candidate[index+1:]
	}
	return false
}

func (m *Matcher) Len() int { return len(m.blocked) }

type Store struct{ current atomic.Pointer[Matcher] }

func NewStore(m *Matcher) *Store {
	s := &Store{}
	s.current.Store(m)
	return s
}

func (s *Store) Blocked(name string) bool { return s.current.Load().Blocked(name) }
func (s *Store) Len() int                 { return s.current.Load().Len() }
func (s *Store) Replace(m *Matcher)       { s.current.Store(m) }

type Loader struct {
	Files     []string
	URLs      []string
	Block     []string
	Allow     []string
	MaxBytes  int64
	FileRoots []string
	Client    *http.Client
}

func (l *Loader) Load(ctx context.Context) (*Matcher, error) {
	blocked := append(make([]string, 0, len(l.Block)+1000), l.Block...)
	allowed := append([]string(nil), l.Allow...)
	loaded := 0
	for _, path := range l.Files {
		file, err := openWithinRoots(path, l.FileRoots)
		if err != nil {
			return nil, fmt.Errorf("open blocklist %s: %w", path, err)
		}
		b, a, err := parseLimited(file, l.MaxBytes)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("parse blocklist %s: %w", path, err)
		}
		blocked, allowed = append(blocked, b...), append(allowed, a...)
		loaded++
	}
	client := l.Client
	if client == nil {
		client = secureHTTPClient()
	}
	for _, url := range l.URLs {
		if err := validateRemoteURL(url); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("download blocklist %s: %w", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("download blocklist %s: status %s", url, resp.Status)
		}
		b, a, err := parseLimited(resp.Body, l.MaxBytes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("parse blocklist %s: %w", url, err)
		}
		blocked, allowed = append(blocked, b...), append(allowed, a...)
		loaded++
	}
	if loaded == 0 {
		return New(blocked, allowed), nil
	}
	return New(blocked, allowed), nil
}

func openWithinRoots(path string, roots []string) (*os.File, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	for _, root := range roots {
		rootResolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rootResolved, err = filepath.Abs(rootResolved)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(rootResolved, resolved)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return os.Open(resolved)
		}
	}
	return nil, fmt.Errorf("blocklist file %q is outside configured roots", path)
}

func secureHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, candidate := range addresses {
				if publicIP(candidate.IP) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				}
			}
			return nil, fmt.Errorf("blocklist host %q resolved only to restricted addresses", host)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many blocklist redirects")
		}
		return validateRemoteURL(request.URL.String())
	}
	return client
}

func validateRemoteURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("blocklist URL %q must be an HTTPS URL without credentials", raw)
	}
	return nil
}

func publicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return false
	}
	for _, prefix := range restrictedRemotePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var restrictedRemotePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}

func parseLimited(r io.Reader, maxBytes int64) (blocked, allowed []string, err error) {
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	blocked, allowed, err = Parse(limited)
	if err == nil && limited.N == 0 {
		err = fmt.Errorf("blocklist exceeds %d bytes", maxBytes)
	}
	return blocked, allowed, err
}

func Parse(r io.Reader) (blocked, allowed []string, err error) {
	scanner := bufio.NewScanner(r)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.HasPrefix(line, "@@||") {
			if domain := adblockDomain(strings.TrimPrefix(line, "@@||")); domain != "" {
				allowed = append(allowed, domain)
			}
			continue
		}
		if strings.HasPrefix(line, "||") {
			if domain := adblockDomain(strings.TrimPrefix(line, "||")); domain != "" {
				blocked = append(blocked, domain)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
			for _, domain := range fields[1:] {
				if domain != "localhost" && !strings.HasPrefix(domain, "#") {
					blocked = append(blocked, domain)
				}
			}
			continue
		}
		if len(fields) == 1 && validDomain(fields[0]) {
			blocked = append(blocked, fields[0])
		}
	}
	return blocked, allowed, scanner.Err()
}

func adblockDomain(value string) string {
	if index := strings.IndexAny(value, "^/$*|"); index >= 0 {
		value = value[:index]
	}
	if validDomain(value) {
		return value
	}
	return ""
}

func normalize(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func validDomain(domain string) bool {
	domain = normalize(domain)
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " /:@") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return false
			}
		}
	}
	return true
}
