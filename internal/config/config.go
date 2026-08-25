package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"lightdns/internal/records"
)

type Config struct {
	Listen       string            `yaml:"listen" json:"listen"`
	HTTPListen   string            `yaml:"http_listen" json:"http_listen"`
	Upstreams    []string          `yaml:"upstreams" json:"upstreams"`
	Timeout      time.Duration     `yaml:"-" json:"-"`
	TimeoutText  string            `yaml:"timeout" json:"timeout"`
	Cache        CacheConfig       `yaml:"cache" json:"cache"`
	Blocking     BlockingConfig    `yaml:"blocking" json:"blocking"`
	Blocklists   BlocklistConfig   `yaml:"blocklists" json:"blocklists"`
	Admin        AdminConfig       `yaml:"admin" json:"admin"`
	TLS          TLSConfig         `yaml:"tls" json:"tls"`
	DNSSEC       bool              `yaml:"dnssec" json:"dnssec"`
	Records      []records.Record  `yaml:"records" json:"records"`
	MaxQuestions int               `yaml:"max_questions" json:"max_questions"`
	Access       AccessConfig      `yaml:"access" json:"access"`
	ZoneLimits   *ZoneLimitsConfig `yaml:"zone_limits,omitempty" json:"zone_limits,omitempty"`
}

type CacheConfig struct {
	Entries int           `yaml:"entries" json:"entries"`
	MinTTL  time.Duration `yaml:"-" json:"-"`
	MaxTTL  time.Duration `yaml:"-" json:"-"`
	MinText string        `yaml:"min_ttl" json:"min_ttl"`
	MaxText string        `yaml:"max_ttl" json:"max_ttl"`
}

type BlockingConfig struct {
	Mode      string   `yaml:"mode" json:"mode"`
	IPv4      string   `yaml:"ipv4" json:"ipv4"`
	IPv6      string   `yaml:"ipv6" json:"ipv6"`
	Denylist  []string `yaml:"denylist" json:"denylist"`
	Allowlist []string `yaml:"allowlist" json:"allowlist"`
}

type BlocklistConfig struct {
	Files        []string      `yaml:"files" json:"files"`
	URLs         []string      `yaml:"urls" json:"urls"`
	Refresh      time.Duration `yaml:"-" json:"-"`
	RefreshText  string        `yaml:"refresh" json:"refresh"`
	DownloadSize int64         `yaml:"max_download_bytes" json:"max_download_bytes"`
	FileRoots    []string      `yaml:"file_roots" json:"file_roots"`
}

type AdminConfig struct {
	Token             string `yaml:"token" json:"token,omitempty"`
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http" json:"allow_insecure_http"`
}

type AccessConfig struct {
	AllowedCIDRs []string `yaml:"allowed_cidrs" json:"allowed_cidrs"`
	Rate         int      `yaml:"queries_per_second" json:"queries_per_second"`
	Burst        int      `yaml:"burst" json:"burst"`
	MaxInFlight  int      `yaml:"max_in_flight" json:"max_in_flight"`
}

type ZoneLimitsConfig struct {
	MaxTotalPerUser    int    `yaml:"max_total_per_user" json:"max_total_per_user"`
	MaxActivePerUser   int    `yaml:"max_active_per_user" json:"max_active_per_user"`
	MaxRejectedPerUser int    `yaml:"max_rejected_per_user" json:"max_rejected_per_user"`
	AppealEmail        string `yaml:"appeal_email,omitempty" json:"appeal_email,omitempty"`
}

type TLSConfig struct {
	CertFile  string `yaml:"cert_file" json:"cert_file"`
	KeyFile   string `yaml:"key_file" json:"key_file"`
	DoTListen string `yaml:"dot_listen" json:"dot_listen"`
}

func Default() Config {
	return Config{
		Listen:       "127.0.0.1:53",
		HTTPListen:   "",
		Upstreams:    []string{"https://cloudflare-dns.com/dns-query", "tcp-tls://dns.quad9.net:853"},
		TimeoutText:  "2s",
		MaxQuestions: 1,
		DNSSEC:       true,
		Cache: CacheConfig{
			Entries: 100_000,
			MinText: "5s",
			MaxText: "1h",
		},
		Blocking: BlockingConfig{Mode: "nxdomain", IPv4: "0.0.0.0", IPv6: "::"},
		Blocklists: BlocklistConfig{
			RefreshText:  "24h",
			DownloadSize: 50 << 20,
		},
		Access:     AccessConfig{Rate: 200, Burst: 400, MaxInFlight: 1024},
		ZoneLimits: &ZoneLimitsConfig{MaxTotalPerUser: 25, MaxActivePerUser: 10, MaxRejectedPerUser: 10, AppealEmail: "admin@local.invalid"},
	}
}

func (c Config) EffectiveZoneLimits() ZoneLimitsConfig {
	if c.ZoneLimits == nil {
		return ZoneLimitsConfig{MaxTotalPerUser: 25, MaxActivePerUser: 10, MaxRejectedPerUser: 10, AppealEmail: "admin@local.invalid"}
	}
	limits := *c.ZoneLimits
	if limits.AppealEmail == "" {
		limits.AppealEmail = "admin@local.invalid"
	}
	return limits
}

func Load(path string) (Config, error) {
	return load(path, true, true)
}

func LoadSettings(path string) (Config, error) {
	return load(path, false, false)
}

func load(path string, applyEnvironment, requireLegacyToken bool) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}
	if applyEnvironment {
		if value := os.Getenv("LIGHTDNS_LISTEN"); value != "" {
			cfg.Listen = value
		}
		if value := os.Getenv("LIGHTDNS_HTTP_LISTEN"); value != "" {
			cfg.HTTPListen = value
		}
		if value := os.Getenv("LIGHTDNS_ADMIN_TOKEN"); value != "" {
			cfg.Admin.Token = value
		}
		if value := os.Getenv("LIGHTDNS_ALLOW_INSECURE_HTTP"); value != "" {
			allowed, err := strconv.ParseBool(value)
			if err != nil {
				return Config{}, fmt.Errorf("LIGHTDNS_ALLOW_INSECURE_HTTP: %w", err)
			}
			cfg.Admin.AllowInsecureHTTP = allowed
		}
	}
	if !requireLegacyToken {
		cfg.Admin.Token = ""
	}
	if err := cfg.validate(requireLegacyToken); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	return c.validate(true)
}

func (c *Config) ValidateSettings() error {
	return c.validate(false)
}

func (c *Config) validate(requireLegacyToken bool) error {
	var err error
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	c.Timeout, err = parseDuration("timeout", c.TimeoutText)
	if err != nil {
		return err
	}
	c.Cache.MinTTL, err = parseDuration("cache.min_ttl", c.Cache.MinText)
	if err != nil {
		return err
	}
	c.Cache.MaxTTL, err = parseDuration("cache.max_ttl", c.Cache.MaxText)
	if err != nil {
		return err
	}
	c.Blocklists.Refresh, err = parseDuration("blocklists.refresh", c.Blocklists.RefreshText)
	if err != nil {
		return err
	}
	if c.Timeout <= 0 || c.Cache.Entries < 0 || c.Cache.MinTTL < 0 || c.Cache.MaxTTL < c.Cache.MinTTL {
		return errors.New("invalid timeout or cache limits")
	}
	if c.Blocklists.DownloadSize <= 0 {
		return errors.New("blocklists.max_download_bytes must be positive")
	}
	if c.Blocking.Mode != "nxdomain" && c.Blocking.Mode != "null" {
		return errors.New("blocking.mode must be nxdomain or null")
	}
	if c.Blocking.Mode == "null" && (net.ParseIP(c.Blocking.IPv4) == nil || net.ParseIP(c.Blocking.IPv6) == nil) {
		return errors.New("blocking.ipv4 and blocking.ipv6 must be valid IP addresses")
	}
	if c.MaxQuestions != 1 {
		return errors.New("max_questions must be 1")
	}
	if c.Access.Rate <= 0 || c.Access.Burst < c.Access.Rate || c.Access.MaxInFlight <= 0 {
		return errors.New("access limits must be positive and burst must be at least queries_per_second")
	}
	limits := c.EffectiveZoneLimits()
	if limits.MaxTotalPerUser <= 0 || limits.MaxActivePerUser <= 0 || limits.MaxRejectedPerUser <= 0 {
		return errors.New("zone limits must be positive")
	}
	if limits.MaxActivePerUser > limits.MaxTotalPerUser || limits.MaxRejectedPerUser > limits.MaxTotalPerUser {
		return errors.New("active and rejected zone limits cannot exceed the total zone limit")
	}
	address, err := mail.ParseAddress(limits.AppealEmail)
	if err != nil || address.Address != limits.AppealEmail {
		return errors.New("zone_limits.appeal_email must be a valid email address")
	}
	if c.HTTPListen != "" {
		if requireLegacyToken {
			if c.Admin.Token == "" {
				return errors.New("admin.token is required when http_listen is enabled")
			}
			if len(c.Admin.Token) < 8 {
				return errors.New("admin.token must contain at least 8 characters")
			}
		}
		if c.TLS.CertFile == "" && !loopbackListener(c.HTTPListen) && !c.Admin.AllowInsecureHTTP {
			return errors.New("plaintext http_listen must bind to a loopback address")
		}
	}
	for _, raw := range c.Blocklists.URLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("blocklist URL %q must be an HTTPS URL without credentials", raw)
		}
	}
	for _, path := range c.Blocklists.Files {
		if !withinRoots(path, c.Blocklists.FileRoots) {
			return fmt.Errorf("blocklist file %q is outside blocklists.file_roots", path)
		}
	}
	for _, value := range c.Upstreams {
		if strings.HasPrefix(value, "https://") {
			continue
		}
		address := value
		if protocol, remainder, ok := strings.Cut(value, "://"); ok {
			if protocol != "udp" && protocol != "tcp" && protocol != "tcp-tls" {
				return fmt.Errorf("unsupported upstream protocol %q", protocol)
			}
			address = remainder
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("upstream %q must include a port: %w", value, err)
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return errors.New("tls.cert_file and tls.key_file must be configured together")
	}
	if c.TLS.DoTListen != "" && c.TLS.CertFile == "" {
		return errors.New("tls.dot_listen requires a certificate and key")
	}
	if _, err := records.New(c.Records); err != nil {
		return err
	}
	return nil
}

func loopbackListener(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func withinRoots(path string, roots []string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, root := range roots {
		rootAbsolute, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(rootAbsolute, absolute)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func Save(path string, cfg Config) error {
	if path == "" {
		return errors.New("state path is empty")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".lightdns-*.yaml")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func parseDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}
