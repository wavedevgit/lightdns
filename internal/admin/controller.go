package admin

import (
	"context"
	"crypto/subtle"
	"fmt"
	"slices"
	"sync"

	"gopkg.in/yaml.v3"

	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/config"
	"lightdns/internal/resolver"
)

type Controller struct {
	mu        sync.RWMutex
	config    config.Config
	statePath string
	resolver  *resolver.Resolver
	blocks    *blocklist.Store
}

func NewController(cfg config.Config, statePath string, dnsResolver *resolver.Resolver, blocks *blocklist.Store) *Controller {
	return &Controller{config: cfg, statePath: statePath, resolver: dnsResolver, blocks: blocks}
}

func (c *Controller) Snapshot() config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copy := cloneConfig(c.config)
	copy.Admin.Token = ""
	return copy
}

func (c *Controller) Apply(ctx context.Context, next config.Config) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if next.Admin.Token == "" {
		next.Admin.Token = c.config.Admin.Token
	}
	if err := next.Validate(); err != nil {
		return false, err
	}
	blocklistsChanged := !slices.Equal(next.Blocklists.Files, c.config.Blocklists.Files) ||
		!slices.Equal(next.Blocklists.URLs, c.config.Blocklists.URLs) ||
		!slices.Equal(next.Blocklists.FileRoots, c.config.Blocklists.FileRoots) ||
		!slices.Equal(next.Blocking.Denylist, c.config.Blocking.Denylist) ||
		!slices.Equal(next.Blocking.Allowlist, c.config.Blocking.Allowlist) ||
		next.Blocklists.DownloadSize != c.config.Blocklists.DownloadSize
	var matcher *blocklist.Matcher
	if blocklistsChanged {
		var err error
		matcher, err = loaderFor(next).Load(ctx)
		if err != nil {
			return false, err
		}
	}
	if err := config.Save(c.statePath, next); err != nil {
		return false, fmt.Errorf("persist configuration: %w", err)
	}
	if err := c.resolver.Update(optionsFor(next, c.blocks)); err != nil {
		return false, err
	}
	restartRequired := next.Listen != c.config.Listen || next.HTTPListen != c.config.HTTPListen || next.TLS != c.config.TLS ||
		next.Access.Rate != c.config.Access.Rate ||
		next.Access.Burst != c.config.Access.Burst || next.Access.MaxInFlight != c.config.Access.MaxInFlight
	if matcher != nil {
		c.blocks.Replace(matcher)
	}
	c.config = next
	return restartRequired, nil
}

func (c *Controller) ReloadBlocklists(ctx context.Context) error {
	c.mu.RLock()
	cfg := cloneConfig(c.config)
	c.mu.RUnlock()
	matcher, err := loaderFor(cfg).Load(ctx)
	if err != nil {
		return err
	}
	c.blocks.Replace(matcher)
	return nil
}

func (c *Controller) Authorized(token string) bool {
	c.mu.RLock()
	expected := c.config.Admin.Token
	c.mu.RUnlock()
	return expected != "" && len(token) == len(expected) && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func (c *Controller) RefreshInterval() config.BlocklistConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Blocklists
}

func loaderFor(cfg config.Config) *blocklist.Loader {
	return &blocklist.Loader{
		Files: cfg.Blocklists.Files, URLs: cfg.Blocklists.URLs,
		Block: cfg.Blocking.Denylist, Allow: cfg.Blocking.Allowlist, MaxBytes: cfg.Blocklists.DownloadSize,
		FileRoots: cfg.Blocklists.FileRoots,
	}
}

func optionsFor(cfg config.Config, blocks *blocklist.Store) resolver.Options {
	return resolver.Options{
		Blocklists: blocks,
		Cache:      cache.New(cfg.Cache.Entries, cfg.Cache.MinTTL, cfg.Cache.MaxTTL),
		Upstreams:  cfg.Upstreams, Timeout: cfg.Timeout, MaxQuestions: cfg.MaxQuestions,
		BlockMode: cfg.Blocking.Mode, BlockIPv4: cfg.Blocking.IPv4, BlockIPv6: cfg.Blocking.IPv6,
		Records: cfg.Records, DNSSEC: cfg.DNSSEC,
	}
}

func cloneConfig(cfg config.Config) config.Config {
	data, _ := yaml.Marshal(cfg)
	copy := config.Default()
	_ = yaml.Unmarshal(data, &copy)
	_ = copy.Validate()
	return copy
}
