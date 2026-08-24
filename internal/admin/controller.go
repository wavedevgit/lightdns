package admin

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"lightdns/internal/blocklist"
	"lightdns/internal/cache"
	"lightdns/internal/config"
	"lightdns/internal/database"
	"lightdns/internal/resolver"
)

type Controller struct {
	mu       sync.RWMutex
	zoneMu   sync.Mutex
	config   config.Config
	revision int64
	database *database.Store
	resolver *resolver.Resolver
	blocks   *blocklist.Store
}

func NewController(cfg config.Config, revision int64, db *database.Store, dnsResolver *resolver.Resolver, blocks *blocklist.Store) *Controller {
	return &Controller{config: cfg, revision: revision, database: db, resolver: dnsResolver, blocks: blocks}
}

func (c *Controller) Snapshot() config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copy := cloneConfig(c.config)
	copy.Admin.Token = ""
	return copy
}

func (c *Controller) SnapshotWithRevision() (config.Config, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copy := cloneConfig(c.config)
	copy.Admin.Token = ""
	return copy, c.revision
}

func (c *Controller) Apply(ctx context.Context, next config.Config) (bool, error) {
	return c.ApplyRevision(ctx, next, 0)
}

func (c *Controller) ApplyRevision(ctx context.Context, next config.Config, expectedRevision int64) (bool, error) {
	return c.applyRevision(ctx, next, expectedRevision, nil)
}

func (c *Controller) ApplyRevisionAudited(ctx context.Context, next config.Config, expectedRevision int64, actor database.User) (bool, error) {
	return c.applyRevision(ctx, next, expectedRevision, &actor)
}

func (c *Controller) applyRevision(ctx context.Context, next config.Config, expectedRevision int64, actor *database.User) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if expectedRevision > 0 && expectedRevision != c.revision {
		return false, database.ErrConfigConflict
	}
	next.Admin.Token = ""
	if err := next.ValidateSettings(); err != nil {
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
	prepared, err := resolver.Prepare(optionsFor(next, c.blocks))
	if err != nil {
		return false, err
	}
	var revision int64
	if actor == nil {
		revision, err = c.database.SaveConfig(ctx, next, c.revision)
	} else {
		revision, err = c.database.SaveConfigAudited(ctx, next, c.revision, *actor)
	}
	if err != nil {
		return false, fmt.Errorf("persist configuration: %w", err)
	}
	c.resolver.Publish(prepared)
	restartRequired := next.Listen != c.config.Listen || next.HTTPListen != c.config.HTTPListen || next.TLS != c.config.TLS ||
		next.Access.Rate != c.config.Access.Rate ||
		next.Access.Burst != c.config.Access.Burst || next.Access.MaxInFlight != c.config.Access.MaxInFlight
	if matcher != nil {
		c.blocks.Replace(matcher)
	}
	c.config = next
	c.revision = revision
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

func (c *Controller) RefreshInterval() config.BlocklistConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Blocklists
}

func (c *Controller) ReloadZones(_ context.Context) error {
	c.zoneMu.Lock()
	defer c.zoneMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := c.database.AuthoritativeSnapshot(ctx)
	if err != nil {
		return err
	}
	c.resolver.ReplaceManaged(snapshot)
	return nil
}

func (c *Controller) Database() *database.Store {
	return c.database
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
	_ = copy.ValidateSettings()
	return copy
}
