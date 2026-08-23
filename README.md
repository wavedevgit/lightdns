# LightDNS

LightDNS is a small, production-oriented DNS blocker and local DNS manager. It serves UDP, TCP, DNS-over-HTTPS, and DNS-over-TLS; manages local records; filters common Pi-hole-style lists; caches answers; and exposes health and Prometheus metrics.

## Run it

For a packaged Linux release:

```sh
tar -xzf lightdns-linux-amd64.tar.gz
cd lightdns-linux-amd64
sudo ./install.sh
lightdns-run
```

The installer places the binary in `/usr/local/bin`, creates `/etc/lightdns/config.yaml`, stores dashboard state under `/var/lib/lightdns`, and asks for the admin token twice on first install. Re-running the installer updates only the binary when configuration already exists.

To run from source, Docker Compose downloads the configured blocklist during startup:

```sh
export LIGHTDNS_ADMIN_TOKEN="$(openssl rand -hex 24)"
docker compose up -d --build
dig @127.0.0.1 example.com
curl -H "Authorization: Bearer $LIGHTDNS_ADMIN_TOKEN" http://127.0.0.1:8080/metrics
```

Open `http://127.0.0.1:8080` and sign in with the configured admin token. Tokens must contain at least 8 characters. Use a longer passphrase when exposing the dashboard beyond loopback. Successful login creates an opaque, HttpOnly session cookie; unauthenticated users cannot download the dashboard bundle.

Or run it directly (binding port 53 may require root or `CAP_NET_BIND_SERVICE`):

```sh
export LIGHTDNS_ADMIN_TOKEN="$(openssl rand -hex 24)"
go run ./cmd/lightdns -config config.example.yaml
```

Without `-config`, LightDNS exposes DNS only on `127.0.0.1:53`; the dashboard and DoH endpoint are disabled. `LIGHTDNS_LISTEN`, `LIGHTDNS_HTTP_LISTEN`, and `LIGHTDNS_ADMIN_TOKEN` override their corresponding settings.

The dashboard persists changes as YAML. Set a writable state path explicitly in production:

```sh
lightdns -config /etc/lightdns/config.yaml -state /var/lib/lightdns/state.yaml
```

If the state file exists at startup it takes precedence over the seed configuration. Listener and TLS changes require a restart; records, filters, cache settings, DNSSEC behavior, and upstreams apply live.

## Configuration

See [`config.example.yaml`](config.example.yaml). Blocklist inputs may use:

- Pi-hole/hosts syntax: `0.0.0.0 ads.example.com`
- Adblock syntax: `||ads.example.com^` and exception rules such as `@@||safe.example.com^`
- one domain per line

Raw GitHub URLs work directly, for example `https://raw.githubusercontent.com/owner/repository/main/hosts`. Remote lists must use HTTPS, cannot redirect to plaintext, and cannot resolve or connect to loopback, private, link-local, or multicast addresses. Local files must be beneath a configured `blocklists.file_roots` directory. Pi-hole regex rules and its SQLite gravity database are intentionally not imported; export those entries as domains or hosts format.

A rule blocks the domain and all of its subdomains. Allowlist entries take precedence. Lists refresh atomically, so requests continue using the previous complete list if a refresh fails. Startup fails if a configured list cannot load rather than silently running without protection.

Local records support `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SRV`, and `CAA`. Wildcards are supported. A known local name answers authoritatively; unknown names continue through filtering and forwarding.

Upstreams accept full HTTPS DoH URLs plus `udp://`, `tcp://`, and `tcp-tls://` addresses; no prefix means UDP. Requests rotate, fail over, and retry truncated UDP responses over TCP. DoH uses pooled HTTPS connections.

DNS and DoH do not perform source-IP allowlisting. Per-client rate limits and a global in-flight cap limit abuse, but public listeners are still open recursive resolvers. Restrict port 53 and encrypted DNS listeners to networks you operate with the host and provider firewalls.

## Encrypted DNS and DNSSEC

DNSSEC authenticates DNS data; it does **not** encrypt queries. LightDNS requests DNSSEC proofs when `dnssec: true` and relies on the configured validating upstream, such as Cloudflare or Quad9, to set the authenticated-data response flag.

For confidentiality:

- Configure a DoH URL or `tcp-tls://` forwarding upstream.
- Configure `tls.cert_file` and `tls.key_file` to serve the dashboard and `/dns-query` over HTTPS. Plaintext management is rejected on non-loopback listeners unless `admin.allow_insecure_http` is explicitly enabled for a trusted local proxy/container boundary.
- Set `tls.dot_listen: ":853"` to serve inbound DNS-over-TLS.

Protect private keys with filesystem permissions and do not expose an unencrypted admin listener to an untrusted network.

## Scale and operations

- The hot path uses immutable atomic configuration and blocklists, 256 cache shards, request coalescing, pooled DoH connections, and lock-free counters.
- Run multiple identical replicas behind a UDP/TCP-aware load balancer for horizontal scale. There is no shared state to coordinate.
- Give each replica enough memory for its cache and blocklists. A 100,000-entry cache is a practical starting point; tune `cache.entries` per replica.
- Probe `GET /healthz` for liveness and `GET /readyz` for readiness. Scrape `GET /metrics` with the admin bearer token.
- Health endpoints disclose no body. Metrics and management APIs require authentication, and the shared HTTP listener is loopback-only unless TLS or an explicit insecure-local override is configured.

Graceful `SIGTERM` shutdown drains UDP, TCP, DoT, and HTTP servers. The cache and active blocklists remain in memory; dashboard configuration is persisted atomically as YAML.

## Test

```sh
go test -race ./...
go test -bench=. ./internal/resolver
```
