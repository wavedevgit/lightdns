# LightDNS

A small DNS blocker, cache, and local record manager with a web dashboard.

![LightDNS dashboard](docs/dashboard.png)

## Install

```sh
wget https://github.com/wavedevgit/lightdns/releases/download/v1/lightdns-linux-amd64.tar.gz
wget https://github.com/wavedevgit/lightdns/releases/download/v1/lightdns-linux-amd64.tar.gz.sha256
sha256sum -c lightdns-linux-amd64.tar.gz.sha256
tar -xzf lightdns-linux-amd64.tar.gz
cd lightdns-linux-amd64
sudo ./install.sh
lightdns-run
```

Dashboard: `http://127.0.0.1:8080`

## Test DNS

```sh
dig @127.0.0.1 example.com A
```

For a custom port:

```sh
dig @127.0.0.1 -p 1053 example.com A
```

## Configuration

- Base config: `/etc/lightdns/config.yaml`
- Dashboard state: `/var/lib/lightdns/state.yaml`
- Example: [`config.example.yaml`](config.example.yaml)

The state file overrides the base config after dashboard changes are saved.

## Build

```sh
go test -race ./...
./build.sh
./package.sh
```

## Security

DNS clients are not filtered by IP inside LightDNS. Restrict public DNS ports with your host or provider firewall. Keep the dashboard on loopback or use HTTPS.
