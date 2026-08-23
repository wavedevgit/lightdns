#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
go build -trimpath -ldflags="-s -w" -o lightdns ./cmd/lightdns

printf 'Built %s/lightdns\n' "$(pwd)"
