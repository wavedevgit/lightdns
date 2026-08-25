#!/usr/bin/env sh
set -eu

binary="${LIGHTDNS_BINARY:-/usr/local/bin/lightdns}"
database_file="${LIGHTDNS_DATABASE:-/var/lib/lightdns/lightdns.db}"

if [ ! -x "$binary" ]; then
  printf 'LightDNS binary is not executable: %s\n' "$binary" >&2
  exit 1
fi
if [ ! -r "$database_file" ] || [ ! -w "$database_file" ] || [ ! -w "$(dirname "$database_file")" ]; then
  printf 'LightDNS database or its directory is not accessible: %s\n' "$database_file" >&2
  exit 1
fi

printf 'Database: %s\n' "$database_file"
exec "$binary" -database "$database_file"
