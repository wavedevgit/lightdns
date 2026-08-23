#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

config_file="${LIGHTDNS_CONFIG_FILE:-/etc/lightdns/config.yaml}"
state_file="${LIGHTDNS_STATE_FILE:-/var/lib/lightdns/state.yaml}"

if [ ! -x ./lightdns ]; then
  printf 'lightdns is not built. Run ./build.sh first.\n' >&2
  exit 1
fi

if [ ! -r "$config_file" ]; then
  printf 'Configuration is not readable: %s\n' "$config_file" >&2
  printf 'Install and edit config.example.yaml at that location first.\n' >&2
  exit 1
fi

if [ ! -d "$(dirname "$state_file")" ] || [ ! -w "$(dirname "$state_file")" ]; then
  printf 'State directory is not writable: %s\n' "$(dirname "$state_file")" >&2
  exit 1
fi

printf 'Configuration: %s\n' "$config_file"
printf 'State: %s\n' "$state_file"

exec ./lightdns -config "$config_file" -state "$state_file"
