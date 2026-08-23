#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  printf 'Run this installer as root: sudo ./install.sh\n' >&2
  exit 1
fi

install_user="${SUDO_USER:-root}"
install_group="$(id -gn "$install_user")"
config_dir=/etc/lightdns
config_file="$config_dir/config.yaml"
state_dir=/var/lib/lightdns

if [ ! -x ./lightdns ]; then
  printf 'Built binary ./lightdns was not found. Run ./build.sh first.\n' >&2
  exit 1
fi

if [ -e "$config_file" ]; then
  install -m 755 lightdns /usr/local/bin/lightdns
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_bind_service=+ep /usr/local/bin/lightdns
  else
    printf 'Warning: setcap is unavailable; run lightdns as root to bind port 53.\n' >&2
  fi
  printf 'Installed /usr/local/bin/lightdns; existing configuration and state were unchanged.\n'
  exit 0
fi

if [ ! -t 0 ]; then
  printf 'Interactive input is required to create the initial admin token.\n' >&2
  exit 1
fi

install -d -m 755 "$config_dir"
install -d -m 750 -o "$install_user" -g "$install_group" "$state_dir"
install -m 755 lightdns /usr/local/bin/lightdns
install -m 755 run.sh /usr/local/bin/lightdns-run

while :; do
  printf 'Choose a memorable admin token (8+ letters, numbers, dots, dashes, or underscores): '
  IFS= read -r admin_token
  if [ "${#admin_token}" -lt 8 ]; then
    printf 'The token must contain at least 8 characters.\n' >&2
    continue
  fi
  case "$admin_token" in
    *[!A-Za-z0-9._-]*)
      printf 'Use only letters, numbers, dots, dashes, and underscores.\n' >&2
      continue
      ;;
  esac
  printf 'Confirm admin token: '
  IFS= read -r admin_token_confirmation
  if [ "$admin_token" != "$admin_token_confirmation" ]; then
    printf 'The tokens do not match. Try again.\n' >&2
    continue
  fi
  break
done
temporary_config="$(mktemp)"
trap 'rm -f "$temporary_config"' EXIT HUP INT TERM
sed "s/token: \"\"/token: \"$admin_token\"/" config.example.yaml >"$temporary_config"
install -m 640 -o root -g "$install_group" "$temporary_config" "$config_file"
rm -f "$temporary_config"
trap - EXIT HUP INT TERM

printf 'Created %s\n' "$config_file"

if command -v setcap >/dev/null 2>&1; then
  setcap cap_net_bind_service=+ep /usr/local/bin/lightdns
else
  printf 'Warning: setcap is unavailable; run lightdns as root to bind port 53.\n' >&2
fi

printf '\nInstalled lightdns. Start it with:\n'
printf '  lightdns-run\n'
