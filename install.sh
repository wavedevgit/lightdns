#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

install_root="${LIGHTDNS_INSTALL_ROOT:-}"
if [ -z "$install_root" ] && [ "$(id -u)" -ne 0 ]; then
  printf 'Run this installer as root: sudo ./install.sh\n' >&2
  exit 1
fi

bindir="$install_root/usr/local/bin"
config_dir="$install_root/etc/lightdns"
config_file="$config_dir/config.yaml"
state_dir="$install_root/var/lib/lightdns"
database_file="$state_dir/lightdns.db"
backup_dir="$install_root/var/backups/lightdns"
installed_binary="$bindir/lightdns"
installed_wrapper="$bindir/lightdns-run"
runtime_user="${LIGHTDNS_USER:-${SUDO_USER:-root}}"
runtime_group="${LIGHTDNS_GROUP:-$(id -gn "$runtime_user")}"
config_owner=root
if [ "$(id -u)" -ne 0 ]; then
  config_owner="$runtime_user"
fi
timestamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"

if [ ! -x ./lightdns ]; then
  printf 'Built binary ./lightdns was not found. Run ./build.sh first.\n' >&2
  exit 1
fi

backup_binary=""
backup_wrapper=""
backup_database=""
temporary_password=""
had_binary=false
had_wrapper=false
had_database=false
had_capability=false
had_bindir=false
had_config_dir=false
had_state_dir=false
had_backup_dir=false
had_config=false
[ -d "$bindir" ] && had_bindir=true
[ -d "$config_dir" ] && had_config_dir=true
[ -d "$state_dir" ] && had_state_dir=true
[ -d "$backup_dir" ] && had_backup_dir=true
[ -f "$config_file" ] && had_config=true

install -d -m 755 "$bindir"
install -d -m 750 "$config_dir"
install -d -m 700 -o "$config_owner" -g "$runtime_group" "$backup_dir"
if [ "$had_state_dir" = false ]; then
  install -d -m 750 -o "$runtime_user" -g "$runtime_group" "$state_dir"
elif [ -L "$state_dir" ]; then
  printf 'The LightDNS state directory must not be a symbolic link.\n' >&2
  exit 1
fi

lock_held=false
if command -v flock >/dev/null 2>&1; then
  exec 9<"$state_dir"
  if ! flock -n 9; then
    printf 'LightDNS is running. Stop it before upgrading.\n' >&2
    exit 1
  fi
  lock_held=true
elif [ -f "$database_file" ]; then
  printf 'The flock utility is required for a safe database upgrade.\n' >&2
  exit 1
fi
chown "$config_owner:$runtime_group" "$state_dir"
chmod 750 "$state_dir"
trap 'chown "$runtime_user:$runtime_group" "$state_dir" 2>/dev/null || true; chmod 750 "$state_dir" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
if [ -e "$database_file-wal" ] || [ -e "$database_file-shm" ]; then
  printf 'SQLite WAL files are present. Stop LightDNS cleanly before upgrading.\n' >&2
  exit 1
fi
if [ -f "$installed_binary" ]; then
  had_binary=true
  backup_binary="$backup_dir/lightdns-$timestamp"
  install -m 755 "$installed_binary" "$backup_binary"
  if command -v getcap >/dev/null 2>&1 && getcap "$installed_binary" | grep -q 'cap_net_bind_service'; then
    had_capability=true
  fi
fi
if [ -f "$installed_wrapper" ]; then
  had_wrapper=true
  backup_wrapper="$backup_dir/lightdns-run-$timestamp"
  install -m 755 "$installed_wrapper" "$backup_wrapper"
fi
if [ -f "$database_file" ]; then
  had_database=true
  backup_database="$backup_dir/lightdns-$timestamp.db"
  LIGHTDNS_DATABASE_LOCK_FD=9 ./lightdns -database "$database_file" -backup-database "$backup_database"
fi
if [ -f "$config_file" ]; then
  install -m 600 "$config_file" "$backup_dir/config-$timestamp.yaml"
fi
legacy_state="$state_dir/state.yaml"
if [ -e "$legacy_state" ]; then
  LIGHTDNS_DATABASE_LOCK_FD=9 ./lightdns -database "$database_file" -state "$legacy_state" -backup-file "$backup_dir/state-$timestamp.yaml"
fi

rollback() {
  rm -f "$temporary_password" "$database_file-wal" "$database_file-shm"
  if [ -n "$backup_binary" ] && [ -f "$backup_binary" ]; then
    install -m 755 "$backup_binary" "$installed_binary"
  elif [ "$had_binary" = false ]; then
    rm -f "$installed_binary"
  fi
  if [ -n "$backup_wrapper" ] && [ -f "$backup_wrapper" ]; then
    install -m 755 "$backup_wrapper" "$installed_wrapper"
  elif [ "$had_wrapper" = false ]; then
    rm -f "$installed_wrapper"
  fi
  if [ -n "$backup_database" ] && [ -f "$backup_database" ]; then
    rm -f "$database_file" "$database_file-wal" "$database_file-shm"
    install -m 600 -o "$runtime_user" -g "$runtime_group" "$backup_database" "$database_file"
  elif [ "$had_database" = false ]; then
    rm -f "$database_file"
  fi
  if [ "$had_capability" = true ] && command -v setcap >/dev/null 2>&1 && [ -f "$installed_binary" ]; then
    setcap cap_net_bind_service=+ep "$installed_binary" || true
  fi
  if [ "$had_config" = false ]; then
    rm -f "$config_file"
  fi
  [ "$had_backup_dir" = true ] || rmdir "$backup_dir" 2>/dev/null || true
  [ "$had_state_dir" = true ] || rmdir "$state_dir" 2>/dev/null || true
  [ "$had_config_dir" = true ] || rmdir "$config_dir" 2>/dev/null || true
  [ "$had_bindir" = true ] || rmdir "$bindir" 2>/dev/null || true
  chown "$runtime_user:$runtime_group" "$state_dir" 2>/dev/null || true
  chmod 750 "$state_dir" 2>/dev/null || true
}
trap 'rollback' EXIT
trap 'exit 1' HUP INT TERM

install -m 755 lightdns "$installed_binary.new"
install -m 755 run.sh "$installed_wrapper.new"
mv -f "$installed_binary.new" "$installed_binary"
mv -f "$installed_wrapper.new" "$installed_wrapper"

if [ ! -f "$config_file" ]; then
  install -m 640 -o "$config_owner" -g "$runtime_group" config.example.yaml "$config_file"
fi

password_file="${LIGHTDNS_BOOTSTRAP_PASSWORD_FILE:-}"
admin_username="${LIGHTDNS_BOOTSTRAP_ADMIN:-admin}"
needs_bootstrap=false
if [ ! -f "$database_file" ]; then
  needs_bootstrap=true
else
  if [ "$lock_held" = true ]; then
    user_count="$(LIGHTDNS_DATABASE_LOCK_FD=9 "$installed_binary" -database "$database_file" -user-count-only)"
  else
    user_count="$("$installed_binary" -database "$database_file" -user-count-only)"
  fi
  if [ "$user_count" -eq 0 ]; then
    needs_bootstrap=true
  fi
fi
if [ "$needs_bootstrap" = true ] && [ -z "$password_file" ]; then
  if [ ! -r /dev/tty ]; then
    printf 'A TTY or LIGHTDNS_BOOTSTRAP_PASSWORD_FILE is required for initial setup.\n' >&2
    exit 1
  fi
  temporary_password="$(mktemp "$state_dir/.bootstrap-password.XXXXXX")"
  chmod 600 "$temporary_password"
  chown "$runtime_user:$runtime_group" "$temporary_password"
  while :; do
    printf 'Initial admin username [admin]: ' >/dev/tty
    IFS= read -r admin_username </dev/tty || exit 1
    admin_username="${admin_username:-admin}"
    printf 'Initial admin password (12+ characters): ' >/dev/tty
    stty -echo </dev/tty
    IFS= read -r admin_password </dev/tty || { stty echo </dev/tty; exit 1; }
    stty echo </dev/tty
    printf '\nConfirm password: ' >/dev/tty
    stty -echo </dev/tty
    IFS= read -r admin_confirmation </dev/tty || { stty echo </dev/tty; exit 1; }
    stty echo </dev/tty
    printf '\n' >/dev/tty
    if [ "${#admin_password}" -lt 12 ]; then
      printf 'The password must contain at least 12 characters.\n' >&2
      continue
    fi
    if [ "$admin_password" != "$admin_confirmation" ]; then
      printf 'The passwords do not match.\n' >&2
      continue
    fi
    printf '%s' "$admin_password" >"$temporary_password"
    password_file="$temporary_password"
    break
  done
fi

set -- -database "$database_file" -config "$config_file" -state "$legacy_state" -init-only
if [ -n "$password_file" ]; then
  set -- "$@" -bootstrap-admin "$admin_username" -bootstrap-password-file "$password_file"
fi
if [ "$lock_held" = true ]; then
  export LIGHTDNS_DATABASE_LOCK_FD=9
fi
if ! "$installed_binary" "$@"; then
  rm -f "$temporary_password"
  printf 'Database initialization failed; installed files were rolled back.\n' >&2
  exit 1
fi
rm -f "$temporary_password"
chown "$runtime_user:$runtime_group" "$database_file"
chmod 600 "$database_file"
chown "$runtime_user:$runtime_group" "$state_dir"
chmod 750 "$state_dir"

if [ "${LIGHTDNS_SKIP_CAPABILITY:-false}" = true ]; then
  :
elif command -v setcap >/dev/null 2>&1; then
  if ! setcap cap_net_bind_service=+ep "$installed_binary"; then
    printf 'Could not apply the low-port capability; installed files were rolled back.\n' >&2
    exit 1
  fi
else
  printf 'Warning: setcap is unavailable; run LightDNS as root or use a high DNS port.\n' >&2
fi

trap - EXIT HUP INT TERM
printf 'Installed LightDNS with database %s. Start it with:\n  %s\n' "$database_file" "$installed_wrapper"
