#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ ! -x ./lightdns ]; then
  printf 'Built binary ./lightdns was not found. Run ./build.sh first.\n' >&2
  exit 1
fi

for file in install.sh run.sh config.example.yaml README.md; do
  if [ ! -f "$file" ]; then
    printf 'Required package file is missing: %s\n' "$file" >&2
    exit 1
  fi
done

case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *) architecture="$(uname -m)" ;;
esac

package="lightdns-linux-$architecture"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT HUP INT TERM

mkdir -p "dist" "$staging/$package"
install -m 755 lightdns install.sh run.sh "$staging/$package/"
install -m 644 config.example.yaml README.md "$staging/$package/"

archive="dist/$package.tar.gz"
tar_file="$staging/$package.tar"
tar -C "$staging" --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2020-01-01' -cf "$tar_file" "$package"
gzip -n -c "$tar_file" >"$archive"
(cd dist && sha256sum "$package.tar.gz" >"$package.tar.gz.sha256")

printf 'Created %s\n' "$archive"
printf 'Created %s.sha256\n' "$archive"
