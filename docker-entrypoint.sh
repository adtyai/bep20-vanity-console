#!/bin/sh
set -eu
data="${DATA_DIR:-/data}"
if [ "$(id -u)" = 0 ]; then
  data=$(realpath -m "$data")
  case "$data" in
    /data|/data/*)
      mkdir -p "$data"
      chown -R vanity:vanity "$data"
      chmod 700 "$data"
      ;;
    *)
      echo "DATA_DIR 必须在 /data 下面" >&2
      exit 1
      ;;
  esac
  exec setpriv --reuid=vanity --regid=vanity --init-groups --inh-caps=-all /usr/local/bin/bep20-vanity-console
fi
exec /usr/local/bin/bep20-vanity-console
