#!/usr/bin/env bash
# Simulates teams changing their services' dependencies.
#   bash scripts/change.sh list                  show the available changes
#   bash scripts/change.sh fix-quote-axios       quote-svc upgrades axios and follow-redirects (lockfile only)
#   bash scripts/change.sh revert-quote-axios    quote-svc goes back to the old versions
#   bash scripts/change.sh fix-payments-jwt      payments-svc upgrades jsonwebtoken to a new major version
#   bash scripts/change.sh revert-payments-jwt   payments-svc goes back to the old version
#   bash scripts/change.sh reset                 put every service back as shipped
set -eu
KIT="$(cd "$(dirname "$0")/.." && pwd)"
CH="$KIT/scripts/changes"
apply() { # source-folder
  for svc_dir in "$1"/*/; do
    svc=$(basename "$svc_dir")
    for f in "$svc_dir"*; do cp "$f" "$KIT/services/$svc/"; echo "  updated services/$svc/$(basename "$f")"; done
  done
}
case "${1:-list}" in
  list) sed -n '2,8p' "$0" | sed 's/^# //';;
  fix-quote-axios|fix-payments-jwt) apply "$CH/$1";;
  revert-quote-axios) cp "$CH/original/quote-svc/package-lock.json" "$KIT/services/quote-svc/"; echo "  restored services/quote-svc/package-lock.json";;
  revert-payments-jwt) cp "$CH/original/payments-svc/"* "$KIT/services/payments-svc/"; echo "  restored services/payments-svc/package.json and package-lock.json";;
  reset) apply "$CH/original";;
  *) echo "Unknown change: $1"; sed -n '2,8p' "$0" | sed 's/^# //'; exit 1;;
esac
