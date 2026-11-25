#!/usr/bin/env bash
#
# update.sh — pull the latest code and redeploy CyberScore safely.
#
# Usage (on the server):
#   bash /root/cyberscore/scripts/update.sh
#
# What it does: git pull -> rebuild image -> recreate app -> reload Caddy config
# -> prune old images. Rebuilding also refreshes SSLyze / OpenSSL / CA trust store.
#
set -euo pipefail

# Resolve the app directory (the parent of this script's folder).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$(dirname "${SCRIPT_DIR}")}"
cd "${APP_DIR}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

log "Pulling latest from GitHub (branch: $(git rev-parse --abbrev-ref HEAD))"
BEFORE="$(git rev-parse HEAD)"
git pull --ff-only
AFTER="$(git rev-parse HEAD)"

if [[ "${BEFORE}" == "${AFTER}" && "${1:-}" != "--force" ]]; then
  echo "Already up to date (no new commits). Use --force to rebuild anyway."
  exit 0
fi

log "Rebuilding and restarting the app"
docker compose up -d --build

log "Reloading Caddy (bind-mounted Caddyfile)"
docker compose restart caddy

log "Pruning old images"
docker image prune -f >/dev/null 2>&1 || true

log "Health check"
if curl -fsS --max-time 15 https://cyberscore.cc/api/health >/dev/null 2>&1; then
  echo "OK — https://cyberscore.cc/api/health responded."
else
  echo "WARNING: health check did not pass yet. Check: docker compose logs --tail=50"
fi

log "Current state"
docker compose ps
