#!/usr/bin/env bash
#
# backup.sh — encrypted, off-site backup of CyberScore's stateful data.
#
# Backs up: .env (secrets) + the Caddy Docker volumes (Let's Encrypt account &
# certificates + config). The app code itself lives in git, so it isn't backed up.
#
# The archive is encrypted with `age` to a PUBLIC recipient key, so the server can
# CREATE backups but cannot DECRYPT them — keep the matching private key off-server.
# The encrypted file is then uploaded off-site with `rclone`.
#
# Requirements on the server:  age, rclone, docker, tar  (install.sh installs them).
# Configure in .env:
#   AGE_RECIPIENT=age1...            # your age PUBLIC key (recipient)
#   RCLONE_REMOTE=b2:cyberscore-backups   # an rclone remote + path (rclone config)
#   BACKUP_KEEP_LOCAL=7              # keep N newest local copies
#   BACKUP_PRUNE_REMOTE_DAYS=30     # delete remote backups older than N days (0 = never)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$(dirname "${SCRIPT_DIR}")}"
cd "${APP_DIR}"

# --- Load configuration from .env --------------------------------------------
if [[ -f .env ]]; then
  set -a; . ./.env; set +a
fi
: "${AGE_RECIPIENT:?Set AGE_RECIPIENT (age public key) in .env}"
: "${RCLONE_REMOTE:?Set RCLONE_REMOTE (e.g. b2:cyberscore-backups) in .env}"
BACKUP_KEEP_LOCAL="${BACKUP_KEEP_LOCAL:-7}"
BACKUP_PRUNE_REMOTE_DAYS="${BACKUP_PRUNE_REMOTE_DAYS:-30}"

LOCAL_DIR="${APP_DIR}/backups"
mkdir -p "${LOCAL_DIR}"

# Avoid overlapping runs.
exec 9>"${LOCAL_DIR}/.lock"
flock -n 9 || { echo "Another backup is running — exiting."; exit 0; }

for bin in age rclone docker tar; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Missing dependency: $bin" >&2; exit 1; }
done

STAMP="$(date -u +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "==> Collecting state"
# .env (secrets)
[[ -f .env ]] && cp .env "${WORK}/env.backup"

# Caddy volumes — detect the compose-prefixed names.
dump_volume() {
  local match="$1" out="$2" name
  name="$(docker volume ls --format '{{.Name}}' | grep -E "${match}\$" | head -n1 || true)"
  if [[ -n "${name}" ]]; then
    echo "    - volume ${name}"
    docker run --rm -v "${name}:/v:ro" -v "${WORK}:/out" alpine \
      tar czf "/out/${out}" -C /v . 2>/dev/null
  else
    echo "    - (no volume matching ${match} — skipped)"
  fi
}
dump_volume "_caddy_data"   "caddy_data.tgz"
dump_volume "_caddy_config" "caddy_config.tgz"

echo "==> Packing + encrypting (age)"
ARCHIVE="cyberscore-backup-${STAMP}.tar.age"
OUT="${LOCAL_DIR}/${ARCHIVE}"
tar czf - -C "${WORK}" . | age -r "${AGE_RECIPIENT}" -o "${OUT}"
echo "    wrote ${OUT} ($(du -h "${OUT}" | cut -f1))"

echo "==> Uploading off-site: ${RCLONE_REMOTE}"
rclone copy "${OUT}" "${RCLONE_REMOTE%/}/" --no-traverse

echo "==> Retention"
# Local: keep the newest N.
ls -1t "${LOCAL_DIR}"/cyberscore-backup-*.tar.age 2>/dev/null | tail -n +"$((BACKUP_KEEP_LOCAL+1))" | xargs -r rm -f
# Remote: delete older than N days (0 disables).
if [[ "${BACKUP_PRUNE_REMOTE_DAYS}" -gt 0 ]]; then
  rclone delete "${RCLONE_REMOTE%/}/" --min-age "${BACKUP_PRUNE_REMOTE_DAYS}d" \
    --include 'cyberscore-backup-*.tar.age' 2>/dev/null || true
fi

echo "==> Backup complete: ${ARCHIVE}"
