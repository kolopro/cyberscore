#!/usr/bin/env bash
#
# restore.sh — decrypt and (optionally) restore a CyberScore backup.
#
# Run this where the age PRIVATE key is available (your trusted machine, or the
# server if you keep the key there only when restoring).
#
# Usage:
#   RCLONE_REMOTE=b2:cyberscore-backups \
#   bash scripts/restore.sh --identity /path/to/age-key.txt [--file latest] [--apply]
#
#   --identity FILE   age identity (private key) file (required)
#   --file NAME       backup file name, or "latest" (default: latest from remote)
#   --local PATH      use a local .tar.age instead of downloading
#   --apply           restore the Caddy volumes + .env onto THIS server (else extract only)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$(dirname "${SCRIPT_DIR}")}"
[[ -f "${APP_DIR}/.env" ]] && { set -a; . "${APP_DIR}/.env"; set +a; }

IDENTITY=""; FILE="latest"; LOCAL=""; APPLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2;;
    --file) FILE="$2"; shift 2;;
    --local) LOCAL="$2"; shift 2;;
    --apply) APPLY=1; shift;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done
: "${IDENTITY:?--identity <age key file> is required}"

WORK="$(mktemp -d)"; trap 'rm -rf "${WORK}"' EXIT
ENC="${WORK}/backup.tar.age"

if [[ -n "${LOCAL}" ]]; then
  cp "${LOCAL}" "${ENC}"
else
  : "${RCLONE_REMOTE:?Set RCLONE_REMOTE or pass --local}"
  if [[ "${FILE}" == "latest" ]]; then
    FILE="$(rclone lsf "${RCLONE_REMOTE%/}/" --include 'cyberscore-backup-*.tar.age' | sort | tail -n1)"
    [[ -n "${FILE}" ]] || { echo "No backups found on remote." >&2; exit 1; }
  fi
  echo "==> Downloading ${FILE}"
  rclone copyto "${RCLONE_REMOTE%/}/${FILE}" "${ENC}"
fi

echo "==> Decrypting + extracting"
age -d -i "${IDENTITY}" "${ENC}" | tar xzf - -C "${WORK}"
echo "    extracted to: ${WORK}"
ls -la "${WORK}"

if [[ "${APPLY}" -eq 0 ]]; then
  cat <<EOF

Extracted (not applied). Contents:
  - env.backup         -> your .env (secrets)
  - caddy_data.tgz     -> Caddy /data volume (certs + ACME account)
  - caddy_config.tgz   -> Caddy /config volume
Re-run with --apply on the target server to restore the volumes + .env.
EOF
  # Keep the extraction around for manual inspection.
  cp -r "${WORK}" "${APP_DIR}/restore-${RANDOM}" && echo "Copied to ${APP_DIR}/restore-*"
  exit 0
fi

echo "==> Applying to this server"
cd "${APP_DIR}"
[[ -f "${WORK}/env.backup" ]] && cp "${WORK}/env.backup" .env && echo "    restored .env"

restore_volume() {
  local tgz="$1" match="$2" name
  [[ -f "${WORK}/${tgz}" ]] || { echo "    (${tgz} absent — skipped)"; return; }
  name="$(docker volume ls --format '{{.Name}}' | grep -E "${match}\$" | head -n1 || true)"
  [[ -n "${name}" ]] || name="$(basename "${APP_DIR}")${match}"
  docker volume create "${name}" >/dev/null
  docker run --rm -v "${name}:/v" -v "${WORK}:/in" alpine \
    sh -c "rm -rf /v/* && tar xzf /in/${tgz} -C /v"
  echo "    restored volume ${name}"
}
restore_volume "caddy_data.tgz"   "_caddy_data"
restore_volume "caddy_config.tgz" "_caddy_config"

echo "==> Restarting stack"
docker compose up -d
echo "Done."
