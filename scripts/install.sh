#!/usr/bin/env bash
#
# install.sh — provision a fresh Ubuntu server for CyberScore from scratch.
# Installs Docker, firewall, swap, clones the repo and brings the stack up.
#
# Usage (as root on a fresh Ubuntu 24.04/26.04 box):
#   curl -fsSL https://raw.githubusercontent.com/kolopro/cyberscore/main/scripts/install.sh | bash
#   # or, from a checkout:  sudo bash scripts/install.sh
#
# Override defaults with env vars, e.g.:
#   REPO_URL=... APP_DIR=/opt/cyberscore bash scripts/install.sh
#
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/kolopro/cyberscore.git}"
APP_DIR="${APP_DIR:-/root/cyberscore}"
SWAP_SIZE="${SWAP_SIZE:-2G}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo bash scripts/install.sh)." >&2
  exit 1
fi

log "Updating apt and installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git ufw age rclone

log "Installing Docker (if missing)"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

log "Ensuring swap (${SWAP_SIZE})"
if ! swapon --show | grep -q .; then
  fallocate -l "${SWAP_SIZE}" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
else
  echo "Swap already present — skipping."
fi

log "Configuring firewall (ufw: 22, 80, 443)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

log "Fetching the application into ${APP_DIR}"
if [[ -d "${APP_DIR}/.git" ]]; then
  git -C "${APP_DIR}" pull --ff-only
else
  git clone "${REPO_URL}" "${APP_DIR}"
fi
cd "${APP_DIR}"

log "Preparing .env"
if [[ ! -f .env ]]; then
  cp .env.example .env 2>/dev/null || true
  echo "Created .env — edit it to add API keys and backup settings (nano ${APP_DIR}/.env)."
else
  echo ".env already exists — leaving it untouched."
fi

log "Building and starting the stack"
docker compose up -d --build

log "Done. Containers:"
docker compose ps

cat <<EOF

Next steps:
  1. Point your DNS A records (@ and www) to this server's IP.
  2. Edit ${APP_DIR}/.env for reputation API keys + backup (age/rclone) settings.
  3. For HTTPS, Caddy obtains certificates automatically once DNS resolves here.
  4. To enable scheduled encrypted backups, see scripts/README.md.
EOF
