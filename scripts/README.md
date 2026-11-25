# CyberScore — DevOps scripts & automation

This folder holds everything needed to install, update and back up CyberScore on a
VPS, plus the GitHub Actions CI pipeline.

## 1. GitHub Actions CI — `.github/workflows/ci.yml`
On every push/PR it runs the unit tests. On pushes to `main` (and `v*` tags) it also
builds the Docker image and publishes it to the GitHub Container Registry at
`ghcr.io/kolopro/cyberscore` (tags: `latest` + short SHA). No secrets to configure —
it uses the built-in `GITHUB_TOKEN`. (The server currently still builds locally; the
GHCR image is available if you later want the server to `docker pull` instead of build.)

## 2. First-time server setup — `install.sh`
On a fresh Ubuntu 24.04/26.04 box, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/kolopro/cyberscore/main/scripts/install.sh | bash
```

Installs Docker, `ufw` (22/80/443), 2 GB swap, `age` + `rclone`, clones the repo to
`/root/cyberscore`, creates `.env` from the template, and starts the stack. Then edit
`/root/cyberscore/.env` and point your DNS at the server.

## 3. Updating — `update.sh`
```bash
bash /root/cyberscore/scripts/update.sh          # pull + rebuild + reload Caddy + prune
bash /root/cyberscore/scripts/update.sh --force   # rebuild even with no new commits
```
Rebuilding also refreshes SSLyze / OpenSSL / the CA trust store, keeping the TLS checks
current. Includes a health check against `https://cyberscore.cc/api/health`.

## 4. Encrypted off-site backup — `backup.sh` / `restore.sh`
Backs up `.env` + the Caddy volumes (certs/ACME account), encrypts with **age** to a
public key you control, and uploads with **rclone**. The server can create but **not
decrypt** backups — keep the private key off the server.

### One-time setup
1. On your **own** machine, make a keypair and keep the private file safe:
   ```bash
   age-keygen -o age-key.txt      # prints "Public key: age1..."
   ```
2. On the **server**, configure an rclone remote (Backblaze B2 / Cloudflare R2 / S3 / Drive):
   ```bash
   rclone config                  # create a remote, e.g. named "b2"
   ```
3. Put the values in `/root/cyberscore/.env`:
   ```
   AGE_RECIPIENT=age1...                 # the PUBLIC key from step 1
   RCLONE_REMOTE=b2:cyberscore-backups   # remote:bucket from step 2
   ```
4. Test it once:
   ```bash
   bash /root/cyberscore/scripts/backup.sh
   ```

### Schedule it (systemd timer, daily 03:30)
```bash
cp /root/cyberscore/scripts/cyberscore-backup.service /etc/systemd/system/
cp /root/cyberscore/scripts/cyberscore-backup.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cyberscore-backup.timer
systemctl list-timers cyberscore-backup   # verify
journalctl -u cyberscore-backup -n 50     # view last run
```

### Restore (on a trusted machine with the private key)
```bash
RCLONE_REMOTE=b2:cyberscore-backups \
  bash scripts/restore.sh --identity /path/to/age-key.txt --file latest        # decrypt + extract
# add --apply to restore the volumes + .env onto the current server
```

## Notes
- The app has **no database** — only `.env` and the Caddy volumes are stateful, so those
  are what gets backed up. Everything else is reproducible from git.
- `.env`, `backups/`, `*.tar.age` and `age-key.txt` are gitignored — never commit them.
