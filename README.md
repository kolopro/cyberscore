# Deploy CyberScore to the server (cyberscore.cc)

Server: Ubuntu 26.04, Docker already installed (via cloud-init).
These commands run **on the server** (after `ssh root@YOUR_SERVER_IP`).

## 1. Get the code onto the server

```bash
git clone https://github.com/YOUR_USERNAME/cyberscore.git
cd cyberscore
```

## 2. Start it (builds the image, first time ~3-5 min)

```bash
docker compose up -d --build
```

That starts two containers:
- **app** – the CyberScore FastAPI app (Chromium bundled for URL previews)
- **caddy** – reverse proxy that gets a free HTTPS certificate automatically

## 3. Point the domain at the server

In Cloudflare DNS for **cyberscore.cc**, add:

| Type | Name | Content          | Proxy status        |
|------|------|------------------|---------------------|
| A    | @    | YOUR_SERVER_IP   | DNS only (grey)*    |
| A    | www  | YOUR_SERVER_IP   | DNS only (grey)*    |

\* Start as **DNS only (grey cloud)** so Caddy can obtain the Let's Encrypt
certificate directly. Once HTTPS works, you can switch Cloudflare back to
**Proxied (orange)** with SSL mode **Full (strict)**.

Within a minute or two, https://cyberscore.cc is live with a valid certificate.

## Useful commands

```bash
docker compose logs -f           # watch logs
docker compose restart           # restart
git pull && docker compose up -d --build   # apply an update
docker compose down              # stop everything
```

## Enabling live reputation engines (optional, later)

Create a file named `.env` next to docker-compose.yml:

```
URLHAUS_AUTH_KEY=...
GOOGLE_SAFE_BROWSING_KEY=...
VIRUSTOTAL_API_KEY=...
```

then `docker compose up -d`. Without these the site still works (heuristic fallback).
