# CyberScore (cyberscore.cc)

Web scanner ασφάλειας domain/URL/email με βαθμολογία. Python (FastAPI) + Chromium για URL previews, πίσω από Caddy με αυτόματο HTTPS. Οδηγίες: `README.md`, `DEPLOY.md`, `scripts/README.md`.

## Δομή
- `main.py` (CLI), `run_web.py` + `web/app.py` (FastAPI), `web/static/` (index.html, el.html, guides, privacy, contact, sitemap, robots, ads.txt).
- `scanner/`: `dns`, `email`, `email_headers`, `http`, `tls` (+`deep.py`), `reputation` (providers/coordinator), `technology`, `urlcheck` (+`shot.py`), `scoring`, `engine.py`, `models.py`, `remediation.py`.
- `reports/` (console, `pdf.py`), `config/settings.py`, `tests/test_basic.py`.
- Deploy: `Dockerfile`, `docker-compose.yml` (`app` + `caddy`), `Caddyfile`, `scripts/` (install, update, backup + systemd timer, restore). Windows: `.bat` launchers και `scanner.ico`.

## Παραγωγή
- VPS `38.45.81.177` (Ubuntu 26.04, Docker), compose στο `/root/cyberscore`. Το ίδιο Caddy σερβίρει και `license.vortisec.com` (VortiLS) και `update.vortisec.com` (VortiUpdate): **προσοχή σε αλλαγές στο `Caddyfile`** (single-file bind mount, επεξεργασία επί τόπου).
- DNS στο Cloudflare, DNS only (γκρι σύννεφο) για το Let's Encrypt.
- Ενημέρωση: `git pull && docker compose up -d --build`. Logs: `docker compose logs -f`.
- Προαιρετικά κλειδιά reputation στο `.env`: `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_KEY`, `VIRUSTOTAL_API_KEY` (χωρίς αυτά δουλεύει με heuristics). Βλ. `.env.example`.

## Κανόνες
- Δοκιμές: `pytest tests/` πριν από deploy.
- Μην κάνεις commit `.env` ή κλειδιά.
- Όλα τα deliverables γράφονται στον φάκελο `AI Shit`.
- Μέγιστη οικονομία σε tokens: σύντομες απαντήσεις, χωρίς περιττά διαβάσματα· η ταχύτητα δεν μετράει.
- Απάντηση στα ελληνικά, εκτός αν ζητηθεί αλλιώς.
