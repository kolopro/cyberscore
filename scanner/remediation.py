"""Remediation knowledge base.

Maps a finding's stable `code` to a concrete remediation plan: why it matters,
step-by-step fix, rough effort, and references. This is deliberately data (not
code) so it can later be edited by non-developers, translated, or served from a
database in a SaaS.
"""
from __future__ import annotations

from typing import Any, Dict, List

from scanner.models import Finding

# effort scale: "Low" (minutes/config), "Medium" (hours), "High" (project)
CATALOG: Dict[str, Dict[str, Any]] = {
    # --- HTTP / HTTPS -------------------------------------------------------
    "http.no_https": {
        "why": "Without HTTPS all traffic — including credentials and session "
               "cookies — travels in clear text and can be read or modified by "
               "anyone on the network path.",
        "effort": "Medium",
        "steps": [
            "Obtain a TLS certificate (Let's Encrypt is free and automatable).",
            "Configure the web server to listen on port 443 with the certificate.",
            "Redirect all HTTP traffic to HTTPS (301).",
            "Verify the full chain is served (leaf + intermediates).",
        ],
        "refs": ["https://letsencrypt.org/getting-started/"],
    },
    "http.no_redirect": {
        "why": "If plain HTTP does not redirect to HTTPS, users and bots can "
               "keep talking to the insecure endpoint, exposing data and "
               "enabling downgrade attacks.",
        "effort": "Low",
        "steps": [
            "Add a server rule returning HTTP 301 to the https:// equivalent.",
            "Apply it to every path, not just the homepage.",
            "Once stable, add HSTS so browsers upgrade automatically.",
        ],
        "refs": [],
    },
    "http.powered_by": {
        "why": "The X-Powered-By header reveals your framework and sometimes its "
               "version, helping attackers target known vulnerabilities.",
        "effort": "Low",
        "steps": [
            "Remove or blank the X-Powered-By header at the app or proxy layer.",
            "For PHP set expose_php = Off; for Express call app.disable('x-powered-by').",
        ],
        "refs": [],
    },
    "http.header.strict-transport-security": {
        "why": "HSTS forces browsers to use HTTPS only, preventing SSL-stripping "
               "and accidental downgrades to HTTP.",
        "effort": "Low",
        "steps": [
            "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Start with a shorter max-age while testing, then raise it.",
            "Only add 'preload' once you are certain all subdomains are HTTPS.",
        ],
        "refs": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "http.header.content-security-policy": {
        "why": "A Content-Security-Policy is the strongest defence against XSS "
               "and data-injection by controlling which resources may load.",
        "effort": "High",
        "steps": [
            "Start in report-only mode: Content-Security-Policy-Report-Only.",
            "Inventory the scripts/styles/images your pages actually use.",
            "Write a policy (e.g. default-src 'self') and tighten iteratively.",
            "Switch from report-only to enforcing once clean.",
        ],
        "refs": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"],
    },
    "http.header.x-content-type-options": {
        "why": "Without nosniff, browsers may MIME-sniff responses and execute "
               "content as an unintended type, enabling some XSS vectors.",
        "effort": "Low",
        "steps": ["Send: X-Content-Type-Options: nosniff on all responses."],
        "refs": [],
    },
    "http.header.x-frame-options": {
        "why": "Missing framing protection allows clickjacking, where your site "
               "is embedded invisibly over a malicious page.",
        "effort": "Low",
        "steps": [
            "Send: X-Frame-Options: DENY (or SAMEORIGIN if you self-embed).",
            "Preferably also set CSP frame-ancestors 'self'.",
        ],
        "refs": [],
    },
    "http.header.referrer-policy": {
        "why": "A permissive referrer policy can leak full URLs (with tokens or "
               "IDs) to third-party sites.",
        "effort": "Low",
        "steps": ["Send: Referrer-Policy: strict-origin-when-cross-origin."],
        "refs": [],
    },
    "http.header.permissions-policy": {
        "why": "Permissions-Policy lets you switch off powerful browser features "
               "(camera, geolocation, etc.) your site does not use, shrinking "
               "the attack surface.",
        "effort": "Low",
        "steps": [
            "Send a restrictive policy, e.g. Permissions-Policy: geolocation=(), "
            "camera=(), microphone=().",
        ],
        "refs": [],
    },
    "http.cookie_flags": {
        "why": "Cookies without Secure/HttpOnly/SameSite can be stolen over HTTP, "
               "read by JavaScript (XSS) or sent in cross-site requests (CSRF).",
        "effort": "Low",
        "steps": [
            "Set Secure so cookies are only sent over HTTPS.",
            "Set HttpOnly on session cookies so scripts cannot read them.",
            "Set SameSite=Lax or Strict to limit cross-site sending.",
        ],
        "refs": [],
    },
    # --- TLS ----------------------------------------------------------------
    "tls.no_tls": {
        "why": "No usable TLS on 443 means the site cannot be served securely at "
               "all.",
        "effort": "Medium",
        "steps": [
            "Install a valid certificate from a trusted CA.",
            "Enable TLS 1.2 and 1.3 in the server configuration.",
            "Confirm port 443 is open and the service is listening.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.untrusted": {
        "why": "An untrusted or mismatched certificate triggers browser warnings "
               "and enables man-in-the-middle attacks if users click through.",
        "effort": "Medium",
        "steps": [
            "Use a certificate whose name matches the hostname (or a SAN/wildcard).",
            "Serve the complete chain (leaf + intermediate certificates).",
            "Replace self-signed certs with one from a trusted CA.",
        ],
        "refs": ["https://www.ssllabs.com/ssltest/"],
    },
    "tls.expired": {
        "why": "An expired certificate makes the site unusable in browsers and "
               "breaks trust immediately.",
        "effort": "Low",
        "steps": [
            "Renew the certificate now.",
            "Automate renewal (e.g. certbot/ACME) so it never lapses again.",
            "Add expiry monitoring/alerting.",
        ],
        "refs": [],
    },
    "tls.expiring_soon": {
        "why": "The certificate expires within days; if renewal fails the site "
               "will go down.",
        "effort": "Low",
        "steps": [
            "Renew immediately and confirm the new cert is deployed.",
            "Verify auto-renewal is actually running (check timers/cron).",
        ],
        "refs": [],
    },
    "tls.expiring": {
        "why": "The certificate expires soon; renewing early avoids a last-minute "
               "outage.",
        "effort": "Low",
        "steps": [
            "Confirm auto-renewal is scheduled and working.",
            "If manual, renew now rather than close to the deadline.",
        ],
        "refs": [],
    },
    "tls.no_tls13": {
        "why": "TLS 1.3 is faster and removes weak options present in older "
               "versions.",
        "effort": "Low",
        "steps": [
            "Enable TLS 1.3 in the server/CDN configuration.",
            "Keep TLS 1.2 for compatibility; drop everything below.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.legacy": {
        "why": "TLS 1.0/1.1 are deprecated and vulnerable to known attacks; "
               "supporting them weakens every connection.",
        "effort": "Low",
        "steps": [
            "Disable TLS 1.0 and 1.1 in the server/CDN.",
            "Require TLS 1.2 as the minimum, prefer 1.3.",
            "Re-test to confirm legacy handshakes now fail.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.weak_protocol": {
        "why": "SSL 2.0/3.0 are broken and enable attacks like POODLE; any support "
               "for them undermines the whole site.",
        "effort": "Low",
        "steps": [
            "Disable SSL 2.0 and SSL 3.0 in the server/CDN configuration.",
            "Allow only TLS 1.2 and TLS 1.3.",
            "Re-test to confirm SSL handshakes now fail.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.no_forward_secrecy": {
        "why": "Without forward secrecy, if the server key is ever compromised, past "
               "recorded traffic can be decrypted.",
        "effort": "Low",
        "steps": [
            "Prefer ECDHE (or DHE) key-exchange cipher suites.",
            "Use Mozilla's 'intermediate' or 'modern' config generator.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.weak_cipher": {
        "why": "RC4, 3DES, NULL, EXPORT and anonymous ciphers are weak or broken and "
               "weaken every connection that negotiates them.",
        "effort": "Low",
        "steps": [
            "Remove RC4, 3DES, NULL, EXPORT and anonymous cipher suites.",
            "Keep modern AEAD suites: AES-GCM and ChaCha20-Poly1305.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.heartbleed": {
        "why": "Heartbleed lets attackers read server memory, including private keys "
               "and session data.",
        "effort": "Medium",
        "steps": [
            "Upgrade OpenSSL to a patched version immediately.",
            "Reissue the certificate and rotate the private key.",
            "Revoke the old certificate.",
        ],
        "refs": ["https://heartbleed.com/"],
    },
    "tls.robot": {
        "why": "ROBOT allows decrypting RSA-encrypted TLS traffic or forging "
               "signatures.",
        "effort": "Medium",
        "steps": [
            "Disable RSA key-exchange (static RSA) cipher suites.",
            "Patch/upgrade the TLS termination stack.",
        ],
        "refs": ["https://robotattack.org/"],
    },
    "tls.ccs_injection": {
        "why": "CCS injection (CVE-2014-0224) lets a man-in-the-middle force weak "
               "keys on a session.",
        "effort": "Medium",
        "steps": [
            "Upgrade OpenSSL to a fixed version.",
        ],
        "refs": [],
    },
    "tls.insecure_reneg": {
        "why": "Without secure renegotiation (RFC 5746) a man-in-the-middle can "
               "inject data into a session.",
        "effort": "Low",
        "steps": [
            "Enable secure renegotiation in the TLS stack / upgrade it.",
        ],
        "refs": [],
    },
    "tls.compression": {
        "why": "TLS-level compression enables the CRIME attack, which can recover "
               "secrets such as cookies.",
        "effort": "Low",
        "steps": [
            "Disable TLS compression in the server/CDN.",
        ],
        "refs": [],
    },
    "tls.weak_key": {
        "why": "An RSA key under 2048 bits is too weak against modern factoring "
               "attacks.",
        "effort": "Medium",
        "steps": [
            "Reissue the certificate with a 2048-bit+ RSA key, or an EC key (P-256).",
            "Deploy the new certificate and revoke the old one.",
        ],
        "refs": ["https://ssl-config.mozilla.org/"],
    },
    "tls.sha1_cert": {
        "why": "SHA-1 signatures are considered insecure and are distrusted by "
               "browsers.",
        "effort": "Medium",
        "steps": [
            "Reissue the certificate chain with SHA-256 or stronger signatures.",
        ],
        "refs": [],
    },
    # --- DNS ----------------------------------------------------------------
    "dns.no_a": {
        "why": "Without an A record the host does not resolve over IPv4 and is "
               "unreachable for most users.",
        "effort": "Low",
        "steps": ["Publish an A record pointing to the server's IPv4 address."],
        "refs": [],
    },
    "dns.no_caa": {
        "why": "A CAA record restricts which certificate authorities may issue "
               "certificates for your domain, reducing mis-issuance risk.",
        "effort": "Low",
        "steps": [
            "Add a CAA record naming your CA, e.g. 0 issue \"letsencrypt.org\".",
            "Optionally add an iodef contact for violation reports.",
        ],
        "refs": ["https://sslmate.com/caa/"],
    },
    "dns.no_dnssec": {
        "why": "Without DNSSEC, DNS answers can be spoofed, redirecting users to "
               "attacker-controlled servers.",
        "effort": "Medium",
        "steps": [
            "Enable DNSSEC signing at your DNS provider.",
            "Publish the DS record at your registrar to complete the chain.",
            "Validate with a DNSSEC checker afterwards.",
        ],
        "refs": ["https://dnssec-analyzer.verisignlabs.com/"],
    },
    # --- Email --------------------------------------------------------------
    "email.no_spf": {
        "why": "Without SPF, anyone can send email claiming to be from your "
               "domain, aiding phishing and spoofing.",
        "effort": "Low",
        "steps": [
            "Publish an SPF TXT record listing authorised senders.",
            "End it with -all (hard fail) once you are sure it is complete.",
        ],
        "refs": ["https://dmarcian.com/spf-syntax-table/"],
    },
    "email.spf_weak": {
        "why": "An SPF record without a strict 'all' qualifier lets unlisted "
               "servers pass, weakening spoofing protection.",
        "effort": "Low",
        "steps": [
            "Change the ending to ~all (softfail) or -all (fail).",
            "Verify all legitimate senders are included first.",
        ],
        "refs": [],
    },
    "email.no_dmarc": {
        "why": "DMARC tells receivers what to do with mail that fails SPF/DKIM "
               "and gives you visibility via reports. Without it, spoofing is "
               "easier and invisible.",
        "effort": "Medium",
        "steps": [
            "Publish _dmarc TXT starting with p=none to monitor.",
            "Add rua= to collect aggregate reports.",
            "Once clean, move to p=quarantine then p=reject.",
        ],
        "refs": ["https://dmarc.org/overview/"],
    },
    "email.dmarc_weak": {
        "why": "A DMARC policy of p=none only monitors; spoofed mail is still "
               "delivered.",
        "effort": "Medium",
        "steps": [
            "Review aggregate reports to confirm legitimate sources pass.",
            "Move the policy to p=quarantine, then p=reject.",
        ],
        "refs": [],
    },
    "email.no_dkim": {
        "why": "DKIM cryptographically signs your mail so receivers can verify it "
               "was not altered and really came from you.",
        "effort": "Medium",
        "steps": [
            "Enable DKIM signing in your mail provider/server.",
            "Publish the provider's public key at selector._domainkey.",
            "Send a test and confirm the signature verifies.",
            "Note: detection here probes common selectors only — yours may exist.",
        ],
        "refs": [],
    },
    "email.dmarc_pct": {
        "why": "A pct below 100 applies the DMARC policy to only a fraction of "
               "mail, leaving the rest unprotected.",
        "effort": "Low",
        "steps": ["Set pct=100 in the _dmarc record once you trust the policy."],
        "refs": [],
    },
    "email.dmarc_sp": {
        "why": "Without a strict subdomain policy, attackers can spoof "
               "subdomains (e.g. news.yourdomain) even if the apex is protected.",
        "effort": "Low",
        "steps": ["Add sp=reject (or sp=quarantine) to the _dmarc record."],
        "refs": [],
    },
    "email.dmarc_no_rua": {
        "why": "Without a rua address you get no DMARC reports, so you are blind "
               "to who is sending as your domain and whether alignment passes.",
        "effort": "Low",
        "steps": [
            "Add rua=mailto:dmarc@yourdomain to the _dmarc record.",
            "Review the aggregate reports before tightening the policy.",
        ],
        "refs": ["https://dmarc.org/overview/"],
    },
    "email.spf_lookups": {
        "why": "SPF allows at most 10 DNS lookups; exceeding it makes SPF return "
               "permerror and receivers treat SPF as failing.",
        "effort": "Medium",
        "steps": [
            "Remove unnecessary include: mechanisms.",
            "Consolidate senders or use an SPF-flattening service.",
            "Re-check the lookup count stays at or below 10.",
        ],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
    },
    "email.no_mtasts": {
        "why": "MTA-STS forces sending servers to use validated TLS to your mail "
               "servers, preventing downgrade and man-in-the-middle interception.",
        "effort": "Medium",
        "steps": [
            "Publish a _mta-sts TXT record (v=STSv1; id=...).",
            "Host the policy file at https://mta-sts.yourdomain/.well-known/mta-sts.txt.",
            "Start with mode=testing, then move to mode=enforce.",
        ],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc8461"],
    },
    "email.no_tlsrpt": {
        "why": "TLS-RPT gives you reports when inbound TLS to your mail servers "
               "fails, so you can catch delivery/interception problems.",
        "effort": "Low",
        "steps": ["Add a _smtp._tls TXT record (v=TLSRPTv1; rua=mailto:...)."],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc8460"],
    },
    # --- Email header analyzer ---------------------------------------------
    "hdr.spf_fail": {
        "why": "SPF failed for this message: the sending server is not authorised "
               "in the From domain's SPF record — a common sign of spoofing.",
        "effort": "Low",
        "steps": [
            "If the mail is legitimate, add the sending server to the SPF record.",
            "If not, treat the message as spoofed / phishing.",
        ],
        "refs": [],
    },
    "hdr.dkim_fail": {
        "why": "DKIM did not verify: the message may have been altered in transit "
               "or was not signed by the claimed domain.",
        "effort": "Low",
        "steps": [
            "Confirm the sender signs with DKIM and the key is published.",
            "A fail on mail you did not send is a spoofing indicator.",
        ],
        "refs": [],
    },
    "hdr.dmarc_fail": {
        "why": "DMARC failed: the message did not pass aligned SPF or DKIM, so it "
               "fails the domain owner's authentication policy.",
        "effort": "Low",
        "steps": ["Treat as unauthenticated; likely spoofed unless you know the source."],
        "refs": [],
    },
    "hdr.from_returnpath_mismatch": {
        "why": "The visible From domain differs from the Return-Path (envelope "
               "sender). Legitimate bulk mail sometimes does this, but it is also "
               "a classic spoofing/phishing pattern.",
        "effort": "Low",
        "steps": [
            "Verify the sender is who they claim to be before trusting the message.",
            "Check that SPF/DKIM/DMARC pass for the From domain.",
        ],
        "refs": [],
    },
    "hdr.no_auth_results": {
        "why": "No Authentication-Results header was found, so the receiving "
               "server did not record SPF/DKIM/DMARC verification — you cannot "
               "confirm the sender.",
        "effort": "Low",
        "steps": ["Obtain full headers including the receiver's Authentication-Results."],
        "refs": [],
    },
    "hdr.reply_to_mismatch": {
        "why": "Reply-To points to a different domain than From, which is often "
               "used in phishing to redirect replies to an attacker.",
        "effort": "Low",
        "steps": ["Confirm the Reply-To address is expected before replying."],
        "refs": [],
    },
    # --- URL check ----------------------------------------------------------
    "url.dangerous_scheme": {
        "why": "javascript: and data: URLs run code or load content directly in "
               "your browser rather than pointing at a web page — a common way to "
               "deliver malicious scripts or fake login screens.",
        "effort": "Low",
        "steps": [
            "Never open this link.",
            "If it came by email or chat, report it and delete it.",
        ],
        "refs": [],
    },
    "url.no_host": {
        "why": "The link has no real hostname, so there is nothing legitimate to "
               "navigate to — often a sign of a malformed or obfuscated URL.",
        "effort": "Low",
        "steps": ["Do not open the link; confirm the real address with the sender."],
        "refs": [],
    },
    "url.no_https": {
        "why": "A link over plain HTTP sends everything in clear text and can be "
               "modified in transit; legitimate sites that handle logins use HTTPS.",
        "effort": "Low",
        "steps": [
            "Prefer the https:// version of the address.",
            "Never enter passwords or card details on an HTTP page.",
        ],
        "refs": [],
    },
    "url.userinfo": {
        "why": "An '@' before the host lets attackers put a trusted-looking name in "
               "front while the real destination is whatever follows the @ — a "
               "classic deception (e.g. paypal.com@evil.tld).",
        "effort": "Low",
        "steps": [
            "Read the host as whatever comes AFTER the last '@'.",
            "Treat the link as deceptive and do not open it.",
        ],
        "refs": [],
    },
    "url.ip_host": {
        "why": "Legitimate services almost always use a domain name. A raw IP in a "
               "link is frequently used to dodge domain-reputation checks.",
        "effort": "Low",
        "steps": ["Verify why a bare IP is used; be wary of entering any data."],
        "refs": [],
    },
    "url.punycode": {
        "why": "Punycode (xn--) hosts can render as look-alike domains using "
               "non-Latin characters that imitate a real brand (homograph attack).",
        "effort": "Low",
        "steps": [
            "Inspect the decoded domain carefully for look-alike characters.",
            "Navigate to the brand's known address manually instead.",
        ],
        "refs": [],
    },
    "url.many_subdomains": {
        "why": "A long chain of subdomains is often used to bury a trusted brand "
               "name on the left while the real registered domain is something else.",
        "effort": "Low",
        "steps": ["Identify the registered domain (the last two labels) and judge that."],
        "refs": [],
    },
    "url.shortener": {
        "why": "A shortener hides the true destination until you click, so you "
               "cannot see where it really leads.",
        "effort": "Low",
        "steps": [
            "Expand the link first (e.g. append '+' on bit.ly, or use an unshortener).",
            "Only follow shortened links from senders you trust.",
        ],
        "refs": [],
    },
    "url.risky_tld": {
        "why": "Some top-level domains are cheap and lightly policed, so they are "
               "over-represented in phishing and malware campaigns.",
        "effort": "Low",
        "steps": ["Apply extra scrutiny; confirm the brand really uses this domain."],
        "refs": [],
    },
    "url.odd_port": {
        "why": "A non-standard port can indicate a service deliberately placed off "
               "the usual web ports to avoid scrutiny.",
        "effort": "Low",
        "steps": ["Confirm the service and port are expected before connecting."],
        "refs": [],
    },
    "url.phish_words": {
        "why": "Words like login/verify/secure/account in the URL are heavily used "
               "in phishing to make a malicious page feel official.",
        "effort": "Low",
        "steps": [
            "Reach the service by typing its known address, not via this link.",
            "Never enter credentials on a page you arrived at from a link.",
        ],
        "refs": [],
    },
    "url.long": {
        "why": "Excessively long URLs are used to push the real domain out of view "
               "and pack in redirects or tracking that hide the destination.",
        "effort": "Low",
        "steps": ["Inspect the registered domain; treat very long links with caution."],
        "refs": [],
    },
    "url.no_resolve": {
        "why": "The host does not currently resolve in DNS — it may be dead, "
               "newly-registered, or deliberately transient (common for scams).",
        "effort": "Low",
        "steps": ["Do not rely on the link; verify the address independently."],
        "refs": [],
    },
    "url.cross_redirect": {
        "why": "The link silently redirects to a different domain than the one "
               "shown, a frequent technique for disguising the true destination.",
        "effort": "Low",
        "steps": [
            "Judge the link by the FINAL domain, not the one you were shown.",
            "If the final domain is unexpected, do not trust the page.",
        ],
        "refs": [],
    },
    "url.downgrade": {
        "why": "Being redirected from HTTPS to HTTP drops encryption, exposing "
               "anything you send and enabling tampering.",
        "effort": "Low",
        "steps": ["Do not submit any data; the connection is no longer encrypted."],
        "refs": [],
    },
    # --- Reputation (multi-engine) -----------------------------------------
    "rep.flagged": {
        "why": "One or more threat-intelligence engines have this domain/URL on a "
               "blocklist for malware, phishing, or abuse.",
        "effort": "Low",
        "steps": [
            "Treat the destination as unsafe until proven otherwise.",
            "If this is your own domain, investigate for compromise and request "
            "delisting from the engines that flagged it.",
        ],
        "refs": [],
    },
    # --- Technology ---------------------------------------------------------
    "tech.wp_version": {
        "why": "Exposing the exact WordPress version helps attackers match it to "
               "known vulnerabilities.",
        "effort": "Low",
        "steps": [
            "Remove the generator meta tag (via theme or a security plugin).",
            "Keep WordPress, themes and plugins updated regardless.",
        ],
        "refs": [],
    },
}

# Rough remediation ordering weight per severity (higher = do first).
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def plan_for(finding: Finding) -> Dict[str, Any]:
    """Return a full remediation entry for one finding.

    Falls back gracefully to the finding's own recommendation when the code is
    not in the catalog (e.g. a new check added before its remediation text).
    """
    entry = CATALOG.get(finding.code, {})
    return {
        "severity": finding.severity.value,
        "title": finding.title,
        "module": finding.module,
        "why": entry.get("why", ""),
        "effort": entry.get("effort", "—"),
        "steps": entry.get("steps") or ([finding.recommendation] if finding.recommendation else []),
        "refs": entry.get("refs", []),
        "evidence": finding.evidence,
    }


def build_plan(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Return remediation entries ordered by severity, then module."""
    ordered = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f.severity.value, 9), f.module, f.title),
    )
    plan = []
    for i, f in enumerate(ordered, start=1):
        entry = plan_for(f)
        entry["priority"] = i
        plan.append(entry)
    return plan
