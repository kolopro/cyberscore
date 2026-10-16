"""Global configuration for the security scanner.

All values here are intentionally conservative: v0.1 performs only passive /
non-invasive checks. No aggressive probing, fuzzing or exploitation.
"""

# Network behaviour -----------------------------------------------------------
HTTP_TIMEOUT = 12          # seconds, per request
TLS_TIMEOUT = 10           # seconds, TLS handshake
DNS_TIMEOUT = 6            # seconds, per DNS query
MAX_REDIRECTS = 10
USER_AGENT = (
    "SecurityScanner/0.1 (+passive; non-invasive) "
    "Mozilla/5.0 (compatible)"
)

# Passive mode is the ONLY mode in v0.1. An 'authorized' deeper mode is
# reserved for a later version and is a no-op here.
PASSIVE_ONLY = True

# Security response headers we care about, mapped to a human label and
# whether their absence is HIGH / MEDIUM / LOW severity.
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "MEDIUM"),
    "content-security-policy": ("Content-Security-Policy", "MEDIUM"),
    "x-content-type-options": ("X-Content-Type-Options", "LOW"),
    "x-frame-options": ("X-Frame-Options", "MEDIUM"),
    "referrer-policy": ("Referrer-Policy", "LOW"),
    "permissions-policy": ("Permissions-Policy", "LOW"),
}

# Cookie flags we audit.
COOKIE_FLAGS = ("secure", "httponly", "samesite")

# Certificate expiry warning thresholds (days).
CERT_EXPIRY_CRITICAL = 7
CERT_EXPIRY_WARNING = 21

# Common DKIM selectors we can passively probe via DNS (no email sent).
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "smtp", "s1", "s2", "mandrill", "mailjet",
    "everlytickey1", "everlytickey2", "zoho", "amazonses",
)
