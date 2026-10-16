"""Passive technology fingerprinting from HTML + response headers.

Signature-based only. We fetch the homepage once and look for well-known
markers. No admin paths are probed aggressively; a small set of *public*,
conventional paths (e.g. /robots.txt) may be read.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import requests

from config import settings
from scanner.models import ModuleResult, Severity, Status


def _fetch(url: str) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=settings.HTTP_TIMEOUT,
                            headers={"User-Agent": settings.USER_AGENT})
    except requests.RequestException:
        return None


# Each signature: label -> (compiled regexes over html, header substrings)
_HTML_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r'name="generator"[^>]*WordPress'],
    "WooCommerce": [r"woocommerce", r"wc-ajax", r"/plugins/woocommerce/"],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme", r"myshopify\.com"],
    "Magento": [r"/static/version\d+/frontend/", r"Magento_", r"mage/cookies"],
    "Drupal": [r"/sites/default/files/", r'name="Generator"[^>]*Drupal', r"drupal.js"],
    "Joomla": [r"/media/jui/", r"com_content", r'name="generator"[^>]*Joomla'],
    "React": [r"data-reactroot", r"__NEXT_DATA__", r"/_next/static/"],
    "Vue.js": [r"data-v-[0-9a-f]{8}", r"__vue__", r"vue(?:\.min)?\.js"],
    "Angular": [r"ng-version=", r"ng-app", r"angular(?:\.min)?\.js"],
    "jQuery": [r"jquery(?:\-|\.)[\d.]+(?:\.min)?\.js"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.css"],
    "Google Analytics": [r"www\.google-analytics\.com", r"gtag\(", r"googletagmanager"],
    "Elementor": [r"elementor-frontend", r"/elementor/"],
}

_HEADER_SIGNATURES = {
    "Cloudflare": [("server", "cloudflare"), ("cf-ray", "")],
    "Nginx": [("server", "nginx")],
    "Apache": [("server", "apache")],
    "Microsoft IIS": [("server", "microsoft-iis"), ("server", "iis")],
    "LiteSpeed": [("server", "litespeed")],
    "Fastly": [("x-served-by", "cache"), ("x-fastly", "")],
    "Amazon CloudFront": [("via", "cloudfront"), ("x-amz-cf-id", "")],
    "Akamai": [("server", "akamaighost"), ("x-akamai", "")],
    "Varnish": [("via", "varnish"), ("x-varnish", "")],
    "Vercel": [("server", "vercel"), ("x-vercel-id", "")],
    "PHP": [("x-powered-by", "php")],
    "ASP.NET": [("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
    "Express": [("x-powered-by", "express")],
}


def run(host: str) -> ModuleResult:
    result = ModuleResult(name="technology")

    resp = _fetch(f"https://{host}/") or _fetch(f"http://{host}/")
    if resp is None:
        result.add_check("tech", "Technology detection", Status.INFO,
                         "could not fetch homepage")
        result.error = "No homepage response for fingerprinting."
        return result

    html = resp.text or ""
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    detected: List[str] = []

    for label, patterns in _HTML_SIGNATURES.items():
        if any(re.search(p, html, re.IGNORECASE) for p in patterns):
            detected.append(label)

    for label, sigs in _HEADER_SIGNATURES.items():
        for hkey, needle in sigs:
            val = headers.get(hkey)
            if val is not None and (needle == "" or needle in val):
                detected.append(label)
                break

    # robots.txt is a conventional, public file — safe to read.
    robots = _fetch(f"https://{host}/robots.txt")
    if robots is not None and robots.status_code == 200:
        rt = robots.text.lower()
        if "wp-admin" in rt and "WordPress" not in detected:
            detected.append("WordPress")
        if "/admin" in rt and "Shopify" not in detected and "shopify" in rt:
            detected.append("Shopify")

    # De-duplicate, keep order.
    seen = set()
    ordered = [d for d in detected if not (d in seen or seen.add(d))]
    result.data["detected"] = ordered

    if ordered:
        for tech in ordered:
            result.add_check(tech.lower().replace(" ", "_"), tech, Status.INFO)
    else:
        result.add_check("tech", "Technology detected", Status.INFO,
                         "no known signatures")

    # A couple of low-severity informational findings for exposed CMS.
    if "WordPress" in ordered:
        gen = re.search(r'name="generator"[^>]*WordPress\s*([\d.]+)', html, re.IGNORECASE)
        if gen:
            result.data["wordpress_version"] = gen.group(1)
            result.add_finding(
                Severity.LOW, f"WordPress version exposed ({gen.group(1)})",
                "Remove the generator meta tag to avoid version disclosure.",
                evidence=gen.group(0)[:80],
                code="tech.wp_version",
            )

    return result
