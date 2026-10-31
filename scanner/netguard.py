"""SSRF protection for outbound scanning traffic.

Two layers:

1. A process-wide guard on urllib3's socket creation (``install()``). Once
   installed, every HTTP(S) request made through ``requests`` — the http
   checker, the urlcheck live fetch, the reputation providers — can only
   connect to a PUBLIC IP address. Because the guard runs at connect time on
   the IP it actually dials, it covers redirect chains AND defeats DNS
   rebinding / TOCTOU: there is no window between validating the address and
   using it, and the connection is pinned to the validated IP.

2. Helpers (``is_public_ip``, ``resolve_host``, ``host_is_public``) for the
   user-facing "is this target internal?" reporting and for guarding the
   Playwright/Chromium screenshot, which runs in a separate process that the
   socket guard cannot reach.

Blocked ranges (IPv4 + IPv6): loopback, private (RFC1918 / ``fc00::/7``),
link-local (``169.254/16`` incl. the cloud metadata address, ``fe80::/10``),
reserved, multicast and unspecified.

The web app installs the guard at import; the CLI does NOT, so a trusted local
operator can still intentionally scan an internal host from the command line.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import List

from urllib3.util import connection as _urllib3_connection


class BlockedAddressError(OSError):
    """Raised when a connection to a non-public address is attempted.

    Subclasses OSError so urllib3 wraps it like any other connection failure,
    surfacing to callers as ``requests.ConnectionError`` (a RequestException),
    which the checkers already handle gracefully.
    """


def is_public_ip(ip: str) -> bool:
    """True if ``ip`` is a routable, non-internal address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def resolve_host(host: str) -> List[str]:
    """Return every IP ``host`` resolves to (empty list on failure)."""
    host = (host or "").strip().strip("[]")
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return [host]  # already a literal IP
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def host_is_public(host: str) -> bool:
    """True only if ``host`` resolves AND every resolved IP is public.

    Requiring *all* resolved addresses to be public means a host that mixes a
    public and an internal answer (a rebinding trick) is rejected outright.
    """
    ips = resolve_host(host)
    return bool(ips) and all(is_public_ip(ip) for ip in ips)


# --- process-wide connect guard --------------------------------------------
_orig_create_connection = _urllib3_connection.create_connection


def _guarded_create_connection(address, *args, **kwargs):
    host, port = address[0], address[1]
    ips = resolve_host(host)
    if not ips:
        # Let the original raise the usual clean DNS error.
        return _orig_create_connection(address, *args, **kwargs)
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise BlockedAddressError(
            f"blocked connection to non-public address: {host} -> {bad[0]}")
    # Pin to the validated IP so there is no second, unchecked DNS lookup.
    return _orig_create_connection((ips[0], port), *args, **kwargs)


_guarded_create_connection._cyberscore_guard = True  # type: ignore[attr-defined]


def install() -> None:
    """Idempotently install the process-wide SSRF connect guard."""
    if getattr(_urllib3_connection.create_connection, "_cyberscore_guard", False):
        return
    _urllib3_connection.create_connection = _guarded_create_connection
