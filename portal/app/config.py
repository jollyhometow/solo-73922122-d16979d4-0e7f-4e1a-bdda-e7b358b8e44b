"""Static configuration for the portal API.

Everything security-relevant (IdP public key, issuer, audience, and the
report-download egress policy) is fixed configuration supplied via
environment variables / mounted files.  There is no dynamic key discovery
and no runtime-settable egress policy: the allowed destination CIDRs,
ports and DNS servers are all read once at process start.
"""

import ipaddress
import os
from pathlib import Path

# --- Fixed trust configuration -------------------------------------------------
ISSUER = os.getenv("IDP_ISSUER", "enterprise-idp")
AUDIENCE = os.getenv("IDP_AUDIENCE", "enterprise-portal")
PUBLIC_KEY_PATH = os.getenv("IDP_PUBLIC_KEY_PATH", "/keys/idp_public.pem")

# --- Attached local identity source --------------------------------------------
TOKEN_URL = os.getenv("IDP_TOKEN_URL", "http://localhost:9000/token")
# The token exchange may legitimately be slow (this is the "late login
# response" scenario), so the HTTP timeout must be generous.  No database
# lock is held while waiting (see app/main.py).
TOKEN_EXCHANGE_TIMEOUT = float(os.getenv("IDP_TOKEN_EXCHANGE_TIMEOUT", "75"))

# --- Local state ---------------------------------------------------------------
DB_PATH = os.getenv("PORTAL_DB_PATH", "/data/portal.db")

# Tolerated clock skew (seconds) when validating exp/iat.
CLOCK_LEEWAY = int(os.getenv("TOKEN_CLOCK_LEEWAY", "30"))

# --- Report download egress policy (fixed at startup) --------------------------
# Every URL the fetcher touches (the initial URL and every redirect target)
# must satisfy ALL of:
#   * plain http:// scheme and no userinfo component;
#   * host is an IPv4 literal or resolves (via the configured DNS servers
#     only) to IPv4 addresses, and EVERY resolved address is inside one of
#     EGRESS_ALLOWED_CIDRS;
#   * the explicit/default port is in EGRESS_ALLOWED_PORTS.
# The actual TCP connection is opened to an address that passed this check;
# the hostname is never re-resolved for the connection (no DNS rebinding
# window).  Nothing here is configurable per request.


def _parse_cidrs(raw: str) -> list[ipaddress.IPv4Network]:
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        network = ipaddress.ip_network(item, strict=False)
        if network.version != 4:
            raise ValueError(f"only IPv4 CIDRs are allowed in EGRESS_ALLOWED_CIDRS: {item}")
        networks.append(network)
    if not networks:
        raise ValueError("EGRESS_ALLOWED_CIDRS must contain at least one IPv4 CIDR")
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique = []
    for network in networks:
        key = str(network)
        if key not in seen:
            seen.add(key)
            unique.append(network)
    return unique


def _parse_ports(raw: str) -> frozenset[int]:
    ports = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in EGRESS_ALLOWED_PORTS: {port}")
        ports.add(port)
    if not ports:
        raise ValueError("EGRESS_ALLOWED_PORTS must contain at least one port")
    return frozenset(ports)


def _parse_dns_servers(raw: str) -> tuple[str, ...]:
    servers = tuple(item.strip() for item in raw.split(",") if item.strip())
    for item in servers:
        address = ipaddress.ip_address(item)
        if address.version != 4:
            raise ValueError(f"only IPv4 DNS servers are allowed in EGRESS_DNS_SERVERS: {item}")
    if not servers:
        raise ValueError("EGRESS_DNS_SERVERS must contain at least one IPv4 DNS server")
    return servers


EGRESS_ALLOWED_CIDRS = _parse_cidrs(
    os.getenv("EGRESS_ALLOWED_CIDRS", "172.31.10.0/24")
)
EGRESS_ALLOWED_PORTS = _parse_ports(os.getenv("EGRESS_ALLOWED_PORTS", "80,8080"))
EGRESS_DNS_SERVERS = _parse_dns_servers(
    os.getenv("EGRESS_DNS_SERVERS", "172.31.10.53")
)
EGRESS_DNS_PORT = int(os.getenv("EGRESS_DNS_PORT", "53"))
EGRESS_MAX_REDIRECTS = int(os.getenv("EGRESS_MAX_REDIRECTS", "3"))
EGRESS_TOTAL_TIMEOUT = float(os.getenv("EGRESS_TOTAL_TIMEOUT", "5"))
EGRESS_MAX_BODY_BYTES = int(os.getenv("EGRESS_MAX_BODY_BYTES", 1024 * 1024))  # 1 MiB

PUBLIC_KEY = Path(PUBLIC_KEY_PATH).read_text(encoding="utf-8")
