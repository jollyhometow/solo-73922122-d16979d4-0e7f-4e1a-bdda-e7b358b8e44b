"""SSRF-hardened report fetcher.

The fetcher downloads a support-supplied URL on behalf of a portal support
operator, while keeping the download primitive from being turned into an
internal-network probe.  The security rules, enforced on the INITIAL url and
on EVERY redirect target, are:

1. Only plain ``http`` URLs are accepted (no ``https``, ``file``, ``gopher``
   ...).  A URL carrying userinfo (``user[:pass]@host``) is rejected.
2. Hosts must be IPv4 literals or names that resolve through the *configured*
   DNS servers (``EGRESS_DNS_SERVERS``) to IPv4 (A) records.  IPv6 is refused.
   ALL resolved addresses must fall inside an ``EGRESS_ALLOWED_CIDRS`` entry
   and the port must be in ``EGRESS_ALLOWED_PORTS``; one out-of-range address
   rejects the whole request.
3. The actual TCP connection is opened to one of the addresses that just
   passed the check, while the original host name is retained in the
   ``Host`` header.  The name is NEVER handed to the HTTP client / OS
   resolver again, so a DNS answer that changes between the check and the
   connect (rebinding) cannot steer the connection: the second resolution
   happens on the next redirect hop and is fully re-validated.
4. At most ``EGRESS_MAX_REDIRECTS`` (3) redirects are followed.  Each target
   goes through the full scheme/userinfo/DNS/CIDR/port check again.
5. A single wall-clock budget (``EGRESS_TOTAL_TIMEOUT`` = 5 s) covers every
   hop, including DNS.  The response body is capped at
   ``EGRESS_MAX_BODY_BYTES`` (1 MiB of *decompressed* bytes).
6. No portal credentials or cookies are sent upstream; each hop gets a fresh
   HTTP client with no cookie jar and no proxy/ambient environment, so
   nothing is shared across requests.

On any failure the caller returns an error response only; a partially read
body is discarded and never forwarded.
"""

from __future__ import annotations

import ipaddress
import time
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx

from . import config


class EgressPolicyError(Exception):
    """The requested destination violates the fixed egress policy (HTTP 400)."""

    status_code = 400


class UpstreamFetchError(Exception):
    """The policy allowed the destination but the fetch failed (502 / 504)."""

    def __init__(self, detail: str, *, status_code: int = 502):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


# Nameservers come exclusively from the fixed startup configuration; a fresh
# Resolver is built per lookup (see _resolve_a) so per-call timeouts never
# race across concurrent portal requests.  dnspython opens its query socket
# per resolve() call, so these short-lived objects hold no persistent state.
_NAMESERVERS = tuple(config.EGRESS_DNS_SERVERS)
_DNS_PORT = config.EGRESS_DNS_PORT

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = "portal-report-fetcher/1.0"


def _address_allowed(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in config.EGRESS_ALLOWED_CIDRS)


def _resolve_a(hostname: str, remaining: float) -> list[ipaddress.IPv4Address]:
    """Resolve A records via the configured DNS servers only.

    Every hop re-runs this, so a name whose answers change over time is
    re-validated on every use.  The returned addresses are unordered as far
    as the policy goes: callers must validate ALL of them.
    """
    if remaining <= 0:
        raise UpstreamFetchError("total time budget exhausted during DNS resolution", status_code=504)
    # Independent resolver per lookup: per-hop timeout values live on this
    # object and therefore cannot be overwritten by a concurrent request.
    # configure=False keeps the host's /etc/resolv.conf out of the picture.
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(_NAMESERVERS)
    resolver.port = _DNS_PORT
    resolver.timeout = min(1.0, max(0.05, remaining / 2))
    resolver.lifetime = remaining
    try:
        answer = resolver.resolve(hostname, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
        raise UpstreamFetchError(f"DNS resolution for {hostname!r} returned no IPv4 address: {exc}") from exc
    except dns.exception.Timeout as exc:
        raise UpstreamFetchError(f"DNS resolution for {hostname!r} timed out", status_code=504) from exc

    addresses: list[ipaddress.IPv4Address] = []
    for rdata in answer:
        # Only A records were requested; ip_address rejects anything odd.
        addresses.append(ipaddress.IPv4Address(rdata.address))
    if not addresses:
        raise UpstreamFetchError(f"DNS resolution for {hostname!r} returned no IPv4 address")
    return addresses


def authorize_url(url: str, remaining: float) -> tuple[str, list[ipaddress.IPv4Address], int, str]:
    """Validate one hop URL and return (pinned host header, addresses, port, path+query).

    Raises EgressPolicyError for every policy violation.  ALL resolved
    addresses are checked against the allow list before any of them may be
    used for a connection.
    """
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise EgressPolicyError(f"malformed URL: {exc}") from exc

    if parsed.scheme != "http":
        raise EgressPolicyError(
            f"only plain http:// URLs are supported (got scheme {parsed.scheme!r})"
        )
    # userinfo would otherwise be silently stripped and could carry portal
    # data or confuse log parsing; refuse it outright.
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        raise EgressPolicyError("URLs with user information (userinfo) are not allowed")
    if not parsed.hostname:
        raise EgressPolicyError("URL has no host component")

    hostname = parsed.hostname.lower()
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EgressPolicyError("non-ASCII host names (IDN) are not supported") from exc

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        addresses = _resolve_a(hostname, remaining)
    else:
        if literal.version != 4:
            raise EgressPolicyError("only IPv4 addresses are supported")
        addresses = [literal]

    try:
        port = parsed.port
    except ValueError as exc:
        raise EgressPolicyError(f"invalid port in URL: {exc}") from exc
    if port is None:
        port = 80
    if port not in config.EGRESS_ALLOWED_PORTS:
        raise EgressPolicyError(
            f"port {port} is not in the allowed egress ports: "
            f"{sorted(config.EGRESS_ALLOWED_PORTS)}"
        )

    blocked = sorted(str(addr) for addr in addresses if not _address_allowed(addr))
    if blocked:
        raise EgressPolicyError(
            f"resolved address(es) {blocked} are outside the allowed egress CIDRs "
            f"{[str(n) for n in config.EGRESS_ALLOWED_CIDRS]}; request refused"
        )

    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    # Preserve the original host name for the upstream Host header (no
    # re-resolution happens downstream of this point).
    host_header = hostname if port == 80 else f"{hostname}:{port}"
    return host_header, addresses, port, target


def _read_limited(response: httpx.Response, deadline: float) -> bytes:
    """Read a full body, aborting past the size or time budget.

    iter_bytes yields *decompressed* content, so a compressed response that
    expands past 1 MiB is caught too.  On abort the connection is closed and
    whatever was buffered is discarded (never returned to the caller).
    """
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_bytes(64 * 1024):
            total += len(chunk)
            if total > config.EGRESS_MAX_BODY_BYTES:
                raise UpstreamFetchError(
                    f"report body exceeds the {config.EGRESS_MAX_BODY_BYTES} byte limit"
                )
            if time.monotonic() > deadline:
                raise UpstreamFetchError("total time budget exhausted while reading body", status_code=504)
            chunks.append(chunk)
    finally:
        # On abort the connection is closed and whatever was buffered here is
        # discarded (never returned to the caller).
        response.close()
    return b"".join(chunks)


def _open_pinned(
    host_header: str,
    addresses: list[ipaddress.IPv4Address],
    port: int,
    target: str,
    deadline: float,
) -> tuple[httpx.Client, httpx.Response]:
    """Open one GET to an already-authorized address, keeping the Host name.

    A fresh client per hop means: no cookie jar, no redirect following, no
    ambient proxy settings (trust_env) and no headers inherited from the
    portal request.  Only addresses from THIS authorization are tried.  The
    client is returned alongside the streamed response: the caller owns it
    and must close it after the body is consumed (or on any error), since
    closing the client early invalidates the response stream.
    """
    last_error: Exception | None = None
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        pinned_url = f"http://{address}:{port}{target}"
        client = httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(remaining),
        )
        request = client.build_request(
            "GET",
            pinned_url,
            headers={"Host": host_header, "User-Agent": _USER_AGENT},
        )
        try:
            response = client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            client.close()
            # A timeout consumes the whole remaining budget anyway.
            raise UpstreamFetchError(f"connection to {address} timed out", status_code=504) from exc
        except httpx.HTTPError as exc:
            client.close()
            last_error = exc
            continue
        return client, response
    raise UpstreamFetchError(f"could not connect to any approved address: {last_error}")


def _attachment_filename(url: str) -> str:
    path_name = PurePosixPath(urlsplit(url).path).name
    # Keep the name simple and header-safe; fall back to a generic name.
    cleaned = "".join(ch for ch in path_name if ch.isalnum() or ch in ".-_").strip(".")
    return cleaned or "report.bin"


def download(url: str) -> tuple[bytes, str, str]:
    """Fetch ``url`` under the full egress policy.

    Returns ``(body, content_type, filename)``.  Raises EgressPolicyError /
    UpstreamFetchError on any failure; partial bodies are never returned.
    """
    deadline = time.monotonic() + config.EGRESS_TOTAL_TIMEOUT
    current_url = url

    for hop in range(config.EGRESS_MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpstreamFetchError("total time budget exhausted", status_code=504)

        host_header, addresses, port, target = authorize_url(current_url, remaining)
        # Fresh client (and therefore fresh cookie-less connection state) for
        # every single hop, including redirects.
        client, response = _open_pinned(host_header, addresses, port, target, deadline)
        try:
            if response.status_code in _REDIRECT_STATUSES:
                if hop >= config.EGRESS_MAX_REDIRECTS:
                    raise EgressPolicyError(
                        f"more than {config.EGRESS_MAX_REDIRECTS} redirects; refusing to follow"
                    )
                location = response.headers.get("location")
                if not location:
                    raise UpstreamFetchError(
                        f"redirect response {response.status_code} without a Location header"
                    )
                # Join against the current URL so relative redirects resolve
                # against the hop that produced them; re-validated next loop.
                current_url = urljoin(current_url, location)
                continue

            if not 200 <= response.status_code < 300:
                raise UpstreamFetchError(
                    f"upstream returned unsupported status {response.status_code}"
                )
            body = _read_limited(response, deadline)
        finally:
            # Release the streamed response AND its client on every path
            # (success, redirect, error). _read_limited already closes the
            # response on success; close() is idempotent.
            response.close()
            client.close()

        content_type = response.headers.get("content-type", "application/octet-stream")
        return body, content_type, _attachment_filename(url)

    # Unreachable: the redirect limit is enforced inside the loop.
    raise EgressPolicyError("redirect limit exceeded")
