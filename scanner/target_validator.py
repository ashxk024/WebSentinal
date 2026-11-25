"""Target validation for WebSentinel.

Responsibilities:
    * Normalise and validate user-supplied URLs.
    * Require explicit authorization (and optionally enforce an allowlist).
    * Block SSRF: localhost, private ranges, link-local and cloud metadata hosts.
    * Verify connectivity while validating every redirect hop.

Known limitation: the hostname is resolved here and again by ``requests`` when
the connection is made, so a DNS-rebinding attack is not fully closed in this
stage. Later stages route all scanner traffic through one shared safe session.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import socket
import sys
import time
import warnings
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, SSLError, Timeout
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_CODES = (301, 302, 303, 307, 308)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED_HOSTNAMES = {"metadata.google.internal", "metadata", "instance-data"}
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS / GCP / Azure / most clouds
    ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 metadata
}
_NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")


class TargetValidationError(ValueError):
    """Raised when a target URL fails validation."""


@dataclass(frozen=True)
class TargetPolicy:
    """Rules that decide which targets may be scanned and how we connect."""

    allowed_ports: tuple = (80, 443, 8080, 8443)
    allowed_targets: tuple = ()
    max_url_length: int = 2048
    timeout: float = 10.0
    request_delay: float = 0.5
    max_redirects: int = 5
    user_agent: str = "WebSentinel/0.1"
    allow_cross_host_redirects: bool = False

    @classmethod
    def from_config(cls, config=None) -> "TargetPolicy":
        """Build a policy from the application ``Config`` class."""
        if config is None:
            from config import Config as config
        return cls(
            allowed_ports=tuple(config.ALLOWED_PORTS),
            allowed_targets=tuple(config.ALLOWED_TARGETS),
            max_url_length=config.MAX_URL_LENGTH,
            timeout=config.REQUEST_TIMEOUT,
            request_delay=config.REQUEST_DELAY,
            max_redirects=config.MAX_REDIRECTS,
            user_agent=config.USER_AGENT,
            allow_cross_host_redirects=config.ALLOW_CROSS_HOST_REDIRECTS,
        )


@dataclass
class ValidationResult:
    """Outcome of validating a target URL."""

    valid: bool
    url: Optional[str] = None
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    resolved_ips: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ConnectivityResult:
    """Outcome of a connectivity check."""

    reachable: bool
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    redirect_chain: list = field(default_factory=list)
    tls_verification_failed: bool = False
    response_time_ms: Optional[float] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------
# URL normalisation
# --------------------------------------------------------------------------
def _parse_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def normalize_url(raw_url: str, policy: TargetPolicy) -> str:
    """Return a canonical http(s) URL or raise ``TargetValidationError``.

    A missing scheme defaults to https. Credentials, fragments, control
    characters, unusual ports and malformed hostnames are rejected.
    """
    if not isinstance(raw_url, str):
        raise TargetValidationError("URL must be a string.")
    url = raw_url.strip()
    if not url:
        raise TargetValidationError("URL is empty.")
    if len(url) > policy.max_url_length:
        raise TargetValidationError("URL is too long.")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise TargetValidationError("URL must not contain whitespace or control characters.")
    if "://" not in url:
        url = "https://" + url

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError(f"Malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetValidationError("Only http and https URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise TargetValidationError("URLs containing credentials are not allowed.")
    if not parts.hostname:
        raise TargetValidationError("URL has no hostname.")

    hostname = parts.hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("Hostname is not valid.") from exc

    if _parse_ip(hostname) is None:
        labels = hostname.split(".")
        if len(hostname) > 253 or not all(_LABEL_RE.match(label) for label in labels):
            raise TargetValidationError("Hostname is not valid.")

    effective_port = port or _DEFAULT_PORTS[scheme]
    if effective_port not in policy.allowed_ports:
        raise TargetValidationError(
            f"Port {effective_port} is not allowed. "
            f"Allowed ports: {', '.join(map(str, policy.allowed_ports))}."
        )

    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------
def is_public_ip(ip) -> bool:
    """Return True only for globally routable, non-metadata addresses."""
    if ip in _METADATA_IPS:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is not None:
            return is_public_ip(embedded)
        if ip.teredo is not None:
            return False
        if ip in _NAT64_NETWORK:
            return is_public_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)


def _text_is_public(address: str) -> bool:
    try:
        return is_public_ip(ipaddress.ip_address(address))
    except ValueError:
        return False


def resolve_host(hostname: str) -> list:
    """Resolve a hostname to a sorted list of unique IP strings."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise TargetValidationError(f"Could not resolve hostname '{hostname}'.") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise TargetValidationError(f"Could not resolve hostname '{hostname}'.")
    return addresses


def assert_public_host(hostname: str) -> list:
    """Ensure every address behind ``hostname`` is public; return the addresses."""
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname in _BLOCKED_HOSTNAMES
    ):
        raise TargetValidationError("Scanning local or metadata hosts is not permitted.")

    literal = _parse_ip(hostname)
    addresses = [str(literal)] if literal is not None else resolve_host(hostname)

    for address in addresses:
        if not _text_is_public(address):
            raise TargetValidationError(
                f"'{hostname}' resolves to a non-public address ({address}); "
                "scanning internal targets is not permitted."
            )
    return addresses


# --------------------------------------------------------------------------
# Authorization and validation entry points
# --------------------------------------------------------------------------
def _check_allowlist(hostname: str, policy: TargetPolicy) -> None:
    if not policy.allowed_targets:
        return
    if any(hostname == entry or hostname.endswith("." + entry) for entry in policy.allowed_targets):
        return
    raise TargetValidationError(f"'{hostname}' is not in the configured list of authorized targets.")


def validate_destination(raw_url: str, policy: TargetPolicy) -> ValidationResult:
    """Validate URL format, allowlist and SSRF safety (no authorization prompt).

    Used for the initial target and for every redirect hop.
    """
    try:
        url = normalize_url(raw_url, policy)
        parts = urlsplit(url)
        _check_allowlist(parts.hostname, policy)
        addresses = assert_public_host(parts.hostname)
    except TargetValidationError as exc:
        logger.info("Target rejected: %s", exc)
        return ValidationResult(valid=False, error=str(exc))
    return ValidationResult(
        valid=True,
        url=url,
        scheme=parts.scheme,
        hostname=parts.hostname,
        port=parts.port or _DEFAULT_PORTS[parts.scheme],
        resolved_ips=addresses,
    )


def validate_target(
    raw_url: str, authorized: bool, policy: Optional[TargetPolicy] = None
) -> ValidationResult:
    """Validate a user-supplied scan target.

    ``authorized`` must be exactly True: the caller attests that they own the
    target or hold explicit permission to test it. This is an attestation, not
    proof of ownership; use ``ALLOWED_TARGETS`` to hard-limit scanning.
    """
    policy = policy or TargetPolicy.from_config()
    if authorized is not True:
        return ValidationResult(
            valid=False,
            error="Authorization not confirmed: you must own this target or have "
            "explicit permission to test it.",
        )
    return validate_destination(raw_url, policy)


# --------------------------------------------------------------------------
# Connectivity check
# --------------------------------------------------------------------------
def _same_site(host_a: str, host_b: str) -> bool:
    strip = lambda h: h[4:] if h.startswith("www.") else h  # noqa: E731
    return strip(host_a) == strip(host_b)


def _fetch(session, url: str, policy: TargetPolicy, verify: bool):
    """Send HEAD (falling back to GET) without following redirects or reading the body."""
    kwargs = {
        "headers": {"User-Agent": policy.user_agent, "Accept": "*/*"},
        "timeout": policy.timeout,
        "allow_redirects": False,
        "stream": True,
        "verify": verify,
    }
    with warnings.catch_warnings():
        if not verify:
            warnings.simplefilter("ignore", InsecureRequestWarning)
        response = session.request("HEAD", url, **kwargs)
        if response.status_code in (405, 501):
            response.close()
            time.sleep(policy.request_delay)
            response = session.request("GET", url, **kwargs)
    return response


def _describe_error(exc: Exception, policy: TargetPolicy) -> str:
    if isinstance(exc, Timeout):
        return f"Connection timed out after {policy.timeout:g}s."
    if isinstance(exc, SSLError):
        return "TLS handshake failed."
    if isinstance(exc, RequestsConnectionError):
        return "Could not connect to the target."
    return f"Request failed ({type(exc).__name__})."


def check_connectivity(
    start_url: str, policy: Optional[TargetPolicy] = None, session=None
) -> ConnectivityResult:
    """Check that ``start_url`` answers over HTTP(S).

    Any HTTP response (including 4xx/5xx) counts as reachable. Redirects are
    followed manually; each hop is re-validated against the SSRF rules and the
    allowlist, and cross-host redirects are refused unless the policy allows
    them. A certificate failure is recorded rather than treated as
    unreachable, so the Stage 3 analyzer can report it.
    """
    policy = policy or TargetPolicy.from_config()
    session = session or requests.Session()

    current = start_url
    origin_host = urlsplit(start_url).hostname or ""
    chain = [current]
    verify = True
    tls_failed = False
    started = time.perf_counter()

    def finish(reachable: bool, status=None, error=None) -> ConnectivityResult:
        return ConnectivityResult(
            reachable=reachable,
            final_url=current if reachable else None,
            status_code=status,
            redirect_chain=list(chain),
            tls_verification_failed=tls_failed,
            response_time_ms=round((time.perf_counter() - started) * 1000, 1),
            error=error,
        )

    for hop in range(policy.max_redirects + 1):
        try:
            try:
                response = _fetch(session, current, policy, verify)
            except SSLError:
                if not verify:
                    raise
                logger.warning("TLS verification failed for %s; retrying without verification", current)
                verify, tls_failed = False, True
                response = _fetch(session, current, policy, verify)
        except RequestException as exc:
            logger.info("Connectivity check failed: %s", type(exc).__name__)
            return finish(False, error=_describe_error(exc, policy))

        status = response.status_code
        location = response.headers.get("Location")
        response.close()

        if status in _REDIRECT_CODES and location:
            if hop >= policy.max_redirects:
                return finish(False, status, f"Too many redirects (limit {policy.max_redirects}).")
            check = validate_destination(urljoin(current, location), policy)
            if not check.valid:
                return finish(False, status, f"Redirect blocked: {check.error}")
            if not policy.allow_cross_host_redirects and not _same_site(origin_host, check.hostname):
                return finish(False, status, f"Redirect to a different host ({check.hostname}) blocked.")
            current = check.url
            chain.append(current)
            time.sleep(policy.request_delay)
            continue

        return finish(True, status)

    return finish(False, error="Redirect handling ended unexpectedly.")


# --------------------------------------------------------------------------
# Command line helper:  python -m scanner.target_validator URL --authorized
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scanner.target_validator",
        description="Validate a WebSentinel scan target.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the target or have explicit permission to test it.",
    )
    parser.add_argument("--connect", action="store_true", help="Also run the connectivity check.")
    args = parser.parse_args(argv)

    policy = TargetPolicy.from_config()
    result = validate_target(args.url, args.authorized, policy)
    output = {"validation": result.to_dict()}
    ok = result.valid
    if result.valid and args.connect:
        connectivity = check_connectivity(result.url, policy)
        output["connectivity"] = asdict(connectivity)
        ok = connectivity.reachable
    print(json.dumps(output, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
