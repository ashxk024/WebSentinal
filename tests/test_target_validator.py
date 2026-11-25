"""Unit tests for scanner.target_validator."""
import ipaddress

import pytest
import requests

from scanner import target_validator as tv
from scanner.target_validator import (
    TargetPolicy,
    TargetValidationError,
    check_connectivity,
    normalize_url,
    validate_target,
)

POLICY = TargetPolicy(request_delay=0)


# ---------------------------------------------------------------- normalize
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "https://example.com/"),
        ("  Example.COM  ", "https://example.com/"),
        ("http://example.com:80/a?b=1#frag", "http://example.com/a?b=1"),
        ("https://example.com:443", "https://example.com/"),
        ("example.com:8080", "https://example.com:8080/"),
        ("https://example.com./", "https://example.com/"),
        ("http://[2606:4700:4700::1111]/", "http://[2606:4700:4700::1111]/"),
    ],
)
def test_normalize_accepts_and_canonicalises(raw, expected):
    assert normalize_url(raw, POLICY) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pass@example.com",
        "https://user@example.com",
        "https://exa mple.com",
        "https://example.com/\r\nHost: evil",
        "https://example.com:22",
        "https://example.com:99999",
        "https://-bad.example.com",
        "https://bad..example.com",
        "https:///path-only",
        "a" * 2100,
        None,
        123,
    ],
)
def test_normalize_rejects_bad_input(raw):
    with pytest.raises(TargetValidationError):
        normalize_url(raw, POLICY)


# ------------------------------------------------------------------ is_public_ip
@pytest.mark.parametrize(
    "address", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"]
)
def test_public_addresses_allowed(address):
    assert tv.is_public_ip(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254",
        "169.254.170.2", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1",
        "fc00::1", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        "64:ff9b::7f00:1", "2002:7f00:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_non_public_addresses_blocked(address):
    assert not tv.is_public_ip(ipaddress.ip_address(address))


# ------------------------------------------------------------- validate_target
def test_valid_target(fake_dns):
    result = validate_target("https://example.com", True, POLICY)
    assert result.valid
    assert result.url == "https://example.com/"
    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.resolved_ips == ["93.184.216.34"]


def test_valid_ipv6_only_target(fake_dns):
    assert validate_target("v6only.example.com", True, POLICY).valid


@pytest.mark.parametrize("flag", [False, None, "true", 1])
def test_authorization_must_be_explicit_true(fake_dns, flag):
    result = validate_target("https://example.com", flag, POLICY)
    assert not result.valid
    assert "Authorization" in result.error


def test_allowlist_permits_listed_host_and_subdomains(fake_dns):
    policy = TargetPolicy(request_delay=0, allowed_targets=("example.com",))
    assert validate_target("https://example.com", True, policy).valid
    assert validate_target("https://www.example.com", True, policy).valid
    blocked = validate_target("https://other.org", True, policy)
    assert not blocked.valid
    assert "authorized targets" in blocked.error


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://app.localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://10.1.2.3",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal",
        "http://2130706433",  # decimal form of 127.0.0.1
        "https://internal.example.com",
        "https://mixed.example.com",  # one public + one private record
        "https://metadata-alias.example.com",
    ],
)
def test_internal_targets_blocked(fake_dns, url):
    result = validate_target(url, True, POLICY)
    assert not result.valid
    assert result.error


def test_unresolvable_host_rejected(fake_dns):
    result = validate_target("https://does-not-exist.example", True, POLICY)
    assert not result.valid
    assert "resolve" in result.error


# -------------------------------------------------------------- connectivity
class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    """Routes: url -> FakeResponse | Exception | callable(method, kwargs)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self.routes[url]
        if callable(outcome):
            outcome = outcome(method, kwargs)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def redirect(to, status=301):
    return FakeResponse(status, {"Location": to})


def test_connectivity_success(fake_dns):
    session = FakeSession({"https://example.com/": FakeResponse(200)})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert result.reachable and result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert not result.tls_verification_failed
    assert session.calls[0][0] == "HEAD"
    assert session.calls[0][2]["allow_redirects"] is False


def test_http_error_status_still_counts_as_reachable(fake_dns):
    session = FakeSession({"https://example.com/": FakeResponse(403)})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert result.reachable and result.status_code == 403


def test_follows_same_site_redirects(fake_dns):
    session = FakeSession(
        {
            "http://example.com/": redirect("https://example.com/"),
            "https://example.com/": redirect("https://www.example.com/home"),
            "https://www.example.com/home": FakeResponse(200),
        }
    )
    result = check_connectivity("http://example.com/", POLICY, session)
    assert result.reachable
    assert result.redirect_chain == [
        "http://example.com/",
        "https://example.com/",
        "https://www.example.com/home",
    ]


def test_redirect_to_private_address_blocked(fake_dns):
    session = FakeSession({"https://example.com/": redirect("http://169.254.169.254/latest/")})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert not result.reachable
    assert "Redirect blocked" in result.error
    assert len(session.calls) == 1  # the internal URL was never requested


def test_redirect_to_other_host_blocked_by_default(fake_dns):
    session = FakeSession({"https://example.com/": redirect("https://other.org/")})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert not result.reachable
    assert "different host" in result.error


def test_cross_host_redirect_allowed_when_policy_permits(fake_dns):
    policy = TargetPolicy(request_delay=0, allow_cross_host_redirects=True)
    session = FakeSession(
        {"https://example.com/": redirect("https://other.org/"), "https://other.org/": FakeResponse(200)}
    )
    assert check_connectivity("https://example.com/", policy, session).reachable


def test_redirect_loop_stops_at_limit(fake_dns):
    session = FakeSession({"https://example.com/": redirect("https://example.com/")})
    policy = TargetPolicy(request_delay=0, max_redirects=3)
    result = check_connectivity("https://example.com/", policy, session)
    assert not result.reachable
    assert "Too many redirects" in result.error
    assert len(session.calls) == 4


def test_head_not_allowed_falls_back_to_get(fake_dns):
    def handler(method, kwargs):
        return FakeResponse(405 if method == "HEAD" else 200)

    session = FakeSession({"https://example.com/": handler})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert result.reachable and result.status_code == 200
    assert [call[0] for call in session.calls] == ["HEAD", "GET"]


def test_invalid_certificate_is_recorded_not_fatal(fake_dns):
    def handler(method, kwargs):
        if kwargs["verify"]:
            return requests.exceptions.SSLError("bad cert")
        return FakeResponse(200)

    session = FakeSession({"https://example.com/": handler})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert result.reachable
    assert result.tls_verification_failed


@pytest.mark.parametrize(
    "exc, fragment",
    [
        (requests.exceptions.Timeout(), "timed out"),
        (requests.exceptions.ConnectionError(), "Could not connect"),
    ],
)
def test_network_errors_reported_without_details(fake_dns, exc, fragment):
    session = FakeSession({"https://example.com/": exc})
    result = check_connectivity("https://example.com/", POLICY, session)
    assert not result.reachable
    assert fragment in result.error
