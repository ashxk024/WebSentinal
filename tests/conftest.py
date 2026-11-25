"""Shared test fixtures: deterministic DNS so tests never touch the network."""
import socket

import pytest

DNS_TABLE = {
    "example.com": ["93.184.216.34"],
    "www.example.com": ["93.184.216.34"],
    "other.org": ["8.8.8.8"],
    "internal.example.com": ["10.0.0.5"],
    "mixed.example.com": ["93.184.216.34", "192.168.1.10"],
    "metadata-alias.example.com": ["169.254.169.254"],
    "v6only.example.com": ["2606:4700:4700::1111"],
}


@pytest.fixture
def fake_dns(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host in DNS_TABLE:
            results = []
            for ip in DNS_TABLE[host]:
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                results.append((family, socket.SOCK_STREAM, 6, "", (ip, 0)))
            return results
        # Numeric forms such as 2130706433 resolve locally without DNS.
        if host.replace(".", "").isdigit():
            return real_getaddrinfo(host, *args, **kwargs)
        raise socket.gaierror("name not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
