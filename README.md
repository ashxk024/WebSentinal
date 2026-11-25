# WebSentinel

Automated web application security assessment tool (Python, Flask, SQLite).
For use **only** on systems you own or have explicit written permission to test.
All checks are passive and non-destructive: no exploitation, brute forcing or DoS.

## Status

| Stage | Scope | State |
|-------|-------|-------|
| 1 | Structure, config, target validation, SSRF protection | Done |
| 2 | Reconnaissance and HTTP security headers | Planned |
| 3 | SSL/TLS analysis | Planned |
| 4 | Misconfiguration checks | Planned |
| 5 | Vulnerability classification engine | Planned |
| 6 | SQLite storage and JSON/HTML reports | Planned |
| 7 | Flask dashboard | Planned |
| 8 | Testing, hardening, documentation | Planned |

## Install

Windows (PowerShell):

    py -3 -m venv venv
    venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt

Kali Linux / Linux:

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Run

    python app.py                        # API on http://127.0.0.1:5000
    python -m scanner.target_validator https://example.com --authorized --connect

## Test

    pytest -v

## Configuration (environment variables)

`WEBSENTINEL_HOST`, `WEBSENTINEL_PORT`, `WEBSENTINEL_TIMEOUT`,
`WEBSENTINEL_REQUEST_DELAY`, `WEBSENTINEL_MAX_REDIRECTS`, `WEBSENTINEL_LOG_LEVEL`,
`WEBSENTINEL_ALLOWED_TARGETS` (comma-separated allowlist of hosts).
