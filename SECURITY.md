# Security Policy

GateCheck is designed for read-only public metadata checks. It should not
receive credentials, cookies, private keys, wallet secrets, raw payment
signatures, customer data, or private/internal service URLs.

## Supported Versions

The `main` branch is the supported development line.

## Reporting A Vulnerability

Open a private security advisory on GitHub if available, or open an issue with
only a high-level description and reproduction outline. Do not include live
secrets, private customer data, raw payment headers, or exploit payloads against
third-party systems.

## Current Safety Boundaries

- Credentialed URLs are rejected.
- Private, loopback, link-local, and internal hostnames are rejected by default.
- DNS answers resolving to non-global IP addresses are rejected before connect.
- Scanner fetches do not follow redirects.
- Receipt evidence rejects secret-like field names.
- MCP tool execution can fail closed in production unless upstream auth is configured.
- The project does not sign payments, move funds, custody wallets, or claim marketplace endorsement.

## Public Security Automation

- Pytest runs on pushes and pull requests.
- CodeQL scans Python code paths.
- Dependabot watches GitHub Actions and Python packaging updates.
- OpenSSF Scorecard records supply-chain hygiene signals.

These checks are reviewer aids, not security certification. GateCheck's public
claim remains limited to observed metadata, unpaid 402 behavior, sanitized
receipts, and tested safety boundaries.
