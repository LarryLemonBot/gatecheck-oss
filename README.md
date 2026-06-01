# GateCheck

GateCheck is an open-source, read-only x402 and MCP readiness toolkit for paid
agent-tool sellers. It helps developers inspect whether a public paid API or MCP
server is discoverable, payable, inspectable, and claim-bounded before buyers or
agents route spend to it.

The code is intentionally stdlib-first and safe by default. It does not contain
private LarryBuildsAI workspace state, credentials, wallets, customer data,
deployment secrets, or unrelated product source.

## What It Includes

- Public `.well-known/x402`, OpenAPI, `llms.txt`, `agents.txt`, and MCP discovery scanning.
- Unpaid x402 paid-path probes that check HTTP 402 challenge behavior without signing or paying.
- Deterministic receipts with secret-like evidence rejection.
- Agent-tool readiness scoring for x402/MCP sellers.
- Buyer-safe x402 launch-pack generation.
- A small JSON-RPC MCP surface for GateCheck tools.
- Focused tests for SSRF protections, URL sanitization, auth boundaries, x402 payment helpers, and claim-bounded receipts.

## Install And Test

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Run a local scan:

```bash
python -m x402_resource_scanner https://example.com --agent-discovery
```

## Safety Boundaries

GateCheck is designed for public metadata and unpaid challenge checks only.

- No private endpoint probing by default.
- No credentialed URLs.
- No cookies, API keys, private keys, wallet secrets, customer data, or raw payment headers.
- No signing, funds movement, custody, escrow, outreach, or listing submission.
- No marketplace endorsement, certification, ranking, customer adoption, or downstream execution claims.
- Scanner fetches reject private/internal hosts and DNS answers resolving to non-global IP addresses.
- Scanner fetches do not follow redirects.

## Core Modules

- `x402_resource_scanner/scanner.py` checks public x402, OpenAPI, and agent-discovery metadata.
- `x402_resource_scanner/health.py` probes unpaid x402 paid paths.
- `x402_resource_scanner/receipt.py` creates claim-bounded receipts.
- `x402_resource_scanner/readiness.py` composes scan/probe evidence into readiness reports.
- `x402_resource_scanner/launch_pack.py` generates launch artifacts without publishing or outreach.
- `x402_resource_scanner/mcp.py` exposes GateCheck tools over JSON-RPC.
- `x402_resource_scanner/x402_payment.py` implements small x402 payment helper primitives.

## Hosted Service

The hosted GateCheck service is available at:

- Product homepage: `https://proofbeforepay.vercel.app/gatecheck`
- Remote MCP endpoint: `https://proofbeforepay.vercel.app/gatecheck/mcp`

The hosted service may require product-specific authorization for protected tool
execution. Public initialization and tool-list discovery are available for
marketplace/client inspection.

## Claim Boundary

GateCheck documents observed public metadata, unpaid 402 challenge behavior,
request summaries, hashes, and generated artifacts only. It does not prove
marketplace endorsement, payment settlement, security certification, custody,
KYC/AML coverage, buyer adoption, or downstream execution.
