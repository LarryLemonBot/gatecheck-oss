# GateCheck Roadmap

This roadmap is intentionally scoped to the open-source GateCheck core. It does
not include private LarryBuildsAI workspace state, hosted-service secrets,
customer data, or sibling product plans.

## Near Term

- Add fixture-backed examples for healthy x402, partial x402, MCP-only, and
  missing-metadata services.
- Publish a compact demo receipt and readiness report generated from sanitized
  public sample data.
- Expand MCP client examples for local JSON-RPC use.
- Add more regression tests around redirect refusal, DNS rebinding protections,
  credentialed URL rejection, and secret-like receipt evidence.

## Medium Term

- Add optional SARIF or Markdown report output for maintainers who want to
  attach GateCheck findings to issues and pull requests.
- Add structured policy presets for common paid-tool launch reviews.
- Improve scoring explanations while preserving the current claim boundary:
  observed public metadata and unpaid checks only.

## Non-Goals

- No payment signing or funds movement.
- No wallet custody, escrow, settlement proof, or KYC/AML claims.
- No private endpoint probing by default.
- No marketplace endorsement, ranking, adoption, or security certification
  claims.
