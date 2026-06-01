"""Agent Tool Readiness Checker v1.

This module composes the existing read-only x402 metadata scanner, agent-
discovery public metadata checks, and optional unpaid paid-path health probe into
a higher-priced readiness product for agents, marketplaces, and x402 sellers. It
deliberately does not add any independent external fetch behavior: network I/O
stays inside ``scan_target`` and ``probe_paid_path``.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Callable, Mapping

from .health import probe_paid_path, validate_probe_request
from .scanner import normalize_base_url, scan_target

ReadinessChecker = Callable[[Mapping[str, Any]], dict[str, Any]]
Scanner = Callable[..., dict[str, Any]]
HealthProber = Callable[[Mapping[str, Any]], dict[str, Any]]

READINESS_PRODUCT = "agent_tool_readiness_checker"
READINESS_TIERS: dict[str, dict[str, str]] = {
    "quick": {
        "priceUsd": "1.00",
        "label": "Quick readiness check",
        "description": "x402 manifest, OpenAPI, price metadata, resource counts, and listing hygiene from existing public metadata scans.",
    },
    "deep": {
        "priceUsd": "5.00",
        "label": "Deep readiness check",
        "description": "Quick scan plus optional unpaid 402 paid-path health probe and expected network/asset/price comparison.",
    },
    "report": {
        "priceUsd": "10.00",
        "label": "Readiness report pack",
        "description": "Deep readiness check plus a concise Markdown report suitable for buyer, marketplace, or launch-review handoff.",
    },
}

CLAIM_BOUNDARY = (
    "Readiness is based on public metadata and optional unpaid x402 402 challenge checks only; "
    "it does not sign payments, spend funds, prove settlement, or prove downstream real-world execution."
)


def readiness_price_usdc(tier: str | None) -> str:
    """Return the x402 price for a readiness tier, raising for unknown tiers."""
    normalized = _normalize_tier(tier)
    return READINESS_TIERS[normalized]["priceUsd"]


def validate_readiness_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and validate a readiness request before payment verification.

    URL query strings/fragments are stripped from response-bound fields to avoid
    accidental leakage of tokens, campaign params, or customer identifiers.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")

    raw_target = str(payload.get("target") or payload.get("url") or "").strip()
    if not raw_target:
        raise ValueError("target is required")
    target = _public_metadata_url(raw_target, field="target")

    tier = _normalize_tier(str(payload.get("tier") or "quick"))
    marketplace_url = _optional_public_metadata_url(payload.get("marketplace_url") or payload.get("marketplace"), field="marketplace_url")
    expected_resources = _parse_optional_non_negative_int(payload.get("expected_resources"))

    expected = payload.get("expected") or {}
    if not isinstance(expected, Mapping):
        raise ValueError("expected must be a JSON object when provided")
    expected_dict = dict(expected)
    paid_path_query = _optional_paid_path_query(payload)
    paid_path_query_keys: list[str] = []

    method = str(payload.get("method") or "GET").strip().upper() or "GET"
    mode = str(payload.get("mode") or "unpaid_402").strip().lower() or "unpaid_402"
    raw_paid_path = (
        payload.get("paid_path")
        or payload.get("paidPath")
        or payload.get("paidPathUrl")
        or payload.get("probe_target")
        or payload.get("probeTarget")
    )
    paid_path: str | None = None
    if raw_paid_path not in (None, ""):
        probe_request = validate_probe_request(
            {
                "target": str(raw_paid_path),
                "method": method,
                "mode": mode,
                "expected": expected_dict,
                "query": paid_path_query,
            }
        )
        paid_path = str(probe_request["displayTarget"])
        method = str(probe_request["method"])
        mode = str(probe_request["mode"])
        expected_dict = dict(probe_request.get("expected") or {})
        paid_path_query_keys = [str(key) for key in probe_request.get("queryKeys") or []]

    return {
        "product": READINESS_PRODUCT,
        "target": target,
        "tier": tier,
        "priceUsd": READINESS_TIERS[tier]["priceUsd"],
        "marketplace_url": marketplace_url,
        "expected_resources": expected_resources,
        "paid_path": paid_path,
        "paid_path_query_keys": paid_path_query_keys,
        "method": method,
        "mode": mode,
        "expected": expected_dict,
    }


def check_agent_tool_readiness(
    payload: Mapping[str, Any],
    *,
    scanner: Scanner = scan_target,
    health_prober: HealthProber = probe_paid_path,
) -> dict[str, Any]:
    """Run Agent Tool Readiness Checker v1 using existing safe primitives."""
    normalized = validate_readiness_request(payload)
    tier = normalized["tier"]

    scan = scanner(
        normalized["target"],
        marketplace_url=normalized["marketplace_url"],
        expected_resources=normalized["expected_resources"],
        include_agent_discovery=True,
    )
    metadata_checks = _metadata_checks(scan)
    agent_discovery_checks = _agent_discovery_checks(scan)

    issues = _string_list(scan.get("issues"))
    scan_next_steps = _string_list(scan.get("nextSteps"))
    recommended_fixes = scan_next_steps if issues else []
    health_probe: dict[str, Any] | None = None
    paid_path_checks: dict[str, Any] | None

    if tier in {"deep", "report"}:
        if normalized["paid_path"]:
            probe_payload = {
                "target": normalized["paid_path"],
                "method": normalized["method"],
                "mode": normalized["mode"],
                "expected": normalized["expected"],
            }
            paid_path_query = _optional_paid_path_query(payload)
            if paid_path_query:
                probe_payload["query"] = paid_path_query
            health_probe = health_prober(probe_payload)
            paid_path_checks = {"healthProbeSupplied": True, **dict(health_probe.get("checks") or {}), "healthy": bool(health_probe.get("healthy"))}
            issues.extend(_string_list(health_probe.get("issues")))
            recommended_fixes.extend(_string_list(health_probe.get("recommendedFixes")))
        else:
            paid_path_checks = {"healthProbeSupplied": False, "healthy": None}
            issues.append("paid path not supplied for deep/report readiness check")
            recommended_fixes.append("supply paid_path to verify unpaid 402 challenge health without signing or spending")
    else:
        paid_path_checks = None

    issues = _dedupe(issues)
    recommended_fixes = _dedupe(recommended_fixes)
    score = _readiness_score(_safe_score(scan.get("score")), tier=tier, health_probe=health_probe, paid_path=normalized["paid_path"])
    result: dict[str, Any] = {
        "product": READINESS_PRODUCT,
        "tier": tier,
        "priceUsd": normalized["priceUsd"],
        "target": str(scan.get("target") or normalized["target"]),
        "ready": score >= 80 and not issues,
        "score": score,
        "checks": {
            "metadata": metadata_checks,
            "agentDiscovery": agent_discovery_checks,
            "paidPath": paid_path_checks,
            "reportPackIncluded": tier == "report",
        },
        "scan": scan,
        "healthProbe": health_probe,
        "issues": issues,
        "recommendedFixes": recommended_fixes,
        "nextSteps": recommended_fixes or scan_next_steps or ["agent tool metadata appears ready for the selected readiness tier"],
        "marketplacePositioning": _marketplace_positioning(tier),
        "claimBoundary": CLAIM_BOUNDARY,
    }
    if tier == "report":
        result["report"] = {"format": "markdown", "body": _markdown_report(result)}
    return result


def _normalize_tier(tier: str | None) -> str:
    normalized = str(tier or "quick").strip().lower()
    if normalized not in READINESS_TIERS:
        raise ValueError("tier must be one of: quick, deep, report")
    return normalized


def _public_metadata_url(raw_url: str, *, field: str) -> str:
    _ensure_no_url_credentials(raw_url, field=field)
    return normalize_base_url(raw_url)


def _optional_public_metadata_url(value: Any, *, field: str) -> str | None:
    if value in (None, ""):
        return None
    return _public_metadata_url(str(value), field=field)


def _ensure_no_url_credentials(raw_url: str, *, field: str) -> None:
    raw = (raw_url or "").strip()
    if not raw:
        return
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.username or parsed.password:
        raise ValueError(f"{field} URL must not include username or password")


def _parse_optional_non_negative_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_resources must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError("expected_resources must be a non-negative integer")
    return parsed


def _optional_paid_path_query(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    value = payload.get("paid_path_query") or payload.get("paidPathQuery") or payload.get("probe_query") or payload.get("probeQuery")
    if value in (None, ""):
        return None
    if not isinstance(value, Mapping):
        raise ValueError("paid_path_query must be a JSON object when provided")
    return dict(value)


def _metadata_checks(scan: Mapping[str, Any]) -> dict[str, Any]:
    well_known = scan.get("wellKnown") if isinstance(scan.get("wellKnown"), Mapping) else {}
    openapi = scan.get("openapi") if isinstance(scan.get("openapi"), Mapping) else {}
    marketplace = scan.get("marketplace") if isinstance(scan.get("marketplace"), Mapping) else None
    well_known_status = _safe_int(well_known.get("status"))
    resource_count = _safe_int(well_known.get("resourceCount"))
    openapi_status = _safe_int(openapi.get("status"))
    path_count = _safe_int(openapi.get("pathCount"))
    prices = scan.get("prices") if isinstance(scan.get("prices"), list) else []
    return {
        "x402ManifestPublished": well_known_status == 200,
        "resourcesDeclared": resource_count > 0,
        "openapiPublished": openapi_status == 200,
        "openapiPathsDeclared": path_count > 0,
        "priceMetadataPresent": len(prices) > 0,
        "marketplaceInSync": None if marketplace is None else not bool(marketplace.get("stale")),
    }


def _agent_discovery_checks(scan: Mapping[str, Any]) -> dict[str, Any]:
    discovery = scan.get("agentDiscovery") if isinstance(scan.get("agentDiscovery"), Mapping) else {}
    surfaces = discovery.get("surfaces") if isinstance(discovery.get("surfaces"), Mapping) else {}
    llms = surfaces.get("llmsTxt") if isinstance(surfaces.get("llmsTxt"), Mapping) else {}
    agents = surfaces.get("agentsTxt") if isinstance(surfaces.get("agentsTxt"), Mapping) else {}
    mcp_json = surfaces.get("wellKnownMcpJson") if isinstance(surfaces.get("wellKnownMcpJson"), Mapping) else {}
    mcp_endpoint = surfaces.get("mcpEndpoint") if isinstance(surfaces.get("mcpEndpoint"), Mapping) else {}
    return {
        "llmsTxtPublished": bool(llms.get("available")),
        "agentsTxtPublished": bool(agents.get("available")),
        "mcpDiscoveryPublished": bool(mcp_json.get("available")),
        "mcpDiscoveryToolsDeclared": _safe_int(mcp_json.get("toolsCount")) > 0,
        "mcpEndpointAvailable": bool(mcp_endpoint.get("available")),
        "score": _safe_int(discovery.get("score")),
    }


def _readiness_score(scan_score: int, *, tier: str, health_probe: Mapping[str, Any] | None, paid_path: str | None) -> int:
    if tier == "quick":
        return _clamp_score(scan_score)
    if not paid_path or health_probe is None:
        return _clamp_score(scan_score - 15)
    if bool(health_probe.get("healthy")):
        return _clamp_score(scan_score + 5)
    return _clamp_score(scan_score - 25)


def _markdown_report(result: Mapping[str, Any]) -> str:
    issues = _string_list(result.get("issues"))
    fixes = _string_list(result.get("recommendedFixes"))
    issue_lines = "\n".join(f"- {item}" for item in issues) or "- None observed for this tier."
    fix_lines = "\n".join(f"- {item}" for item in fixes) or "- No immediate fixes required for this tier."
    health = result.get("healthProbe") if isinstance(result.get("healthProbe"), Mapping) else None
    health_line = "not supplied"
    if health is not None:
        health_line = "healthy" if health.get("healthy") else "issues observed"
    scan = result.get("scan") if isinstance(result.get("scan"), Mapping) else {}
    metadata = result.get("checks", {}).get("metadata") if isinstance(result.get("checks"), Mapping) else {}
    agent_discovery = result.get("checks", {}).get("agentDiscovery") if isinstance(result.get("checks"), Mapping) else {}
    score_breakdown = scan.get("scoreBreakdown") if isinstance(scan.get("scoreBreakdown"), Mapping) else {}
    evidence_lines = _markdown_evidence_lines(metadata if isinstance(metadata, Mapping) else {}, agent_discovery if isinstance(agent_discovery, Mapping) else {}, health)
    score_lines = _markdown_score_lines(score_breakdown)
    retest_lines = _markdown_retest_lines(result)
    ready_word = "ready" if result.get("ready") else "not ready yet"
    return (
        "# Agent Tool Readiness Report\n\n"
        "## Executive summary\n"
        f"- Target: `{result.get('target')}`\n"
        f"- Tier: `{result.get('tier')}` (${result.get('priceUsd')})\n"
        f"- Readiness: **{ready_word}** with score **{result.get('score')}** / 100.\n"
        f"- Paid-path health: **{health_line}**.\n\n"
        "## Evidence\n"
        f"{evidence_lines}\n\n"
        "## Score breakdown\n"
        f"{score_lines}\n\n"
        "## Issues\n"
        f"{issue_lines}\n\n"
        "## Recommended fixes\n"
        f"{fix_lines}\n\n"
        "## Re-test commands\n"
        f"{retest_lines}\n\n"
        "## Marketplace-safe positioning\n"
        "Use this as pre-listing readiness checks and launch artifacts for paid x402/MCP builders. "
        "Do not describe it as an official listing, security guarantee, marketplace endorsement, escrow proof, or agent trust score.\n\n"
        "## Claim boundary\n"
        f"{CLAIM_BOUNDARY}\n"
    )


def _markdown_evidence_lines(metadata: Mapping[str, Any], agent_discovery: Mapping[str, Any], health: Mapping[str, Any] | None) -> str:
    rows = [
        ("x402 manifest published", metadata.get("x402ManifestPublished")),
        ("resources declared", metadata.get("resourcesDeclared")),
        ("OpenAPI published", metadata.get("openapiPublished")),
        ("OpenAPI paths declared", metadata.get("openapiPathsDeclared")),
        ("price metadata present", metadata.get("priceMetadataPresent")),
        ("marketplace in sync", metadata.get("marketplaceInSync")),
        ("agent llms.txt published", agent_discovery.get("llmsTxtPublished")),
        ("agent agents.txt published", agent_discovery.get("agentsTxtPublished")),
        ("agent MCP discovery published", agent_discovery.get("mcpDiscoveryPublished")),
        ("agent MCP endpoint available", agent_discovery.get("mcpEndpointAvailable")),
    ]
    if health is None:
        rows.append(("unpaid 402 paid-path probe", "not supplied"))
    else:
        rows.append(("unpaid 402 paid-path probe", "healthy" if health.get("healthy") else "issues observed"))
    return "\n".join(f"- {label}: `{value}`" for label, value in rows)


def _markdown_score_lines(score_breakdown: Mapping[str, Any]) -> str:
    if not score_breakdown:
        return "- Detailed scanner score breakdown was not supplied by this scan."
    lines: list[str] = []
    for name in ("metadata", "documentation", "marketplace", "agentDiscovery", "confidence"):
        section = score_breakdown.get(name)
        if section is None:
            lines.append(f"- {name}: `not tested`")
            continue
        if not isinstance(section, Mapping):
            continue
        reasons = section.get("reasons") if isinstance(section.get("reasons"), list) else []
        reason_text = "; ".join(str(reason) for reason in reasons) if reasons else "no deductions observed"
        lines.append(f"- {name}: `{section.get('score')}` — {reason_text}")
    return "\n".join(lines) or "- Detailed scanner score breakdown was not supplied by this scan."


def _markdown_retest_lines(result: Mapping[str, Any]) -> str:
    scan = result.get("scan") if isinstance(result.get("scan"), Mapping) else {}
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    commands = []
    for finding in findings:
        if isinstance(finding, Mapping) and finding.get("retest"):
            commands.append(str(finding["retest"]))
    target = result.get("target")
    if target:
        commands.append(f"curl -i {target}/.well-known/x402")
        commands.append(f"curl -i {target}/openapi.json")
    commands = _dedupe(commands)
    return "\n".join(f"- `{command}`" for command in commands) or "- Re-run the readiness check after applying fixes."


def _marketplace_positioning(tier: str) -> dict[str, Any]:
    return {
        "recommendedCollection": "Agent Verification & Security",
        "buyerPain": "Agents and marketplaces need a compact paid readiness check before listing, buying, or routing traffic to x402 tools.",
        "recommendedXpayPriceUsd": READINESS_TIERS[tier]["priceUsd"],
        "pricingTiers": {name: data["priceUsd"] for name, data in READINESS_TIERS.items()},
        "claimBoundary": CLAIM_BOUNDARY,
    }


def _safe_score(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
