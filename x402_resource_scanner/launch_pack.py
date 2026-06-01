"""x402 Launch Pack Generator v0.

This product turns the existing Agent Tool Readiness Checker output into buyer-
facing launch artifacts for x402/MCP sellers. It does not post, list, contact,
sign, or spend. Network behavior stays inside the readiness checker primitives.
"""

from __future__ import annotations

import datetime as _dt
import re
import urllib.parse
from typing import Any, Callable, Mapping

from .readiness import CLAIM_BOUNDARY as READINESS_CLAIM_BOUNDARY
from .readiness import check_agent_tool_readiness, validate_readiness_request

LaunchPackGenerator = Callable[[Mapping[str, Any]], dict[str, Any]]
ReadinessChecker = Callable[[Mapping[str, Any]], dict[str, Any]]

LAUNCH_PACK_PRODUCT = "x402_launch_pack_generator"
LAUNCH_PACK_TIERS: dict[str, dict[str, str]] = {
    "single": {
        "priceUsd": "9.00",
        "label": "Single-route launch pack",
        "description": "Listing copy, FAQ, checklist, and approval-safe launch notes for one paid route/tool.",
        "readinessTier": "quick",
    },
    "service": {
        "priceUsd": "29.00",
        "label": "Service launch pack",
        "description": "Readiness-backed launch artifacts for a paid x402/MCP service with multiple buyer-facing surfaces.",
        "readinessTier": "report",
    },
    "premium": {
        "priceUsd": "49.00",
        "label": "Premium marketplace launch pack",
        "description": "Full pre-listing pack with positioning, FAQ, checklist, claim boundaries, and distribution approval copy.",
        "readinessTier": "report",
    },
}

LAUNCH_PACK_CLAIM_BOUNDARY = (
    "This launch pack generates copy, checklist items, and approval-review artifacts for a public listing; "
    "it does not post, submit, contact prospects, sign payments, spend funds, prove settlement, or claim marketplace endorsement. "
    f"Readiness evidence boundary: {READINESS_CLAIM_BOUNDARY}"
)


def launch_pack_price_usdc(tier: str | None) -> str:
    """Return the x402 price for a launch-pack tier."""
    normalized = _normalize_tier(tier)
    return LAUNCH_PACK_TIERS[normalized]["priceUsd"]


def validate_launch_pack_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a Launch Pack request before payment/generation.

    URL query strings/fragments are intentionally stripped from returned fields so
    generated launch artifacts do not leak campaign params, tokens, or customer
    identifiers.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")

    tier = _normalize_tier(str(payload.get("tier") or "single"))
    readiness_tier = LAUNCH_PACK_TIERS[tier]["readinessTier"]
    readiness_payload = {**dict(payload), "tier": readiness_tier}
    readiness_normalized = validate_readiness_request(readiness_payload)

    product_name = _clean_label(payload.get("product_name") or payload.get("productName") or "")
    if not product_name:
        product_name = _default_product_name(str(readiness_normalized["target"]))
    audience = _clean_sentence(payload.get("audience") or payload.get("buyer") or "x402/MCP buyers, AI agents, and agent-tool marketplaces")
    primary_use_case = _clean_sentence(payload.get("primary_use_case") or payload.get("useCase") or "verify paid-tool readiness before marketplace listing or agent routing")

    desired_marketplaces = _string_list(payload.get("desired_marketplaces") or payload.get("marketplaces"))
    if not desired_marketplaces:
        desired_marketplaces = ["xpay Tools", "Agentic.Market", "CDP Bazaar", "pay.sh / x402 directories"]

    return {
        "product": LAUNCH_PACK_PRODUCT,
        "target": readiness_normalized["target"],
        "tier": tier,
        "readinessTier": readiness_tier,
        "priceUsd": LAUNCH_PACK_TIERS[tier]["priceUsd"],
        "productName": product_name,
        "audience": audience,
        "primaryUseCase": primary_use_case,
        "marketplace_url": readiness_normalized.get("marketplace_url"),
        "expected_resources": readiness_normalized.get("expected_resources"),
        "paid_path": readiness_normalized.get("paid_path"),
        "paid_path_query_keys": list(readiness_normalized.get("paid_path_query_keys") or []),
        "method": readiness_normalized.get("method"),
        "mode": readiness_normalized.get("mode"),
        "expected": dict(readiness_normalized.get("expected") or {}),
        "desiredMarketplaces": desired_marketplaces[:8],
    }


def generate_x402_launch_pack(
    payload: Mapping[str, Any],
    *,
    readiness_checker: ReadinessChecker = check_agent_tool_readiness,
) -> dict[str, Any]:
    """Generate launch artifacts for an x402/MCP seller from readiness evidence."""
    normalized = validate_launch_pack_request(payload)
    readiness_request: dict[str, Any] = {
        "target": normalized["target"],
        "tier": normalized["readinessTier"],
        "marketplace_url": normalized["marketplace_url"],
        "expected_resources": normalized["expected_resources"],
        "paid_path": normalized["paid_path"],
        "method": normalized["method"],
        "mode": normalized["mode"],
        "expected": normalized["expected"],
    }
    paid_path_query = payload.get("paid_path_query") or payload.get("paidPathQuery") or payload.get("probe_query") or payload.get("probeQuery")
    if isinstance(paid_path_query, Mapping):
        readiness_request["paid_path_query"] = dict(paid_path_query)
    readiness_request = {key: value for key, value in readiness_request.items() if value not in (None, "")}

    readiness = readiness_checker(readiness_request)
    score = _safe_int(readiness.get("score"))
    ready = bool(readiness.get("ready"))
    issues = _string_list(readiness.get("issues"))
    fixes = _readiness_fix_list(readiness, issues)
    product_name = str(normalized["productName"])
    target = str(normalized["target"])

    marketplace_listing = _marketplace_listing(normalized, score=score, ready=ready, issues=issues)
    checklist = _launch_checklist(normalized, readiness, score=score, ready=ready, issues=issues, fixes=fixes)
    buyer_faq = _buyer_faq(normalized, readiness)
    distribution_copy = _distribution_copy(normalized, marketplace_listing, score=score, ready=ready)
    launch_pack = {
        "headline": marketplace_listing["headline"],
        "oneLine": marketplace_listing["summary"],
        "marketplaceListing": marketplace_listing,
        "buyerFAQ": buyer_faq,
        "launchChecklist": checklist,
        "distributionCopy": distribution_copy,
        "pricingRecommendation": _pricing_recommendation(normalized, readiness),
        "approvalPacket": {
            "approvalRequired": True,
            "approvalReason": "public posting/listing/submission is an external distribution action",
            "suggestedReviewerQuestion": "Approve publishing/submitting this exact launch pack copy and target surfaces?",
        },
    }
    result: dict[str, Any] = {
        "product": LAUNCH_PACK_PRODUCT,
        "tier": normalized["tier"],
        "priceUsd": normalized["priceUsd"],
        "target": target,
        "productName": product_name,
        "generatedAt": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "readinessTierUsed": normalized["readinessTier"],
        "readinessScore": score,
        "readyForDistribution": ready and score >= 80 and not issues,
        "approvalRequiredBeforeDistribution": True,
        "readiness": readiness,
        "launchPack": launch_pack,
        "claimBoundary": LAUNCH_PACK_CLAIM_BOUNDARY,
    }
    result["report"] = {"format": "markdown", "body": _markdown_launch_report(result)}
    return result


def _normalize_tier(tier: str | None) -> str:
    normalized = str(tier or "single").strip().lower()
    aliases = {"single-route": "single", "single_route": "single", "service-pack": "service", "service_pack": "service", "premium-pack": "premium", "premium_pack": "premium"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in LAUNCH_PACK_TIERS:
        raise ValueError("tier must be one of: single, service, premium")
    return normalized


def _default_product_name(target: str) -> str:
    parsed = urllib.parse.urlparse(target)
    host = (parsed.hostname or target).replace("www.", "")
    words = re.split(r"[^A-Za-z0-9]+", host)
    label = " ".join(word.capitalize() for word in words if word)
    return label or "x402 Paid Tool"


def _clean_label(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = re.sub(r"[<>`{}]", "", text)
    return text[:120]


def _clean_sentence(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = re.sub(r"[<>`{}]", "", text)
    return text[:280]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_clean_sentence(item) for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [_clean_sentence(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [_clean_sentence(value)]
    return []


def _readiness_fix_list(readiness: Mapping[str, Any], issues: list[str]) -> list[str]:
    recommended = _string_list(readiness.get("recommendedFixes"))
    if recommended:
        return recommended
    if issues:
        return _string_list(readiness.get("nextSteps"))
    return []


def _safe_int(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _marketplace_listing(normalized: Mapping[str, Any], *, score: int, ready: bool, issues: list[str]) -> dict[str, Any]:
    product_name = str(normalized["productName"])
    audience = str(normalized["audience"])
    primary_use_case = str(normalized["primaryUseCase"])
    target = str(normalized["target"])
    summary = f"{product_name} helps {audience} {primary_use_case}, with public x402/OpenAPI readiness evidence attached."
    return {
        "title": product_name,
        "headline": f"{product_name}: x402-ready paid tool launch pack",
        "summary": summary,
        "category": "Agent Verification & Security",
        "buyer": audience,
        "targetUrl": target,
        "tags": ["x402", "MCP", "agent-tools", "paid-api", "readiness"],
        "readinessBadge": "ready" if ready and score >= 80 and not issues else "fix-before-launch",
        "scoreLine": f"Readiness score: {score}/100 based on public metadata and optional unpaid 402 checks.",
        "safeClaims": [
            "Public metadata was checked for x402, OpenAPI, pricing, and agent-routing readiness.",
            "The paid path was not executed with funds unless explicitly supplied and separately approved by the buyer.",
            "This is pre-listing launch support, not a marketplace endorsement or settlement guarantee.",
        ],
    }


def _buyer_faq(normalized: Mapping[str, Any], readiness: Mapping[str, Any]) -> list[dict[str, str]]:
    score = _safe_int(readiness.get("score"))
    issues = _string_list(readiness.get("issues"))
    fixes = _readiness_fix_list(readiness, issues)
    return [
        {
            "question": "What does this launch pack prove?",
            "answer": f"It packages public readiness evidence for {normalized['productName']}: score {score}/100, observed issues, recommended fixes, listing copy, and re-test commands.",
        },
        {
            "question": "Does it prove payment settlement or downstream execution?",
            "answer": "No. It only uses public metadata and optional unpaid 402 challenge checks unless a separate approved paid test is performed.",
        },
        {
            "question": "What should be fixed before listing?",
            "answer": "; ".join(fixes or issues or ["No blocking fixes observed for the selected tier."]),
        },
        {
            "question": "Where can this be used?",
            "answer": "Use it as a pre-listing artifact for xpay Tools, Agentic.Market, CDP Bazaar, pay.sh/x402 directories, buyer due diligence, or internal launch review.",
        },
    ]


def _launch_checklist(
    normalized: Mapping[str, Any],
    readiness: Mapping[str, Any],
    *,
    score: int,
    ready: bool,
    issues: list[str],
    fixes: list[str],
) -> list[dict[str, str]]:
    status = "ready" if ready and score >= 80 and not issues else "fix_first"
    checklist = [
        {"item": "Readiness score reviewed", "status": status, "source": f"score={score}"},
        {"item": "x402 manifest and OpenAPI surfaces checked", "status": "ready" if score >= 60 else "fix_first", "source": "readiness scan"},
        {"item": "Claim boundaries included in listing copy", "status": "ready", "source": "launch pack"},
        {"item": "Public distribution approval requested before posting/submitting", "status": "approval_required", "source": "operator approval gate"},
    ]
    for fix in fixes[:5]:
        checklist.append({"item": fix, "status": "fix_first", "source": "readiness recommendation"})
    return checklist


def _distribution_copy(normalized: Mapping[str, Any], listing: Mapping[str, Any], *, score: int, ready: bool) -> dict[str, str]:
    status = "ready" if ready and score >= 80 else "pre-launch fixes identified"
    return {
        "marketplaceShort": f"{listing['title']} — {listing['summary']} {listing['scoreLine']}",
        "communityPostDraft": f"Built a pre-listing x402 launch pack for {listing['title']}: {score}/100 readiness, status: {status}. Public metadata only; no settlement or endorsement claims.",
        "approvalNote": "No public posting, listing, outreach, or marketplace submission is included in this generated pack. Distribution requires explicit approval.",
    }


def _pricing_recommendation(normalized: Mapping[str, Any], readiness: Mapping[str, Any]) -> dict[str, Any]:
    tier = str(normalized["tier"])
    score = _safe_int(readiness.get("score"))
    if tier == "single":
        upsell = "If this route is core to revenue, upgrade to service/premium for full listing copy and paid-path review."
    elif tier == "service":
        upsell = "Use premium when submitting to multiple marketplaces or when a buyer needs a polished handoff packet."
    else:
        upsell = "Premium pack is the launch artifact; next upsell is custom implementation or monitoring."
    return {
        "launchPackPriceUsd": normalized["priceUsd"],
        "recommendedBuyerOffer": "$9 single route / $29 service pack / $49 premium pack, with custom implementation quoted separately.",
        "readinessScore": score,
        "upsellPath": upsell,
    }


def _markdown_launch_report(result: Mapping[str, Any]) -> str:
    launch_pack = result.get("launchPack") if isinstance(result.get("launchPack"), Mapping) else {}
    listing = launch_pack.get("marketplaceListing") if isinstance(launch_pack.get("marketplaceListing"), Mapping) else {}
    faq = launch_pack.get("buyerFAQ") if isinstance(launch_pack.get("buyerFAQ"), list) else []
    checklist = launch_pack.get("launchChecklist") if isinstance(launch_pack.get("launchChecklist"), list) else []
    copy = launch_pack.get("distributionCopy") if isinstance(launch_pack.get("distributionCopy"), Mapping) else {}
    readiness = result.get("readiness") if isinstance(result.get("readiness"), Mapping) else {}
    issues = _string_list(readiness.get("issues"))
    fixes = _readiness_fix_list(readiness, issues)
    faq_lines = "\n".join(f"- **{item.get('question')}** {item.get('answer')}" for item in faq if isinstance(item, Mapping)) or "- No FAQ generated."
    checklist_lines = "\n".join(f"- `{item.get('status')}` — {item.get('item')} ({item.get('source')})" for item in checklist if isinstance(item, Mapping)) or "- No checklist generated."
    issue_lines = "\n".join(f"- {item}" for item in issues) or "- None observed for selected tier."
    fix_lines = "\n".join(f"- {item}" for item in fixes) or "- No immediate fixes required for selected tier."
    return (
        "# x402 Launch Pack\n\n"
        "## Executive summary\n"
        f"- Product: `{result.get('productName')}`\n"
        f"- Target: `{result.get('target')}`\n"
        f"- Tier: `{result.get('tier')}` (${result.get('priceUsd')})\n"
        f"- Readiness tier used: `{result.get('readinessTierUsed')}`\n"
        f"- Readiness score: **{result.get('readinessScore')}** / 100\n"
        f"- Approval required before distribution: **{result.get('approvalRequiredBeforeDistribution')}**\n\n"
        "## Listing copy\n"
        f"- Title: {listing.get('title')}\n"
        f"- Headline: {listing.get('headline')}\n"
        f"- Summary: {listing.get('summary')}\n"
        f"- Category: {listing.get('category')}\n"
        f"- Score line: {listing.get('scoreLine')}\n\n"
        "## Buyer FAQ\n"
        f"{faq_lines}\n\n"
        "## Launch checklist\n"
        f"{checklist_lines}\n\n"
        "## Issues\n"
        f"{issue_lines}\n\n"
        "## Recommended fixes\n"
        f"{fix_lines}\n\n"
        "## Distribution draft\n"
        f"- Marketplace short: {copy.get('marketplaceShort')}\n"
        f"- Community post draft: {copy.get('communityPostDraft')}\n"
        f"- Approval note: {copy.get('approvalNote')}\n\n"
        "## Approval boundary\n"
        "No public posting, listing, outreach, or marketplace submission is included in this generated pack. Explicit approval is required before distribution.\n\n"
        "## Claim boundary\n"
        f"{result.get('claimBoundary')}\n"
    )
