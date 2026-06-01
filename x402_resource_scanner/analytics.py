"""Privacy-safe analytics for paid x402 endpoint calls.

The service must be able to answer who used which endpoint and why without
retaining customer payloads, auth headers, payment signatures, or full URLs with
query strings. This module builds a sanitized event and emits it to structured
stdout only when analytics are enabled.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse

from .x402_payment import PaymentResource, PaymentSession

SCHEMA_VERSION = "x402_purchase_event.v1"
PUBLIC_ROUTE_SCHEMA_VERSION = "x402_public_route_event.v1"
SERVICE_NAME = "x402-resource-scanner"
AnalyticsSink = Callable[[dict[str, Any]], None]

_SOURCE_RE = re.compile(r"[^a-zA-Z0-9_.:/@+-]+")
_SECRET_KEY_RE = re.compile(r"(secret|token|key|password|cookie|auth|signature|bearer)", re.I)


def analytics_enabled() -> bool:
    """Return whether default stdout analytics emission is enabled.

    Production Vercel deployments log settled purchase events by default. Local
    tests/dev stay quiet unless explicitly opted in with ANALYTICS_ENABLED=true.
    """
    value = os.getenv("ANALYTICS_ENABLED")
    if value is not None:
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return os.getenv("VERCEL_ENV", "").strip().lower() == "production"


def emit_purchase_event(event: Mapping[str, Any]) -> None:
    """Emit a sanitized analytics event to stdout, fail-open on all errors."""
    if not analytics_enabled():
        return
    try:
        print("ANALYTICS " + json.dumps(dict(event), sort_keys=True, separators=(",", ":")), flush=True)
    except Exception:
        return


def safe_emit(sink: AnalyticsSink | None, event: dict[str, Any]) -> None:
    """Call an analytics sink without letting analytics break paid responses."""
    if sink is None:
        sink = emit_purchase_event
    try:
        sink(event)
    except Exception:
        return


def build_purchase_event(
    path_and_query: str,
    *,
    request_headers: Mapping[str, str] | None,
    route_name: str,
    resource: PaymentResource,
    payment_session: PaymentSession,
    payment_summary: Mapping[str, Any] | None = None,
    result_payload: Mapping[str, Any] | None = None,
    request_payload: Mapping[str, Any] | None = None,
    status_code: int,
    outcome: str,
    payment_state: str,
    error_code: str | None = None,
    latency_ms: int | None = None,
) -> dict[str, Any]:
    """Build a privacy-safe event describing a paid x402 request outcome."""
    parsed = urlparse(path_and_query)
    query = parse_qs(parsed.query)
    headers = _lower_headers(request_headers)
    summary = dict(payment_summary or {})
    requirements = payment_session.requirements or {}
    settlement = payment_session.settlement_response or {}
    verify = payment_session.verify_response or {}

    payer = _first_string(summary.get("payer"), settlement.get("payer"), verify.get("payer"))
    tx_hash = _first_string(summary.get("transaction"), summary.get("txHash"), settlement.get("transaction"), settlement.get("txHash"), settlement.get("tx_hash"))
    amount_atomic = _first_string(summary.get("amount"), settlement.get("amount"), requirements.get("amount"))
    network = _first_string(summary.get("network"), settlement.get("network"), requirements.get("network"))
    asset = _first_string(summary.get("asset"), settlement.get("asset"), requirements.get("asset"))
    pay_to = _first_string(requirements.get("payTo"), requirements.get("pay_to"))

    target_url = _query_first(query, "url")
    if not target_url and isinstance(request_payload, Mapping):
        target_url = _first_string(request_payload.get("target"), request_payload.get("url"))
    marketplace_url = _query_first(query, "marketplace_url") or _query_first(query, "marketplace")
    referer = headers.get("referer") or headers.get("referrer")
    origin = headers.get("origin")
    source_param = _source_value(
        _query_first(query, "source")
        or _query_first(query, "src")
        or _query_first(query, "ref")
        or _query_first(query, "utm_source")
    )
    source_header = _source_value(headers.get("x-source") or headers.get("x-client-name") or headers.get("x-marketplace"))

    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": f"evt_{uuid.uuid4()}",
        "event_ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "environment": os.getenv("VERCEL_ENV") or os.getenv("ENVIRONMENT") or "development",
        "service_name": SERVICE_NAME,
        "deployment_id": os.getenv("VERCEL_GIT_COMMIT_SHA"),
        "vercel_region": os.getenv("VERCEL_REGION"),
        "request_id": headers.get("x-vercel-id") or f"req_{uuid.uuid4()}",
        "host": _host_only(headers.get("host")),
        "http_method": resource.method,
        "endpoint_path": parsed.path or resource.path,
        "route_name": route_name,
        "mcp_method": None,
        "tool_name": None,
        "status_code": int(status_code),
        "latency_ms": latency_ms,
        "outcome": outcome,
        "error_code": _source_value(error_code),
        "payment_state": payment_state,
        "payment_mode": payment_session.summary().get("mode") if payment_session else None,
        "price_usdc": str(resource.price_usdc),
        "amount_atomic": amount_atomic,
        "amount_usdc": _atomic_usdc(amount_atomic),
        "network": network,
        "asset": _lower_or_none(asset),
        "pay_to_address": _lower_or_none(pay_to),
        "payer_address": _lower_or_none(payer),
        "payer_hash": _hash_value(payer),
        "tx_hash": tx_hash,
        "payment_payload_hash": _hash_json(payment_session.payment_payload),
        "verify_valid": _bool_or_none(verify.get("isValid") or verify.get("valid")),
        "settle_success": _bool_or_none(settlement.get("success")),
        "failure_code": _source_value(_first_string(settlement.get("errorReason"), settlement.get("errorCode"), error_code)),
        "source_param": source_param,
        "utm_source": _source_value(_query_first(query, "utm_source")),
        "utm_medium": _source_value(_query_first(query, "utm_medium")),
        "utm_campaign": _source_value(_query_first(query, "utm_campaign"), limit=120),
        "utm_content": _source_value(_query_first(query, "utm_content"), limit=120),
        "source_header": source_header,
        "marketplace_name": _marketplace_name(source_param, source_header, marketplace_url, referer),
        "marketplace_url_host": _host_from_url(marketplace_url),
        "marketplace_url_hash": _hash_value(marketplace_url),
        "referer_host": _host_from_url(referer),
        "referer_hash": _hash_value(referer),
        "origin_host": _host_from_url(origin),
        "user_agent_hash": _hash_value(headers.get("user-agent")),
        "user_agent_family": _user_agent_family(headers.get("user-agent")),
        "ip_hash": _hash_value(_first_ip(headers.get("x-forwarded-for"))),
        "country": _source_value(headers.get("x-vercel-ip-country"), limit=8),
        "intent_label": _intent_label(route_name),
        "target_host": _host_from_url(target_url),
        "target_url_hash": _hash_value(target_url),
        "target_scheme": _scheme_from_url(target_url),
        "expected_resources_bucket": _count_bucket(_safe_int(_query_first(query, "expected_resources"))),
        "scan_score_bucket": _score_bucket(_safe_int((result_payload or {}).get("score"))),
        "scan_issue_count": _safe_len((result_payload or {}).get("issues")),
        "receipt_id": _safe_public_id((result_payload or {}).get("receiptId")),
        "decision": _source_value((result_payload or {}).get("decision")),
        "request_hash": _safe_public_hash((result_payload or {}).get("requestHash")),
        "policy_hash": _safe_public_hash((result_payload or {}).get("policyHash")),
        "result_hash": _safe_public_hash((result_payload or {}).get("resultHash")),
        "payment_hash": _safe_public_hash((result_payload or {}).get("paymentHash")),
        "evidence_hash": _safe_public_hash((result_payload or {}).get("evidenceHash")),
        "input_size_bucket": _input_size_bucket(request_payload),
        "payload_shape_hash": _payload_shape_hash(request_payload),
        "request_object_keys": _request_object_keys(request_payload),
        "has_payment_evidence": bool(isinstance(request_payload, Mapping) and request_payload.get("payment")) if request_payload is not None else None,
        "response_hash": _hash_json(_response_summary(result_payload)),
    }
    return {key: value for key, value in event.items() if value is not None}


def build_public_route_event(
    path_and_query: str,
    *,
    request_headers: Mapping[str, str] | None,
    status_code: int,
    content_type: str | None,
    latency_ms: int | None = None,
) -> dict[str, Any]:
    """Build a privacy-safe event for public discovery, product, and MCP route hits."""

    parsed = urlparse(path_and_query)
    query = parse_qs(parsed.query)
    headers = _lower_headers(request_headers)
    referer = headers.get("referer") or headers.get("referrer")
    origin = headers.get("origin")
    source_param = _source_value(
        _query_first(query, "source")
        or _query_first(query, "src")
        or _query_first(query, "ref")
        or _query_first(query, "utm_source")
    )
    source_header = _source_value(headers.get("x-source") or headers.get("x-client-name") or headers.get("x-marketplace"))
    path = parsed.path or "/"
    event: dict[str, Any] = {
        "schema_version": PUBLIC_ROUTE_SCHEMA_VERSION,
        "event_id": f"evt_{uuid.uuid4()}",
        "event_ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "environment": os.getenv("VERCEL_ENV") or os.getenv("ENVIRONMENT") or "development",
        "service_name": SERVICE_NAME,
        "request_id": headers.get("x-vercel-id") or f"req_{uuid.uuid4()}",
        "host": _host_only(headers.get("host")),
        "http_method": "GET",
        "endpoint_path": path,
        "route_name": "public_route",
        "product_id": _product_for_path(path),
        "surface_type": _surface_type_for_path(path, content_type),
        "status_code": int(status_code),
        "latency_ms": latency_ms,
        "content_type": _source_value(content_type, limit=80),
        "source_param": source_param,
        "utm_source": _source_value(_query_first(query, "utm_source")),
        "utm_medium": _source_value(_query_first(query, "utm_medium")),
        "utm_campaign": _source_value(_query_first(query, "utm_campaign"), limit=120),
        "source_header": source_header,
        "marketplace_name": _marketplace_name(source_param, source_header, referer),
        "referer_host": _host_from_url(referer),
        "referer_hash": _hash_value(referer),
        "origin_host": _host_from_url(origin),
        "user_agent_hash": _hash_value(headers.get("user-agent")),
        "user_agent_family": _user_agent_family(headers.get("user-agent")),
        "ip_hash": _hash_value(_first_ip(headers.get("x-forwarded-for"))),
        "country": _source_value(headers.get("x-vercel-ip-country"), limit=8),
    }
    return {key: value for key, value in event.items() if value is not None}


def _product_for_path(path: str) -> str:
    if path.startswith("/gatecheck") or path in {"/mcp", "/openapi.json", "/llms.txt", "/agents.txt", "/skill.md", "/product-card.md"}:
        return "gatecheck"
    if "marketplace" in path or path.startswith("/.well-known/marketplace"):
        return "gatecheck"
    if path in {"/", "/x402-agent-commerce-proof", "/agent-commerce-proof"}:
        return "gatecheck"
    return "unknown"


def _surface_type_for_path(path: str, content_type: str | None) -> str:
    if path.endswith("/mcp") or path == "/mcp":
        return "mcp"
    if path.endswith(".json") or (content_type or "").startswith("application/json"):
        return "json"
    if path.endswith(".md") or "markdown" in (content_type or ""):
        return "markdown"
    if path.endswith(".xml") or "xml" in (content_type or ""):
        return "sitemap"
    if path.endswith((".png", ".svg")):
        return "asset"
    if (content_type or "").startswith("text/html"):
        return "html"
    return "other"


def _lower_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def _query_first(query: Mapping[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    return str(values[0])


def _first_string(*values: Any) -> str | None:
    for value in values:
        if value not in (None, ""):
            return str(value)
    return None


def _source_value(value: Any, *, limit: int = 80) -> str | None:
    if value in (None, ""):
        return None
    cleaned = _SOURCE_RE.sub("-", str(value).strip())[:limit].strip("-._:/@+")
    return cleaned or None


def _host_only(value: str | None) -> str | None:
    if not value:
        return None
    return str(value).split(",", 1)[0].strip().lower()[:255]


def _host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(str(value))
    if not parsed.netloc and parsed.path and "." in parsed.path:
        parsed = urlparse("https://" + str(value))
    return _host_only(parsed.hostname)


def _scheme_from_url(value: str | None) -> str | None:
    if not value:
        return None
    scheme = urlparse(str(value)).scheme.lower()
    return scheme if scheme in {"http", "https"} else None


def _marketplace_name(*values: str | None) -> str:
    text = " ".join(str(value).lower() for value in values if value)
    if "x402ui" in text or "x402-ui" in text:
        return "x402-ui"
    if "agentic" in text:
        return "agentic-market"
    if "hol" in text or "hashgraphonline" in text:
        return "hol-registry"
    if "xpay" in text or "pay.sh" in text or "paysh" in text:
        return "xpay-tools"
    if "awesome-x402" in text or "github" in text:
        return "awesome-x402"
    if "direct" in text:
        return "direct"
    return "unknown"


def _intent_label(route_name: str) -> str:
    return {
        "scan": "scan_x402_resource",
        "receipt": "generate_trust_receipt",
        "health_probe": "probe_x402_paid_path",
        "agent_tool_readiness": "check_agent_tool_readiness",
        "mcp": "mcp_tool_call",
    }.get(route_name, route_name)


def _lower_or_none(value: str | None) -> str | None:
    return str(value).lower() if value else None


def _atomic_usdc(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return f"{(Decimal(str(value)) / Decimal(1_000_000)).quantize(Decimal('0.000001'))}"
    except (InvalidOperation, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_len(value: Any) -> int | None:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return None


def _score_bucket(score: int | None) -> str | None:
    if score is None:
        return None
    if score < 25:
        return "0-24"
    if score < 50:
        return "25-49"
    if score < 75:
        return "50-74"
    return "75-100"


def _count_bucket(count: int | None) -> str | None:
    if count is None:
        return None
    if count <= 0:
        return "none"
    if count == 1:
        return "1"
    if count <= 5:
        return "2-5"
    if count <= 20:
        return "6-20"
    return "21+"


def _input_size_bucket(payload: Mapping[str, Any] | None) -> str | None:
    if payload is None:
        return None
    size = len(json.dumps(_payload_shape(payload), sort_keys=True, separators=(",", ":")))
    if size == 0:
        return "0"
    if size <= 1_000:
        return "1-1k"
    if size <= 10_000:
        return "1k-10k"
    if size <= 100_000:
        return "10k-100k"
    return "100k+"


def _payload_shape_hash(payload: Mapping[str, Any] | None) -> str | None:
    if payload is None:
        return None
    return _hash_json(_payload_shape(payload))


def _payload_shape(payload: Mapping[str, Any]) -> dict[str, str]:
    return {str(key): type(value).__name__ for key, value in sorted(payload.items()) if not _SECRET_KEY_RE.search(str(key))}


def _request_object_keys(payload: Mapping[str, Any] | None) -> list[str] | None:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("request"), Mapping):
        return None
    keys = []
    for key in sorted(str(item) for item in payload["request"].keys()):
        if not _SECRET_KEY_RE.search(key):
            keys.append(key[:80])
    return keys or None


def _response_summary(payload: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, Mapping):
        return None
    return {
        key: payload.get(key)
        for key in ("target", "score", "receiptId", "decision", "evidenceHash")
        if key in payload
    }


def _safe_public_hash(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", text):
        return text.lower()
    return None


def _safe_public_id(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return _source_value(value, limit=120)


def _first_ip(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(",", 1)[0].strip()


def _user_agent_family(value: str | None) -> str | None:
    if not value:
        return None
    ua = value.lower()
    if "curl" in ua:
        return "curl"
    if "python" in ua or "httpx" in ua or "aiohttp" in ua:
        return "python"
    if "node" in ua or "undici" in ua or "axios" in ua:
        return "node"
    if "claude" in ua or "codex" in ua or "mcp" in ua or "agent" in ua or "bot" in ua:
        return "agent"
    if "mozilla" in ua or "chrome" in ua or "safari" in ua or "firefox" in ua:
        return "browser"
    return "unknown"


def _hash_json(value: Any) -> str | None:
    if value in (None, {}, []):
        return None
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        text = str(value)
    return _hash_value(text)


def _hash_value(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    salt = os.getenv("ANALYTICS_HASH_SALT")
    if salt:
        digest = hmac.new(salt.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"hmac_sha256:{digest}"
    if os.getenv("VERCEL_ENV", "").strip().lower() == "production" or os.getenv("ENVIRONMENT", "").strip().lower() == "production":
        return None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
