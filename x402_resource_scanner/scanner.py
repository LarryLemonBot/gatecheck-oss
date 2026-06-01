"""x402 Resource Scanner core library.

Read-only scanner for public x402 metadata surfaces. It intentionally does not
probe private paths, send credentials, execute remote code, or mutate targets.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import os
import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

DEFAULT_TIMEOUT_SECONDS = 8
USER_AGENT = "BoundaryGuard-x402/0.1 (+https://proofbeforepay.vercel.app)"

FetchResult = dict[str, Any]
Fetcher = Callable[[str, int], FetchResult]


@dataclass(frozen=True)
class CandidateUrls:
    base: str
    well_known: str
    openapi: str
    llms_txt: str
    agents_txt: str
    mcp_json: str
    mcp_endpoint: str


def normalize_base_url(url: str, *, allow_private_targets: bool | None = None) -> str:
    """Return a normalized HTTPS/HTTP base URL without trailing slash/path query noise."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("url is required")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("url must use http or https")
    if not parsed.netloc:
        raise ValueError("url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("url must not include username or password")
    hostname = parsed.hostname or ""
    if not _private_targets_allowed(allow_private_targets) and _is_private_or_internal_hostname(hostname):
        raise ValueError(
            "refusing to scan private or internal host; "
            "set allow_private_targets only for authorized local testing"
        )
    base_path = parsed.path.rstrip("/")
    if base_path in {"", "/"}:
        base_path = ""
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", "")).rstrip("/")


def candidate_urls(url: str, *, allow_private_targets: bool | None = None) -> CandidateUrls:
    base = normalize_base_url(url, allow_private_targets=allow_private_targets)
    return CandidateUrls(
        base=base,
        well_known=f"{base}/.well-known/x402",
        openapi=f"{base}/openapi.json",
        llms_txt=f"{base}/llms.txt",
        agents_txt=f"{base}/agents.txt",
        mcp_json=f"{base}/.well-known/mcp.json",
        mcp_endpoint=f"{base}/mcp",
    )


def _private_targets_allowed(value: bool | None) -> bool:
    if os.getenv("VERCEL_ENV", "").strip().lower() == "production" or os.getenv("ENVIRONMENT", "").strip().lower() == "production":
        return False
    if value is not None:
        return bool(value)
    return os.getenv("X402_SCANNER_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {"1", "true", "yes", "on"}


def _is_private_or_internal_hostname(hostname: str) -> bool:
    """Conservative SSRF guard for public scanner deployments.

    The scanner is a paid public product, so the default boundary is public
    metadata only. Literal non-global IPs, localhost aliases, and single-label
    intranet names are rejected unless a caller explicitly opts in for local
    testing.
    """
    host = hostname.strip().strip("[]").rstrip(".").lower()
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return True
    if host.endswith((".local", ".internal", ".lan")):
        return True
    if "." not in host and ":" not in host:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def fetch_json(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> FetchResult:
    """Fetch a public URL safely and parse JSON when possible.

    Caller-supplied scanner URLs are resolved before connect, any non-global
    answer is rejected, and the connection is pinned to the validated IP to avoid
    DNS rebinding/TOCTOU. Redirects are not followed.
    """
    try:
        parsed, address, port = _resolve_public_endpoint(url)
        return _fetch_json_via_pinned_ip(parsed, address, port, timeout)
    except Exception as exc:  # Network failures are scan results, not scanner crashes.
        return {"status": 0, "body": None, "error": str(exc), "url": _safe_url_for_response(url)}


def _parse_url_for_fetch(raw_url: str) -> urllib.parse.ParseResult:
    raw = (raw_url or "").strip()
    if not raw:
        raise ValueError("url is required")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("url must use http or https")
    if not parsed.hostname:
        raise ValueError("url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("url must not include username or password")
    if _is_private_or_internal_hostname(parsed.hostname):
        raise ValueError(
            "refusing to scan private or internal host; "
            "set allow_private_targets only for authorized local testing"
        )
    return parsed


def _resolve_public_endpoint(url: str) -> tuple[urllib.parse.ParseResult, ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    parsed = _parse_url_for_fetch(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _resolved_ip_addresses(hostname, port)
    for address in addresses:
        if not address.is_global:
            raise ValueError(f"target hostname resolves to non-global address: {address}")
    return parsed, addresses[0], port


def _resolved_ip_addresses(hostname: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve target hostname: {exc}") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        raw_address = str(sockaddr[0])
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ValueError(f"could not parse resolved target address: {raw_address}") from exc
        if str(address) not in seen:
            seen.add(str(address))
            addresses.append(address)
    if not addresses:
        raise ValueError("could not resolve target hostname")
    return addresses


def _safe_url_for_response(url: str) -> str | None:
    try:
        return normalize_base_url(url)
    except ValueError:
        try:
            parsed = _parse_url_for_fetch(url)
        except ValueError:
            return None
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        path = parsed.path.rstrip("/")
        return urllib.parse.urlunparse((parsed.scheme, netloc, path, "", "", "")).rstrip("/")


def _request_target(parsed: urllib.parse.ParseResult) -> str:
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _open_socket_to_pinned_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    timeout: int,
) -> socket.socket:
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if family == socket.AF_INET6:
            sock.connect((str(address), port, 0, 0))
        else:
            sock.connect((str(address), port))
    except Exception:
        sock.close()
        raise
    return sock


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, port: int, connect_address: ipaddress.IPv4Address | ipaddress.IPv6Address, timeout: int):
        super().__init__(host, port=port, timeout=timeout)
        self._connect_address = connect_address

    def connect(self) -> None:
        self.sock = _open_socket_to_pinned_ip(self._connect_address, self.port, int(self.timeout or DEFAULT_TIMEOUT_SECONDS))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        *,
        port: int,
        connect_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        timeout: int,
        context: ssl.SSLContext,
    ):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_address = connect_address

    def connect(self) -> None:
        raw_sock = _open_socket_to_pinned_ip(self._connect_address, self.port, int(self.timeout or DEFAULT_TIMEOUT_SECONDS))
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


def _fetch_json_via_pinned_ip(
    parsed: urllib.parse.ParseResult,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    timeout: int,
) -> FetchResult:
    hostname = parsed.hostname or ""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
    conn: http.client.HTTPConnection
    if parsed.scheme == "https":
        conn = _PinnedHTTPSConnection(
            hostname,
            port=port,
            connect_address=address,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = _PinnedHTTPConnection(hostname, port=port, connect_address=address, timeout=timeout)
    try:
        conn.request("GET", _request_target(parsed), headers=headers)
        response = conn.getresponse()
        raw = response.read(2_000_000)
        text = raw.decode("utf-8", errors="replace")
        safe_url = _safe_url_for_response(urllib.parse.urlunparse(parsed))
        return {"status": int(response.status), "body": _loads_json_or_text(text), "url": safe_url}
    finally:
        conn.close()


def _loads_json_or_text(text: str) -> Any:
    if not text:
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def parse_resource_count(document: Any) -> int:
    """Count endpoint-like resources across common x402/OpenAPI-ish shapes."""
    resources = _resource_items(document)
    if resources is not None:
        return len(resources)
    if isinstance(document, Mapping):
        paths = document.get("paths")
        if isinstance(paths, Mapping):
            return len(paths)
    return 0


def _resource_items(document: Any) -> list[Any] | None:
    if isinstance(document, list):
        return document
    if not isinstance(document, Mapping):
        return None
    for key in ("resources", "endpoints"):
        value = document.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, Mapping):
            return list(value.values())
    nested = document.get("x402")
    if isinstance(nested, Mapping):
        return _resource_items(nested)
    return None


def parse_openapi_path_count(document: Any) -> int:
    if isinstance(document, Mapping) and isinstance(document.get("paths"), Mapping):
        return len(document["paths"])
    return parse_resource_count(document)


def extract_prices(document: Any) -> list[dict[str, Any]]:
    """Extract simple path/amount/asset price records from common resource shapes."""
    items = _resource_items(document) or []
    prices: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        path = item.get("path") or item.get("route") or item.get("url") or item.get("resource")
        price = item.get("price") or item.get("payment") or item.get("amount") or item.get("cost")
        if price is None:
            continue
        if isinstance(price, Mapping):
            amount = price.get("amount") or price.get("maxAmountRequired") or price.get("value")
            asset = price.get("asset") or price.get("currency") or price.get("token")
        else:
            amount = str(price)
            asset = None
        prices.append({"path": path, "amount": str(amount) if amount is not None else None, "asset": asset})
    return prices


def parse_agentic_market_listing(document: Any, url: str) -> dict[str, Any]:
    """Extract Agentic.Market-specific listing fields from JSON or HTML/text."""
    base = {"kind": "agentic.market", "url": url}
    if isinstance(document, Mapping):
        count = parse_resource_count(document)
        provider_url = document.get("providerUrl") or document.get("provider_url") or document.get("providerURL")
        category = document.get("category")
        enriched = document.get("enriched")
        return {
            **base,
            "indexedResourceCount": count,
            "providerUrl": provider_url,
            "category": category,
            "enriched": enriched if isinstance(enriched, bool) else None,
            "missingProviderUrl": not bool(provider_url),
            "missingCategory": not bool(category),
        }

    text = str(document or "")
    compact = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()
    count_match = re.search(r"(\d+)\s+(?:endpoint|endpoints|resource|resources)\b", compact, flags=re.IGNORECASE)
    enriched_match = re.search(r"enriched\s*[:=]\s*(true|false)", compact, flags=re.IGNORECASE)
    provider_match = re.search(r"provider\s*url\s*[:=]?\s*(https?://\S+)", compact, flags=re.IGNORECASE)
    category_match = re.search(r"category\s*[:=]\s*([A-Za-z0-9 _.-]+)", compact, flags=re.IGNORECASE)

    category = category_match.group(1).strip(" -—") if category_match else None
    if category in {"", "none", "null"}:
        category = None
    return {
        **base,
        "indexedResourceCount": int(count_match.group(1)) if count_match else 0,
        "providerUrl": provider_match.group(1).rstrip(".,)") if provider_match else None,
        "category": category,
        "enriched": (enriched_match.group(1).lower() == "true") if enriched_match else None,
        "missingProviderUrl": provider_match is None,
        "missingCategory": category is None,
    }


def scan_target(
    url: str,
    *,
    marketplace_url: str | None = None,
    expected_resources: int | None = None,
    fetcher: Fetcher = fetch_json,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    allow_private_targets: bool | None = None,
    include_agent_discovery: bool = False,
) -> dict[str, Any]:
    """Scan public x402 metadata surfaces and return a normalized product-readiness report."""
    started = time.perf_counter()
    urls = candidate_urls(url, allow_private_targets=allow_private_targets)
    normalized_marketplace_url = normalize_base_url(marketplace_url, allow_private_targets=allow_private_targets) if marketplace_url else None
    fetch_requests = {"well_known": urls.well_known, "openapi": urls.openapi}
    if include_agent_discovery:
        fetch_requests.update(
            {
                "llms_txt": urls.llms_txt,
                "agents_txt": urls.agents_txt,
                "mcp_json": urls.mcp_json,
                "mcp_endpoint": urls.mcp_endpoint,
            }
        )
    if normalized_marketplace_url:
        fetch_requests["marketplace"] = normalized_marketplace_url
    fetched = _fetch_scan_sources(fetch_requests, fetcher, timeout)
    well_known_raw = fetched["well_known"]
    openapi_raw = fetched["openapi"]

    well_known_body = well_known_raw.get("body")
    openapi_body = openapi_raw.get("body")
    well_known_count = parse_resource_count(well_known_body)
    openapi_path_count = parse_openapi_path_count(openapi_body)
    prices = extract_prices(well_known_body)

    issues: list[str] = []
    next_steps: list[str] = []
    findings: list[dict[str, Any]] = []

    def add_finding(finding: dict[str, Any]) -> None:
        findings.append(finding)
        issues.append(str(finding["message"]))
        next_steps.append(str(finding["fix"]))

    well_known_status = int(well_known_raw.get("status") or 0)
    openapi_status = int(openapi_raw.get("status") or 0)
    if well_known_status != 200:
        add_finding(
            _finding(
                "missing_x402_manifest",
                "critical",
                "/.well-known/x402",
                {"status": well_known_status},
                {"status": 200},
                "missing .well-known/x402 manifest",
                "publish /.well-known/x402 with resource and payment metadata",
                f"curl -i {urls.well_known}",
            )
        )
    if openapi_status != 200:
        add_finding(
            _finding(
                "missing_openapi_document",
                "high",
                "/openapi.json",
                {"status": openapi_status},
                {"status": 200},
                "missing OpenAPI document",
                "publish /openapi.json or include an OpenAPI URL in the manifest",
                f"curl -i {urls.openapi}",
            )
        )
    elif openapi_path_count <= 0:
        add_finding(
            _finding(
                "openapi_has_no_paths",
                "medium",
                "/openapi.json",
                {"status": openapi_status, "pathCount": openapi_path_count},
                {"pathCount": ">0"},
                "OpenAPI document has no paths",
                "publish OpenAPI paths for paid resources so agents can route calls",
                f"curl -s {urls.openapi}",
            )
        )
    if well_known_status == 200 and well_known_count <= 0:
        add_finding(
            _finding(
                "x402_manifest_has_no_resources",
                "high",
                "/.well-known/x402",
                {"status": well_known_status, "resourceCount": well_known_count},
                {"resourceCount": ">0"},
                "x402 manifest has no resources",
                "declare paid resources in /.well-known/x402",
                f"curl -s {urls.well_known}",
            )
        )
    if well_known_status == 200 and not prices:
        add_finding(
            _finding(
                "missing_price_metadata",
                "medium",
                "/.well-known/x402",
                {"priceCount": 0},
                {"priceCount": ">0"},
                "missing price metadata",
                "include price/payment metadata for each paid resource",
                f"curl -s {urls.well_known}",
            )
        )
    if expected_resources is not None and well_known_count != expected_resources:
        add_finding(
            _finding(
                "expected_resource_count_mismatch",
                "medium",
                "/.well-known/x402",
                {"resourceCount": well_known_count},
                {"resourceCount": expected_resources},
                "expected resource count mismatch",
                "reconcile expected resource count with manifest",
                f"curl -s {urls.well_known}",
                confidence="derived",
            )
        )

    marketplace_summary: dict[str, Any] | None = None
    if normalized_marketplace_url:
        market_raw = fetched.get("marketplace") or {"status": 0, "body": None}
        market_body = market_raw.get("body")
        if "agentic.market" in normalized_marketplace_url.lower():
            marketplace_summary = parse_agentic_market_listing(market_body, normalized_marketplace_url)
            marketplace_summary["status"] = market_raw.get("status", 0)
            indexed_count = int(marketplace_summary.get("indexedResourceCount") or 0)
        else:
            indexed_count = parse_resource_count(market_body)
            marketplace_summary = {
                "url": normalized_marketplace_url,
                "status": market_raw.get("status", 0),
                "indexedResourceCount": indexed_count,
            }
            if isinstance(market_body, Mapping):
                provider_url = market_body.get("providerUrl") or market_body.get("provider_url") or market_body.get("providerURL")
                category = market_body.get("category")
                marketplace_summary["providerUrl"] = provider_url
                marketplace_summary["category"] = category
                marketplace_summary["missingProviderUrl"] = not bool(provider_url)
                marketplace_summary["missingCategory"] = not bool(category)
        stale = bool(well_known_count and indexed_count != well_known_count)
        marketplace_summary["stale"] = stale
        if stale:
            add_finding(
                _finding(
                    "marketplace_resource_count_mismatch",
                    "medium",
                    "marketplace_url",
                    {"indexedResourceCount": indexed_count, "manifestResourceCount": well_known_count},
                    {"indexedResourceCount": well_known_count},
                    "marketplace resource count mismatch",
                    "request marketplace reindex or update listing resources",
                    f"curl -i {normalized_marketplace_url}",
                    confidence="derived",
                )
            )
        if marketplace_summary.get("missingProviderUrl"):
            add_finding(
                _finding(
                    "marketplace_missing_provider_url",
                    "medium",
                    "marketplace_url",
                    {"providerUrl": marketplace_summary.get("providerUrl")},
                    {"providerUrl": urls.base},
                    "marketplace missing provider URL",
                    "add provider URL to marketplace listing",
                    f"curl -i {normalized_marketplace_url}",
                )
            )
        if marketplace_summary.get("missingCategory"):
            add_finding(
                _finding(
                    "marketplace_missing_category",
                    "low",
                    "marketplace_url",
                    {"category": marketplace_summary.get("category")},
                    {"category": "declared listing category"},
                    "marketplace missing category",
                    "add marketplace category",
                    f"curl -i {normalized_marketplace_url}",
                )
            )
        if marketplace_summary.get("enriched") is False:
            add_finding(
                _finding(
                    "agentic_market_listing_not_enriched",
                    "low",
                    "marketplace_url",
                    {"enriched": False},
                    {"enriched": True},
                    "agentic.market listing is not enriched",
                    "submit enriched provider metadata to Agentic.Market",
                    f"curl -i {normalized_marketplace_url}",
                )
            )

    agent_discovery_summary: dict[str, Any] | None = None
    if include_agent_discovery:
        agent_discovery_summary = _agent_discovery_summary(urls, fetched)
        for finding in _agent_discovery_findings(agent_discovery_summary):
            add_finding(finding)

    deduped_issues = _dedupe(issues)
    score = score_scan(
        well_known_status=well_known_status,
        well_known_count=well_known_count,
        openapi_status=openapi_status,
        openapi_count=openapi_path_count,
        issue_count=len(deduped_issues),
        price_count=len(prices),
    )
    score_breakdown = _score_breakdown(
        well_known_status=well_known_status,
        well_known_count=well_known_count,
        openapi_status=openapi_status,
        openapi_count=openapi_path_count,
        price_count=len(prices),
        marketplace=marketplace_summary,
        agent_discovery=agent_discovery_summary,
    )

    result: dict[str, Any] = {
        "target": urls.base,
        "latencyMs": int((time.perf_counter() - started) * 1000),
        "wellKnown": {
            "url": urls.well_known,
            "status": well_known_raw.get("status", 0),
            "resourceCount": well_known_count,
        },
        "openapi": {
            "url": urls.openapi,
            "status": openapi_raw.get("status", 0),
            "pathCount": openapi_path_count,
        },
        "prices": prices,
        "findings": _dedupe_findings(findings),
        "issues": deduped_issues,
        "score": score,
        "scoreBreakdown": score_breakdown,
        "nextSteps": _dedupe(next_steps) or ["metadata looks ready for a basic x402 listing scan"],
    }
    if marketplace_summary is not None:
        result["marketplace"] = marketplace_summary
    if agent_discovery_summary is not None:
        result["agentDiscovery"] = agent_discovery_summary
    return result


def _fetch_scan_sources(requests: Mapping[str, str], fetcher: Fetcher, timeout: int) -> dict[str, FetchResult]:
    if not requests:
        return {}
    max_workers = max(1, len(requests))
    results: dict[str, FetchResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {key: executor.submit(fetcher, request_url, timeout) for key, request_url in requests.items()}
        for key, future in futures.items():
            request_url = requests[key]
            try:
                result = future.result()
            except Exception as exc:
                result = {"status": 0, "body": None, "error": str(exc), "url": _safe_url_for_response(request_url)}
            if int(result.get("status") or 0) == 0:
                for _attempt in range(2):
                    try:
                        retry_result = fetcher(request_url, timeout)
                        if int(retry_result.get("status") or 0) != 0:
                            result = retry_result
                            break
                    except Exception as exc:
                        result.setdefault("retryError", str(exc))
            results[key] = result
    return results


_MCP_ENDPOINT_AVAILABLE_STATUSES = {200, 204, 400, 401, 405, 406, 415}


def _agent_discovery_summary(urls: CandidateUrls, fetched: Mapping[str, FetchResult]) -> dict[str, Any]:
    surfaces = {
        "llmsTxt": _agent_text_surface(urls.llms_txt, fetched.get("llms_txt"), required_terms=("mcp", "openapi")),
        "agentsTxt": _agent_text_surface(urls.agents_txt, fetched.get("agents_txt"), required_terms=("mcp", "discovery")),
        "wellKnownMcpJson": _agent_mcp_json_surface(urls.mcp_json, fetched.get("mcp_json")),
        "mcpEndpoint": _agent_mcp_endpoint_surface(urls.mcp_endpoint, fetched.get("mcp_endpoint")),
    }
    score = 0
    if surfaces["llmsTxt"].get("available"):
        score += 25
    if surfaces["agentsTxt"].get("available"):
        score += 25
    if surfaces["wellKnownMcpJson"].get("available"):
        score += 25
    if surfaces["mcpEndpoint"].get("available"):
        score += 25
    return {
        "score": _clamp_score(score),
        "surfaces": surfaces,
        "claimBoundary": "Agent discovery checks use public GET probes only; response bodies are not included in the scan result.",
    }


def _agent_text_surface(url: str, raw: FetchResult | None, *, required_terms: tuple[str, ...]) -> dict[str, Any]:
    raw = raw or {"status": 0, "body": None}
    status = int(raw.get("status") or 0)
    body = raw.get("body")
    text = body if isinstance(body, str) else ""
    lower_text = text.lower()
    return {
        "url": url,
        "status": status,
        "available": status == 200,
        "signals": {term: term in lower_text for term in required_terms},
    }


def _agent_mcp_json_surface(url: str, raw: FetchResult | None) -> dict[str, Any]:
    raw = raw or {"status": 0, "body": None}
    status = int(raw.get("status") or 0)
    body = raw.get("body")
    is_mapping = isinstance(body, Mapping)
    tools = body.get("tools") if is_mapping else None
    tools_count = len(tools) if isinstance(tools, list) else 0
    return {
        "url": url,
        "status": status,
        "available": status == 200 and is_mapping,
        "hasUrl": bool(body.get("url")) if is_mapping else False,
        "transport": body.get("transport") if is_mapping and isinstance(body.get("transport"), str) else None,
        "toolsCount": tools_count,
    }


def _agent_mcp_endpoint_surface(url: str, raw: FetchResult | None) -> dict[str, Any]:
    raw = raw or {"status": 0, "body": None}
    status = int(raw.get("status") or 0)
    return {
        "url": url,
        "status": status,
        "available": status in _MCP_ENDPOINT_AVAILABLE_STATUSES,
    }


def _agent_discovery_findings(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    surfaces = summary.get("surfaces") if isinstance(summary.get("surfaces"), Mapping) else {}
    llms = surfaces.get("llmsTxt") if isinstance(surfaces.get("llmsTxt"), Mapping) else {}
    agents = surfaces.get("agentsTxt") if isinstance(surfaces.get("agentsTxt"), Mapping) else {}
    mcp_json = surfaces.get("wellKnownMcpJson") if isinstance(surfaces.get("wellKnownMcpJson"), Mapping) else {}
    mcp_endpoint = surfaces.get("mcpEndpoint") if isinstance(surfaces.get("mcpEndpoint"), Mapping) else {}
    findings: list[dict[str, Any]] = []
    if not llms.get("available"):
        findings.append(
            _finding(
                "missing_agent_llms_txt",
                "low",
                "/llms.txt",
                {"status": llms.get("status", 0)},
                {"status": 200},
                "missing agent llms.txt discovery file",
                "publish /llms.txt so LLM crawlers can understand the paid tool",
                f"curl -i {llms.get('url')}",
            )
        )
    if not agents.get("available"):
        findings.append(
            _finding(
                "missing_agent_agents_txt",
                "low",
                "/agents.txt",
                {"status": agents.get("status", 0)},
                {"status": 200},
                "missing agents.txt discovery file",
                "publish /agents.txt with MCP, skill, OpenAPI, and policy links",
                f"curl -i {agents.get('url')}",
            )
        )
    if not mcp_json.get("available"):
        findings.append(
            _finding(
                "missing_agent_well_known_mcp_json",
                "medium",
                "/.well-known/mcp.json",
                {"status": mcp_json.get("status", 0)},
                {"status": 200},
                "missing .well-known/mcp.json discovery file",
                "publish /.well-known/mcp.json with MCP URL, transport, and tool summaries",
                f"curl -i {mcp_json.get('url')}",
            )
        )
    elif not (mcp_json.get("hasUrl") and (mcp_json.get("transport") or int(mcp_json.get("toolsCount") or 0) > 0)):
        findings.append(
            _finding(
                "agent_mcp_discovery_incomplete",
                "low",
                "/.well-known/mcp.json",
                {"hasUrl": bool(mcp_json.get("hasUrl")), "transport": mcp_json.get("transport"), "toolsCount": int(mcp_json.get("toolsCount") or 0)},
                {"hasUrl": True, "transport": "streamable-http", "toolsCount": ">0"},
                ".well-known/mcp.json missing core MCP discovery fields",
                "include MCP URL, transport, and tool summaries in /.well-known/mcp.json",
                f"curl -s {mcp_json.get('url')}",
            )
        )
    if not mcp_endpoint.get("available"):
        findings.append(
            _finding(
                "missing_agent_mcp_endpoint",
                "medium",
                "/mcp",
                {"status": mcp_endpoint.get("status", 0)},
                {"status": sorted(_MCP_ENDPOINT_AVAILABLE_STATUSES)},
                "MCP endpoint not reachable at /mcp",
                "serve an MCP endpoint at /mcp or link the canonical MCP endpoint from /.well-known/mcp.json",
                f"curl -i {mcp_endpoint.get('url')}",
            )
        )
    return findings


def _finding(
    finding_id: str,
    severity: str,
    source: str,
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    message: str,
    fix: str,
    retest: str,
    *,
    confidence: str = "observed",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "source": source,
        "confidence": confidence,
        "observed": dict(observed),
        "expected": dict(expected),
        "message": message,
        "fix": fix,
        "retest": retest,
    }


def _score_breakdown(
    *,
    well_known_status: int,
    well_known_count: int,
    openapi_status: int,
    openapi_count: int,
    price_count: int,
    marketplace: Mapping[str, Any] | None,
    agent_discovery: Mapping[str, Any] | None,
) -> dict[str, Any]:
    metadata_reasons: list[str] = []
    metadata_score = 100
    if well_known_status != 200:
        metadata_score -= 55
        metadata_reasons.append("x402 manifest not observed")
    if well_known_count <= 0:
        metadata_score -= 25
        metadata_reasons.append("no x402 resources observed")
    if price_count <= 0:
        metadata_score -= 20
        metadata_reasons.append("no price metadata observed")

    documentation_reasons: list[str] = []
    documentation_score = 100
    if openapi_status != 200:
        documentation_score -= 70
        documentation_reasons.append("OpenAPI document not observed")
    if openapi_count <= 0:
        documentation_score -= 30
        documentation_reasons.append("no OpenAPI paths observed")

    marketplace_score: int | None = None
    marketplace_reasons: list[str] = []
    if marketplace is not None:
        marketplace_score = 100
        if marketplace.get("stale"):
            marketplace_score -= 40
            marketplace_reasons.append("marketplace resource count differs from manifest")
        if marketplace.get("missingProviderUrl"):
            marketplace_score -= 20
            marketplace_reasons.append("marketplace provider URL missing")
        if marketplace.get("missingCategory"):
            marketplace_score -= 20
            marketplace_reasons.append("marketplace category missing")
        if marketplace.get("enriched") is False:
            marketplace_score -= 20
            marketplace_reasons.append("marketplace enrichment not observed")

    agent_discovery_score: int | None = None
    agent_discovery_reasons: list[str] = []
    if agent_discovery is not None:
        agent_discovery_score = _clamp_score(int(agent_discovery.get("score") or 0))
        surfaces = agent_discovery.get("surfaces") if isinstance(agent_discovery.get("surfaces"), Mapping) else {}
        expected = (
            ("llmsTxt", "llms.txt not observed"),
            ("agentsTxt", "agents.txt not observed"),
            ("wellKnownMcpJson", ".well-known/mcp.json not observed"),
            ("mcpEndpoint", "MCP endpoint not reachable"),
        )
        for key, reason in expected:
            surface = surfaces.get(key) if isinstance(surfaces.get(key), Mapping) else {}
            if not surface.get("available"):
                agent_discovery_reasons.append(reason)

    return {
        "metadata": {"score": _clamp_score(metadata_score), "reasons": metadata_reasons or ["x402 manifest/resources/prices observed"]},
        "documentation": {"score": _clamp_score(documentation_score), "reasons": documentation_reasons or ["OpenAPI document and paths observed"]},
        "marketplace": None if marketplace_score is None else {"score": _clamp_score(marketplace_score), "reasons": marketplace_reasons or ["marketplace listing appears in sync"]},
        "agentDiscovery": None if agent_discovery_score is None else {"score": agent_discovery_score, "reasons": agent_discovery_reasons or ["llms.txt, agents.txt, MCP discovery, and MCP endpoint observed"]},
        "confidence": {
            "score": 100,
            "reasons": ["public metadata and unpaid checks only; no settlement/downstream execution claims"],
        },
    }


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for finding in findings:
        key = (str(finding.get("id")), str(finding.get("source")), str(finding.get("message")))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def score_scan(*, well_known_status: int, well_known_count: int, openapi_status: int, openapi_count: int, issue_count: int, price_count: int) -> int:
    score = 100
    if well_known_status != 200:
        score -= 35
    if openapi_status != 200:
        score -= 20
    if well_known_count <= 0:
        score -= 20
    if openapi_count <= 0:
        score -= 10
    if price_count <= 0:
        score -= 10
    score -= min(issue_count * 5, 25)
    return max(0, min(100, score))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
