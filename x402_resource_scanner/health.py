"""x402 paid-path health probe core.

The probe performs a conservative unpaid request against a public target endpoint
and checks whether the target still returns a parseable x402 HTTP 402 challenge.
It does not sign payments, spend funds, send credentials, or prove downstream
execution.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping

from .receipt import create_receipt
from .scanner import USER_AGENT, normalize_base_url
from .x402_payment import SOLANA_MAINNET_USDC, decode_x402_header

DEFAULT_TIMEOUT_SECONDS = 8
SAFE_UNPAID_METHODS = {"GET", "HEAD", "OPTIONS"}
BASE_MAINNET_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
USDC_ASSETS = {BASE_MAINNET_USDC, BASE_SEPOLIA_USDC, SOLANA_MAINNET_USDC.lower(), "usdc"}

FetchResult = dict[str, Any]
HealthFetcher = Callable[[str, str, int], FetchResult]


def validate_probe_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return normalized probe request fields or raise ValueError.

    This function is intentionally fetch-free so API callers are not charged for
    malformed/private targets before x402 payment verification.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")
    raw_target = str(payload.get("target") or payload.get("url") or "")
    _ensure_no_url_credentials(raw_target)
    display_target = normalize_base_url(raw_target)
    query = _parse_safe_query(payload.get("query") or payload.get("safeQuery") or payload.get("queryParams"))
    target = _append_query(display_target, query)
    method = str(payload.get("method") or "GET").strip().upper()
    if not method:
        method = "GET"
    if method not in SAFE_UNPAID_METHODS:
        raise ValueError(f"{method} probes are disabled by default")
    mode = str(payload.get("mode") or "unpaid_402").strip().lower()
    if mode not in {"unpaid_402", "metadata_only"}:
        raise ValueError("mode must be unpaid_402 or metadata_only in v1")
    expected = payload.get("expected") or {}
    if expected is not None and not isinstance(expected, Mapping):
        raise ValueError("expected must be a JSON object when provided")
    return {"target": target, "displayTarget": display_target, "queryKeys": sorted(query), "method": method, "mode": mode, "expected": dict(expected or {})}


def probe_paid_path(
    payload: Mapping[str, Any],
    *,
    fetcher: HealthFetcher | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Probe an x402 endpoint's unpaid paid-path health."""
    fetch = fetcher or fetch_unpaid_target
    try:
        normalized = validate_probe_request(payload)
    except ValueError as exc:
        method = str((payload or {}).get("method") or "GET").strip().upper() if isinstance(payload, Mapping) else "GET"
        target = _safe_target(payload) if isinstance(payload, Mapping) else None
        return _build_probe_payload(
            target=target,
            method=method,
            mode=str((payload or {}).get("mode") or "unpaid_402") if isinstance(payload, Mapping) else "unpaid_402",
            expected=dict((payload or {}).get("expected") or {}) if isinstance(payload, Mapping) and isinstance((payload or {}).get("expected") or {}, Mapping) else {},
            observed={"status": None},
            requirements=None,
            issues=[str(exc)],
            fixes=["use a public http(s) target and a safe unpaid method (GET/HEAD/OPTIONS) for v1 probes"],
        )

    target = normalized["target"]
    display_target = str(normalized.get("displayTarget") or normalize_base_url(str(target)))
    method = normalized["method"]
    mode = normalized["mode"]
    expected = normalized["expected"]

    response = fetch(target, method, timeout)
    if _safe_int(response.get("status")) == 0:
        for _attempt in range(2):
            retry_response = fetch(target, method, timeout)
            if _safe_int(retry_response.get("status")) != 0:
                response = retry_response
                break
    observed_status = _safe_int(response.get("status"))
    requirement, parse_issue = _extract_payment_requirement(response)
    observed = _observed_fields(observed_status, requirement)
    if response.get("url"):
        observed["finalUrlHost"] = _host_only(str(response.get("url")))

    issues: list[str] = []
    fixes: list[str] = []
    if observed_status != 402:
        issues.append(f"expected unpaid x402 response status 402, observed {observed_status}")
        fixes.append("ensure the paid endpoint returns HTTP 402 before running handler logic when no payment is supplied")
    if parse_issue:
        issues.append(parse_issue)
        fixes.append("return a valid PAYMENT-REQUIRED header or JSON body with an accepts/payment requirement object")

    mismatch_issues, mismatch_fixes = _expected_mismatches(expected, observed)
    issues.extend(mismatch_issues)
    fixes.extend(mismatch_fixes)

    return _build_probe_payload(
        target=display_target,
        method=method,
        mode=mode,
        expected=expected,
        observed=observed,
        requirements=requirement,
        issues=_dedupe(issues),
        fixes=_dedupe(fixes),
    )


class _NoRedirectHandler:
    """Compatibility sentinel documenting that v1 never follows redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _parse_url_for_probe(raw_url: str) -> urllib.parse.ParseResult:
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
    return parsed


def _ensure_no_url_credentials(raw_url: str) -> None:
    parsed = _parse_url_for_probe(raw_url)
    if parsed.username or parsed.password:
        raise ValueError("target URL must not include username or password")


def _parse_safe_query(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("query must be a JSON object when provided")
    query: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        if not key:
            raise ValueError("query keys must be non-empty")
        lowered = key.lower()
        if any(marker in lowered for marker in ("auth", "token", "secret", "password", "cookie", "signature", "key")):
            raise ValueError("query must not include credential-like keys")
        if isinstance(raw_value, (list, tuple)):
            query[key] = [str(item) for item in raw_value if item not in (None, "")]
        elif raw_value not in (None, ""):
            query[key] = str(raw_value)
    return query


def _append_query(base_url: str, query: Mapping[str, Any]) -> str:
    if not query:
        return base_url
    encoded = urllib.parse.urlencode(query, doseq=True)
    separator = "&" if urllib.parse.urlparse(base_url).query else "?"
    return f"{base_url}{separator}{encoded}"


def _resolve_public_endpoint(url: str) -> tuple[urllib.parse.ParseResult, ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    parsed = _parse_url_for_probe(url)
    if parsed.username or parsed.password:
        raise ValueError("target URL must not include username or password")
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
        except ValueError:
            raise ValueError(f"could not parse resolved target address: {raw_address}")
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
            parsed = _parse_url_for_probe(url)
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


def _fetch_via_pinned_ip(parsed: urllib.parse.ParseResult, address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, method: str, timeout: int) -> FetchResult:
    hostname = parsed.hostname or ""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/problem+json, */*"}
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
        conn.request(method, _request_target(parsed), headers=headers)
        response = conn.getresponse()
        raw = response.read(250_000) if method != "HEAD" else b""
        return {
            "status": int(response.status),
            "headers": dict(response.getheaders()),
            "body": _loads_json_or_text(raw.decode("utf-8", errors="replace")),
            "url": _safe_url_for_response(urllib.parse.urlunparse(parsed)),
        }
    finally:
        conn.close()


def fetch_unpaid_target(url: str, method: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> FetchResult:
    """Fetch a target endpoint without payment credentials and capture 402 headers."""
    try:
        parsed, address, port = _resolve_public_endpoint(url)
        return _fetch_via_pinned_ip(parsed, address, port, method, timeout)
    except Exception as exc:
        return {"status": 0, "headers": {}, "body": None, "error": str(exc), "url": _safe_url_for_response(url)}


def _extract_payment_requirement(response: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    headers = {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}
    header_value = headers.get("payment-required") or headers.get("x-payment-required")
    header_payload: Any = None
    if header_value:
        try:
            header_payload = decode_x402_header(header_value)
        except Exception as exc:
            return None, f"could not decode PAYMENT-REQUIRED header: {exc}"
    source = header_payload if header_payload is not None else response.get("body")
    requirement = _first_requirement(source)
    if requirement is None:
        return None, "payment requirements were not found in PAYMENT-REQUIRED header or JSON body"
    return requirement, None


def _first_requirement(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list):
        for item in value:
            found = _first_requirement(item)
            if found is not None:
                return found
        return None
    if not isinstance(value, Mapping):
        return None
    accepts = value.get("accepts") or value.get("paymentRequirements") or value.get("requirements")
    if isinstance(accepts, list):
        for item in accepts:
            found = _first_requirement(item)
            if found is not None:
                return found
    if isinstance(accepts, Mapping):
        found = _first_requirement(accepts)
        if found is not None:
            return found
    if any(key in value for key in ("network", "asset", "amount", "maxAmountRequired", "payTo", "scheme")):
        return dict(value)
    nested = value.get("x402")
    if isinstance(nested, (Mapping, list)):
        return _first_requirement(nested)
    return None


def _observed_fields(status: int | None, requirement: Mapping[str, Any] | None) -> dict[str, Any]:
    requirement = requirement or {}
    amount = _first_string(requirement.get("amount"), requirement.get("maxAmountRequired"), _nested(requirement, "price", "amount"))
    asset = _first_string(requirement.get("asset"), _nested(requirement, "price", "asset"), requirement.get("currency"))
    network = _first_string(requirement.get("network"), requirement.get("chainId"), requirement.get("chain"))
    return {
        "status": status,
        "network": network,
        "asset": asset,
        "assetSymbol": _asset_symbol(asset),
        "amountAtomic": amount,
        "priceUsd": _atomic_to_usdc(amount),
        "scheme": _first_string(requirement.get("scheme")),
        "payToPresent": bool(requirement.get("payTo") or requirement.get("pay_to")),
        "requirementsParsed": bool(requirement),
    }


def _expected_mismatches(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    fixes: list[str] = []
    expected_network = _first_string(expected.get("network"), expected.get("chain"))
    if expected_network and observed.get("network") != expected_network:
        issues.append(f"expected network {expected_network}, observed {observed.get('network')}")
        fixes.append("update the route network or listing expectation so paid-path metadata matches")
    expected_asset = _first_string(expected.get("asset"), expected.get("currency"), expected.get("token"))
    if expected_asset and not _asset_matches(expected_asset, _first_string(observed.get("asset")), _first_string(observed.get("assetSymbol"))):
        issues.append(f"expected asset {expected_asset}, observed {observed.get('asset') or observed.get('assetSymbol')}")
        fixes.append("update the route asset or listing expectation so paid-path metadata matches")
    expected_price = _first_string(expected.get("priceUsd"), expected.get("price_usd"), expected.get("amountUsd"), expected.get("amount"))
    if expected_price and not _decimal_matches(expected_price, _first_string(observed.get("priceUsd"))):
        issues.append(f"expected priceUsd {expected_price}, observed {observed.get('priceUsd')}")
        fixes.append("update the route price or listing expectation so health probes and marketplace metadata agree")
    return issues, fixes


def _build_probe_payload(
    *,
    target: str | None,
    method: str,
    mode: str,
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    requirements: Mapping[str, Any] | None = None,
    issues: list[str],
    fixes: list[str],
) -> dict[str, Any]:
    returns_402 = observed.get("status") == 402
    parsed = bool(observed.get("requirementsParsed"))
    checks = {
        "returns402WhenUnpaid": returns_402,
        "paymentRequirementsParsed": parsed,
        "networkMatches": _match_or_none(expected, observed, "network"),
        "assetMatches": _asset_match_or_none(expected, observed),
        "priceMatches": _price_match_or_none(expected, observed),
        "settlementObserved": None,
    }
    healthy = bool(returns_402 and parsed and all(value is not False for value in checks.values()))
    decision = "allow" if healthy else "review"
    receipt = create_receipt(
        {
            "request": {"target": target, "method": method, "mode": mode, "expected": dict(expected)},
            "policy": {"decision": decision, "reason": "x402 paid-path health probe"},
            "result": {"healthy": healthy, "checks": checks, "observed": dict(observed), "issues": issues},
            "nextStep": fixes[0] if fixes else "store this health receipt with the seller's endpoint monitoring log",
        },
        payment_observed=False,
    )
    return {
        "target": target,
        "method": method,
        "mode": mode,
        "healthy": healthy,
        "checks": checks,
        "observed": {key: value for key, value in dict(observed).items() if key != "requirementsParsed" and (value is not None or key == "status")},
        "issues": issues,
        "recommendedFixes": fixes,
        "receipt": receipt,
        "claimBoundary": "Health Probe v1 verifies the unpaid x402 challenge shape only; it does not sign payments, spend funds, or prove downstream execution.",
    }


def _match_or_none(expected: Mapping[str, Any], observed: Mapping[str, Any], key: str) -> bool | None:
    expected_value = _first_string(expected.get(key))
    if not expected_value:
        return None
    return observed.get(key) == expected_value


def _asset_match_or_none(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool | None:
    expected_asset = _first_string(expected.get("asset"), expected.get("currency"), expected.get("token"))
    if not expected_asset:
        return None
    return _asset_matches(expected_asset, _first_string(observed.get("asset")), _first_string(observed.get("assetSymbol")))


def _price_match_or_none(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool | None:
    expected_price = _first_string(expected.get("priceUsd"), expected.get("price_usd"), expected.get("amountUsd"), expected.get("amount"))
    if not expected_price:
        return None
    return _decimal_matches(expected_price, _first_string(observed.get("priceUsd")))


def _asset_matches(expected: str, observed_asset: str | None, observed_symbol: str | None) -> bool:
    exp = expected.strip().lower()
    if exp == "usdc":
        return observed_symbol == "USDC" or (observed_asset or "").strip().lower() in USDC_ASSETS
    return exp == (observed_asset or "").strip().lower()


def _asset_symbol(asset: str | None) -> str | None:
    if not asset:
        return None
    value = str(asset).strip().lower()
    if value in USDC_ASSETS:
        return "USDC"
    return None


def _atomic_to_usdc(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    try:
        return f"{(Decimal(str(value)) / Decimal(1_000_000)):.6f}"
    except (InvalidOperation, ValueError):
        return None


def _decimal_matches(expected: str, observed: str | None) -> bool:
    if observed is None:
        return False
    try:
        return Decimal(str(expected)) == Decimal(str(observed))
    except (InvalidOperation, ValueError):
        return False


def _loads_json_or_text(text: str) -> Any:
    if not text:
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _nested(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first_string(*values: Any) -> str | None:
    for value in values:
        if value not in (None, ""):
            return str(value)
    return None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_target(payload: Mapping[str, Any]) -> str | None:
    try:
        raw_target = str(payload.get("target") or payload.get("url") or "")
        _ensure_no_url_credentials(raw_target)
        return normalize_base_url(raw_target)
    except ValueError:
        return None


def _host_only(value: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return None
    return parsed.hostname.lower() if parsed.hostname else None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output
