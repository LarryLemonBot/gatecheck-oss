"""x402 payment gate helpers for the scanner service.

This keeps the core HTTP flow stdlib-only so the small Vercel Python deployment
does not require framework-specific x402 middleware. CDP facilitator auth is
loaded only when the CDP facilitator URL is configured. It implements the
current x402 HTTP facilitator contract used by the TypeScript SDK:

- unpaid API calls return HTTP 402 plus a base64 `PAYMENT-REQUIRED` header when
  a real pay-to address is configured;
- clients send a base64 `PAYMENT-SIGNATURE` header;
- the server calls facilitator `/verify`, runs the protected work, then calls
  facilitator `/settle` and returns a base64 `PAYMENT-RESPONSE` header.

Demo/stub unlock is only available when explicitly enabled with
`X402_ALLOW_STUB_BYPASS=true` or by passing `allow_stub_bypass=True` in tests.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

X402_VERSION = 2
DEFAULT_FACILITATOR_URL = "https://www.x402.org/facilitator"
DEFAULT_NETWORK = "eip155:84532"
BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_MAINNET_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
DEFAULT_MAX_TIMEOUT_SECONDS = 300
FACILITATOR_SOURCE = "x402-resource-scanner"
FACILITATOR_SOURCE_VERSION = "0.1.0"
PUBLIC_CANONICAL_BASE_URL = "https://proofbeforepay.vercel.app"
LEGACY_CANONICAL_HOSTS = {
    "x402-resource-scanner.vercel.app",
    "x402-resource-scanner-orbitals-projects.vercel.app",
    "x402proof.vercel.app",
    "x402ready.vercel.app",
}

FacilitatorPost = Callable[[str, Mapping[str, Any], int], dict[str, Any]]


@dataclass(frozen=True)
class PaymentResource:
    path: str
    method: str
    price_usdc: str
    description: str
    mime_type: str = "application/json"
    resource_url: str | None = None

    @property
    def url(self) -> str:
        if self.resource_url:
            return self.resource_url
        base_url = _canonical_payment_base_url()
        if base_url and self.path.startswith("/"):
            return f"{base_url}{self.path}"
        return self.path


@dataclass
class PaymentSession:
    allowed: bool
    mode: str
    status_code: int = 402
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: dict[str, Any] = field(default_factory=dict)
    payment_payload: dict[str, Any] | None = None
    requirements: dict[str, Any] | None = None
    verify_response: dict[str, Any] | None = None
    settlement_response: dict[str, Any] | None = None
    configuration_required: bool = False

    @classmethod
    def allowed_session(
        cls,
        *,
        mode: str,
        payment_payload: dict[str, Any] | None = None,
        requirements: dict[str, Any] | None = None,
        verify_response: dict[str, Any] | None = None,
        configuration_required: bool = False,
    ) -> "PaymentSession":
        return cls(
            allowed=True,
            mode=mode,
            status_code=200,
            payment_payload=payment_payload,
            requirements=requirements,
            verify_response=verify_response,
            configuration_required=configuration_required,
        )

    def summary(self) -> dict[str, Any]:
        if self.mode == "facilitator":
            settle = self.settlement_response or {}
            verify = self.verify_response or {}
            return {
                "mode": "x402-facilitator",
                "validated": True,
                "settled": bool(settle.get("success")),
                "payer": settle.get("payer") or verify.get("payer"),
                "network": settle.get("network") or (self.requirements or {}).get("network"),
                "transaction": settle.get("transaction"),
                "amount": settle.get("amount") or (self.requirements or {}).get("amount"),
                "claimBoundary": "Payment was verified and settled through the configured x402 facilitator for this endpoint call.",
            }
        return {
            "stubAccepted": True,
            "validated": False,
            "settled": False,
            "mode": "stub-demo-only",
            "configurationRequired": self.configuration_required,
            "claimBoundary": "Presence of a demo payment header only unlocks this demo endpoint; no facilitator settlement validation was performed.",
        }


class PaymentSettlementError(Exception):
    def __init__(self, message: str, *, response: dict[str, Any] | None = None):
        super().__init__(message)
        self.response = response or {}


class X402PaymentGate:
    def __init__(
        self,
        *,
        pay_to: str | None | object = ...,  # sentinel: read env unless caller explicitly passes None
        facilitator_url: str | None = None,
        network: str | None = None,
        asset: str | None = None,
        solana_pay_to: str | None | object = ...,  # sentinel: read env unless caller explicitly passes None
        solana_network: str | None = None,
        solana_asset: str | None = None,
        max_timeout_seconds: int = DEFAULT_MAX_TIMEOUT_SECONDS,
        allow_stub_bypass: bool | None = None,
        facilitator_post: FacilitatorPost | None = None,
        cdp_api_key_id: str | None = None,
        cdp_api_key_secret: str | None = None,
        timeout: int = 8,
    ) -> None:
        if pay_to is ...:
            pay_to_value = os.getenv("X402_PAY_TO_ADDRESS") or os.getenv("X402_PAY_TO")
        else:
            pay_to_value = pay_to
        if solana_pay_to is ...:
            solana_pay_to_value = os.getenv("X402_SOLANA_PAY_TO_ADDRESS") or os.getenv("X402_SOLANA_PAY_TO")
        else:
            solana_pay_to_value = solana_pay_to
        self.pay_to = str(pay_to_value).strip() if pay_to_value else None
        self.solana_pay_to = str(solana_pay_to_value).strip() if solana_pay_to_value else None
        self.facilitator_url = str(facilitator_url or os.getenv("X402_FACILITATOR_URL") or DEFAULT_FACILITATOR_URL).strip().rstrip("/")
        self.network = str(network or os.getenv("X402_NETWORK") or DEFAULT_NETWORK).strip()
        self.asset = str(asset or os.getenv("X402_ASSET") or BASE_SEPOLIA_USDC).strip()
        self.solana_network = str(solana_network or os.getenv("X402_SOLANA_NETWORK") or SOLANA_MAINNET).strip()
        self.solana_asset = str(solana_asset or os.getenv("X402_SOLANA_ASSET") or SOLANA_MAINNET_USDC).strip()
        self.max_timeout_seconds = max_timeout_seconds
        self.timeout = timeout
        self._facilitator_post = facilitator_post
        self.cdp_api_key_id = str(cdp_api_key_id or os.getenv("CDP_API_KEY_ID") or "").strip()
        self.cdp_api_key_secret = str(cdp_api_key_secret or os.getenv("CDP_API_KEY_SECRET") or "").strip()
        if allow_stub_bypass is None:
            allow_stub_bypass = _env_bool("X402_ALLOW_STUB_BYPASS", default=False)
        if os.getenv("VERCEL_ENV", "").strip().lower() == "production":
            allow_stub_bypass = False
        self.allow_stub_bypass = allow_stub_bypass

    @classmethod
    def from_environment(cls) -> "X402PaymentGate":
        return cls()

    def begin(self, resource: PaymentResource, request_headers: Mapping[str, str] | None = None) -> PaymentSession:
        headers = _lower_headers(request_headers)
        payment_signature = headers.get("payment-signature")

        if payment_signature:
            if not self.pay_to and not self.solana_pay_to:
                return self._configuration_required(resource)
            try:
                payment_payload = decode_x402_header(payment_signature)
            except Exception as exc:
                return self._payment_required(resource, error=f"Invalid PAYMENT-SIGNATURE header: {exc}")

            requirements = self._requirements_for_payment_payload(resource, payment_payload)
            if requirements is None:
                return self._payment_required(resource, error="Payment signature did not match any accepted payment requirement")
            verify_payload = {
                "x402Version": int(payment_payload.get("x402Version") or X402_VERSION),
                "paymentPayload": payment_payload,
                "paymentRequirements": facilitator_payment_requirements(requirements),
            }
            verify_response = self._post_facilitator("/verify", verify_payload)
            if not verify_response.get("isValid"):
                reason = verify_response.get("invalidReason") or verify_response.get("invalidMessage") or "Payment verification failed"
                return self._payment_required(resource, error=str(reason))
            return PaymentSession.allowed_session(
                mode="facilitator",
                payment_payload=payment_payload,
                requirements=requirements,
                verify_response=verify_response,
            )

        if self.allow_stub_bypass and _has_demo_payment(headers):
            return PaymentSession.allowed_session(
                mode="stub-demo-only",
                configuration_required=not bool(self.pay_to),
            )

        if not self.pay_to and not self.solana_pay_to:
            return self._stub_payment_required(resource)
        return self._payment_required(resource, error="Payment required")

    def settle(self, session: PaymentSession) -> tuple[dict[str, str], dict[str, Any]]:
        if not session.allowed:
            return {}, session.summary()
        if session.mode != "facilitator":
            return {}, session.summary()
        if not session.payment_payload or not session.requirements:
            raise PaymentSettlementError("Payment session is missing facilitator settlement data")
        settle_payload = {
            "x402Version": int(session.payment_payload.get("x402Version") or X402_VERSION),
            "paymentPayload": session.payment_payload,
            "paymentRequirements": facilitator_payment_requirements(session.requirements),
        }
        settle_response = self._post_facilitator("/settle", settle_payload)
        session.settlement_response = settle_response
        headers = {"PAYMENT-RESPONSE": encode_x402_header(settle_response)}
        if not settle_response.get("success"):
            raise PaymentSettlementError(
                str(settle_response.get("errorMessage") or settle_response.get("errorReason") or "Payment settlement failed"),
                response=settle_response,
            )
        return headers, session.summary()

    def payment_requirements(self, resource: PaymentResource) -> dict[str, Any]:
        return {
            "scheme": "exact",
            "network": self.network,
            "asset": self.asset,
            "amount": price_to_atomic_units(resource.price_usdc),
            "payTo": self.pay_to or "stub-only-no-wallet-configured",
            "resource": resource.url,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": _asset_extra(self.network, self.asset),
        }

    def solana_payment_requirements(self, resource: PaymentResource) -> dict[str, Any]:
        return {
            "scheme": "exact",
            "network": self.solana_network,
            "asset": self.solana_asset,
            "amount": price_to_atomic_units(resource.price_usdc),
            "payTo": self.solana_pay_to or "stub-only-no-solana-wallet-configured",
            "resource": resource.url,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": _asset_extra(self.solana_network, self.solana_asset),
        }

    def payment_requirement_options(self, resource: PaymentResource) -> list[dict[str, Any]]:
        options: list[dict[str, Any]] = []
        if self.solana_pay_to:
            options.append(self.solana_payment_requirements(resource))
        if self.pay_to:
            primary = self.payment_requirements(resource)
            if not any(_requirements_equivalent(primary, existing) for existing in options):
                options.append(primary)
        if not options:
            primary = self.payment_requirements(resource)
            options.append(primary)
        return options

    def payment_required_payload(self, resource: PaymentResource, *, error: str = "Payment required") -> dict[str, Any]:
        service_metadata = _service_metadata_for_resource(resource)
        resource_metadata = {
            "url": resource.url,
            "method": resource.method,
            "description": resource.description,
            "mimeType": resource.mime_type,
            **service_metadata,
        }
        payload = {
            "x402Version": X402_VERSION,
            "error": error,
            "resource": resource_metadata,
            "accepts": self.payment_requirement_options(resource),
        }
        bazaar_metadata = bazaar_discovery_metadata(resource)
        if bazaar_metadata:
            resource_metadata["extensions"] = {"bazaar": bazaar_metadata}
        bazaar_extension = bazaar_discovery_extension(resource)
        if bazaar_extension:
            payload["extensions"] = bazaar_extension
        return payload

    def _payment_required(self, resource: PaymentResource, *, error: str) -> PaymentSession:
        payload = self.payment_required_payload(resource, error=error)
        return PaymentSession(
            allowed=False,
            mode="x402-facilitator",
            status_code=402,
            response_headers={"PAYMENT-REQUIRED": encode_x402_header(payload), "x402-gate-mode": "facilitator"},
            response_body=payload,
        )

    def _stub_payment_required(self, resource: PaymentResource) -> PaymentSession:
        resource_metadata = {
            "url": resource.url,
            "method": resource.method,
            "description": resource.description,
            "mimeType": resource.mime_type,
            **_service_metadata_for_resource(resource),
        }
        payload = {
            "error": "x402 payment required",
            "x402Version": X402_VERSION,
            "stub": True,
            "configured": False,
            "resource": resource_metadata,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:84532",
                    "resource": resource.path,
                    "method": resource.method,
                    "description": resource.description,
                    "price": {"amount": resource.price_usdc, "asset": "USDC"},
                    "payTo": "stub-only-no-wallet-configured",
                    "mimeType": resource.mime_type,
                }
            ],
            "demo": {
                "howToBypassStub": "Send header X-PAYMENT: stub-paid-demo. This does not validate settlement; it only exercises the paid path.",
                "nextProductionStep": "Set X402_PAY_TO_ADDRESS or X402_SOLANA_PAY_TO_ADDRESS and disable stub bypass to require real PAYMENT-SIGNATURE verification and facilitator settlement.",
            },
        }
        return PaymentSession(
            allowed=False,
            mode="stub-demo-only",
            status_code=402,
            response_headers={"x402-stub": "payment-required", "x402-gate-mode": "stub-demo-only"},
            response_body=payload,
            configuration_required=True,
        )

    def _configuration_required(self, resource: PaymentResource) -> PaymentSession:
        session = self._stub_payment_required(resource)
        session.response_body["error"] = "x402 pay-to address is not configured"
        return session

    def _requirements_for_payment_payload(self, resource: PaymentResource, payment_payload: Mapping[str, Any]) -> dict[str, Any] | None:
        accepted = payment_payload.get("accepted") or payment_payload.get("paymentRequirements") or payment_payload.get("payment_requirement")
        if not isinstance(accepted, Mapping):
            return self.payment_requirements(resource)
        for requirements in self.payment_requirement_options(resource):
            if _requirements_equivalent(accepted, requirements):
                return requirements
        return None

    def _post_facilitator(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if self._facilitator_post:
            return self._facilitator_post(path, payload, self.timeout)
        url = f"{self.facilitator_url}{path}"
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"content-type": "application/json", **self._facilitator_auth_headers("POST", path)}
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text = response.read(1_000_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            text = exc.read(250_000).decode("utf-8", errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError as parse_exc:
                raise PaymentSettlementError(f"Facilitator {path} failed ({exc.code}): {text[:180]}") from parse_exc
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PaymentSettlementError(f"Facilitator {path} returned invalid JSON: {text[:180]}") from exc
        if not isinstance(parsed, dict):
            raise PaymentSettlementError(f"Facilitator {path} returned non-object JSON")
        return parsed

    def _facilitator_auth_headers(self, method: str, path: str) -> dict[str, str]:
        if not _uses_cdp_facilitator(self.facilitator_url):
            return {}
        if not self.cdp_api_key_id or not self.cdp_api_key_secret:
            raise PaymentSettlementError(
                "CDP facilitator requires CDP_API_KEY_ID and CDP_API_KEY_SECRET; no payment was settled"
            )
        try:
            from cdp.auth import GetAuthHeadersOptions, get_auth_headers
        except ImportError as exc:
            raise PaymentSettlementError(
                "CDP facilitator support requires cdp-sdk; no payment was settled"
            ) from exc

        parsed = urlparse(self.facilitator_url)
        base_path = parsed.path.rstrip("/")
        return dict(
            get_auth_headers(
                GetAuthHeadersOptions(
                    api_key_id=self.cdp_api_key_id,
                    api_key_secret=self.cdp_api_key_secret,
                    request_method=method,
                    request_host=parsed.netloc,
                    request_path=f"{base_path}{path}",
                    source=FACILITATOR_SOURCE,
                    source_version=FACILITATOR_SOURCE_VERSION,
                )
            )
        )


def bazaar_discovery_metadata(resource: PaymentResource) -> dict[str, Any] | None:
    """Return CDP Bazaar discovery metadata for flagship paid routes."""
    service = {
        "id": "x402-resource-scanner",
        "name": "GateCheck by LarryBuildsAI",
        "legacyName": "Boundary Guard x402",
        "aliases": ["Agent Tool Readiness Checker by LarryBuildsAI", "x402 Resource Scanner", "x402 Launch Pack Generator"],
        "provider": "LarryBuildsAI",
        "providerName": "LarryBuildsAI",
        "providerUrl": "https://proofbeforepay.vercel.app",
        "homepageUrl": "https://proofbeforepay.vercel.app",
        "docsUrl": "https://proofbeforepay.vercel.app/llms.txt",
        "openapiUrl": "https://proofbeforepay.vercel.app/openapi.json",
        "x402WellKnownUrl": "https://proofbeforepay.vercel.app/.well-known/x402",
        "mcpUrl": "https://proofbeforepay.vercel.app/gatecheck/mcp",
        "legacyMcpUrl": "https://proofbeforepay.vercel.app/mcp",
        "category": "Agent Verification & Security",
        "discoverable": True,
    }
    common = {
        "discoverable": True,
        "category": "Agent Verification & Security",
        "provider": "LarryBuildsAI",
        "providerName": "LarryBuildsAI",
        "providerUrl": service["providerUrl"],
        "homepageUrl": service["homepageUrl"],
        "docsUrl": service["docsUrl"],
        "openapiUrl": service["openapiUrl"],
        "x402WellKnownUrl": service["x402WellKnownUrl"],
        "mcpUrl": service["mcpUrl"],
        "service": service,
        "tags": [
            "x402",
            "MCP",
            "agent-tools",
            "paid-api",
            "seller-readiness",
            "marketplace-readiness",
            "launch-pack",
        ],
    }
    if resource.path == "/v1/x402/agent-tools/readiness":
        return {
            **common,
            "name": "GateCheck Readiness by LarryBuildsAI",
            "description": "LarryBuildsAI readiness checks for x402 and MCP paid-tool launches: public metadata, unpaid 402 probes, agent-discovery checks, launch-pack guidance, and claim boundaries before marketplace listing.",
            "bodyType": "json",
            "method": "POST",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "format": "uri", "description": "Public x402/API/MCP service URL to inspect."},
                    "tier": {"type": "string", "enum": ["quick", "deep", "report"], "default": "quick"},
                    "expected_resources": {"type": "integer", "minimum": 0},
                    "marketplace_url": {"type": "string", "format": "uri"},
                    "paid_path": {"type": "string", "format": "uri"},
                    "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"], "default": "GET"},
                    "expected": {"type": "object", "additionalProperties": True},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
            "inputExample": {"target": "https://proofbeforepay.vercel.app", "tier": "quick"},
            "outputSchema": {
                "type": "object",
                "properties": {
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "ready": {"type": "boolean"},
                    "checks": {"type": "object"},
                    "issues": {"type": "array", "items": {"type": "string"}},
                    "recommendedFixes": {"type": "array", "items": {"type": "string"}},
                    "claimBoundaries": {"type": "array", "items": {"type": "string"}},
                    "x402Payment": {"type": "object"},
                },
            },
            "outputExample": {
                "score": 96,
                "ready": True,
                "issues": [],
                "recommendedFixes": [],
                "claimBoundaries": ["Observed public metadata only; no security certification or marketplace endorsement is implied."],
            },
        }
    if resource.path == "/v1/x402/launch-pack":
        return {
            **common,
            "name": "x402 Launch Pack Generator",
            "description": "Generates marketplace-safe x402 launch artifacts from readiness evidence: listing copy, buyer FAQ, checklist, approval packet, and claim boundaries.",
            "bodyType": "json",
            "method": "POST",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "format": "uri", "description": "Public x402/API/MCP service URL to package for launch."},
                    "tier": {"type": "string", "enum": ["single", "service", "premium"], "default": "single"},
                    "product_name": {"type": "string"},
                    "audience": {"type": "string"},
                    "primary_use_case": {"type": "string"},
                    "marketplace_url": {"type": "string", "format": "uri"},
                    "expected_resources": {"type": "integer", "minimum": 0},
                    "paid_path": {"type": "string", "format": "uri"},
                    "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"], "default": "GET"},
                    "expected": {"type": "object", "additionalProperties": True},
                    "desired_marketplaces": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
            "inputExample": {"target": "https://proofbeforepay.vercel.app", "tier": "single"},
            "outputSchema": {
                "type": "object",
                "properties": {
                    "listingCopy": {"type": "object"},
                    "buyerFaq": {"type": "array"},
                    "launchChecklist": {"type": "array"},
                    "approvalPacket": {"type": "object"},
                    "claimBoundaries": {"type": "array", "items": {"type": "string"}},
                    "x402Payment": {"type": "object"},
                },
            },
            "outputExample": {
                "listingCopy": {"oneLiner": "GateCheck by LarryBuildsAI: x402 readiness and launch-pack artifacts for paid API/MCP builders."},
                "buyerFaq": [],
                "launchChecklist": [],
                "approvalPacket": {"status": "draft"},
                "claimBoundaries": ["Generated pack does not post, submit listings, spend funds, or imply official endorsement."],
            },
        }
    return None


def _service_metadata_for_resource(resource: PaymentResource) -> dict[str, Any]:
    return {
        "serviceName": "GateCheck by LarryBuildsAI",
        "legacyServiceName": "Boundary Guard x402",
        "tags": ["x402", "scanner", "receipt", "agent-tooling", "LarryBuildsAI", "seller-readiness", "launch-pack"],
    }


def bazaar_discovery_extension(resource: PaymentResource) -> dict[str, Any] | None:
    """Return @x402/extensions-compatible Bazaar discovery declaration."""
    metadata = bazaar_discovery_metadata(resource)
    if not metadata:
        return None

    input_schema = metadata["inputSchema"]
    output_schema = metadata["outputSchema"]
    return {
        "bazaar": {
            "info": {
                "input": {
                    "type": "http",
                    "method": resource.method.upper(),
                    "bodyType": metadata["bodyType"],
                    "body": metadata["inputExample"],
                },
                "output": {
                    "type": "json",
                    "example": metadata["outputExample"],
                },
            },
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "input": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "const": "http"},
                            "method": {"type": "string", "enum": ["POST", "PUT", "PATCH"]},
                            "bodyType": {"type": "string", "enum": ["json", "form-data", "text"]},
                            "body": input_schema,
                        },
                        "required": ["type", "method", "bodyType", "body"],
                        "additionalProperties": False,
                    },
                    "output": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "example": output_schema,
                        },
                        "required": ["type"],
                    },
                },
                "required": ["input"],
            },
        }
    }


def price_to_atomic_units(price: str, decimals: int = 6) -> str:
    raw = str(price).strip().removeprefix("$")
    amount = Decimal(raw)
    scale = Decimal(10) ** decimals
    atomic = (amount * scale).quantize(Decimal("1"), rounding=ROUND_DOWN)
    if atomic <= 0:
        raise ValueError("price must be positive and representable in atomic units")
    return str(int(atomic))


def _canonical_payment_base_url() -> str:
    base_url = os.getenv("X402_CANONICAL_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return ""
    parsed = urlparse(base_url)
    host = parsed.netloc.lower()
    if host in LEGACY_CANONICAL_HOSTS or (host.startswith("x402-resource-scanner-") and host.endswith(".vercel.app")):
        return PUBLIC_CANONICAL_BASE_URL
    return base_url


def facilitator_payment_requirements(requirements: Mapping[str, Any]) -> dict[str, Any]:
    """Strip discovery-only fields before sending requirements to a facilitator."""
    allowed = {"scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"}
    return {key: value for key, value in requirements.items() if key in allowed and value is not None}


def encode_x402_header(payload: Mapping[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def decode_x402_header(header_value: str) -> dict[str, Any]:
    decoded = base64.b64decode(header_value).decode("utf-8")
    payload = json.loads(decoded)
    if not isinstance(payload, dict):
        raise ValueError("decoded payment payload is not an object")
    return payload


def _lower_headers(request_headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (request_headers or {}).items()}


def _has_demo_payment(lowered_headers: Mapping[str, str]) -> bool:
    return (
        lowered_headers.get("x-payment") == "stub-paid-demo"
        or lowered_headers.get("x402-payment") == "stub-paid-demo"
        or lowered_headers.get("authorization") == "bearer stub-paid-demo"
    )


def _requirements_equivalent(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    fields = ("scheme", "network", "asset", "amount", "payTo")
    return all(_field_equivalent(field, left.get(field), right.get(field)) for field in fields)


def _field_equivalent(field: str, left: Any, right: Any) -> bool:
    if left in (None, "") or right in (None, ""):
        return left == right
    left_value = str(left).strip()
    right_value = str(right).strip()
    if field == "asset" or left_value.startswith("0x") or right_value.startswith("0x"):
        return left_value.lower() == right_value.lower()
    if field in {"scheme", "network"}:
        return left_value.lower() == right_value.lower()
    return left_value == right_value


def _asset_extra(network: str, asset: str) -> dict[str, Any]:
    if not network.startswith("eip155:"):
        return {}
    if asset.lower() == BASE_MAINNET_USDC.lower():
        return {"name": "USD Coin", "version": "2"}
    if asset.lower() == BASE_SEPOLIA_USDC.lower():
        return {"name": "USDC", "version": "2"}
    return {}


def _uses_cdp_facilitator(facilitator_url: str) -> bool:
    parsed = urlparse(str(facilitator_url).strip())
    return parsed.netloc.lower() == "api.cdp.coinbase.com" and parsed.path.rstrip("/").endswith("/platform/v2/x402")


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
