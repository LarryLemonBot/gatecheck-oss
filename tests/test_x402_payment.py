import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner.x402_payment import (
    BASE_SEPOLIA_USDC,
    PaymentSettlementError,
    PaymentResource,
    SOLANA_MAINNET,
    SOLANA_MAINNET_USDC,
    X402PaymentGate,
    encode_x402_header,
    facilitator_payment_requirements,
    price_to_atomic_units,
)


def test_price_to_atomic_units_converts_usdc_decimal_prices():
    assert price_to_atomic_units("0.25") == "250000"
    assert price_to_atomic_units("$0.05") == "50000"
    assert price_to_atomic_units("1") == "1000000"


def test_environment_payment_config_values_are_trimmed(monkeypatch):
    pay_to = "0x1111111111111111111111111111111111111111"
    asset = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    monkeypatch.setenv("X402_PAY_TO_ADDRESS", f" {pay_to}\n")
    monkeypatch.setenv("X402_FACILITATOR_URL", " https://www.x402.org/facilitator/\n")
    monkeypatch.setenv("X402_NETWORK", "eip155:8453\n")
    monkeypatch.setenv("X402_ASSET", f"{asset}\n")

    gate = X402PaymentGate.from_environment()

    assert gate.pay_to == pay_to
    assert gate.facilitator_url == "https://www.x402.org/facilitator"
    assert gate.network == "eip155:8453"
    assert gate.asset == asset


def test_payment_required_response_uses_x402_v2_shape_and_header():
    gate = X402PaymentGate(
        pay_to="0x1111111111111111111111111111111111111111",
        facilitator_url="https://www.x402.org/facilitator",
        allow_stub_bypass=False,
    )
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    session = gate.begin(resource, request_headers={})

    assert session.allowed is False
    assert session.status_code == 402
    assert "PAYMENT-REQUIRED" in session.response_headers
    payload = session.response_body
    assert payload["x402Version"] == 2
    assert payload["resource"]["url"] == "/v1/x402/scan"
    assert payload["accepts"][0] == {
        "scheme": "exact",
        "network": "eip155:84532",
        "asset": BASE_SEPOLIA_USDC,
        "amount": "250000",
        "payTo": "0x1111111111111111111111111111111111111111",
        "resource": "/v1/x402/scan",
        "maxTimeoutSeconds": 300,
        "extra": {"name": "USDC", "version": "2"},
    }
    decoded = json.loads(base64.b64decode(session.response_headers["PAYMENT-REQUIRED"]).decode())
    assert decoded == payload


def test_facilitator_payment_gate_verifies_then_settles_payment_signature():
    calls = []

    def fake_facilitator_post(path, payload, timeout=8):
        calls.append((path, payload))
        if path == "/verify":
            return {"isValid": True, "payer": "0x2222222222222222222222222222222222222222"}
        if path == "/settle":
            return {
                "success": True,
                "payer": "0x2222222222222222222222222222222222222222",
                "transaction": "0xabc123",
                "network": "eip155:84532",
                "amount": "250000",
            }
        raise AssertionError(path)

    gate = X402PaymentGate(
        pay_to="0x1111111111111111111111111111111111111111",
        facilitator_post=fake_facilitator_post,
        allow_stub_bypass=False,
    )
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")
    payment_payload = {
        "x402Version": 2,
        "accepted": {
            "scheme": "exact",
            "network": "eip155:84532",
            "asset": BASE_SEPOLIA_USDC,
            "amount": "250000",
            "payTo": "0x1111111111111111111111111111111111111111",
            "maxTimeoutSeconds": 300,
            "extra": {"name": "USDC", "version": "2"},
        },
        "payload": {"authorization": "signed-by-client"},
    }

    session = gate.begin(resource, request_headers={"PAYMENT-SIGNATURE": encode_x402_header(payment_payload)})
    settle_headers, summary = gate.settle(session)

    assert session.allowed is True
    assert calls[0][0] == "/verify"
    assert calls[0][1]["paymentPayload"] == payment_payload
    assert calls[0][1]["paymentRequirements"]["amount"] == "250000"
    assert "resource" not in calls[0][1]["paymentRequirements"]
    assert calls[1][0] == "/settle"
    assert "resource" not in calls[1][1]["paymentRequirements"]
    assert "PAYMENT-RESPONSE" in settle_headers
    assert summary["validated"] is True
    assert summary["settled"] is True
    assert summary["transaction"] == "0xabc123"


def test_stub_bypass_is_disabled_by_default_when_no_pay_to_is_configured(monkeypatch):
    monkeypatch.delenv("X402_ALLOW_STUB_BYPASS", raising=False)
    gate = X402PaymentGate(pay_to=None)
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    session = gate.begin(resource, request_headers={"X-PAYMENT": "stub-paid-demo"})

    assert session.allowed is False
    assert session.status_code == 402
    assert session.mode == "stub-demo-only"


def test_stub_bypass_stays_available_when_explicitly_enabled_without_pay_to():
    gate = X402PaymentGate(pay_to=None, allow_stub_bypass=True)
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    session = gate.begin(resource, request_headers={"X-PAYMENT": "stub-paid-demo"})

    assert session.allowed is True
    assert session.mode == "stub-demo-only"
    assert session.summary()["validated"] is False
    assert session.summary()["configurationRequired"] is True


def test_stub_bypass_rejects_arbitrary_payment_header_when_enabled():
    gate = X402PaymentGate(pay_to=None, allow_stub_bypass=True)
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    session = gate.begin(resource, request_headers={"X-PAYMENT": "anything"})

    assert session.allowed is False
    assert session.status_code == 402


def test_stub_bypass_is_blocked_in_production(monkeypatch):
    monkeypatch.setenv("VERCEL_ENV", "production")
    gate = X402PaymentGate(pay_to=None, allow_stub_bypass=True)
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    session = gate.begin(resource, request_headers={"X-PAYMENT": "stub-paid-demo"})

    assert session.allowed is False
    assert session.status_code == 402


def test_payment_required_payload_advertises_solana_mainnet_usdc_when_configured():
    solana_pay_to = "7vJ4JgX8fY4n7mY3M2m2qQzXv4CtdPj7dN5RzZ1xQ9aa"
    gate = X402PaymentGate(
        pay_to="0x1111111111111111111111111111111111111111",
        solana_pay_to=solana_pay_to,
        network="eip155:8453",
        asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        allow_stub_bypass=False,
    )
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")

    payload = gate.payment_required_payload(resource)

    assert {
        "scheme": "exact",
        "network": SOLANA_MAINNET,
        "asset": SOLANA_MAINNET_USDC,
        "amount": "250000",
        "payTo": solana_pay_to,
        "resource": "/v1/x402/scan",
        "maxTimeoutSeconds": 300,
        "extra": {},
    } in payload["accepts"]


def test_solana_only_configuration_issues_real_payment_challenge_without_stub_accepts():
    solana_pay_to = "7vJ4JgX8fY4n7mY3M2m2qQzXv4CtdPj7dN5RzZ1xQ9aa"
    gate = X402PaymentGate(pay_to=None, solana_pay_to=solana_pay_to, allow_stub_bypass=False)
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.12", description="x402 metadata scan")

    session = gate.begin(resource, request_headers={})

    assert session.allowed is False
    assert session.mode == "x402-facilitator"
    assert session.response_headers["x402-gate-mode"] == "facilitator"
    assert "PAYMENT-REQUIRED" in session.response_headers
    assert session.response_body["accepts"] == [
        {
            "scheme": "exact",
            "network": SOLANA_MAINNET,
            "asset": SOLANA_MAINNET_USDC,
            "amount": "120000",
            "payTo": solana_pay_to,
            "resource": "/v1/x402/scan",
            "maxTimeoutSeconds": 300,
            "extra": {},
        }
    ]


def test_facilitator_verification_uses_matching_solana_payment_requirement():
    solana_pay_to = "7vJ4JgX8fY4n7mY3M2m2qQzXv4CtdPj7dN5RzZ1xQ9aa"
    calls = []

    def fake_facilitator_post(path, payload, timeout=8):
        calls.append((path, payload))
        if path == "/verify":
            return {"isValid": True, "payer": "BuyerSolana111111111111111111111111111111111"}
        if path == "/settle":
            return {
                "success": True,
                "payer": "BuyerSolana111111111111111111111111111111111",
                "transaction": "5RzSolanaTx",
                "network": SOLANA_MAINNET,
                "amount": "250000",
            }
        raise AssertionError(path)

    gate = X402PaymentGate(
        pay_to="0x1111111111111111111111111111111111111111",
        solana_pay_to=solana_pay_to,
        network="eip155:8453",
        asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        facilitator_post=fake_facilitator_post,
        allow_stub_bypass=False,
    )
    resource = PaymentResource(path="/v1/x402/scan", method="GET", price_usdc="0.25", description="Scan")
    solana_requirement = {
        "scheme": "exact",
        "network": SOLANA_MAINNET,
        "asset": SOLANA_MAINNET_USDC,
        "amount": "250000",
        "payTo": solana_pay_to,
        "resource": "/v1/x402/scan",
        "maxTimeoutSeconds": 300,
        "extra": {},
    }
    payment_payload = {
        "x402Version": 2,
        "accepted": solana_requirement,
        "payload": {"transaction": "signed-solana-transfer"},
    }

    session = gate.begin(resource, request_headers={"PAYMENT-SIGNATURE": encode_x402_header(payment_payload)})
    gate.settle(session)

    assert session.allowed is True
    expected_facilitator_requirement = facilitator_payment_requirements(solana_requirement)
    assert calls[0][1]["paymentRequirements"] == expected_facilitator_requirement
    assert calls[1][1]["paymentRequirements"] == expected_facilitator_requirement
    assert "resource" not in calls[0][1]["paymentRequirements"]


def test_payment_resource_uses_canonical_base_url_from_environment(monkeypatch):
    monkeypatch.setenv("X402_CANONICAL_BASE_URL", " https://proofbeforepay.vercel.app/ ")
    resource = PaymentResource(path="/v1/x402/agent-tools/readiness", method="POST", price_usdc="1.00", description="Readiness")

    assert resource.url == "https://proofbeforepay.vercel.app/v1/x402/agent-tools/readiness"


def test_payment_required_payload_normalizes_legacy_scanner_resource_url(monkeypatch):
    monkeypatch.setenv("X402_CANONICAL_BASE_URL", "https://x402-resource-scanner.vercel.app")
    gate = X402PaymentGate(pay_to="0x1111111111111111111111111111111111111111", allow_stub_bypass=False)
    resource = PaymentResource(path="/v1/x402/agent-tools/readiness", method="POST", price_usdc="1.00", description="Readiness")

    payload = gate.payment_required_payload(resource)

    assert payload["resource"]["url"] == "https://proofbeforepay.vercel.app/v1/x402/agent-tools/readiness"
    assert all(
        accept["resource"] == "https://proofbeforepay.vercel.app/v1/x402/agent-tools/readiness"
        for accept in payload["accepts"]
    )


def test_payment_required_payload_includes_bazaar_metadata_for_agent_readiness(monkeypatch):
    monkeypatch.setenv("X402_CANONICAL_BASE_URL", "https://proofbeforepay.vercel.app")
    gate = X402PaymentGate(pay_to="0x1111111111111111111111111111111111111111", allow_stub_bypass=False)
    resource = PaymentResource(
        path="/v1/x402/agent-tools/readiness",
        method="POST",
        price_usdc="1.00",
        description="Agent Tool Readiness Checker",
    )

    payload = gate.payment_required_payload(resource)

    assert payload["resource"]["url"] == "https://proofbeforepay.vercel.app/v1/x402/agent-tools/readiness"
    assert payload["resource"]["method"] == "POST"
    assert all(
        accept["resource"] == "https://proofbeforepay.vercel.app/v1/x402/agent-tools/readiness"
        for accept in payload["accepts"]
    )
    bazaar_metadata = payload["resource"]["extensions"]["bazaar"]
    bazaar_extension = payload["extensions"]["bazaar"]
    assert payload["resource"]["serviceName"] == "GateCheck by LarryBuildsAI"
    assert payload["resource"]["legacyServiceName"] == "Boundary Guard x402"
    assert bazaar_metadata["name"] == "GateCheck Readiness by LarryBuildsAI"
    assert bazaar_metadata["description"].startswith("LarryBuildsAI readiness checks")
    assert bazaar_metadata["discoverable"] is True
    assert bazaar_metadata["providerName"] == "LarryBuildsAI"
    assert bazaar_metadata["service"]["legacyName"] == "Boundary Guard x402"
    assert bazaar_metadata["service"]["openapiUrl"] == "https://proofbeforepay.vercel.app/openapi.json"
    assert bazaar_metadata["bodyType"] == "json"
    assert bazaar_metadata["inputSchema"]["required"] == ["target"]
    assert bazaar_metadata["inputSchema"]["properties"]["method"]["enum"] == ["GET", "HEAD", "OPTIONS"]
    assert bazaar_metadata["inputExample"] == {"target": "https://proofbeforepay.vercel.app", "tier": "quick"}
    assert "score" in bazaar_metadata["outputSchema"]["properties"]
    assert bazaar_metadata["outputExample"]["claimBoundaries"]
    assert bazaar_extension["info"]["input"]["body"]["target"] == "https://proofbeforepay.vercel.app"


def test_payment_required_payload_includes_bazaar_metadata_for_launch_pack(monkeypatch):
    monkeypatch.setenv("X402_CANONICAL_BASE_URL", "https://proofbeforepay.vercel.app")
    gate = X402PaymentGate(pay_to="0x1111111111111111111111111111111111111111", allow_stub_bypass=False)
    resource = PaymentResource(
        path="/v1/x402/launch-pack",
        method="POST",
        price_usdc="9.00",
        description="x402 Launch Pack Generator",
    )

    payload = gate.payment_required_payload(resource)

    bazaar_metadata = payload["resource"]["extensions"]["bazaar"]
    bazaar_extension = payload["extensions"]["bazaar"]
    assert bazaar_metadata["description"].startswith("Generates marketplace-safe x402 launch artifacts")
    assert bazaar_metadata["bodyType"] == "json"
    assert bazaar_metadata["inputSchema"]["required"] == ["target"]
    assert "paid_path" in bazaar_metadata["inputSchema"]["properties"]
    assert "expected_resources" in bazaar_metadata["inputSchema"]["properties"]
    assert bazaar_metadata["inputSchema"]["properties"]["method"]["enum"] == ["GET", "HEAD", "OPTIONS"]
    assert bazaar_metadata["inputExample"]["tier"] == "single"
    assert "listingCopy" in bazaar_metadata["outputSchema"]["properties"]
    assert "does not post" in bazaar_metadata["outputExample"]["claimBoundaries"][0]
    assert bazaar_extension["info"]["input"]["body"]["tier"] == "single"


def test_cdp_facilitator_requires_cdp_api_keys_before_network_request():
    gate = X402PaymentGate(
        pay_to="0x1111111111111111111111111111111111111111",
        facilitator_url="https://api.cdp.coinbase.com/platform/v2/x402",
        cdp_api_key_id="",
        cdp_api_key_secret="",
        allow_stub_bypass=False,
    )

    with pytest.raises(PaymentSettlementError, match="CDP facilitator requires CDP_API_KEY_ID"):
        gate._post_facilitator("/verify", {"x402Version": 2})
