import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner import health
from x402_resource_scanner.health import probe_paid_path
from x402_resource_scanner.x402_payment import SOLANA_MAINNET, SOLANA_MAINNET_USDC, encode_x402_header


def test_probe_paid_path_parses_unpaid_402_and_matches_expected_requirements():
    required_payload = {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "amount": "250000",
                "payTo": "0x4200ab5Af9E541b6A89eb39EeF3140f83D9De8b0",
            }
        ],
    }

    def fake_fetch(url, method, timeout):
        assert url == "https://seller.example/v1/paid"
        assert method == "GET"
        return {
            "status": 402,
            "headers": {"PAYMENT-REQUIRED": encode_x402_header(required_payload)},
            "body": {"ignored": "because header is authoritative"},
            "url": url,
        }

    payload = probe_paid_path(
        {
            "target": "https://seller.example/v1/paid?campaign=abc",
            "method": "GET",
            "mode": "unpaid_402",
            "expected": {"network": "eip155:8453", "asset": "USDC", "priceUsd": "0.25"},
        },
        fetcher=fake_fetch,
    )

    assert payload["target"] == "https://seller.example/v1/paid"
    assert payload["healthy"] is True
    assert payload["checks"] == {
        "returns402WhenUnpaid": True,
        "paymentRequirementsParsed": True,
        "networkMatches": True,
        "assetMatches": True,
        "priceMatches": True,
        "settlementObserved": None,
    }
    assert payload["observed"]["status"] == 402
    assert payload["observed"]["network"] == "eip155:8453"
    assert payload["observed"]["assetSymbol"] == "USDC"
    assert payload["observed"]["amountAtomic"] == "250000"
    assert payload["observed"]["priceUsd"] == "0.250000"
    assert payload["issues"] == []
    assert payload["recommendedFixes"] == []
    assert payload["receipt"]["receiptId"].startswith("rct_")
    assert "does not prove downstream execution" in payload["receipt"]["claimBoundary"]
    assert "campaign=abc" not in json.dumps(payload)


def test_probe_paid_path_keeps_explicit_safe_query_for_fetch_but_not_output():
    required_payload = {
        "accepts": [
            {
                "network": "eip155:8453",
                "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "amount": "250000",
            }
        ]
    }

    def fake_fetch(url, method, timeout):
        assert url == "https://seller.example/v1/paid?url=https%3A%2F%2Fwww.x402.org"
        return {"status": 402, "headers": {}, "body": required_payload, "url": url}

    payload = probe_paid_path(
        {
            "target": "https://seller.example/v1/paid",
            "query": {"url": "https://www.x402.org"},
            "expected": {"asset": "USDC", "priceUsd": "0.25"},
        },
        fetcher=fake_fetch,
    )

    payload_text = json.dumps(payload, sort_keys=True)
    assert payload["healthy"] is True
    assert payload["target"] == "https://seller.example/v1/paid"
    assert "www.x402.org" not in payload_text
    assert "url=https" not in payload_text


def test_probe_paid_path_recognizes_solana_mainnet_usdc():
    required_payload = {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "exact",
                "network": SOLANA_MAINNET,
                "asset": SOLANA_MAINNET_USDC,
                "amount": "250000",
                "payTo": "7vJ4JgX8fY4n7mY3M2m2qQzXv4CtdPj7dN5RzZ1xQ9aa",
            }
        ],
    }

    def fake_fetch(url, method, timeout):
        return {"status": 402, "headers": {"PAYMENT-REQUIRED": encode_x402_header(required_payload)}, "body": {}, "url": url}

    payload = probe_paid_path(
        {
            "target": "https://seller.example/v1/paid",
            "expected": {"network": SOLANA_MAINNET, "asset": "USDC", "priceUsd": "0.25"},
        },
        fetcher=fake_fetch,
    )

    assert payload["healthy"] is True
    assert payload["checks"]["assetMatches"] is True
    assert payload["observed"]["asset"] == SOLANA_MAINNET_USDC
    assert payload["observed"]["assetSymbol"] == "USDC"
    assert payload["issues"] == []


def test_probe_paid_path_retries_transient_fetch_miss_once():
    calls = 0
    required_payload = {
        "accepts": [
            {
                "network": "eip155:8453",
                "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "amount": "250000",
            }
        ]
    }

    def flaky_fetch(url, method, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"status": 0, "headers": {}, "body": None, "error": "temporary miss", "url": url}
        return {"status": 402, "headers": {}, "body": required_payload, "url": url}

    payload = probe_paid_path(
        {"target": "https://seller.example/v1/paid", "expected": {"asset": "USDC", "priceUsd": "0.25"}},
        fetcher=flaky_fetch,
    )

    assert calls == 2
    assert payload["healthy"] is True
    assert payload["issues"] == []


def test_probe_paid_path_reports_expected_price_mismatch():
    required_payload = {
        "accepts": [
            {
                "network": "eip155:8453",
                "asset": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "amount": "100000",
            }
        ]
    }

    def fake_fetch(url, method, timeout):
        return {"status": 402, "headers": {}, "body": required_payload, "url": url}

    payload = probe_paid_path(
        {
            "target": "https://seller.example/v1/paid",
            "expected": {"network": "eip155:8453", "asset": "USDC", "priceUsd": "0.25"},
        },
        fetcher=fake_fetch,
    )

    assert payload["healthy"] is False
    assert payload["checks"]["priceMatches"] is False
    assert "expected priceUsd 0.25, observed 0.100000" in payload["issues"]
    assert "update the route price or listing expectation so health probes and marketplace metadata agree" in payload["recommendedFixes"]


def test_probe_paid_path_blocks_unsafe_methods():
    payload = probe_paid_path({"target": "https://seller.example/v1/paid", "method": "POST"})

    assert payload["healthy"] is False
    assert payload["checks"]["returns402WhenUnpaid"] is False
    assert payload["observed"]["status"] is None
    assert "POST probes are disabled by default" in payload["issues"]


def test_probe_paid_path_blocks_unsafe_method_even_with_override_flag():
    payload = probe_paid_path(
        {
            "target": "https://seller.example/v1/paid",
            "method": "DELETE",
            "allowUnsafeMethodsForUnpaidProbe": True,
        }
    )

    assert payload["healthy"] is False
    assert payload["observed"]["status"] is None
    assert "DELETE probes are disabled by default" in payload["issues"]


def test_probe_paid_path_rejects_url_credentials_before_fetch():
    def fake_fetch(url, method, timeout):  # pragma: no cover - should never run
        raise AssertionError("fetcher should not receive credentialed URL")

    payload = probe_paid_path({"target": "https://user:pass@seller.example/v1/paid"}, fetcher=fake_fetch)

    assert payload["healthy"] is False
    assert payload["target"] is None
    assert payload["observed"]["status"] is None
    assert "target URL must not include username or password" in payload["issues"]


def test_fetch_unpaid_target_rejects_hostname_that_resolves_private(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "seller.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(health.socket, "getaddrinfo", fake_getaddrinfo)
    result = health.fetch_unpaid_target("https://seller.example/v1/paid", "GET")

    assert result["status"] == 0
    assert "resolves to non-global address" in result["error"]


def test_fetch_unpaid_target_pins_validated_public_ip(monkeypatch):
    dns_answers = ["93.184.216.34", "127.0.0.1"]
    getaddrinfo_calls = []
    connect_targets = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        getaddrinfo_calls.append((host, port))
        answer = dns_answers[min(len(getaddrinfo_calls) - 1, len(dns_answers) - 1)]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answer, port))]

    class FakeSocket:
        def __init__(self, family, socktype):
            self.family = family
            self.socktype = socktype

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, target):
            connect_targets.append(target)
            raise OSError("stop before network")

        def close(self):
            pass

    monkeypatch.setattr(health.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(health.socket, "socket", FakeSocket)

    result = health.fetch_unpaid_target("http://seller.example/v1/paid", "GET")

    assert result["status"] == 0
    assert len(getaddrinfo_calls) == 1
    assert connect_targets == [("93.184.216.34", 80)]


def test_redirect_handler_never_follows_redirects():
    handler = health._NoRedirectHandler()

    assert handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/admin") is None
