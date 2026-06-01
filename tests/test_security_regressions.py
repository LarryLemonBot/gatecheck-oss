import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner import scanner
from x402_resource_scanner.analytics import _hash_value
from x402_resource_scanner.receipt import create_receipt


def test_normalize_base_url_rejects_url_credentials():
    with pytest.raises(ValueError, match="username or password"):
        scanner.normalize_base_url("https://user:pass@api.example.com/v1")


def test_private_target_env_override_is_ignored_in_production(monkeypatch):
    monkeypatch.setenv("X402_SCANNER_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("VERCEL_ENV", "production")

    with pytest.raises(ValueError, match="private or internal"):
        scanner.normalize_base_url("http://127.0.0.1:8502")


def test_scan_target_rejects_private_marketplace_url_before_fetch():
    calls = []
    fixtures = {
        "https://api.example.com/.well-known/x402": {"status": 200, "body": {"resources": [{"path": "/a", "price": "0.01"}]}},
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/a": {}}}},
    }

    def fake_fetch(url, timeout=8):
        calls.append(url)
        if "169.254.169.254" in url:
            raise AssertionError("private marketplace URL reached fetcher")
        return fixtures[url]

    with pytest.raises(ValueError, match="private or internal"):
        scanner.scan_target("https://api.example.com", marketplace_url="http://169.254.169.254/latest/meta-data", fetcher=fake_fetch)

    assert calls == []


def test_fetch_json_rejects_hostname_resolving_to_private_ip(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "seller.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(scanner.socket, "getaddrinfo", fake_getaddrinfo)

    result = scanner.fetch_json("https://seller.example/.well-known/x402")

    assert result["status"] == 0
    assert "resolves to non-global address" in result["error"]


def test_fetch_json_pins_validated_public_ip(monkeypatch):
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

    monkeypatch.setattr(scanner.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)

    result = scanner.fetch_json("http://seller.example/.well-known/x402")

    assert result["status"] == 0
    assert len(getaddrinfo_calls) == 1
    assert connect_targets == [("93.184.216.34", 80)]


def test_receipt_with_submitted_payment_evidence_does_not_claim_settlement_observed():
    receipt = create_receipt({"request": {"path": "/v1/tool"}, "payment": {"tx": "0xabc"}})

    assert receipt["paymentEvidenceSubmitted"] is True
    assert receipt["paymentHash"]
    assert receipt["paymentSettlementObserved"] is False


def test_receipt_after_service_observed_payment_marks_settlement_observed():
    receipt = create_receipt({"request": {"path": "/v1/tool"}}, payment_observed=True)

    assert receipt["paymentEvidenceSubmitted"] is False
    assert receipt["paymentSettlementObserved"] is True


def test_analytics_uses_hmac_when_salt_present(monkeypatch):
    monkeypatch.setenv("ANALYTICS_HASH_SALT", "unit-test-salt")
    monkeypatch.setenv("VERCEL_ENV", "production")

    hashed = _hash_value("sensitive")

    assert hashed is not None
    assert hashed.startswith("hmac_sha256:")


def test_analytics_omits_sensitive_hashes_in_production_without_salt(monkeypatch):
    monkeypatch.delenv("ANALYTICS_HASH_SALT", raising=False)
    monkeypatch.setenv("VERCEL_ENV", "production")

    assert _hash_value("sensitive") is None
