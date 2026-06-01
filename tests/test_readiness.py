import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner.readiness import check_agent_tool_readiness, readiness_price_usdc, validate_readiness_request


def test_validate_readiness_request_normalizes_urls_and_tier_price_without_query_leaks():
    normalized = validate_readiness_request(
        {
            "target": "https://api.example.com/base?secret=do-not-log",
            "tier": "report",
            "marketplace_url": "https://agentic.market/listing/example?private=yes",
            "expected_resources": "2",
            "paid_path": "https://api.example.com/v1/paid?campaign=abc",
            "method": "HEAD",
            "expected": {"priceUsd": "1.00"},
        }
    )

    as_text = json.dumps(normalized, sort_keys=True)
    assert normalized["target"] == "https://api.example.com/base"
    assert normalized["tier"] == "report"
    assert normalized["priceUsd"] == "10.00"
    assert normalized["marketplace_url"] == "https://agentic.market/listing/example"
    assert normalized["expected_resources"] == 2
    assert normalized["paid_path"] == "https://api.example.com/v1/paid"
    assert normalized["method"] == "HEAD"
    assert readiness_price_usdc("quick") == "1.00"
    assert "do-not-log" not in as_text
    assert "private=yes" not in as_text
    assert "campaign=abc" not in as_text


def test_validate_readiness_request_rejects_private_targets_before_payment_or_probe():
    with pytest.raises(ValueError, match="private or internal"):
        validate_readiness_request({"target": "https://api.example.com", "paid_path": "http://127.0.0.1:8502/paid", "tier": "deep"})


def test_quick_agent_tool_readiness_uses_scan_only_and_scores_metadata():
    calls = []

    def fake_scanner(url, **kwargs):
        calls.append((url, kwargs))
        return {
            "target": url,
            "score": 92,
            "wellKnown": {"status": 200, "resourceCount": 2},
            "openapi": {"status": 200, "pathCount": 2},
            "prices": [{"path": "/v1/check", "amount": "0.10", "asset": "USDC"}],
            "issues": [],
            "nextSteps": ["metadata looks ready for a basic x402 listing scan"],
        }

    def fail_health_probe(payload):  # pragma: no cover - quick tier must not probe
        raise AssertionError("quick readiness should not call the health prober")

    result = check_agent_tool_readiness(
        {"target": "https://api.example.com", "tier": "quick"},
        scanner=fake_scanner,
        health_prober=fail_health_probe,
    )

    assert calls == [("https://api.example.com", {"marketplace_url": None, "expected_resources": None, "include_agent_discovery": True})]
    assert result["product"] == "agent_tool_readiness_checker"
    assert result["tier"] == "quick"
    assert result["priceUsd"] == "1.00"
    assert result["ready"] is True
    assert result["score"] == 92
    assert result["healthProbe"] is None
    assert result["checks"]["metadata"]["x402ManifestPublished"] is True
    assert result["checks"]["metadata"]["priceMetadataPresent"] is True
    assert result["issues"] == []
    assert result["recommendedFixes"] == []
    assert result["nextSteps"] == ["metadata looks ready for a basic x402 listing scan"]


def test_deep_agent_tool_readiness_runs_paid_path_health_probe_when_supplied():
    def fake_scanner(url, **kwargs):
        assert url == "https://api.example.com"
        return {
            "target": url,
            "score": 86,
            "wellKnown": {"status": 200, "resourceCount": 1},
            "openapi": {"status": 200, "pathCount": 1},
            "prices": [{"path": "/v1/paid", "amount": "0.50", "asset": "USDC"}],
            "issues": [],
            "nextSteps": [],
        }

    def fake_health_probe(payload):
        assert payload["target"] == "https://api.example.com/v1/paid"
        assert payload["method"] == "GET"
        assert payload["query"] == {"url": "https://www.x402.org"}
        assert payload["expected"] == {"priceUsd": "0.50"}
        return {
            "target": payload["target"],
            "healthy": True,
            "checks": {"returns402WhenUnpaid": True, "paymentRequirementsParsed": True},
            "issues": [],
            "recommendedFixes": [],
        }

    result = check_agent_tool_readiness(
        {
            "target": "https://api.example.com",
            "tier": "deep",
            "paid_path": "https://api.example.com/v1/paid?utm=drop-me",
            "paid_path_query": {"url": "https://www.x402.org"},
            "expected": {"priceUsd": "0.50"},
        },
        scanner=fake_scanner,
        health_prober=fake_health_probe,
    )

    assert result["tier"] == "deep"
    assert result["priceUsd"] == "5.00"
    assert result["ready"] is True
    assert result["score"] == 91
    assert result["healthProbe"]["healthy"] is True
    assert result["checks"]["paidPath"]["returns402WhenUnpaid"] is True
    assert "utm=drop-me" not in json.dumps(result)


def test_report_agent_tool_readiness_includes_markdown_report_and_missing_probe_issue():
    def fake_scanner(url, **kwargs):
        return {
            "target": url,
            "score": 74,
            "wellKnown": {"status": 200, "resourceCount": 1},
            "openapi": {"status": 200, "pathCount": 1},
            "prices": [],
            "issues": ["marketplace resource count mismatch"],
            "nextSteps": ["request marketplace reindex or update listing resources"],
            "marketplace": {"stale": True},
            "agentDiscovery": {
                "score": 50,
                "surfaces": {
                    "llmsTxt": {"status": 200, "available": True},
                    "agentsTxt": {"status": 404, "available": False},
                    "wellKnownMcpJson": {"status": 200, "available": True, "toolsCount": 1},
                    "mcpEndpoint": {"status": 405, "available": True},
                },
            },
        }

    result = check_agent_tool_readiness(
        {"target": "https://api.example.com", "tier": "report"},
        scanner=fake_scanner,
    )

    assert result["tier"] == "report"
    assert result["priceUsd"] == "10.00"
    assert result["ready"] is False
    assert result["score"] == 59
    assert "paid path not supplied for deep/report readiness check" in result["issues"]
    assert result["checks"]["metadata"]["marketplaceInSync"] is False
    assert result["checks"]["agentDiscovery"]["llmsTxtPublished"] is True
    assert result["checks"]["agentDiscovery"]["agentsTxtPublished"] is False
    assert result["checks"]["agentDiscovery"]["mcpDiscoveryPublished"] is True
    assert result["checks"]["agentDiscovery"]["mcpEndpointAvailable"] is True
    assert result["report"]["format"] == "markdown"
    assert "# Agent Tool Readiness Report" in result["report"]["body"]
    assert "## Executive summary" in result["report"]["body"]
    assert "## Evidence" in result["report"]["body"]
    assert "agent llms.txt published" in result["report"]["body"]
    assert "## Score breakdown" in result["report"]["body"]
    assert "## Re-test commands" in result["report"]["body"]
    assert "## Marketplace-safe positioning" in result["report"]["body"]
    assert "marketplace resource count mismatch" in result["report"]["body"]
    assert "public metadata and optional unpaid x402 402 challenge checks only" in result["report"]["body"]