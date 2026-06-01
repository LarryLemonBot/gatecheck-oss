import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner.launch_pack import generate_x402_launch_pack, launch_pack_price_usdc, validate_launch_pack_request


def test_validate_launch_pack_request_normalizes_tier_price_and_strips_query_leaks():
    normalized = validate_launch_pack_request(
        {
            "target": "https://api.example.com/base?secret=do-not-log",
            "tier": "premium",
            "product_name": "Example Paid API",
            "marketplace_url": "https://agentic.market/listing/example?private=yes",
            "paid_path": "https://api.example.com/v1/paid?campaign=abc",
            "paid_path_query": {"url": "https://www.x402.org"},
            "expected_resources": "3",
            "expected": {"priceUsd": "0.25"},
        }
    )

    as_text = json.dumps(normalized, sort_keys=True)
    assert normalized["product"] == "x402_launch_pack_generator"
    assert normalized["target"] == "https://api.example.com/base"
    assert normalized["tier"] == "premium"
    assert normalized["priceUsd"] == "49.00"
    assert normalized["productName"] == "Example Paid API"
    assert normalized["marketplace_url"] == "https://agentic.market/listing/example"
    assert normalized["paid_path"] == "https://api.example.com/v1/paid"
    assert normalized["expected_resources"] == 3
    assert launch_pack_price_usdc("single") == "9.00"
    assert "do-not-log" not in as_text
    assert "private=yes" not in as_text
    assert "campaign=abc" not in as_text


def test_validate_launch_pack_request_rejects_private_targets_before_generation():
    with pytest.raises(ValueError, match="private or internal"):
        validate_launch_pack_request({"target": "http://127.0.0.1:8502", "tier": "single"})


def test_generate_launch_pack_composes_readiness_into_buyer_facing_artifacts():
    calls = []

    def fake_readiness_checker(payload):
        calls.append(payload)
        return {
            "product": "agent_tool_readiness_checker",
            "tier": "report",
            "target": "https://api.example.com",
            "priceUsd": "10.00",
            "ready": False,
            "score": 72,
            "issues": ["missing price metadata"],
            "recommendedFixes": ["include price/payment metadata for each paid resource"],
            "nextSteps": ["include price/payment metadata for each paid resource"],
            "claimBoundary": "Public metadata only; no settlement proof.",
            "checks": {"metadata": {"x402ManifestPublished": True, "openapiPublished": True}},
            "report": {"format": "markdown", "body": "# Agent Tool Readiness Report\n\nNeeds pricing metadata."},
        }

    result = generate_x402_launch_pack(
        {
            "target": "https://api.example.com?campaign=drop-me",
            "tier": "service",
            "product_name": "Example Paid API",
            "audience": "AI agents that buy data tools",
            "paid_path": "https://api.example.com/v1/paid?utm=drop-me",
        },
        readiness_checker=fake_readiness_checker,
    )

    assert calls[0]["tier"] == "report"
    assert calls[0]["target"] == "https://api.example.com"
    assert result["product"] == "x402_launch_pack_generator"
    assert result["tier"] == "service"
    assert result["priceUsd"] == "29.00"
    assert result["target"] == "https://api.example.com"
    assert result["readinessScore"] == 72
    assert result["approvalRequiredBeforeDistribution"] is True
    assert result["launchPack"]["marketplaceListing"]["title"] == "Example Paid API"
    assert "AI agents that buy data tools" in result["launchPack"]["marketplaceListing"]["buyer"]
    assert result["launchPack"]["buyerFAQ"]
    assert result["launchPack"]["launchChecklist"][0]["status"] in {"ready", "fix_first"}
    assert "public listing" in result["claimBoundary"]
    assert "campaign=drop-me" not in json.dumps(result)
    assert "utm=drop-me" not in json.dumps(result)


def test_generate_launch_pack_markdown_report_contains_launch_assets_and_boundaries():
    def fake_readiness_checker(payload):
        return {
            "target": "https://api.example.com",
            "tier": "quick",
            "priceUsd": "1.00",
            "ready": True,
            "score": 94,
            "issues": [],
            "recommendedFixes": [],
            "claimBoundary": "Public metadata only.",
        }

    result = generate_x402_launch_pack(
        {"target": "https://api.example.com", "tier": "single", "product_name": "Example Paid API"},
        readiness_checker=fake_readiness_checker,
    )

    body = result["report"]["body"]
    assert result["readinessTierUsed"] == "quick"
    assert "# x402 Launch Pack" in body
    assert "## Listing copy" in body
    assert "## Buyer FAQ" in body
    assert "## Launch checklist" in body
    assert "## Approval boundary" in body
    assert "No public posting, listing, outreach, or marketplace submission is included in this generated pack." in body


def test_generate_launch_pack_does_not_turn_positive_next_step_into_fix_when_ready():
    def fake_readiness_checker(payload):
        return {
            "target": "https://api.example.com",
            "tier": "report",
            "priceUsd": "10.00",
            "ready": True,
            "score": 100,
            "issues": [],
            "recommendedFixes": [],
            "nextSteps": ["metadata looks ready for a basic x402 listing scan"],
            "claimBoundary": "Public metadata only.",
        }

    result = generate_x402_launch_pack(
        {"target": "https://api.example.com", "tier": "premium", "product_name": "Example Paid API"},
        readiness_checker=fake_readiness_checker,
    )

    checklist_items = result["launchPack"]["launchChecklist"]
    assert all(item["item"] != "metadata looks ready for a basic x402 listing scan" for item in checklist_items)
    assert all(item["status"] != "fix_first" for item in checklist_items)
    assert "metadata looks ready for a basic x402 listing scan" not in result["report"]["body"]
