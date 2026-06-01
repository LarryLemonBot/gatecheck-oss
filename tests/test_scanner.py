import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from x402_resource_scanner.scanner import normalize_base_url, parse_agentic_market_listing, parse_resource_count, scan_target


def test_parse_resource_count_supports_common_manifest_shapes():
    assert parse_resource_count({"resources": [{"path": "/a"}, {"path": "/b"}]}) == 2
    assert parse_resource_count({"endpoints": [{"path": "/a"}]}) == 1
    assert parse_resource_count({"paths": {"/a": {}, "/b": {}, "/c": {}}}) == 3
    assert parse_resource_count({"x402": {"resources": [{"path": "/a"}]}}) == 1
    assert parse_resource_count([{"path": "/a"}, {"path": "/b"}]) == 2


def test_normalize_base_url_rejects_private_and_internal_targets_by_default():
    for url in ("http://127.0.0.1:8502", "http://localhost:8502", "http://169.254.169.254/latest", "http://intranet"):
        with pytest.raises(ValueError, match="private or internal"):
            normalize_base_url(url)

    assert normalize_base_url("api.example.com") == "https://api.example.com"


def test_scan_target_allows_private_targets_only_when_explicitly_enabled():
    fixtures = {
        "http://127.0.0.1:8502/.well-known/x402": {"status": 200, "body": {"resources": [{"path": "/a", "price": "0.01"}]}},
        "http://127.0.0.1:8502/openapi.json": {"status": 200, "body": {"paths": {"/a": {}}}},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("http://127.0.0.1:8502", fetcher=fake_fetch, allow_private_targets=True)

    assert result["target"] == "http://127.0.0.1:8502"
    assert result["score"] == 100


def test_scan_target_detects_well_known_openapi_marketplace_mismatch_and_prices():
    fixtures = {
        "https://api.example.com/.well-known/x402": {
            "status": 200,
            "body": {
                "provider": {"name": "Example API"},
                "resources": [
                    {"path": "/v1/check", "price": {"amount": "0.01", "asset": "USDC"}},
                    {"path": "/v1/report", "price": "$5"},
                ],
            },
        },
        "https://api.example.com/openapi.json": {
            "status": 200,
            "body": {
                "openapi": "3.1.0",
                "info": {"title": "Example", "version": "0.1.0"},
                "paths": {"/v1/check": {}, "/v1/report": {}, "/health": {}},
            },
        },
        "https://agentic.example/listing/example": {
            "status": 200,
            "body": {"resources": [{"path": "/v1/check"}], "providerUrl": "", "category": ""},
        },
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target(
        "https://api.example.com",
        marketplace_url="https://agentic.example/listing/example",
        fetcher=fake_fetch,
    )

    assert result["target"] == "https://api.example.com"
    assert result["wellKnown"]["status"] == 200
    assert result["wellKnown"]["resourceCount"] == 2
    assert result["openapi"]["status"] == 200
    assert result["openapi"]["pathCount"] == 3
    assert result["marketplace"]["indexedResourceCount"] == 1
    assert result["marketplace"]["stale"] is True
    assert "marketplace resource count mismatch" in result["issues"]
    assert "marketplace missing provider URL" in result["issues"]
    assert "marketplace missing category" in result["issues"]
    assert {"path": "/v1/check", "amount": "0.01", "asset": "USDC"} in result["prices"]
    assert {"path": "/v1/report", "amount": "$5", "asset": None} in result["prices"]
    assert 0 <= result["score"] <= 100
    assert result["nextSteps"]


def test_scan_target_can_include_agent_discovery_surfaces_and_score_breakdown():
    fixtures = {
        "https://api.example.com/.well-known/x402": {
            "status": 200,
            "body": {"resources": [{"path": "/v1/check", "price": "0.01"}]},
        },
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/v1/check": {}}}},
        "https://api.example.com/llms.txt": {"status": 200, "body": "# Example API\nMCP endpoint: https://api.example.com/mcp\nOpenAPI: https://api.example.com/openapi.json\n"},
        "https://api.example.com/agents.txt": {"status": 200, "body": "MCP: https://api.example.com/mcp\nDiscovery: https://api.example.com/.well-known/mcp.json\n"},
        "https://api.example.com/.well-known/mcp.json": {
            "status": 200,
            "body": {"name": "Example API", "url": "https://api.example.com/mcp", "transport": "streamable-http", "tools": [{"name": "scan"}]},
        },
        "https://api.example.com/mcp": {"status": 405, "body": "method not allowed"},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("https://api.example.com", fetcher=fake_fetch, include_agent_discovery=True)

    assert result["agentDiscovery"]["score"] == 100
    assert result["agentDiscovery"]["surfaces"]["llmsTxt"]["status"] == 200
    assert result["agentDiscovery"]["surfaces"]["agentsTxt"]["status"] == 200
    assert result["agentDiscovery"]["surfaces"]["wellKnownMcpJson"]["toolsCount"] == 1
    assert result["agentDiscovery"]["surfaces"]["mcpEndpoint"]["status"] == 405
    assert result["agentDiscovery"]["surfaces"]["mcpEndpoint"]["available"] is True
    assert result["scoreBreakdown"]["agentDiscovery"]["score"] == 100
    assert all(not finding["id"].startswith("missing_agent_") for finding in result["findings"])


def test_scan_target_agent_discovery_missing_surfaces_emit_buyer_safe_findings():
    fixtures = {
        "https://api.example.com/.well-known/x402": {
            "status": 200,
            "body": {"resources": [{"path": "/v1/check", "price": "0.01"}]},
        },
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/v1/check": {}}}},
        "https://api.example.com/llms.txt": {"status": 404, "body": "not found"},
        "https://api.example.com/agents.txt": {"status": 404, "body": "not found"},
        "https://api.example.com/.well-known/mcp.json": {"status": 404, "body": "not found"},
        "https://api.example.com/mcp": {"status": 404, "body": "not found"},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("https://api.example.com", fetcher=fake_fetch, include_agent_discovery=True)

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert result["agentDiscovery"]["score"] == 0
    assert result["scoreBreakdown"]["agentDiscovery"]["score"] == 0
    assert "missing_agent_llms_txt" in finding_ids
    assert "missing_agent_agents_txt" in finding_ids
    assert "missing_agent_well_known_mcp_json" in finding_ids
    assert "missing_agent_mcp_endpoint" in finding_ids
    assert "publish /llms.txt so LLM crawlers can understand the paid tool" in result["nextSteps"]
    assert "not found" not in json.dumps(result)


def test_parse_agentic_market_listing_extracts_endpoint_count_and_missing_metadata():
    html = """
    <html><body>
      <h1>Boundary Guard</h1>
      <div>4 endpoints</div>
      <div>Category</div><div>-</div>
      <div>Provider URL</div><div></div>
      <code>enriched=false</code>
    </body></html>
    """

    parsed = parse_agentic_market_listing(html, "https://agentic.market/boundary-guard")

    assert parsed["kind"] == "agentic.market"
    assert parsed["indexedResourceCount"] == 4
    assert parsed["enriched"] is False
    assert parsed["missingProviderUrl"] is True
    assert parsed["missingCategory"] is True


def test_scan_target_uses_agentic_market_specific_parser():
    fixtures = {
        "https://api.example.com/.well-known/x402": {"status": 200, "body": {"resources": [{"path": "/a"}, {"path": "/b"}, {"path": "/c"}]}},
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/a": {}, "/b": {}, "/c": {}}}},
        "https://agentic.market/example": {"status": 200, "body": "<h1>Example</h1><p>1 endpoint</p><p>enriched=false</p>"},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("https://api.example.com", marketplace_url="https://agentic.market/example", fetcher=fake_fetch)

    assert result["marketplace"]["kind"] == "agentic.market"
    assert result["marketplace"]["indexedResourceCount"] == 1
    assert result["marketplace"]["stale"] is True
    assert result["marketplace"]["enriched"] is False
    assert "agentic.market listing is not enriched" in result["issues"]
    assert "marketplace resource count mismatch" in result["issues"]


def test_scan_target_handles_missing_manifest_as_nonfatal_issue():
    fixtures = {
        "https://empty.example/.well-known/x402": {"status": 404, "body": "not found"},
        "https://empty.example/openapi.json": {"status": 404, "body": "not found"},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("https://empty.example", fetcher=fake_fetch)

    assert result["wellKnown"]["status"] == 404
    assert result["wellKnown"]["resourceCount"] == 0
    assert result["openapi"]["status"] == 404
    assert result["openapi"]["pathCount"] == 0
    assert "missing .well-known/x402 manifest" in result["issues"]
    assert "missing OpenAPI document" in result["issues"]
    assert result["score"] < 60


def test_scan_target_returns_structured_findings_score_breakdown_and_latency():
    fixtures = {
        "https://empty.example/.well-known/x402": {"status": 404, "body": "not found"},
        "https://empty.example/openapi.json": {"status": 200, "body": {"paths": {}}},
    }

    def fake_fetch(url, timeout=8):
        return fixtures[url]

    result = scan_target("https://empty.example", fetcher=fake_fetch)

    assert result["latencyMs"] >= 0
    assert result["scoreBreakdown"]["metadata"]["score"] < 100
    assert result["scoreBreakdown"]["documentation"]["score"] < 100
    assert result["findings"][0]["id"] == "missing_x402_manifest"
    assert result["findings"][0]["confidence"] == "observed"
    assert result["findings"][0]["source"] == "/.well-known/x402"
    assert result["findings"][0]["retest"].startswith("curl -i https://empty.example/.well-known/x402")
    assert "missing .well-known/x402 manifest" in result["issues"]
    assert "publish /.well-known/x402" in " ".join(result["nextSteps"])


def test_scan_target_retries_transient_public_metadata_fetch_failures_once():
    calls = {"https://api.example.com/openapi.json": 0}
    fixtures = {
        "https://api.example.com/.well-known/x402": {"status": 200, "body": {"resources": [{"path": "/a", "price": "0.01"}]}},
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/a": {}}}},
    }

    def flaky_fetch(url, timeout=8):
        if url.endswith("/openapi.json"):
            calls[url] += 1
            if calls[url] == 1:
                return {"status": 0, "body": None, "error": "temporary network miss"}
        return fixtures[url]

    result = scan_target("https://api.example.com", fetcher=flaky_fetch)

    assert calls["https://api.example.com/openapi.json"] == 2
    assert result["openapi"]["status"] == 200
    assert result["issues"] == []


def test_scan_target_fetches_public_metadata_in_parallel_for_speed():
    fixtures = {
        "https://api.example.com/.well-known/x402": {"status": 200, "body": {"resources": [{"path": "/a", "price": "0.01"}]}},
        "https://api.example.com/openapi.json": {"status": 200, "body": {"paths": {"/a": {}}}},
    }

    def slow_fetch(url, timeout=8):
        time.sleep(0.15)
        return fixtures[url]

    started = time.perf_counter()
    result = scan_target("https://api.example.com", fetcher=slow_fetch)
    elapsed = time.perf_counter() - started

    assert result["score"] == 100
    assert elapsed < 0.25
