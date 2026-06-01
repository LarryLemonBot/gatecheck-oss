from __future__ import annotations

import argparse
import json

from .scanner import scan_target


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only GateCheck x402/MCP readiness scan.")
    parser.add_argument("url", help="Public HTTP(S) service URL to inspect")
    parser.add_argument("--marketplace-url", help="Optional public marketplace/listing URL to compare")
    parser.add_argument("--expected-resources", type=int, help="Expected paid resource count")
    parser.add_argument("--agent-discovery", action="store_true", help="Also inspect /llms.txt, /agents.txt, and MCP discovery metadata")
    args = parser.parse_args()

    result = scan_target(
        args.url,
        marketplace_url=args.marketplace_url,
        expected_resources=args.expected_resources,
        include_agent_discovery=args.agent_discovery,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
