# Contributing

GateCheck welcomes focused fixes that improve read-only x402/MCP readiness
checks, safety boundaries, tests, and public documentation.

Before opening a PR:

1. Do not include secrets, private keys, cookies, `.env` files, raw payment
   headers, customer data, private transcripts, or internal machine paths.
2. Keep product scope GateCheck-only unless a maintainer explicitly accepts a
   broader change.
3. Run the test suite:

   ```bash
   python -m pytest -q
   ```

4. Keep claims bounded. Public docs may describe observed metadata and unpaid
   402 behavior, but must not imply marketplace endorsement, payment settlement,
   security certification, customer adoption, or downstream execution proof.
