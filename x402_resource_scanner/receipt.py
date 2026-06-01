"""Boundary Guard-style receipt endpoint core.

The receipt proves what this service received and decided/returned. It does not
prove downstream execution or real-world outcomes.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

_SECRET_LIKE_RE = re.compile(
    r"authorization|bearer|cookie|token|api[_-]?key|apikey|secret|password|"
    r"private[_-]?key|mnemonic|seed|signature|payment[-_]?signature|"
    r"payment[-_]?response|payment[-_]?required|x[-_]?payment|session|jwt",
    re.IGNORECASE,
)


def create_receipt(payload: Mapping[str, Any], *, payment_observed: bool = False, now: datetime | None = None) -> dict[str, Any]:
    validate_receipt_payload(payload)
    request = payload.get("request", {})
    policy = payload.get("policy", {})
    result = payload.get("result", {})
    payment = payload.get("payment")
    decision = "review"
    if isinstance(policy, Mapping):
        decision = str(policy.get("decision") or decision)

    request_hash = stable_hash(request)
    policy_hash = stable_hash(policy)
    result_hash = stable_hash(result)
    payment_hash = stable_hash(payment) if payment is not None else None
    evidence = {
        "requestHash": request_hash,
        "policyHash": policy_hash,
        "resultHash": result_hash,
        "paymentHash": payment_hash,
        "decision": decision,
    }
    evidence_hash = stable_hash(evidence)
    timestamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "receiptId": f"rct_{evidence_hash[:20]}",
        "createdAt": timestamp,
        "decision": decision,
        "requestHash": request_hash,
        "policyHash": policy_hash,
        "resultHash": result_hash,
        "paymentHash": payment_hash,
        "evidenceHash": evidence_hash,
        "paymentEvidenceSubmitted": payment is not None,
        "paymentEvidenceHash": payment_hash,
        "paymentSettlementObserved": bool(payment_observed),
        "claimBoundary": "Boundary Guard Receipt API records submitted request metadata, policy decision, hashes, response/result summary, and suggested next step; it does not prove downstream execution or real-world outcomes.",
        "nextStep": payload.get("nextStep") or "store receipt with the caller's workflow run and verify downstream systems separately if needed",
    }


def stable_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def validate_receipt_payload(payload: Mapping[str, Any]) -> None:
    _reject_secret_like_evidence(payload)


def _reject_secret_like_evidence(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if _SECRET_LIKE_RE.search(key_text):
                raise ValueError(
                    "receipt evidence must be sanitized; remove raw secret, auth, cookie, signature, session, "
                    "or payment header fields before submitting"
                )
            _reject_secret_like_evidence(item, child_path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_like_evidence(item, f"{path}[{index}]")
        return
