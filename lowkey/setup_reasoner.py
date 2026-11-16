"""Quiet, bounded AI ranking for deterministic protocol setup candidates.

The model may rank only functions already present in the target ABI. It cannot
invent selectors, argument values, commands, transactions, or proof outcomes.
All selected calldata is still generated and executed by Lowkey's native path.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


def _fingerprint(candidates: Sequence[Mapping[str, Any]]) -> str:
    stable = []
    for item in candidates:
        stable.append({
            "signature": str(item.get("signature") or ""),
            "state_mutability": str(item.get("stateMutability") or ""),
            "inputs": [
                {"name": str(arg.get("name") or ""), "type": str(arg.get("type") or "")}
                for arg in (item.get("inputs") or [])
                if isinstance(arg, Mapping)
            ],
        })
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def rank_setup_candidates(
    candidates: Sequence[Mapping[str, Any]],
    *,
    ai_module: Any | None = None,
) -> dict[str, Any]:
    """Return an ABI-bound recommendation or a deterministic no-op.

    Only enabled automatic-assist configurations invoke the provider. Provider
    errors, budget exhaustion, malformed output, and non-candidate signatures
    all fall back to the native deterministic selector.
    """
    if not isinstance(candidates, (list, tuple)) or len(candidates) < 2:
        return {"selected_signature": None, "mode": "deterministic", "reason": "not_ambiguous"}

    module = ai_module
    if module is None:
        try:
            from . import ai_harness as module
        except ImportError:
            try:
                import ai_harness as module
            except ImportError:
                return {"selected_signature": None, "mode": "deterministic", "reason": "ai_unavailable"}

    try:
        status = module.status()
        if not (
            status.get("enabled")
            and status.get("usable")
            and (status.get("auto_assist") or status.get("jev_autonomous"))
        ):
            return {"selected_signature": None, "mode": "deterministic", "reason": "automatic_assist_disabled"}
        provider = str(status.get("provider") or "")
        model = str(status.get("model") or "")
        allowed = {
            str(item.get("signature") or "")
            for item in candidates
            if isinstance(item, Mapping) and item.get("signature")
        }
        if len(allowed) < 2:
            return {"selected_signature": None, "mode": "deterministic", "reason": "insufficient_candidates"}
        compact = []
        for item in candidates[:24]:
            if not isinstance(item, Mapping):
                continue
            compact.append({
                "signature": str(item.get("signature") or ""),
                "stateMutability": str(item.get("stateMutability") or ""),
                "inputs": [
                    {
                        "name": str(arg.get("name") or ""),
                        "type": str(arg.get("type") or ""),
                    }
                    for arg in (item.get("inputs") or [])
                    if isinstance(arg, Mapping)
                ],
            })
        allowed = {
            str(item.get("signature") or "")
            for item in compact
            if item.get("signature")
        }
        if len(allowed) < 2:
            return {"selected_signature": None, "mode": "deterministic", "reason": "candidate_context_too_small"}
        result = module.request_structured(
            purpose="setup_reasoning",
            task=(
                "Rank the supplied ABI functions for establishing a test actor's initial "
                "protocol position before a local security experiment. Prefer a function "
                "whose ABI and name indicate deposit, supply, stake, provide, mint, wrap, "
                "lock, contribute, or position creation. Reject withdraw/claim/execute/admin "
                "operations and do not infer missing semantics. Select only one exact "
                "signature from the supplied candidates, or an empty string when none is "
                "clearly suitable. Do not invent functions, values, selectors, or commands."
            ),
            context={
                "abi_candidates": compact,
                "selection_constraints": {
                    "candidate_count": len(compact),
                    "allowed_signatures": sorted(allowed),
                    "read_only_model_role": True,
                    "target_address_included": False,
                    "rpc_url_included": False,
                    "source_code_included": False,
                    "credentials_included": False,
                    "execution_authority": False,
                },
            },
            required_fields=("selected_signature", "rationale"),
        )
        selected = str(result.get("selected_signature") or "").strip()
        rationale = str(result.get("rationale") or "").strip()[:500]
        if selected not in allowed:
            return {
                "selected_signature": None,
                "mode": "deterministic",
                "reason": "model_selection_not_in_candidate_set",
                "provider": provider,
                "model": model,
                "candidate_sha256": _fingerprint(candidates),
            }
        return {
            "selected_signature": selected,
            "mode": "ai_ranked_candidate",
            "reason": rationale or "Model selected an exact candidate from the supplied ABI.",
            "provider": provider,
            "model": model,
            "candidate_sha256": _fingerprint(candidates),
        }
    except Exception as exc:
        # AI assistance is advisory. A provider or quota problem must never
        # prevent deterministic local testing from continuing.
        return {
            "selected_signature": None,
            "mode": "deterministic",
            "reason": "ai_assist_unavailable:" + type(exc).__name__,
        }
