"""Independent proof dimensions and frozen control expectations."""
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

AUTHENTICITIES = {"unknown", "fixture", "local_reimplementation", "forked_deployment"}
FIDELITIES = {"unknown", "synthetic_state", "simulated_caller", "simulated_dependencies", "constrained_inputs", "real_funded"}
OUTCOMES = {"not_run", "observed", "profitable", "rejected"}
NON_ECONOMIC_FAMILIES = {
    "dos", "denial_of_service", "griefing", "liveness", "signature_replay",
    "replay", "authorization_bypass", "access_control", "governance_takeover",
    "governance_liveness", "integrity", "oracle_griefing",
}

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()
def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
def normalize_family(value):
    return str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")

def evaluate_economic_policy(family, net_profit_wei=None, *, non_economic=False, semantic_invariant_verified=False):
    family = normalize_family(family)
    requested_non_economic = bool(non_economic or family in NON_ECONOMIC_FAMILIES)
    if requested_non_economic:
        if not semantic_invariant_verified:
            return {"accepted": False, "economic": False, "net_profit_wei": net_profit_wei,
                    "reason": "A non-economic result requires a separately executed, passing semantic invariant.",
                    "promotion_cap": "SIMULATED_BREAK"}
        return {"accepted": True, "economic": False, "net_profit_wei": net_profit_wei,
                "reason": "Semantic impact was asserted; no profitability is claimed.",
                "promotion_cap": "SIMULATED_BREAK"}
    if not isinstance(net_profit_wei, int):
        return {"accepted": False, "economic": True, "net_profit_wei": net_profit_wei,
                "reason": "Economic attack families require a measured integer net-profit value.",
                "promotion_cap": "OBSERVED"}
    if net_profit_wei <= 0:
        return {"accepted": False, "economic": True, "net_profit_wei": net_profit_wei,
                "reason": "Net profit after measured costs must be positive for an economic proof.",
                "promotion_cap": "OBSERVED"}
    return {"accepted": True, "economic": True, "net_profit_wei": net_profit_wei,
            "reason": "Measured net profit is positive.", "promotion_cap": None}

def classify_proof(target_authenticity="unknown", fidelity="unknown", outcome="observed",
                   *, authenticity_verified=False, human_confirmed=False):
    authenticity = str(target_authenticity or "unknown").strip().lower()
    fidelity = str(fidelity or "unknown").strip().lower()
    outcome = str(outcome or "observed").strip().lower()
    if authenticity not in AUTHENTICITIES:
        raise ValueError("target_authenticity must be one of: " + ", ".join(sorted(AUTHENTICITIES)))
    if fidelity not in FIDELITIES:
        raise ValueError("fidelity must be one of: " + ", ".join(sorted(FIDELITIES)))
    if outcome not in OUTCOMES:
        raise ValueError("outcome must be one of: " + ", ".join(sorted(OUTCOMES)))
    authentic_fork = authenticity == "forked_deployment" and bool(authenticity_verified)
    realistic = fidelity == "real_funded"
    if outcome == "rejected": status = "REJECTED"
    elif outcome == "not_run": status = "UNPROVEN"
    elif authenticity in {"fixture", "local_reimplementation"} or fidelity in {
        "synthetic_state", "simulated_dependencies"
    }: status = "SIMULATED_BREAK"
    elif authentic_fork and fidelity in {"simulated_caller", "constrained_inputs"}: status = "FORK_OBSERVED"
    elif authentic_fork and realistic and outcome == "profitable": status = "PROFITABLE"
    elif authentic_fork and realistic: status = "FORK_REPRODUCED"
    elif authentic_fork: status = "FORK_OBSERVED"
    else: status = "OBSERVED"
    if human_confirmed and outcome in {"observed", "profitable"}: status = "HUMAN_CONFIRMED"
    return {
        "target_authenticity": authenticity, "target_authenticity_verified": bool(authenticity_verified),
        "fidelity": fidelity, "outcome": outcome, "human_confirmed": bool(human_confirmed), "status": status,
        "status_axes": {"target_authenticity": authenticity, "fidelity": fidelity, "outcome": outcome},
        "status_policy": ("A fixture or local reimplementation cannot become deployment proof. "
            "FORK_REPRODUCED/PROFITABLE require an independently verified forked deployment; "
            "PROFITABLE additionally requires real-funded execution. HUMAN_CONFIRMED is explicit."),
    }

def _referenced_inputs(root, spec):
    found = set()
    candidates = [x for x in (spec.get("freeze_inputs") or []) if isinstance(x, str)]
    for scenario_name in ("control", "attack", "negative_control"):
        scenario = spec.get(scenario_name) or {}
        for key in ("argv", "prepare_argv", "semantic_check_argv", "support_files"):
            values = scenario.get(key) or []
            if isinstance(values, str):
                candidates.append(values)
            elif isinstance(values, list):
                candidates.extend(token for token in values if isinstance(token, str))
        for key in ("harness", "state_diff_file"):
            if isinstance(scenario.get(key), str):
                candidates.append(scenario[key])
    for token in candidates:
        candidate = Path(token).expanduser()
        candidate = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if candidate.is_relative_to(root) and candidate.is_file(): found.add(candidate)
    return [{"path": p.relative_to(root).as_posix(), "sha256": _sha256_file(p)} for p in sorted(found)]

def _freeze_core(root, manifest_path, spec):
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_relative_to(root) or not manifest_path.is_file():
        raise ValueError("Control manifest must be an existing file inside the project.")
    return {
        "schema_version": 1, "manifest_path": manifest_path.relative_to(root).as_posix(),
        "manifest_sha256": _sha256_file(manifest_path), "inputs": _referenced_inputs(root, spec),
        "experiment": {
            "same_calls_id": spec.get("same_calls_id"), "family": normalize_family(spec.get("family")),
            "target_address": str(spec.get("target_address") or "").lower(),
            "target_authenticity": spec.get("target_authenticity", "unknown"),
            "trace_backend": spec.get("trace_backend", "anvil-calltracer"),
            "freeze_inputs": spec.get("freeze_inputs") or [],
            "source_addresses": spec.get("source_addresses") or [],
            "expected_chain_id": spec.get("expected_chain_id"),
            "expected_fork_block": spec.get("expected_fork_block"),
            "require_trace_storage": bool(spec.get("require_trace_storage", False)),
            "metric_addresses": spec.get("metric_addresses") or [],
            "non_economic": bool(spec.get("non_economic", False)),
            "require_negative_control": bool(spec.get("require_negative_control", False)),
            "trace_expectations": spec.get("trace_expectations") or [],
            "semantic_expectations": spec.get("semantic_expectations") or [],
            "scenario_parameters": spec.get("scenario_parameters") or [],
            "prestate_addresses": spec.get("prestate_addresses") or [],
            "prestate_slots": spec.get("prestate_slots") or [],
            "commands": {
                name: {key: (spec.get(name) or {}).get(key) for key in
                       ("prepare_argv", "argv", "semantic_check_argv", "harness", "state_diff_file")}
                for name in ("control", "attack", "negative_control") if spec.get(name)
            },
        },
    }

def freeze_control_manifest(root, manifest_path, spec, output_path=None):
    root = Path(root).resolve()
    core = _freeze_core(root, Path(manifest_path), spec)
    digest = _sha256_bytes(_canonical(core).encode("utf-8"))
    payload = {**core, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "freeze_sha256": digest,
               "policy": "Expectations and all referenced local command inputs are frozen before execution."}
    output = Path(output_path or ".audit/godmode/control.freeze.json")
    output = root / output if not output.is_absolute() else output
    if not output.resolve().is_relative_to(root): raise ValueError("Freeze output must stay inside the project.")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return payload, output

def validate_control_freeze(root, manifest_path, spec, *, required=False, freeze_path=".audit/godmode/control.freeze.json"):
    root = Path(root).resolve()
    freeze = Path(freeze_path)
    freeze = root / freeze if not freeze.is_absolute() else freeze
    if not freeze.is_file():
        if required: raise ValueError("Frozen expectations are required. Run lk control --freeze before validation.")
        return {"present": False, "verified": False, "path": None,
                "reason": "No frozen expectations; result must remain review-only."}
    stored = json.loads(freeze.read_text(encoding="utf-8"))
    current = _freeze_core(root, Path(manifest_path), spec)
    digest = _sha256_bytes(_canonical(current).encode("utf-8"))
    if stored.get("freeze_sha256") != digest:
        raise ValueError("Frozen expectations do not match the current manifest, command arguments, or referenced script hashes.")
    if {key: stored.get(key) for key in current} != current:
        raise ValueError("Frozen expectation contents do not match the recomputed experiment.")
    return {"present": True, "verified": True, "path": freeze.relative_to(root).as_posix(),
            "freeze_sha256": digest, "manifest_sha256": current["manifest_sha256"], "inputs": current["inputs"]}
