"""Independent proof dimensions and frozen control expectations."""
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

AUTHENTICITIES = {"unknown", "fixture", "local_reimplementation", "forked_deployment"}
FIDELITIES = {"unknown", "synthetic_state", "simulated_caller", "simulated_dependencies", "constrained_inputs", "real_funded"}
OUTCOMES = {"not_run", "observed", "profitable", "rejected"}
# Only families whose primary impact is availability/griefing default to the
# semantic-invariant path. Replay, signature and access-control bugs can directly
# drain assets, so they remain economic unless the auditor explicitly opts out.
NON_ECONOMIC_FAMILIES = {
    "dos", "denial_of_service", "griefing", "liveness", "governance_liveness",
    "oracle_griefing", "gas_griefing", "resource_exhaustion", "permanent_lock",
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

STORAGE_CAPABILITY_RANK = {
    "declared_only": 0,
    "partial": 1,
    "derived_per_access": 2,
}

DEFAULT_EVIDENCE_REQUIREMENTS = {
    "reentrancy": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
    "cross_function_reentrancy": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
    "read_only_reentrancy": {"call_tree": "exact", "calldata": "exact", "storage": "per_access"},
}


def trace_evidence_capabilities(
    backend, *, storage_trace_supported=False, storage_observations=0
):
    """Describe evidence dimensions without changing the experiment fidelity tier."""
    backend = str(backend or "unknown").strip().lower()
    if backend == "forge-state-diff":
        return {
            "backend": backend,
            "call_tree": "exact",
            "calldata": "exact",
            "storage": "derived_per_access",
            "storage_observations": int(storage_observations),
            "storage_source": "Vm.AccountAccess.storageAccesses",
            "storage_scope": "ordered per-account-access storage observations",
        }
    if backend == "anvil-calltracer":
        return {
            "backend": backend,
            "call_tree": "exact",
            "calldata": "exact",
            "storage": "partial" if storage_trace_supported else "declared_only",
            "storage_observations": int(storage_observations),
            "storage_source": "prestateTracer-diff" if storage_trace_supported else "manifest declarations only",
            "storage_scope": (
                "transaction-level changed slots only; read-only slots may be absent and slots are not associated with individual call frames"
                if storage_trace_supported else
                "no trace-derived storage evidence; only explicitly declared slots are available"
            ),
        }
    return {
        "backend": backend,
        "call_tree": "unavailable",
        "calldata": "unavailable",
        "storage": "declared_only",
        "storage_source": "manifest declarations only",
        "storage_scope": "unknown backend",
    }


def evaluate_evidence_requirements(
    family, capabilities, configured=None, *, require_trace_storage=False
):
    """Evaluate per-dimension requirements without inventing stronger evidence."""
    family = normalize_family(family)
    requirements = dict(DEFAULT_EVIDENCE_REQUIREMENTS.get(family, {}))
    if configured is not None:
        if not isinstance(configured, dict):
            raise ValueError("evidence_requirements must be a JSON object.")
        unknown = set(configured) - {"call_tree", "calldata", "storage"}
        if unknown:
            raise ValueError("Unknown evidence requirement dimension(s): " + ", ".join(sorted(unknown)))
        requirements.update(configured)
    if require_trace_storage and "storage" not in requirements:
        requirements["storage"] = "derived"

    missing = []
    for dimension, required in requirements.items():
        actual = capabilities.get(dimension, "unavailable")
        if dimension in {"call_tree", "calldata"}:
            accepted = required == "exact" and actual == "exact"
            if not accepted:
                missing.append({
                    "dimension": dimension, "required": required,
                    "actual": actual, "reason": "required exact execution evidence is unavailable",
                })
            continue
        if required not in {"declared_only", "derived", "per_access"}:
            raise ValueError("evidence_requirements.storage must be declared_only, derived or per_access.")
        actual_rank = STORAGE_CAPABILITY_RANK.get(actual, -1)
        required_rank = {"declared_only": 0, "derived": 1, "per_access": 2}[required]
        if actual_rank < required_rank:
            missing.append({
                "dimension": dimension, "required": required,
                "actual": actual,
                "reason": "declared slots cannot satisfy a trace-derived storage requirement",
            })
        elif required_rank > 0 and int(capabilities.get("storage_observations", 0)) <= 0:
            missing.append({
                "dimension": dimension, "required": required,
                "actual": actual,
                "reason": "backend supports this storage evidence mode but the measured run contains no derived storage observations",
            })
    return {
        "accepted": not missing,
        "family": family,
        "requirements": requirements,
        "capabilities": dict(capabilities),
        "missing": missing,
    }

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
    candidates.extend(x for x in (spec.get("fidelity_sources") or []) if isinstance(x, str))
    generator_files = spec.get("generator_files") or []
    if not isinstance(generator_files, list) or not all(isinstance(x, str) and x.strip() for x in generator_files):
        raise ValueError("generator_files must be an array of project-relative file paths.")
    # Generator bytes are fingerprinted separately so generator-only drift can
    # be distinguished from changes to the manifest, harness or command inputs.
    for scenario_name in ("control", "attack", "negative_control"):
        scenario = spec.get(scenario_name) or {}
        for key in ("argv", "prepare_argv", "semantic_check_argv", "support_files"):
            values = scenario.get(key) or []
            if isinstance(values, str):
                candidates.append(values)
            elif isinstance(values, list):
                candidates.extend(token for token in values if isinstance(token, str))
        # Recorder artifacts are outputs, not frozen inputs. Hash their paths
        # through the manifest, but never hash prior-run bytes into expectations.
        if isinstance(scenario.get("harness"), str):
            candidates.append(scenario["harness"])
    for token in candidates:
        candidate = Path(token).expanduser()
        candidate = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if candidate.is_relative_to(root) and candidate.is_file(): found.add(candidate)
    return [{"path": p.relative_to(root).as_posix(), "sha256": _sha256_file(p)} for p in sorted(found)]

def _generator_fingerprints(root, spec):
    paths = {Path(__file__).resolve()}
    for module_name in (
        "godmode.py", "forge_state_diff.py", "trace_evidence.py",
        "break_engine.py", "generator.py", "test_generation.py",
        "test_generation_analysis.py", "generation_plugins.py",
    ):
        module_path = Path(__file__).with_name(module_name)
        if module_path.is_file():
            paths.add(module_path.resolve())
    declared = spec.get("generator_files") or []
    if not isinstance(declared, list) or not all(isinstance(item, str) and item.strip() for item in declared):
        raise ValueError("generator_files must be an array of project-relative file paths.")
    for item in declared:
        path = (root / Path(item).expanduser()).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Declared generator file must be an existing project file: " + item)
        paths.add(path)
    fingerprints = []
    for path in sorted(paths):
        try:
            label = path.relative_to(root).as_posix()
        except ValueError:
            label = "lowkey-runtime/" + path.name
        fingerprints.append({"path": label, "sha256": _sha256_file(path)})
    return fingerprints


def _freeze_core(root, manifest_path, spec):
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_relative_to(root) or not manifest_path.is_file():
        raise ValueError("Control manifest must be an existing file inside the project.")
    return {
        "schema_version": 2, "manifest_path": manifest_path.relative_to(root).as_posix(),
        "manifest_sha256": _sha256_file(manifest_path), "inputs": _referenced_inputs(root, spec),
        "generator_hashes": _generator_fingerprints(root, spec),
        "experiment": {
            "same_calls_id": spec.get("same_calls_id"), "family": normalize_family(spec.get("family")),
            "target_address": str(spec.get("target_address") or "").lower(),
            "target_authenticity": spec.get("target_authenticity", "unknown"),
            "trace_backend": spec.get("trace_backend", "anvil-calltracer"),
            "freeze_inputs": spec.get("freeze_inputs") or [],
            "generator_files": spec.get("generator_files") or [],
            "source_addresses": spec.get("source_addresses") or [],
            "expected_chain_id": spec.get("expected_chain_id"),
            "expected_fork_block": spec.get("expected_fork_block"),
            "require_trace_storage": bool(spec.get("require_trace_storage", False)),
            "evidence_requirements": spec.get("evidence_requirements") or {},
            "metric_addresses": spec.get("metric_addresses") or [],
            "non_economic": bool(spec.get("non_economic", False)),
            "semantic_check_test": spec.get("semantic_check_test"),
            "require_negative_control": bool(spec.get("require_negative_control", False)),
            "trace_expectations": spec.get("trace_expectations") or [],
            "semantic_expectations": spec.get("semantic_expectations") or [],
            "scenario_parameters": spec.get("scenario_parameters") or [],
            "prestate_addresses": spec.get("prestate_addresses") or [],
            "prestate_slots": spec.get("prestate_slots") or [],
            "commands": {
                name: {key: (spec.get(name) or {}).get(key) for key in
                       ("prepare_argv", "argv", "semantic_check_argv", "semantic_check_test",
                        "harness", "state_diff_file", "support_files")}
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
               "policy": "Expectations, Lowkey gate sources, declared generator files and all referenced local command inputs are frozen before execution."}
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
    if stored.get("schema_version") != 2:
        raise ValueError("Frozen expectations use an older schema; run lk control --freeze again with the current generator.")
    core_fields = (
        "schema_version", "manifest_path", "manifest_sha256", "inputs",
        "generator_hashes", "experiment",
    )
    stored_core = {key: stored.get(key) for key in core_fields}
    stored_digest = _sha256_bytes(_canonical(stored_core).encode("utf-8"))
    if stored.get("freeze_sha256") != stored_digest:
        raise ValueError("Frozen expectations integrity digest is invalid; regenerate the freeze before validation.")
    current = _freeze_core(root, Path(manifest_path), spec)
    stable_fields = (
        "schema_version", "manifest_path", "manifest_sha256", "inputs", "experiment",
    )
    changed = [key for key in stable_fields if stored_core.get(key) != current.get(key)]
    if changed:
        raise ValueError(
            "Frozen expectations do not match the current manifest, harness, command inputs or experiment fields: "
            + ", ".join(changed)
        )
    if stored_core.get("generator_hashes") != current.get("generator_hashes"):
        stored_hashes = {item["path"]: item["sha256"] for item in stored_core["generator_hashes"]}
        current_hashes = {item["path"]: item["sha256"] for item in current["generator_hashes"]}
        changed_generators = sorted(
            path for path in set(stored_hashes) | set(current_hashes)
            if stored_hashes.get(path) != current_hashes.get(path)
        )
        return {
            "present": True, "verified": False, "requires_refreeze": True,
            "reason_code": "generator_drift",
            "reason": "Lowkey generator source changed after this experiment was frozen. The frozen harness and manifest still match, but re-freeze is required before execution or promotion.",
            "changed_generators": changed_generators,
            "stored_generator_hashes": stored_core["generator_hashes"],
            "current_generator_hashes": current["generator_hashes"],
            "path": freeze.relative_to(root).as_posix(),
            "freeze_sha256": stored_digest,
            "manifest_sha256": current["manifest_sha256"],
            "inputs": current["inputs"],
        }
    digest = _sha256_bytes(_canonical(current).encode("utf-8"))
    return {"present": True, "verified": True, "requires_refreeze": False,
            "path": freeze.relative_to(root).as_posix(),
            "freeze_sha256": digest, "manifest_sha256": current["manifest_sha256"], "inputs": current["inputs"]}
