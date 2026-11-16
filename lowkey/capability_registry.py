"""Authoritative, machine-readable inventory of Lowkey security capabilities.

Registration describes a contract and current reported implementation state. It
does not prove runtime readiness; external tool dependencies are always marked
unverified until a command performs its own preflight and evidence checks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class CapabilitySpec:
    number: int
    name: str
    title: str
    status: str
    inputs: tuple[str, ...]
    dependencies: tuple[str, ...]
    outputs: tuple[str, ...]
    safety_requirements: tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["metadata_version"] = 1
        return value


# Keep existing status labels intact. Contract fields are descriptive interface
# metadata; they do not upgrade "partial" or "adapter-required" capabilities.
_ROWS = (
    (1, "cheat-fingerprint", "Fingerprint dangerous source sequences", "partial"),
    (2, "control", "Sequential control gate", "implemented"),
    (3, "mutation-score", "Harness mutation score", "implemented"),
    (4, "target-coverage", "Coverage restricted to target lines", "implemented"),
    (5, "provenance", "Artifact hash and run provenance", "partial"),
    (6, "sandbox", "Isolated untrusted build/test execution", "partial"),
    (7, "decompile", "Unverified bytecode decompilation", "adapter-required"),
    (8, "storage-infer", "Probabilistic storage-layout inference", "partial"),
    (9, "proxy-resolve", "Generic proxy and implementation resolution", "partial"),
    (10, "selectors-full", "Runtime selector extraction and resolution", "partial"),
    (11, "cfg", "Control-flow outline", "partial"),
    (12, "reentrancy-graph", "Storage read/call/write graph", "partial"),
    (13, "fallback-map", "Fallback and callback map", "implemented"),
    (14, "calldata-mine", "Historical calldata corpus", "partial"),
    (15, "attack-forge", "Executable attack-library harness starter", "partial"),
    (16, "invariant-forge", "Invariant candidate generator", "partial"),
    (17, "archetype", "Protocol-shaped attack suites", "partial"),
    (18, "token-weird", "Adversarial token fixtures", "partial"),
    (19, "oracle-map", "Oracle dependency and skew map", "partial"),
    (20, "flashmax", "Flash-loan venue integration", "adapter-required"),
    (21, "time", "Timestamp/block-boundary campaign", "partial"),
    (22, "sig-matrix", "Signature replay matrix", "partial"),
    (23, "init-frontrun", "Initializer exposure analysis", "partial"),
    (24, "path", "Symbolic path enumeration", "adapter-required"),
    (25, "compose", "Cross-contract attack-chain planner", "partial"),
    (26, "fidelity", "Evidence fidelity ledger", "implemented"),
    (27, "reprove", "Cheatcode-free local-fork reproof", "partial"),
    (28, "economic", "Net-profit calculation", "implemented"),
    (29, "gas-ladder", "Measured gas/DoS threshold search", "partial"),
    (30, "state-diff", "Predicted/observed storage diff", "partial"),
    (31, "watch", "Deployment/code-change watcher", "partial"),
    (32, "godmode", "End-to-end audit orchestrator", "partial"),
    (33, "custody", "Asset custody and authority map", "partial"),
    (34, "questions", "Question-driven audit loop", "implemented"),
    (35, "agent-split", "Planner/attacker/verifier/critic roles", "partial"),
    (36, "verify-hack", "Historical exploit replay", "adapter-required"),
    (37, "unravel", "Transaction call-tree decoder", "partial"),
    (38, "bundle", "Private bundle simulation", "adapter-required"),
    (39, "sandwich", "Sandwich/JIT ordering simulation", "adapter-required"),
    (40, "fork-cache", "Local Anvil snapshot cache", "partial"),
    (41, "upgrade-diff", "Implementation upgrade diff", "partial"),
    (42, "cross-vm", "Cross-VM static/native detector routing", "partial"),
    (43, "learn", "Evidence-backed experience learning", "implemented"),
    (44, "report", "Reproducible audit report", "implemented"),
)

# name -> (inputs, dependencies, outputs, safety requirements)
_CONTRACTS = {
    "cheat-fingerprint": (("project_root:Path", "source_paths:Path[]"), ("tool:solidity-parser",), ("fingerprint_matches", "source_locations"), ("read-only static scan", "matches are review leads, not vulnerability proof")),
    "control": (("control_manifest:Path", "project_root:Path", "rpc_url:URL"), ("tool:forge", "tool:anvil", "capability:fidelity"), ("control_verdict", "matched_execution_evidence", "reason_code"), ("validate frozen inputs before execution", "callTracer mode is restricted to local Anvil")),
    "mutation-score": (("mutation_manifest:Path", "minimum_score:float", "timeout_seconds:int"), ("tool:forge",), ("mutation_score", "killed_mutants", "surviving_mutants"), ("run only in an isolated project/test workspace", "score is test sensitivity, not exploit proof")),
    "target-coverage": (("source_file:Path", "start_line:int?", "end_line:int?"), ("tool:forge-lcov",), ("target_line_coverage", "uncovered_lines"), ("build/test execution is local", "coverage is reachability, not security proof")),
    "provenance": (("evidence_artifacts:Path[]", "chain_id:int?", "fork_block:int?"), ("tool:sha256",), ("artifact_hashes", "run_provenance"), ("sign only with explicitly configured signing material", "hash identity does not prove evidence correctness")),
    "sandbox": (("project_root:Path", "command:string[]", "timeout_seconds:int"), ("tool:bubblewrap",), ("isolated_exit_code", "sandbox_output"), ("network disabled", "fail closed when isolation is unavailable")),
    "decompile": (("bytecode:bytes|target_address:Address", "rpc_url:URL?", "output_path:Path"), ("tool:heimdall-adapter",), ("decompiled_pseudocode", "decompiler_metadata"), ("read-only chain access", "decompiled output is unverified and adapter-required")),
    "storage-infer": (("target_address:Address", "rpc_url:URL", "slot_range:int?"), ("tool:rpc-provider",), ("candidate_storage_layout", "confidence_annotations"), ("read-only RPC calls", "probabilistic inference must remain labeled as such")),
    "proxy-resolve": (("target_address:Address", "rpc_url:URL"), ("tool:rpc-provider",), ("proxy_kind", "implementation_address", "admin_or_beacon"), ("read-only RPC calls", "unknown proxy patterns must remain unresolved")),
    "selectors-full": (("target_address:Address", "rpc_url:URL"), ("tool:rpc-provider", "tool:selector-database"), ("runtime_selectors", "candidate_signatures"), ("read-only RPC calls", "selector matches are candidates, not ABI authenticity")),
    "cfg": (("project_root:Path", "contract_or_function:string"), ("tool:solidity-parser",), ("control_flow_outline", "source_locations"), ("read-only static analysis", "outline completeness must be reported")),
    "reentrancy-graph": (("project_root:Path", "contract_or_function:string?"), ("tool:solidity-parser",), ("storage_read_call_write_graph", "candidate_reentry_paths"), ("read-only static analysis", "graph edges are candidates until dynamically verified")),
    "fallback-map": (("project_root:Path",), ("tool:solidity-parser",), ("fallback_handlers", "callback_handlers"), ("read-only static analysis", "source pattern matches are not runtime proof")),
    "calldata-mine": (("target_address:Address", "rpc_url:URL", "from_block:int", "to_block:int"), ("tool:archive-rpc",), ("calldata_samples", "transaction_references"), ("read-only archive queries", "bound block range and sample count; never broadcast transactions")),
    "attack-forge": (("attack_spec:Path", "target_address:Address?", "actor_profiles:string[]"), ("tool:forge", "tool:anvil"), ("generated_harness", "execution_artifacts", "machine_readable_refusal"), ("local Anvil only for execution", "generated harnesses require review and matched controls")),
    "invariant-forge": (("project_root:Path", "protocol_profile:string?", "seed_values:object?"), ("tool:forge",), ("invariant_candidates", "generated_test_harness"), ("local test execution only", "candidate invariants are not proof of completeness")),
    "archetype": (("project_root:Path", "source_files:Path[]"), ("tool:solidity-parser",), ("protocol_classification", "assumption_ledger", "capability_skips"), ("read-only source analysis", "ambiguous targets remain UNCLASSIFIED")),
    "token-weird": (("token_interface:ABI", "token_behaviors:string[]"), ("tool:forge",), ("adversarial_token_fixtures", "compatibility_cases"), ("fixtures are local test artifacts", "never deploy or transfer real assets implicitly")),
    "oracle-map": (("project_root:Path", "target_address:Address?"), ("tool:solidity-parser",), ("oracle_dependency_graph", "skew_and_staleness_leads"), ("read-only static analysis", "oracle manipulation is not claimed without execution evidence")),
    "flashmax": (("venue:string", "asset:Address", "amount:uint256", "callback_adapter:Path"), ("tool:flash-loan-adapter", "tool:forge"), ("venue_integration_plan", "callback_harness"), ("adapter-required", "no borrowing or transaction broadcast from planning mode")),
    "time": (("project_root:Path", "fork_block:int?", "timestamp_boundaries:uint256[]"), ("tool:forge", "tool:anvil"), ("boundary_campaign", "execution_results"), ("local fork/test execution only", "bound the number of test cases and timestamp changes")),
    "sig-matrix": (("project_root:Path", "signature_schema:string", "domain_values:object"), ("tool:forge",), ("signature_replay_cases", "nonce_and_domain_results"), ("local tests only", "private keys must be generated test keys, never stored in artifacts")),
    "init-frontrun": (("project_root:Path",), ("tool:solidity-parser",), ("initializer_exposure_map", "source_locations"), ("read-only static analysis", "do not attempt initialization on a live deployment")),
    "path": (("project_root:Path", "contract:string", "function:string"), ("tool:symbolic-executor-adapter",), ("symbolic_paths", "path_constraints"), ("adapter-required", "resource limits and unsupported opcodes must be explicit")),
    "compose": (("target_capabilities:string[]", "abi_sources:Path[]", "attacker_constraints:object"), ("capability:invariant-forge", "capability:proxy-resolve"), ("candidate_attack_chains", "dependency_graph"), ("planning only until separately approved execution", "never infer unsupported callbacks or protocols")),
    "fidelity": (("harness:Path", "evidence_artifacts:Path[]"), ("tool:evidence-ledger",), ("fidelity_classification", "evidence_limitations"), ("preserve UNKNOWN and evidence degradation", "static fidelity scans cannot authenticate deployment identity")),
    "reprove": (("harness:Path", "rpc_url:URL", "fork_block:int", "target_address:Address", "profit_address:Address", "prior_cost_wei:uint256"), ("tool:forge", "tool:anvil"), ("mined_receipt", "execution_trace", "gas_cost", "net_profit"), ("local fork only", "subtract measured setup costs and replay gas", "fixture proof is not production authenticity")),
    "economic": (("asset_balances:object", "native_value_wei:uint256", "gas_cost_wei:uint256", "prior_cost_wei:uint256"), (), ("gross_value", "total_cost", "net_profit", "unknown_costs"), ("do not invent asset prices or unknown costs", "no transaction is broadcast")),
    "gas-ladder": (("harness:Path", "gas_limit_range:object", "timeout_seconds:int"), ("tool:forge", "tool:anvil"), ("gas_thresholds", "out_of_gas_boundary"), ("bounded local execution", "never present synthetic gas thresholds as mainnet measurements")),
    "state-diff": (("before_state:Path|block", "after_state:Path|block", "target_address:Address"), ("tool:forge", "tool:anvil"), ("predicted_storage_diff", "observed_storage_diff", "parity_limits"), ("structural evidence only", "never equate raw state deltas with net EOA profit")),
    "watch": (("target_address:Address", "rpc_url:URL", "poll_interval_seconds:int"), ("tool:rpc-provider",), ("code_change_events", "observed_block_hashes"), ("read-only RPC polling", "bounded poll interval and no signing capability")),
    "godmode": (("project_root:Path", "target_address:Address?", "rpc_url:URL?"), ("capability:cheat-fingerprint", "capability:proxy-resolve", "capability:questions", "capability:report"), ("audit_report", "stage_evidence", "explicit_skips"), ("source-only by default", "active attack execution requires explicit opt-in and local Anvil", "partial stages remain partial")),
    "custody": (("project_root:Path", "asset_list:Address[]?"), ("tool:solidity-parser",), ("asset_custody_map", "authority_edges"), ("read-only static analysis", "role edges are leads until verified against runtime state")),
    "questions": (("project_root:Path", "audit_context:object?", "review_focus:string[]?"), ("tool:source-parser",), ("structured_audit_questions", "review_queue"), ("do not store secrets or unnecessary absolute paths", "questions guide review; they are not findings")),
    "agent-split": (("audit_plan:object", "role_constraints:object", "evidence_scope:Path[]"), ("tool:role-runtime", "capability:questions"), ("planner_tasks", "attacker_hypotheses", "verifier_checks", "critic_objections"), ("bounded roles with explicit permissions", "no autonomous transaction signing or unbounded external actions")),
    "verify-hack": (("exploit_reference:string", "target_address:Address", "rpc_url:URL", "fork_block:int"), ("tool:archive-rpc", "tool:exploit-fixture"), ("replay_result", "reproduction_artifacts"), ("adapter-required", "local fork only", "historical reports are not proof until replayed")),
    "unravel": (("transaction_hash:Hash32", "rpc_url:URL"), ("tool:trace-provider",), ("decoded_call_tree", "unknown_selector_nodes"), ("read-only trace queries", "preserve undecoded nodes rather than guessing")),
    "bundle": (("transactions:RawTransaction[]", "relay:string", "simulation_block:int"), ("tool:relay-simulator",), ("bundle_simulation", "ordering_and_failure_report"), ("adapter-required", "never broadcast or submit a private bundle")),
    "sandwich": (("pending_transaction:RawTransaction", "pool_adapter:Path", "simulation_block:int"), ("tool:pending-tx-feed", "tool:pool-simulator"), ("ordering_simulation", "slippage_and_fee_estimates"), ("adapter-required", "simulation only; no transaction broadcast")),
    "fork-cache": (("rpc_url:URL", "chain_id:int", "fork_block:int"), ("tool:anvil",), ("fork_cache_entry", "cache_fingerprint"), ("local Anvil process only", "cache key includes chain and block; no signing")),
    "upgrade-diff": (("old_implementation:Address", "new_implementation:Address", "rpc_url:URL?"), ("tool:rpc-provider", "capability:proxy-resolve"), ("selector_diff", "storage_layout_diff", "upgrade_risk_leads"), ("read-only chain access", "layout incompatibilities are leads until validated")),
    "cross-vm": (("project_root:Path", "source_languages:string[]"), ("tool:native-detector-adapters",), ("detector_routes", "unsupported_language_report"), ("no cross-chain writes", "unsupported languages stay explicitly unsupported")),
    "learn": (("project_context:object", "verified_evidence:Path[]", "lesson:string"), ("tool:evidence-ledger",), ("experience_record", "reusable_review_hint"), ("store evidence-backed lessons only", "redact secrets and absolute paths", "preserve confidence and provenance")),
    "report": (("evidence_artifacts:Path[]", "project_revision:string", "scope:string"), ("tool:evidence-ledger", "tool:sha256"), ("reproducible_audit_report", "artifact_hash_manifest"), ("preserve UNKNOWN and skipped stages", "do not strengthen claims beyond linked evidence")),
}

def _build_registry() -> dict[str, CapabilitySpec]:
    if len(_ROWS) != 44:
        raise RuntimeError(f"Expected 44 capability rows, found {len(_ROWS)}")
    if set(_CONTRACTS) != {row[1] for row in _ROWS}:
        missing = {row[1] for row in _ROWS} - set(_CONTRACTS)
        extra = set(_CONTRACTS) - {row[1] for row in _ROWS}
        raise RuntimeError(f"Capability contract mismatch; missing={sorted(missing)}, extra={sorted(extra)}")
    registry = {}
    for number, name, title, status in _ROWS:
        inputs, dependencies, outputs, safety = _CONTRACTS[name]
        if not all((inputs, outputs, safety)):
            raise RuntimeError(f"Capability '{name}' is missing contract fields")
        registry[name] = CapabilitySpec(
            number=number,
            name=name,
            title=title,
            status=status,
            inputs=inputs,
            dependencies=dependencies,
            outputs=outputs,
            safety_requirements=safety,
        )
    for name, spec in registry.items():
        for dependency in spec.dependencies:
            if dependency.startswith("capability:") and dependency.split(":", 1)[1] not in registry:
                raise RuntimeError(f"Capability '{name}' references unknown dependency '{dependency}'")
    return registry


CAPABILITY_REGISTRY = _build_registry()
CAPABILITIES = [
    (spec.number, spec.name, spec.title, spec.status)
    for spec in CAPABILITY_REGISTRY.values()
]

ROUTED_COMMANDS = (
    "capabilities", "godmode", "control", "trace-parity", "steps", "mutation-score",
    "target-coverage", "provenance", "fidelity", "sandbox", "cheat-fingerprint", "decompile",
    "storage-infer", "proxy-resolve", "selectors-full", "cfg",
    "reentrancy-graph", "fallback-map", "calldata-mine", "attack-forge",
    "invariant-forge", "archetype", "assumptions", "capability", "token-weird", "oracle-map", "skew",
    "flashmax", "time", "sig-matrix", "init-frontrun", "path", "compose",
    "reprove", "economic", "gas-ladder", "watch", "custody", "agent-split",
    "verify-hack", "unravel", "bundle", "sandwich", "jit", "fork-cache",
    "upgrade-diff", "cross-vm", "learn", "report", "questions",
)
SPECIALIZED_ALIAS_COMMANDS = frozenset({"attack", "block", "blocks", "forge", "coverage", "state-diff"})
RPC_CONTEXT_COMMANDS = frozenset({
    "attack", "block", "coverage", "forge", "godmode", "control", "trace-parity",
    "decompile", "storage-infer", "proxy-resolve", "selectors-full",
    "reentrancy-graph", "fallback-map", "calldata-mine", "oracle-map", "skew",
    "flashmax", "time", "sig-matrix", "init-frontrun", "path", "compose",
    "reprove", "economic", "gas-ladder", "watch", "custody", "verify-hack",
    "unravel", "bundle", "sandwich", "jit", "fork-cache", "upgrade-diff",
    "cross-vm", "state-diff",
})


def get_capability(name: str) -> CapabilitySpec | None:
    return CAPABILITY_REGISTRY.get(str(name or "").strip().lower())


def list_capabilities() -> list[dict]:
    return [spec.to_dict() for spec in CAPABILITY_REGISTRY.values()]


def dependency_plan(name: str) -> dict | None:
    """Return transitive declared dependencies without claiming runtime readiness."""
    root = get_capability(name)
    if root is None:
        return None
    capabilities: list[str] = []
    tools: list[str] = []
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(spec: CapabilitySpec) -> None:
        if spec.name in visited:
            return
        if spec.name in visiting:
            raise RuntimeError(f"Capability dependency cycle at '{spec.name}'")
        visiting.add(spec.name)
        for dependency in spec.dependencies:
            kind, _, value = dependency.partition(":")
            if kind == "capability":
                child = get_capability(value)
                if child is None:
                    raise RuntimeError(f"Unknown capability dependency '{dependency}'")
                visit(child)
                if value not in capabilities:
                    capabilities.append(value)
            elif kind == "tool":
                if value not in tools:
                    tools.append(value)
            else:
                raise RuntimeError(f"Unknown dependency type '{dependency}'")
        visiting.remove(spec.name)
        visited.add(spec.name)

    visit(root)
    return {
        "capability": root.to_dict(),
        "transitive_capability_dependencies": capabilities,
        "external_tool_dependencies": tools,
        "runtime_readiness": "NOT_CHECKED",
    }
