"""Typed, evidence-preserving deployment dependency graph.

This module normalizes compiler observations for planning and automation. It
never promotes a source hint or same-chain address into a reusable deployment:
reuse requires complete managed network identity and runtime verification.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping


def _chain_id(value: Any) -> int | None:
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def _network_identity(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    keys = (
        "project_id", "project_root", "network_session_id", "session_kind",
        "chain_id", "genesis_hash", "identity_block_hash",
        "identity_block_number", "rpc_fingerprint", "rpc_origin",
        "reuse_permitted",
    )
    result = {key: value.get(key) for key in keys if value.get(key) is not None}
    return result or None


def _same_network(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool:
    """Strict network-session equality; chain ID and genesis alone are not enough."""
    required = ("project_id", "network_session_id", "chain_id", "genesis_hash")
    if any(expected.get(key) is None or observed.get(key) is None for key in required):
        return False
    if str(expected.get("project_id")) != str(observed.get("project_id")):
        return False
    if str(expected.get("network_session_id")) != str(observed.get("network_session_id")):
        return False
    expected_chain = _chain_id(expected.get("chain_id"))
    observed_chain = _chain_id(observed.get("chain_id"))
    if expected_chain is None or expected_chain != observed_chain:
        return False
    if str(expected.get("genesis_hash") or "").lower() != str(observed.get("genesis_hash") or "").lower():
        return False
    expected_block = expected.get("identity_block_hash")
    if expected_block is not None and str(expected_block).lower() != str(observed.get("identity_block_hash") or "").lower():
        return False
    return True


@dataclass(frozen=True)
class DependencyNode:
    id: str
    category: str
    source_identity: str | None
    source_path: str | None
    resolution_status: str
    deployment_status: str
    address: str | None
    network_identity: Mapping[str, Any] | None
    evidence: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "source_identity": self.source_identity,
            "source_path": self.source_path,
            "resolution_status": self.resolution_status,
            "deployment_status": self.deployment_status,
            "address": self.address,
            "network_identity": dict(self.network_identity) if self.network_identity else None,
            "evidence": [dict(item) for item in self.evidence],
        }


@dataclass(frozen=True)
class DependencyEdge:
    source: str
    target: str
    kind: str
    confidence: str
    resolution_status: str
    requires_resolution: bool
    auto_deploy: bool
    creation_phase: str | None
    function: str | None
    link_references: tuple[tuple[int, int], ...]
    origin: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source,
            "to": self.target,
            "kind": self.kind,
            "confidence": self.confidence,
            "resolution_status": self.resolution_status,
            "requires_resolution": self.requires_resolution,
            "auto_deploy": self.auto_deploy,
            "creation_phase": self.creation_phase,
            "function": self.function,
            "link_references": [list(item) for item in self.link_references],
            "origin": dict(self.origin),
        }


@dataclass(frozen=True)
class DependencyGraph:
    nodes: tuple[DependencyNode, ...]
    edges: tuple[DependencyEdge, ...]
    cycles: tuple[tuple[str, ...], ...]
    library_deployment_order: tuple[str, ...]
    planning_status: str
    execution_status: str
    network_identity: Mapping[str, Any] | None
    warnings: tuple[str, ...]
    external_manifest: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "planning_status": self.planning_status,
            "execution_status": self.execution_status,
            "network_identity": dict(self.network_identity) if self.network_identity else None,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "cycles": [list(cycle) for cycle in self.cycles],
            "library_deployment_order": list(self.library_deployment_order),
            "summary": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "unresolved_edges": sum(
                    1 for edge in self.edges
                    if edge.requires_resolution and edge.resolution_status not in {
                        "RESOLVED", "IDENTIFIED_BY_COMPILER",
                    }
                ),
                "deployable_library_edges": sum(
                    1 for edge in self.edges
                    if edge.kind == "solidity-library-link" and edge.auto_deploy
                ),
                "cycles": len(self.cycles),
            },
            "warnings": list(self.warnings),
            "external_manifest": dict(self.external_manifest),
        }


def build_dependency_graph(
    compiler_report: Mapping[str, Any] | None,
    *,
    network_identity: Mapping[str, Any] | None = None,
    deployment_records: Iterable[Mapping[str, Any]] | Mapping[str, Mapping[str, Any]] | None = None,
    external_manifest: Mapping[str, Any] | None = None,
) -> DependencyGraph:
    """Convert source-matched compiler evidence into typed nodes and edges.

    Deployment records are considered only when a network identity is supplied.
    An address from another session, even with the same chain ID and genesis,
    is excluded. This graph is analysis evidence, not an approved deploy plan.
    """
    report = compiler_report if isinstance(compiler_report, Mapping) else {}
    network = _network_identity(network_identity)
    manifest = external_manifest if isinstance(external_manifest, Mapping) else {
        "status": "NOT_PRESENT", "path": ".audit/dependencies.json",
        "schema": None, "sha256": None, "network_identity": None,
        "dependencies": [], "warnings": [],
    }
    manifest_status = str(manifest.get("status") or "BLOCKED").upper()
    warnings = [str(item) for item in (report.get("warnings") or []) if isinstance(item, str)]
    warnings.extend(str(item) for item in (manifest.get("warnings") or []) if isinstance(item, str))
    manifest_summary = {
        "status": manifest_status,
        "path": str(manifest.get("path") or ".audit/dependencies.json"),
        "schema": manifest.get("schema"),
        "sha256": manifest.get("sha256"),
        "dependency_count": (
            len(manifest.get("dependencies") or [])
            if isinstance(manifest.get("dependencies"), list) else 0
        ),
    }
    if not report.get("available"):
        warnings.append("Source-matched compiler dependency evidence is unavailable.")

    raw_contracts = report.get("contracts")
    contracts = [row for row in raw_contracts if isinstance(row, Mapping)] if isinstance(raw_contracts, list) else []
    raw_edges = report.get("edges")
    evidence_edges = [edge for edge in raw_edges if isinstance(edge, Mapping)] if isinstance(raw_edges, list) else []
    if isinstance(deployment_records, Mapping):
        records = [row for row in deployment_records.values() if isinstance(row, Mapping)]
    elif deployment_records is None:
        records = []
    else:
        records = [row for row in deployment_records if isinstance(row, Mapping)]

    contract_ids = {str(row.get("id")) for row in contracts if row.get("id")}
    records_by_identity: dict[str, list[Mapping[str, Any]]] = {}
    if network is not None:
        for record in records:
            identity = str(record.get("qualified_identity") or "")
            observed = record.get("network")
            if (
                identity and isinstance(observed, Mapping)
                and _same_network(network, observed)
                and record.get("reuse_permitted") is True
            ):
                records_by_identity.setdefault(identity, []).append(record)

    def deployment_state(identity: str) -> tuple[str, str | None, Mapping[str, Any] | None]:
        if network is None or deployment_records is None:
            return "NOT_TESTED", None, None
        candidates = records_by_identity.get(identity, [])
        if len(candidates) > 1:
            warnings.append(
                f"Multiple session-matched deployment records exist for {identity}; address reuse is ambiguous."
            )
            return "REVIEW_REQUIRED", None, None
        if not candidates:
            return "NOT_DEPLOYED", None, None
        record = candidates[0]
        observed_evidence = {
            "origin": "managed-network-deployment-registry",
            "role": record.get("role"),
            "operation_key": record.get("operation_key"),
            "deployment_transaction": record.get("deployment_transaction"),
            "artifact_sha256": record.get("artifact_sha256"),
            "artifact_current_match": record.get("artifact_current_match") is True,
            "runtime_code_hash": record.get("runtime_code_hash"),
            "runtime_verification": record.get("runtime_verification"),
            "last_verified_at": record.get("last_verified_at") or record.get("recorded_at"),
            "network_session_id": (
                record.get("network", {}).get("network_session_id")
                if isinstance(record.get("network"), Mapping) else None
            ),
        }
        address = record.get("address")
        if not _is_address(address):
            return "DEPLOYED_UNVERIFIED", None, observed_evidence
        if record.get("artifact_current_match") is not True:
            # A previously verified runtime cannot prove today's artifact is identical.
            return "DEPLOYED_ARTIFACT_UNVERIFIED", None, observed_evidence
        runtime = str(record.get("runtime_verification") or "UNVERIFIED").upper()
        if runtime == "MATCHED":
            # This is persisted last-check evidence, not a fresh RPC runtime read.
            return "DEPLOYED_RUNTIME_MATCHED_AT_LAST_CHECK", str(address), observed_evidence
        return "DEPLOYED_UNVERIFIED", str(address), observed_evidence

    nodes: dict[str, DependencyNode] = {}

    def add_node(
        identity: str,
        category: str,
        *,
        source_identity: str | None = None,
        source_path: str | None = None,
        resolution_status: str = "UNRESOLVED",
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if not identity:
            return
        existing = nodes.get(identity)
        collected = list(existing.evidence) if existing else []
        if evidence is not None and dict(evidence) not in collected:
            collected.append(dict(evidence))
        address = existing.address if existing else None
        deployment_status = existing.deployment_status if existing else "NOT_TESTED"
        if identity in contract_ids and (existing is None or existing.deployment_status == "NOT_TESTED"):
            deployment_status, address, deployment_evidence = deployment_state(identity)
            if deployment_evidence is not None and dict(deployment_evidence) not in collected:
                collected.append(dict(deployment_evidence))
        nodes[identity] = DependencyNode(
            id=identity,
            category=category if existing is None or existing.category == "dependency" else existing.category,
            source_identity=source_identity or (existing.source_identity if existing else None),
            source_path=source_path or (existing.source_path if existing else None),
            resolution_status=(
                resolution_status
                if existing is None or existing.resolution_status == "UNRESOLVED"
                else existing.resolution_status
            ),
            deployment_status=deployment_status,
            address=address,
            network_identity=network,
            evidence=tuple(collected),
        )

    def contract_category(row: Mapping[str, Any]) -> str:
        kind = str(row.get("contract_kind") or "contract").lower()
        if kind == "library":
            return "solidity-library"
        if kind == "interface":
            return "solidity-interface"
        return "solidity-contract"

    contract_by_id = {str(row.get("id")): row for row in contracts if row.get("id")}
    for row in contracts:
        identity = str(row.get("id") or "")
        if not identity:
            warnings.append("Compiler contract row has no stable source-qualified identity.")
            continue
        add_node(
            identity,
            contract_category(row),
            source_identity=identity,
            source_path=str(row.get("source") or "") or None,
            resolution_status="IDENTIFIED_BY_COMPILER",
            evidence={
                "origin": "solc-ast:ContractDefinition",
                "build_info": row.get("compiler_build_info"),
                "declaration_id": row.get("declaration_id"),
            },
        )

    typed_edges: list[DependencyEdge] = []
    for raw in evidence_edges:
        source = str(raw.get("from") or "")
        target = str(raw.get("to") or "")
        kind = str(raw.get("kind") or "unknown")
        confidence = str(raw.get("confidence") or "UNVERIFIED")
        edge_evidence = raw.get("evidence") if isinstance(raw.get("evidence"), Mapping) else {}
        if source and source not in nodes:
            add_node(source, "source-contract", source_identity=source, resolution_status="REVIEW_REQUIRED")
        target_row = contract_by_id.get(target)
        if target and target not in nodes:
            if kind == "constructor-input":
                category, node_resolution = "constructor-value", str(raw.get("resolution_status") or "VALUE_REQUIRED")
            elif kind == "solidity-library-link":
                category, node_resolution = "solidity-library", "LIBRARY_ARTIFACT_UNRESOLVED"
            elif kind == "creation-expression":
                category, node_resolution = "created-contract", "IDENTIFIED_BY_COMPILER"
            elif kind in {"typed-parameter-reference", "state-contract-reference"}:
                category, node_resolution = "contract-reference", "CONTRACT_INSTANCE_UNRESOLVED"
            else:
                category, node_resolution = "dependency", "REVIEW_REQUIRED"
            add_node(
                target, category,
                source_identity=target if target_row else None,
                source_path=(str(target_row.get("source") or "") if target_row else "") or None,
                resolution_status=node_resolution,
                evidence={"origin": str(raw.get("source") or "compiler-evidence"), **dict(edge_evidence)},
            )

        refs: list[tuple[int, int]] = []
        raw_refs = raw.get("link_references")
        if isinstance(raw_refs, list):
            for item in raw_refs:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    start, length = item
                    if (
                        isinstance(start, int) and not isinstance(start, bool) and start >= 0
                        and isinstance(length, int) and not isinstance(length, bool) and length > 0
                    ):
                        refs.append((start, length))

        requires_resolution = raw.get("requires_resolution") is True
        edge_status = str(raw.get("resolution_status") or (
            "IDENTIFIED_BY_COMPILER" if confidence == "CONFIRMED" and not requires_resolution
            else "PENDING_RESOLUTION" if requires_resolution and confidence == "CONFIRMED"
            else "REVIEW_REQUIRED" if confidence == "INFERRED"
            else "UNRESOLVED"
        ))
        target_is_library = (
            (target_row is not None and str(target_row.get("contract_kind") or "").lower() == "library")
            or (target in nodes and nodes[target].category == "solidity-library")
        )
        auto_deploy = (
            kind == "solidity-library-link"
            and confidence == "CONFIRMED"
            and target_is_library
            and raw.get("auto_deploy") is True
            and bool(refs)
        )
        typed_edges.append(DependencyEdge(
            source=source,
            target=target,
            kind=kind,
            confidence=confidence,
            resolution_status=edge_status,
            requires_resolution=requires_resolution,
            auto_deploy=auto_deploy,
            creation_phase=str(raw.get("creation_phase") or "") or None,
            function=str(raw.get("function") or "") or None,
            link_references=tuple(refs),
            origin={
                "source": raw.get("source"),
                "line": raw.get("line"),
                "build_info": edge_evidence.get("build_info"),
                "source_path": edge_evidence.get("source_path"),
                "evidence": dict(edge_evidence),
            },
        ))

    # Explicit project declarations classify dependencies, but never prove
    # runtime code identity or protocol readiness.
    manifest_dependencies = manifest.get("dependencies")
    if manifest_status == "VALID" and isinstance(manifest_dependencies, list):
        manifest_network = manifest.get("network_identity")
        for entry in manifest_dependencies:
            if not isinstance(entry, Mapping):
                warnings.append("External dependency manifest contains a malformed normalized entry.")
                continue
            identifier = str(entry.get("id") or "")
            consumer = str(entry.get("consumer") or "")
            parameter = str(entry.get("parameter") or "")
            kind = str(entry.get("kind") or "other-contract")
            declared_address = entry.get("address") if _is_address(entry.get("address")) else None
            binding_target = f"{consumer}#constructor.{parameter}"
            has_compiler_binding = (
                consumer in contract_by_id
                and any(
                    str(raw_edge.get("from") or "") == consumer
                    and str(raw_edge.get("to") or "") == binding_target
                    and str(raw_edge.get("kind") or "") == "constructor-input"
                    for raw_edge in evidence_edges
                    if isinstance(raw_edge, Mapping)
                )
            )
            address = declared_address
            if consumer not in contract_by_id:
                status = "CONSUMER_NOT_FOUND"
                warnings.append(
                    f"External dependency {identifier} references a consumer absent from compiler evidence: {consumer}."
                )
                address = None
            elif not has_compiler_binding:
                status = "CONSTRUCTOR_PARAMETER_NOT_FOUND"
                warnings.append(
                    f"External dependency {identifier} does not match a compiler-reported constructor input: {binding_target}."
                )
                address = None
            elif declared_address is not None and network is None:
                status = "NETWORK_CONTEXT_REQUIRED"
                warnings.append(
                    f"External dependency {identifier} has a declared address but no verified managed network context; address was detached."
                )
                address = None
            elif declared_address is not None and not _same_network(
                network, manifest_network if isinstance(manifest_network, Mapping) else {}
            ):
                status = "NETWORK_IDENTITY_MISMATCH"
                warnings.append(
                    f"External dependency {identifier} was declared for a different or incomplete network identity; address was detached."
                )
                address = None
            elif declared_address is not None:
                status = "DECLARED_UNVERIFIED"
            else:
                status = "ADDRESS_REQUIRED"

            external_id = f"external:{identifier}"
            provenance = {
                "origin": "project-dependency-manifest",
                "manifest_path": manifest_summary["path"],
                "manifest_sha256": manifest_summary["sha256"],
                "manifest_schema": manifest_summary["schema"],
                "entry_id": identifier,
                "dependency_kind": kind,
                "consumer": consumer,
                "constructor_parameter": parameter,
                "description": str(entry.get("description") or ""),
                "address_declared": declared_address is not None,
                "network_identity_matched": status == "DECLARED_UNVERIFIED",
            }
            consumer_row = contract_by_id.get(consumer)
            nodes[external_id] = DependencyNode(
                id=external_id,
                category=f"external-infrastructure:{kind}",
                source_identity=consumer or None,
                source_path=(
                    str(consumer_row.get("source") or "") or None
                    if isinstance(consumer_row, Mapping) else None
                ),
                resolution_status=status,
                deployment_status="DECLARED_UNVERIFIED" if address is not None else "NOT_TESTED",
                address=str(address) if address is not None else None,
                network_identity=network,
                evidence=(provenance,),
            )
            typed_edges.append(DependencyEdge(
                source=consumer or "<unresolved-consumer>",
                target=external_id,
                kind="external-infrastructure",
                confidence="DECLARED",
                resolution_status=status,
                requires_resolution=True,
                auto_deploy=False,
                creation_phase=None,
                function=parameter or None,
                link_references=(),
                origin=provenance,
            ))

    raw_cycles = report.get("library_cycles")
    cycles = tuple(
        tuple(str(node) for node in cycle if node)
        for cycle in raw_cycles if isinstance(cycle, list) and cycle
    ) if isinstance(raw_cycles, list) else ()
    raw_order = report.get("library_deployment_order")
    order = tuple(str(item) for item in raw_order if isinstance(item, str)) if isinstance(raw_order, list) else ()
    if cycles:
        warnings.append("Compiler-confirmed Solidity library cycle blocks a linear deployment order.")
    unresolved_library = any(
        edge.kind == "solidity-library-link"
        and (not edge.auto_deploy or edge.confidence != "CONFIRMED")
        for edge in typed_edges
    )
    if not report.get("available") or cycles or unresolved_library or manifest_status == "BLOCKED":
        planning_status = "BLOCKED"
    elif any(edge.requires_resolution for edge in typed_edges):
        planning_status = "REVIEW_REQUIRED"
    else:
        planning_status = "OBSERVED"

    return DependencyGraph(
        nodes=tuple(nodes[key] for key in sorted(nodes)),
        edges=tuple(typed_edges),
        cycles=cycles,
        library_deployment_order=order if not cycles else (),
        planning_status=planning_status,
        execution_status="NOT_EXECUTED",
        network_identity=network,
        warnings=tuple(dict.fromkeys(warnings)),
        external_manifest=manifest_summary,
    )
