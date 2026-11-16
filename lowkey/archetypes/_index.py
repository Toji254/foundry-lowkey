#!/usr/bin/env python3
"""Deterministic protocol archetype and assumption discovery for Lowkey P3.

This module emits source-backed candidates only. It does not infer exploitability,
promote findings, contact RPC endpoints, invoke AI providers, or execute tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
CONFIDENCE_FLOOR = 0.35
MIN_DISTINCT_SIGNAL_KINDS = 2
AMBIGUITY_MARGIN = 0.08
MAX_SOURCE_FILES = 3000
MAX_SOURCE_BYTES = 1_000_000
SOURCE_SUFFIXES = {".sol", ".vy"}
SKIP_PARTS = {".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache",
              "node_modules", "out", "cache", "artifacts", "build", "dist",
              "vendor", "coverage", "lib", ".lowkey"}
ASSUMPTION_CLASSES = {
    "oracle_trust", "admin_authority", "token_standardness", "single_block_price",
    "reentrancy_safety", "upgrade_authority", "unbounded_input",
    "external_call_safety", "precision", "access_control", "randomness",
    "time_dependence",
}
PACK_KEYS = {"name", "detect_signals", "invariants", "required_capabilities",
             "forbidden_capabilities", "attack_families", "assumption_classes"}
SIGNAL_KEYS = {"kind", "value", "weight"}


class ArchetypeError(ValueError):
    """A bounded, actionable error from protocol-intelligence discovery."""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_root(value: str | Path) -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise ArchetypeError(f"Project root is not a directory: {root}")
    return root


def _pack_dir() -> Path:
    return Path(__file__).resolve().parent


def load_packs(directory: str | Path | None = None) -> list[dict[str, Any]]:
    pack_dir = Path(directory).resolve() if directory else _pack_dir()
    if not pack_dir.is_dir():
        raise ArchetypeError(f"Archetype pack directory is missing: {pack_dir}")
    packs: list[dict[str, Any]] = []
    for path in sorted(pack_dir.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArchetypeError(f"Invalid archetype pack {path.name}: {exc}") from exc
        if not isinstance(value, dict) or set(value) != PACK_KEYS:
            raise ArchetypeError(f"{path.name} must contain exactly: {', '.join(sorted(PACK_KEYS))}")
        if not isinstance(value["name"], str) or not re.fullmatch(r"[a-z0-9_]{2,48}", value["name"]):
            raise ArchetypeError(f"{path.name} has an invalid pack name.")
        if path.stem != value["name"]:
            raise ArchetypeError(f"{path.name} does not match its declared pack name.")
        if not isinstance(value["detect_signals"], list) or not value["detect_signals"]:
            raise ArchetypeError(f"{path.name} must declare detection signals.")
        for signal in value["detect_signals"]:
            if (not isinstance(signal, dict) or set(signal) != SIGNAL_KEYS
                    or not isinstance(signal["kind"], str)
                    or not isinstance(signal["value"], str)
                    or type(signal["weight"]) is not int or not 1 <= signal["weight"] <= 5):
                raise ArchetypeError(f"{path.name} contains a malformed detect_signals entry.")
            try:
                re.compile(signal["value"], re.IGNORECASE)
            except re.error as exc:
                raise ArchetypeError(f"{path.name} has an invalid signal expression: {exc}") from exc
        for key in ("invariants", "required_capabilities", "forbidden_capabilities",
                    "attack_families", "assumption_classes"):
            if not isinstance(value[key], list) or any(not isinstance(item, str) for item in value[key]):
                raise ArchetypeError(f"{path.name}.{key} must be a string list.")
        unknown_classes = set(value["assumption_classes"]) - ASSUMPTION_CLASSES
        if unknown_classes:
            raise ArchetypeError(f"{path.name} contains unsupported assumption classes: {sorted(unknown_classes)}")
        packs.append(value)
    if not packs:
        raise ArchetypeError("No archetype packs were found.")
    names = [item["name"] for item in packs]
    if len(names) != len(set(names)):
        raise ArchetypeError("Archetype pack names must be unique.")
    return packs


def _source_files(root: Path, max_files: int = MAX_SOURCE_FILES) -> list[Path]:
    found: list[Path] = []
    for dirname in ("src", "contracts", "sources"):
        directory = root / dirname
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in directory.rglob("*"):
            relative = path.relative_to(root)
            if any(part in SKIP_PARTS for part in relative.parts):
                continue
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            found.append(path)
            if len(found) > max_files:
                raise ArchetypeError(f"Source scan exceeded its {max_files}-file safety limit.")
    return sorted(set(found))


def _read_sources(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    sources: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for path in _source_files(root):
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        relative = path.relative_to(root).as_posix()
        sources[relative] = source
        hashes[relative] = sha256_text(source)
    return sources, hashes


def _scan_pack(pack: dict[str, Any], sources: dict[str, str]) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    matched_signals: set[int] = set()
    matched_kinds: set[str] = set()
    total_weight = sum(signal["weight"] for signal in pack["detect_signals"])
    matched_weight = 0
    for signal_index, signal in enumerate(pack["detect_signals"]):
        pattern = re.compile(signal["value"], re.IGNORECASE)
        signal_hit = False
        for filename, source in sources.items():
            for line_number, line in enumerate(source.splitlines(), start=1):
                if pattern.search(line):
                    hits.append({
                        "file": filename,
                        "line": line_number,
                        "kind": signal["kind"],
                        "weight": signal["weight"],
                        "excerpt": line.strip()[:240],
                    })
                    signal_hit = True
                    if len(hits) >= 200:
                        break
            if len(hits) >= 200:
                break
        if signal_hit:
            matched_signals.add(signal_index)
            matched_kinds.add(signal["kind"])
            matched_weight += signal["weight"]
    confidence = (matched_weight / total_weight) if total_weight else 0.0
    return {
        "name": pack["name"],
        "confidence": round(min(1.0, confidence), 4),
        "matched_signal_kinds": sorted(matched_kinds),
        "matched_signal_count": len(matched_signals),
        "matched_weight": matched_weight,
        "total_weight": total_weight,
        "evidence": hits,
        "pack": pack,
    }


def _contract_declarations(sources: dict[str, str]) -> dict[str, str]:
    declarations: dict[str, str] = {}
    pattern = re.compile(r"\b(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for filename, source in sources.items():
        for match in pattern.finditer(source):
            declarations.setdefault(match.group(1), filename)
    return declarations


def build_protocol_graph(root: Path, sources: dict[str, str], source_hashes: dict[str, str]) -> dict[str, Any]:
    """Build conservative source-file relationships; edges are leads, not call proof."""
    declarations = _contract_declarations(sources)
    nodes = []
    edges: list[dict[str, Any]] = []
    import_pattern = re.compile(r"\bimport\s+(?:[^\"']*?\s+from\s+)?[\"']([^\"']+)[\"']\s*;")
    typed_decl = re.compile(
        r"\b([A-Z][A-Za-z0-9_]*)\s+(?:(?:public|private|internal|constant)\s+)?([a-z][A-Za-z0-9_]*)\s*;"
    )
    for filename, source in sorted(sources.items()):
        symbols = sorted(set(re.findall(
            r"\b(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)", source
        )))
        nodes.append({
            "id": filename,
            "kind": "source_file",
            "sha256": source_hashes[filename],
            "symbols": symbols,
        })
        for line_number, line in enumerate(source.splitlines(), start=1):
            imported = import_pattern.search(line)
            if imported:
                raw = imported.group(1)
                normalized = (root / Path(filename).parent / raw).resolve()
                try:
                    target = normalized.relative_to(root).as_posix() if normalized.is_relative_to(root) else None
                except (OSError, ValueError):
                    target = None
                if target not in sources:
                    root_candidate = (root / raw).resolve()
                    target = root_candidate.relative_to(root).as_posix() if root_candidate.is_relative_to(root) else None
                    if target not in sources:
                        target = None
                edges.append({
                    "source": filename,
                    "target": target,
                    "kind": "import" if target else "unresolved_import",
                    "citation": {"file": filename, "line": line_number},
                    "reference": raw,
                })
        declarations_here = list(typed_decl.finditer(source))
        for declaration in declarations_here:
            type_name, variable = declaration.group(1), declaration.group(2)
            target_file = declarations.get(type_name)
            if not target_file or target_file == filename:
                continue
            tail = source[declaration.end():]
            call = re.search(r"\b" + re.escape(variable) + r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", tail)
            if not call:
                continue
            absolute_offset = declaration.end() + call.start()
            line_number = source.count("\n", 0, absolute_offset) + 1
            edges.append({
                "source": filename,
                "target": target_file,
                "kind": "typed_call_candidate",
                "citation": {"file": filename, "line": line_number},
                "reference": type_name + " " + variable,
            })
    edges.sort(key=lambda item: (item["source"], item["kind"], item["target"] or "", item["citation"]["line"]))
    return {"nodes": nodes, "edges": edges}


def _capability_states() -> dict[str, str]:
    try:
        from godmode import CAPABILITIES
    except ImportError:
        try:
            from lowkey.godmode import CAPABILITIES
        except ImportError:
            return {}
    return {str(row[1]): str(row[3]) for row in CAPABILITIES}


def _assumptions(pack: dict[str, Any], scan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    allowed = set(pack["assumption_classes"])
    values: list[dict[str, Any]] = []
    fingerprints: dict[str, str] = {}
    seen: set[tuple[str, str, int]] = set()
    for evidence in scan["evidence"]:
        assumption_class = evidence["kind"]
        if assumption_class not in allowed:
            continue
        key = (assumption_class, evidence["file"], evidence["line"])
        if key in seen:
            continue
        seen.add(key)
        assumption_id = assumption_class + ":" + sha256_text(
            evidence["file"] + ":" + str(evidence["line"]) + ":" + assumption_class
        )[:16]
        values.append({
            "id": assumption_id,
            "class": assumption_class,
            "citation": {"file": evidence["file"], "line": evidence["line"]},
            "confidence": round(min(1.0, evidence["weight"] / 5.0), 4),
            "verification_status": "unverified",
            "attacked_by": None,
        })
        fingerprints[assumption_id] = sha256_text(evidence["excerpt"])
    return values, fingerprints


def verify_assumption_citations(
    root: str | Path,
    assumptions: list[dict[str, Any]],
    citation_fingerprints: dict[str, str],
    source_hashes: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Re-read source citations and reject changed files or line contents."""
    base = project_root(root)
    results: list[dict[str, Any]] = []
    for item in assumptions:
        citation = item.get("citation") if isinstance(item, dict) else None
        filename = citation.get("file") if isinstance(citation, dict) else None
        line_number = citation.get("line") if isinstance(citation, dict) else None
        resolved = False
        detail = "citation_missing"
        if isinstance(filename, str) and type(line_number) is int and line_number > 0:
            relative = Path(filename)
            target = (base / relative).resolve()
            if not relative.is_absolute() and ".." not in relative.parts and target.is_relative_to(base) and target.is_file():
                try:
                    source = target.read_text(encoding="utf-8")
                    lines = source.splitlines()
                    if source_hashes and filename in source_hashes and sha256_text(source) != source_hashes[filename]:
                        detail = "source_digest_mismatch"
                    elif line_number > len(lines) or not lines[line_number - 1].strip():
                        detail = "citation_line_unresolved"
                    else:
                        expected = citation_fingerprints.get(str(item.get("id")), "")
                        if expected and sha256_text(lines[line_number - 1].strip()[:240]) == expected:
                            resolved, detail = True, "resolved"
                        else:
                            detail = "citation_content_mismatch"
                except (OSError, UnicodeError):
                    detail = "citation_read_error"
            else:
                detail = "citation_out_of_scope"
        results.append({"assumption_id": item.get("id"), "resolved": resolved, "reason": detail})
    return results


def classify_project(root: str | Path = ".") -> dict[str, Any]:
    base = project_root(root)
    packs = load_packs()
    sources, source_hashes = _read_sources(base)
    if not sources:
        raise ArchetypeError("No bounded Solidity/Vyper source files were found in src/, contracts/, or sources/.")
    scans = [_scan_pack(pack, sources) for pack in packs]
    ranked = sorted(scans, key=lambda item: (-item["confidence"], item["name"]))
    best = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None
    enough_signals = len(best["matched_signal_kinds"]) >= MIN_DISTINCT_SIGNAL_KINDS
    decisive = second is None or (best["confidence"] - second["confidence"]) >= AMBIGUITY_MARGIN
    classified = best["confidence"] >= CONFIDENCE_FLOOR and enough_signals and decisive
    selected = best["pack"] if classified else None
    assumptions: list[dict[str, Any]] = []
    fingerprints: dict[str, str] = {}
    if selected:
        assumptions, fingerprints = _assumptions(selected, best)
    citation_results = verify_assumption_citations(base, assumptions, fingerprints, source_hashes)
    capability_states = _capability_states()
    required = list(selected["required_capabilities"]) if selected else []
    forbidden = list(selected["forbidden_capabilities"]) if selected else []
    capability_report = {
        name: {"status": capability_states.get(name, "unknown"),
               "available": capability_states.get(name) == "implemented"}
        for name in sorted(set(required + forbidden))
    }
    skip_list = [name for name in required if capability_states.get(name) != "implemented"]
    if not classified:
        skip_list = sorted({
            "archetype-specific invariant handlers",
            "protocol-specific attack adapters",
            "asset-specific economic valuation",
        })
    graph = build_protocol_graph(base, sources, source_hashes)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "OBSERVED" if classified else "UNCLASSIFIED",
        "archetype": selected["name"] if selected else None,
        "confidence": best["confidence"] if classified else 0.0,
        "confidence_floor": CONFIDENCE_FLOOR,
        "reason": None if classified else (
            "no_candidate_above_confidence_floor" if best["confidence"] < CONFIDENCE_FLOOR
            else "insufficient_distinct_signal_kinds" if not enough_signals
            else "ambiguous_top_candidates"
        ),
        "ranked_candidates": [{
            "name": item["name"], "confidence": item["confidence"],
            "matched_signal_kinds": item["matched_signal_kinds"],
            "matched_signal_count": item["matched_signal_count"],
        } for item in ranked],
        "evidence": best["evidence"] if classified else [],
        "assumptions": assumptions,
        "citation_resolution": citation_results,
        "citations_all_resolved": all(item["resolved"] for item in citation_results),
        "source_hashes": source_hashes,
        "protocol_graph": graph,
        "capabilities": capability_report,
        "generic_mode": {
            "enabled": True,
            "skip_list": sorted(set(skip_list)),
            "note": "Generic mode is a bounded fallback, not a safety or coverage claim.",
        },
        "limitations": [
            "Classification is source-level and deterministic; it does not authenticate a deployment.",
            "Relationship edges are import or typed-call candidates, not proof of runtime reachability.",
            "Assumptions are unverified until an explicit check changes verification_status.",
            "No vulnerability verdict, exploit execution, profit calculation, or status promotion occurs.",
        ],
    }


def verify_report(root: str | Path, report_path: str | Path) -> dict[str, Any]:
    base = project_root(root)
    path = Path(report_path)
    if path.is_absolute() or ".." in path.parts:
        raise ArchetypeError("Report path must be project-relative and must not traverse outside the project.")
    target = (base / path).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        raise ArchetypeError("Classification report is missing or outside the project.")
    try:
        report = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchetypeError(f"Cannot read classification report: {exc}") from exc
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        raise ArchetypeError("Unsupported classification report schema.")
    assumptions = report.get("assumptions")
    fingerprints = report.get("citation_fingerprints")
    source_hashes = report.get("source_hashes")
    if not isinstance(assumptions, list) or any(not isinstance(item, dict) for item in assumptions):
        raise ArchetypeError("Saved classification report has a malformed assumption ledger.")
    if not isinstance(fingerprints, dict) or not isinstance(source_hashes, dict):
        raise ArchetypeError("Saved classification report is missing citation/source fingerprint maps.")
    results = verify_assumption_citations(base, assumptions, fingerprints, source_hashes)
    all_resolved = bool(assumptions) and all(item["resolved"] for item in results)
    return {"status": "OBSERVED" if all_resolved else "UNRESOLVED",
            "citations_all_resolved": all_resolved,
            "citation_resolution": results}


def _write_report(root: Path, output: str, report: dict[str, Any]) -> str:
    relative = Path(output)
    if relative.is_absolute() or ".." in relative.parts:
        raise ArchetypeError("Output path must be project-relative and must not traverse outside the project.")
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise ArchetypeError("Output path resolves outside the project.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return relative.as_posix()


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lk archetype classify")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default=".audit/godmode/archetype-classification.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verify", metavar="REPORT", help="re-read and verify citations in an existing report")
    parser.add_argument("--report", default=".audit/godmode/archetype-classification.json")
    parser.add_argument("--assumptions", action="store_true", help="print and re-verify the assumption ledger")
    parser.add_argument("--capability", action="store_true", help="print capability negotiation from a saved report")
    ns = parser.parse_args(args)
    try:
        root = project_root(ns.root)
        if ns.verify or ns.assumptions or ns.capability:
            report_path = ns.verify or ns.report
            path = Path(report_path)
            if path.is_absolute() or ".." in path.parts:
                raise ArchetypeError("Report path must be project-relative and must not traverse outside the project.")
            saved_path = (root / path).resolve()
            if not saved_path.is_relative_to(root) or not saved_path.is_file():
                raise ArchetypeError("Classification report is missing or outside the project.")
            saved = json.loads(saved_path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict) or saved.get("schema_version") != SCHEMA_VERSION:
                raise ArchetypeError("Unsupported classification report schema.")
            if ns.capability:
                report = {"status": saved.get("status"), "archetype": saved.get("archetype"),
                          "capabilities": saved.get("capabilities", {}),
                          "generic_mode": saved.get("generic_mode", {})}
            else:
                report = verify_report(root, report_path)
                if ns.assumptions:
                    report["assumptions"] = saved.get("assumptions", [])
        else:
            report = classify_project(root)
            report["citation_fingerprints"] = {}
            # Preserve the exact line fingerprints used by the assumption records.
            # Reconstruct them from evidence without changing the canonical Assumption shape.
            by_key = {(item["kind"], item["file"], item["line"]): item for item in report["evidence"]}
            for assumption in report["assumptions"]:
                citation = assumption["citation"]
                hit = by_key.get((assumption["class"], citation["file"], citation["line"]))
                if hit:
                    report["citation_fingerprints"][assumption["id"]] = sha256_text(hit["excerpt"].strip()[:240])
            output_path = _write_report(root, ns.output, report)
            report["report_path"] = output_path
        if ns.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif ns.verify or ns.assumptions:
            print("Citation verification: " + ("OBSERVED" if report["citations_all_resolved"] else "UNRESOLVED"))
            for item in report["citation_resolution"]:
                print(f"  {item['assumption_id']}: {item['reason']}")
            for item in report.get("assumptions", []):
                print(f"  {item['class']}: {item['citation']['file']}:{item['citation']['line']} [{item['verification_status']}]")
        elif ns.capability:
            print("Archetype: " + str(report.get("archetype") or "UNCLASSIFIED"))
            print("Capability negotiation:")
            for name, details in sorted(report.get("capabilities", {}).items()):
                print(f"  {name}: {details.get('status')} (available={details.get('available')})")
            print("Generic-mode skip list:")
            for item in report.get("generic_mode", {}).get("skip_list", []):
                print("  - " + item)
        else:
            print("Protocol archetype: " + (report["archetype"] or "UNCLASSIFIED"))
            print(f"Confidence: {report['confidence']:.3f} (floor {report['confidence_floor']:.2f})")
            print("Source files: " + str(len(report["source_hashes"])))
            print("Assumption candidates: " + str(len(report["assumptions"])))
            print("Protocol graph edges: " + str(len(report["protocol_graph"]["edges"])))
            print("Generic-mode skip list:")
            for item in report["generic_mode"]["skip_list"]:
                print("  - " + item)
            print("Report: " + report.get("report_path", ns.output))
        return 0
    except (ArchetypeError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"BLOCKED: protocol-intelligence operation could not be completed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
