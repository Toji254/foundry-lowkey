"""Signal-scoped, evidence-backed test generation for eligible Solidity findings."""
from __future__ import annotations

import hashlib
import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any


def _slug(signal_id: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_-]+", "-", signal_id).strip("-_")[:48] or "signal"
    return readable + "-" + hashlib.sha256(signal_id.encode("utf-8")).hexdigest()[:10]


def _is_access_control_finding(signal: dict[str, Any]) -> bool:
    value = " ".join(str(signal.get(key) or "") for key in (
        "category", "check", "pattern_id", "title", "description", "meaning", "why"
    )).lower()
    return bool(re.search(
        r"access[\s_-]*control|onlyowner|authori[sz]ation|unauthori[sz]ed|"
        r"owner(?:ship)?|privileged|permission(?:less)?|tx[\s._-]*origin|"
        r"unprotected|role[\s_-]*based",
        value,
    ))


def investigate_signal(
    signal_id: str,
    *,
    project_root: str | Path,
    audit_context: Any,
    constructor_args: list[str] | None = None,
) -> dict[str, Any]:
    """Generate and execute only the recognized onlyOwner/non-owner-revert property."""
    root = Path(project_root).expanduser().resolve()
    signal_id = str(signal_id or "").strip()
    if not signal_id:
        raise ValueError("provide an existing Lowkey signal ID")
    signal = next((
        item for item in audit_context.signals(root)
        if isinstance(item, dict) and str(item.get("id") or "") == signal_id
    ), None)
    if signal is None:
        raise ValueError(f"signal '{signal_id}' was not found in the current project")

    slug = _slug(signal_id)
    output_root = (root / ".audit" / "investigations" / slug).resolve()
    if not output_root.is_relative_to(root):
        raise ValueError("investigation output path escaped the active project")
    output_root.mkdir(parents=True, exist_ok=True)
    report_path = output_root / "investigation.json"
    report: dict[str, Any] = {
        "schema_version": 1,
        "signal_id": signal_id,
        "project_root": str(root),
        "status": "unsupported",
        "reason": None,
        "source_file": signal.get("file"),
        "source_line": signal.get("line"),
        "function": signal.get("function"),
        "source_sha256": None,
        "property": None,
        "target_test_name": None,
        "targeted_test": None,
        "targeted_test_sha256": None,
        "generated_artifacts": [],
        "generation_exit_code": None,
        "validation": {"status": "not-run", "detail": "No generation or execution attempted."},
        "interpretation": "No vulnerability verdict has been established.",
        "generation_stdout_tail": "",
        "generation_stderr_tail": "",
        "evidence_attached": False,
        "report_path": str(report_path.relative_to(root)),
    }

    def finish(
        status: str, reason: str, *, source_digest: str | None = None,
        test_path: str | None = None, test_digest: str | None = None,
        test_name: str | None = None, validation: dict[str, Any] | None = None,
        exit_code: int | None = None, stdout: str = "", stderr: str = "",
        generated: list[str] | None = None, property_text: str | None = None,
        target_test_status: str = "not-run", native_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        report.update({
            "status": status, "reason": reason, "source_sha256": source_digest,
            "targeted_test": test_path, "targeted_test_sha256": test_digest,
            "target_test_name": test_name, "validation": validation or {"status": "not-run", "detail": reason},
            "generation_exit_code": exit_code, "generation_stdout_tail": str(stdout or "")[-6000:],
            "generation_stderr_tail": str(stderr or "")[-6000:], "generated_artifacts": list(generated or []),
            "property": property_text, "target_test_status": target_test_status,
            "native_evidence": native_evidence or {},
        })
        stable = "|".join((signal_id, str(source_digest or "no-source"),
                           str(report.get("function") or "no-function"), "onlyOwner-non-owner-revert"))
        evidence_id = "TARGETED-INVESTIGATION-" + hashlib.sha1(stable.encode("utf-8")).hexdigest()[:12].upper()
        report["evidence_id"] = evidence_id
        evidence = {
            "id": evidence_id, "kind": "targeted-test-investigation", "status": status,
            "signal_id": signal_id, "function": report.get("function"),
            "source_file": report.get("source_file"), "source_line": report.get("source_line"),
            "source_sha256": source_digest, "property": property_text,
            "targeted_test": test_path, "targeted_test_sha256": test_digest,
            "target_test_name": test_name, "target_test_status": target_test_status,
            "generated_artifacts": list(generated or []), "generation_exit_code": exit_code,
            "validation_status": str((validation or {}).get("status") or "not-run"),
            "validation_detail": str((validation or {}).get("detail") or reason),
            "report_path": str(report_path.relative_to(root)),
            "security_finding_confirmed": False,
            "interpretation": report.get("interpretation"),
            "reason": reason,
        }
        attached = audit_context.attach_signal_evidence(signal_id, evidence, root)
        report["evidence_attached"] = attached is not None
        if attached is None:
            report["status"] = "evidence-attachment-failed"
            report["reason"] = reason + " Evidence could not be attached to the originating signal."
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return report

    if not _is_access_control_finding(signal):
        report["interpretation"] = "No complete targeted generator is available for this finding type; no test was written."
        return finish("unsupported",
                      "The signal is not explicitly classified as access-control/authorization; Lowkey will not infer an intended policy.")
    raw_file = str(signal.get("file") or "").strip()
    if not raw_file:
        return finish("unsupported", "The signal does not identify a source file.")
    source_path = Path(raw_file).expanduser()
    if not source_path.is_absolute():
        source_path = root / source_path
    try:
        source_path = source_path.resolve()
    except (OSError, RuntimeError):
        return finish("unsupported", "The signal source path could not be resolved.")
    if not source_path.is_relative_to(root) or not source_path.is_file():
        return finish("unsupported", "The signal source is missing or outside the active project.")

    try:
        import test_generation
        import test_generation_analysis
    except ImportError:
        try:
            from lowkey import test_generation, test_generation_analysis
        except ImportError as exc:
            return finish("error", f"Targeted generation modules are unavailable: {exc}")
    if not (root / "foundry.toml").is_file():
        return finish("unsupported", "This path requires a Foundry project with foundry.toml.")
    try:
        src_root = test_generation._source_root(root).resolve()
    except (AttributeError, OSError, ValueError, RuntimeError) as exc:
        return finish("unsupported", f"Could not resolve Solidity source root: {exc}")
    if not source_path.is_relative_to(src_root):
        return finish("unsupported", "The signal source is not inside the configured Solidity source root.")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return finish("unsupported", f"Could not read the signal source: {exc}")
    source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    report["source_file"] = source_path.relative_to(root).as_posix()
    report["source_sha256"] = source_digest
    clean = test_generation.mask_solidity(source) if hasattr(test_generation, "mask_solidity") else source
    contract_names = list(dict.fromkeys(re.findall(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", clean)))
    if not contract_names:
        return finish("unsupported", "No contract declaration exists in the signal's source file.", source_digest=source_digest)
    function_value = str(signal.get("function") or "").strip()
    if not function_value:
        return finish("unsupported", "The signal does not identify a function; Lowkey will not guess one.", source_digest=source_digest)
    function_name = function_value.split("(", 1)[0].strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", function_name):
        return finish("unsupported", "The signal function identifier is not a Solidity function name.", source_digest=source_digest)
    if constructor_args is not None and (
        not isinstance(constructor_args, list) or not all(isinstance(x, str) and x.strip() for x in constructor_args)
    ):
        return finish("needs-setup", "--constructor-args must be a JSON array of non-empty Solidity expressions.", source_digest=source_digest)

    candidates = []
    for contract in contract_names:
        try:
            found = test_generation._contract_source(root, contract)
            if not found or Path(found[0]).resolve() != source_path:
                continue
            analysis = test_generation_analysis.analyse_contract(
                root, contract, source_path, source, test_generation._foundry_test_dir(root)
            )
            helper_tests = test_generation_analysis.unit_access_control_tests(analysis, source)
        except (AttributeError, OSError, ValueError, RuntimeError, TypeError):
            continue
        matches = [
            item for item in analysis.get("functions", [])
            if str(item.get("name") or "") == function_name
            and str(item.get("visibility") or "") in {"public", "external"}
        ]
        if len(matches) != 1:
            continue
        target = matches[0]
        modifiers = target.get("modifiers") or []
        if not isinstance(modifiers, (list, tuple, set)) or "onlyOwner" not in modifiers:
            continue
        target_tests = []
        for fragment in helper_tests:
            fn_match = re.search(r"\bfunction\s+(test_nonOwnerCannotCall_[A-Za-z0-9_]+)\s*\(", fragment)
            call_match = re.search(r"\btarget\s*\.\s*([A-Za-z_]\w*)\s*\(", fragment)
            if fn_match and call_match and call_match.group(1) == function_name:
                target_tests.append(fn_match.group(1))
        if target_tests:
            candidates.append({
                "contract": contract, "target": target, "test_name": target_tests[0],
                "constructor_raw": test_generation._constructor_args(source, contract),
            })

    if len(candidates) != 1:
        return finish("unsupported",
                      "No unique, safely testable onlyOwner method was established. The narrow generator requires an explicit onlyOwner modifier and simple state-changing body; no test was written.",
                      source_digest=source_digest)
    candidate = candidates[0]
    contract, target, test_name = candidate["contract"], candidate["target"], candidate["test_name"]
    ctor_raw = candidate["constructor_raw"]
    if ctor_raw is None:
        return finish("needs-setup", "The constructor could not be parsed safely.", source_digest=source_digest)
    ctor_count = len(test_generation._split_parameters(ctor_raw))
    if ctor_count and constructor_args is None:
        return finish("needs-setup",
                      f"{contract} needs {ctor_count} constructor argument(s). Supply --constructor-args as a JSON array; Lowkey will not guess setup.",
                      source_digest=source_digest,
                      property_text=f"Non-owner calls to {target.get('signature') or function_name} must revert.")
    if len(constructor_args or []) != ctor_count and (ctor_count != 0 or constructor_args is not None):
        return finish("needs-setup",
                      f"{contract} expects {ctor_count} constructor argument(s); {len(constructor_args or [])} supplied.",
                      source_digest=source_digest)

    property_text = (
        f"Non-owner calls to {target.get('signature') or function_name} must revert; "
        "the source declares onlyOwner and its state-changing body matches the complete-test generator."
    )
    relative_output = Path(".audit") / "investigations" / slug / "generated"
    gen_args = [contract, "--types", "unit", "--output-dir", relative_output.as_posix(), "--validate", "--force"]
    if constructor_args is not None:
        gen_args.extend(["--constructor-args", json.dumps(constructor_args)])
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            generation_exit = test_generation.run_test_gen(
                {"target_contract": contract, "target": None}, gen_args, project_root=root
            )
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        return finish("generation-error", f"Targeted generator raised: {exc}", source_digest=source_digest,
                      stdout=stdout.getvalue(), stderr=stderr.getvalue(), property_text=property_text, test_name=test_name)

    generated_root = (root / relative_output / test_generation._solidity_name(contract)).resolve()
    try:
        gen_report = json.loads((generated_root / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return finish("generation-error", f"No readable fresh generator report: {exc}",
                      source_digest=source_digest, exit_code=generation_exit,
                      stdout=stdout.getvalue(), stderr=stderr.getvalue(), property_text=property_text, test_name=test_name)

    generated: list[str] = []
    test_file: Path | None = None
    for raw in gen_report.get("generated", []):
        item = Path(str(raw))
        if not item.is_absolute():
            item = root / item
        try:
            item = item.resolve()
        except (OSError, RuntimeError):
            continue
        if not item.is_relative_to(generated_root) or not item.is_file():
            continue
        generated.append(item.relative_to(root).as_posix())
        if item.name.endswith(".t.sol"):
            try:
                text = item.read_text(encoding="utf-8")
            except OSError:
                continue
            if re.search(r"\bfunction\s+" + re.escape(test_name) + r"\s*\(", text):
                test_file = item
    if test_file is None:
        return finish("generation-incomplete",
                      "Generated artifacts did not contain the exact target test; unrelated output is not treated as coverage.",
                      source_digest=source_digest, exit_code=generation_exit,
                      stdout=stdout.getvalue(), stderr=stderr.getvalue(), generated=generated,
                      property_text=property_text, test_name=test_name,
                      validation=gen_report.get("validation") or {"status": "not-requested"})

    test_digest = hashlib.sha256(test_file.read_bytes()).hexdigest()
    validation = gen_report.get("validation") or {"status": "not-requested"}
    if not isinstance(validation, dict):
        validation = {"status": "inconclusive", "detail": "Malformed generator validation report."}
    validation_status = str(validation.get("status") or "unknown").lower()
    executions = validation.get("test_executions")
    if not isinstance(executions, list):
        executions = []
    execution = next((x for x in executions if isinstance(x, dict)
                      and test_file.name in Path(str(x.get("path") or "")).name), None)
    native_output = "\n".join(str(execution.get(k) or "") for k in ("stdout_tail", "stderr_tail")) if execution else ""
    failed = bool(test_name in native_output and re.search(r"(?i)(?:\[FAIL[^\]]*\]|failed|failing tests?|error:)", native_output))
    passed = bool(validation_status == "passed" and execution and execution.get("exit_code") == 0)
    if passed:
        status = "passed"
        interpretation = "The generated non-owner call reverted as expected in the local fixture. This validates the encoded behavior only; it does not confirm or dismiss the original finding."
    elif failed:
        status = "test-failed-needs-review"
        interpretation = "The target test appears in Forge failure output; this may reproduce an authorization failure, but the exact failure and policy need human review."
    elif validation_status in {"baseline-failed", "unavailable", "not-applicable", "pending"}:
        status = "blocked"
        interpretation = "The test did not complete with usable execution evidence; no vulnerability conclusion is available."
    elif validation_status == "failed":
        status = "validation-failed-ambiguous"
        interpretation = "The generated test campaign failed, but the target test was not identified as the cause."
    else:
        status = "not-validated"
        interpretation = "The test was generated but did not complete with a passing or identified failing execution."
    report["interpretation"] = interpretation
    return finish(
        status, str(validation.get("detail") or interpretation), source_digest=source_digest,
        test_path=test_file.relative_to(root).as_posix(), test_digest=test_digest,
        test_name=test_name, validation=validation, exit_code=generation_exit,
        stdout=stdout.getvalue(), stderr=stderr.getvalue(), generated=generated,
        property_text=property_text,
        target_test_status="passed" if passed else "failed-needs-review" if failed else validation_status,
        native_evidence={
            "validation_status": validation_status, "validation_detail": str(validation.get("detail") or ""),
            "baseline_exit_code": validation.get("baseline_exit_code"), "build_exit_code": validation.get("exit_code"),
            "execution": execution, "skipped": gen_report.get("skipped", []),
            "generation_assessment": gen_report.get("generation_assessment", {}),
        },
    )
