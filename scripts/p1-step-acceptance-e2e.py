#!/usr/bin/env python3
"""Installed-lk P1 Step[] acceptance: render all families, compile, and verify refusals."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

TARGET = "0x1111111111111111111111111111111111111111"
SELECTOR = "0x12345678"


def run(argv: list[str], cwd: Path, *, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"Command exited {result.returncode}: {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-10000:]}\n"
            f"--- stderr ---\n{result.stderr[-10000:]}"
        )
    return result


def find_tool(name: str, fallback: Path) -> str:
    found = shutil.which(name)
    if found:
        return found
    if fallback.is_file():
        return str(fallback)
    raise AssertionError(f"Required tool is unavailable: {name}")


def main() -> int:
    forge = find_tool("forge", Path.home() / ".foundry" / "bin" / "forge")
    lk = find_tool("lk", Path.home() / ".foundry" / "bin" / "lk")
    install_root = Path.home() / ".lowkey"
    template_path = install_root / "templates" / "step_harness.sol.tmpl"
    install_manifest_path = install_root / "install-manifest.json"
    if not template_path.is_file():
        raise AssertionError(f"Installed Step template is missing: {template_path}")
    if not install_manifest_path.is_file():
        raise AssertionError(f"Installed runtime manifest is missing: {install_manifest_path}")

    installed_godmode_path = install_root / "godmode.py"
    if not installed_godmode_path.is_file():
        raise AssertionError(f"Installed Godmode module is missing: {installed_godmode_path}")
    module_tree = ast.parse(installed_godmode_path.read_text(encoding="utf-8"))
    family_nodes = [
        node for node in module_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(name, ast.Name) and name.id == "STEP_FAMILIES" for name in node.targets)
    ]
    if len(family_nodes) != 1:
        raise AssertionError("Installed Godmode must declare STEP_FAMILIES exactly once.")
    try:
        families = sorted(ast.literal_eval(family_nodes[0].value))
    except (ValueError, TypeError) as error:
        raise AssertionError(f"Installed STEP_FAMILIES is not a literal set/list: {error}") from error
    if not families or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in families):
        raise AssertionError(f"Installed STEP_FAMILIES contains invalid entries: {families!r}")

    template_digest = hashlib.sha256(template_path.read_bytes()).hexdigest()
    installed_manifest = json.loads(install_manifest_path.read_text(encoding="utf-8"))
    expected_git_sha = os.environ.get("GITHUB_SHA")
    installed_git_sha = installed_manifest.get("git_sha")
    if expected_git_sha and installed_git_sha != expected_git_sha:
        raise AssertionError(
            f"Installed Lowkey SHA does not match this workflow: "
            f"installed={installed_git_sha!r}, expected={expected_git_sha!r}"
        )
    installed_files = installed_manifest.get("files") or {}
    installed_template_hash = next(
        (digest for path, digest in installed_files.items()
         if str(path).endswith("/templates/step_harness.sol.tmpl")),
        None,
    )
    if installed_template_hash != template_digest:
        raise AssertionError(
            "Installed template hash is absent or differs from install-manifest.json: "
            f"manifest={installed_template_hash!r}, actual={template_digest}"
        )

    help_result = run([lk, "steps", "--help"], Path.cwd())
    help_text = help_result.stdout + help_result.stderr
    for flag in ("--root", "--output", "--refusal-output"):
        if flag not in help_text:
            raise AssertionError(f"Installed 'lk steps --help' did not advertise {flag!r}: {help_text}")
    help_lines = [line.strip() for line in help_text.splitlines() if any(
        flag in line for flag in ("--root", "--output", "--refusal-output")
    )]

    forge_std_candidates = [
        Path(os.environ.get("LOWKEY_FORGE_STD", "")) if os.environ.get("LOWKEY_FORGE_STD") else None,
        Path("/tmp/lowkey-fixture/lib/forge-std"),
        Path.cwd() / "lib" / "forge-std",
    ]
    forge_std = next(
        (path for path in forge_std_candidates if path and (path / "src" / "Vm.sol").is_file()),
        None,
    )
    if forge_std is None:
        raise AssertionError("Installed forge-std/src/Vm.sol was not found; cannot validate Step cheatcodes.")

    vm_sol = forge_std / "src" / "Vm.sol"
    source_lines = vm_sol.read_text(encoding="utf-8").splitlines()
    required_cheats = ("expectCall", "snapshot", "revertTo", "warp", "roll")
    cheat_signatures: dict[str, list[str]] = {}
    for name in required_cheats:
        matches = [
            f"{line_no}: {line.strip()}"
            for line_no, line in enumerate(source_lines, start=1)
            if re.search(rf"\bfunction\s+{name}\s*\(", line)
        ]
        if not matches:
            raise AssertionError(f"Installed Vm.sol does not contain function {name}(...).")
        cheat_signatures[name] = matches[:3]

    evidence_root = Path.cwd() / ".audit" / "p1-step-acceptance"
    if evidence_root.exists():
        shutil.rmtree(evidence_root)
    (evidence_root / "generated").mkdir(parents=True, exist_ok=True)
    (evidence_root / "manifests").mkdir(parents=True, exist_ok=True)
    (evidence_root / "refusals").mkdir(parents=True, exist_ok=True)

    generated = []
    refusals = []
    forge_output = ""
    with tempfile.TemporaryDirectory(prefix="lowkey-p1-steps-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "lib").mkdir()
        (root / "lib" / "forge-std").symlink_to(forge_std, target_is_directory=True)
        (root / "foundry.toml").write_text(
            '[profile.default]\n'
            'src = "src"\n'
            'test = "test"\n'
            'out = "out"\n'
            'libs = ["lib"]\n'
            'solc_version = "0.8.20"\n',
            encoding="utf-8",
        )

        common_steps = [
            {"kind": "snapshot"},
            {
                "kind": "call",
                "target": TARGET,
                "selector": SELECTOR,
                "args": [
                    {"type": "address[]", "value": [TARGET]},
                    {"type": "uint256", "value": 1},
                    {"type": "bool", "value": True},
                ],
                "optional": True,
            },
            {"kind": "assert"},
            {"kind": "revert"},
            {"kind": "warp", "value": 1700000000},
            {"kind": "roll", "value": 100},
            {
                "kind": "expect",
                "target": TARGET,
                "selector": SELECTOR,
                "args": [{"type": "uint256[2]", "value": [1, 2]}],
                "expect": {"count": 1, "must_revert": True},
            },
            {
                "kind": "unwind",
                "target": TARGET,
                "selector": SELECTOR,
                "args": [{"type": "uint256[2]", "value": [1, 2]}],
                "optional": True,
            },
            {
                "kind": "read",
                "target": TARGET,
                "selector": SELECTOR,
                "args": [{"type": "string", "value": "lowkey"}],
                "optional": True,
            },
        ]

        for family in families:
            manifest = {
                "family": family,
                "target_address": TARGET,
                "steps": common_steps,
            }
            manifest_path = root / f"{family}.json"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            output_relative = f"test/LowkeySteps_{family}.t.sol"
            result = run([
                lk, "steps", f"{family}.json",
                "--root", str(root),
                "--output", output_relative,
                "--refusal-output", f"refusals/{family}.json",
            ], Path.cwd())
            payload = json.loads(result.stdout.strip().splitlines()[-1])
            if payload.get("status") != "PROPOSED" or payload.get("family") != family:
                raise AssertionError(f"Unexpected installed lk steps response for {family}: {payload}")
            generated_path = root / output_relative
            if not generated_path.is_file():
                raise AssertionError(f"lk steps did not create {output_relative}")
            source = generated_path.read_text(encoding="utf-8")
            if f"contract LowkeySteps_{family}" not in source or "__LOWKEY_STEP_CODE__" in source:
                raise AssertionError(f"Generated harness for {family} has unresolved template tokens.")
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if payload.get("harness_sha256") != digest:
                raise AssertionError(f"Generated harness digest mismatch for {family}.")
            shutil.copy2(generated_path, evidence_root / "generated" / generated_path.name)
            shutil.copy2(manifest_path, evidence_root / "manifests" / manifest_path.name)
            generated.append({
                "family": family,
                "status": payload["status"],
                "harness": output_relative,
                "harness_sha256": digest,
                "step_count": payload["steps_rendered"],
            })

        invalid_cases = [
            ("malformed-json", "broken.json", "{not-json", "unsupported_abi"),
            ("missing-manifest", "missing.json", None, "out_of_scope"),
        ]
        for label, manifest_name, manifest_body, expected_reason in invalid_cases:
            if manifest_body is not None:
                (root / manifest_name).write_text(manifest_body, encoding="utf-8")
            refusal_relative = f"refusals/{label}.json"
            result = subprocess.run(
                [lk, "steps", manifest_name, "--root", str(root),
                 "--refusal-output", refusal_relative],
                cwd=Path.cwd(), text=True, capture_output=True, check=False,
            )
            if result.returncode != 2:
                raise AssertionError(
                    f"Expected exit 2 for {label}; received {result.returncode}. "
                    f"stdout={result.stdout[-3000:]} stderr={result.stderr[-3000:]}"
                )
            refusal_path = root / refusal_relative
            refusal = json.loads(refusal_path.read_text(encoding="utf-8"))
            if refusal.get("reason") != expected_reason:
                raise AssertionError(f"{label} did not emit the expected machine-readable refusal: {refusal}")
            shutil.copy2(refusal_path, evidence_root / "refusals" / f"{label}.json")
            refusals.append({"kind": label, "reason": refusal["reason"], "exit_code": result.returncode})

        for kind in ("flash_borrow", "reenter"):
            family = "reentrancy"
            manifest = {
                "family": family,
                "target_address": TARGET,
                "steps": [{"kind": kind, "target": TARGET, "selector": SELECTOR}],
            }
            manifest_name = f"refuse-{kind}.json"
            manifest_path = root / manifest_name
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            refusal_relative = f"refusals/{kind}.json"
            result = subprocess.run(
                [lk, "steps", manifest_name, "--root", str(root),
                 "--output", f"test/SHOULD_NOT_EXIST_{kind}.t.sol",
                 "--refusal-output", refusal_relative],
                cwd=Path.cwd(), text=True, capture_output=True, check=False,
            )
            if result.returncode != 2:
                raise AssertionError(
                    f"Expected exit 2 for unsupported {kind}; received {result.returncode}. "
                    f"stdout={result.stdout[-3000:]} stderr={result.stderr[-3000:]}"
                )
            refusal_path = root / refusal_relative
            refusal = json.loads(refusal_path.read_text(encoding="utf-8"))
            if refusal.get("reason") != "backend_unsupported" or refusal.get("family") != family:
                raise AssertionError(f"Unsupported {kind} did not emit a machine-readable refusal: {refusal}")
            if (root / f"test/SHOULD_NOT_EXIST_{kind}.t.sol").exists():
                raise AssertionError(f"Unsupported {kind} unexpectedly produced an executable harness.")
            shutil.copy2(refusal_path, evidence_root / "refusals" / f"{kind}.json")
            refusals.append({"kind": kind, "reason": refusal["reason"], "exit_code": result.returncode})

        build = run([forge, "build"], root, timeout=360)
        forge_output = build.stdout[-12000:] + "\n" + build.stderr[-12000:]
        compiled_sources = sorted((root / "out").glob("LowkeySteps_*.t.sol/*.json"))
        if not compiled_sources:
            # Foundry output layout is contract-qualified, so look up artifacts by contract name.
            compiled_sources = sorted((root / "out").rglob("LowkeySteps_*.json"))
        compiled_names = sorted({
            path.name.removesuffix(".json")
            for path in compiled_sources
            if path.name.removesuffix(".json").startswith("LowkeySteps_")
        })
        expected_names = sorted(f"LowkeySteps_{family}" for family in families)
        if compiled_names != expected_names:
            raise AssertionError(
                f"Forge did not compile every Step family. expected={expected_names}, actual={compiled_names}\n"
                f"{forge_output[-6000:]}"
            )

    report = {
        "status": "PASS",
        "source_sha": expected_git_sha,
        "installed_git_sha": installed_git_sha,
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "template_sha256": template_digest,
        "forge_std_vm_sol": str(vm_sol),
        "verified_vm_signatures": cheat_signatures,
        "help_lines": help_lines,
        "families_compiled": compiled_names,
        "generated": generated,
        "refusals": refusals,
        "forge_build_output_tail": forge_output,
    }
    (evidence_root / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "families_compiled": len(compiled_names),
        "refusals": refusals,
        "evidence": evidence_root.as_posix(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
