#!/usr/bin/env python3
"""Deterministic Lowkey security-regression benchmark.

This benchmark answers a narrow engineering question:
"Does the current source-triage layer still recognize the review markers it
claims to recognize, while keeping comments/strings and language boundaries
clean?"

It deliberately does NOT claim to measure real-world vulnerability recall or
audit quality. Those require a larger adjudicated corpus with ground-truth
exploits and false-positive analysis.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any

try:
    from .analysis_adapters import source_triage
except ImportError:  # pragma: no cover
    try:
        from analysis_adapters import source_triage
    except ImportError:
        source_triage = None


CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "SOL-001",
        "language": "solidity",
        "label": "REENTRANCY REVIEW",
        "source": "contract Probe { function run(address target) external payable { target.call{value: msg.value}(\"\"); } }",
        "expected": {"REENTRANCY REVIEW"},
    },
    {
        "id": "SOL-002",
        "language": "solidity",
        "label": "ETH TRANSFER REVIEW",
        "source": "contract Probe { function run(address payable target) external { target.transfer(1); } }",
        "expected": {"ETH TRANSFER REVIEW"},
    },
    {
        "id": "SOL-003",
        "language": "solidity",
        "label": "TX.ORIGIN",
        "source": "contract Probe { address owner; function run() external view returns (bool) { return tx.origin == owner; } }",
        "expected": {"TX.ORIGIN"},
    },
    {
        "id": "SOL-004",
        "language": "solidity",
        "label": "DELEGATECALL",
        "source": "contract Probe { function run(address target, bytes calldata data) external { target.delegatecall(data); } }",
        "expected": {"REENTRANCY REVIEW", "DELEGATECALL"},
    },
    {
        "id": "SOL-005",
        "language": "solidity",
        "label": "SELFDESTRUCT",
        "source": "contract Probe { function run(address payable target) external { selfdestruct(target); } }",
        "expected": {"SELFDESTRUCT"},
    },
    {
        "id": "SOL-006",
        "language": "solidity",
        "label": "UNCHECKED",
        "source": "contract Probe { function run(uint256 x) external pure returns (uint256) { unchecked { return x + 1; } } }",
        "expected": {"UNCHECKED"},
    },
    {
        "id": "SOL-007",
        "language": "solidity",
        "label": "ASSEMBLY",
        "source": "contract Probe { function run() external pure { assembly { mstore(0, 1) } } }",
        "expected": {"ASSEMBLY"},
    },
    {
        "id": "SOL-008",
        "language": "solidity",
        "label": "ENCODE_PACKED",
        "source": "contract Probe { function run(address a, uint256 b) external pure returns (bytes memory) { return abi.encodePacked(a, b); } }",
        "expected": {"ENCODE_PACKED"},
    },
    {
        "id": "SOL-009",
        "language": "solidity",
        "label": "TIMESTAMP",
        "source": "contract Probe { function run() external view returns (uint256) { return block.timestamp; } }",
        "expected": {"TIMESTAMP"},
    },
    {
        "id": "SOL-010",
        "language": "solidity",
        "label": "BLOCKHASH/PREVRANDAO",
        "source": "contract Probe { function run() external view returns (uint256) { return block.prevrandao; } }",
        "expected": {"BLOCKHASH/PREVRANDAO"},
    },
    {
        "id": "SOL-011",
        "language": "solidity",
        "label": "ECRECOVER",
        "source": "contract Probe { function run(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) { return ecrecover(h, v, r, s); } }",
        "expected": {"ECRECOVER"},
    },
    {
        "id": "SOL-012",
        "language": "solidity",
        "label": "CREATE2",
        "source": "contract Probe { function run(bytes memory code, bytes32 salt) external returns (address a) { assembly { a := create2(0, add(code, 32), mload(code), salt) } } }",
        "expected": {"CREATE2", "ASSEMBLY"},
    },
    {
        "id": "SOL-013",
        "language": "solidity",
        "label": "COMMENT-STRING-IGNORED",
        "source": (
            "// delegatecall tx.origin block.timestamp should not count\n"
            "/* selfdestruct unchecked assembly */\n"
            "contract Probe { string public note = \"delegatecall tx.origin\"; "
            "function run() external pure returns (uint256) { return 7; } }"
        ),
        "expected": set(),
    },
    {
        "id": "VYPER-001",
        "language": "vyper",
        "label": "RAW_CALL",
        "source": "#pragma version ^0.4.3\n@external\ndef run(target: address):\n    raw_call(target, b\"\")\n",
        "expected": {"RAW_CALL"},
    },
    {
        "id": "VYPER-002",
        "language": "vyper",
        "label": "TX.ORIGIN",
        "source": "#pragma version ^0.4.3\n@external\ndef run():\n    a: address = tx.origin\n",
        "expected": {"TX.ORIGIN"},
    },
    {
        "id": "RUST-001",
        "language": "rust",
        "label": "UNSAFE",
        "source": "fn probe() { unsafe { std::ptr::read(0 as *const u8); } }",
        "expected": {"UNSAFE"},
    },
    {
        "id": "RUST-002",
        "language": "rust",
        "label": "POTENTIAL_PANIC",
        "source": "fn probe() { let _ = Some(1).unwrap(); }",
        "expected": {"POTENTIAL_PANIC"},
    },
    {
        "id": "CAIRO-001",
        "language": "cairo",
        "label": "SYSCALL",
        "source": "fn probe() { let _ = syscall::call_contract_syscall(0, 0, 0, 0); }",
        "expected": {"SYSCALL", "RAW_CALL"},
    },
    {
        "id": "MOVE-001",
        "language": "move",
        "label": "ENTRYPOINT",
        "source": "public entry fun probe(account: &signer) { }",
        "expected": {"ENTRYPOINT"},
    },
)


def _write_case(root: Path, case: dict[str, Any]) -> None:
    language = str(case["language"])
    extensions = {
        "solidity": ".sol",
        "vyper": ".vy",
        "rust": ".rs",
        "cairo": ".cairo",
        "move": ".move",
    }
    suffix = extensions[language]
    source_dir = root / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / f"Probe{suffix}").write_text(str(case["source"]), encoding="utf-8")

    if language == "solidity":
        (root / "foundry.toml").write_text(
            "[profile.default]\nsrc = \"src\"\ntest = \"test\"\n",
            encoding="utf-8",
        )


def _run_case(case: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="lowkey-bench-") as raw:
        root = Path(raw)
        _write_case(root, case)
        if source_triage is None:
            return {
                "id": case["id"],
                "status": "error",
                "expected": sorted(case["expected"]),
                "observed": [],
                "error": "analysis_adapters.source_triage is unavailable",
            }

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                result = source_triage(str(root))
        except Exception as exc:
            return {
                "id": case["id"],
                "status": "error",
                "expected": sorted(case["expected"]),
                "observed": [],
                "error": str(exc),
            }

        observed = {str(item.get("label")) for item in result.get("markers", [])}
        expected = set(case["expected"])
        passed = observed == expected
        return {
            "id": case["id"],
            "status": "pass" if passed else "fail",
            "expected": sorted(expected),
            "observed": sorted(observed),
            "files_scanned": result.get("files_scanned", 0),
        }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lk benchmark",
        description="Run deterministic source-triage security regressions.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    results = [_run_case(case) for case in CASES]
    passed = sum(item["status"] == "pass" for item in results)
    failed = sum(item["status"] != "pass" for item in results)
    payload = {
        "name": "lowkey-source-triage-regression",
        "cases": len(results),
        "passed": passed,
        "failed": failed,
        "scope": "source-triage detector regression",
        "not_a_security_accuracy_claim": True,
        "results": results,
    }

    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        print("LOWKEY SECURITY REGRESSION BENCHMARK")
        print("=" * 72)
        print("Scope : source-triage detector regression")
        print("Note  : this checks detector behavior; it is not a real-world audit-accuracy score.")
        print("")
        for item in results:
            marker = "PASS" if item["status"] == "pass" else "FAIL"
            print(f"{marker:<5} {item['id']:<18} expected={','.join(item['expected']) or 'none'} observed={','.join(item['observed']) or 'none'}")
            if args.verbose and item.get("error"):
                print(f"      error: {item['error']}")
        print("")
        print(f"Cases : {len(results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())
