"""Evidence-oriented Solidity source analysis for LowkeyCast test generation."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


def mask_solidity(text: str) -> str:
    """Mask comments and quoted literals without changing offsets or newlines."""
    chars = list(text)
    i, state, quote = 0, "code", ""
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch in ("'", '"'):
                quote = ch
                chars[i] = " "
                state = "string"
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        elif state == "string":
            if ch == "\\":
                chars[i] = " "
                if i + 1 < len(chars):
                    if chars[i + 1] != "\n":
                        chars[i + 1] = " "
                    i += 2
                    continue
            elif ch == quote:
                chars[i] = " "
                state = "code"
            elif ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _matching(mask: str, opening: int, left: str = "{", right: str = "}") -> int | None:
    depth = 0
    for i in range(opening, len(mask)):
        if mask[i] == left:
            depth += 1
        elif mask[i] == right:
            depth -= 1
            if depth == 0:
                return i
    return None


def _split(raw: str) -> list[str]:
    clean = mask_solidity(raw)
    parts, start, depth = [], 0, 0
    for i, ch in enumerate(clean):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            if raw[start:i].strip():
                parts.append(raw[start:i].strip())
            start = i + 1
    if raw[start:].strip():
        parts.append(raw[start:].strip())
    return parts


def _extract(source: str, name: str):
    masked = mask_solidity(source)
    match = re.search(r"\b(?:abstract\s+)?contract\s+" + re.escape(name) + r"\b[^{}]*\{", masked)
    if not match:
        return None
    opening = masked.find("{", match.start(), match.end())
    closing = _matching(masked, opening)
    if closing is None:
        return None
    header = source[match.start():opening]
    return source[opening + 1:closing], masked[opening + 1:closing], header, match.start()


def _parse_functions(body: str, clean: str, line_base: int) -> list[dict[str, Any]]:
    result = []
    for match in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", clean):
        name = match.group(1)
        op = clean.find("(", match.start())
        cp = _matching(clean, op, "(", ")")
        if cp is None:
            continue
        params = _split(body[op + 1:cp])
        cursor, parens, brace_open, semi = cp + 1, 0, None, None
        while cursor < len(clean):
            ch = clean[cursor]
            if ch == "(":
                parens += 1
            elif ch == ")":
                parens = max(0, parens - 1)
            elif parens == 0 and ch == "{":
                brace_open = cursor
                break
            elif parens == 0 and ch == ";":
                semi = cursor
                break
            cursor += 1
        end = brace_open if brace_open is not None else semi
        if end is None:
            continue
        header = body[match.start():end]
        body_text = ""
        if brace_open is not None:
            close = _matching(clean, brace_open)
            if close is None:
                continue
            body_text = body[brace_open + 1:close]
        vis = re.search(r"\b(external|public|internal|private)\b", header)
        returns_match = re.search(r"\breturns\s*\((.*?)\)", header, flags=re.S)
        ret = _split(returns_match.group(1)) if returns_match else []
        type_names = []
        for param in params:
            tokens = param.replace("memory", "").replace("calldata", "").replace("storage", "").split()
            if tokens:
                type_names.append(tokens[0])
        result.append({
            "name": name,
            "line": line_base + body.count("\n", 0, match.start()),
            "visibility": vis.group(1) if vis else "unknown",
            "parameters": params,
            "returns": ret,
            "modifiers": [m for m in ("onlyOwner", "onlyRole", "whenNotPaused", "whenPaused", "nonReentrant", "initializer") if re.search(r"\b" + m + r"\b", header)],
            "view": bool(re.search(r"\bview\b", header)),
            "pure": bool(re.search(r"\bpure\b", header)),
            "payable": bool(re.search(r"\bpayable\b", header)),
            "signature": name + "(" + ",".join(type_names) + ")",
            "header": header,
            "body": body_text,
        })
    return result


def _read_evidence(root: Path) -> dict[str, Any]:
    folder = root / ".audit" / "evidence"
    files, signals = [], []
    if not folder.is_dir():
        return {"files": [], "signals": [], "note": "No .audit/evidence directory found."}
    for path in sorted(folder.glob("*.json"))[:40]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        files.append(path.relative_to(root).as_posix())
        def walk(node: Any, depth: int = 0) -> None:
            if depth > 6 or len(signals) >= 25:
                return
            if isinstance(node, dict):
                title = node.get("check") or node.get("title") or node.get("description") or node.get("name")
                severity = node.get("impact") or node.get("severity")
                if isinstance(title, str) and (severity is not None or "check" in node):
                    item = {"source": path.relative_to(root).as_posix(), "title": title[:220]}
                    if isinstance(severity, (str, int, float)):
                        item["severity"] = str(severity)[:40]
                    signals.append(item)
                for value in node.values():
                    walk(value, depth + 1)
            elif isinstance(node, list):
                for value in node[:100]:
                    walk(value, depth + 1)
        walk(payload)
    return {"files": files, "signals": signals[:25], "note": None if files else "No readable JSON evidence was found."}


def _existing_tests(root: Path, configured_test_dir: Path | None = None) -> dict[str, Any]:
    files, count = [], 0
    directories = [configured_test_dir or (root / "test")]
    seen_directories: set[Path] = set()
    for directory in directories:
        directory = directory.resolve()
        if directory in seen_directories:
            continue
        seen_directories.add(directory)
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.sol"))[:300]:
            try:
                clean = mask_solidity(path.read_text(encoding="utf-8"))
            except OSError:
                continue
            names = re.findall(r"\bfunction\s+((?:test|invariant|echidna_)\w*)\s*\(", clean)
            count += len(names)
            try:
                relative_path = path.relative_to(root).as_posix()
            except ValueError:
                relative_path = str(path)
            files.append({"path": relative_path, "functions": names[:60]})
    return {"file_count": len(files), "function_count": count, "files": files[:100]}


def analyse_contract(
    root: Path,
    name: str,
    source_path: Path,
    source: str,
    configured_test_dir: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    extracted = _extract(source, name)
    functions, variables, events, declared_modifiers, inheritance = [], [], [], [], []
    if extracted:
        body, clean, header, contract_offset = extracted
        functions = _parse_functions(body, clean, source.count("\n", 0, contract_offset) + 1)
        inheritance_match = re.search(r"\bis\b", mask_solidity(header))
        if inheritance_match:
            inheritance_clause = header[inheritance_match.end():]
            for base_clause in _split(inheritance_clause):
                base_match = re.match(r"\s*([A-Za-z_]\w*)", mask_solidity(base_clause))
                if base_match and base_match.group(1) not in inheritance:
                    inheritance.append(base_match.group(1))
        simple_type = r"(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|address|bool|bytes(?:[1-9]|[12][0-9]|3[0-2])?|string)"
        for m in re.finditer(r"(?m)^\s*(" + simple_type + r")\s+((?:(?:public|private|internal|constant|immutable|override)\s+)*)([A-Za-z_]\w*)\s*(?:=[^;]*)?;", clean):
            modifiers = m.group(2).split()
            variables.append({"type": m.group(1), "name": m.group(3), "visibility": "public" if "public" in modifiers else "non-public", "line": source.count("\n", 0, contract_offset) + 1 + body.count("\n", 0, m.start())})
        events = [{"name": m.group(1), "line": source.count("\n", 0, contract_offset) + 1 + body.count("\n", 0, m.start())} for m in re.finditer(r"\bevent\s+([A-Za-z_]\w*)\s*\(", clean)]
        declared_modifiers = sorted(set(re.findall(r"\bmodifier\s+([A-Za-z_]\w*)\s*\(", clean)))
    full = mask_solidity(source)
    surface_rules = {
        "access control": r"\bonlyOwner\b|\bonlyRole\b|\bhasRole\s*\(|\bOwnable\b|\bAccessControl\b",
        "reentrancy / callbacks": r"\bnonReentrant\b|\.call\s*\(|\bonERC721Received\b|\bonFlashLoan\b",
        "pause / emergency stop": r"\bwhenNotPaused\b|\bPausable\b|\bpause\s*\(|\bunpause\s*\(",
        "upgrade / initialization": r"\bdelegatecall\b|\bupgradeTo(?:AndCall)?\s*\(|\binitialize\s*\(|\binitializer\b|\bERC1967\b|\bUUPS\b",
        "oracle / price": r"\blatestRoundData\s*\(|\blatestAnswer\s*\(|\bpriceFeed\b|\boracle\b",
        "signature / replay": r"\becrecover\s*\(|\bECDSA\b|\bnonces\s*\(|\bDOMAIN_SEPARATOR\b|\bpermit\s*\(",
        "accounting / solvency": r"\btotalAssets\s*\(|\btotalSupply\b|\btotalDebt\b|\baccountedBalance\b|\bliabilit(?:y|ies)\b",
        "token integration": r"\btransferFrom\s*\(|\bsafeTransferFrom\s*\(|\bSafeERC20\b|\bIERC20\b|\brebase\b",
        "time / ordering": r"\bblock\.timestamp\b|\bblock\.number\b|\bdeadline\b|\bblockhash\s*\(|\bprevrandao\b",
        "low-level calls": r"\.call\s*\(|\.staticcall\s*\(|\.delegatecall\s*\(|\bselfdestruct\s*\(",
        "bridge / cross-chain": r"\bmessageRoot\b|\brelay\s*\(|\bfinalize\s*\(|\bsourceChain\b|\bdestinationChain\b|\bmerkle\b",
        "lending / liquidation": r"\bliquidat(?:e|ion)\b|\bcollateral\b|\bhealthFactor\b|\bborrow\s*\(|\brepay\s*\(",
        "governance / timelock": r"\bpropose\s*\(|\bcastVote\s*\(|\bquorum\s*\(|\bTimelock\b|\bexecute\s*\(",
    }
    surfaces = {label: pattern for label, pattern in surface_rules.items() if re.search(pattern, full, flags=re.I)}
    lower = full.lower()
    profiles = []
    profile_rules = {
        "ERC-20-like token": (("balanceof", "totalsupply", "transfer(", "transferfrom(", "allowance", "approve("), 3),
        "ERC-721-like NFT": (("ownerof(", "safetransferfrom(", "getapproved(", "setapprovalforall("), 2),
        "ERC-4626-like vault": (("deposit(", "withdraw(", "redeem(", "totalassets(", "convertToShares(".lower()), 3),
        "escrow": (("createescrow", "release(", "refund(", "claim("), 2),
        "lending / collateral": (("borrow(", "repay(", "liquidate(", "collateral", "healthfactor"), 2),
        "staking / rewards": (("stake(", "unstake(", "claimreward", "rewardrate"), 2),
        "bridge / cross-chain": (("messageroot", "relay(", "finalize(", "sourcechain", "destinationchain"), 2),
        "oracle consumer": (("latestrounddata(", "latestanswer(", "pricefeed", "oracle"), 1),
        "governance": (("propose(", "castvote(", "quorum(", "proposalthreshold"), 2),
        "AMM / DEX": (("swap(", "getreserves(", "addliquidity(", "removeliquidity(", "sqrtpricex96", "tickspacing"), 2),
        "ERC-4337 account abstraction": (("validateuserop(", "entrypoint", "userophash", "paymaster", "executeuserop("), 2),
        "flash-loan / callback": (("flashloan(", "executeoperation(", "onflashloan(", "flashloanreceiver"), 2),
        "Merkle claims / airdrop": (("merkleroot", "proof", "claim(", "claimed"), 3),
        "NFT marketplace": (("listing", "cancellisting", "royalty", "safetransferfrom", "buy("), 3),
    }
    for profile, (tokens, threshold) in profile_rules.items():
        if sum(token in lower for token in tokens) >= threshold:
            profiles.append(profile)

    # Inherited standards often expose their API without repeating function names
    # in the child source, so include explicit base-contract evidence as well.
    inherited_profile_rules = {
        "ERC20": "ERC-20-like token",
        "ERC721": "ERC-721-like NFT",
        "ERC4626": "ERC-4626-like vault",
        "ERC1155": "ERC-1155-like multi-token",
    }
    for base in inheritance:
        compact = re.sub(r"[^A-Za-z0-9]", "", base).upper()
        for marker, profile in inherited_profile_rules.items():
            if marker in compact and profile not in profiles:
                profiles.append(profile)
    if re.search(r"\b(?:UUPSUpgradeable|ERC1967Proxy|Initializable)\b|\bupgradeToAndCall\b|\bdelegatecall\b", full, flags=re.I):
        if "proxy / upgradeable" not in profiles:
            profiles.append("proxy / upgradeable")
    imports = []
    for match in re.finditer(r"\bimport\b[^;]*;", mask_solidity(source)):
        raw = source[match.start():match.end()]
        quoted = re.search(r"""["']([^"']+)["']""", raw)
        if quoted:
            import_path = quoted.group(1)
            resolved = None
            if import_path.startswith("."):
                candidate = (source_path.parent / import_path).resolve()
                try:
                    resolved = candidate.relative_to(root).as_posix() if candidate.is_file() else None
                except ValueError:
                    pass
            imports.append({"path": import_path, "local_source": resolved})
    opportunities = []
    for profile in profiles:
        opportunities.append({"area": profile, "priority": "high", "reason": "Recognizable interface pattern; validate its exact protocol semantics."})
    for surface in surfaces:
        opportunities.append({"area": surface, "priority": "high" if surface in ("access control", "reentrancy / callbacks", "accounting / solvency", "upgrade / initialization") else "medium", "reason": "Source cue found; not a vulnerability conclusion."})
    return {
        "schema_version": 1,
        "contract": name,
        "source": source_path.relative_to(root).as_posix() if source_path.is_relative_to(root) else str(source_path),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "inheritance": inheritance,
        "profiles": profiles,
        "functions": [{k: fn[k] for k in ("name", "line", "visibility", "signature", "parameters", "returns", "modifiers", "view", "pure", "payable")} for fn in functions if fn["visibility"] in ("external", "public")],
        "state_variables": variables,
        "events": events,
        "declared_modifiers": declared_modifiers,
        "imports": imports,
        "security_surfaces": surfaces,
        "test_opportunities": opportunities,
        "existing_tests": _existing_tests(root, configured_test_dir),
        "audit_evidence": _read_evidence(root),
        "limitations": [
            "Heuristic source analysis can miss inheritance, aliases, assembly, proxy dispatch, and generated code.",
            "A detected signal is an audit lead, not proof of a vulnerability.",
            "Protocol invariants and expected economic outcomes must be grounded in project-specific evidence.",
        ],
    }


def unit_access_control_tests(analysis: dict[str, Any], contract_source: str) -> list[str]:
    """Generate narrow non-owner tests for plainly unconditional onlyOwner methods."""
    extracted = _extract(contract_source, analysis.get("contract", ""))
    if not extracted:
        return []
    body, clean, _, _ = extracted
    tests, used = [], {}
    for fn in _parse_functions(body, clean, 1):
        if fn["visibility"] not in ("external", "public") or "onlyOwner" not in fn["modifiers"]:
            continue
        code = mask_solidity(fn["body"])
        if re.search(r"\b(require|revert|if|while|for|try|catch)\b|[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(", code):
            continue
        if not re.search(r"\b[A-Za-z_]\w*\s*=(?!=)|\bemit\s+[A-Za-z_]\w*", code):
            continue
        args, valid = [], True
        for param in fn["parameters"]:
            tokens = param.replace("memory", "").replace("calldata", "").replace("storage", "").split()
            if not tokens:
                valid = False
                break
            kind = tokens[0]
            if re.fullmatch(r"u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", kind):
                args.append("0")
            elif kind == "bool":
                args.append("false")
            elif kind == "address":
                args.append("address(0xBEEF)")
            elif kind == "string":
                args.append('""')
            elif kind == "bytes":
                args.append('bytes("")')
            elif re.fullmatch(r"bytes(?:[1-9]|[12][0-9]|3[0-2])", kind):
                args.append(kind + "(0)")
            else:
                valid = False
                break
        if not valid:
            continue
        index = used.get(fn["name"], 0)
        used[fn["name"]] = index + 1
        suffix = "" if index == 0 else "_" + str(index + 1)
        tests.append(
            "    function test_nonOwnerCannotCall_" + fn["name"] + suffix + "() public {\n"
            "        vm.prank(address(0xBEEF));\n"
            "        vm.expectRevert();\n"
            "        target." + fn["name"] + "(" + ", ".join(args) + ");\n"
            "    }"
        )
    return tests


PROFILE_TEST_CHECKLISTS: dict[str, list[str]] = {
    "ERC-20-like token": [
        "Check zero-value transfers, self-transfers, insufficient balances, and recipient balance deltas.",
        "Check allowance consumption, infinite-allowance semantics, and unauthorized approval changes.",
        "Check mint/burn supply changes and totalSupply consistency; enumerate a closed actor set before asserting sum(balances) == totalSupply.",
        "Check non-standard token return behavior and fee-on-transfer/rebasing assumptions where integrations depend on them.",
    ],
    "ERC-721-like NFT": [
        "Check ownerOf before/after transfer, approval clearing, operator approvals, and unauthorized transfer reverts.",
        "Check safe-transfer callbacks for valid receivers, rejecting receivers, and reentrant receiver behavior.",
        "Check mint/burn token-existence boundaries, duplicate mint prevention, and approvals for nonexistent tokens.",
    ],
    "ERC-1155-like multi-token": [
        "Check per-token balances and supply assumptions across single and batch mint, burn, and transfer operations.",
        "Test operator approvals, unauthorized transfers, zero amounts, duplicate token IDs in batches, and array-length mismatch reverts.",
        "Exercise receiver callbacks for accepted/rejected single and batch transfers, including reentrancy-sensitive state updates.",
    ],
    "proxy / upgradeable": [
        "Check initializer and reinitializer access, one-time initialization, and implementation-constructor locking.",
        "Test upgrade authorization, invalid implementations, storage-layout compatibility, and preservation of critical state.",
        "Attempt initializer front-running and verify admin/owner/role separation across proxy and implementation.",
    ],
    "ERC-4626-like vault": [
        "Check deposit/mint/withdraw/redeem asset-share deltas and rounding direction at zero, one-unit, and large values.",
        "Check preview/max methods against actual operations under the same state and caller assumptions.",
        "Model donation/inflation attacks, first-depositor behavior, empty-vault transitions, fees, and rounding dust.",
        "Assert asset accounting only against the vault's documented treatment of fees, donations, rebasing, and strategy assets.",
    ],
    "escrow": [
        "Model the lifecycle as a state machine; release and refund must not both succeed for the same escrow.",
        "Check buyer/seller/arbitrator authorization, deadlines, cancellation, and exact boundary timestamps.",
        "Attempt duplicate claims and reentrant receiver/token callbacks; compare credited liabilities with held assets.",
    ],
    "lending / collateral": [
        "Test health-factor and liquidation-threshold boundaries immediately above, at, and below the threshold.",
        "Check collateral/debt deltas across borrow, repay, deposit, withdraw, and liquidation, including partial and full repayment.",
        "Test stale/invalid oracle data, decimal mismatches, extreme prices, rounding, bad debt, and insolvency handling.",
    ],
    "staking / rewards": [
        "Check reward accrual across stake/unstake/claim ordering and exact reward-period boundaries.",
        "Test late stakers, repeated claims, zero stake, reward exhaustion, rounding dust, and denominator changes.",
        "Assert reward liabilities against funded rewards and verify users cannot claim another user's accrued rewards.",
    ],
    "bridge / cross-chain": [
        "Check replay protection over message ID, source chain, sender, destination chain, and nonce/domain.",
        "Test duplicate, out-of-order, invalid-proof, expired, and wrong-destination messages.",
        "Check pause/emergency paths and that finalized messages cannot mint/release assets twice.",
    ],
    "oracle consumer": [
        "Test stale rounds, zero/negative answers, incomplete rounds, future timestamps, decimals, and extreme values.",
        "Check behavior when the oracle reverts or returns malformed data and whether actions fail closed.",
        "Exercise price movement around liquidation, mint, redemption, or settlement thresholds.",
    ],
    "governance": [
        "Test proposal threshold and quorum boundaries, vote snapshots, duplicate voting, and vote-weight changes.",
        "Check timelock minimum delay, queued/cancelled/executed transitions, and replay of execution payloads.",
        "Verify proposer, voter, guardian, and executor role separation; test malicious targets and failed execution recovery.",
    ],
    "AMM / DEX": [
        "Test swap slippage/deadline boundaries, fee arithmetic, reserve or tick accounting, and zero-liquidity transitions.",
        "Check price-impact manipulation, donation/reserve desynchronization, rounding dust, and multi-swap sequences.",
        "Verify liquidity mint/burn shares against the documented invariant and test callbacks/reentrancy around token transfers.",
    ],
    "ERC-4337 account abstraction": [
        "Test UserOperation hash domain separation, chain/EntryPoint binding, nonce replay, and signature validation boundaries.",
        "Check validation/execution separation, sender deployment, aggregator behavior, and paymaster deposit/refund accounting.",
        "Exercise malformed operations, gas/fee edge cases, bundler simulation differences, and unauthorized EntryPoint calls.",
    ],
    "flash-loan / callback": [
        "Verify callback initiator, asset, amount, and fee are authenticated and cannot be replayed or spoofed.",
        "Test exact repayment requirements, underpayment, multiple assets, callback reentrancy, and state changes before repayment.",
        "Check failures revert the whole operation and that callback success cannot be forged by returning an unexpected value.",
    ],
    "Merkle claims / airdrop": [
        "Test valid/invalid proofs, duplicate claims, leaf domain separation, and replay across campaigns or chains.",
        "Exercise duplicate leaves, sorted-pair assumptions, zero allocations, claim deadlines, and root replacement.",
        "Check total claimed versus funded allocation only where the full claimant set and accounting model are known.",
    ],
    "NFT marketplace": [
        "Test listing ownership/approval, stale or cancelled listings, duplicate fills, and atomic asset/payment transfer.",
        "Check fee/royalty rounding, recipient changes, zero-price edge cases, and reentrancy across NFT/token callbacks.",
        "Verify signed orders bind chain, marketplace, token ID, price, nonce, expiry, and cancellation state.",
    ],
}


def render_test_plan(analysis: dict[str, Any], generated_types: list[str]) -> str:
    lines = [
        "# LowkeyCast test-generation plan: " + analysis.get("contract", "unknown"),
        "",
        "> Evidence map and ranked test plan; this is not a coverage claim or a vulnerability verdict.",
        "",
        "## Project surface",
        "",
        "- Source: " + str(analysis.get("source", "unknown")),
        "- Source SHA-256: `" + str(analysis.get("source_sha256", "not available")) + "`",
        "- Inheritance: " + (", ".join(analysis.get("inheritance", [])) or "not recognized"),
        "- Candidate profiles: " + (", ".join(analysis.get("profiles", [])) or "none confidently recognized"),
        "- Existing Solidity test files: " + str(analysis.get("existing_tests", {}).get("file_count", 0)),
        "- Existing test/invariant functions: " + str(analysis.get("existing_tests", {}).get("function_count", 0)),
        "- Requested generated families: " + (", ".join(generated_types) or "none"),
        "",
        "## Recognized security surfaces",
        "",
    ]
    if analysis.get("security_surfaces"):
        for label, pattern in analysis["security_surfaces"].items():
            lines.append("- **" + label + "** — source cue: " + pattern + ". This is an audit lead, not a finding.")
    else:
        lines.append("- No listed pattern was recognized. This does not establish that the contract is safe.")
    lines += ["", "## Test plan by family", ""]
    for heading, detail in [
        ("Unit", "Cover valid state transitions, caller identity, permissions, reverts, events, boundaries, initialization and repeated calls. Use assertions tied to intended behavior."),
        ("Fuzz", "Fuzz meaningful inputs with boundary-biased values and valid preconditions; assert a precise property rather than merely executing calls."),
        ("Invariant", "Define accounting conservation, solvency, role isolation, state-machine legality and token/balance consistency where relevant. Ensure handlers make successful state changes."),
        ("Integration", "Configure actual peer contracts and dependencies; examine callbacks and non-standard token behavior when relevant."),
        ("Fork", "Pin chain/block when reproducibility matters; verify target code, proxy implementation and critical dependency addresses; compare deployed state with explicit expectations."),
        ("PoC / regression", "Record exact preconditions, trigger, violated property, measurable asset/state impact and a regression assertion that detects the original bug."),
        ("Formal", "State assumptions and properties precisely, check for vacuity and unsound external summaries, run the configured verifier and review counterexamples. A spec is not a proof."),
    ]:
        lines.extend(["### " + heading, detail, ""])
    matched_profiles = [profile for profile in analysis.get("profiles", []) if profile in PROFILE_TEST_CHECKLISTS]
    lines += ["", "## Profile-specific test obligations", ""]
    if matched_profiles:
        lines.append("These are candidate checks suggested by source/interface cues. Confirm the protocol specification and assumptions before turning them into assertions.")
        lines.append("")
        for profile in matched_profiles:
            lines.append("### " + profile)
            for obligation in PROFILE_TEST_CHECKLISTS[profile]:
                lines.append("- " + obligation)
            lines.append("")
    else:
        lines.append("No known protocol profile was confidently recognized; derive obligations from the specification, dependencies, and audit evidence.")
        lines.append("")
    lines += ["## Public/external functions", ""]
    for fn in analysis.get("functions", [])[:100]:
        suffix = " — modifiers: " + ", ".join(fn["modifiers"]) if fn.get("modifiers") else ""
        lines.append("- " + fn["signature"] + " (line " + str(fn["line"]) + ")" + suffix)
    if not analysis.get("functions"):
        lines.append("- No public/external functions were confidently parsed.")
    lines += ["", "## Dependency imports", ""]
    if analysis.get("imports"):
        for item in analysis["imports"]:
            lines.append("- " + item["path"] + (" — local file: " + item["local_source"] if item.get("local_source") else " — external/remapped path or unresolved locally"))
    else:
        lines.append("- No imports found.")
    lines += ["", "## Existing audit evidence", ""]
    evidence = analysis.get("audit_evidence", {})
    if evidence.get("files"):
        for path in evidence["files"]:
            lines.append("- " + path)
    else:
        lines.append("- " + str(evidence.get("note") or "No reusable evidence found."))
    if evidence.get("signals"):
        lines += ["", "### Extracted signal summaries", ""]
        for item in evidence["signals"]:
            severity = " [" + item["severity"] + "]" if item.get("severity") else ""
            lines.append("- " + item["title"] + severity + " — " + item["source"])
    lines += [
        "",
        "## Limitations and validation",
        "",
        "- Constructor defaults are compile-oriented placeholders, not proof of valid protocol setup.",
        "- Source-pattern inference can miss inheritance, aliases, inline assembly and dynamic dispatch.",
        "- A generated file is not a passing test until compiled and executed.",
        "- Formal properties require a real prover run and review of assumptions/counterexamples.",
        "",
        "## Research references",
        "",
        "- Foundry invariant testing: https://getfoundry.sh/forge/invariant-testing",
        "- Foundry fork testing: https://getfoundry.sh/reference/cheatcodes/create-select-fork",
        "- Echidna property-based testing: https://ethereum.org/developers/tutorials/how-to-use-echidna-to-test-smart-contracts/",
        "- Certora CVL: https://docs.certora.com/en/latest/docs/cvl/overview.html",
        "- Solidity SMTChecker: https://docs.solidity.org/en/latest/smtchecker.html",
        "",
    ]
    return "\n".join(lines)
