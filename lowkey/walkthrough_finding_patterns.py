"""Real-world smart-contract finding pattern checks for the live walkthrough.

This module deliberately distills recurring, adjudicated bug logic from public
audit contests and bug-bounty research instead of copying individual findings.
Results are candidates unless a concrete local-chain invariant is reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

try:
    from . import walkthrough as core
    from . import audit_context
except ImportError:
    import walkthrough as core
    try:
        import audit_context
    except ImportError:
        audit_context = None


@dataclass
class PatternObservation:
    pattern_id: str
    title: str
    status: str
    contract: str
    function: str = ""
    source: str = ""
    line: int | None = None
    evidence: list[str] = field(default_factory=list)
    logic: str = ""
    next_step: str = ""
    provenance: list[str] = field(default_factory=list)


# The catalog is intentionally small and recurrence-driven.  Each entry is
# supported by concrete public contest/bug-bounty examples and is guarded
# against becoming an automatic vulnerability verdict.
PATTERN_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "REPLAY-001",
        "title": "Replayable payout / claim path",
        "keywords": ("claim", "redeem", "withdraw", "release", "collect", "harvest", "faucet", "drip", "payout", "refund"),
        "logic": "A one-shot entitlement is dangerous when the same economic action can be executed again without consuming the user's entitlement.",
        "provenance": ["CodeHawks SNARKeling", "CodeHawks Tadle", "Immunefi Belong"],
    },
    {
        "id": "REENTRANCY-001",
        "title": "External call before state update",
        "keywords": (),
        "logic": "If control leaves the contract before the state that authorizes the payout is consumed, a callback may repeat the same path.",
        "provenance": ["CodeHawks Raisebox", "Immunefi Omni", "Immunefi Common Vulnerabilities"],
    },
    {
        "id": "READONLY-001",
        "title": "Read-only reentrancy around external callbacks",
        "keywords": (),
        "logic": "A callback can observe or trigger a read while the protocol's temporary state is inconsistent, causing another contract to consume a transient price/share/debt value.",
        "provenance": ["Code4rena Revert Lend", "Immunefi Common Vulnerabilities"],
    },
    {
        "id": "AUTH-001",
        "title": "Sensitive state change without an obvious authorization boundary",
        "keywords": ("admin", "owner", "upgrade", "pause", "unpause", "set", "configure", "remove", "rescue", "sweep", "mint"),
        "logic": "A privileged state transition should have an explicit authorization boundary. A missing boundary is a candidate until call reachability and intended publicness are proven.",
        "provenance": ["Code4rena Maia", "Immunefi Common Vulnerabilities", "CodeHawks access-control findings"],
    },
    {
        "id": "ORACLE-001",
        "title": "Oracle freshness / round checks may be missing",
        "keywords": (),
        "logic": "A price read can be numerically valid while economically stale or invalid unless freshness and round metadata are checked.",
        "provenance": ["CodeHawks Stratax", "Code4rena BakerFi", "Code4rena Perennial"],
    },
    {
        "id": "ROUND-001",
        "title": "Deposit/mint rounding can produce zero shares",
        "keywords": ("deposit", "mint", "stake", "redeem"),
        "logic": "A positive asset deposit that mints zero accounting shares can strand value or let later users capture it.",
        "provenance": ["CodeHawks Company Simulator", "Code4rena Panoptic", "Code4rena BakerFi"],
    },
    {
        "id": "SIG-001",
        "title": "Signature replay / weak binding",
        "keywords": ("permit", "signature", "sig", "verify", "execute", "authorization"),
        "logic": "A signed action normally needs replay and context binding such as a nonce and appropriate domain, contract, chain, or expiry constraints.",
        "provenance": ["Immunefi Belong", "Immunefi Common Vulnerabilities", "Code4rena Revert Lend"],
    },
    {
        "id": "DOS-001",
        "title": "Unbounded storage growth in a mutating loop",
        "keywords": ("withdraw", "claim", "redeem", "update", "settle", "harvest", "liquidate", "execute"),
        "logic": "A loop over attacker-influenceable or permanently growing storage can make a critical path exceed the block gas limit.",
        "provenance": ["CodeHawks The Standard", "Code4rena Vader", "Immunefi Belong"],
    },
    {
        "id": "TOKEN-001",
        "title": "ERC20 transfer result may be ignored",
        "keywords": ("transfer", "withdraw", "deposit", "stake", "claim", "mint", "rescue"),
        "logic": "Accounting that assumes token.transfer/transferFrom succeeded can diverge when a token returns false or behaves non-standardly.",
        "provenance": ["Code4rena Inverse Finance", "Immunefi Common Vulnerabilities"],
    },
    {
        "id": "ACCOUNTING-001",
        "title": "Repeated / mismatched accounting reference in a validation path",
        "keywords": (),
        "logic": "Validation must compare the field actually being constrained. Checking one variable twice while another related field is unchecked can create asymmetric validation.",
        "provenance": ["CodeHawks Gamma", "CodeHawks RebateFi", "CodeHawks Token0x", "CodeHawks TempleGold"],
    },
    {
        "id": "FOT-001",
        "title": "Fee-on-transfer accounting assumption",
        "keywords": ("deposit", "stake", "fund", "transferfrom"),
        "logic": "Crediting a user with the requested amount instead of the amount actually received can over-credit balances for fee-on-transfer tokens.",
        "provenance": ["Code4rena DeFiProtocol", "Code4rena Token handling findings"],
    },
    {
        "id": "RNG-001",
        "title": "Predictable randomness source",
        "keywords": ("random", "winner", "lottery", "roll", "draw", "nonce"),
        "logic": "Block timestamp/number/hash and similar chain-visible values are generally predictable enough to be unsafe as sole randomness for valuable outcomes.",
        "provenance": ["CodeHawks Rock Paper Scissors", "Immunefi Common Vulnerabilities"],
    },
    {
        "id": "INIT-001",
        "title": "Initializer may be callable after configuration",
        "keywords": ("initialize", "initializer", "reinitialize"),
        "logic": "An upgradeable or initializer-based instance must not allow an attacker to initialize or reinitialize it after ownership/admin state has already been established.",
        "provenance": ["Immunefi Common Vulnerabilities", "Code4rena Perennial", "Immunefi Wormhole bug-fix review"],
    },
    {
        "id": "CALL-001",
        "title": "User-controlled external call target / data",
        "keywords": ("call", "execute", "delegatecall", "multicall"),
        "logic": "An arbitrary external call primitive needs a deliberate authorization boundary and explicit trust model for target and calldata.",
        "provenance": ["Immunefi Common Vulnerabilities", "Code4rena Revert Lend"],
    },
    {
        "id": "ECONOMIC-001",
        "title": "Hardcoded fee/rate/price in an economic path",
        "keywords": ("fee", "rate", "price", "exchange"),
        "logic": "Economic parameters that are expected to track an external protocol, market, or governance setting can become incorrect when embedded as fixed literals.",
        "provenance": ["CodeHawks Steadefi", "CodeHawks RAAC", "Code4rena BakerFi"],
    },
    {
        "id": "ZEROADDR-001",
        "title": "Zero-address accepted on a configuration path",
        "keywords": ("set", "configure", "register", "initialize", "rescue", "router", "oracle", "treasury"),
        "logic": "Critical dependencies such as owners, tokens, routers, or recipients can become permanently unusable when address(0) is accepted without an explicit design reason.",
        "provenance": ["CodeHawks SNARKeling", "CodeHawks access/configuration findings", "Immunefi Common Vulnerabilities"],
    },
    {
        "id": "TIME-001",
        "title": "Deadline / expiry guard deserves a boundary probe",
        "keywords": ("deadline", "expiry", "expiration", "validuntil"),
        "logic": "Time-bounded signatures and actions fail safely only when expired inputs are actually rejected at execution time.",
        "provenance": ["Immunefi Common Vulnerabilities", "Immunefi Belong", "CodeHawks time/expiry findings"],
    },
)

_PATTERN_BY_ID = {str(item["id"]): item for item in PATTERN_CATALOG}


def _pattern(pattern_id: str) -> dict[str, Any]:
    return _PATTERN_BY_ID[pattern_id]


def _read_source(root: Path, model: core.ContractModel) -> str:
    path = root / str(model.source)
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _function_blocks(source: str, language: str = "solidity") -> list[tuple[str, int, str, str]]:
    """Return function name, line, declaration/header, and body for Solidity or Vyper."""
    blocks: list[tuple[str, int, str, str]] = []
    if language == "vyper":
        lines = source.splitlines(True)
        current: tuple[str, int, int, str] | None = None
        body_lines: list[str] = []
        decorators: list[str] = []
        for index, line in enumerate(lines):
            stripped_line = line.strip()
            match = re.match(r"^([ \\t]*)def\\s+(\\w+)\\s*\\([^)]*\\)\\s*:\\s*(?:#.*)?$", line.rstrip("\\n"))
            if match:
                if current:
                    name, start, indent, header = current
                    blocks.append((name, start, header, "".join(body_lines)))
                header = "\\n".join(decorators + [line.rstrip("\\n")])
                current = (match.group(2), index + 1, len(match.group(1)), header)
                body_lines = []
                decorators = []
                continue
            if current:
                if line.strip() and len(line) - len(line.lstrip(" \\t")) <= current[2]:
                    name, start, indent, header = current
                    blocks.append((name, start, header, "".join(body_lines)))
                    current = None
                    body_lines = []
                else:
                    body_lines.append(line)
            elif stripped_line.startswith("@"):
                decorators.append(line.rstrip("\\n"))
            elif stripped_line:
                decorators = []
        if current:
            name, start, indent, header = current
            blocks.append((name, start, header, "".join(body_lines)))
        return blocks

    for match in re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{", source, re.S):
        opening = match.end() - 1
        body = core._balanced_block(source, opening)
        header = source[match.start():opening]
        blocks.append((match.group(1), source.count("\n", 0, match.start()) + 1, header, body))
    return blocks


def _abi_function(model: core.ContractModel, name: str) -> dict[str, Any] | None:
    return next(
        (
            item for item in model.abi
            if item.get("type") == "function" and str(item.get("name") or "") == name
        ),
        None,
    )


def _mutating(model: core.ContractModel, name: str) -> bool:
    item = _abi_function(model, name)
    return bool(item and item.get("stateMutability") in {"nonpayable", "payable"})


def _sensitive_name(name: str, keywords: tuple[str, ...]) -> bool:
    lower = name.lower()
    return any(token in lower for token in keywords)


def _result(
    pattern: str,
    title: str,
    model: core.ContractModel,
    fn: str,
    source: str,
    line: int,
    evidence: list[str],
    logic: str,
    next_step: str,
    provenance: list[str],
    status: str = "CANDIDATE",
) -> PatternObservation:
    return PatternObservation(
        pattern_id=pattern,
        title=title,
        status=status,
        contract=model.name,
        function=fn,
        source=str(model.source),
        line=line,
        evidence=evidence,
        logic=logic,
        next_step=next_step,
        provenance=provenance,
    )


def scan_model(root: Path, model: core.ContractModel) -> list[PatternObservation]:
    """Run conservative source-level pattern checks against one model."""
    source = _read_source(root, model)
    if not source:
        return []

    stripped = core._strip_source_comments(
        source,
        "vyper" if str(model.source).lower().endswith((".vy", ".vyi")) else "solidity",
    )
    results: list[PatternObservation] = []

    # Global tx.origin signal.
    if re.search(r"\btx\.origin\b", stripped):
        line = source.count("\n", 0, stripped.find("tx.origin")) + 1
        results.append(_result(
            "AUTH-002",
            "tx.origin used in contract logic",
            model,
            "<contract>",
            source,
            line,
            ["The source references tx.origin."],
            "Authorization based on tx.origin can be bypassed through an intermediate contract and is usually weaker than checking the intended caller.",
            "Inspect whether tx.origin is part of authorization, signature binding, or another security boundary.",
            ["Immunefi Common Vulnerabilities"],
        ))

    language = "vyper" if str(model.source).lower().endswith((".vy", ".vyi")) else "solidity"
    for name, line, header, body in _function_blocks(stripped, language):
        if not _mutating(model, name):
            continue
        lower = name.lower()

        # Replay/claim path candidate.
        if _sensitive_name(name, _pattern("REPLAY-001")["keywords"]):
            has_user_key = bool(re.search(r"\[[^\]]*(msg\.sender|_msgSender|caller|owner|user)", body))
            has_state_write = bool(re.search(r"\b(claimed|claimedAmount|withdrawn|used|spent|redeemed|nonce|balance|balances|entitled|remaining)\w*\s*\[?[^;=]*\]?\s*(?:[-+]?=|\+\+|--)", body))
            has_native_payout = bool(re.search(r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(", body))
            if has_user_key or has_state_write or has_native_payout:
                evidence = [
                    "This function looks like an economic claim/withdraw/redeem path.",
                ]
                if has_state_write:
                    evidence.append("The body writes user/entitlement state; this is the state that must be consumed exactly once.")
                elif has_native_payout:
                    evidence.append("The function performs a native-value payout but does not show an entitlement-consumption write in this function.")
                elif has_user_key:
                    evidence.append("The function is keyed by caller/user state; replay safety depends on how that state is consumed.")
                results.append(_result(
                    "REPLAY-001",
                    _pattern("REPLAY-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    evidence,
                    _pattern("REPLAY-001")["logic"],
                    "Run the same concrete call twice from the same actor with enough protocol reserve and compare the second call's value/state delta.",
                    _pattern("REPLAY-001")["provenance"],
                ))

        # Reentrancy / CEI candidate.
        calls = list(re.finditer(
            r"(?:\.call\s*(?:\{|\()|\.transfer\s*\(|\.send\s*\(|\.safeTransfer\s*\(|\.safeTransferFrom\s*\(|\.functionCall\s*\(|\braw_call\s*\(|\bsend\s*\()",
            body,
        ))
        if calls:
            first_call = calls[0].start()
            writes = list(re.finditer(
                r"\b(?:\w+\[[^\]]+\]|\w+)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)",
                body,
            ))
            later_write = next((item for item in writes if item.start() > first_call), None)
            has_guard = bool(re.search(r"\bnonReentrant\b|\breentrancy\b", header + " " + body, re.I))
            if later_write and not has_guard:
                results.append(_result(
                    "REENTRANCY-001",
                    _pattern("REENTRANCY-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["An external interaction appears before a later state write.", "No obvious nonReentrant guard was found in the local source context."],
                    _pattern("REENTRANCY-001")["logic"],
                    "Trace the callee and try to reproduce a callback before the authorization/balance state is consumed.",
                    _pattern("REENTRANCY-001")["provenance"],
                ))

        # Read-only reentrancy candidate.
        if calls:
            first_call = calls[0].start()
            readonly_call = re.search(
                r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                body[first_call + 1:],
            )
            if readonly_call and re.search(r"(?:^|_)(?:get|quote|price|rate|balance|total|debt|share|value|preview)", readonly_call.group(1), re.I):
                results.append(_result(
                    "READONLY-001",
                    _pattern("READONLY-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["An external interaction is followed by a getter/quote-like call in the same mutating path."],
                    _pattern("READONLY-001")["logic"],
                    "Trace the callback path and check whether the getter can observe transient state before it is restored.",
                    _pattern("READONLY-001")["provenance"],
                ))

        # Sensitive state changes without a visible auth check.
        if _sensitive_name(name, _pattern("AUTH-001")["keywords"]):
            auth_evidence = re.search(
                r"\bonly[A-Za-z0-9_]*\b|\b(?:require|assert)\s*\([^)]*(?:msg\.sender|_msgSender|hasRole|owner\s*\(\)|authority)",
                header + " " + body,
                re.I,
            )
            if not auth_evidence:
                results.append(_result(
                    "AUTH-001",
                    _pattern("AUTH-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["No obvious caller/role/owner check was found in the function body or its nearby modifiers."],
                    _pattern("AUTH-001")["logic"],
                    "Verify whether the function is intentionally public. If not, reproduce the call from an unprivileged actor.",
                    _pattern("AUTH-001")["provenance"],
                ))

        # Oracle freshness.
        if "latestRoundData" in body or "getRoundData" in body:
            has_freshness = bool(
                re.search(r"updatedAt|answeredInRound|roundId", body)
                and re.search(r"[<>]=?|==|!=", body)
            )
            if not has_freshness:
                results.append(_result(
                    "ORACLE-001",
                    _pattern("ORACLE-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["latestRoundData/getRoundData is read, but no obvious freshness/round comparison appears in this function."],
                    _pattern("ORACLE-001")["logic"],
                    "Check what happens when the oracle returns an old round or stale updatedAt.",
                    _pattern("ORACLE-001")["provenance"],
                ))

        # Zero-share / rounding candidate.
        if _sensitive_name(name, _pattern("ROUND-001")["keywords"]) and re.search(r"\/|mulDiv|divWad|mulWad|convertToShares|shares", body, re.I):
            has_zero_guard = bool(re.search(r"(shares|minted|received)[^\n;]{0,100}(?:>|!=)\s*0|(?:>\s*0|!=\s*0)[^\n;]{0,100}(shares|minted|received)", body, re.I))
            if not has_zero_guard:
                results.append(_result(
                    "ROUND-001",
                    _pattern("ROUND-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["The path performs share/amount conversion or division without an obvious zero-output guard."],
                    _pattern("ROUND-001")["logic"],
                    "Try the smallest positive deposit or a boundary ratio and verify minted shares against the deposited assets.",
                    _pattern("ROUND-001")["provenance"],
                ))

        # Signature binding.
        if re.search(r"ecrecover|ECDSA|recover\s*\(|verify\s*\(|signature|permit", body, re.I):
            has_nonce = bool(re.search(r"\bnonce\b|nonces\s*\(", body, re.I))
            has_context = bool(re.search(r"address\s*\(\s*this\s*\)|block\.chainid|DOMAIN_SEPARATOR|domainSeparator", body, re.I))
            if not has_nonce or not has_context:
                missing = []
                if not has_nonce:
                    missing.append("nonce/replay counter")
                if not has_context:
                    missing.append("domain/contract/chain binding")
                results.append(_result(
                    "SIG-001",
                    _pattern("SIG-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    [f"Signature handling is present but no obvious {' and '.join(missing)} was found."],
                    _pattern("SIG-001")["logic"],
                    "Replay the exact signed payload, then vary chain/contract/deadline context if the protocol supports it.",
                    _pattern("SIG-001")["provenance"],
                ))

        # Unbounded storage loop.
        state_arrays = {str(item.get("name") or "") for item in model.arrays if item.get("name")}
        for loop in re.finditer(r"\bfor\s*\([^)]*\b(\w+)\.length\b[^)]*\)", body):
            collection = loop.group(1)
            if collection in state_arrays:
                results.append(_result(
                    "DOS-001",
                    _pattern("DOS-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    [f"Loop iterates over storage array '{collection}' with no local bound visible in the loop header."],
                    _pattern("DOS-001")["logic"],
                    "Check whether an untrusted actor can increase the array and whether the loop sits on a critical withdrawal/settlement path.",
                    _pattern("DOS-001")["provenance"],
                ))
                break

        # ERC20 result + accounting.
        transfer_calls = re.findall(r"\b\w+\.(transfer|transferFrom)\s*\(", body)
        if transfer_calls and not re.search(r"(?:require|if|assert)\s*\([^)]*(?:transfer|transferFrom)\s*\(", body) and not re.search(r"\bSafeERC20\b|\.safeTransfer(?:From)?\s*\(", body):
            results.append(_result(
                "TOKEN-001",
                _pattern("TOKEN-001")["title"],
                model,
                name,
                source,
                line,
                ["Raw ERC20 transfer/transferFrom usage was found without an obvious checked return or SafeERC20 wrapper."],
                _pattern("TOKEN-001")["logic"],
                "Inspect the exact token interface and verify what happens when transfer returns false instead of reverting.",
                _pattern("TOKEN-001")["provenance"],
            ))

        # Obvious paired-variable mismatch candidate.
        paired_fields = (
            ("token0", "token1"),
            ("currency0", "currency1"),
            ("longtoken", "indextoken"),
            ("longtoken", "shorttoken"),
            ("long", "short"),
        )
        conditions = re.findall(r"\b(?:if|require|assert)\s*\(([^;]+)\)", body, re.I)
        for left, right in paired_fields:
            if not (re.search(r"\b" + left + r"\b", body, re.I) and re.search(r"\b" + right + r"\b", body, re.I)):
                continue
            suspicious = next(
                (cond for cond in conditions if re.search(r"\b" + left + r"\b", cond, re.I) and re.search(r"\b" + right + r"\b", cond, re.I)),
                None,
            )
            if suspicious:
                results.append(_result(
                    "ACCOUNTING-001",
                    _pattern("ACCOUNTING-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    [f"Validation condition references paired fields '{left}' and '{right}'; compare each check against the correct operand."],
                    _pattern("ACCOUNTING-001")["logic"],
                    "Inspect both sides of the paired validation and trace the value actually used later for accounting/pricing.",
                    _pattern("ACCOUNTING-001")["provenance"],
                ))
                break

        # Fee-on-transfer assumption.
        if "transferFrom" in body and re.search(r"\b(?:balance|balances|amount|deposit|stake)\w*\s*(?:\+=|=)\s*\w*amount\w*\b", body, re.I) and "balanceOf" not in body:
            results.append(_result(
                "FOT-001",
                _pattern("FOT-001")["title"],
                model,
                name,
                source,
                line,
                ["transferFrom is followed by accounting that appears to credit the requested amount without measuring actual balance received."],
                _pattern("FOT-001")["logic"],
                "Test with a fee-on-transfer token or compare the contract's balance before/after transferFrom.",
                _pattern("FOT-001")["provenance"],
            ))

        # Predictable randomness.
        if _sensitive_name(name, _pattern("RNG-001")["keywords"]) and re.search(r"\b(block\.timestamp|block\.number|blockhash\s*\(|block\.prevrandao|block\.difficulty)\b", body):
            results.append(_result(
                "RNG-001",
                _pattern("RNG-001")["title"],
                model,
                name,
                source,
                line,
                ["A chain-visible block value is used in a function whose name suggests a random outcome."],
                _pattern("RNG-001")["logic"],
                "Ask whether a validator/builder or another participant can predict or influence the outcome enough to profit.",
                _pattern("RNG-001")["provenance"],
            ))

        # Initializer signal.
        if lower.startswith(("initialize", "reinitialize", "initializer")):
            results.append(_result(
                "INIT-001",
                _pattern("INIT-001")["title"],
                model,
                name,
                source,
                line,
                ["Initializer-like function exists on a state-changing contract."],
                _pattern("INIT-001")["logic"],
                "Call the initializer from an unprivileged actor against the live configured instance inside a snapshot.",
                _pattern("INIT-001")["provenance"],
            ))

        # Arbitrary call / delegatecall signal.
        if re.search(r"\.(?:call|delegatecall|staticcall)\s*\(", body):
            external_target = bool(re.search(r"\b(address|target|to|recipient|implementation)\b", body, re.I))
            if external_target and _sensitive_name(name, _pattern("CALL-001")["keywords"]):
                results.append(_result(
                    "CALL-001",
                    _pattern("CALL-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["The function combines a generic call primitive with a caller-supplied or address-like target."],
                    _pattern("CALL-001")["logic"],
                    "Trace the callee and verify the authorization boundary around target + calldata.",
                    _pattern("CALL-001")["provenance"],
                ))

        # Hardcoded economic parameter candidate.
        if _sensitive_name(name, _pattern("ECONOMIC-001")["keywords"]):
            literal_economic = re.search(r"\b(?:fee|rate|price|exchangeRate|feeBps)\w*\s*=\s*(?:[0-9]+(?:\.[0-9]+)?|(?:0x|0X)[0-9a-fA-F]+)", body, re.I)
            configurable_read = re.search(r"\b(?:config|settings|oracle|registry|governance|storage)\w*", body, re.I)
            if literal_economic and not configurable_read:
                results.append(_result(
                    "ECONOMIC-001",
                    _pattern("ECONOMIC-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["An economic parameter is assigned from a literal inside a state-changing path without an obvious configuration/oracle read."],
                    _pattern("ECONOMIC-001")["logic"],
                    "Check whether the hardcoded value is intended to be immutable and compare it with the external protocol's current parameter.",
                    _pattern("ECONOMIC-001")["provenance"],
                ))

        # Zero-address configuration check.
        if _sensitive_name(name, _pattern("ZEROADDR-001")["keywords"]) and re.search(r"\baddress\s*\(\s*0\s*\)", body, re.I) is None:
            address_params = [
                p for p in list((_abi_function(model, name) or {}).get("inputs") or [])
                if core._canonical_type(p) == "address"
            ]
            if address_params and re.search(r"\b(?:token|owner|admin|router|oracle|recipient|receiver|treasury|registry|authority)\w*\s*(?:=|\+=|-=)", body, re.I):
                results.append(_result(
                    "ZEROADDR-001",
                    _pattern("ZEROADDR-001")["title"],
                    model,
                    name,
                    source,
                    line,
                    ["An address parameter reaches a configuration/state-write path, but the function contains no obvious zero-address guard."],
                    _pattern("ZEROADDR-001")["logic"],
                    "Probe address(0) and verify whether the dependency becomes unusable or whether zero is an intentional sentinel.",
                    _pattern("ZEROADDR-001")["provenance"],
                ))

        # Deadline / expiry boundary.
        if re.search(r"\b(?:deadline|expiry|expiration|validUntil)\b", body, re.I):
            results.append(_result(
                "TIME-001",
                _pattern("TIME-001")["title"],
                model,
                name,
                source,
                line,
                ["A time-bounded parameter or state variable is used in this function."],
                _pattern("TIME-001")["logic"],
                "Replay with a deadline/expiry just before the current block timestamp and verify the exact revert boundary.",
                _pattern("TIME-001")["provenance"],
            ))

    return results


def scan_project(root: Path, models: list[core.ContractModel]) -> list[PatternObservation]:
    """Scan application models only; dependency artifacts stay out of the signal set."""
    results: list[PatternObservation] = []
    for model in models:
        if model.kind in {"interface", "library", "abstract"}:
            continue
        name = model.name.lower()
        if any(token in name for token in ("mock", "test", "erc20", "token")):
            continue
        results.extend(scan_model(root, model))
    return results[:60]


def _function_inputs(model: core.ContractModel, fn: dict[str, Any]) -> list[dict[str, Any]]:
    return list(fn.get("inputs") or [])


def _build_replay_stories(
    config: dict[str, Any],
    actors: list[core.Actor],
    targets: list[tuple[str, str, core.ContractModel]],
    rng_seed: int,
    root: Path | None = None,
) -> list[core.WalkthroughStory]:
    stories: list[core.WalkthroughStory] = []
    observed = core._merge_protocol_observations(
        config.get("_walkthrough_observed") or {},
        config=config,
    )

    for _label, address, model in targets:
        for fn in core._adversarial_functions(model):
            name = str(fn.get("name") or "")
            if not _sensitive_name(name, _pattern("REPLAY-001")["keywords"]):
                continue
            if not actors:
                continue

            # Replay must start from a state in which the target action is actually
            # executable. Reuse Lowkey's normal lifecycle planner rather than
            # inventing a second, protocol-specific setup engine.
            actor = actors[2] if len(actors) > 2 else actors[0]
            replay_actors = [actor, actor, actor]
            planned = core.plan_workflow(
                model,
                replay_actors,
                address,
                0,
                24,
                observed,
                root=root,
            )
            target_index = next(
                (
                    index for index, step in enumerate(planned)
                    if str(step.function or "").split("(", 1)[0].lower() == name.lower()
                ),
                None,
            )

            if target_index is None:
                stories.append(core.WalkthroughStory(
                    story_id=f"RP-{len(stories)+1:02d}",
                    title=f"Replay probe: {model.name}.{name}",
                    goal="Does the same economic action pay again when repeated by the same actor?",
                    actions=[],
                    signal="BLOCKED",
                    evidence=[
                        "Lowkey could not derive a valid lifecycle setup that reaches the target payout action.",
                    ],
                ))
                if len(stories) >= 4:
                    return stories
                continue

            setup_steps = planned[:target_index]
            if not setup_steps:
                stories.append(core.WalkthroughStory(
                    story_id=f"RP-{len(stories)+1:02d}",
                    title=f"Replay probe: {model.name}.{name}",
                    goal="Does the same economic action pay again when repeated by the same actor?",
                    actions=[],
                    signal="BLOCKED",
                    evidence=[
                        "No source-guided setup action was available before the payout path; Lowkey refused to test an invalid starting state.",
                    ],
                ))
                if len(stories) >= 4:
                    return stories
                continue

            actions: list[dict[str, Any]] = []
            for setup in setup_steps[-4:]:
                setup_fn = next(
                    (
                        item for item in model.abi
                        if item.get("type") == "function"
                        and core._signature(item) == setup.function
                    ),
                    None,
                )
                value = int(setup.value_wei or 0)
                if setup_fn and setup_fn.get("stateMutability") == "payable" and value <= 0:
                    # Economic setup needs a nonzero payment to create a real entitlement.
                    # One wei is deliberately the smallest possible local amount.
                    value = 1
                actions.append({
                    "kind": "call",
                    "actor": actor.name,
                    "contract": setup.contract,
                    "address": setup.address,
                    "function": setup.function,
                    "args": list(setup.args),
                    "value": value,
                    "reason": "replay setup: establish the target action's source-guided preconditions",
                })

            target_signature = core._signature(fn)
            target_action = {
                "kind": "call",
                "actor": actor.name,
                "contract": model.name,
                "address": address,
                "function": target_signature,
                "args": list(
                    core._random_sol_value(
                        param,
                        replay_actors,
                        address,
                        __import__("random").Random(rng_seed),
                        observed,
                        model,
                        name,
                    )
                    for param in _function_inputs(model, fn)
                ),
                "value": 0,
                "reason": "real-world pattern probe: execute the same payout path twice",
            }
            setup_value = sum(int(action.get("value") or 0) for action in actions)
            payout_value = max(1, setup_value)
            actions.append({
                "kind": "fund_target",
                "actor": actor.name,
                "contract": "AnvilLab",
                "address": address,
                "amount": max(2, payout_value * 2),
                "reason": "replay harness: provision enough native reserve for two payout attempts",
            })
            actions.extend([dict(target_action), dict(target_action)])
            stories.append(core.WalkthroughStory(
                story_id=f"RP-{len(stories)+1:02d}",
                title=f"Replay probe: {model.name}.{name}",
                goal="Does the same economic action pay again when repeated by the same actor?",
                actions=actions,
                execution_scope="persistent_story",
                reset_between_actions=False,
            ))
            if len(stories) >= 4:
                return stories
    return stories


def _observation_step_for_story(story: core.WalkthroughStory, steps: list[core.Step]) -> core.Step | None:
    if not steps:
        return None
    if story.story_id.startswith("RP-"):
        # Replay stories contain setup + repeated target calls. The source
        # observation belongs to the repeated payout target, not setup.
        return steps[-2] if len(steps) >= 2 else steps[-1]
    return steps[0]


def assess_replay_story(
    story: core.WalkthroughStory,
    steps: list[core.Step],
    actors: list[core.Actor],
) -> None:
    if story.signal == "BLOCKED" and not story.actions:
        return

    # Replay requires a persistent state sequence. Randomized probes restore
    # state after each call and therefore cannot prove replay by repeatability.
    if (
        str(getattr(story, "execution_scope", "")) != "persistent_story"
        or bool(getattr(story, "reset_between_actions", True))
        or any(
            str(getattr(step, "observation_scope", "")) == "isolated_probe"
            for step in steps[-2:]
        )
    ):
        story.signal = "BLOCKED"
        story.evidence = [
            "Replay evidence requires one persistent state sequence; this execution restored state between actions.",
            "Repeated success across isolated snapshots is repeatability, not replay evidence.",
        ]
        return

    if len(steps) < 2:
        story.signal = "BLOCKED"
        story.evidence = ["Replay probe did not produce the two repeated payout actions."]
        return

    setup_steps = steps[:-2]
    if any(step.status != "success" for step in setup_steps):
        story.signal = "BLOCKED"
        failed = next(step for step in setup_steps if step.status != "success")
        story.evidence = [
            "The replay setup did not establish the target action's preconditions.",
            f"setup failed at {failed.function}: {failed.error_reason or failed.error or 'unknown failure'}",
        ]
        return

    first, second = steps[-2], steps[-1]

    same_action = (
        first.actor == second.actor
        and first.contract == second.contract
        and first.address.lower() == second.address.lower()
        and first.function == second.function
        and first.args == second.args
        and int(first.value_wei or 0) == int(second.value_wei or 0)
    )
    if not same_action:
        story.signal = "BLOCKED"
        story.evidence = [
            "The two final calls were not the same actor/action/value on the same target, so replay was not isolated.",
        ]
        return

    if first.status != "success":
        story.signal = "NOT_TRIGGERED"
        story.evidence = ["The first payout call was rejected, so a replay condition was not reached."]
        return
    if second.status != "success":
        story.signal = "NOT_REPRODUCED"
        story.evidence = ["The first payout call succeeded but the repeated call was rejected."]
        return

    actor = next((a for a in actors if a.name == second.actor), None)
    token_gain = 0
    native_gain = 0
    trace_native_gain = 0
    if actor:
        key = actor.address.lower()
        token_gain = second.token_balance_after.get(key, 0) - second.token_balance_before.get(key, 0)
        # Net wallet balance includes gas. Prefer the protocol's traced native
        # transfer to the actor so transaction fees cannot hide a real payout.
        for edge in second.execution_edges or []:
            if (
                int(edge.get("depth", 0) or 0) > 0
                and str(edge.get("to_address") or "").lower() == key
                and int(edge.get("value_wei", 0) or 0) > 0
            ):
                trace_native_gain += int(edge.get("value_wei", 0) or 0)

        # Some local nodes/tooling provide a textual cast-trace fallback even
        # when the structured call tree cannot be decoded. Parse only the
        # recipient + positive value needed for this replay classification.
        if trace_native_gain == 0:
            for line in second.trace_edges or []:
                match = re.search(
                    r"\b(?:CALL|CALLCODE|DELEGATECALL)\b[^\\n]*\bto=(0x[0-9a-fA-F]{40})\b[^\\n]*\bvalue=(\\d+)\\s+wei\\b",
                    str(line),
                    re.IGNORECASE,
                )
                if match and match.group(1).lower() == key:
                    trace_native_gain += int(match.group(2))

        native_gain = max(
            second.balance_after.get(key, 0) - second.balance_before.get(key, 0),
            trace_native_gain,
        )

    if token_gain > 0 or native_gain > 0:
        story.signal = "CONFIRMED"
        gain = f"{token_gain / 10**18:.4f} token units" if token_gain > 0 else f"{native_gain} wei"
        story.evidence = [
            "the same payout call succeeded twice after a valid setup",
            f"the second payout call produced a positive protocol-value delta: {gain}",
        ]
    else:
        story.signal = "REVIEW"
        story.evidence = [
            "the same payout call succeeded twice after a valid setup, but this run did not prove a positive payout/state delta on the actor",
            "the function may intentionally support repeated partial withdrawals",
        ]

def _render_observation(obs: PatternObservation) -> list[str]:
    icon = {
        "CONFIRMED": "🚨",
        "CANDIDATE": "⚠️",
        "REVIEW": "🟨",
        "NOT_TRIGGERED": "·",
        "NOT_REPRODUCED": "·",
        "BLOCKED": "🔧",
    }.get(obs.status, "❓")
    where = f"{obs.source}:{obs.line}" if obs.line else obs.source
    lines = [
        f"  {icon} {obs.pattern_id}  {obs.title}",
        f"     WHERE    {obs.contract}.{obs.function}" if obs.function else f"     WHERE    {obs.contract}",
        f"     EVIDENCE {obs.evidence[0]}" if obs.evidence else "     EVIDENCE source pattern matched",
        f"     LOGIC    {obs.logic}",
        f"     NEXT     {obs.next_step}",
        f"     SEEN IN  {', '.join(obs.provenance[:3])}" if obs.provenance else "     SEEN IN  public adjudicated security reports",
        f"     SOURCE   {where}",
    ]
    return lines


def render_summary(observations: list[PatternObservation]) -> list[str]:
    if not observations:
        return [
            "",
            "  SECURITY PATTERN REVIEW",
            "    No recurring source patterns matched the current application models.",
            "",
        ]

    counts: dict[str, int] = {}
    groups: dict[str, list[PatternObservation]] = {}
    for item in observations:
        counts[item.status] = counts.get(item.status, 0) + 1
        groups.setdefault(item.pattern_id, []).append(item)

    static_candidates = counts.get("CANDIDATE", 0)
    live_upgraded = counts.get("CONFIRMED", 0) + counts.get("REVIEW", 0)
    lines = [
        "",
        "  SECURITY PATTERN REVIEW",
        f"    {len(observations)} source-pattern match(es) across {len({item.contract for item in observations})} contracts",
        "",
        f"    🚨 CONFIRMED         {counts.get('CONFIRMED', 0)}  concrete security condition reproduced",
        f"    🟨 NEEDS REVIEW      {counts.get('REVIEW', 0)}  live behavior needs manual verification",
        f"    ⚠️ STATIC CANDIDATES  {static_candidates}  source patterns awaiting live verification",
        f"    🟦 LIVE-UPGRADED     {live_upgraded}  source matches exercised by stateful probes",
        "",
    ]

    confirmed_or_review = [
        item for item in observations
        if item.status in {"CONFIRMED", "REVIEW"}
    ]
    if confirmed_or_review:
        lines.append("  INVESTIGATE FIRST")
        for item in confirmed_or_review[:8]:
            icon = "🚨" if item.status == "CONFIRMED" else "🟨"
            location = f"{item.contract}.{item.function}" if item.function else item.contract
            lines.append(f"    {icon} {item.pattern_id}  {location}")
            if item.evidence:
                lines.append(f"       {item.evidence[0]}")
            if item.next_step:
                lines.append(f"       NEXT: {item.next_step}")
        lines.append("")
    else:
        lines += [
            "  LIVE VERIFICATION",
            "    No finding pattern was confirmed by the isolated runtime probes.",
            "    The remaining signals are source-level candidates for manual review.",
            "",
        ]

    lines.append("  SOURCE PATTERN MATCHES")
    for pattern_id, items in sorted(groups.items()):
        catalog = _pattern(pattern_id)
        title = str(catalog.get("title") or pattern_id)
        candidate_items = [item for item in items if item.status == "CANDIDATE"]
        live_items = [item for item in items if item.status != "CANDIDATE"]
        shown = candidate_items[:6]
        lines.append(
            f"    {pattern_id}  {title}  —  {len(items)} match"
            + ("" if len(items) == 1 else "es")
        )
        for item in shown:
            location = f"{item.contract}.{item.function}" if item.function else item.contract
            suffix = f"  ({item.source}:{item.line})" if item.line else f"  ({item.source})"
            lines.append(f"       • {location}{suffix}")
        if len(candidate_items) > len(shown):
            lines.append(f"       • +{len(candidate_items) - len(shown)} more locations saved to evidence")
        if live_items:
            lines.append(f"       • {len(live_items)} location(s) upgraded by live probing")

    lines += [
        "",
        "  HOW TO READ IT",
        "    STATIC MATCH = a source pattern worth checking, not a vulnerability verdict.",
        "    NEEDS REVIEW  = live behavior matched the pattern strongly enough for manual verification.",
        "    CONFIRMED      = the local probe reproduced the pattern's concrete security condition.",
        "    Sources are public audit/bounty research used to choose recurring patterns to test.",
        "",
        "    Full evidence: .audit/walkthrough/test.json",
    ]
    return lines



def persist_security_patterns(
    root: Path,
    observations: list[PatternObservation],
) -> None:
    """Publish source/runtime pattern observations into the shared audit ledger."""
    if audit_context is None:
        return
    for obs in observations:
        verification = str(obs.status or "CANDIDATE").upper()
        mode = "source+stateful" if verification in {"CONFIRMED", "REVIEW"} else "source"
        audit_context.add_security_pattern(
            root,
            pattern_id=str(obs.pattern_id),
            title=str(obs.title),
            contract=str(obs.contract),
            function=str(obs.function or ""),
            file=str(obs.source or ""),
            line=obs.line,
            logic=str(obs.logic or ""),
            description=(obs.evidence[0] if obs.evidence else "Source pattern matched."),
            next_step=str(obs.next_step or ""),
            provenance=list(obs.provenance or []),
            verification_status=verification,
            verification_evidence=list(obs.evidence or []),
            evidence_mode=mode,
        )


def _cast_read_simple(rpc: str, address: str, signature: str, args: list[Any] | None = None) -> Any:
    if not core.is_address(address):
        return None
    command = ["cast", "call", address, signature]
    command.extend(core._cli_arg(value) for value in (args or []))
    command += ["--rpc-url", rpc]
    code, out, err = core._cmd(command, timeout=8)
    if code != 0:
        return None
    raw = " ".join((out or err or "").strip().split()).strip()
    if not raw:
        return None
    raw = raw.splitlines()[-1].strip()
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def _build_initializer_stories(
    config: dict[str, Any],
    actors: list[core.Actor],
    targets: list[tuple[str, str, core.ContractModel]],
    seed: int,
) -> list[core.WalkthroughStory]:
    if len(actors) < 3:
        return []
    rng = __import__("random").Random(seed + 101)
    observed = core._merge_protocol_observations(config.get("_walkthrough_observed") or {}, config=config)
    stories: list[core.WalkthroughStory] = []
    attacker = actors[2]
    for _label, address, model in targets:
        for fn in core._adversarial_functions(model):
            name = str(fn.get("name") or "")
            if not name.lower().startswith(("initialize", "reinitialize")):
                continue
            args = []
            for param in list(fn.get("inputs") or []):
                pname = str(param.get("name") or "").lower()
                if core._canonical_type(param) == "address" and any(k in pname for k in ("owner", "admin", "authority", "guardian")):
                    args.append(attacker.address)
                else:
                    args.append(core._random_sol_value(param, actors, address, rng, observed, model, name))
            stories.append(core.WalkthroughStory(
                story_id=f"IN-{len(stories)+1:02d}",
                title=f"Initializer probe: {model.name}.{name}",
                goal="Can an unprivileged actor initialize or reinitialize an already configured instance?",
                actions=[{
                    "kind": "call",
                    "actor": attacker.name,
                    "contract": model.name,
                    "address": address,
                    "function": core._signature(fn),
                    "args": args,
                    "value": 0,
                    "reason": "real-world pattern probe: initializer takeover",
                }],
            ))
            if len(stories) >= 2:
                return stories
    return stories


def _build_deadline_stories(
    config: dict[str, Any],
    actors: list[core.Actor],
    targets: list[tuple[str, str, core.ContractModel]],
    seed: int,
    now: int,
) -> list[core.WalkthroughStory]:
    if len(actors) < 1:
        return []
    rng = __import__("random").Random(seed + 202)
    observed = core._merge_protocol_observations(config.get("_walkthrough_observed") or {}, config=config)
    stories: list[core.WalkthroughStory] = []
    actor = actors[2] if len(actors) > 2 else actors[0]
    for _label, address, model in targets:
        for fn in core._adversarial_functions(model):
            name = str(fn.get("name") or "")
            params = list(fn.get("inputs") or [])
            deadline_index = next((i for i,p in enumerate(params) if re.search(r"\b(?:deadline|expiry|expiration|validuntil)\b", str(p.get("name") or ""), re.I)), None)
            if deadline_index is None:
                continue
            args = []
            for i, param in enumerate(params):
                if i == deadline_index and core._canonical_type(param).startswith(("uint", "int")):
                    args.append(max(0, int(now) - 1))
                else:
                    args.append(core._random_sol_value(param, actors, address, rng, observed, model, name))
            stories.append(core.WalkthroughStory(
                story_id=f"DL-{len(stories)+1:02d}",
                title=f"Expired-input probe: {model.name}.{name}",
                goal="Does a call with an already expired deadline get rejected at execution time?",
                actions=[{
                    "kind": "call",
                    "actor": actor.name,
                    "contract": model.name,
                    "address": address,
                    "function": core._signature(fn),
                    "args": args,
                    "value": 0,
                    "reason": "real-world pattern probe: expired deadline boundary",
                }],
            ))
            if len(stories) >= 2:
                return stories
    return stories


def _build_zero_address_stories(
    config: dict[str, Any],
    actors: list[core.Actor],
    targets: list[tuple[str, str, core.ContractModel]],
    seed: int,
) -> list[core.WalkthroughStory]:
    if not actors:
        return []
    rng = __import__("random").Random(seed + 303)
    observed = core._merge_protocol_observations(config.get("_walkthrough_observed") or {}, config=config)
    stories: list[core.WalkthroughStory] = []
    actor = actors[2] if len(actors) > 2 else actors[0]
    for _label, address, model in targets:
        for fn in core._adversarial_functions(model):
            name = str(fn.get("name") or "")
            if not _sensitive_name(name, _pattern("ZEROADDR-001")["keywords"]):
                continue
            params = list(fn.get("inputs") or [])
            address_index = next(
                (i for i,p in enumerate(params)
                 if core._canonical_type(p) == "address"
                 and any(k in str(p.get("name") or "").lower() for k in ("owner", "admin", "token", "router", "oracle", "recipient", "receiver", "treasury", "registry"))),
                None,
            )
            if address_index is None:
                continue
            args=[]
            for i,param in enumerate(params):
                if i == address_index:
                    args.append("0x" + "00" * 20)
                else:
                    args.append(core._random_sol_value(param, actors, address, rng, observed, model, name))
            stories.append(core.WalkthroughStory(
                story_id=f"ZA-{len(stories)+1:02d}",
                title=f"Zero-address probe: {model.name}.{name}",
                goal="Does a configuration path accept address(0) where a real dependency is expected?",
                actions=[{
                    "kind": "call", "actor": actor.name, "contract": model.name,
                    "address": address, "function": core._signature(fn), "args": args,
                    "value": 0, "reason": "real-world pattern probe: zero-address boundary",
                }],
            ))
            if len(stories) >= 2:
                return stories
    return stories


def assess_zero_address_story(story: core.WalkthroughStory, steps: list[core.Step]) -> None:
    if not steps or steps[0].status != "success":
        story.signal = "NOT_REPRODUCED"
        story.evidence = ["The zero-address call was rejected or could not execute."]
        return
    story.signal = "REVIEW"
    story.evidence = ["the configuration call accepted address(0)", "verify whether zero is an intentional sentinel or leaves the dependency unusable"]


def assess_initializer_story(
    story: core.WalkthroughStory,
    steps: list[core.Step],
    rpc: str,
    actors: list[core.Actor],
) -> None:
    if not steps or steps[0].status != "success":
        story.signal = "NOT_TRIGGERED" if steps else "BLOCKED"
        story.evidence = ["The initializer call was not accepted on the live target."]
        return
    attacker = actors[2] if len(actors) > 2 else actors[0]
    owner = _cast_read_simple(rpc, steps[0].address, "owner()(address)")
    if isinstance(owner, str) and owner.lower() == attacker.address.lower():
        story.signal = "CONFIRMED"
        story.evidence = ["an unprivileged actor called the initializer successfully", "owner() now resolves to that attacker"]
    else:
        story.signal = "REVIEW"
        story.evidence = ["initializer succeeded, but ownership takeover was not proven by owner()"]


def assess_deadline_story(story: core.WalkthroughStory, steps: list[core.Step]) -> None:
    if not steps or steps[0].status != "success":
        story.signal = "NOT_REPRODUCED"
        story.evidence = ["The expired-input call was rejected or could not execute."]
        return
    story.signal = "REVIEW"
    story.evidence = ["the call accepted an input that was one second before the observed block timestamp", "verify whether this function intentionally permits expired inputs"]


def run(
    root: Path,
    config: dict[str, Any],
    host: Any,
    rpc: str,
    actors: list[core.Actor],
    models: list[core.ContractModel],
    targets: list[tuple[str, str, core.ContractModel]],
    seed: int,
) -> tuple[list[PatternObservation], list[core.WalkthroughStory], list[core.Step]]:
    """Run source patterns plus a small set of isolated live probes."""
    observations = scan_project(root, models)
    replay_stories = _build_replay_stories(config, actors, targets, seed, root=root)[:3]
    initializer_stories = _build_initializer_stories(config, actors, targets, seed)[:1]
    deadline_stories = _build_deadline_stories(config, actors, targets, seed, core._block_timestamp(rpc))[:2]
    zero_address_stories = _build_zero_address_stories(config, actors, targets, seed)[:2]
    stories = replay_stories + initializer_stories + deadline_stories + zero_address_stories

    live_steps: list[core.Step] = []
    for story in stories:
        snapshot = core._rpc_snapshot(rpc)
        if snapshot is None:
            story.signal = "BLOCKED"
            story.evidence = ["Anvil could not snapshot the pattern baseline."]
            continue
        story_steps: list[core.Step] = []
        for action in story.actions:
            step = core._execute_stateful_story_action(
                root, config, host, rpc, actors, action, len(story_steps) + 1, models
            )
            story_steps.append(step)
            live_steps.append(step)
        if story.story_id.startswith("RP-"):
            assess_replay_story(story, story_steps, actors)
        elif story.story_id.startswith("IN-"):
            assess_initializer_story(story, story_steps, rpc, actors)
        elif story.story_id.startswith("ZA-"):
            assess_zero_address_story(story, story_steps)
        else:
            assess_deadline_story(story, story_steps)
        family_id = (
            "REPLAY-001" if story.story_id.startswith("RP-")
            else "INIT-001" if story.story_id.startswith("IN-")
            else "ZEROADDR-001" if story.story_id.startswith("ZA-")
            else "TIME-001"
        )
        observation_step = _observation_step_for_story(story, story_steps)
        if observation_step:
            for obs in observations:
                obs_name = str(obs.function or "").split("(", 1)[0]
                step_name = str(observation_step.function or "").split("(", 1)[0]
                if obs.pattern_id == family_id and obs.contract == observation_step.contract and obs_name == step_name:
                    if story.signal in {"CONFIRMED", "REVIEW"}:
                        obs.status = story.signal
                    if story.evidence:
                        obs.evidence = story.evidence[:]
        if not core._rpc_revert(rpc, snapshot):
            story.signal = "BLOCKED"
            story.evidence = ["Anvil could not restore the pattern snapshot."]
            break
    persist_security_patterns(root, observations)
    return observations, stories, live_steps
