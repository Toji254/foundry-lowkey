"""Cross-language adversarial finding playbook for Lowkey.

The playbook distills recurring vulnerability *logic* from public audit and
bug-bounty material. It is intentionally framework/language aware and does not
copy individual reports or turn a pattern match into a vulnerability verdict.

A pattern has:
  - what invariant/assumption can fail,
  - what source/runtime clues make it relevant,
  - what native backend can exercise it,
  - whether Lowkey can presently execute a generic experiment or needs a
    protocol-specific harness.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class FindingPattern:
    id: str
    family: str
    title: str
    logic: str
    anchors: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("solidity", "vyper", "cairo", "move", "rust")
    executable: str = "hypothesis"  # executable | partial | hypothesis


# The catalog is recurrence-driven.  These are attack hypotheses, not verdicts.
FINDING_PATTERNS: tuple[FindingPattern, ...] = (
    FindingPattern(
        "INPUT-001", "boundary", "Missing input validation",
        "An attacker-controlled value reaches a security/economic decision without the constraint the protocol's invariant requires.",
        ("set", "configure", "register", "deposit", "mint", "borrow", "liquidate", "execute"),
        executable="partial",
    ),
    FindingPattern(
        "CALC-001", "accounting", "Incorrect calculation / unit mismatch",
        "A calculation uses the wrong scale, operand, decimal basis, sign, or order and produces more entitlement than intended.",
        ("amount", "shares", "price", "rate", "fee", "reward", "exchange"),
        executable="partial",
    ),
    FindingPattern(
        "ROUND-001", "accounting", "Rounding / zero-output extraction",
        "Integer rounding can turn a positive input into zero output, or bias repeated operations so value accumulates to the attacker.",
        ("deposit", "mint", "redeem", "stake", "convert", "preview", "shares"),
        executable="partial",
    ),
    FindingPattern(
        "REENT-001", "reentrancy", "State-before-interaction / callback reentrancy",
        "Control leaves the contract before the state authorizing a payout or state transition is consumed.",
        ("call", "transfer", "send", "safeTransfer", "raw_call", "callback", "hook"),
        executable="executable",
    ),
    FindingPattern(
        "READONLY-001", "callback", "Read-only reentrancy",
        "A callback can observe a transiently inconsistent price/share/debt value and consume it from another path.",
        ("price", "quote", "rate", "balance", "total", "share", "preview"),
        executable="hypothesis",
    ),
    FindingPattern(
        "AUTH-001", "access", "Weak access control",
        "A state transition intended for a privileged actor lacks a reliable authorization boundary.",
        ("owner", "admin", "guardian", "pause", "upgrade", "grant", "revoke", "rescue", "set"),
        executable="partial",
    ),
    FindingPattern(
        "AUTH-002", "access", "tx.origin authorization",
        "An intermediate contract can satisfy an origin check while changing the actual caller context.",
        ("tx.origin",),
        executable="hypothesis",
    ),
    FindingPattern(
        "REPLAY-001", "replay", "Replayable entitlement",
        "A one-shot action can be repeated without consuming the nonce, balance, claim flag, or other entitlement state.",
        ("claim", "withdraw", "redeem", "release", "payout", "refund", "nonce"),
        executable="partial",
    ),
    FindingPattern(
        "SIG-001", "signature", "Weak signature binding / replay protection",
        "Signed actions need nonce and context binding such as domain, chain, contract, signer, or expiry.",
        ("permit", "signature", "sig", "recover", "verify", "authorization", "nonce"),
        executable="hypothesis",
    ),
    FindingPattern(
        "ORACLE-001", "oracle", "Stale / invalid oracle data",
        "A numerically valid oracle response can still be economically invalid when freshness, round, or sequencer assumptions are unchecked.",
        ("latestRoundData", "getRoundData", "oracle", "price", "updatedAt", "roundId"),
        executable="hypothesis",
    ),
    FindingPattern(
        "ORACLE-002", "oracle", "Spot-price / shallow-liquidity manipulation",
        "A protocol consumes a manipulable spot price instead of a manipulation-resistant reference.",
        ("slot0", "getReserves", "spot", "sqrtPrice", "reserve", "price"),
        executable="hypothesis",
    ),
    FindingPattern(
        "FRONT-001", "economic", "Transaction-order dependence / frontrunning",
        "A profitable outcome depends on execution order and can be moved by a preceding attacker transaction.",
        ("commit", "reveal", "bid", "swap", "deposit", "claim", "liquidate", "deadline"),
        executable="hypothesis",
    ),
    FindingPattern(
        "DOS-001", "dos", "Unbounded attacker-influenced work",
        "An attacker can grow the amount of work required by a critical path until execution becomes impractical.",
        ("for", "while", "claim", "withdraw", "settle", "liquidate", "harvest"),
        executable="hypothesis",
    ),
    FindingPattern(
        "DOS-002", "dos", "Griefing via forced revert / unusable recipient",
        "A user-controlled recipient or callback can make a required path revert and deny service to other users.",
        ("receiver", "recipient", "callback", "hook", "transfer", "send"),
        executable="hypothesis",
    ),
    FindingPattern(
        "TOKEN-001", "erc20", "Unchecked token transfer result",
        "Accounting assumes a token transfer succeeded even when a token can return false or otherwise behave non-standardly.",
        ("transfer", "transferFrom", "approve", "safeTransfer", "SafeERC20"),
        executable="hypothesis",
    ),
    FindingPattern(
        "TOKEN-002", "erc20", "Fee-on-transfer mismatch",
        "The contract credits the requested amount instead of measuring the amount actually received.",
        ("transferFrom", "deposit", "stake", "fund", "balanceOf"),
        executable="hypothesis",
    ),
    FindingPattern(
        "TOKEN-003", "erc20", "Rebasing / balance-drift assumption",
        "The accounting model assumes token balances are stable while the asset can change balances independently.",
        ("balanceOf", "shares", "rebasing", "index", "yield"),
        executable="hypothesis",
    ),
    FindingPattern(
        "CALL-001", "callback", "Arbitrary external call / delegatecall",
        "A user-controlled target plus calldata needs an explicit authorization and trust boundary.",
        ("call", "delegatecall", "multicall", "execute", "target", "to"),
        executable="hypothesis",
    ),
    FindingPattern(
        "CALL-002", "callback", "Callback recipient is attacker-controlled",
        "A recipient contract can execute attacker code during a value/token/NFT transfer.",
        ("safeTransfer", "safeTransferFrom", "receiver", "callback", "hook", "raw_call"),
        executable="partial",
    ),
    FindingPattern(
        "INIT-001", "upgrade", "Uninitialized / repeat-initializable contract",
        "Initialization can be performed or repeated by an attacker after deployment state is expected to be fixed.",
        ("initialize", "initializer", "reinitialize", "setup", "proxy"),
        executable="partial",
    ),
    FindingPattern(
        "PROXY-001", "proxy", "Proxy / implementation authorization mismatch",
        "Proxy, implementation, admin, and delegatecall storage can disagree about the actor authorized to change logic.",
        ("proxy", "implementation", "delegatecall", "upgradeTo", "beacon", "admin"),
        executable="hypothesis",
    ),
    FindingPattern(
        "PROXY-002", "proxy", "Implementation storage collision / slot corruption",
        "Two execution contexts make incompatible storage-layout assumptions and overwrite security-critical state.",
        ("slot", "storage", "delegatecall", "implementation", "assembly"),
        executable="hypothesis",
    ),
    FindingPattern(
        "GOV-001", "economic", "Governance / quorum bypass",
        "Voting or proposal execution can proceed without the required participation, delay, or authorization.",
        ("vote", "quorum", "proposal", "delegate", "timelock", "execute"),
        executable="hypothesis",
    ),
    FindingPattern(
        "FLASH-001", "economic", "Temporary-capital invariant break",
        "A protocol accepts a temporary balance/price/state increase and fails to enforce the invariant after the attacker unwinds it.",
        ("flashLoan", "borrow", "repay", "collateral", "reserve", "liquidate", "swap"),
        executable="hypothesis",
    ),
    FindingPattern(
        "VAULT-001", "accounting", "Share inflation / donation attack",
        "Direct asset donations or first-depositor edge states can skew the asset-to-share ratio for later users.",
        ("deposit", "mint", "withdraw", "redeem", "shares", "totalAssets", "preview"),
        executable="hypothesis",
    ),
    FindingPattern(
        "LIQ-001", "economic", "Liquidation / health-factor boundary abuse",
        "Rounding, stale prices, ordering, or inconsistent debt/collateral accounting can make an unsafe position appear safe or vice versa.",
        ("liquidate", "health", "collateral", "debt", "ltv", "threshold"),
        executable="hypothesis",
    ),
    FindingPattern(
        "BRIDGE-001", "signature", "Cross-domain message replay / weak binding",
        "A bridge message must bind chain/domain, source, nonce/message id, and destination strongly enough to prevent reuse.",
        ("message", "nonce", "domain", "sourceChain", "destination", "relay", "bridge"),
        executable="hypothesis",
    ),
    FindingPattern(
        "MERKLE-001", "replay", "Claim proof / leaf binding weakness",
        "A proof must bind all economically relevant leaf fields and consume the entitlement exactly once.",
        ("merkle", "proof", "claim", "leaf", "index"),
        executable="hypothesis",
    ),
    FindingPattern(
        "RAND-001", "time", "Predictable randomness",
        "Block-derived values are observable or influenceable enough to make valuable random outcomes predictable.",
        ("random", "winner", "lottery", "draw", "roll", "prevrandao", "timestamp", "blockhash"),
        executable="hypothesis",
    ),
    FindingPattern(
        "TIME-001", "time", "Deadline / expiry boundary failure",
        "An expired or not-yet-valid action must be rejected at the point where it has economic effect.",
        ("deadline", "expiry", "expiration", "validUntil", "epoch"),
        executable="partial",
    ),
    FindingPattern(
        "ETH-001", "accounting", "Unexpected native-asset flow",
        "The contract's native balance can change in ways its internal accounting or withdrawal rules do not model.",
        ("call", "transfer", "send", "selfdestruct", "coinbase", "deposit", "withdraw"),
        executable="partial",
    ),
    FindingPattern(
        "STORAGE-001", "storage", "State-slot / mapping corruption",
        "An attacker-controlled path changes state outside the intended ownership or index domain.",
        ("mapping", "array", "slot", "storage", "assembly", "set"),
        executable="hypothesis",
    ),
    FindingPattern(
        "VALIDATE-001", "boundary", "Paired-variable validation mismatch",
        "A check constrains one side of a paired relationship while another field used later remains weakly constrained.",
        ("token0", "token1", "currency0", "currency1", "long", "short"),
        executable="hypothesis",
    ),
)


FAMILY_ALIASES = {
    "input-validation": "boundary",
    "validation": "boundary",
    "incorrect-calculation": "accounting",
    "rounding": "accounting",
    "front-running": "economic",
    "frontrunning": "economic",
    "governance": "economic",
    "flash-loan": "economic",
    "token": "erc20",
    "erc4626": "accounting",
    "bridge": "signature",
    "message-replay": "signature",
}


def patterns_for(
    *,
    project: dict[str, Any] | None = None,
    function_name: str = "",
    source_text: str = "",
) -> list[FindingPattern]:
    text = " ".join(
        str(x or "").lower()
        for x in (
            function_name,
            source_text[:12000],
            " ".join(str(k) for k in (project or {}).get("languages", {}).keys()),
            " ".join(str(k) for k in (project or {}).get("stacks", [])),
        )
    )
    ranked: list[tuple[int, FindingPattern]] = []
    for item in FINDING_PATTERNS:
        score = 0
        for anchor in item.anchors:
            if anchor.lower() in text:
                score += 2
        if not item.anchors:
            score += 1
        languages = set(str(x).lower() for x in item.languages)
        project_languages = set(str(x).lower() for x in ((project or {}).get("languages") or {}).keys())
        if project_languages & languages:
            score += 2
        if score:
            ranked.append((score, item))
    return [item for _score, item in sorted(ranked, key=lambda pair: (-pair[0], pair[1].id))]


def family_names(patterns: Iterable[FindingPattern]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in patterns:
        family = FAMILY_ALIASES.get(item.family, item.family)
        if family not in seen:
            seen.add(family)
            result.append(family)
    return result


def backend_for_project(info: dict[str, Any] | None) -> str:
    info = info or {}
    stacks = {str(x).lower() for x in (info.get("stacks") or [])}
    languages = {str(x).lower() for x in (info.get("languages") or {}).keys()}
    if stacks & {"foundry", "hardhat", "vyper"} or languages & {"solidity", "vyper", "huff", "yul"}:
        return "evm"
    if "cairo-starknet" in stacks or "cairo" in languages:
        return "cairo-starknet"
    if "solana-anchor" in stacks or "rust" in languages and "anchor" in " ".join(stacks):
        return "solana-anchor"
    if "move" in stacks or "move" in languages:
        return "move"
    return "generic"


def language_label(info: dict[str, Any] | None) -> str:
    info = info or {}
    languages = info.get("effective_languages") or info.get("languages") or {}
    if isinstance(languages, dict):
        return ", ".join(f"{k} ({v})" for k, v in languages.items()) or "unknown"
    return ", ".join(str(x) for x in languages) or "unknown"


def native_probe_commands(info: dict[str, Any] | None) -> list[list[str]]:
    info = info or {}
    native = info.get("native") or {}
    stacks = {str(x).lower() for x in (info.get("stacks") or [])}
    commands: list[list[str]] = []
    if "cairo-starknet" in stacks and native.get("snforge"):
        commands.append(["snforge", "test"])
    if "solana-anchor" in stacks and native.get("anchor"):
        commands.append(["anchor", "test"])
    if "move" in stacks:
        if native.get("sui"):
            commands.append(["sui", "move", "test"])
        if native.get("aptos"):
            commands.append(["aptos", "move", "test"])
    if not commands:
        if native.get("pytest"):
            commands.append(["pytest", "-q"])
        elif native.get("cargo"):
            commands.append(["cargo", "test"])
    return commands


def describe_pattern(pattern: FindingPattern) -> dict[str, Any]:
    data = asdict(pattern)
    data["family"] = FAMILY_ALIASES.get(pattern.family, pattern.family)
    return data


def catalog_summary(project: dict[str, Any] | None = None) -> dict[str, Any]:
    patterns = patterns_for(project=project)
    return {
        "total_patterns": len(FINDING_PATTERNS),
        "relevant_patterns": [describe_pattern(item) for item in patterns[:24]],
        "families": family_names(patterns),
    }
