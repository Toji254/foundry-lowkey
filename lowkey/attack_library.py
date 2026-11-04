#!/usr/bin/env python3
"""Read-only smart-contract and blockchain attack library for LowkeyCast."""

from __future__ import annotations

import difflib
import re
import sys
from collections import Counter
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

try:
    from .attack_catalog import ATTACKS, REFERENCE_SOURCES
except ImportError:
    from attack_catalog import ATTACKS, REFERENCE_SOURCES


VERSION = "0.1.0"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

HELP = """
LOWKEY // ATTACK LIBRARY
========================

Read-only security reference. No RPC, Anvil, target, project, or wallet access.

START:
  lk attack                         overview and learning path
  lk attack categories              all attack families
  lk attack list                    browse every catalogue entry
  lk attack search <words>          search names, concepts, and explanations
  lk attack show <id-or-name>       short reference card
  lk attack learn <id-or-name>      beginner-first detailed lesson
  lk attack lab <id-or-name>        local-only reproduction plan and example
  lk attack quiz <id-or-name>       check your understanding
  lk attack related <id-or-name>    related patterns and variants
  lk attack map [protocol-profile]  audit investigation checklist
  lk attack incidents [words]       documented historical examples
  lk attack sources                 external standards and research
  lk attack severity                severity scale and rating rules
  lk attack glossary                explain common audit words
  lk attack check                   validate catalogue integrity
  lk attack version                 show catalogue version and entry count

LIST FILTERS:
  lk attack list --severity High
  lk attack list --severity Critical --category "Oracle & market economics"
  lk attack list --all

PROTOCOL MAP PROFILES:
  general, defi, lending, dex, vault, staking, bridge, governance,
  nft, wallet, account-abstraction, solana, move, cosmos, privacy

EXAMPLES:
  lk attack search reentrancy
  lk attack learn EVM-001
  lk attack lab single-function-reentrancy
  lk attack map lending

Severity is a starting risk hint, not a final finding rating. Always assess
the actual code, preconditions, affected users/assets, likelihood, and the
specific contest or bug-bounty severity rubric.
"""

SEVERITY_GUIDE = {
    "Critical": "A realistic exploit can cause catastrophic loss, broad unauthorized control, systemic insolvency, or compromise of a core trust boundary.",
    "High": "A realistic exploit can cause major asset loss, privileged control, severe protocol disruption, or materially unsafe accounting.",
    "Medium": "A bounded or conditional exploit can cause meaningful loss, degraded security, or partial disruption.",
    "Low": "Impact is limited, exploitability is constrained, or the issue mainly affects a narrow edge case.",
    "Informational": "A hardening, documentation, observability, or trust-model concern without demonstrated direct exploit impact on its own.",
}

# Profiles are investigation lenses, not vulnerability detectors.
PROFILES = {
    "general": [
        "single-function-reentrancy", "missing-access-control", "signature-replay",
        "rounding-direction", "spot-price-manipulation", "unbounded-loop",
        "uninitialized-proxy", "cross-chain-message-replay",
    ],
    "defi": [
        "flash-loan-assisted-exploit", "spot-price-manipulation",
        "stale-oracle-price", "cross-market-price-manipulation",
        "share-inflation-donation", "reward-accounting-drift",
        "fee-on-transfer-misaccounting", "rounding-direction",
    ],
    "lending": [
        "spot-price-manipulation", "stale-oracle-price",
        "bad-health-factor-math", "liquidation-threshold-manipulation",
        "debt-share-rounding", "interest-index-staleness",
        "collateral-withdrawal-before-health-check", "bad-debt-socialization",
        "l2-sequencer-dependency",
    ],
    "dex": [
        "spot-price-manipulation", "twap-window-manipulation",
        "missing-slippage-protection", "sandwich-attack", "jit-liquidity",
        "k-invariant-accounting", "unvalidated-flash-callback",
        "first-liquidity-manipulation", "pool-initialization-front-run",
    ],
    "vault": [
        "share-inflation-donation", "erc4626-preview-mismatch",
        "rounding-direction", "dust-accumulation",
        "fee-on-transfer-misaccounting", "rebase-balance-drift",
        "single-function-reentrancy", "withdrawal-liquidity-mismatch",
    ],
    "staking": [
        "staking-lockup-bypass", "reward-rate-manipulation",
        "reward-accounting-drift", "double-claim",
        "interest-index-staleness", "unbounded-loop",
    ],
    "bridge": [
        "cross-chain-message-replay", "bridge-source-chain-spoof",
        "bridge-sender-spoof", "bridge-validator-threshold",
        "bridge-proof-verification", "bridge-nonce-ordering",
        "bridge-decimal-conversion", "bridge-mint-cap-bypass",
        "optimistic-bridge-challenge-bypass", "light-client-stale-root",
    ],
    "governance": [
        "flashloan-governance", "voting-snapshot-error",
        "delegation-vote-accounting", "proposal-threshold-manipulation",
        "timelock-bypass", "quorum-manipulation",
        "governance-parameter-capture", "governance-key-centralization",
    ],
    "nft": [
        "safe-mint-reentrancy", "nft-receiver-validation",
        "marketplace-order-replay", "royalty-bypass",
        "mutable-metadata-rug", "duplicate-token-id",
        "marketplace-payment-reentrancy", "nft-approval-confusion",
    ],
    "wallet": [
        "missing-access-control", "tx-origin-auth",
        "signature-replay", "cross-chain-signature-replay",
        "ecrecover-zero-address", "erc1271-validation-bypass",
        "wallet-batch-call-abuse", "private-key-compromise",
    ],
    "account-abstraction": [
        "userop-signature-validation", "paymaster-drain",
        "userop-nonce-key-collision", "session-key-overpermission",
        "eip7702-delegation-confusion", "wallet-batch-call-abuse",
        "paymaster-postop-gas-grief",
    ],
    "solana": [
        "solana-missing-signer", "solana-account-owner-check",
        "solana-pda-seed-bump", "solana-sysvar-spoof",
        "solana-cpi-program-id", "solana-duplicate-account-alias",
        "solana-close-reinitialize", "solana-remaining-accounts",
        "solana-upgrade-authority", "token2022-hook-trust",
    ],
    "move": [
        "move-capability-leak", "move-object-owner-check",
        "move-shared-object-auth", "move-generic-type-confusion",
        "move-one-time-witness", "move-resource-accounting",
    ],
    "cosmos": [
        "cosmwasm-funds-validation", "cosmwasm-reply-auth",
        "cosmwasm-address-validation", "ibc-packet-replay",
        "ibc-timeout-denom-confusion", "migration-admin-abuse",
    ],
    "privacy": [
        "underconstrained-circuit", "public-input-binding",
        "nullifier-reuse", "stale-merkle-root",
        "trusted-setup-compromise", "verifier-key-mismatch",
        "proof-malleability",
    ],
}

INCIDENTS = [
    {
        "year": "2016",
        "name": "The DAO",
        "patterns": "Recursive reentrancy and stale internal accounting",
        "lesson": "The original public incident explains how a callback re-entered a withdrawal-like path before balances were consumed.",
        "url": "https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability",
    },
    {
        "year": "2022",
        "name": "Wormhole bridge",
        "patterns": "Bridge signature/proof verification and Solana sysvar validation",
        "lesson": "A forged verification context let a bridge message pass a trust check it should not have passed.",
        "url": "https://www.certik.com/blog/wormhole-bridge-exploit-incident-analysis",
    },
    {
        "year": "2023",
        "name": "Euler Finance",
        "patterns": "Composed lending, donation, and accounting logic",
        "lesson": "A complex sequence of protocol actions exploited how debt and collateral accounting interacted; read the protocol's own recovery history.",
        "url": "https://www.euler.finance/blog/war-peace-behind-the-scenes-of-eulers-240m-exploit-recovery",
    },
    {
        "year": "2023",
        "name": "Curve and affected Vyper pools",
        "patterns": "Cross-function reentrancy enabled by a compiler reentrancy-lock bug",
        "lesson": "The incident demonstrates that compiler/toolchain versions can invalidate an assumed protection.",
        "url": "https://github.com/advisories/GHSA-5824-cm3x-3c38",
    },
    {
        "year": "2023",
        "name": "Curve pool reentrancy post-mortem",
        "patterns": "Compiler-specific reentrancy protection failure",
        "lesson": "Compare the incident timeline, affected compiler versions, and the exact conditions required for exploitation.",
        "url": "https://www.llamarisk.com/research/curve-pool-reentrancy-exploit-postmortem",
    },
]

GLOSSARY = {
    "attack surface": "Every entrypoint, dependency, role, asset, and external system an attacker can influence.",
    "precondition": "Something that must be true before a weakness can be exploited.",
    "invariant": "A rule that must remain true across every valid sequence of actions.",
    "exploit chain": "A sequence of actions or weaknesses combined to reach an impact.",
    "proof of concept": "A small, repeatable demonstration that a suspected issue is real.",
    "reentrancy": "A call-back into a contract before its earlier operation has finished.",
    "oracle": "A source or mechanism that supplies external facts such as prices or timestamps.",
    "MEV": "Value gained by influencing transaction inclusion, ordering, or execution.",
    "front-running": "Getting a transaction executed before another transaction to benefit from its expected effect.",
    "back-running": "Executing after a transaction to benefit from the state it created.",
    "flash loan": "A loan that must be repaid in the same transaction or the whole transaction reverts.",
    "delegatecall": "A message call that executes another contract's code using the caller's storage and execution context.",
    "callback": "A function invoked by another contract during an interaction, such as a token or receiver hook.",
    "blast radius": "How much of a protocol, user base, or asset pool an exploit can affect.",
    "liveness": "The ability of users or the system to keep making progress, such as withdrawing or settling.",
    "domain separation": "Including context such as chain, contract, and operation type so a signature/hash cannot be reused elsewhere.",
    "finality": "The point at which a chain treats a transaction or state as sufficiently irreversible.",
    "sequencer": "An operator that orders transactions on some Layer 2 networks.",
    "nullifier": "A unique marker that records a private entitlement or action has already been used.",
    "PDA": "A Solana Program Derived Address, deterministically derived from seeds and a program ID.",
    "CPI": "A Solana cross-program invocation, where one program calls another program.",
}

# Complete, intentionally vulnerable local teaching fixtures for selected core patterns.
# They are toy examples only and should never be deployed with real assets.
LAB_SNIPPETS = {
    "single-function-reentrancy": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyVault {
    mapping(address => uint256) public credit;

    receive() external payable {}

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // BUG: interaction happens before the entitlement is consumed.
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "payment failed");

        credit[msg.sender] = 0;
    }
}

contract ReenteringReceiver {
    ToyVault public immutable vault;
    uint256 public callbacks;

    constructor(ToyVault target) {
        vault = target;
    }

    function attack() external payable {
        require(msg.value > 0, "seed value required");
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        callbacks++;
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}""",
    "tx-origin-auth": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        // BUG: the original transaction sender may be an owner
        // who was tricked into calling a malicious intermediary.
        require(tx.origin == owner, "not owner");
        _;
    }

    function sweep(address payable recipient) external onlyOwner {
        (bool ok,) = recipient.call{value: address(this).balance}("");
        require(ok, "payment failed");
    }

    receive() external payable {}
}

contract MaliciousRelay {
    ToyWallet public immutable wallet;

    constructor(ToyWallet target) {
        wallet = target;
    }

    function trick(address payable destination) external {
        wallet.sweep(destination);
    }
}""",
    "untrusted-delegatecall": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyModule {
    function seize() external {
        assembly {
            sstore(0, caller())
        }
    }
}

contract ToyProxyLike {
    address public owner; // slot zero

    function run(address module, bytes calldata data) external {
        // BUG: caller chooses code that runs in this contract's storage.
        (bool ok,) = module.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}""",
    "signature-replay": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToySignedClaim {
    address public signer;
    mapping(address => uint256) public paid;

    constructor(address trustedSigner) {
        signer = trustedSigner;
    }

    function claim(uint256 amount, bytes calldata signature) external {
        // BUG: no nonce, deadline, chain, or consumed digest is included.
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));
        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        require(ecrecover(digest, v, r, s) == signer, "bad signature");
        paid[msg.sender] += amount;
    }

    function _split(bytes calldata sig)
        internal pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "bad length");
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
    }
}""",
    "fee-on-transfer-misaccounting": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract ToyDepositBook {
    IERC20Like public immutable token;
    mapping(address => uint256) public credit;

    constructor(IERC20Like asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        // BUG: credits the requested amount, not the amount actually received.
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        credit[msg.sender] += amount;
    }
}""",
    "cross-chain-message-replay": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyBridge {
    mapping(address => uint256) public minted;

    function complete(address recipient, uint256 amount, bytes32 messageId) external {
        // BUG: messageId is never consumed and the source domain is not bound.
        require(messageId != bytes32(0), "empty message");
        minted[recipient] += amount;
    }
}""",
    "missing-access-control": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyTreasury {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address nextOwner) external {
        // BUG: no authorization check.
        owner = nextOwner;
    }
}""",
    "stale-oracle-price": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceFeed {
    function latestRoundData()
        external view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract ToyValuation {
    IPriceFeed public immutable feed;

    constructor(IPriceFeed source) {
        feed = source;
    }

    function price() external view returns (uint256) {
        // BUG: no positive-price, updatedAt, or round validation.
        (, int256 answer,,,) = feed.latestRoundData();
        return uint256(answer);
    }
}""",
    "share-inflation-donation": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyShareVault {
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 assets) external returns (uint256 minted) {
        uint256 totalAssets = address(this).balance;
        if (totalShares == 0) {
            minted = assets;
        } else {
            // BUG: raw donations can distort this exchange rate and rounding.
            minted = assets * totalShares / totalAssets;
        }
        totalShares += minted;
        shares[msg.sender] += minted;
    }

    function donate() external payable {}
}""",
    "push-payment-dos": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyBatchPayout {
    function payAll(address payable[] calldata users) external payable {
        uint256 each = msg.value / users.length;
        for (uint256 i; i < users.length; ++i) {
            // BUG: one reverting receiver blocks the complete batch.
            users[i].transfer(each);
        }
    }
}""",
    "weak-randomness": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyLottery {
    function winnerSeed() external view returns (uint256) {
        // BUG: values are public and influenceable; this is not secure randomness.
        return uint256(keccak256(abi.encode(
            block.timestamp, block.prevrandao, block.number, msg.sender
        )));
    }
}""",
    "initializer-frontrunning": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ToyInitializable {
    address public owner;
    bool public initialized;

    function initialize(address firstOwner) external {
        // BUG: any account can win the race to initialize.
        require(!initialized, "already initialized");
        initialized = true;
        owner = firstOwner;
    }
}""",
}

INCIDENT_HINTS = {
    "single-function-reentrancy": ["The DAO"],
    "cross-function-reentrancy": ["Curve and affected Vyper pools"],
    "solana-sysvar-spoof": ["Wormhole bridge"],
    "bridge-proof-verification": ["Wormhole bridge"],
    "compiler-bug": ["Curve and affected Vyper pools"],
    "share-inflation-donation": ["Euler Finance"],
}


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-")


def _index():
    by_slug = {}
    by_id = {}
    for entry in ATTACKS:
        by_slug[entry["slug"]] = entry
        by_id[entry["id"].lower()] = entry
    return by_slug, by_id


BY_SLUG, BY_ID = _index()


def validate_catalogue():
    problems = []
    seen_ids = set()
    seen_slugs = set()
    for entry in ATTACKS:
        for field in ("id", "slug", "title", "category", "severity", "plain",
                      "pattern", "audit_signal", "local_lab", "mitigation"):
            if not str(entry.get(field, "")).strip():
                problems.append("%s: missing %s" % (entry.get("slug", "?"), field))
        if entry["id"] in seen_ids:
            problems.append("duplicate ID: %s" % entry["id"])
        if entry["slug"] in seen_slugs:
            problems.append("duplicate slug: %s" % entry["slug"])
        if entry["severity"] not in SEVERITIES:
            problems.append("%s: invalid severity %s" % (entry["slug"], entry["severity"]))
        for source in entry["references"]:
            if source not in REFERENCE_SOURCES and not re.fullmatch(r"OWASP-SCWE-\d{3}", source):
                problems.append("%s: unknown reference %s" % (entry["slug"], source))
        seen_ids.add(entry["id"])
        seen_slugs.add(entry["slug"])

    known_slugs = seen_slugs
    for profile, slugs in PROFILES.items():
        for slug in slugs:
            if slug not in known_slugs:
                problems.append("%s profile: unknown attack slug %s" % (profile, slug))
    return problems


def find_attack(query: str):
    raw = str(query).strip()
    if not raw:
        return None
    normalized = _norm(raw)
    if normalized in BY_SLUG:
        return BY_SLUG[normalized]
    if raw.lower() in BY_ID:
        return BY_ID[raw.lower()]
    for entry in ATTACKS:
        if normalized in {_norm(entry["title"]), _norm(entry["slug"])}:
            return entry
    matches = search_attacks(raw)
    if matches and matches[0]["score"] >= 0.72:
        return matches[0]["entry"]
    return None


def search_attacks(query: str, severity=None, category=None):
    q = _norm(query)
    wanted_severity = severity.title() if severity else None
    wanted_category = _norm(category) if category else None
    ranked = []
    for entry in ATTACKS:
        if wanted_severity and entry["severity"] != wanted_severity:
            continue
        if wanted_category and _norm(entry["category"]) != wanted_category:
            continue
        haystack = " ".join((
            entry["id"], entry["slug"], entry["title"], entry["category"],
            entry["plain"], entry["pattern"], entry["audit_signal"],
            entry["local_lab"], entry["mitigation"],
        )).lower()
        if not q:
            score = 1.0
        else:
            slug = _norm(entry["slug"])
            title = _norm(entry["title"])
            score = 0.0
            if q in slug or q in title:
                score = 1.0
            elif q in _norm(haystack):
                score = 0.86
            else:
                score = max(
                    difflib.SequenceMatcher(None, q, slug).ratio(),
                    difflib.SequenceMatcher(None, q, title).ratio(),
                )
                query_words = [w for w in q.split("-") if len(w) > 2]
                if query_words and all(w in haystack for w in query_words):
                    score = max(score, 0.8)
            if score < 0.38:
                continue
        ranked.append({"score": score, "entry": entry})
    ranked.sort(key=lambda row: (
        -row["score"],
        SEVERITY_ORDER.get(row["entry"]["severity"], 99),
        row["entry"]["title"],
    ))
    return ranked


def _print_refs(entry):
    if not entry["references"]:
        print("  No external mapping recorded yet.")
        return
    print("  " + ", ".join(entry["references"]))
    for source_id in entry["references"]:
        source = REFERENCE_SOURCES.get(source_id)
        if source:
            print("    %s: %s" % (source["name"], source["url"]))
        elif re.fullmatch(r"OWASP-SCWE-\d{3}", source_id):
            # Keep individual weakness IDs searchable while linking to the
            # maintained OWASP catalogue rather than inventing an ID-specific URL.
            catalogue = REFERENCE_SOURCES.get("OWASP-SCWE")
            print("    OWASP SCWE identifier: %s" % source_id)
            if catalogue:
                print("    %s: %s" % (catalogue["name"], catalogue["url"]))


def _resolve_or_suggest(query):
    entry = find_attack(query)
    if entry:
        return entry
    print("No exact attack matched: %s" % query)
    suggestions = search_attacks(query)[:6]
    if suggestions:
        print("Closest matches:")
        for row in suggestions:
            item = row["entry"]
            print("  %-9s [%-13s] %s" % (item["id"], item["severity"].upper(), item["title"]))
    print("Use: lk attack search <words>")
    return None


def render_index():
    counts = Counter(entry["category"] for entry in ATTACKS)
    severity_counts = Counter(entry["severity"] for entry in ATTACKS)
    print("LOWKEY // ATTACK LIBRARY  v%s" % VERSION)
    print("=" * 76)
    print("RESEARCH REFERENCE  |  LOCAL LABS  |  AUDIT CHECKLISTS")
    print()
    print("%d attack patterns across %d families" % (len(ATTACKS), len(counts)))
    print("Severity guide: " + "  ".join(
        "%s %d" % (level, severity_counts.get(level, 0)) for level in SEVERITIES
    ))
    print()
    print("BROWSE FAMILIES")
    print("---------------")
    for category in sorted(counts):
        print("  %-34s %3d patterns" % (category, counts[category]))
    print()
    print("BEGINNER ROUTE")
    print("--------------")
    print("  1. lk attack learn single-function-reentrancy")
    print("  2. lk attack learn missing-access-control")
    print("  3. lk attack learn spot-price-manipulation")
    print("  4. lk attack learn share-inflation-donation")
    print("  5. lk attack learn signature-replay")
    print("  6. lk attack map lending")
    print()
    print("QUICK COMMANDS")
    print("--------------")
    print("  lk attack list --severity Critical")
    print("  lk attack search oracle")
    print("  lk attack show EVM-001")
    print("  lk attack lab single-function-reentrancy")
    print("  lk attack incidents")
    print("  lk attack sources")
    print()
    print("The catalogue is an expanding reference, not a claim that every possible")
    print("attack has been discovered or that every listed pattern is exploitable.")
    return 0


def render_categories():
    counts = Counter(entry["category"] for entry in ATTACKS)
    print("ATTACK FAMILIES")
    print("===============")
    for index, category in enumerate(sorted(counts), 1):
        print("%2d. %-36s %3d patterns" % (index, category, counts[category]))
    print()
    print("Use: lk attack list --category \"<exact family name>\"")
    return 0


def render_list(args):
    severity = None
    category = None
    all_rows = False
    query_parts = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--severity" and i + 1 < len(args):
            severity = args[i + 1]
            i += 2
        elif arg.startswith("--severity="):
            severity = arg.split("=", 1)[1]
            i += 1
        elif arg == "--category" and i + 1 < len(args):
            category = args[i + 1]
            i += 2
        elif arg.startswith("--category="):
            category = arg.split("=", 1)[1]
            i += 1
        elif arg == "--all":
            all_rows = True
            i += 1
        else:
            query_parts.append(arg)
            i += 1

    if severity and severity.title() not in SEVERITIES:
        print("Unknown severity: %s" % severity)
        print("Choose: %s" % ", ".join(SEVERITIES))
        return 2

    query = " ".join(query_parts).strip()
    rows = search_attacks(query, severity=severity, category=category)
    if not rows:
        print("No attack entries match those filters.")
        return 0
    limit = len(rows) if all_rows else min(len(rows), 60)
    print("ATTACK CATALOGUE")
    print("===============")
    if severity:
        print("Severity: %s" % severity.title())
    if category:
        print("Family: %s" % category)
    print("%d result(s)" % len(rows))
    print()
    for row in rows[:limit]:
        entry = row["entry"]
        print("%-9s [%-13s] %-38s %s [%s]" % (
            entry["id"], entry["severity"].upper(), entry["title"], entry["category"], entry["slug"]
        ))
    if len(rows) > limit:
        print()
        print("Showing first %d. Use --all to show every match." % limit)
    print()
    print("Open: lk attack learn <ID or slug>")
    return 0


def render_card(entry):
    print()
    print("LOWKEY // ATTACK CARD")
    print("=" * 76)
    print("%s  %s" % (entry["id"], entry["title"]))
    print("Family  : %s" % entry["category"])
    print("Severity: %s (typical starting estimate)" % entry["severity"].upper())
    print()
    print("PLAIN ENGLISH")
    print("-------------")
    print(entry["plain"])
    print()
    print("VULNERABLE SHAPE")
    print("----------------")
    print(entry["pattern"])
    print()
    print("AUDIT SIGNAL")
    print("------------")
    print(entry["audit_signal"])
    print()
    print("LOCAL REPRODUCTION IDEA")
    print("-----------------------")
    print(entry["local_lab"])
    print()
    print("MITIGATION DIRECTION")
    print("--------------------")
    print(entry["mitigation"])
    print()
    print("CROSS-REFERENCES")
    print("----------------")
    _print_refs(entry)
    print()
    print("Next: lk attack learn %s  |  lk attack lab %s" % (entry["slug"], entry["slug"]))
    return 0


def render_learn(entry):
    print()
    print("LOWKEY // ATTACK LESSON")
    print("=" * 76)
    print("%s  %s" % (entry["id"], entry["title"]))
    print("Family: %s" % entry["category"])
    print("Typical starting severity: %s" % entry["severity"].upper())
    print()
    print("1. THE SIMPLE EXPLANATION")
    print("-------------------------")
    print(entry["plain"])
    print()
    print("2. WHAT THE CODE IS DOING")
    print("-------------------------")
    print(entry["pattern"])
    print()
    print("3. WHAT MUST BE TRUE FOR THIS TO MATTER")
    print("---------------------------------------")
    print(entry["audit_signal"])
    print()
    print("4. REPRODUCE IT STEP BY STEP IN A LOCAL LAB")
    print("-------------------------------------------")
    steps = [
        "Write down the intended rule first: what must never happen?",
        "Create a tiny local fixture containing only the relevant state and function path.",
        "Set the preconditions described below; use test actors and mock assets only.",
        "Trigger the suspicious call sequence or input described below.",
        "Assert a measurable violation: unauthorized state change, excess assets, broken accounting, or blocked progress.",
        "Patch the fixture, repeat the exact same test, and prove the invariant now holds.",
    ]
    for number, step in enumerate(steps, 1):
        print("  %d. %s" % (number, step))
    print()
    print("YOUR ATTACK-SPECIFIC EXPERIMENT")
    print("------------------------------")
    print(entry["local_lab"])
    print()
    print("5. WHAT COUNTS AS PROOF")
    print("----------------------")
    print("Capture the caller, calldata, state before/after, asset deltas, emitted events,")
    print("revert reason or return data, and the exact test that reproduces the behavior.")
    print("A suspicious line or tool warning alone is not a confirmed vulnerability.")
    print()
    print("6. THE FIXING IDEA")
    print("-----------------")
    print(entry["mitigation"])
    print()
    print("7. RELATED INCIDENTS")
    print("-------------------")
    incident_names = INCIDENT_HINTS.get(entry["slug"], [])
    if incident_names:
        for incident in incident_names:
            print("  - %s" % incident)
    else:
        print("  See: lk attack incidents")
    print()
    print("8. CROSS-REFERENCES")
    print("------------------")
    _print_refs(entry)
    print()
    print("NEXT")
    print("----")
    print("  lk attack lab %s" % entry["slug"])
    print("  lk attack related %s" % entry["slug"])
    print("  lk attack quiz %s" % entry["slug"])
    print()
    print("Remember: this lesson explains a pattern, not a verdict about any live protocol.")
    return 0


def render_lab(entry):
    print()
    print("LOWKEY // LOCAL ATTACK LAB")
    print("=" * 76)
    print("%s  %s" % (entry["id"], entry["title"]))
    print("SAFETY: toy code and local test networks only; this command does not connect to RPCs.")
    print()
    print("LAB OBJECTIVE")
    print("-------------")
    print(entry["local_lab"])
    print()
    print("VULNERABLE PATTERN")
    print("------------------")
    print(entry["pattern"])
    snippet = LAB_SNIPPETS.get(entry["slug"])
    if snippet:
        print()
        print("COMPLETE TOY SOLIDITY FIXTURE")
        print("-----------------------------")
        print(snippet)
    else:
        print()
        print("MINIMAL TEST SHAPE")
        print("------------------")
        print("  // Arrange: deploy the toy target and mock dependencies.")
        print("  // Act:      use the precondition and trigger described above.")
        print("  // Assert:   prove the expected invariant is violated.")
        print("  // Patch:    apply the mitigation and assert the same action is safe.")
    print()
    print("LOCAL WORKSPACE")
    print("---------------")
    print("  mkdir -p ~/lk-attack-labs/%s" % entry["slug"])
    print("  cd ~/lk-attack-labs/%s" % entry["slug"])
    print("  forge init --no-git .")
    print("  # Put the toy target in src/ and a test harness in test/")
    print("  forge test -vvv")
    print()
    print("Do not point this exercise at a public RPC, real wallet, or third-party protocol.")
    print("The fixture is intentionally vulnerable. Do not reuse it in production.")
    print()
    print("Next: lk attack learn %s" % entry["slug"])
    return 0


def render_quiz(entry):
    print()
    print("LOWKEY // ATTACK CHECK")
    print("=" * 76)
    print("%s  %s" % (entry["id"], entry["title"]))
    print()
    print("1. Explain this weakness as if you were explaining it to a non-programmer.")
    print("2. What exact precondition must an attacker control or wait for?")
    print("3. Which state variable, asset balance, role, or liveness property can change?")
    print("4. What trace or assertion would prove that the behavior is exploitable?")
    print("5. What invariant should remain true after the vulnerable path is fixed?")
    print()
    print("Check your answers against:")
    print("  lk attack learn %s" % entry["slug"])
    print("  lk attack lab %s" % entry["slug"])
    return 0


def render_related(entry):
    related = []
    for candidate in ATTACKS:
        if candidate["slug"] == entry["slug"]:
            continue
        shared = set(candidate["tags"]) & set(entry["tags"])
        same_family = candidate["category"] == entry["category"]
        if same_family or len(shared) >= 2:
            related.append((same_family, len(shared), candidate))
    related.sort(key=lambda row: (not row[0], -row[1], row[2]["title"]))
    print()
    print("RELATED ATTACK PATTERNS")
    print("=======================")
    print("Starting point: %s" % entry["title"])
    for _, _, candidate in related[:15]:
        print("  %-9s [%-13s] %s" % (
            candidate["id"], candidate["severity"].upper(), candidate["title"]
        ))
    if not related:
        print("No direct catalogue links yet.")
    print()
    print("Open: lk attack learn <slug>")
    return 0


def render_map(profile):
    key = _norm(profile or "general")
    if key not in PROFILES:
        print("Unknown profile: %s" % profile)
        print("Profiles: %s" % ", ".join(sorted(PROFILES)))
        return 2
    print()
    print("LOWKEY // AUDIT ATTACK-SURFACE MAP")
    print("=" * 76)
    print("Profile: %s" % key)
    print("These are hypotheses to investigate, not detected vulnerabilities.")
    print()
    for index, slug in enumerate(PROFILES[key], 1):
        entry = BY_SLUG.get(slug)
        if not entry:
            continue
        print("[ ] %2d. %-9s [%-13s] %s" % (
            index, entry["id"], entry["severity"].upper(), entry["title"]
        ))
        print("       %s" % entry["audit_signal"])
    print()
    print("For each item: inspect source -> understand assumptions -> write invariant")
    print("-> build a local test -> prove impact -> record evidence or mark not applicable.")
    print("This map does not scan source or claim that any listed issue exists.")
    return 0


def render_incidents(query=""):
    q = _norm(query)
    rows = []
    for item in INCIDENTS:
        hay = _norm(" ".join((item["name"], item["year"], item["patterns"], item["lesson"])))
        if not q or q in hay or all(part in hay for part in q.split("-")):
            rows.append(item)
    print()
    print("DOCUMENTED INCIDENT STARTING POINTS")
    print("===================================")
    if not rows:
        print("No matching seeded incident. Try: lk attack incidents reentrancy")
        return 0
    for item in rows:
        print("%s  %s" % (item["year"], item["name"]))
        print("  Pattern: %s" % item["patterns"])
        print("  Lesson : %s" % item["lesson"])
        print("  Source : %s" % item["url"])
        print()
    print("Incident summaries are starting points. Read the source and check its facts.")
    print("More reproductions: https://github.com/SunWeb3Sec/DeFiHackLabs")
    return 0


def render_sources():
    print()
    print("ATTACK LIBRARY RESEARCH SOURCES")
    print("===============================")
    for source_id, source in REFERENCE_SOURCES.items():
        print("%s  %s" % (source_id, source["name"]))
        print("  %s" % source["why"])
        print("  %s" % source["url"])
        print()
    print("Sources have different scopes and maintenance levels. Check version and date.")
    print("The legacy SWC Registry is retained for historical cross-reference only.")
    return 0


def render_severity():
    print()
    print("SEVERITY GUIDE")
    print("==============")
    for level in SEVERITIES:
        print("%-14s %s" % (level.upper(), SEVERITY_GUIDE[level]))
        print()
    print("HOW TO RATE A REAL FINDING")
    print("--------------------------")
    print("1. Identify the exact asset, role, invariant, or user population affected.")
    print("2. Prove the exploit preconditions and whether an attacker can realistically meet them.")
    print("3. Measure direct loss, control impact, duration, reversibility, and blast radius.")
    print("4. Consider required privileges, user interaction, liquidity, chain state, and mitigations.")
    print("5. Apply the target program's own rubric. Immunefi, audit contests, and firms can differ.")
    print()
    print("Catalogue levels are typical teaching estimates, not promises or triage decisions.")
    return 0


def render_glossary(query=""):
    q = _norm(query)
    print()
    print("LOWKEY // ATTACK GLOSSARY")
    print("=========================")
    rows = [(term, definition) for term, definition in GLOSSARY.items()
            if not q or q in _norm(term) or q in _norm(definition)]
    if not rows:
        print("No glossary match: %s" % query)
        return 0
    for term, definition in rows:
        print("%-24s %s" % (term, definition))
    return 0


def render_check():
    problems = validate_catalogue()
    counts = Counter(entry["category"] for entry in ATTACKS)
    print("ATTACK CATALOGUE CHECK")
    print("=====================")
    print("Entries   : %d" % len(ATTACKS))
    print("Families  : %d" % len(counts))
    print("Severity  : %s" % ", ".join(
        "%s=%d" % (name, sum(1 for e in ATTACKS if e["severity"] == name))
        for name in SEVERITIES
    ))
    print("Local labs: %d complete toy fixtures, %d guided patterns" % (
        len(LAB_SNIPPETS), len(ATTACKS) - len(LAB_SNIPPETS)
    ))
    if problems:
        print("Result    : FAIL")
        for problem in problems:
            print("  - %s" % problem)
        return 1
    print("Result    : PASS")
    print("Every entry has a unique ID/slug, required lesson fields, a supported severity, recognized source keys, and valid OWASP SCWE ID formats.")
    return 0


def run(args=None):
    args = list(args or [])
    if not args or args[0].lower() in {"--help", "--h", "-h", "help"}:
        print(HELP.strip())
        if not args:
            print()
            render_index()
        return 0

    command = args.pop(0).lower()
    if command in {"list", "all"}:
        return render_list(args)
    if command in {"categories", "families"}:
        return render_categories()
    if command == "search":
        query = " ".join(args).strip()
        if not query:
            print("Usage: lk attack search <words>")
            return 2
        rows = search_attacks(query)
        print("ATTACK SEARCH: %s" % query)
        print("==============================")
        if not rows:
            print("No match. Try broader terms or another name for the technique.")
            return 0
        for row in rows[:25]:
            entry = row["entry"]
            print("%-9s [%-13s] %-38s %s" % (
                entry["id"], entry["severity"].upper(), entry["title"], entry["category"]
            ))
        print()
        print("Open: lk attack learn <ID or slug>")
        return 0
    if command in {"show", "learn", "lab", "quiz", "related"}:
        if not args:
            print("Usage: lk attack %s <ID or name>" % command)
            return 2
        entry = _resolve_or_suggest(" ".join(args))
        if not entry:
            return 2
        if command == "show":
            return render_card(entry)
        if command == "learn":
            return render_learn(entry)
        if command == "lab":
            return render_lab(entry)
        if command == "quiz":
            return render_quiz(entry)
        return render_related(entry)
    if command == "map":
        return render_map(" ".join(args).strip() or "general")
    if command == "incidents":
        return render_incidents(" ".join(args).strip())
    if command == "sources":
        return render_sources()
    if command == "severity":
        return render_severity()
    if command == "glossary":
        return render_glossary(" ".join(args).strip())
    if command == "check":
        return render_check()
    if command == "version":
        print("Lowkey Attack Library %s (%d patterns)" % (VERSION, len(ATTACKS)))
        return 0

    print("Unknown attack-library command: %s" % command)
    print("Try: lk attack --help")
    return 2


if __name__ == "__main__":
    raise SystemExit(run())
