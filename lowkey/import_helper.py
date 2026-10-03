#!/usr/bin/env python3
"""Standalone Solidity import browser for Lowkey."""
from __future__ import annotations

import difflib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


HELP = """
LOWKEY // IMPORT HELPER
=======================

Browse Solidity things you can import from the current Foundry project.

Usage:
  lk import
  lk import packages
  lk import contracts
  lk import interfaces
  lk import libraries
  lk import types
  lk import files
  lk import mappings
  lk import common
  lk import <symbol>
  lk import --install <symbol>
  lk import install <symbol>
  lk import --install --dry-run <symbol>
  lk import --json <symbol>
  lk import --copy-only <symbol>
  lk import search nft
  lk import explain ERC721
  lk import explain interface
  lk import explain abstract
  lk import graph ERC721
  lk import usage ERC721
  lk import related ERC721
  lk import audit ERC721
  lk import "<import declaration>"
  lk import "<import/path.sol>"
  lk import --h

IMPORT SYNTAX CHEAT SHEET:
  Named symbols:
    import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  One symbol:
    import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
  Whole file:
    import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
  Namespace:
    import * as Utils from "@openzeppelin/contracts/utils/Address.sol";

  You can paste any of those directly into:
    lk import "..."

INSTALL INTELLIGENCE:
  lk import ERC721
    Read the verified install command, import path, why/when, use cases,
    example usage, and audit lens without changing the project.

  lk import --install ERC721
    Explicitly run the verified Forge install command, then re-run the
    lookup to resolve the actual source/remapping.

  lk import --install --dry-run ERC721
    Show the exact Forge install plan without changing the project.

  lk import --json ERC721
    Emit machine-readable import/learning/dependency metadata.

  lk import --copy-only ERC721
    Emit only the copy-ready Solidity import.

  lk import --verbose ERC721
    Show the deeper package/version/dependency/project-usage/audit details.

  lk import search nft
    Search deterministic learning tags, roles, use cases, and import paths.

  lk import explain/usage/related/audit ERC721
    Jump directly to the conceptual explanation, project usage, related
    components, or auditor questions for a symbol.

The lookup mode is standalone: it does not select targets, change RPC/ABI/audit
state, send transactions, or write project files. Only explicit --install mode
runs a verified Forge dependency install command.
"""


COMMON = {
    "Ownable": ("Single-owner access control.", "Use for simple owner-only administration.", "@openzeppelin/contracts/access/Ownable.sol"),
    "Ownable2Step": ("Two-step ownership transfer.", "Use when ownership handover should require explicit acceptance.", "@openzeppelin/contracts/access/Ownable2Step.sol"),
    "AccessControl": ("Role-based access control.", "Use when a contract needs multiple permissions/roles.", "@openzeppelin/contracts/access/AccessControl.sol"),
    "ReentrancyGuard": ("Reentrancy protection helper.", "Use for sensitive functions that make external calls and need a reentrancy guard.", "@openzeppelin/contracts/utils/ReentrancyGuard.sol"),
    "Pausable": ("Pause/unpause building block.", "Use when an authorized account should be able to stop selected operations.", "@openzeppelin/contracts/utils/Pausable.sol"),
    "ERC20": ("Reusable ERC20 token implementation.", "Use when building a fungible token.", "@openzeppelin/contracts/token/ERC20/ERC20.sol"),
    "IERC20": ("ERC20 interface.", "Use when interacting with an existing ERC20 without inheriting its implementation.", "@openzeppelin/contracts/token/ERC20/IERC20.sol"),
    "SafeERC20": ("ERC20 safety wrappers.", "Use when making ERC20 operations safer across token implementations.", "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"),
    "ERC721": ("Reusable ERC721 NFT implementation.", "Use when building an NFT contract.", "@openzeppelin/contracts/token/ERC721/ERC721.sol"),
    "IERC721": ("ERC721 interface.", "Use when interacting with an existing NFT.", "@openzeppelin/contracts/token/ERC721/IERC721.sol"),
    "ERC721URIStorage": ("ERC721 metadata extension.", "Use when storing per-token URI metadata on-chain.", "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol"),
    "ERC1155": ("Reusable ERC1155 multi-token implementation.", "Use for collections containing fungible and/or non-fungible token IDs.", "@openzeppelin/contracts/token/ERC1155/ERC1155.sol"),
    "AggregatorV3Interface": ("Chainlink price-feed interface.", "Use when reading data from an AggregatorV3-compatible price feed.", "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol"),
    "Test": ("Foundry Std test base.", "Use in Foundry tests for assertions, cheatcodes, and the vm interface.", "forge-std/Test.sol"),
    "Script": ("Foundry Std script base.", "Use for Foundry deployment/interaction scripts.", "forge-std/Script.sol"),
}

# Import Intelligence metadata is deliberately separate from COMMON so existing
# tuple-style callers remain stable.
IMPORT_METADATA = {
    "Ownable": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["simple owner-only admin actions", "emergency configuration", "treasury/admin controls"],
        "how": "Inherit from Ownable, then protect selected functions with onlyOwner.",
        "example": "contract Vault is Ownable { constructor(address initialOwner) Ownable(initialOwner) {} }",
        "audit": "Check every onlyOwner path, ownership-transfer flow, initialization, and whether privileged actions have the intended blast radius.",
    },
    "Ownable2Step": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["safer ownership handover", "admin rotation", "multisig/EOA ownership changes"],
        "how": "Inherit from Ownable2Step and use the two-step ownership transfer flow so the recipient explicitly accepts ownership.",
        "example": "contract Admin is Ownable2Step { constructor(address initialOwner) Ownable(initialOwner) {} }",
        "audit": "Check pending-owner state, acceptance conditions, cancellation/overwrite behavior, and whether privileged logic still assumes a single EOA.",
    },
    "AccessControl": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["operator/admin separation", "role-based protocol permissions", "upgrade or parameter-management roles"],
        "how": "Inherit from AccessControl, define role identifiers, grant roles, and gate functions with onlyRole(...).",
        "example": 'bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");',
        "audit": "Map each role to its actual powers, inspect grant/revoke/admin-role paths, and check for accidental privilege escalation.",
    },
    "ReentrancyGuard": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["withdrawal functions", "ETH/token redemption", "callback-sensitive state transitions"],
        "how": "Inherit from ReentrancyGuard and add nonReentrant to the functions that need the guard.",
        "example": "function withdraw() external nonReentrant { /* checks-effects-interactions */ }",
        "audit": "Do not treat the modifier as proof of safety: inspect alternate entry points, cross-function reentrancy, callbacks, and state updates around external calls.",
    },
    "Pausable": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["incident response", "emergency shutdowns", "pausing deposits/withdrawals/mints"],
        "how": "Inherit from Pausable, expose authorized pause/unpause controls, and gate the intended operations with whenNotPaused/whenPaused.",
        "example": "function deposit() external whenNotPaused { /* ... */ }",
        "audit": "Verify who can pause/unpause, which operations are actually covered, and whether the pause path itself can be abused or permanently lock funds.",
    },
    "ERC20": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["fungible tokens", "protocol reward tokens", "share/accounting units"],
        "how": "Inherit from ERC20, set the token name/symbol in the constructor, and implement your mint/burn policy in your contract.",
        "example": 'contract MyToken is ERC20 { constructor() ERC20("MyToken", "MTK") {} }',
        "audit": "Focus on mint/burn authorization, supply/accounting invariants, decimals assumptions, hooks/extensions, and any custom transfer logic.",
    },
    "IERC20": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["calling an external ERC20", "token deposits/withdrawals", "generic token integrations"],
        "how": "Declare an IERC20 reference at the token address and call the standard interface methods without inheriting the implementation.",
        "example": "IERC20 token = IERC20(tokenAddress); token.transfer(to, amount);",
        "audit": "Check token trust assumptions, non-standard ERC20 behavior, return-value handling, fee-on-transfer effects, and approval race/allowance logic.",
    },
    "SafeERC20": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["safe token transfers", "interacting with inconsistent ERC20s", "pull/payment flows"],
        "how": "Use the library with an IERC20 token so transfer/transferFrom/approve-style operations are wrapped consistently.",
        "example": "using SafeERC20 for IERC20; token.safeTransfer(to, amount);",
        "audit": "Check the surrounding accounting anyway: SafeERC20 handles call semantics, not business-logic mistakes such as wrong amounts, recipients, or fee-on-transfer assumptions.",
    },
    "ERC721": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["NFT collections", "membership/access NFTs", "game items", "tokenized assets"],
        "how": "Inherit from ERC721, provide name/symbol, and build your mint/burn/application authorization around the standard transfer and approval machinery.",
        "example": 'contract MyNFT is ERC721 { constructor() ERC721("MyNFT", "MNFT") {} }',
        "audit": "Inspect mint/burn authorization, token-ID uniqueness, approvals, receiver callbacks, transfer hooks/overrides, and metadata assumptions.",
    },
    "IERC721": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["NFT ownership checks", "NFT-gated logic", "integrating with existing NFT collections"],
        "how": "Cast the known NFT address to IERC721 and call ownership/approval/transfer functions through the interface.",
        "example": "IERC721 nft = IERC721(nftAddress); address owner = nft.ownerOf(tokenId);",
        "audit": "Treat the external NFT contract as a trust boundary; validate token IDs, ownership timing, approvals, callback behavior, and any assumptions about implementation/version.",
    },
    "ERC721URIStorage": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["per-token metadata URIs", "dynamic NFT metadata", "collections needing token-specific URI state"],
        "how": "Inherit from ERC721URIStorage alongside ERC721 and use the extension's per-token URI storage helpers.",
        "example": "contract MyNFT is ERC721, ERC721URIStorage { /* override required ERC721 hooks/functions */ }",
        "audit": "Check URI authorization, storage growth/cost, override correctness, token existence assumptions, and whether metadata updates can create unexpected trust or gameability.",
    },
    "ERC1155": {
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "use_cases": ["multi-token game inventories", "semi-fungible assets", "batch transfers", "mixed fungible/non-fungible IDs"],
        "how": "Inherit from ERC1155 and define your URI and mint/burn authorization around the standard multi-token balance model.",
        "example": "contract Items is ERC1155 { constructor(string memory uri_) ERC1155(uri_) {} }",
        "audit": "Inspect per-ID accounting, batch paths, authorization, receiver callbacks, URI assumptions, and any custom supply/transfer restrictions.",
    },
    "AggregatorV3Interface": {
        "package": "Chainlink Contracts (chainlink-evm)",
        "forge_install": "forge install smartcontractkit/chainlink-evm",
        "use_cases": ["ETH/USD and other price feeds", "collateral valuation", "liquidation checks", "protocol pricing"],
        "how": "Point an AggregatorV3Interface variable at a feed address and read latestRoundData(), then apply the feed's decimals and validation rules.",
        "example": "AggregatorV3Interface priceFeed = AggregatorV3Interface(feedAddress);",
        "audit": "Check freshness, round completeness, decimals, answer bounds, feed/address configuration, heartbeat assumptions, and how oracle failure affects protocol accounting.",
    },
    "Test": {
        "package": "forge-std",
        "forge_install": "forge install foundry-rs/forge-std",
        "use_cases": ["unit tests", "fuzz tests", "invariant tests", "cheatcode-driven security tests"],
        "how": "Inherit from Test in a Forge test contract to use assertions and the vm cheatcode interface.",
        "example": "contract MyTest is Test { function testSomething() public { assertEq(1, 1); } }",
        "audit": "Check that tests assert the security property you care about, not merely transaction success; cover attacker roles, alternate paths, and boundary states.",
    },
    "Script": {
        "package": "forge-std",
        "forge_install": "forge install foundry-rs/forge-std",
        "use_cases": ["deployments", "on-chain interactions", "repeatable local/fork scripts"],
        "how": "Inherit from Script, use vm.startBroadcast()/stopBroadcast(), and keep constructor/call inputs explicit.",
        "example": "contract Deploy is Script { function run() external { vm.startBroadcast(); /* deploy */ vm.stopBroadcast(); } }",
        "audit": "Keep deployment assumptions explicit: sender, constructor arguments, network/RPC, upgrade/admin addresses, and any post-deployment initialization.",
    },
}


# Extra learning/reference entries cover common OpenZeppelin pieces that are useful
# neighbours but are intentionally not all promoted into the short COMMON list.
REFERENCE_CATALOG = {
    "IERC721Receiver": {
        "kind": "interface",
        "import_path": "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol",
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "why": "Receiver interface used by safe ERC721 transfers to verify the recipient contract can handle NFTs.",
        "when": "Study this whenever an NFT is sent to a contract address or you are implementing an NFT vault/game/market.",
        "role": "interface",
        "tags": ["nft", "erc721", "interface", "callback", "receiver"],
        "related": ["IERC721", "ERC721", "ERC721URIStorage"],
        "surface": ["onERC721Received(operator, from, tokenId, data)"],
        "how": "A receiving contract implements onERC721Received and returns the expected selector during safeTransferFrom.",
        "example": "contract Vault is IERC721Receiver { function onERC721Received(address,address,uint256,bytes calldata) external pure returns (bytes4) { return this.onERC721Received.selector; } }",
        "audit": "Check callback assumptions, sender/token binding, reentrancy, and whether the recipient can cause state-dependent logic to run during NFT transfers.",
        "mistakes": ["Assuming safeTransferFrom means the transfer itself is safe from reentrancy.", "Ignoring the receiver callback as an external execution boundary."],
    },
    "ERC721Enumerable": {
        "kind": "extension",
        "import_path": "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol",
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "why": "ERC721 extension that tracks owner/global token enumeration.",
        "when": "Use when your application needs enumerable token IDs or owner token lists and you accept the extra bookkeeping/gas.",
        "role": "extension",
        "tags": ["nft", "erc721", "extension", "enumeration"],
        "related": ["ERC721", "IERC721", "ERC721URIStorage"],
        "how": "Inherit alongside ERC721 and satisfy any required overrides for the OpenZeppelin version you installed.",
        "audit": "Check enumeration bookkeeping across mint, burn, and transfer paths plus gas growth for state-heavy collections.",
        "mistakes": ["Treating enumeration as free; it adds state bookkeeping.", "Copying override lists from a different OpenZeppelin major version."],
    },
    "ERC721Burnable": {
        "kind": "extension",
        "import_path": "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol",
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "why": "ERC721 extension that provides burn functionality subject to ownership/approval rules.",
        "when": "Use when NFTs should be permanently destroyed through a standard burn path.",
        "role": "extension",
        "tags": ["nft", "erc721", "extension", "burn"],
        "related": ["ERC721", "IERC721"],
        "how": "Inherit ERC721Burnable with ERC721 and call burn(tokenId) from an authorized owner/operator.",
        "audit": "Check who can burn, whether business logic assumes token existence, and what state/metadata is removed on burn.",
        "mistakes": ["Assuming burn can only ever be called by the owner without checking approval semantics.", "Leaving protocol accounting tied to a token that can disappear."],
    },
    "ERC20Burnable": {
        "kind": "extension",
        "import_path": "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol",
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "why": "ERC20 extension that provides burn functionality.",
        "when": "Use when token holders or permitted spenders need a standard burn path.",
        "role": "extension",
        "tags": ["token", "erc20", "extension", "burn"],
        "related": ["ERC20", "IERC20", "SafeERC20"],
        "how": "Inherit the extension with ERC20 and use burn/burnFrom according to the allowance model.",
        "audit": "Check who can burn, supply accounting, allowance semantics, and whether external protocol accounting updates consistently.",
        "mistakes": ["Assuming burnFrom ignores allowance semantics.", "Forgetting that total supply changes can affect protocol accounting."],
    },
    "IERC20Metadata": {
        "kind": "interface",
        "import_path": "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol",
        "package": "OpenZeppelin Contracts",
        "forge_install": "forge install OpenZeppelin/openzeppelin-contracts",
        "why": "ERC20 metadata interface for name, symbol, and decimals.",
        "when": "Use when an integration needs human/display metadata or decimals from an external token.",
        "role": "interface",
        "tags": ["token", "erc20", "interface", "metadata", "decimals"],
        "related": ["IERC20", "ERC20", "SafeERC20"],
        "surface": ["name()", "symbol()", "decimals()"],
        "how": "Cast a token address to IERC20Metadata and query metadata; treat returned decimals as token-specific configuration, not a universal value.",
        "audit": "Check decimal normalization, precision loss, and whether a protocol incorrectly assumes 18 decimals.",
        "mistakes": ["Assuming every ERC20 uses 18 decimals.", "Using UI metadata as a security-critical identity without validating the token address."],
    },
}


# Official upstreams are trusted installation sources. Never infer install commands
# from a dependency's local git origin: forks/mirrors/superprojects can rewrite it.
OFFICIAL_PACKAGE_REGISTRY = {
    "openzeppelin-contracts": {"package": "OpenZeppelin Contracts", "repo": "OpenZeppelin/openzeppelin-contracts", "forge_install": "forge install OpenZeppelin/openzeppelin-contracts", "docs": "https://docs.openzeppelin.com/contracts/5.x"},
    "openzeppelin-contracts-upgradeable": {"package": "OpenZeppelin Contracts Upgradeable", "repo": "OpenZeppelin/openzeppelin-contracts-upgradeable", "forge_install": "forge install OpenZeppelin/openzeppelin-contracts-upgradeable", "docs": "https://docs.openzeppelin.com/upgrades-plugins"},
    "openzeppelin-foundry-upgrades": {"package": "OpenZeppelin Foundry Upgrades", "repo": "OpenZeppelin/openzeppelin-foundry-upgrades", "forge_install": "forge install OpenZeppelin/openzeppelin-foundry-upgrades", "docs": "https://docs.openzeppelin.com/upgrades-plugins/foundry-upgrades"},
    "openzeppelin-community-contracts": {"package": "OpenZeppelin Community Contracts", "repo": "OpenZeppelin/openzeppelin-community-contracts", "forge_install": "forge install OpenZeppelin/openzeppelin-community-contracts", "docs": "https://docs.openzeppelin.com/community-contracts"},
    "chainlink-evm": {"package": "Chainlink EVM Contracts", "repo": "smartcontractkit/chainlink-evm", "forge_install": "forge install smartcontractkit/chainlink-evm", "docs": "https://docs.chain.link"},
    "chainlink-ccip": {"package": "Chainlink CCIP Contracts", "repo": "smartcontractkit/chainlink-ccip", "forge_install": "forge install smartcontractkit/chainlink-ccip", "docs": "https://docs.chain.link/ccip"},
    "chainlink-local": {"package": "Chainlink Local", "repo": "smartcontractkit/chainlink-local", "forge_install": "forge install smartcontractkit/chainlink-local", "docs": "https://docs.chain.link/chainlink-local"},
    "forge-std": {"package": "forge-std", "repo": "foundry-rs/forge-std", "forge_install": "forge install foundry-rs/forge-std", "docs": "https://getfoundry.sh/reference/forge-std/overview/"},
}
IMPORT_LEARNING = {
    "Ownable": {
        "role": "access-control base contract",
        "tags": ["access", "admin", "owner", "authorization", "contract"],
        "related": ["Ownable2Step", "AccessControl", "Pausable"],
        "next": ["Read owner()/onlyOwner first, then inspect ownership transfer.", "Compare Ownable with Ownable2Step."],
        "mistakes": ["Assuming onlyOwner means the whole protocol is safe; map every privileged function.", "Missing the ownership-transfer path and its operational consequences."],
        "compatibility": "OpenZeppelin major versions can change constructors and inheritance details. Check the installed package source before copying a tutorial.",
    },
    "Ownable2Step": {
        "role": "access-control base contract",
        "tags": ["access", "admin", "owner", "authorization", "handover"],
        "related": ["Ownable", "AccessControl"],
        "next": ["Trace transferOwnership → pending owner → acceptOwnership."],
        "mistakes": ["Forgetting the recipient must explicitly accept ownership.", "Not checking what happens when a pending owner is replaced."],
        "compatibility": "Ownership APIs and constructor requirements can vary by OpenZeppelin major version.",
    },
    "AccessControl": {
        "role": "role-based access-control base contract",
        "tags": ["access", "roles", "admin", "authorization", "contract"],
        "related": ["Ownable", "Ownable2Step"],
        "next": ["Read role identifiers, grantRole/revokeRole, and each onlyRole gate."],
        "mistakes": ["Looking only at role checks without tracing who can grant/revoke the role.", "Treating role names as permissions; the implementation defines the actual powers."],
        "compatibility": "Role-management and constructor/inheritance details depend on the installed OpenZeppelin major version.",
    },
    "ReentrancyGuard": {
        "role": "security helper / base contract",
        "tags": ["security", "reentrancy", "external-call", "guard"],
        "related": ["Address", "SafeERC20"],
        "next": ["Trace the external call sites first, then inspect which state changes happen before/after them."],
        "mistakes": ["Thinking nonReentrant proves there is no reentrancy.", "Missing cross-function/read-only reentrancy or callback paths."],
        "compatibility": "Check the installed OpenZeppelin source for modifier/state details before relying on tutorial-specific internals.",
    },
    "Pausable": {
        "role": "lifecycle/emergency-control base contract",
        "tags": ["pause", "emergency", "access", "lifecycle", "contract"],
        "related": ["Ownable", "AccessControl"],
        "next": ["Find who controls pause/unpause and which entry points use whenNotPaused/whenPaused."],
        "mistakes": ["Pausing one function while another path still changes the same critical state.", "Giving pause power to an address without considering the trust boundary."],
    },
    "ERC20": {
        "role": "token implementation",
        "tags": ["token", "erc20", "fungible", "contract"],
        "related": ["IERC20", "IERC20Metadata", "SafeERC20", "ERC20Burnable"],
        "next": ["Understand IERC20 first, then ERC20's internal token update/mint/burn behavior in the installed version."],
        "mistakes": ["Assuming ERC20 behavior is identical across every token.", "Missing custom transfer/mint/burn logic added by the application contract."],
        "compatibility": "OpenZeppelin ERC20 internals and extension hooks differ across major versions; inspect the version you actually installed.",
    },
    "IERC20": {
        "role": "token interface",
        "tags": ["token", "erc20", "interface", "integration"],
        "related": ["ERC20", "IERC20Metadata", "SafeERC20"],
        "surface": ["totalSupply()", "balanceOf(account)", "transfer(to, value)", "allowance(owner, spender)", "approve(spender, value)", "transferFrom(from, to, value)"],
        "next": ["Trace one transferFrom flow: owner → allowance → spender → token balance."],
        "mistakes": ["Treating an interface as the implementation.", "Assuming every token returns values or behaves exactly like the reference implementation."],
    },
    "SafeERC20": {
        "role": "token safety library",
        "tags": ["token", "erc20", "library", "transfer", "safety"],
        "related": ["IERC20", "ERC20"],
        "next": ["Understand why low-level wrappers exist, then inspect the surrounding protocol accounting."],
        "mistakes": ["Thinking SafeERC20 fixes wrong amounts/recipients or business-logic bugs.", "Ignoring fee-on-transfer or rebasing behavior."],
    },
    "ERC721": {
        "role": "NFT implementation",
        "tags": ["nft", "erc721", "token", "contract"],
        "related": ["IERC721", "IERC721Receiver", "ERC721URIStorage", "ERC721Enumerable", "ERC721Burnable"],
        "next": ["Read IERC721 first. Then trace mint → transfer → approval → safe receiver callback."],
        "mistakes": ["Thinking ERC721 is only ownerOf/tokenURI; approvals and receiver callbacks matter.", "Copying override patterns from another OpenZeppelin major version."],
        "compatibility": "ERC721 extension/override requirements differ across OpenZeppelin major versions. The installed source is the authority.",
    },
    "IERC721": {
        "role": "NFT interface",
        "tags": ["nft", "erc721", "interface", "ownership", "approval"],
        "related": ["ERC721", "IERC721Receiver", "ERC721URIStorage"],
        "surface": ["balanceOf(owner)", "ownerOf(tokenId)", "approve(to, tokenId)", "getApproved(tokenId)", "setApprovalForAll(operator, approved)", "isApprovedForAll(owner, operator)", "transferFrom(from, to, tokenId)", "safeTransferFrom(...)"],
        "next": ["Understand ownerOf + approvals + transferFrom before reading ERC721 internals."],
        "mistakes": ["Treating ownerOf as proof of application-level authorization.", "Ignoring operator approvals and safe-transfer callbacks."],
    },
    "ERC721URIStorage": {
        "role": "NFT metadata extension",
        "tags": ["nft", "erc721", "metadata", "extension", "uri"],
        "related": ["ERC721", "IERC721", "IERC721Receiver"],
        "next": ["Compare tokenURI and URI storage with the base ERC721 metadata model."],
        "mistakes": ["Copying required override lists across OpenZeppelin versions.", "Forgetting metadata update authorization and storage-cost implications."],
        "compatibility": "This extension has version-specific inheritance/override details. Inspect the installed source rather than a tutorial's exact override list.",
    },
    "ERC1155": {
        "role": "multi-token implementation",
        "tags": ["token", "erc1155", "batch", "fungible", "nft", "contract"],
        "related": ["IERC1155", "IERC1155Receiver"],
        "next": ["Understand balances[id][account] and safe batch receiver callbacks."],
        "mistakes": ["Treating ERC1155 as a normal one-balance-per-address token.", "Ignoring batch callbacks and per-token-ID accounting."],
        "compatibility": "ERC1155 hook/override details vary by OpenZeppelin major version.",
    },
    "AggregatorV3Interface": {
        "role": "oracle interface",
        "tags": ["oracle", "chainlink", "price-feed", "interface", "defi"],
        "related": ["IERC20"],
        "surface": ["decimals()", "description()", "version()", "getRoundData(roundId)", "latestRoundData()"],
        "next": ["Read latestRoundData() and understand round IDs, updatedAt, decimals, and zero/negative answers."],
        "mistakes": ["Using a price without checking freshness.", "Forgetting feed decimals or assuming any feed address is trustworthy."],
    },
    "Test": {
        "role": "testing base contract",
        "tags": ["foundry", "test", "cheatcode", "contract"],
        "related": ["Script"],
        "next": ["Learn vm.prank, vm.deal, vm.expectRevert, and invariant/fuzz assertions."],
        "mistakes": ["Writing tests that only assert a transaction succeeded.", "Using powerful cheatcodes without understanding which state they mutate."],
    },
    "Script": {
        "role": "deployment/interaction base contract",
        "tags": ["foundry", "script", "deployment", "contract"],
        "related": ["Test"],
        "next": ["Trace startBroadcast/stopBroadcast and make every deployed address/argument explicit."],
        "mistakes": ["Assuming deployment inputs are correct because deployment succeeded.", "Forgetting post-deployment initialization/admin ownership."],
    },
}



LEARNING_CONCEPTS = {
    "interface": {
        "title": "INTERFACE",
        "what": "A Solidity interface is a contract-shaped list of callable declarations. It tells your code what functions/events/errors it can expect, but the implementation lives at another address.",
        "analogy": "Think M-Pesa API docs: the API tells you how to call sendMoney(), but the docs themselves do not move the money.",
        "use": "Use an interface when your contract needs to interact with an existing contract without inheriting its implementation.",
        "audit": "Find the concrete address behind the interface. Then audit that real implementation and every assumption your code makes about its behavior.",
    },
    "abstract": {
        "title": "ABSTRACT CONTRACT",
        "what": "An abstract contract is a reusable base contract that is not deployable while required behavior is still unimplemented. It may still contain real state, constructors, modifiers, and working functions.",
        "analogy": "Think of a partly-built house blueprint that already specifies the foundation and some finished rooms, but leaves required rooms for the final builder.",
        "use": "Use it when several child contracts should share real implementation/state while forcing each child to provide specific behavior.",
        "audit": "Audit the base implementation as executable code, then compare every child override against the security invariants established by the base.",
    },
    "contract": {
        "title": "NORMAL CONTRACT",
        "what": "A normal concrete contract has all required behavior implemented and can be deployed as its own runtime contract.",
        "analogy": "A finished M-Pesa business workflow: the rules and operations are actually implemented, so it can run.",
        "use": "Deploy it directly or inherit from it when the implementation is complete.",
        "audit": "Review its public/external entry points, state, trust boundaries, external calls, and inherited behavior.",
    },
}

@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    source: Path
    import_path: str
    line: int
    abstract: bool = False

    @property
    def import_stmt(self) -> str:
        return f'import {{{self.name}}} from "{self.import_path}";'

@dataclass(frozen=True)
class Package:
    name: str
    path: Path
    prefix: str | None


def root_for(start: Path | None = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for candidate in (p, *p.parents):
        if (candidate / "foundry.toml").is_file():
            return candidate
    return p


def remappings(root: Path) -> list[tuple[str, Path]]:
    raw: list[str] = []
    f = root / "remappings.txt"
    if f.is_file():
        try:
            raw += f.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
    try:
        r = subprocess.run(["forge", "remappings"], cwd=root, capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            raw += r.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        pass
    out: dict[str, Path] = {}
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        prefix, target = (x.strip() for x in line.split("=", 1))
        if prefix and target:
            path = Path(target)
            out[prefix] = (root / path).resolve() if not path.is_absolute() else path.resolve()
    return sorted(out.items(), key=lambda x: (-len(x[0]), x[0]))


def usable_prefix(prefix: str) -> bool:
    # Forge can expose nested dependency remappings such as
    # "lib/openzeppelin-contracts/:forge-std/". Those are useful to Forge
    # internally but are not normal user-facing import paths.
    return not prefix.startswith("lib/") and "/:" not in prefix and not prefix.startswith(":")


def import_path(path: Path, root: Path, maps: list[tuple[str, Path]]) -> str:
    resolved = path.resolve()
    for prefix, target in maps:
        if not usable_prefix(prefix):
            continue
        try:
            return prefix + resolved.relative_to(target).as_posix()
        except ValueError:
            pass
    try:
        return "./" + resolved.relative_to((root / "src").resolve()).as_posix()
    except ValueError:
        try:
            return "../lib/" + resolved.relative_to((root / "lib").resolve()).as_posix()
        except ValueError:
            return resolved.as_posix()


def sol_files(base: Path):
    if not base.is_dir():
        return
    skip = {
        ".git", "node_modules", "out", "cache", "broadcast",
        "test", "tests", "script", "scripts", "mocks", "mock",
        "fixtures", "examples", "lib", "fv", "docs", "certora",
    }
    for p in base.rglob("*.sol"):
        try:
            rel_parts = p.relative_to(base).parts
        except ValueError:
            continue
        if p.is_file() and not any(part in skip for part in rel_parts[:-1]):
            yield p


def extract(path: Path, root: Path, maps: list[tuple[str, Path]]) -> list[Symbol]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    depth = 0
    found: list[Symbol] = []
    patterns = [
        ("contract", r"^(?:abstract\s+)?contract\s+([A-Za-z_]\w*)"),
        ("interface", r"^interface\s+([A-Za-z_]\w*)"),
        ("library", r"^library\s+([A-Za-z_]\w*)"),
        ("struct", r"^struct\s+([A-Za-z_]\w*)"),
        ("enum", r"^enum\s+([A-Za-z_]\w*)"),
        ("error", r"^error\s+([A-Za-z_]\w*)"),
        ("type", r"^type\s+([A-Za-z_]\w*)\s+is\b"),
        ("function", r"^function\s+([A-Za-z_]\w*)\s*\("),
        ("constant", r"^[A-Za-z_][\w\[\]]*(?:\s+[^\s]+)*\s+constant\s+([A-Za-z_]\w*)\b"),
    ]
    compiled = [(k, re.compile(p)) for k, p in patterns]
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if depth == 0 and line:
            for kind, pat in compiled:
                m = pat.match(line)
                if m:
                    found.append(
                        Symbol(
                            m.group(1),
                            kind,
                            path,
                            import_path(path, root, maps),
                            n,
                            abstract=(kind == "contract" and bool(re.match(r"^abstract\s+contract\b", line))),
                        )
                    )
                    break
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    unique = {(s.kind, s.name, s.import_path): s for s in found}
    return sorted(unique.values(), key=lambda s: (s.name.lower(), s.kind, str(s.source)))


def all_symbols(root: Path, maps: list[tuple[str, Path]]) -> list[Symbol]:
    files = list(sol_files(root / "src")) + list(sol_files(root / "lib"))
    out: list[Symbol] = []
    for p in files:
        out += extract(p, root, maps)
    return out


def known_metadata(name: str) -> dict:
    meta: dict = {}
    meta.update(IMPORT_METADATA.get(name, {}))
    meta.update(IMPORT_LEARNING.get(name, {}))
    meta.update(REFERENCE_CATALOG.get(name, {}))
    return meta


def canonical_import_path(name: str) -> str | None:
    if name in COMMON:
        return COMMON[name][2]
    extra = REFERENCE_CATALOG.get(name, {})
    return extra.get("import_path")


def symbol_metadata(s: Symbol) -> dict:
    canonical_path = canonical_import_path(s.name)
    if not canonical_path:
        return {}
    if s.source.name.startswith("(reference only") or s.import_path == canonical_path:
        return known_metadata(s.name)
    return {}


def package_root_for(source: Path, root: Path) -> Path | None:
    try:
        rel = source.resolve().relative_to((root / "lib").resolve())
    except ValueError:
        return None
    if not rel.parts:
        return None
    candidate = (root / "lib" / rel.parts[0]).resolve()
    return candidate if candidate.is_dir() else None


def git_remote(package_root: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(package_root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode == 0:
            remote = r.stdout.strip()
            return remote or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def forge_repo_slug(remote: str | None) -> str | None:
    if not remote:
        return None
    value = remote.strip()
    value = re.sub(
        r"^(?:https?://github\.com/|ssh://git@github\.com/|git@github\.com:|git://github\.com/)",
        "",
        value,
    )
    value = value.removesuffix(".git").strip("/")
    if re.fullmatch(r"[^/\s]+/[^/\s]+", value):
        return value
    return None


def install_status(symbol: Symbol, root: Path) -> str:
    if symbol.source.name.startswith("(reference only"):
        meta = known_metadata(symbol.name)
        package_dirs = {
            "OpenZeppelin Contracts": "openzeppelin-contracts",
            "Chainlink Contracts (chainlink-evm)": "chainlink-evm",
            "forge-std": "forge-std",
        }
        package_dir = meta.get("package_dir") or package_dirs.get(meta.get("package", ""))
        if package_dir and (root / "lib" / package_dir).is_dir():
            return f"INSTALLED at lib/{package_dir}"
        return "NOT INSTALLED"
    package_root = package_root_for(symbol.source, root)
    if package_root:
        return f"INSTALLED at {package_root.relative_to(root).as_posix()}"
    if symbol.source.exists():
        return "LOCAL PROJECT SOURCE"
    return "SOURCE NOT PRESENT"


def official_package(package_root: Path | None) -> dict:
    if not package_root:
        return {}
    return OFFICIAL_PACKAGE_REGISTRY.get(package_root.name, {})

def install_guidance(symbol: Symbol, root: Path) -> tuple[str, str]:
    package_root = package_root_for(symbol.source, root)
    if package_root:
        official = official_package(package_root)
        if official:
            return official["package"], official["forge_install"]
        return package_root.name, "No verified upstream install command in Lowkey's registry."

    meta = symbol_metadata(symbol)
    if meta.get("forge_install"):
        return meta.get("package", "Known dependency"), meta["forge_install"]

    return "Current project", "No install needed — this symbol is in the current project's source."


def reference_symbol(name: str, root: Path) -> Symbol | None:
    entry = COMMON.get(name)
    if entry:
        _why, _when, import_name = entry
        meta = known_metadata(name)
        kind = meta.get("kind")
        if not kind:
            if name == "SafeERC20":
                kind = "library"
            elif name.startswith("I") and (name.endswith("Interface") or name.startswith("IERC")):
                kind = "interface"
            else:
                kind = "contract"
        return Symbol(
            name=name,
            kind=kind,
            source=Path("(reference only — dependency not installed)"),
            import_path=import_name,
            line=0,
            abstract=False,
        )
    extra = REFERENCE_CATALOG.get(name)
    if not extra:
        return None
    return Symbol(
        name=name,
        kind=extra.get("kind", "contract"),
        source=Path("(reference only — dependency not installed)"),
        import_path=extra["import_path"],
        line=0,
        abstract=False,
    )


def usage_guidance(s: Symbol) -> tuple[str, list[str], str, str]:
    meta = symbol_metadata(s)
    if meta:
        return (
            meta.get("how", "Read the source/API before using it."),
            list(meta.get("use_cases", [])),
            meta.get("example", ""),
            meta.get("audit", ""),
        )
    if s.kind == "interface":
        return (
            f"Declare {s.name} at a trusted contract address and call its typed external methods.",
            ["typed integration with an existing contract", "feature-gating based on external state"],
            f"{s.name} dependency = {s.name}(trustedAddress);",
            "Treat the interface as a trust boundary: validate returned data, permissions, callbacks, and assumptions about the implementation behind the address.",
        )
    if s.kind == "library":
        return (
            f"Import {s.name} and use its reusable helper logic directly or with Solidity's using-for syntax when appropriate.",
            ["reusable helper logic", "shared validation or math"],
            f"using {s.name} for SomeType;",
            "Review library assumptions, unsafe external calls, storage context, and whether the helper is suitable for the values and invariants in your protocol.",
        )
    if s.kind == "contract" and s.abstract:
        return (
            f"Inherit from {s.name}; implement every required abstract member in the child contract before deployment.",
            ["shared state and implementation", "template/base-contract behavior", "extension points"],
            f"contract MyContract is {s.name} {{ /* implement required functions */ }}",
            "Separate inherited behavior from child overrides. An abstract base can contain real state-changing logic, so audit it just like any other execution path.",
        )
    if s.kind == "contract":
        return (
            f"Inherit from or instantiate {s.name} after reading its constructor, public API, and extension points.",
            ["shared base contract behavior", "standardized implementation reuse"],
            f"contract MyContract is {s.name} {{ }}",
            "Inspect inherited behavior and every override/hook boundary; dependency code is part of your attack surface even when it lives under lib/.",
        )
    if s.kind in {"struct", "enum", "type", "error", "constant"}:
        return (
            f"Import {s.name} from its defining file and reuse the exact declared type/value across contracts.",
            ["shared protocol data models", "consistent error/state definitions", "cross-file typing"],
            f"{s.name} value = /* construct or use the imported declaration */;",
            "Check ABI/storage compatibility, enum bounds, custom-type conversions, and whether shared definitions drift between packages or versions.",
        )
    return (
        f"Read the defining source for {s.name}, then import it where the compiler can resolve the file.",
        ["shared source-level helpers", "cross-file reuse"],
        "",
        "Verify the imported symbol's trust boundary, inputs/outputs, state effects, and version assumptions before relying on it.",
    )


def install_symbols(symbols: list[Symbol], root: Path, dry_run: bool = False) -> int:
    if not (root / "foundry.toml").is_file():
        print()
        print("Forge installation requires a Foundry project.")
        print(f"Current root: {root}")
        print("Run this command from a directory containing foundry.toml, or cd into the project first.")
        return 2

    commands: dict[str, tuple[str, str]] = {}
    skipped = []
    unavailable = []

    for symbol in symbols:
        package, command = install_guidance(symbol, root)
        status = install_status(symbol, root)
        if status.startswith("INSTALLED") or status == "LOCAL PROJECT SOURCE":
            skipped.append((package, status))
        elif command.startswith("forge install "):
            commands[command] = (package, command)
        else:
            unavailable.append((package, status))

    if skipped:
        print()
        print("INSTALL STATUS")
        print("--------------")
        for package, status in skipped:
            print(f"  SKIP: {package} — {status}")

    if unavailable:
        print()
        print("NO AUTOMATIC INSTALL")
        print("--------------------")
        for package, status in unavailable:
            print(f"  {package}: {status}")

    if not commands:
        if skipped and not unavailable:
            print()
            print("Everything requested is already available; nothing was installed.")
            return 0
        print()
        print("No safe automatic install command is available for the requested symbol(s).")
        return 2

    print()
    print("FOUNDRY INSTALL" + (" • DRY RUN" if dry_run else ""))
    print("----------------")
    for package, command in commands.values():
        print(f"  {package}: {command}")

    if dry_run:
        print()
        print("No changes made.")
        return 0

    for package, command in commands.values():
        try:
            result = subprocess.run(command.split(), cwd=root, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"  FAILED: {package}: {exc}")
            return 1
        if result.returncode != 0:
            print(f"  FAILED: {package} (forge exited {result.returncode})")
            return result.returncode

    print()
    print("Install complete. Re-run lk import <symbol> to resolve the actual source/remapping.")
    return 0


def kind_label(s: Symbol) -> str:
    if s.kind == "contract" and s.abstract:
        return "abstract contract"
    return s.kind


def explain(s: Symbol) -> tuple[str, str]:
    meta = symbol_metadata(s)
    if meta.get("why") and meta.get("when"):
        return meta["why"], meta["when"]
    if s.kind == "interface":
        return f"Interface {s.name} describes callable behavior that another contract can implement.", "Use it for typed interaction with an existing contract; the interface tells you what can be called, not how it works."
    if s.kind == "library":
        return f"Library {s.name} contains reusable helper logic.", "Use it when you need the helper behavior exposed by this library."
    if s.kind == "contract" and s.abstract:
        return f"Abstract contract {s.name} is a reusable base that is not directly deployable until all required abstract behavior is implemented.", "Use it as a building block for another contract when you want shared state/logic plus extension points."
    if s.kind == "contract":
        return f"Contract {s.name} is a reusable implementation.", "Use it when you want to inherit from or instantiate this component."
    if s.kind == "struct":
        return f"Struct {s.name} defines reusable structured data.", "Use it when multiple files need the same data shape."
    if s.kind == "enum":
        return f"Enum {s.name} defines named states or choices.", "Use it for state machines or fixed sets of options."
    if s.kind == "type":
        return f"User-defined value type {s.name} gives a primitive its own type identity.", "Use it when stronger type separation is useful."
    if s.kind == "error":
        return f"Custom error {s.name} represents a reusable revert condition.", "Use it when several files need the same error definition."
    if s.kind == "function":
        return f"File-level function {s.name} is directly importable.", "Use it when the source exposes a reusable file-level helper."
    if s.kind == "constant":
        return f"File-level constant {s.name} is directly importable.", "Use it when several files need the same constant."
    return f"Importable {s.kind} {s.name}.", "Read its source/API before using it."


def git_commit(package_root: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(package_root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode == 0:
            value = r.stdout.strip()
            return value or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def git_version(package_root: Path) -> str | None:
    for command in (
        ["git", "-C", str(package_root), "describe", "--tags", "--exact-match"],
        ["git", "-C", str(package_root), "describe", "--tags", "--always", "--dirty"],
    ):
        try:
            r = subprocess.run(command, capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                value = r.stdout.strip()
                if value:
                    return value
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def source_status_label(s: Symbol, root: Path | None = None) -> str:
    root = root or root_for()
    if s.source.name.startswith("(reference only"):
        return "📚 REFERENCE ONLY"
    if s.source.resolve().is_relative_to((root / "lib").resolve()):
        return "📦 INSTALLED DEPENDENCY"
    return "✅ VERIFIED PROJECT SOURCE"


def source_location(s: Symbol) -> str:
    if s.line <= 0 or s.source.name.startswith("(reference only"):
        return str(s.source)
    return f"{s.source.resolve()}:{s.line}"


def source_web_url(s: Symbol, root: Path) -> str | None:
    package_root = package_root_for(s.source, root)
    official = official_package(package_root)
    if not package_root or not official or s.line <= 0:
        return None
    remote = git_remote(package_root)
    slug = forge_repo_slug(remote)
    if not slug or slug.lower() != official["repo"].lower():
        return None
    commit = git_commit(package_root)
    if not commit:
        return None
    try:
        rel = s.source.resolve().relative_to(package_root.resolve()).as_posix()
    except ValueError:
        return None
    return f"https://github.com/{official['repo']}/blob/{commit}/{rel}#L{s.line}"

def interface_surface(s: Symbol) -> list[str]:
    meta = symbol_metadata(s)
    surface = list(meta.get("surface", []))
    if surface:
        return surface
    if s.source.name.startswith("(reference only") or not s.source.is_file():
        return []
    try:
        text = s.source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    match = re.search(rf"\binterface\s+{re.escape(s.name)}\s*\{{", text)
    if not match:
        return []
    depth = 1
    end = match.end()
    for idx in range(match.end(), len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                end = idx
                break
    body = text[match.end():end]
    methods = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", body):
        params = re.sub(r"\s+", " ", m.group(2)).strip()
        signature = f"{m.group(1)}({params})"
        methods.append(signature)
    return methods[:16]


def direct_imports(source: Path) -> list[str]:
    if not source.is_file():
        return []
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found = re.findall(r'\bimport\s+(?:[^;]*?\s+from\s+)?["\']([^"\']+)["\']\s*;', text)
    return list(dict.fromkeys(found))


def project_usage(s: Symbol, root: Path) -> list[tuple[Path, int, str]]:
    if s.source.name.startswith("(reference only"):
        return []
    uses = []
    needle = re.compile(rf"\b{re.escape(s.name)}\b")
    for path in sol_files(root / "src"):
        if path.resolve() == s.source.resolve():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            if needle.search(line):
                uses.append((path, line_no, line.strip()))
                if len(uses) >= 20:
                    return uses
    return uses


def related_symbols(s: Symbol, root: Path, maps) -> list[Symbol]:
    names = list(symbol_metadata(s).get("related", []))
    out = []
    all_syms = all_symbols(root, maps)
    by_name = {}
    for item in all_syms:
        by_name.setdefault(item.name.lower(), []).append(item)
    for name in names:
        candidates = by_name.get(name.lower(), [])
        canonical = canonical_import_path(name)
        canonical_candidates = [x for x in candidates if canonical and x.import_path == canonical]
        if canonical_candidates:
            item = canonical_candidates[0]
        else:
            item = reference_symbol(name, root)
            if not item and candidates:
                item = candidates[0]
        if item:
            out.append(item)
    return out


def audit_questions(s: Symbol) -> list[str]:
    questions = [
        "Who controls the privileged entry points around this component?",
        "What state can this component read or change?",
        "What external calls/callbacks can happen on its paths?",
        "What assumptions does application code make about this dependency?",
    ]
    meta = symbol_metadata(s)
    if s.kind == "interface":
        questions.insert(0, "What concrete contract is actually behind this interface address?")
    if s.kind == "contract" and s.abstract:
        questions.insert(0, "Which abstract functions are implemented by the child, and did any override weaken a security invariant?")
    questions.extend(meta.get("mistakes", [])[:2])
    return list(dict.fromkeys(questions))


def symbol_record(s: Symbol, root: Path, maps) -> dict:
    why, when = explain(s)
    how, use_cases, example, audit = usage_guidance(s)
    package, forge_command = install_guidance(s, root)
    status = install_status(s, root)
    package_root = package_root_for(s.source, root)
    version = git_version(package_root) if package_root else None
    commit = git_commit(package_root) if package_root else None
    meta = symbol_metadata(s)
    return {
        "name": s.name,
        "type": kind_label(s),
        "role": meta.get("role", kind_label(s)),
        "abstract": bool(s.abstract),
        "source": str(s.source),
        "source_location": source_location(s),
        "source_status": source_status_label(s, root),
        "import_path": s.import_path,
        "import": s.import_stmt,
        "why": why,
        "when": when,
        "package": package,
        "status": status,
        "version": version or "unknown",
        "commit": commit or "unknown",
        "forge": forge_command,
        "how": how,
        "use_cases": use_cases,
        "interface_surface": interface_surface(s),
        "related": [x.name for x in related_symbols(s, root, maps)],
        "next_to_learn": meta.get("next", []),
        "common_mistakes": meta.get("mistakes", []),
        "compatibility": meta.get("compatibility", "Check the installed source/version before copying examples from another project."),
        "project_usage": [
            {"path": str(path.resolve()), "line": line, "text": text}
            for path, line, text in project_usage(s, root)
        ],
        "direct_imports": direct_imports(s.source),
        "source_web_url": source_web_url(s, root),
        "audit_lens": audit,
        "audit_questions": audit_questions(s),
    }


def print_symbol_json(s: Symbol, root: Path, maps) -> None:
    print(json.dumps(symbol_record(s, root, maps), indent=2, sort_keys=False))


def print_related(s: Symbol, root: Path, maps) -> int:
    related = related_symbols(s, root, maps)
    if not related:
        print("\nRELATED: none recorded for this symbol.")
        return 0
    print("\nRELATED / NEXT TO LEARN:")
    for item in related:
        print(f"  - {item.name} [{kind_label(item)}] -> {item.import_path}")
        print(f"    source: {source_location(item)}")
        why, _when = explain(item)
        print(f"    why: {why}")
    return 0


def search_imports(query: str, root: Path, maps) -> int:
    q = query.strip().lower()
    if not q:
        print("Usage: lk import search <term>")
        return 2
    catalog = {}
    for item in all_symbols(root, maps):
        catalog[(item.name.lower(), item.import_path)] = item
    for name in list(COMMON) + list(REFERENCE_CATALOG):
        ref = reference_symbol(name, root)
        if ref:
            catalog[(ref.name.lower(), ref.import_path)] = ref
    scored = []
    for item in catalog.values():
        meta = symbol_metadata(item)
        hay = " ".join([
            item.name,
            kind_label(item),
            item.import_path,
            meta.get("package", ""),
            meta.get("role", ""),
            meta.get("why", ""),
            meta.get("when", ""),
            " ".join(meta.get("tags", [])),
            " ".join(meta.get("use_cases", [])),
        ]).lower()
        score = 0
        for token in re.findall(r"[a-z0-9_]+", q):
            if token == item.name.lower():
                score += 100
            if token in hay:
                score += 10
            if token in " ".join(meta.get("tags", [])).lower():
                score += 25
        if score:
            scored.append((score, item))
    if not scored:
        print(f"No import-learning matches for '{query.strip()}'.")
        return 2
    scored.sort(key=lambda x: (-x[0], x[1].name.lower(), kind_label(x[1])))
    print(f"\nLOWKEY // IMPORT SEARCH • {query.strip()}")
    print("=" * 76)
    for _score, item in scored[:20]:
        print(f"{item.name} [{kind_label(item)}]")
        print(f"  import: {item.import_path}")
        print(f"  source: {source_location(item)}")
        meta = symbol_metadata(item)
        if meta.get("role"):
            print(f"  role:   {meta['role']}")
        if meta.get("tags"):
            print(f"  tags:   {', '.join(meta['tags'])}")
        print()
    return 0



def show_concept(name: str, json_mode: bool = False) -> int:
    key = name.strip().lower().replace("-", " ")
    aliases = {
        "interfaces": "interface",
        "abstract contract": "abstract",
        "abstract contracts": "abstract",
        "normal": "contract",
        "concrete contract": "contract",
    }
    key = aliases.get(key, key)
    item = LEARNING_CONCEPTS.get(key)
    if not item:
        return 2
    if json_mode:
        print(json.dumps({"concept": key, **item}, indent=2))
        return 0
    print(f"\nLOWKEY // SOLIDITY CONCEPT • {item['title']}")
    print("=" * 76)
    print(f"WHAT: {item['what']}")
    print(f"ANALOGY: {item['analogy']}")
    print(f"USE: {item['use']}")
    print(f"AUDIT: {item['audit']}")
    return 0

def print_import_graph(s: Symbol, root: Path, maps) -> int:
    print(f"\nIMPORT GRAPH • {s.name}")
    print("=" * 76)
    print(f"ROOT: {s.name} [{kind_label(s)}]")
    print(f"SOURCE: {source_location(s)}")
    print(f"IMPORT: {s.import_path}")
    imports = direct_imports(s.source)
    if imports:
        print("DIRECT DEPENDENCIES:")
        for item in imports:
            print(f"  └─ {item}")
    else:
        print("DIRECT DEPENDENCIES: none detected")
    related = related_symbols(s, root, maps)
    if related:
        print("RELATED LEARNING NODES:")
        for item in related:
            print(f"  └─ {item.name} [{kind_label(item)}] → {item.import_path}")
    uses = project_usage(s, root)
    if uses:
        print("APPLICATION EDGES:")
        for path, line, text in uses[:12]:
            print(f"  └─ {path.resolve()}:{line}  {text}")
    else:
        print("APPLICATION EDGES: no project-source references detected")
    return 0


def package_prefix(package: Path, maps: list[tuple[str, Path]]) -> str | None:
    candidates = []
    package = package.resolve()
    for prefix, target in maps:
        if not usable_prefix(prefix):
            continue
        target = target.resolve()
        if target != package and package not in target.parents:
            continue
        try:
            depth = len(target.relative_to(package).parts)
        except ValueError:
            continue
        # Prefer mappings aimed closest to the package root. This prevents a
        # nested dependency mapping from masquerading as the package prefix.
        candidates.append((
            depth,
            0 if prefix.startswith("@") else 1,
            -len(prefix),
            prefix,
        ))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][3]


def packages(root: Path, maps: list[tuple[str, Path]]) -> list[Package]:
    lib = root / "lib"
    if not lib.is_dir():
        return []
    out = []
    for p in sorted(lib.iterdir(), key=lambda x: x.name.lower()):
        if not p.is_dir() or p.name.startswith("."):
            continue
        out.append(Package(p.name, p, package_prefix(p, maps)))
    return out


def header(title: str):
    print()
    print(f"LOWKEY // IMPORT  •  {title}")
    print("=" * 76)


def search_tokens(query: str) -> list[str]:
    """
    Normalize human Solidity import searches.

    Examples:
      ERC721URIStorage,
      import {ERC721URIStorage, ERC721} from "...";
      @openzeppelin/contracts/token/ERC721/ERC721.sol
    """
    q = query.strip()
    brace = re.search(r"\{(.*?)\}", q, flags=re.S)
    if brace:
        return [x.lower() for x in re.findall(r"\b[A-Za-z_]\w*\b", brace.group(1))]
    q = re.sub(r"^\s*import\s+", "", q, flags=re.I).strip()
    q = q.strip().strip(";").strip().strip('"').strip("'")
    q = re.sub(r"[,;]+$", "", q).strip()
    if not q:
        return []
    q = re.sub(r"[^A-Za-z0-9_@./:-]", "", q)
    return [q.lower()] if q else []


def choose(items, renderer, label):
    if not items:
        print(f"No {label} found.")
        return None
    current = items
    while True:
        for i, item in enumerate(current, 1):
            print(renderer(i, item))
        try:
            a = input("\nSelect number, /search, b=back, q=quit: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if a.lower() == "q":
            raise SystemExit(0)
        if a.lower() == "b":
            return None
        if a.startswith("/"):
            tokens = search_tokens(a[1:])
            if not tokens:
                print("Enter a symbol, import path, or Solidity import declaration after '/'.")
                continue
            rendered = [renderer(0, x).lower() for x in current]
            matches = [
                x for x, text in zip(current, rendered)
                if any(token in text for token in tokens)
            ]
            if not matches:
                print(f"No matches for '{a[1:].strip()}'.")
                continue
            exact_symbols = [
                x for x in matches
                if isinstance(x, Symbol) and any(token == x.name.lower() for token in tokens)
            ]
            if len(exact_symbols) == 1:
                return exact_symbols[0]
            current = matches
            continue
        try:
            return current[int(a) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")


def sym_render(i, s):
    why, when = explain(s)
    p = f"{i:>2}. " if i else ""
    return (
        f"{p}{s.name} [{kind_label(s)}]\n"
        f"    source: {source_location(s)}\n"
        f"    import: {s.import_stmt}\n"
        f"    why: {why}\n"
        f"    when: {when}\n"
    )


def pkg_render(i, p):
    lead = f"{i:>2}. " if i else ""
    return f"{lead}{p.name}\n    path: {p.path}\n    prefix: {p.prefix or '(no remapping detected)'}\n"


def file_render(i, item):
    path, syms = item
    lead = f"{i:>2}. " if i else ""
    names = ", ".join(s.name for s in syms[:10])
    if len(syms) > 10:
        names += " ..."
    return f"{lead}{path}\n    import: {syms[0].import_path}\n    exports: {names}\n"


def combined_import(symbols: list[Symbol], aliases: dict[str, str] | None = None) -> list[str]:
    """Build copy-ready imports, grouping symbols by their verified source."""
    groups: dict[str, list[Symbol]] = {}
    aliases = aliases or {}
    for symbol in symbols:
        groups.setdefault(symbol.import_path, []).append(symbol)

    lines = []
    for path, grouped in groups.items():
        names = ", ".join(
            f"{symbol.name} as {aliases[symbol.name]}" if symbol.name in aliases else symbol.name
            for symbol in grouped
        )
        lines.append(f'import {{{names}}} from "{path}";')
    return lines


def show_copy_imports(symbols: list[Symbol], requested_path: str | None = None, aliases: dict[str, str] | None = None, copy_only: bool = False):
    if not copy_only:
        print("\nCOPY:")
    for stmt in combined_import(symbols, aliases=aliases):
        print(f"  {stmt}")
    if requested_path and not copy_only:
        actual = sorted({s.import_path for s in symbols})
        if requested_path not in actual:
            print()
            print(f"NOTE: requested path was not the defining source: {requested_path}")
            print("      Lowkey used the verified source path(s) above.")


def show_symbol(
    s: Symbol,
    root: Path | None = None,
    maps=None,
    json_mode: bool = False,
    copy_only: bool = False,
    verbose: bool = False,
):
    root = root or root_for()
    maps = maps if maps is not None else remappings(root)
    if json_mode:
        print_symbol_json(s, root, maps)
        return
    if copy_only:
        show_copy_imports([s], copy_only=True)
        return
    why, _when = explain(s)
    how, _use_cases, _example, _audit = usage_guidance(s)
    print()
    print(f"NAME:   {s.name}")
    print(f"TYPE:   {kind_label(s)}")
    print(f"SOURCE: {source_location(s)}")
    print(f"IMPORT: {s.import_stmt}")
    print(f"WHY:    {why}")
    print(f"HOW:    {how}")
    if s.kind == "interface":
        surface = interface_surface(s)
        if surface:
            print("API:")
            for method in surface:
                print(f"  - {method}")
    related = related_symbols(s, root, maps)
    if related:
        print("RELATED:")
        for item in related:
            print(f"  - {item.name} [{kind_label(item)}] -> {source_location(item)}")
    if s.line > 0 and not s.source.name.startswith("(reference only"):
        print("EDITOR: Ctrl+Click SOURCE above to open the exact file/line.")
    show_copy_imports([s])
    if not verbose:
        return
    meta = symbol_metadata(s)
    package, forge_command = install_guidance(s, root)
    status = install_status(s, root)
    package_root = package_root_for(s.source, root)
    print()
    print("DETAILS:")
    print(f"  ROLE:       {meta.get('role', kind_label(s))}")
    print(f"  SOURCE KIND:{'  ' + source_status_label(s, root)}")
    print(f"  PACKAGE:    {package}")
    print(f"  STATUS:     {status}")
    print(f"  VERSION:    {git_version(package_root) if package_root else 'not installed / not versioned'}")
    print(f"  COMMIT:     {git_commit(package_root) if package_root else 'n/a'}")
    print(f"  FORGE:      {forge_command}")
    official = official_package(package_root)
    if official.get('repo'):
        print(f"  UPSTREAM:   {official['repo']}")
    url = source_web_url(s, root)
    if url:
        print(f"  SOURCE URL: {url}")
    if meta.get("use_cases"):
        print("  USE CASES:")
        for item in meta["use_cases"]:
            print(f"    - {item}")
    if meta.get("next"):
        print("  NEXT:")
        for item in meta["next"]:
            print(f"    - {item}")
    imports = direct_imports(s.source)
    if imports:
        print("  DEPENDS ON:")
        for item in imports[:24]:
            print(f"    - {item}")
    usage = project_usage(s, root)
    if usage:
        print("  PROJECT USAGE:")
        for path, line, text in usage[:20]:
            print(f"    - {path.resolve()}:{line}  {text}")
    if meta.get("compatibility"):
        print(f"  COMPATIBILITY: {meta['compatibility']}")
    mistakes = meta.get("mistakes", [])
    if mistakes:
        print("  COMMON MISTAKES:")
        for item in mistakes:
            print(f"    - {item}")
    audit = usage_guidance(s)[3]
    if audit:
        print(f"  AUDIT LENS: {audit}")
    questions = audit_questions(s)
    if questions:
        print("  AUDIT QUESTIONS:")
        for item in questions[:12]:
            print(f"    ? {item}")

def show_file(item):
    path, syms = item
    line = syms[0].line if syms else 1
    print()
    print(f"SOURCE:      {path.resolve()}:{line}")
    print(f"IMPORT FILE: {syms[0].import_path}")
    print("IMPORTABLE SYMBOLS:")
    for s in syms:
        print(f"  {s.name} [{kind_label(s)}] — {source_location(s)}")
        print(f"    {s.import_stmt}")


def browse_package(p: Package, root: Path, maps):
    while True:
        header(f"PACKAGE • {p.name}")
        print(f"Path: {p.path}")
        print(f"Import prefix: {p.prefix or '(none detected)'}")
        print()
        print("  1. Contracts / abstract contracts")
        print("  2. Interfaces")
        print("  3. Libraries")
        print("  4. Structs / enums / types / errors / constants")
        print("  5. Source files")
        print("  6. Search this package")
        print("  b. Back")
        a = input("\nSelect: ").strip().lower()
        if a == "b":
            return
        kinds = {
            "1": {"contract"}, "2": {"interface"}, "3": {"library"},
            "4": {"struct", "enum", "type", "error", "constant"},
        }
        if a == "5":
            items = [(x, extract(x, root, maps)) for x in sol_files(p.path)]
            items = [x for x in items if x[1]]
            s = choose(items, file_render, "source files")
            if s:
                show_file(s)
        elif a == "6":
            q = input("Search package for: ").strip().lower()
            if q:
                items = []
                for source in sol_files(p.path):
                    syms = extract(source, root, maps)
                    if q in source.as_posix().lower() or any(q in x.name.lower() for x in syms):
                        items.extend(syms)
                s = choose(items, sym_render, "package matches")
                if s:
                    show_symbol(s, root, maps)
        elif a in kinds:
            syms = []
            for source in sol_files(p.path):
                syms += [s for s in extract(source, root, maps) if s.kind in kinds[a]]
            syms = sorted({(s.kind, s.name, s.import_path): s for s in syms}.values(),
                          key=lambda s: (s.name.lower(), s.kind, str(s.source)))
            s = choose(syms, sym_render, "symbols")
            if s:
                show_symbol(s, root)
        else:
            print("Pick 1-6 or b.")


def common():
    header("COMMON REFERENCE IMPORTS")
    print("These are verified reference entries. Use lk import <symbol> for the")
    print("full install, usage, use-case, and audit guide; lookup never mutates a project.")
    print()
    for i, (name, (why, when, path)) in enumerate(COMMON.items(), 1):
        meta = known_metadata(name)
        package = meta.get("package", "Unknown package")
        install = meta.get("forge_install", "No verified Forge install command")
        print(f"{i:>2}. {name}")
        print(f"    package: {package}")
        print(f"    forge:   {install}")
        print(f"    import:  import {{{name}}} from \"{path}\";")
        print(f"    why:     {why}")
        print(f"    when:    {when}")
        if meta.get("role"):
            print(f"    role:    {meta['role']}")
        if meta.get("tags"):
            print(f"    tags:    {', '.join(meta['tags'])}")
        if meta.get("use_cases"):
            print(f"    use:     {', '.join(meta['use_cases'])}")
        print()


def parse_import_query(
    query: str,
) -> tuple[list[tuple[str, str | None]], str | None, str, str | None]:
    """Parse a pasted Solidity import declaration."""
    q = query.strip()

    match = re.fullmatch(
        r'\s*import\s*\{(.*?)\}\s*from\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        imports = []
        for item in match.group(1).split(','):
            item = item.strip()
            if not item:
                continue
            parts = re.split(r'\s+as\s+', item, maxsplit=1, flags=re.I)
            name = parts[0].strip()
            alias = parts[1].strip() if len(parts) == 2 else None
            if not re.fullmatch(r'[A-Za-z_]\w*', name):
                continue
            if alias and not re.fullmatch(r'[A-Za-z_]\w*', alias):
                alias = None
            imports.append((name, alias))
        return imports, match.group(2), 'symbols', None

    match = re.fullmatch(
        r'\s*import\s*\*\s*as\s+([A-Za-z_]\w*)\s*from\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        return [], match.group(2), 'namespace', match.group(1)

    match = re.fullmatch(
        r'\s*import\s*["\']([^"\']+)["\']\s*;?\s*',
        q,
        flags=re.I | re.S,
    )
    if match:
        return [], match.group(1), 'file', None

    return [], None, 'search', None

def importable_files(root: Path, maps) -> list[tuple[Path, str]]:
    files = list(sol_files(root / 'src')) + list(sol_files(root / 'lib'))
    return [(path, import_path(path, root, maps)) for path in files]


def find_import_path(path_query: str, root: Path, maps):
    target = path_query.strip().strip('"').strip("'")
    for source, resolved in importable_files(root, maps):
        if resolved == target or resolved.lower() == target.lower():
            return source, resolved
    return None


def print_import_file(
    path: str,
    root: Path,
    maps,
    mode: str,
    namespace_alias: str | None = None,
) -> int:
    resolved = find_import_path(path, root, maps)
    if not resolved:
        print(f"No Solidity source file resolves to import path '{path}'.")
        return 2
    source, import_name = resolved
    print()
    print(f"SOURCE:      {source}")
    print(f"IMPORT FILE: {import_name}")
    print("COPY:")
    if mode == 'namespace':
        alias = namespace_alias or 'Lib'
        print(f'  import * as {alias} from "{import_name}";')
    else:
        print(f'  import "{import_name}";')
    return 0


def import_query(query: str, root: Path, maps, install: bool = False, dry_run: bool = False, json_mode: bool = False, copy_only: bool = False, verbose: bool = False) -> int:
    requested_imports, requested_path, mode, namespace_alias = parse_import_query(query)
    tokens = [name for name, _alias in requested_imports]

    if mode in {'file', 'namespace'}:
        return print_import_file(requested_path, root, maps, mode, namespace_alias)

    if mode == 'symbols':
        if not tokens:
            print('No imported symbols found inside the declaration.')
            return 2

        syms = all_symbols(root, maps)
        by_name: dict[str, list[Symbol]] = {}
        for symbol in syms:
            by_name.setdefault(symbol.name.lower(), []).append(symbol)

        found = []
        missing = []
        aliases: dict[str, str] = {}
        for name, alias in requested_imports:
            candidates = by_name.get(name.lower(), [])
            if requested_path:
                same_file = [s for s in candidates if s.import_path == requested_path]
                if same_file:
                    candidates = same_file
            if candidates:
                found.append(candidates[0])
                if alias:
                    aliases[candidates[0].name] = alias
            else:
                missing.append(name)

        unique_found = []
        seen = set()
        for symbol in found:
            key = (symbol.name.lower(), symbol.import_path)
            if key not in seen:
                seen.add(key)
                unique_found.append(symbol)

        if missing:
            reference_found = []
            still_missing = []
            for name in missing:
                ref = reference_symbol(name, root)
                if ref:
                    reference_found.append(ref)
                else:
                    still_missing.append(name)
            if reference_found:
                unique_found.extend(reference_found)
            if still_missing:
                print('UNRESOLVED SYMBOLS:')
                for name in still_missing:
                    print(f'  - {name}')
                if unique_found:
                    print()
                    print('RESOLVED SYMBOLS:')
                    for symbol in unique_found:
                        print(f'  - {symbol.name} -> {symbol.import_path}')
                return 2
            print()
            print(f'RESOLVED {len(unique_found)} SYMBOL(S)')
            for symbol in unique_found:
                show_symbol(symbol, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
            show_copy_imports(unique_found, requested_path=requested_path, aliases=aliases)
            if install:
                return install_symbols(unique_found, root, dry_run=dry_run)
            return 0

        print()
        print(f'RESOLVED {len(unique_found)} SYMBOL(S)')
        for symbol in unique_found:
            print(f'  {symbol.name} [{symbol.kind}] -> {symbol.import_path}')
        for symbol in unique_found:
            show_symbol(symbol, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
        show_copy_imports(unique_found, requested_path=requested_path, aliases=aliases)
        if len({s.import_path for s in unique_found}) > 1:
            print()
            print('NOTE: symbols came from different source files, so Lowkey emitted separate valid imports.')
        if install:
            return install_symbols(unique_found, root, dry_run=dry_run)
        return 0

    if not tokens:
        tokens = search_tokens(query)

    if not tokens:
        path_match = find_import_path(query, root, maps)
        if path_match:
            source, import_name = path_match
            symbols = [s for s in all_symbols(root, maps) if s.import_path == import_name]
            if symbols:
                show_file((source, symbols))
            else:
                print()
                print(f'SOURCE:      {source}')
                print(f'IMPORT FILE: {import_name}')
                print('COPY:')
                print(f'  import "{import_name}";')
            return 0
        print('No import query provided.')
        return 2

    path_query = query.strip().strip('"').strip("'")
    if path_query.lower().endswith(".sol"):
        path_match = find_import_path(path_query, root, maps)
        if path_match:
            source, import_name = path_match
            symbols = [s for s in all_symbols(root, maps) if s.import_path == import_name]
            if symbols:
                show_file((source, symbols))
            else:
                print()
                print(f"SOURCE:      {source}")
                print(f"IMPORT FILE: {import_name}")
                print("COPY:")
                print(f'  import "{import_name}";')
            return 0

    syms = all_symbols(root, maps)
    exact = [s for s in syms if s.name.lower() in tokens or s.import_path.lower() in tokens]
    if len(exact) == 1:
        show_symbol(exact[0], root, maps, json_mode=json_mode, copy_only=copy_only)
        return 0

    matches = [
        s for s in syms
        if any(token in s.name.lower() or token in s.import_path.lower() for token in tokens)
    ]
    if not matches:
        known_matches = []
        for name in list(COMMON) + list(REFERENCE_CATALOG):
            if any(token == name.lower() for token in tokens):
                ref = reference_symbol(name, root)
                if ref:
                    known_matches.append(ref)
        if known_matches:
            if len(known_matches) == 1:
                show_symbol(known_matches[0], root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
                if install:
                    return install_symbols(known_matches, root, dry_run=dry_run)
                return 0
            s = choose(known_matches, sym_render, 'known import references')
            if s:
                show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
                if install:
                    return install_symbols([s], root, dry_run=dry_run)
            return 0
        choices = sorted(
            {s.name for s in syms},
            key=lambda name: difflib.SequenceMatcher(None, tokens[0], name.lower()).ratio(),
            reverse=True,
        )[:3]
        print(f"No importable symbol or source file matches '{query.strip()}'.")
        if choices and difflib.SequenceMatcher(None, tokens[0], choices[0].lower()).ratio() >= 0.45:
            print('Did you mean:')
            for name in choices:
                print(f'  - {name}')
        print('Try: lk import /<symbol>, lk import <symbol>, or lk import files')
        return 2

    s = choose(matches, sym_render, 'matching importable symbols')
    if s:
        show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
    return 0

def resolve_single_symbol(query: str, root: Path, maps) -> Symbol | None:
    tokens = search_tokens(query)
    syms = all_symbols(root, maps)
    exact = [s for s in syms if tokens and (s.name.lower() in tokens or s.import_path.lower() in tokens)]
    if len(exact) == 1:
        return exact[0]
    for token in tokens:
        ref = reference_symbol(token, root)
        if ref:
            return ref
    return None


def run_learning_command(category: str, root: Path, maps, json_mode: bool = False, copy_only: bool = False, verbose: bool = False) -> int:
    parts = category.split(None, 1)
    command = parts[0].lower() if parts else ""
    query = parts[1].strip() if len(parts) > 1 else ""
    if command == "search":
        return search_imports(query, root, maps)
    if command == "explain" and query.strip().lower().replace("-", " ") in {"interface", "interfaces", "abstract", "abstract contract", "abstract contracts", "normal", "concrete contract", "contract"}:
        return show_concept(query, json_mode=json_mode)
    if command in {"explain", "usage", "audit", "related", "graph"}:
        symbol = resolve_single_symbol(query, root, maps)
        if not symbol:
            print(f"No import-learning symbol matches '{query}'.")
            return 2
        if command == "related":
            return print_related(symbol, root, maps)
        if command == "graph":
            return print_import_graph(symbol, root, maps)
        if command == "usage":
            if json_mode:
                data = symbol_record(symbol, root, maps)
                print(json.dumps({"name": symbol.name, "project_usage": data["project_usage"]}, indent=2))
                return 0
            uses = project_usage(symbol, root)
            print(f"\nPROJECT USAGE • {symbol.name}")
            print("=" * 76)
            if not uses:
                print("No project-source usage found.")
            for path, line, text in uses:
                print(f"  {path.resolve()}:{line}  {text}")
            return 0
        show_symbol(symbol, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
        if command == "audit" and not json_mode:
            print()
            print("AUDITOR VIEW: start from the questions above; these are hypotheses to investigate, not a verdict.")
        return 0
    return import_query(category, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)


def run_category(category: str, root: Path, maps, install: bool = False, dry_run: bool = False, json_mode: bool = False, copy_only: bool = False, verbose: bool = False) -> int:
    category = category.strip()
    cat = category.lower()
    if cat.startswith(("search ", "explain ", "usage ", "audit ", "related ", "graph ")):
        return run_learning_command(category, root, maps, json_mode=json_mode, copy_only=copy_only, verbose=verbose)
    if cat in {"packages", "package", "deps"}:
        header("INSTALLED PACKAGES")
        p = choose(packages(root, maps), pkg_render, "installed packages")
        if p:
            browse_package(p, root, maps)
        return 0
    if cat in {"contracts", "contract"}:
        header("CONTRACTS / ABSTRACT CONTRACTS")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "contract"], sym_render, "contracts")
        if s:
            show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only)
        return 0
    if cat in {"interfaces", "interface"}:
        header("INTERFACES")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "interface"], sym_render, "interfaces")
        if s:
            show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only)
        return 0
    if cat in {"libraries", "library"}:
        header("SOLIDITY LIBRARIES")
        s = choose([x for x in all_symbols(root, maps) if x.kind == "library"], sym_render, "libraries")
        if s:
            show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only)
        return 0
    if cat in {"types", "structs", "errors", "type"}:
        header("STRUCTS / ENUMS / TYPES / ERRORS / CONSTANTS")
        s = choose([x for x in all_symbols(root, maps) if x.kind in {"struct", "enum", "type", "error", "constant"}], sym_render, "types")
        if s:
            show_symbol(s, root, maps, json_mode=json_mode, copy_only=copy_only)
        return 0
    if cat in {"files", "file", "source", "sources"}:
        header("IMPORTABLE SOURCE FILES")
        items = [(p, extract(p, root, maps)) for p in list(sol_files(root / "src")) + list(sol_files(root / "lib"))]
        items = [x for x in items if x[1]]
        s = choose(items, file_render, "source files")
        if s:
            show_file(s)
        return 0
    if cat in {"mappings", "mapping", "remappings"}:
        header("FORGE IMPORT MAPPINGS")
        if not maps:
            print("No remappings detected.")
        else:
            for prefix, target in maps:
                print(f"{prefix}= {target}")
        return 0
    if cat in {"common", "known"}:
        common()
        return 0
    if cat.startswith("--install "):
        install = True
        category = category[10:].strip()
    if cat.startswith("install "):
        install = True
        category = category[8:].strip()
    if install:
        symbol = resolve_single_symbol(category, root, maps)
        if symbol:
            if not copy_only:
                show_symbol(symbol, root, maps, json_mode=json_mode)
            else:
                show_symbol(symbol, root, maps, copy_only=True)
            return install_symbols([symbol], root, dry_run=dry_run)
    return import_query(category, root, maps, install=install, dry_run=dry_run, json_mode=json_mode, copy_only=copy_only, verbose=verbose)


def interactive(root: Path, maps) -> int:
    header("IMPORT BROWSER")
    print("A standalone learning lookup. It does not touch audit/target/RPC state.\n")
    print("  1. Installed packages")
    print("  2. Contracts / abstract contracts")
    print("  3. Interfaces")
    print("  4. Solidity libraries")
    print("  5. Structs / enums / types / errors / constants")
    print("  6. Source files")
    print("  7. Forge import mappings")
    print("  8. Common reference imports")
    print("  9. Search import concepts (nft, oracle, access, token, reentrancy)")
    print("  q. Quit")
    while True:
        a = input("\nSelect: ").strip().lower()
        if a == "q":
            return 0
        cat = {"1":"packages","2":"contracts","3":"interfaces","4":"libraries","5":"types","6":"files","7":"mappings","8":"common"}.get(a)
        if a == "9":
            query = input("Search concept: ").strip()
            if query:
                search_imports(query, root, maps)
            continue
        if not cat:
            print("Pick 1-9 or q.")
            continue
        run_category(cat, root, maps)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].lower() in {"--h", "--help", "-h", "help"}:
        print(HELP.strip())
        return 0

    install = False
    dry_run = False
    json_mode = False
    copy_only = False
    verbose = False
    cleaned = []
    for arg in args:
        flag = arg.lower()
        if flag == "--install":
            install = True
            continue
        if flag == "--dry-run":
            dry_run = True
            continue
        if flag == "--json":
            json_mode = True
            continue
        if flag in {"--copy-only", "--copy"}:
            copy_only = True
            continue
        if flag in {"--verbose", "-v"}:
            verbose = True
            continue
        cleaned.append(arg)

    root = root_for()
    maps = remappings(root)
    if not cleaned:
        if install or dry_run or json_mode or copy_only:
            print("Usage: lk import [--install] [--dry-run] [--json] [--copy-only] [--verbose] <symbol>")
            return 2
        try:
            return interactive(root, maps)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    query = " ".join(cleaned)
    if install:
        query = f"--install {query}"
    return run_category(
        query,
        root,
        maps,
        install=install,
        dry_run=dry_run,
        json_mode=json_mode,
        copy_only=copy_only,
        verbose=verbose,
    )


if __name__ == "__main__":
    raise SystemExit(main())
