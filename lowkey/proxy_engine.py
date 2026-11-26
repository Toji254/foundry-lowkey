"""Evidence-first proxy reconnaissance and upgrade-safety helpers for Lowkey.

This module is intentionally read-only. It does not broadcast transactions, impersonate
production accounts, or claim that a heuristic is an exploit proof. Runtime facts are
pinned to one block and RPC failures remain explicit in the returned evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_UUID = EIP1967_IMPLEMENTATION_SLOT.lower()
ZERO_ADDRESS = "0x" + "0" * 40
DIAMOND_FACET_ADDRESSES = "0x52ef6b2c"
DIAMOND_FACET_SELECTORS = "0xadfca15e"
PROXIABLE_UUID_SELECTOR = "0x52d1902d"
SENTINEL_CALLERS = (
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
)
MAX_DIAMOND_FACETS = 64


class ProxyError(RuntimeError):
    """Expected proxy-inspection failure with a user-actionable message."""


def is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value.strip()))


def _hex_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        return None
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        return None


def _decode_slot_address(value: Any) -> tuple[str | None, str]:
    """Decode a canonical EIP-1967 address word; reject malformed high bytes."""
    raw = _hex_bytes(value)
    if raw is None or len(raw) != 32:
        return None, "malformed or unavailable 32-byte slot value"
    if raw[:12] != b"\x00" * 12:
        return None, "slot word has non-zero high 12 bytes; not a canonical address"
    address = "0x" + raw[12:].hex()
    if address.lower() == ZERO_ADDRESS:
        return None, "slot is zero"
    return address, "non-zero canonical address"


def _minimal_clone_implementation(runtime: str) -> str | None:
    """Recognize the exact deployed runtime of the canonical ERC-1167 minimal proxy."""
    raw = str(runtime or "").strip().lower().removeprefix("0x")
    match = re.fullmatch(
        r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3",
        raw,
    )
    return "0x" + match.group(1) if match else None


def _has_opcode(runtime: str, wanted: int) -> bool:
    """Walk EVM instruction bytes, skipping PUSH data rather than matching raw hex."""
    code = _hex_bytes(runtime)
    if code is None:
        return False
    index = 0
    while index < len(code):
        opcode = code[index]
        index += 1
        if opcode == wanted:
            return True
        if 0x60 <= opcode <= 0x7F:
            index += opcode - 0x5F
    return False


# A small dependency-free Keccak-256 implementation for ABI selector derivation.
_MASK64 = (1 << 64) - 1
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_R = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256 (not NIST SHA3-256)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:(lane + 1) * 8], "little")
        for rc in _KECCAK_RC:
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] ^= d[x]
            b = [0] * 25
            for y in range(5):
                for x in range(5):
                    new_x = y
                    new_y = (2 * x + 3 * y) % 5
                    b[new_x + 5 * new_y] = _rol64(state[x + 5 * y], _KECCAK_R[x][y])
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] = b[x + 5 * y] ^ (
                        (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
                    )
                    state[x + 5 * y] &= _MASK64
            state[0] ^= rc
    output = b"".join(value.to_bytes(8, "little") for value in state[:rate // 8])
    return output[:32]


def function_selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()[:8]


class RpcClient:
    """JSON-RPC client that pins every state read to one block number."""

    def __init__(self, url: str, timeout: float = 8.0):
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ProxyError("A valid HTTP(S) RPC URL is required.")
        self.url = url
        self.timeout = timeout
        self.block_tag = "latest"
        self.block_number: int | None = None
        self.block_hash: str | None = None
        self.chain_id: int | None = None
        self._request_id = 0

    def request(self, method: str, params: list[Any] | None = None) -> Any:
        self._request_id += 1
        payload = json.dumps({
            "jsonrpc": "2.0", "id": self._request_id,
            "method": method, "params": params or [],
        }).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ProxyError(f"RPC {method} failed: {exc}") from exc
        if not isinstance(body, dict):
            raise ProxyError(f"RPC {method} returned a non-object response.")
        if body.get("error") is not None:
            error = body["error"]
            message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
            raise ProxyError(f"RPC {method} error: {message}")
        if "result" not in body:
            raise ProxyError(f"RPC {method} response omitted result.")
        return body["result"]

    def pin(self, requested_block: int | None = None) -> dict[str, Any]:
        chain_raw = self.request("eth_chainId", [])
        block_raw = (
            hex(requested_block) if requested_block is not None
            else self.request("eth_blockNumber", [])
        )
        try:
            self.chain_id = int(str(chain_raw), 16)
            self.block_number = int(str(block_raw), 16)
        except (TypeError, ValueError) as exc:
            raise ProxyError("RPC returned an invalid chain ID or block number.") from exc
        block = self.request("eth_getBlockByNumber", [hex(self.block_number), False])
        if not isinstance(block, dict) or not block.get("hash"):
            raise ProxyError(f"Block {self.block_number} could not be resolved.")
        self.block_hash = str(block["hash"]).lower()
        self.block_tag = hex(self.block_number)
        return {
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "timestamp": int(str(block.get("timestamp", "0x0")), 16),
        }

    def verify_snapshot(self) -> bool:
        if self.block_number is None or not self.block_hash:
            return False
        block = self.request("eth_getBlockByNumber", [hex(self.block_number), False])
        return isinstance(block, dict) and str(block.get("hash", "")).lower() == self.block_hash

    def code(self, address: str) -> str:
        value = self.request("eth_getCode", [address, self.block_tag])
        if not isinstance(value, str) or _hex_bytes(value) is None:
            raise ProxyError(f"eth_getCode returned malformed bytecode for {address}.")
        return value.lower()

    def storage(self, address: str, slot: str) -> str:
        value = self.request("eth_getStorageAt", [address, slot, self.block_tag])
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
            raise ProxyError(f"eth_getStorageAt returned malformed data for slot {slot}.")
        return value.lower()

    def call(self, to: str, data: str, caller: str = SENTINEL_CALLERS[0]) -> str:
        value = self.request(
            "eth_call",
            [{"to": to, "from": caller, "data": data}, self.block_tag],
        )
        if not isinstance(value, str) or _hex_bytes(value) is None:
            raise ProxyError(f"eth_call returned malformed data for {to}.")
        return value.lower()


def _decode_returned_address(data: str) -> str | None:
    raw = _hex_bytes(data)
    if raw is None or len(raw) != 32 or raw[:12] != b"\x00" * 12:
        return None
    address = "0x" + raw[12:].hex()
    return None if address == ZERO_ADDRESS else address


def _decode_dynamic_array(data: str, item_bytes: int, address_items: bool = False) -> list[str] | None:
    raw = _hex_bytes(data)
    if raw is None or len(raw) < 64:
        return None
    offset = int.from_bytes(raw[:32], "big")
    if offset % 32 or offset + 32 > len(raw):
        return None
    count = int.from_bytes(raw[offset:offset + 32], "big")
    if count > MAX_DIAMOND_FACETS or offset + 32 + count * 32 > len(raw):
        return None
    items = []
    for index in range(count):
        word = raw[offset + 32 + index * 32:offset + 64 + index * 32]
        if address_items:
            if word[:12] != b"\x00" * 12 or word[12:] == b"\x00" * 20:
                return None
            items.append("0x" + word[12:].hex())
        else:
            if word[4:] != b"\x00" * 28:
                return None
            items.append("0x" + word[:4].hex())
    return items


def _diamond_loupe(client: RpcClient, target: str) -> dict[str, Any] | None:
    """Require a coherent loupe address list, per-facet selector lists and live code."""
    try:
        raw = client.call(target, DIAMOND_FACET_ADDRESSES)
        facets = _decode_dynamic_array(raw, 32, address_items=True)
        if not facets:
            return None
        checked = []
        for facet in facets[:MAX_DIAMOND_FACETS]:
            selectors_data = client.call(
                target,
                DIAMOND_FACET_SELECTORS + facet[2:].lower().rjust(64, "0"),
            )
            selectors = _decode_dynamic_array(selectors_data, 32, address_items=False)
            if not selectors:
                return None
            facet_code = client.code(facet)
            if facet_code == "0x":
                return None
            checked.append({
                "address": facet,
                "selectors": selectors,
                "code_sha256": hashlib.sha256(bytes.fromhex(facet_code[2:])).hexdigest(),
            })
        return {"facets": checked, "facet_count": len(facets)}
    except ProxyError:
        return None


def inspect_proxy(
    rpc_url: str,
    target: str,
    requested_block: int | None = None,
    abi: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Inspect one target against a consistent block-pinned RPC snapshot."""
    report: dict[str, Any] = {
        "schema": "lowkey.proxy.v1",
        "target": target,
        "status": "UNVERIFIED",
        "architecture": "UNKNOWN",
        "upgrade_mechanisms": [],
        "confidence": "NONE",
        "snapshot": None,
        "evidence": [],
        "warnings": [],
        "errors": [],
        "addresses": {},
        "checks": {},
    }
    if not is_address(target):
        report["errors"].append("Target must be a 20-byte hexadecimal address.")
        return report

    client = RpcClient(rpc_url)
    try:
        report["snapshot"] = client.pin(requested_block)
        runtime = client.code(target)
        if runtime == "0x":
            report["status"] = "NO_CODE"
            report["warnings"].append("The selected address has no runtime bytecode at the pinned block.")
            return report
        report["target_code_sha256"] = hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()

        slot_results = {}
        for name, slot in (
            ("implementation", EIP1967_IMPLEMENTATION_SLOT),
            ("beacon", EIP1967_BEACON_SLOT),
            ("admin", EIP1967_ADMIN_SLOT),
        ):
            try:
                raw = client.storage(target, slot)
                address, explanation = _decode_slot_address(raw)
                slot_results[name] = {"read": True, "raw": raw, "address": address, "explanation": explanation}
            except ProxyError as exc:
                slot_results[name] = {"read": False, "raw": None, "address": None, "explanation": str(exc)}
                report["errors"].append(str(exc))

        report["checks"]["eip1967_slots"] = slot_results
        impl = slot_results["implementation"]["address"]
        beacon = slot_results["beacon"]["address"]
        admin_slot = slot_results["admin"]["address"]
        report["slot_candidates"] = {
            "implementation": impl,
            "beacon": beacon,
            "admin": admin_slot,
        }
        report["addresses"]["admin_slot_candidate"] = admin_slot

        # The EIP-1967 beacon slot is meaningful only when the implementation slot is empty.
        if impl and beacon:
            report["architecture"] = "CONFLICTING_EIP1967_SLOTS"
            report["confidence"] = "HIGH"
            report["status"] = "REVIEW_REQUIRED"
            report["warnings"].append(
                "Both implementation and beacon slots are non-zero. ERC-1967 says the beacon slot "
                "should only be considered when the implementation slot is empty; no routing choice was guessed."
            )
        elif not slot_results["implementation"]["read"] or not slot_results["beacon"]["read"]:
            report["architecture"] = "UNVERIFIED_EIP1967"
            report["status"] = "UNVERIFIED"
            report["warnings"].append("Implementation/beacon precedence could not be established because a slot read failed.")
        elif impl:
            report["addresses"]["implementation"] = impl
            report["architecture"] = "ERC1967_IMPLEMENTATION_PROXY"
            report["confidence"] = "HIGH"
            report["status"] = "OBSERVED"
            try:
                impl_code = client.code(impl)
                report["addresses"]["implementation_has_code"] = impl_code != "0x"
                if impl_code == "0x":
                    report["status"] = "REVIEW_REQUIRED"
                    report["warnings"].append("The implementation slot points to an address without runtime code.")
                else:
                    report["addresses"]["implementation_code_sha256"] = hashlib.sha256(
                        bytes.fromhex(impl_code[2:])
                    ).hexdigest()
            except ProxyError as exc:
                report["errors"].append(str(exc))
                report["status"] = "UNVERIFIED"
            try:
                uuid = client.call(impl, PROXIABLE_UUID_SELECTOR)
                raw_uuid = _hex_bytes(uuid)
                matches = raw_uuid is not None and len(raw_uuid) == 32 and uuid.lower() == EIP1967_UUID
                report["checks"]["proxiable_uuid"] = {
                    "status": "MATCH" if matches else "NO_MATCH",
                    "value": uuid,
                    "note": "Direct implementation call only; a matching UUID is a UUPS-compatible signal, not proof of authorization safety or exclusive UUPS routing.",
                }
                if matches:
                    report["upgrade_mechanisms"].append("UUPS_COMPATIBLE_IMPLEMENTATION")
                    report["evidence"].append("Implementation directly returned the ERC-1967 implementation slot from proxiableUUID().")
            except ProxyError as exc:
                report["checks"]["proxiable_uuid"] = {
                    "status": "UNAVAILABLE",
                    "note": "The implementation did not provide a readable proxiableUUID() result.",
                    "error": str(exc),
                }
            if admin_slot:
                report["upgrade_mechanisms"].append("PROXY_ADMIN_SLOT_PRESENT")
                report["warnings"].append(
                    "The EIP-1967 admin slot is a candidate signal, not proof of the effective admin. "
                    "Immutable-admin proxy designs can diverge from this mirrored slot."
                )
            if not admin_slot:
                report["evidence"].append("No non-zero EIP-1967 admin storage value was observed; this does not exclude UUPS or immutable-admin designs.")
        elif beacon:
            report["addresses"]["beacon"] = beacon
            report["architecture"] = "ERC1967_BEACON_PROXY"
            report["confidence"] = "HIGH"
            report["status"] = "OBSERVED"
            report["addresses"]["beacon_has_code"] = False
            try:
                beacon_code = client.code(beacon)
                report["addresses"]["beacon_has_code"] = beacon_code != "0x"
                if beacon_code == "0x":
                    report["status"] = "REVIEW_REQUIRED"
                    report["warnings"].append("Beacon slot points to an address without runtime code.")
                else:
                    results = []
                    for caller in SENTINEL_CALLERS:
                        try:
                            result = client.call(beacon, function_selector("implementation()"), caller=caller)
                            results.append({"caller": caller, "raw": result, "implementation": _decode_returned_address(result)})
                        except ProxyError as exc:
                            results.append({"caller": caller, "error": str(exc), "implementation": None})
                    report["checks"]["beacon_implementation"] = results
                    addresses = {row.get("implementation") for row in results if row.get("implementation")}
                    if len(addresses) == 1 and all(row.get("implementation") for row in results):
                        resolved = next(iter(addresses))
                        report["addresses"]["implementation"] = resolved
                        report["checks"]["beacon_caller_independence"] = "CONSISTENT_FOR_TWO_SENTINEL_CALLERS"
                        resolved_code = client.code(resolved)
                        report["addresses"]["implementation_has_code"] = resolved_code != "0x"
                        if resolved_code == "0x":
                            report["status"] = "REVIEW_REQUIRED"
                            report["warnings"].append("Beacon implementation() resolves to an address without runtime code.")
                    elif len(addresses) > 1:
                        report["checks"]["beacon_caller_independence"] = "CALLER_DEPENDENT"
                        report["status"] = "REVIEW_REQUIRED"
                        report["warnings"].append("Beacon implementation() returned different values for two read-only caller probes.")
                    else:
                        report["checks"]["beacon_caller_independence"] = "INCONCLUSIVE"
                        report["status"] = "UNVERIFIED"
                        report["warnings"].append("Beacon implementation() could not be resolved consistently.")
            except ProxyError as exc:
                report["errors"].append(str(exc))
                report["status"] = "UNVERIFIED"
            report["upgrade_mechanisms"].append("BEACON_CONTROLLED")
            if admin_slot:
                report["addresses"]["admin_slot_candidate"] = admin_slot
                report["warnings"].append("Beacon admin slot is recorded as a candidate only; it does not establish beacon ownership.")
        else:
            clone_impl = _minimal_clone_implementation(runtime)
            if clone_impl:
                report["architecture"] = "EIP1167_MINIMAL_CLONE"
                report["confidence"] = "HIGH"
                report["status"] = "OBSERVED"
                report["addresses"]["implementation"] = clone_impl
                impl_code = client.code(clone_impl)
                report["addresses"]["implementation_has_code"] = impl_code != "0x"
                if impl_code == "0x":
                    report["status"] = "REVIEW_REQUIRED"
                    report["warnings"].append("Clone embeds an implementation address without runtime code.")
            else:
                diamond = _diamond_loupe(client, target)
                if diamond:
                    report["architecture"] = "DIAMOND_LOUPE_CONFIRMED"
                    report["confidence"] = "HIGH"
                    report["status"] = "OBSERVED"
                    report["checks"]["diamond_loupe"] = diamond
                    report["upgrade_mechanisms"].append("DIAMONDCUT_REVIEW_REQUIRED")
                    report["evidence"].append("facetAddresses() and per-facet selector/code checks returned a coherent Diamond Loupe surface.")
                elif _has_opcode(runtime, 0xF4):
                    report["architecture"] = "CUSTOM_DELEGATECALL_CANDIDATE"
                    report["confidence"] = "INFERRED"
                    report["status"] = "REVIEW_REQUIRED"
                    report["warnings"].append(
                        "Runtime contains a DELEGATECALL opcode but no supported standard routing pattern was proven. "
                        "This is a custom-proxy investigation lead, not a confirmed proxy classification."
                    )
                else:
                    report["architecture"] = "DIRECT_OR_UNKNOWN"
                    report["confidence"] = "LOW"
                    report["status"] = "UNCLASSIFIED"
                    report["warnings"].append(
                        "No supported proxy pattern was proven. This does not exclude custom dispatch, immutable routing, "
                        "or an unsupported proxy family."
                    )

        # ABI signals are kept separate from runtime classification.
        functions = []
        for item in abi or []:
            if not isinstance(item, dict) or item.get("type") != "function":
                continue
            name = str(item.get("name") or "")
            inputs = item.get("inputs") or []
            signature = name + "(" + ",".join(str(param.get("type") or "") for param in inputs) + ")"
            if re.search(r"upgrade|authorizeUpgrade|proxiable|diamondCut|implementation|admin|beacon", name, re.I):
                functions.append({"name": name, "signature": signature, "selector": function_selector(signature)})
        report["checks"]["upgrade_abi_signals"] = functions
        if any(item["name"] in {"upgradeTo", "upgradeToAndCall"} for item in functions):
            report["upgrade_mechanisms"].append("IMPLEMENTATION_UPGRADE_FUNCTION_IN_ABI")

        # Re-check the pinned block hash so a reorg cannot silently mix states.
        try:
            if not client.verify_snapshot():
                report["status"] = "UNVERIFIED"
                report["warnings"].append("The pinned block hash changed during inspection; discard mixed-state conclusions and retry.")
        except ProxyError as exc:
            report["status"] = "UNVERIFIED"
            report["errors"].append("Could not verify the pinned block after inspection: " + str(exc))
    except ProxyError as exc:
        report["status"] = "UNVERIFIED"
        report["errors"].append(str(exc))
    report["upgrade_mechanisms"] = list(dict.fromkeys(report["upgrade_mechanisms"]))
    return report


_SOURCE_PATTERNS = (
    ("uups_authorization_hook", re.compile(r"\b_authorizeUpgrade\s*\(")),
    ("uups_only_proxy", re.compile(r"\bonlyProxy\b")),
    ("uups_not_delegated", re.compile(r"\bnotDelegated\b")),
    ("uups_proxiable_uuid", re.compile(r"\bproxiableUUID\s*\(")),
    ("upgrade_to_and_call", re.compile(r"\bupgradeToAndCall\s*\(")),
    ("upgrade_to", re.compile(r"\bupgradeTo\s*\(")),
    ("initializer", re.compile(r"\binitializer\b|\breinitializer\s*\(")),
    ("implementation_lock", re.compile(r"\b_disableInitializers\s*\(")),
    ("diamond_cut", re.compile(r"\bdiamondCut\s*\(")),
    ("delegatecall", re.compile(r"\.delegatecall\s*\(|\bdelegatecall\b")),
    ("namespaced_storage", re.compile(r"@custom:storage-location")),
    ("assembly_storage", re.compile(r"\bassembly\s*\{|\bsstore\s*\(")),
    ("authorization_modifiers", re.compile(r"\bonlyOwner\b|\bonlyRole\s*\(")),
)


def scan_sources(root: str | Path, max_files: int = 400) -> list[dict[str, Any]]:
    """Collect line-anchored Solidity source signals; this is not a parser or verdict."""
    base = Path(root).expanduser().resolve()
    candidates = []
    for folder_name in ("src", "contracts"):
        folder = base / folder_name
        if folder.is_dir():
            candidates.extend(folder.rglob("*.sol"))
    excluded = {".git", "node_modules", "lib", "vendor", "cache", "out"}
    rows = []
    for path in sorted(set(candidates))[:max_files]:
        try:
            relative_parts = path.relative_to(base).parts
            if any(part in excluded for part in relative_parts):
                continue
            if path.stat().st_size > 1_000_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            for key, pattern in _SOURCE_PATTERNS:
                if pattern.search(line):
                    rows.append({
                        "signal": key,
                        "path": path.relative_to(base).as_posix(),
                        "line": line_no,
                        "excerpt": line.strip()[:220],
                        "evidence_type": "SOURCE_PATTERN",
                        "confidence": "LOW",
                    })
    return rows


def audit_proxy(
    rpc_url: str,
    target: str,
    root: str | Path | None = None,
    abi: list[dict[str, Any]] | None = None,
    requested_block: int | None = None,
) -> dict[str, Any]:
    """Combine pinned runtime facts with source and ABI investigation leads."""
    report = inspect_proxy(rpc_url, target, requested_block=requested_block, abi=abi)
    source_signals = scan_sources(root) if root else []
    report["source_signals"] = source_signals
    report["source_scan"] = {
        "status": "SCANNED" if root else "NOT_AVAILABLE",
        "root": str(Path(root).resolve()) if root else None,
        "note": "Textual source signals only. Inheritance, aliases, assembly semantics and reachability require compiler-backed analysis.",
    }
    upgrade_names = {
        row.get("name") for row in (report.get("checks", {}).get("upgrade_abi_signals") or [])
    }
    source_names = {row.get("signal") for row in source_signals}
    hypotheses = []
    architecture = report.get("architecture")
    if architecture in {"ERC1967_IMPLEMENTATION_PROXY", "CONFLICTING_EIP1967_SLOTS"}:
        if "uups_authorization_hook" in source_names or "UUPS_COMPATIBLE_IMPLEMENTATION" in report.get("upgrade_mechanisms", []):
            hypotheses.append({
                "id": "PROXY-UUPS-AUTH",
                "title": "Verify UUPS upgrade authorization",
                "status": "INVESTIGATION_REQUIRED",
                "reason": "UUPS-compatible upgrade surface observed; authorization correctness has not been executed or proven.",
                "next": "Inspect _authorizeUpgrade and reproduce unauthorized upgrade attempts against a local fork.",
            })
        if "initializer" in source_names:
            hypotheses.append({
                "id": "PROXY-INIT",
                "title": "Verify proxy and implementation initialization boundaries",
                "status": "INVESTIGATION_REQUIRED",
                "reason": "Initializer annotations or functions were found in the source inventory; live initialized state and caller permissions remain unproven.",
                "next": "Check proxy initialization state, implementation locking, reinitializers and initialization transaction provenance.",
            })
        if "delegatecall" in source_names or "assembly_storage" in source_names:
            hypotheses.append({
                "id": "PROXY-STORAGE",
                "title": "Review delegated storage writes and critical slots",
                "status": "INVESTIGATION_REQUIRED",
                "reason": "Source includes delegatecall or manual storage operations; exact slot effects need compiler/trace-backed analysis.",
                "next": "Trace writes to ERC-1967 slots and application authorization/accounting slots.",
            })
    if architecture == "ERC1967_BEACON_PROXY":
        hypotheses.append({
            "id": "PROXY-BEACON-AUTH",
            "title": "Verify beacon ownership and implementation integrity",
            "status": "INVESTIGATION_REQUIRED",
            "reason": "A beacon-controlled implementation path was observed; beacon owner permissions and upgrade effects were not tested.",
            "next": "Trace beacon upgrade authority and enumerate dependent proxies.",
        })
    if architecture == "DIAMOND_LOUPE_CONFIRMED":
        hypotheses.append({
            "id": "PROXY-DIAMOND-CUT",
            "title": "Verify diamondCut authority and facet replacement safety",
            "status": "INVESTIGATION_REQUIRED",
            "reason": "A coherent Diamond Loupe interface was observed; cut permissions and initialization delegatecall were not tested.",
            "next": "Resolve the diamondCut selector, authorization path, facet changes and storage invariants.",
        })
    if "upgradeTo" in upgrade_names or "upgradeToAndCall" in upgrade_names:
        hypotheses.append({
            "id": "PROXY-UPGRADE-SURFACE",
            "title": "Review exposed upgrade entrypoints",
            "status": "INVESTIGATION_REQUIRED",
            "reason": "Upgrade function names appear in the supplied ABI; routing and authorization must be verified against runtime behavior.",
            "next": "Test caller-dependent proxy dispatch and privileged/unprivileged upgrade attempts.",
        })
    report["hypotheses"] = hypotheses
    report["audit_disclaimer"] = (
        "No hypothesis in this report is a confirmed vulnerability. Static source and ABI signals are investigation leads. "
        "A finding requires a target-specific executable reproduction, expected control, state/trace evidence and human review."
    )
    return report


_ATTACK_SCENARIOS = (
    ("PROXY-INIT-001", "Uninitialized proxy takeover", "initializer state, owner/role capture and first-caller control"),
    ("PROXY-INIT-002", "Implementation initialization takeover", "direct implementation initialization and implementation locking"),
    ("PROXY-UUPS-001", "Unauthorized UUPS upgrade", "onlyProxy context and _authorizeUpgrade caller restrictions"),
    ("PROXY-UUPS-002", "UUPS compatibility failure", "proxiableUUID validation and post-upgrade upgradeability"),
    ("PROXY-UUPS-003", "Upgrade lockout", "replacement implementation removes or disables future upgrade route"),
    ("PROXY-TRANSPARENT-001", "Transparent admin routing", "admin versus non-admin selector routing and ProxyAdmin ownership"),
    ("PROXY-TRANSPARENT-002", "Second upgrade surface", "UUPS-compatible implementation exposed behind a Transparent proxy"),
    ("PROXY-BEACON-001", "Beacon authorization takeover", "beacon owner, implementation mutation and dependent proxy impact"),
    ("PROXY-DIAMOND-001", "Unauthorized diamondCut", "facet selector add/replace/remove authorization"),
    ("PROXY-DIAMOND-002", "Diamond initialization delegatecall", "cut initialization target, calldata and storage side effects"),
    ("PROXY-STORAGE-001", "Storage layout regression", "state preservation across implementation upgrade"),
    ("PROXY-STORAGE-002", "Critical proxy slot corruption", "implementation, beacon and admin slots under delegated execution"),
    ("PROXY-CUSTOM-001", "Custom delegatecall target control", "custom dispatch and attacker-influenced implementation destination"),
)


def build_attack_plan(report: dict[str, Any]) -> dict[str, Any]:
    """Create review tasks only; never label these generated hypotheses as executed attacks."""
    architecture = report.get("architecture", "UNKNOWN")
    applicable = []
    for row in _ATTACK_SCENARIOS:
        key, title, invariant = row
        if "UUPS" in key and architecture not in {"ERC1967_IMPLEMENTATION_PROXY", "CONFLICTING_EIP1967_SLOTS"}:
            continue
        if "TRANSPARENT" in key and architecture not in {"ERC1967_IMPLEMENTATION_PROXY", "CONFLICTING_EIP1967_SLOTS"}:
            continue
        if "BEACON" in key and architecture != "ERC1967_BEACON_PROXY":
            continue
        if "DIAMOND" in key and architecture != "DIAMOND_LOUPE_CONFIRMED":
            continue
        if "CUSTOM" in key and architecture != "CUSTOM_DELEGATECALL_CANDIDATE":
            continue
        applicable.append({
            "id": key,
            "title": title,
            "invariant_to_test": invariant,
            "status": "NOT_EXECUTED",
            "required_evidence": [
                "deployment-specific fixture or pinned local fork",
                "attacker and expected-control actors",
                "pre/post implementation and critical-storage state",
                "transaction trace and revert/success evidence",
                "independent reproduction",
            ],
        })
    # Generic initialization and storage tests apply to all recognized proxy-like targets.
    if architecture not in {"DIRECT_OR_UNKNOWN", "NO_CODE", "UNKNOWN", "UNVERIFIED_EIP1967"}:
        applicable.extend([
            {
                "id": "PROXY-INIT-001",
                "title": "Uninitialized proxy takeover",
                "invariant_to_test": "initializer state, owner/role capture and first-caller control",
                "status": "NOT_EXECUTED",
                "required_evidence": ["target-specific initializer", "control actor", "attacker actor", "state diff"],
            },
            {
                "id": "PROXY-STORAGE-001",
                "title": "Storage layout regression",
                "invariant_to_test": "state preservation across implementation upgrade",
                "status": "NOT_EXECUTED",
                "required_evidence": ["V1/V2 compiler storage layouts", "upgrade route", "state invariants", "paired control"],
            },
        ])
    # De-duplicate IDs where general and architecture-specific plans overlap.
    unique = {item["id"]: item for item in applicable}
    return {
        "schema": "lowkey.proxy.attack-plan.v1",
        "target": report.get("target"),
        "snapshot": report.get("snapshot"),
        "architecture": architecture,
        "status": "HYPOTHESES_ONLY",
        "executed": False,
        "scenarios": list(unique.values()),
        "limitations": [
            "No transaction was sent and no production state was changed.",
            "Scenario selection is based on architecture evidence, not proof of exploitability.",
            "Each scenario needs a target-specific Foundry/Anvil adapter and paired safe control before it can become an executable BREAK result.",
        ],
    }


def _type_fingerprint(type_id: str, type_table: dict[str, Any], seen: set[str] | None = None) -> Any:
    seen = set() if seen is None else set(seen)
    if type_id in seen:
        return {"recursive": type_id}
    seen.add(type_id)
    item = type_table.get(type_id)
    if not isinstance(item, dict):
        return {"unknown_type": type_id}
    result = {
        key: item.get(key)
        for key in ("encoding", "label", "numberOfBytes")
        if item.get(key) is not None
    }
    for key in ("key", "value", "base"):
        if item.get(key) is not None:
            result[key] = _type_fingerprint(str(item[key]), type_table, seen)
    if isinstance(item.get("members"), list):
        result["members"] = [
            {
                "label": member.get("label"),
                "slot": str(member.get("slot")),
                "offset": int(member.get("offset") or 0),
                "type": _type_fingerprint(str(member.get("type") or ""), type_table, seen),
            }
            for member in item["members"] if isinstance(member, dict)
        ]
    return result


def _extract_layout(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    for key in ("storageLayout", "storage_layout", "storageLayoutOutput"):
        if isinstance(value.get(key), dict):
            value = value[key]
            break
    if isinstance(value.get("storage"), list) and isinstance(value.get("types"), dict):
        return value
    return None


def compare_storage_layouts(reference: Any, candidate: Any) -> dict[str, Any]:
    """Conservative V1/V2 layout comparison; not a substitute for OZ validation."""
    old = _extract_layout(reference)
    new = _extract_layout(candidate)
    result = {
        "schema": "lowkey.proxy.storage-diff.v1",
        "status": "INCONCLUSIVE",
        "compatible_candidate": False,
        "breaking": [],
        "warnings": [],
        "additions": [],
        "summary": "",
    }
    if old is None or new is None:
        result["summary"] = "Both inputs must contain compiler storageLayout.storage and storageLayout.types."
        result["warnings"].append("Missing compiler storage layout; no compatibility conclusion was made.")
        return result

    old_items = old.get("storage") or []
    new_items = new.get("storage") or []
    old_types = old.get("types") or {}
    new_types = new.get("types") or {}
    by_label = {str(item.get("label")): item for item in new_items if isinstance(item, dict)}
    max_end = 0
    gaps = []
    for item in old_items:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "")
        if label.startswith("__gap") or label.lower() in {"__gap", "storagegap"}:
            gaps.append(label)
        try:
            slot = int(str(item.get("slot")), 0) if str(item.get("slot")).startswith("0x") else int(str(item.get("slot")))
            offset = int(item.get("offset") or 0)
            old_type = old_types.get(str(item.get("type")), {})
            size = int(old_type.get("numberOfBytes") or 32)
        except (TypeError, ValueError):
            result["warnings"].append(f"Could not calculate the end position of reference field {label!r}.")
            continue
        end = slot + max(1, (offset + max(1, size) + 31) // 32)
        max_end = max(max_end, end)

        match = by_label.get(label)
        if match is None:
            result["breaking"].append({"field": label, "reason": "reference field is missing or renamed in candidate"})
            continue
        old_slot = str(item.get("slot"))
        new_slot = str(match.get("slot"))
        old_offset = int(item.get("offset") or 0)
        new_offset = int(match.get("offset") or 0)
        if old_slot != new_slot or old_offset != new_offset:
            result["breaking"].append({
                "field": label, "reason": "slot or packed offset changed",
                "reference": {"slot": old_slot, "offset": old_offset},
                "candidate": {"slot": new_slot, "offset": new_offset},
            })
            continue
        old_fp = _type_fingerprint(str(item.get("type") or ""), old_types)
        new_fp = _type_fingerprint(str(match.get("type") or ""), new_types)
        if old_fp != new_fp:
            result["breaking"].append({
                "field": label, "reason": "storage type encoding or member layout changed",
                "reference_type": old_fp, "candidate_type": new_fp,
            })

    old_labels = {str(item.get("label")) for item in old_items if isinstance(item, dict)}
    for item in new_items:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "")
        if label in old_labels:
            continue
        try:
            slot = int(str(item.get("slot")), 0) if str(item.get("slot")).startswith("0x") else int(str(item.get("slot")))
        except (TypeError, ValueError):
            result["warnings"].append(f"Could not establish the slot for candidate addition {label!r}.")
            continue
        result["additions"].append({"field": label, "slot": str(item.get("slot"))})
        if slot < max_end:
            result["breaking"].append({
                "field": label,
                "reason": "new field overlaps the reference layout's occupied slot range",
                "candidate_slot": str(item.get("slot")),
                "reference_end_slot_exclusive": max_end,
            })
    if gaps:
        result["warnings"].append(
            "Reference layout contains storage gap(s): " + ", ".join(gaps)
            + ". Gap resizing/inheritance rules require the compiler-backed OpenZeppelin validator and manual review."
        )
    if result["breaking"]:
        result["status"] = "INCOMPATIBLE"
        result["compatible_candidate"] = False
        result["summary"] = f"{len(result['breaking'])} incompatibility issue(s) found."
    elif result["warnings"]:
        result["status"] = "INCONCLUSIVE"
        result["summary"] = "No direct field collision was found, but unresolved storage-gap or layout conditions remain."
    else:
        result["status"] = "COMPATIBLE_CANDIDATE"
        result["compatible_candidate"] = True
        result["summary"] = "Existing compiler storage entries are preserved and additions are appended; this is not a formal upgrade-safety proof."
    result["reference_field_count"] = len(old_items)
    result["candidate_field_count"] = len(new_items)
    result["reference_end_slot_exclusive"] = max_end
    result["namespaced_storage_note"] = (
        "ERC-7201 namespaces may not appear as ordinary top-level compiler storage entries. "
        "Compare namespace identifiers, root slots and struct members separately or use OpenZeppelin validation."
    )
    return result


def _read_json_file(path: str) -> dict[str, Any]:
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise ProxyError(f"Storage layout file does not exist: {candidate}")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProxyError(f"Could not read JSON artifact {candidate}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProxyError(f"JSON artifact must contain an object: {candidate}")
    layout = _extract_layout(value)
    if layout is None:
        raise ProxyError(
            f"{candidate} has no compiler storage layout. Rebuild with storageLayout output enabled."
        )
    return value


def _parse_cli(args: list[str]) -> tuple[list[str], dict[str, str], set[str]]:
    positional = []
    values = {}
    flags = set()
    index = 0
    while index < len(args):
        token = str(args[index])
        if token in {"--json", "--verbose"}:
            flags.add(token[2:])
            index += 1
        elif token.startswith("--"):
            if index + 1 >= len(args) or str(args[index + 1]).startswith("--"):
                raise ProxyError(f"{token} requires a value.")
            values[token] = str(args[index + 1])
            index += 2
        else:
            positional.append(token)
            index += 1
    return positional, values, flags


def _render_inspection(report: dict[str, Any], verbose: bool = False) -> str:
    snapshot = report.get("snapshot") or {}
    addresses = report.get("addresses") or {}
    lines = [
        "LOWKEY / PROXY INTELLIGENCE",
        f"TARGET         {report.get('target')}",
        f"ARCHITECTURE   {report.get('architecture')}",
        f"STATUS         {report.get('status')}",
        f"CONFIDENCE     {report.get('confidence')}",
        f"CHAIN / BLOCK  {snapshot.get('chain_id', '?')} / {snapshot.get('block_number', '?')}",
        f"BLOCK HASH     {snapshot.get('block_hash', 'unavailable')}",
    ]
    for key, label in (
        ("implementation", "IMPLEMENTATION"),
        ("beacon", "BEACON"),
        ("admin_slot_candidate", "ADMIN SLOT CANDIDATE"),
    ):
        if addresses.get(key):
            lines.append(f"{label:<14} {addresses[key]}")
    slot_candidates = report.get("slot_candidates") or {}
    if report.get("architecture") == "CONFLICTING_EIP1967_SLOTS":
        lines.append(f"IMPL SLOT CAND {slot_candidates.get('implementation')}")
        lines.append(f"BEACON SLOT CAND {slot_candidates.get('beacon')}")
    if addresses.get("implementation_has_code") is not None:
        lines.append(f"IMPL CODE      {'YES' if addresses['implementation_has_code'] else 'NO'}")
    uuid = (report.get("checks") or {}).get("proxiable_uuid") or {}
    if uuid:
        lines.append(f"PROXIABLE UUID {uuid.get('status')}")
    lines.append("")
    for evidence in report.get("evidence") or []:
        lines.append("EVIDENCE       " + str(evidence))
    for warning in report.get("warnings") or []:
        lines.append("REVIEW         " + str(warning))
    for error in report.get("errors") or []:
        lines.append("ERROR          " + str(error))
    if verbose:
        lines.append("")
        lines.append("UPGRADE MECHANISM SIGNALS")
        for item in report.get("upgrade_mechanisms") or []:
            lines.append("  " + item)
        lines.append("SOURCE SIGNALS")
        for item in report.get("source_signals") or []:
            lines.append(f"  {item.get('path')}:{item.get('line')}  {item.get('signal')}")
        lines.append("HYPOTHESES")
        for item in report.get("hypotheses") or []:
            lines.append(f"  {item.get('id')}  {item.get('title')}  [{item.get('status')}]")
    lines.append("")
    lines.append("NOTE           Runtime evidence is block-pinned. Inference is not an exploit verdict.")
    return "\n".join(lines)


def _save_report(root: str | Path | None, target: str, filename: str, payload: dict[str, Any]) -> Path | None:
    if not root:
        return None
    base = Path(root).expanduser().resolve() / ".audit" / "proxy" / target.lower()
    base.mkdir(parents=True, exist_ok=True)
    path = base / filename
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run_cli(
    config: dict[str, Any],
    args: list[str],
    rpc_resolver=None,
    abi_resolver=None,
    root_resolver=None,
) -> int:
    """CLI entry point used by lk proxy <inspect|audit|plan|validate|simulate>."""
    try:
        positional, values, flags = _parse_cli(list(args or []))
    except ProxyError as exc:
        print("LOWKEY ERROR: " + str(exc))
        return 2
    action = positional.pop(0).lower() if positional and positional[0].lower() in {
        "inspect", "audit", "report", "plan", "attack", "validate", "diff", "simulate",
    } else "inspect"
    address = next((item for item in positional if is_address(item)), None) or config.get("target")
    if action in {"validate", "diff"}:
        reference = values.get("--reference")
        candidate = values.get("--candidate")
        if not reference or not candidate:
            print("Usage: lk proxy validate --reference <V1-artifact.json> --candidate <V2-artifact.json>")
            return 2
        try:
            result = compare_storage_layouts(_read_json_file(reference), _read_json_file(candidate))
        except ProxyError as exc:
            print("LOWKEY BLOCKED: " + str(exc))
            return 2
        print(json.dumps(result, indent=2) if "json" in flags else (
            "LOWKEY / PROXY STORAGE VALIDATION\n"
            f"STATUS       {result['status']}\n"
            f"SUMMARY      {result['summary']}\n"
            f"BREAKING     {len(result['breaking'])}\n"
            f"ADDITIONS    {len(result['additions'])}\n"
            + "\n".join("REVIEW       " + item for item in result["warnings"])
            + "\nNOTE         Candidate compatibility is not proof of upgrade safety."
        ))
        return 0 if result["status"] == "COMPATIBLE_CANDIDATE" else 1

    if not is_address(address):
        print("LOWKEY ERROR: Set a target with 'lk target <address>' or pass a proxy address.")
        return 2
    explicit_rpc = values.get("--rpc-url")
    rpc = None
    if callable(rpc_resolver):
        try:
            rpc = rpc_resolver(config, explicit_rpc=explicit_rpc, target=address)
        except TypeError:
            rpc = rpc_resolver(config)
    rpc = explicit_rpc or rpc
    if not rpc:
        print("LOWKEY BLOCKED: No RPC is configured. Set one with 'lk rpc set <url>' or pass --rpc-url.")
        return 2
    try:
        requested_block = int(values["--block"], 0) if "--block" in values else None
    except ValueError:
        print("LOWKEY ERROR: --block must be an integer or 0x-prefixed block number.")
        return 2
    abi = []
    if callable(abi_resolver):
        try:
            loaded = abi_resolver(address, config)
            abi = loaded if isinstance(loaded, list) else []
        except Exception:
            abi = []
    root = None
    if callable(root_resolver):
        try:
            root = root_resolver()
        except Exception:
            root = None

    if action == "simulate":
        print(
            "LOWKEY BLOCKED / ADAPTER REQUIRED\n"
            "A generic upgrade simulation is unsafe without the target's actual upgrade route, "
            "new implementation artifact, initializer calldata and expected state invariants.\n"
            "Use 'lk proxy audit' and 'lk proxy validate' first. Lowkey did not impersonate an admin, "
            "broadcast a transaction or change chain state."
        )
        return 2

    report = audit_proxy(rpc, address, root=root, abi=abi, requested_block=requested_block) if action in {"audit", "report", "plan", "attack"} else inspect_proxy(
        rpc, address, requested_block=requested_block, abi=abi,
    )
    if action in {"plan", "attack"}:
        plan = build_attack_plan(report)
        path = _save_report(root, address, "attack-plan.json", plan)
        if path:
            plan["evidence_path"] = str(path)
        if "json" in flags:
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            print(
                "LOWKEY / PROXY ATTACK PLAN\n"
                f"TARGET       {address}\n"
                f"ARCHITECTURE {plan['architecture']}\n"
                f"STATUS       {plan['status']}\n"
                f"SCENARIOS    {len(plan['scenarios'])}\n"
                + "\n".join(f"  {item['id']}  {item['title']}  [{item['status']}]" for item in plan["scenarios"])
                + "\nNOTE         Plans are hypotheses only; no attack was executed."
            )
            if path:
                print("EVIDENCE     " + str(path))
        return 0

    if action in {"audit", "report"}:
        block = (report.get("snapshot") or {}).get("block_number", "unknown")
        filename = f"audit-{block}.json"
        path = _save_report(root, address, filename, report)
    else:
        path = None
    if path:
        report["evidence_path"] = str(path)
    if "json" in flags:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_inspection(report, verbose="verbose" in flags or action in {"audit", "report"}))
        if path:
            print("EVIDENCE       " + str(path))
    status = report.get("status")
    if status == "UNVERIFIED":
        return 2
    return 0
