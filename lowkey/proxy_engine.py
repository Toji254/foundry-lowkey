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
DIAMOND_FACET_ADDRESS = "0xcdffacc6"
PROXIABLE_UUID_SELECTOR = "0x52d1902d"
SENTINEL_CALLERS = (
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
)
MAX_DIAMOND_FACETS = 64
MAX_DIAMOND_SELECTORS = 64


class ProxyError(RuntimeError):
    """Expected proxy-inspection failure with a user-actionable message."""


class RpcExecutionError(ProxyError):
    """An eth_call that reached the EVM and reverted, distinct from RPC failure."""


def is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value.strip()))


def _hex_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        return None
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        return None


def _decode_slot_state(value: Any) -> tuple[str, str | None, str]:
    """Return ZERO, ADDRESS, or MALFORMED without conflating bad words with empty slots."""
    raw = _hex_bytes(value)
    if raw is None or len(raw) != 32:
        return "MALFORMED", None, "malformed or unavailable 32-byte slot value"
    if raw[:12] != b"\x00" * 12:
        return "MALFORMED", None, "slot word has non-zero high 12 bytes; not a canonical address"
    address = "0x" + raw[12:].hex()
    if address.lower() == ZERO_ADDRESS:
        return "ZERO", None, "slot is zero"
    return "ADDRESS", address, "non-zero canonical address"


def _decode_slot_address(value: Any) -> tuple[str | None, str]:
    """Compatibility wrapper for callers that only need the address and explanation."""
    _state, address, explanation = _decode_slot_state(value)
    return address, explanation


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
            code = error.get("code") if isinstance(error, dict) else None
            if method == "eth_call" and (code == 3 or "revert" in str(message).lower()):
                raise RpcExecutionError(f"RPC eth_call reverted: {message}")
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


def _decode_abi_address(data: str) -> str | None:
    raw = _hex_bytes(data)
    if raw is None or len(raw) != 32 or raw[:12] != b"\x00" * 12:
        return None
    return "0x" + raw[12:].hex()


def _try_call_detailed(client: RpcClient, address: str, selector: str, caller: str) -> dict[str, Any]:
    """Preserve the difference between an EVM revert and an RPC/provider failure."""
    try:
        return {"status": "SUCCESS", "raw": client.call(address, selector, caller=caller)}
    except RpcExecutionError as exc:
        return {"status": "REVERT", "raw": None, "error": str(exc)}
    except ProxyError as exc:
        return {"status": "RPC_ERROR", "raw": None, "error": str(exc)}


def _try_call(client: RpcClient, address: str, selector: str, caller: str) -> tuple[bool, str | None]:
    """Legacy boolean wrapper; security-sensitive probes use _try_call_detailed."""
    result = _try_call_detailed(client, address, selector, caller)
    return result["status"] == "SUCCESS", result.get("raw")


def _probe_owner_getter(client: RpcClient, address: str) -> dict[str, Any]:
    """Read owner() from two caller contexts; do not collapse RPC failure into a revert."""
    try:
        code = client.code(address)
    except ProxyError as exc:
        return {"status": "UNVERIFIED", "error": str(exc)}
    if code == "0x":
        return {"status": "NO_CODE"}
    selector = function_selector("owner()")
    probes = []
    for caller in SENTINEL_CALLERS:
        attempt = _try_call_detailed(client, address, selector, caller)
        owner = _decode_abi_address(attempt.get("raw")) if attempt["status"] == "SUCCESS" else None
        status = attempt["status"]
        if status == "SUCCESS" and owner is None:
            status = "MALFORMED_RESULT"
        probes.append({
            "caller": caller,
            "status": status,
            "readable": status == "SUCCESS",
            "owner": owner,
            **({"error": attempt["error"]} if attempt.get("error") else {}),
        })
    if any(item["status"] == "RPC_ERROR" for item in probes):
        return {
            "status": "UNVERIFIED_RPC_FAILURE",
            "probes": probes,
            "limitation": "At least one owner() probe failed at the RPC/provider layer; it is not treated as an EVM revert or empty value.",
        }
    owners = {item["owner"] for item in probes if item["status"] == "SUCCESS"}
    if len(owners) == 1 and all(item["status"] == "SUCCESS" for item in probes):
        owner = next(iter(owners))
        if owner.lower() == ZERO_ADDRESS:
            return {
                "status": "ZERO_OWNER_VALUE_OBSERVED",
                "probes": probes,
                "limitation": "owner() consistently returned address(0); this is not an authority candidate and may represent a renounced or unset owner.",
            }
        return {
            "status": "OWNER_GETTER_VALUE_OBSERVED",
            "owner_candidate": owner,
            "caller_independence": "CONSISTENT_FOR_TWO_SENTINEL_CALLERS",
            "probes": probes,
            "limitation": "owner() is an application getter signal; it does not by itself prove control over the proxy upgrade route.",
        }
    if len(owners) > 1:
        return {
            "status": "CALLER_DEPENDENT",
            "probes": probes,
            "limitation": "Different callers observed different owner() values; do not treat one as the authority.",
        }
    if all(item["status"] == "REVERT" for item in probes):
        status = "GETTER_REVERTED_FOR_PROBES"
    else:
        status = "UNAVAILABLE"
    return {
        "status": status,
        "probes": probes,
        "limitation": "No consistent canonical owner() address was decoded; reverts and malformed results remain distinct from RPC failure.",
    }


def _probe_transparent_admin_routing(
    client: RpcClient,
    proxy: str,
    implementation: str,
    admin_candidate: str | None,
    abi: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Require differential caller behavior, matching returndata, and an actual EVM revert."""
    if not admin_candidate:
        return {"status": "NO_ADMIN_SLOT_CANDIDATE"}
    other_caller = next((item for item in SENTINEL_CALLERS if item.lower() != admin_candidate.lower()), None)
    if other_caller is None:
        return {"status": "NO_INDEPENDENT_CALLER"}
    view_items = []
    for item in abi or []:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        if item.get("stateMutability") not in {"view", "pure"}:
            continue
        if item.get("inputs") or not item.get("outputs"):
            continue
        name = str(item.get("name") or "")
        if not name or name in {"proxiableUUID", "implementation", "admin"}:
            continue
        signature = name + "()"
        view_items.append((signature, function_selector(signature)))
    if not view_items:
        return {"status": "NOT_PROBED_NO_SAFE_NOARG_VIEW_FUNCTIONS"}

    examined = []
    rpc_failure = False
    for signature, selector in view_items[:8]:
        direct_admin = _try_call_detailed(client, implementation, selector, admin_candidate)
        direct_other = _try_call_detailed(client, implementation, selector, other_caller)
        proxy_admin = _try_call_detailed(client, proxy, selector, admin_candidate)
        proxy_other = _try_call_detailed(client, proxy, selector, other_caller)
        row = {
            "signature": signature,
            "selector": selector,
            "implementation_admin": direct_admin["status"],
            "implementation_other": direct_other["status"],
            "proxy_admin": proxy_admin["status"],
            "proxy_other": proxy_other["status"],
            "implementation_admin_result": direct_admin.get("raw"),
            "implementation_other_result": direct_other.get("raw"),
            "proxy_other_result": proxy_other.get("raw"),
            "proxy_admin_error": proxy_admin.get("error"),
        }
        examined.append(row)
        if any(item["status"] == "RPC_ERROR" for item in (direct_admin, direct_other, proxy_admin, proxy_other)):
            rpc_failure = True
            continue
        same_return_data = (
            direct_other["status"] == "SUCCESS"
            and proxy_other["status"] == "SUCCESS"
            and direct_other.get("raw") == proxy_other.get("raw")
        )
        if (
            direct_admin["status"] == "SUCCESS"
            and direct_other["status"] == "SUCCESS"
            and same_return_data
            and proxy_admin["status"] == "REVERT"
        ):
            return {
                "status": "TRANSPARENT_ROUTING_CANDIDATE",
                "admin_slot_candidate": admin_candidate,
                "matched_function": signature,
                "return_data_matches": True,
                "probes": examined,
                "limitation": "Differential behavior is consistent with Transparent admin fallback blocking for one selector and a mirrored admin-slot candidate; immutable-admin mismatch and alternative dispatch paths remain possible.",
            }
    return {
        "status": "INCONCLUSIVE_RPC_FAILURE" if rpc_failure else "NOT_OBSERVED",
        "admin_slot_candidate": admin_candidate,
        "probes": examined,
        "limitation": "A Transparent candidate requires direct calls to succeed, the non-admin proxy result to match, and an actual EVM revert for the admin caller. Provider errors are never interpreted as access-control reverts.",
    }


def _resolve_nested_proxy_chain(
    client: RpcClient,
    start: str,
    max_depth: int = 5,
) -> dict[str, Any]:
    """Follow standard proxy/clone edges without allowing loops or unbounded RPC work."""
    current = start
    seen: set[str] = set()
    hops: list[dict[str, Any]] = []
    status = "TERMINAL_IMPLEMENTATION"
    for depth in range(max_depth):
        normalized = current.lower()
        if normalized in seen:
            status = "CYCLE_DETECTED"
            hops.append({"depth": depth, "address": current, "architecture": "CYCLE"})
            break
        seen.add(normalized)
        try:
            runtime = client.code(current)
        except ProxyError as exc:
            status = "UNVERIFIED"
            hops.append({"depth": depth, "address": current, "architecture": "UNVERIFIED", "error": str(exc)})
            break
        if runtime == "0x":
            status = "NO_CODE_AT_HOP"
            hops.append({"depth": depth, "address": current, "architecture": "NO_CODE"})
            break
        clone_impl = _minimal_clone_implementation(runtime)
        if clone_impl:
            hops.append({"depth": depth, "address": current, "architecture": "EIP1167_MINIMAL_CLONE", "implementation": clone_impl})
            current = clone_impl
            continue

        slot_values: dict[str, str | None] = {}
        try:
            impl_state, impl, impl_note = _decode_slot_state(
                client.storage(current, EIP1967_IMPLEMENTATION_SLOT)
            )
            beacon_state, beacon, beacon_note = _decode_slot_state(
                client.storage(current, EIP1967_BEACON_SLOT)
            )
            if "MALFORMED" in {impl_state, beacon_state}:
                status = "MALFORMED_EIP1967_SLOT"
                hops.append({
                    "depth": depth,
                    "address": current,
                    "architecture": "MALFORMED_EIP1967_SLOT",
                    "implementation_state": impl_state,
                    "implementation_explanation": impl_note,
                    "beacon_state": beacon_state,
                    "beacon_explanation": beacon_note,
                })
                break
            slot_values = {"implementation": impl, "beacon": beacon}
        except ProxyError as exc:
            status = "UNVERIFIED"
            hops.append({"depth": depth, "address": current, "architecture": "UNVERIFIED", "error": str(exc)})
            break

        impl = slot_values["implementation"]
        beacon = slot_values["beacon"]
        if (impl or beacon) and not _has_opcode(runtime, 0xF4):
            status = "SLOT_CANDIDATE_ONLY"
            hops.append({
                "depth": depth,
                "address": current,
                "architecture": "EIP1967_SLOT_WITHOUT_DELEGATECALL_EVIDENCE",
                "implementation_candidate": impl,
                "beacon_candidate": beacon,
            })
            break
        if impl and beacon:
            status = "CONFLICTING_ROUTING"
            hops.append({
                "depth": depth, "address": current,
                "architecture": "CONFLICTING_EIP1967_SLOTS",
                "implementation_candidate": impl, "beacon_candidate": beacon,
            })
            break
        if impl:
            hops.append({"depth": depth, "address": current, "architecture": "ERC1967_IMPLEMENTATION_PROXY", "implementation": impl})
            current = impl
            continue
        if beacon:
            try:
                beacon_code = client.code(beacon)
                if beacon_code == "0x":
                    status = "BEACON_NO_CODE"
                    hops.append({"depth": depth, "address": current, "architecture": "ERC1967_BEACON_PROXY", "beacon": beacon, "error": "Beacon has no runtime code."})
                    break
                results = [
                    _decode_returned_address(client.call(beacon, function_selector("implementation()"), caller=caller))
                    for caller in SENTINEL_CALLERS
                ]
            except ProxyError as exc:
                status = "UNVERIFIED"
                hops.append({"depth": depth, "address": current, "architecture": "ERC1967_BEACON_PROXY", "beacon": beacon, "error": str(exc)})
                break
            if not results[0] or not results[1] or results[0].lower() != results[1].lower():
                status = "BEACON_CALLER_DEPENDENT_OR_UNRESOLVED"
                hops.append({
                    "depth": depth, "address": current,
                    "architecture": "ERC1967_BEACON_PROXY",
                    "beacon": beacon, "implementation_probes": results,
                })
                break
            resolved = results[0]
            hops.append({
                "depth": depth, "address": current,
                "architecture": "ERC1967_BEACON_PROXY",
                "beacon": beacon, "implementation": resolved,
            })
            current = resolved
            continue
        if _has_opcode(runtime, 0xF4):
            hops.append({
                "depth": depth,
                "address": current,
                "architecture": "CUSTOM_DELEGATECALL_CANDIDATE",
                "code_sha256": hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),
                "limitation": "Delegatecall opcode presence does not establish its target or reachable dispatch route.",
            })
            status = "CUSTOM_DELEGATECALL_CANDIDATE"
            break
        hops.append({
            "depth": depth,
            "address": current,
            "architecture": "TERMINAL_IMPLEMENTATION",
            "code_sha256": hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),
        })
        status = "TERMINAL_IMPLEMENTATION"
        break
    else:
        status = "DEPTH_LIMIT_REACHED"
    return {
        "start": start,
        "status": status,
        "max_depth": max_depth,
        "hops": hops,
        "limitations": [
            "Only standard ERC-1967 implementation/beacon slots and the canonical ERC-1167 runtime are followed.",
            "Custom slots, immutable routing, diamonds and arbitrary delegatecall graphs require dedicated adapters.",
        ],
    }


def _inspect_initialization(
    client: RpcClient,
    proxy: str,
    implementation: str | None,
    abi: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Read declared view getters only; never call initialize/reinitialize entrypoints."""
    functions = [
        item for item in (abi or [])
        if isinstance(item, dict) and item.get("type") == "function"
    ]
    entrypoints = []
    getters = []
    for item in functions:
        name = str(item.get("name") or "")
        inputs = item.get("inputs") or []
        signature = name + "(" + ",".join(str(value.get("type") or "") for value in inputs) + ")"
        if name == "initialize" or name.startswith("initializeV") or name.startswith("reinitialize"):
            entrypoints.append({
                "name": name,
                "signature": signature,
                "selector": function_selector(signature),
                "mutability": item.get("stateMutability"),
                "input_count": len(inputs),
            })
        if (
            name in {"initialized", "initializedVersion", "initialized_version", "getInitializedVersion"}
            and not inputs
            and item.get("stateMutability") in {"view", "pure"}
            and len(item.get("outputs") or []) == 1
        ):
            getters.append({
                "name": name,
                "signature": signature,
                "selector": function_selector(signature),
                "output_type": str((item.get("outputs") or [{}])[0].get("type") or ""),
            })

    probes = []
    scopes = [("proxy", proxy)]
    if implementation and implementation.lower() != proxy.lower():
        scopes.append(("implementation", implementation))
    for scope, address in scopes:
        for getter in getters:
            try:
                raw = client.call(address, getter["selector"])
                raw_bytes = _hex_bytes(raw)
                if raw_bytes is None or len(raw_bytes) != 32:
                    probes.append({
                        "scope": scope, "getter": getter["signature"],
                        "status": "MALFORMED_RESULT", "raw": raw,
                    })
                    continue
                value = int.from_bytes(raw_bytes, "big")
                output_type = getter["output_type"]
                if output_type == "bool" and value not in {0, 1}:
                    probes.append({
                        "scope": scope, "getter": getter["signature"],
                        "status": "MALFORMED_BOOL", "raw": raw,
                    })
                else:
                    probes.append({
                        "scope": scope, "getter": getter["signature"],
                        "status": "VALUE_OBSERVED",
                        "value": bool(value) if output_type == "bool" else value,
                        "raw": raw,
                    })
            except ProxyError as exc:
                probes.append({
                    "scope": scope, "getter": getter["signature"],
                    "status": "UNAVAILABLE", "error": str(exc),
                })

    if probes and any(item["status"] == "VALUE_OBSERVED" for item in probes):
        status = "EXPLICIT_GETTER_VALUES_OBSERVED"
    elif entrypoints:
        status = "INITIALIZER_ENTRYPOINTS_STATE_NOT_EXTERNALLY_READABLE"
    elif getters:
        status = "GETTERS_UNAVAILABLE"
    else:
        status = "NO_STANDARD_PUBLIC_INITIALIZATION_GETTER"
    return {
        "status": status,
        "initializer_entrypoints": entrypoints,
        "public_state_getters": getters,
        "probes": probes,
        "mutating_entrypoints_called": False,
        "limitation": "An initializer ABI entrypoint or a public getter value does not alone prove takeover risk. Initializer writes, caller authorization, version semantics and deployment history need target-specific tests.",
    }


def _decode_dynamic_array(
    data: str,
    item_bytes: int,
    address_items: bool = False,
    max_items: int = MAX_DIAMOND_FACETS,
) -> list[str] | None:
    raw = _hex_bytes(data)
    if raw is None or len(raw) < 64:
        return None
    offset = int.from_bytes(raw[:32], "big")
    if offset % 32 or offset + 32 > len(raw):
        return None
    count = int.from_bytes(raw[offset:offset + 32], "big")
    if count > max_items or offset + 32 + count * 32 > len(raw):
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
    """Cross-check the Diamond Loupe's facet lists against selector-to-facet routing."""
    try:
        raw = client.call(target, DIAMOND_FACET_ADDRESSES)
        facets = _decode_dynamic_array(raw, 32, address_items=True)
        if not facets or len({item.lower() for item in facets}) != len(facets):
            return None
        checked = []
        seen_selectors: set[str] = set()
        for facet in facets:
            selectors_data = client.call(
                target,
                DIAMOND_FACET_SELECTORS + facet[2:].lower().rjust(64, "0"),
            )
            selectors = _decode_dynamic_array(
                selectors_data, 32, address_items=False, max_items=MAX_DIAMOND_SELECTORS,
            )
            if not selectors:
                return None
            facet_code = client.code(facet)
            if facet_code == "0x":
                return None
            normalized_selectors = [selector.lower() for selector in selectors]
            if len(seen_selectors) + len(normalized_selectors) > MAX_DIAMOND_SELECTORS:
                return None
            if len(set(normalized_selectors)) != len(normalized_selectors):
                return None
            for selector in normalized_selectors:
                if selector in seen_selectors or selector == "0x00000000":
                    return None
                seen_selectors.add(selector)
                mapped = client.call(
                    target,
                    DIAMOND_FACET_ADDRESS + selector[2:].ljust(64, "0"),
                )
                mapped_address = _decode_returned_address(mapped)
                if not mapped_address or mapped_address.lower() != facet.lower():
                    return None
            checked.append({
                "address": facet,
                "selectors": normalized_selectors,
                "code_sha256": hashlib.sha256(bytes.fromhex(facet_code[2:])).hexdigest(),
            })
        return {
            "facets": checked,
            "facet_count": len(facets),
            "selector_count": len(seen_selectors),
            "routing_cross_check": "FACET_ADDRESS_MATCHES_EVERY_REPORTED_SELECTOR",
        }
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
                state, address, explanation = _decode_slot_state(raw)
                slot_results[name] = {
                    "read": True,
                    "valid": state in {"ZERO", "ADDRESS"},
                    "state": state,
                    "raw": raw,
                    "address": address,
                    "explanation": explanation,
                }
                if state == "MALFORMED":
                    report["warnings"].append(f"The {name} slot was readable but malformed: {explanation}.")
            except ProxyError as exc:
                slot_results[name] = {
                    "read": False, "valid": False, "state": "UNREADABLE",
                    "raw": None, "address": None, "explanation": str(exc),
                }
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
        delegatecall_observed = _has_opcode(runtime, 0xF4)
        report["checks"]["runtime_routing"] = {
            "delegatecall_opcode_observed": delegatecall_observed,
            "status": "DELEGATECALL_OPCODE_PRESENT" if delegatecall_observed else "NO_DELEGATECALL_OPCODE_OBSERVED",
            "limitation": "Opcode presence is runtime evidence, not proof that a specific EIP-1967 slot is consumed by a reachable dispatch path.",
        }
        if not slot_results["admin"]["valid"]:
            report["checks"]["admin_slot_authority"] = {
                "status": "UNVERIFIED" if slot_results["admin"]["state"] == "UNREADABLE" else "MALFORMED",
                "note": "The EIP-1967 admin slot was not established as a canonical zero or address word; effective proxy administration remains unknown.",
            }
            report["warnings"].append("The admin slot was unreadable or malformed; effective proxy administration remains unknown.")
        elif admin_slot:
            report["checks"]["admin_slot_authority"] = {
                "status": "NONZERO_SLOT_CANDIDATE",
                "note": "Storage candidate only; immutable-admin runtime behavior may use a different effective address.",
            }
        else:
            report["checks"]["admin_slot_authority"] = {
                "status": "ZERO_VALUE_OBSERVED",
                "note": "A zero EIP-1967 admin slot does not exclude UUPS or immutable-admin proxy designs.",
            }

        # The EIP-1967 beacon slot is meaningful only when the implementation slot is empty.
        if impl and beacon:
            report["architecture"] = "CONFLICTING_EIP1967_SLOTS"
            report["confidence"] = "HIGH"
            report["status"] = "REVIEW_REQUIRED"
            report["warnings"].append(
                "Both implementation and beacon slots are non-zero. ERC-1967 says the beacon slot "
                "should only be considered when the implementation slot is empty; no routing choice was guessed."
            )
        elif not slot_results["implementation"]["valid"] or not slot_results["beacon"]["valid"]:
            report["architecture"] = "UNVERIFIED_EIP1967"
            report["status"] = "UNVERIFIED"
            report["warnings"].append("Implementation/beacon precedence could not be established because a slot read failed.")
        elif impl:
            report["addresses"]["implementation"] = impl
            report["architecture"] = (
                "ERC1967_IMPLEMENTATION_PROXY_CANDIDATE"
                if delegatecall_observed else "ERC1967_IMPLEMENTATION_SLOT_CANDIDATE"
            )
            report["confidence"] = "MEDIUM" if delegatecall_observed else "LOW"
            report["status"] = "REVIEW_REQUIRED"
            report["warnings"].append(
                "A populated EIP-1967 implementation slot is not by itself proof of proxy routing. "
                + ("Runtime contains DELEGATECALL, but slot consumption/reachability is not proven." if delegatecall_observed
                   else "Runtime contains no DELEGATECALL opcode, so this is a slot candidate only.")
            )
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
                owner_probe = _probe_owner_getter(client, admin_slot)
                report["checks"]["admin_owner_getter"] = owner_probe
                if owner_probe.get("owner_candidate"):
                    report["addresses"]["admin_slot_owner_candidate"] = owner_probe["owner_candidate"]
                transparent_probe = _probe_transparent_admin_routing(
                    client, target, impl, admin_slot, abi,
                )
                report["checks"]["transparent_admin_routing"] = transparent_probe
                if transparent_probe.get("status") == "TRANSPARENT_ROUTING_CANDIDATE":
                    report["upgrade_mechanisms"].append("TRANSPARENT_ADMIN_ROUTING_CANDIDATE")
                    report["evidence"].append(
                        "A safe no-argument view call succeeded through the implementation and for a non-admin proxy caller, "
                        "but failed when called through the proxy from the EIP-1967 admin-slot candidate."
                    )
            if not admin_slot and slot_results["admin"]["read"]:
                report["evidence"].append("The EIP-1967 admin slot was successfully read as zero; this does not exclude UUPS or immutable-admin designs.")
        elif beacon:
            report["addresses"]["beacon"] = beacon
            report["architecture"] = (
                "ERC1967_BEACON_PROXY_CANDIDATE"
                if delegatecall_observed else "ERC1967_BEACON_SLOT_CANDIDATE"
            )
            report["confidence"] = "MEDIUM" if delegatecall_observed else "LOW"
            report["status"] = "REVIEW_REQUIRED"
            report["warnings"].append(
                "A populated EIP-1967 beacon slot and coherent implementation() response do not prove "
                "that reachable proxy dispatch delegates to the beacon implementation."
            )
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
            beacon_owner = _probe_owner_getter(client, beacon)
            report["checks"]["beacon_owner_getter"] = beacon_owner
            if beacon_owner.get("owner_candidate"):
                report["addresses"]["beacon_owner_candidate"] = beacon_owner["owner_candidate"]
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
                    report["architecture"] = (
                        "DIAMOND_LOUPE_AND_DELEGATECALL_CANDIDATE"
                        if delegatecall_observed else "DIAMOND_LOUPE_INTERFACE_CANDIDATE"
                    )
                    report["confidence"] = "MEDIUM" if delegatecall_observed else "LOW"
                    report["status"] = "REVIEW_REQUIRED"
                    report["checks"]["diamond_loupe"] = diamond
                    report["upgrade_mechanisms"].append("DIAMONDCUT_REVIEW_REQUIRED")
                    report["evidence"].append("Diamond Loupe selectors/facets were internally consistent and facet code was present.")
                    report["warnings"].append(
                        "Loupe responses are self-reported by the target. "
                        + ("DELEGATECALL is present, but selector dispatch to the reported facets is not proven." if delegatecall_observed
                           else "No DELEGATECALL opcode was observed; this is a Loupe-interface candidate only.")
                    )
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
        report["checks"]["initialization"] = _inspect_initialization(
            client, target, report.get("addresses", {}).get("implementation"), abi,
        )
        impl_for_chain = report.get("addresses", {}).get("implementation")
        if impl_for_chain and report.get("architecture") in {
            "ERC1967_IMPLEMENTATION_PROXY_CANDIDATE",
            "ERC1967_BEACON_PROXY_CANDIDATE",
            "EIP1167_MINIMAL_CLONE",
        }:
            report["nested_proxy_chain"] = _resolve_nested_proxy_chain(client, impl_for_chain)
        elif impl_for_chain:
            report["nested_proxy_chain"] = {
                "start": impl_for_chain,
                "status": "NOT_FOLLOWED_ROUTING_NOT_PROVEN",
                "hops": [],
                "limitations": ["Nested routing is not followed from an unverified slot/interface claim."],
            }

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



def _event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()


def proxy_upgrade_history(
    rpc_url: str,
    target: str,
    from_block: int,
    to_block: int | None = None,
    *,
    chunk_size: int = 2000,
    max_blocks: int = 100000,
    max_logs: int = 20000,
) -> dict[str, Any]:
    """Reconstruct bounded EIP-1967 Upgraded/BeaconUpgraded/AdminChanged logs."""
    if not is_address(target):
        raise ProxyError("Target must be a 20-byte hexadecimal address.")
    if from_block < 0:
        raise ProxyError("--from-block must be a non-negative block number.")
    if chunk_size < 1 or chunk_size > 10000:
        raise ProxyError("History chunk size must be between 1 and 10000 blocks.")
    client = RpcClient(rpc_url)
    snapshot = client.pin(to_block)
    end = int(snapshot["block_number"])
    if from_block > end:
        raise ProxyError(f"--from-block {from_block} is after the pinned block {end}.")
    if end - from_block + 1 > max_blocks:
        raise ProxyError(
            f"Requested history spans more than {max_blocks} blocks. "
            "Narrow the range; Lowkey does not silently scan an unbounded history."
        )
    topics = {
        _event_topic("Upgraded(address)"): "Upgraded",
        _event_topic("BeaconUpgraded(address)"): "BeaconUpgraded",
        _event_topic("AdminChanged(address,address)"): "AdminChanged",
    }
    filter_topics = [list(topics)]
    events = []
    for start in range(from_block, end + 1, chunk_size):
        stop = min(end, start + chunk_size - 1)
        logs = client.request("eth_getLogs", [{
            "address": target,
            "fromBlock": hex(start),
            "toBlock": hex(stop),
            "topics": filter_topics,
        }])
        if not isinstance(logs, list):
            raise ProxyError(f"eth_getLogs returned a non-list response for blocks {start}-{stop}.")
        for log in logs:
            if not isinstance(log, dict):
                continue
            raw_topics = log.get("topics") or []
            if not raw_topics:
                continue
            event_name = topics.get(str(raw_topics[0]).lower())
            if not event_name:
                continue
            row = {
                "event": event_name,
                "block_number": int(str(log.get("blockNumber", "0x0")), 16),
                "block_hash": log.get("blockHash"),
                "transaction_hash": log.get("transactionHash"),
                "transaction_index": int(str(log.get("transactionIndex", "0x0")), 16),
                "log_index": int(str(log.get("logIndex", "0x0")), 16),
                "removed": bool(log.get("removed", False)),
            }
            if event_name == "Upgraded":
                row["implementation"] = _decode_abi_address(str(raw_topics[1])) if len(raw_topics) > 1 else None
            elif event_name == "BeaconUpgraded":
                row["beacon"] = _decode_abi_address(str(raw_topics[1])) if len(raw_topics) > 1 else None
            elif event_name == "AdminChanged":
                # EIP-1967 declares both AdminChanged address fields non-indexed.
                raw_data = _hex_bytes(str(log.get("data") or "0x"))
                if raw_data is not None and len(raw_data) == 64:
                    row["previous_admin"] = _decode_abi_address("0x" + raw_data[:32].hex())
                    row["new_admin"] = _decode_abi_address("0x" + raw_data[32:].hex())
                else:
                    row["previous_admin"] = None
                    row["new_admin"] = None
                    row["decode_status"] = "MALFORMED_ADMIN_CHANGED_DATA"
            events.append(row)
            if len(events) > max_logs:
                raise ProxyError(
                    f"History exceeded the {max_logs}-log safety cap. Narrow the block range."
                )
    events.sort(key=lambda item: (item["block_number"], item["transaction_index"], item["log_index"]))
    current_slots = {}
    for name, slot in (
        ("implementation", EIP1967_IMPLEMENTATION_SLOT),
        ("beacon", EIP1967_BEACON_SLOT),
        ("admin", EIP1967_ADMIN_SLOT),
    ):
        raw = client.storage(target, slot)
        state, address, explanation = _decode_slot_state(raw)
        current_slots[name] = {"state": state, "address": address, "raw": raw, "explanation": explanation}
    if not client.verify_snapshot():
        raise ProxyError("Pinned block hash changed during history reconstruction; discard this report and retry.")
    canonical_events = [item for item in events if not item.get("removed")]
    latest_upgrade = next((item for item in reversed(canonical_events) if item["event"] == "Upgraded"), None)
    latest_beacon = next((item for item in reversed(canonical_events) if item["event"] == "BeaconUpgraded"), None)
    latest_admin = next((item for item in reversed(canonical_events) if item["event"] == "AdminChanged"), None)

    def reconcile(event, field, slot_name):
        if event is None:
            return {"status": "NO_EVENT_IN_REQUESTED_RANGE"}
        current = current_slots[slot_name]
        if current["state"] == "ZERO":
            matches = str(event.get(field) or "").lower() == ZERO_ADDRESS.lower()
            return {
                "status": "MATCH" if matches else "MISMATCH",
                "event_value": event.get(field),
                "current_slot_value": ZERO_ADDRESS,
            }
        if current["state"] != "ADDRESS":
            return {"status": "CURRENT_SLOT_UNAVAILABLE_OR_MALFORMED", "event_value": event.get(field)}
        matches = str(current["address"]).lower() == str(event.get(field) or "").lower()
        return {
            "status": "MATCH" if matches else "MISMATCH",
            "event_value": event.get(field),
            "current_slot_value": current["address"],
        }

    return {
        "schema": "lowkey.proxy.history.v1",
        "target": target,
        "snapshot": snapshot,
        "range": {"from_block": from_block, "to_block": end},
        "status": "OBSERVED",
        "event_count": len(events),
        "events": events,
        "current_slots": current_slots,
        "reconciliation": {
            "implementation": reconcile(latest_upgrade, "implementation", "implementation"),
            "beacon": reconcile(latest_beacon, "beacon", "beacon"),
            "admin": reconcile(latest_admin, "new_admin", "admin"),
        },
        "limitations": [
            "Only standard EIP-1967 Upgraded, BeaconUpgraded and AdminChanged events emitted by the target are included.",
            "Custom upgrade events, ProxyAdmin-mediated history emitted by another contract, and silent storage writes are not discovered.",
            "The requested range is bounded; no claim is made about upgrades before from_block.",
            "Events are historical signals, not proof that the implementation was safely initialized or that a route was reachable.",
        ],
    }


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
            if path.stat().st_size > 500_000:
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
    namespace_inventory = scan_erc7201_namespaces(root) if root else {
        "status": "NOT_AVAILABLE",
        "namespaces": [],
        "root_collisions": [],
        "warnings": ["No local source root was available for namespace inventory."],
    }
    report["source_signals"] = source_signals
    report["erc7201_namespaces"] = namespace_inventory
    report["source_scan"] = {
        "status": "SCANNED" if root else "NOT_AVAILABLE",
        "root": str(Path(root).resolve()) if root else None,
        "note": "Textual source signals only. Inheritance, aliases, assembly semantics and reachability require compiler-backed analysis.",
    }
    upgrade_names = {
        row.get("name") for row in (report.get("checks", {}).get("upgrade_abi_signals") or [])
    }
    namespace_ids = [
        item.get("namespace_id")
        for item in namespace_inventory.get("namespaces", [])
    ]
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
    if namespace_ids or namespace_inventory.get("root_collisions"):
        hypotheses.append({
            "id": "PROXY-ERC7201-001",
            "title": "Review namespaced storage migration and root-slot integrity",
            "status": "INVESTIGATION_REQUIRED",
            "reason": (
                f"ERC-7201 namespace annotations were found ({len(namespace_ids)} namespace(s)); "
                "the source inventory does not prove compiler member layout or migration compatibility."
            ),
            "next": "Compare V1/V2 source roots with lk proxy validate --reference-source/--candidate-source, then run compiler-backed upgrade validation.",
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
    if (report.get("erc7201_namespaces") or {}).get("namespaces"):
        applicable.append({
            "id": "PROXY-ERC7201-001",
            "title": "Namespaced storage compatibility and migration",
            "invariant_to_test": "preserve namespace roots, member slots and initialized application state across implementation changes",
            "status": "NOT_EXECUTED",
            "required_evidence": [
                "V1/V2 annotated namespace source trees",
                "compiler-backed struct/member storage layout",
                "initializer/reinitializer migration path",
                "paired expected-control and attacker scenarios",
                "pre/post namespaced state snapshots",
            ],
        })
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


def _build_info_layouts(value: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    output = value.get("output") if isinstance(value.get("output"), dict) else value
    contracts = output.get("contracts") if isinstance(output, dict) else None
    if not isinstance(contracts, dict):
        return []
    layouts = []
    for source_name, source_contracts in contracts.items():
        if not isinstance(source_contracts, dict):
            continue
        for contract_name, contract_data in source_contracts.items():
            if not isinstance(contract_data, dict):
                continue
            layout = contract_data.get("storageLayout") or contract_data.get("storage_layout")
            if isinstance(layout, dict) and isinstance(layout.get("storage"), list) and isinstance(layout.get("types"), dict):
                layouts.append((str(source_name), str(contract_name), layout))
    return layouts


def _extract_layout(value: Any, contract_name: str | None = None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    direct = value
    for key in ("storageLayout", "storage_layout", "storageLayoutOutput"):
        if isinstance(value.get(key), dict):
            direct = value[key]
            break
    if isinstance(direct.get("storage"), list) and isinstance(direct.get("types"), dict):
        return direct

    layouts = _build_info_layouts(value)
    if contract_name:
        selector = str(contract_name).strip()
        matches = [
            layout for source, name, layout in layouts
            if selector in {name, f"{source}:{name}"}
        ]
        return matches[0] if len(matches) == 1 else None
    return layouts[0][2] if len(layouts) == 1 else None


def _namespace_struct_block(source: str, start: int) -> tuple[str | None, int | None]:
    """Find the struct declaration following an ERC-7201 annotation."""
    match = re.search(
        r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
        source[start:start + 1200],
    )
    if not match:
        return None, None
    absolute_open = start + match.end() - 1
    depth = 0
    for index in range(absolute_open, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return match.group(1), index + 1
    return match.group(1), None


def _erc7201_root_slot(namespace_id: str) -> str:
    """Calculate the ERC-7201 namespace root exactly as specified."""
    first = int.from_bytes(keccak256(namespace_id.encode("utf-8")), "big")
    encoded = ((first - 1) % (1 << 256)).to_bytes(32, "big")
    root = int.from_bytes(keccak256(encoded), "big") & (~0xFF)
    return "0x" + root.to_bytes(32, "big").hex()


def scan_erc7201_namespaces(root: str | Path, max_files: int = 400) -> dict[str, Any]:
    """Inventory ERC-7201 NatSpec annotations and source-level struct declarations."""
    base = Path(root).expanduser().resolve()
    candidates = []
    priorities = {"src": 0, "contracts": 1, "lib": 2, "node_modules": 3}
    for folder_name in ("src", "contracts", "lib", "node_modules"):
        folder = base / folder_name
        if folder.is_dir():
            candidates.extend(folder.rglob("*.sol"))
    excluded = {".git", "vendor", "cache", "out", "artifacts"}
    namespaces = []
    warnings = []
    ordered = sorted(
        set(candidates),
        key=lambda path: (
            priorities.get(path.relative_to(base).parts[0], 9),
            path.relative_to(base).as_posix(),
        ),
    )
    if len(ordered) > max_files:
        warnings.append(
            f"Namespace scan capped at {max_files} Solidity files; {len(ordered) - max_files} file(s) were not examined."
        )
    if not base.is_dir():
        return {
            "status": "UNVERIFIED",
            "root": str(base),
            "namespaces": [],
            "root_collisions": [],
            "warnings": [f"Source directory does not exist: {base}"],
            "limitation": "No namespace conclusion is possible without both source trees.",
        }
    for path in ordered[:max_files]:
        try:
            relative_parts = path.relative_to(base).parts
            if any(part in excluded for part in relative_parts):
                continue
            size = path.stat().st_size
            if size > 1_000_000:
                warnings.append(
                    f"{path.relative_to(base).as_posix()} was skipped because it exceeds the 1 MB source-scan limit."
                )
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"Could not read {path}: {exc}")
            continue
        for match in re.finditer(
            r"@custom:storage-location\s+erc7201:([A-Za-z0-9._-]+)",
            source,
            re.IGNORECASE,
        ):
            namespace_id = match.group(1)
            struct_name, struct_end = _namespace_struct_block(source, match.end())
            if not struct_name or struct_end is None:
                warnings.append(
                    f"{path.relative_to(base).as_posix()}:{source.count(chr(10), 0, match.start()) + 1}: "
                    f"namespace {namespace_id!r} has no complete following struct declaration."
                )
                continue
            struct_header = re.search(
                r"\bstruct\s+" + re.escape(struct_name) + r"\s*\{",
                source[match.end():struct_end],
            )
            if not struct_header:
                warnings.append(
                    f"{path.relative_to(base).as_posix()}:{source.count(chr(10), 0, match.start()) + 1}: "
                    f"namespace {namespace_id!r} could not anchor its struct body."
                )
                continue
            struct_start = match.end() + struct_header.end() - 1
            body = source[struct_start + 1:struct_end - 1]
            # This is deliberately a source declaration digest, not a compiler layout.
            body = re.sub(r"/\*[\s\S]*?\*/", "", body)
            body = re.sub(r"//[^\n]*", "", body)
            members = [
                re.sub(r"\s+", " ", item).strip()
                for item in body.split(";")
                if re.sub(r"\s+", " ", item).strip()
            ]
            line = source.count("\n", 0, match.start()) + 1
            namespaces.append({
                "namespace_id": namespace_id,
                "struct_name": struct_name,
                "root_slot": _erc7201_root_slot(namespace_id),
                "path": path.relative_to(base).as_posix(),
                "line": line,
                "members": members,
                "members_sha256": hashlib.sha256(
                    "\n".join(members).encode("utf-8")
                ).hexdigest(),
                "evidence_type": "NATSPEC_SOURCE_DECLARATION",
                "confidence": "MEDIUM",
            })
    root_owners: dict[str, set[str]] = {}
    for item in namespaces:
        root_owners.setdefault(item["root_slot"], set()).add(item["namespace_id"])
    collisions = [
        {"root_slot": slot, "namespace_ids": sorted(ids)}
        for slot, ids in root_owners.items() if len(ids) > 1
    ]
    return {
        "status": "SCANNED",
        "root": str(base),
        "namespaces": namespaces,
        "root_collisions": collisions,
        "warnings": warnings,
        "limitation": (
            "Member declarations are source-text evidence only. This scanner does not resolve inheritance, "
            "aliases, compiler packing, custom assembly layout or nested type encoding; use compiler-backed "
            "storage layouts and OpenZeppelin's upgrade validator before approving an upgrade."
        ),
    }


def compare_erc7201_namespaces(
    reference_root: str | Path,
    candidate_root: str | Path,
) -> dict[str, Any]:
    """Compare namespace identifiers, calculated roots and source-level members."""
    reference = scan_erc7201_namespaces(reference_root)
    candidate = scan_erc7201_namespaces(candidate_root)
    result = {
        "schema": "lowkey.proxy.erc7201-diff.v1",
        "status": "INCONCLUSIVE",
        "removed": [],
        "added": [],
        "changed": [],
        "unchanged": [],
        "root_collisions": {
            "reference": reference["root_collisions"],
            "candidate": candidate["root_collisions"],
        },
        "warnings": list(reference["warnings"]) + list(candidate["warnings"]),
        "reference": reference,
        "candidate": candidate,
        "summary": "",
    }
    if reference.get("status") != "SCANNED" or candidate.get("status") != "SCANNED":
        result["status"] = "INCONCLUSIVE"
        result["summary"] = "One or both namespace source trees could not be scanned."
        return result
    old_items = reference["namespaces"]
    new_items = candidate["namespaces"]
    old_counts: dict[str, int] = {}
    new_counts: dict[str, int] = {}
    for item in old_items:
        old_counts[item["namespace_id"]] = old_counts.get(item["namespace_id"], 0) + 1
    for item in new_items:
        new_counts[item["namespace_id"]] = new_counts.get(item["namespace_id"], 0) + 1
    result["duplicate_ids"] = {
        "reference": sorted(key for key, count in old_counts.items() if count > 1),
        "candidate": sorted(key for key, count in new_counts.items() if count > 1),
    }
    old_by_id = {item["namespace_id"]: item for item in old_items}
    new_by_id = {item["namespace_id"]: item for item in new_items}
    for namespace_id in sorted(old_by_id.keys() - new_by_id.keys()):
        result["removed"].append(old_by_id[namespace_id])
    for namespace_id in sorted(new_by_id.keys() - old_by_id.keys()):
        result["added"].append(new_by_id[namespace_id])
    for namespace_id in sorted(old_by_id.keys() & new_by_id.keys()):
        old = old_by_id[namespace_id]
        new = new_by_id[namespace_id]
        differences = []
        if old["root_slot"] != new["root_slot"]:
            differences.append("calculated root slot changed")
        if old["struct_name"] != new["struct_name"]:
            differences.append("annotated struct name changed")
        if old["members"] != new["members"]:
            differences.append("source-level member declarations changed")
        if differences:
            result["changed"].append({
                "namespace_id": namespace_id,
                "differences": differences,
                "reference": old,
                "candidate": new,
            })
        else:
            result["unchanged"].append({
                "namespace_id": namespace_id,
                "root_slot": old["root_slot"],
                "struct_name": old["struct_name"],
                "member_count": len(old["members"]),
            })
    if result["root_collisions"]["reference"] or result["root_collisions"]["candidate"]:
        result["status"] = "REVIEW_REQUIRED"
        result["warnings"].append("Multiple namespace identifiers calculate to the same root slot.")
    elif result["duplicate_ids"]["reference"] or result["duplicate_ids"]["candidate"]:
        result["status"] = "REVIEW_REQUIRED"
        result["warnings"].append("A namespace identifier appears in multiple source locations; the inventory is ambiguous.")
    elif result["warnings"]:
        result["status"] = "INCONCLUSIVE"
        result["summary"] = "The namespace scan reported incomplete or unreadable source evidence."
    elif result["removed"]:
        result["status"] = "INCOMPATIBLE_CANDIDATE"
        result["summary"] = "One or more reference namespace identifiers are missing from the candidate."
    elif result["changed"]:
        result["status"] = "LAYOUT_CHANGE_REQUIRES_VALIDATION"
        result["warnings"].append(
            "Source-level namespace declarations changed. This is not a compiler layout diff; "
            "validate member slots, offsets, inheritance and migration semantics."
        )
    elif result["added"]:
        result["status"] = "NAMESPACE_ADDITIONS_REVIEW"
        result["warnings"].append(
            "New namespace IDs were added. Check root-slot collisions, initializer migration and protocol invariants."
        )
    elif not old_items and not new_items:
        result["status"] = "NO_ERC7201_ANNOTATIONS"
        result["warnings"].append("No ERC-7201 annotations were found in either source tree.")
    else:
        result["status"] = "IDS_AND_DECLARATIONS_MATCH"
        result["warnings"].append(
            "Namespace IDs and source declarations match, but this is not a storage-compatibility proof."
        )
    if not result["summary"]:
        result["summary"] = (
            f"{len(result['unchanged'])} unchanged, {len(result['changed'])} changed, "
            f"{len(result['removed'])} removed, {len(result['added'])} added namespace(s)."
        )
    return result


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


def _read_json_file(path: str, contract_name: str | None = None) -> dict[str, Any]:
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise ProxyError(f"Storage layout file does not exist: {candidate}")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProxyError(f"Could not read JSON artifact {candidate}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProxyError(f"JSON artifact must contain an object: {candidate}")
    layout = _extract_layout(value, contract_name=contract_name)
    if layout is None:
        available = _build_info_layouts(value)
        if available and not contract_name:
            choices = ", ".join(
                f"{source}:{name}" for source, name, _layout in available[:12]
            )
            suffix = " ..." if len(available) > 12 else ""
            raise ProxyError(
                f"{candidate} contains {len(available)} contract storage layouts. "
                f"Select the contract with --reference-contract/--candidate-contract. "
                f"Available: {choices}{suffix}"
            )
        if available and contract_name:
            raise ProxyError(
                f"Contract selector {contract_name!r} did not uniquely match a storage layout in {candidate}. "
                "Use the exact ContractName or Source.sol:ContractName."
            )
        raise ProxyError(
            f"{candidate} has no compiler storage layout. Rebuild with storageLayout output enabled."
        )
    # Normalize the selected nested Foundry/solc build-info layout for the comparator.
    value["storageLayout"] = layout
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
    checks = report.get("checks") or {}
    uuid = checks.get("proxiable_uuid") or {}
    if uuid:
        lines.append(f"PROXIABLE UUID {uuid.get('status')}")
    admin_authority = checks.get("admin_slot_authority") or {}
    if admin_authority:
        lines.append(f"ADMIN SLOT STATE {admin_authority.get('status')}")
    transparent = checks.get("transparent_admin_routing") or {}
    if transparent:
        lines.append(f"ADMIN ROUTING    {transparent.get('status')}")
    initialization = checks.get("initialization") or {}
    if initialization:
        lines.append(f"INITIALIZATION   {initialization.get('status')}")
        if initialization.get("initializer_entrypoints"):
            lines.append(
                "INIT FUNCTIONS   " + ", ".join(
                    item.get("signature", item.get("name", "?"))
                    for item in initialization["initializer_entrypoints"]
                )
            )
    chain = report.get("nested_proxy_chain") or {}
    if chain:
        lines.append(f"NESTED ROUTE     {chain.get('status')}")
    for key, label in (
        ("admin_slot_owner_candidate", "ADMIN OWNER CAND"),
        ("beacon_owner_candidate", "BEACON OWNER CAND"),
    ):
        if addresses.get(key):
            lines.append(f"{label:<16} {addresses[key]}")
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
        namespace_inventory = report.get("erc7201_namespaces") or {}
        lines.append("ERC-7201 NAMESPACES")
        for item in namespace_inventory.get("namespaces", []):
            lines.append(
                f"  {item.get('namespace_id')} -> {item.get('root_slot')} "
                f"({item.get('path')}:{item.get('line')})"
            )
        lines.append("AUTHORITY / LIFECYCLE CHECKS")
        for key in ("transparent_admin_routing", "admin_owner_getter", "beacon_owner_getter", "initialization"):
            value = checks.get(key)
            if value:
                lines.append(f"  {key}: {value.get('status')}")
                for probe in value.get("probes", []):
                    lines.append(f"    {probe}")
        if chain:
            lines.append("NESTED PROXY CHAIN")
            for hop in chain.get("hops", []):
                lines.append(
                    f"  [{hop.get('depth')}] {hop.get('address')} "
                    f"{hop.get('architecture')} -> {hop.get('implementation', '-')}"
                )
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
        "inspect", "audit", "report", "plan", "attack", "validate", "diff", "history", "simulate",
    } else "inspect"
    address = next((item for item in positional if is_address(item)), None) or config.get("target")
    if action in {"validate", "diff"}:
        reference = values.get("--reference")
        candidate = values.get("--candidate")
        if not reference or not candidate:
            print("Usage: lk proxy validate --reference <V1.json> --candidate <V2.json> [--reference-contract NAME --candidate-contract NAME] [--reference-source DIR --candidate-source DIR]")
            return 2
        try:
            reference_contract = values.get("--reference-contract")
            candidate_contract = values.get("--candidate-contract")
            if bool(reference_contract) != bool(candidate_contract):
                raise ProxyError("--reference-contract and --candidate-contract must be provided together.")
            result = compare_storage_layouts(
                _read_json_file(reference, reference_contract),
                _read_json_file(candidate, candidate_contract),
            )
            reference_source = values.get("--reference-source")
            candidate_source = values.get("--candidate-source")
            if bool(reference_source) != bool(candidate_source):
                raise ProxyError("--reference-source and --candidate-source must be provided together.")
            if reference_source and candidate_source:
                result["erc7201"] = compare_erc7201_namespaces(reference_source, candidate_source)
                if (
                    result["status"] == "COMPATIBLE_CANDIDATE"
                    and result["erc7201"]["status"] != "IDS_AND_DECLARATIONS_MATCH"
                ):
                    result["status"] = "INCONCLUSIVE"
                    result["compatible_candidate"] = False
                    result["summary"] += " ERC-7201 source review is not a clean match."
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
            + (
                "\nERC-7201      " + result["erc7201"]["status"]
                + "\n" + result["erc7201"]["summary"]
                if result.get("erc7201") else ""
            )
            + "\nNOTE         Candidate compatibility is not proof of upgrade safety."
        ))
        return 0 if result["status"] == "COMPATIBLE_CANDIDATE" else 1

    if not is_address(address):
        print("LOWKEY ERROR: Set a target with 'lk target <address>' or pass a proxy address.")
        return 2
    if action == "history":
        if "--from-block" not in values:
            print("Usage: lk proxy history <address> --from-block N [--to-block N] [--json]")
            return 2
        try:
            from_block = int(values["--from-block"], 0)
            to_block = int(values["--to-block"], 0) if "--to-block" in values else None
        except ValueError:
            print("LOWKEY ERROR: --from-block/--to-block must be integers or 0x-prefixed block numbers.")
            return 2
        history_rpc = values.get("--rpc-url")
        if not history_rpc and callable(rpc_resolver):
            try:
                history_rpc = rpc_resolver(config, explicit_rpc=None, target=address)
            except TypeError:
                history_rpc = rpc_resolver(config)
        if not history_rpc:
            print("LOWKEY BLOCKED: No RPC is configured. Pass --rpc-url or set 'lk rpc'.")
            return 2
        try:
            history = proxy_upgrade_history(history_rpc, address, from_block, to_block)
        except ProxyError as exc:
            print("LOWKEY BLOCKED: " + str(exc))
            return 2
        try:
            report_root = root_resolver() if callable(root_resolver) else None
        except Exception:
            report_root = None
        path = _save_report(
            report_root, address,
            f"history-{history['range']['from_block']}-{history['range']['to_block']}.json",
            history,
        )
        if path:
            history["evidence_path"] = str(path)
        if "json" in flags:
            print(json.dumps(history, indent=2, sort_keys=True))
        else:
            print(
                "LOWKEY / PROXY UPGRADE HISTORY\n"
                f"TARGET       {address}\n"
                f"RANGE        {history['range']['from_block']}..{history['range']['to_block']}\n"
                f"EVENTS       {history['event_count']}\n"
                + "\n".join(
                    f"  {item['block_number']}  {item['event']}  "
                    f"{item.get('implementation') or item.get('beacon') or item.get('new_admin') or '-'}"
                    for item in history["events"]
                )
                + "\nRECONCILE    "
                + ", ".join(f"{key}={value['status']}" for key, value in history["reconciliation"].items())
                + "\nNOTE         Event history is bounded to the selected range and is not a security verdict."
            )
            if path:
                print("EVIDENCE     " + str(path))
        return 0
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
