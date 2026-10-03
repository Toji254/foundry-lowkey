"""Comprehensive concept graph for Lowkey's Solidity/Yul connect command.

The graph is intentionally separate from the cheatsheet prose.  It knows:
- canonical concept names and aliases,
- relationships between Solidity/Yul/Foundry learning concepts,
- small teaching scenes for common multi-concept patterns,
- a safe generic bridge for combinations that have no curated scene.

It is a teaching graph, not a claim that every edge is a direct syntax rule.
"""

from __future__ import annotations

from collections import defaultdict
import heapq


def _norm(value: str) -> str:
    return "-".join(str(value).strip().lower().replace("_", "-").split())


# These are deliberately semantic aliases.  Several old cheatsheet topics are
# broader bundles; connect expands those bundles rather than pretending the
# bundle is one atomic Solidity construct.
_EXPLICIT_ALIASES = {
    "struct": "structs",
    "structs": "structs",
    "mapping": "mapping",
    "mappings": "mapping",
    "map": "mapping",
    "nested-mapping": "nested-mapping",
    "nested-mappings": "nested-mapping",
    "array": "arrays",
    "arrays": "arrays",
    "dynamic-array": "arrays",
    "dynamic-arrays": "arrays",
    "fixed-array": "fixed-array",
    "fixed-arrays": "fixed-array",
    "static-array": "fixed-array",
    "static-arrays": "fixed-array",
    "enum": "enum",
    "enums": "enum",
    "bytes": "bytes",
    "dynamic-bytes": "bytes",
    "bytes32": "bytes32",
    "bytesn": "bytesN",
    "address": "address",
    "addresses": "address",
    "address-payable": "payable",
    "payable-address": "payable",
    "string": "string",
    "strings": "string",
    "uint": "uint256",
    "uint256": "uint256",
    "uints": "uint256",
    "int": "int256",
    "int256": "int256",
    "bool": "bool",
    "constructor": "constructor",
    "constructors": "constructor",
    "import": "imports",
    "imports": "imports",
    "inherit": "inheritance",
    "inheritance": "inheritance",
    "abstract": "abstract",
    "interface": "interface",
    "interfaces": "interface",
    "override": "override",
    "virtual": "virtual",
    "override-virtual": "override-virtual",
    "function": "function",
    "functions": "function",
    "function-syntax": "function",
    "function-call": "function",
    "function-calls": "function",
    "calls": "call",
    "call": "call",
    "external-call": "external-call",
    "external-calls": "external-call",
    "interface-call": "external-call",
    "low-level-call": "low-level-call",
    "staticcall": "staticcall",
    "delegatecall": "delegatecall",
    "modifier": "modifier",
    "modifiers": "modifier",
    "event": "events",
    "events": "events",
    "error": "errors",
    "errors": "errors",
    "custom-error": "custom-errors",
    "custom-errors": "custom-errors",
    "require": "require",
    "revert": "revert",
    "assert": "assert",
    "receive": "receive",
    "fallback": "fallback",
    "payable": "payable",
    "abi": "abi",
    "abi-encode": "abi.encode",
    "abi.encode": "abi.encode",
    "abi-decode": "abi.decode",
    "abi.decode": "abi.decode",
    "encodepacked": "encodePacked",
    "abi.encodepacked": "encodePacked",
    "keccak": "keccak256",
    "keccak256": "keccak256",
    "hash": "keccak256",
    "keccak-selectors": "keccak-selectors",
    "function-selector": "function-selector",
    "function-selectors": "function-selector",
    "selector": "function-selector",
    "function-signature": "function-signature",
    "function-signatures": "function-signature",
    "calldata": "calldata",
    "msg-data": "msg.data",
    "msg.data": "msg.data",
    "msg-sig": "msg.sig",
    "msg.sig": "msg.sig",
    "returndata": "returndata",
    "return-data": "returndata",
    "return-data-bytes": "returndata",
    "bytes.concat": "bytes.concat",
    "string.concat": "string.concat",
    "ecrecover": "ecrecover",
    "sha256": "sha256",
    "ripemd160": "ripemd160",
    "addmod": "addmod",
    "mulmod": "mulmod",
    "eip712": "eip712",
    "signature-verification": "signature-verification",
    "nonce": "nonce",
    "storage": "storage",
    "memory": "memory",
    "calldata-deep": "calldata-deep",
    "call-data-layout": "call-data-layout",
    "data-locations": "storage-memory-calldata",
    "storage-memory-calldata": "storage-memory-calldata",
    "storage-layout": "storage-layout",
    "storage-packing": "storage-packing",
    "mapping-slots": "mapping-slots",
    "nested-mapping-slots": "nested-mapping-slots",
    "array-storage": "array-storage",
    "custom-storage-layout": "custom-storage-layout",
    "erc7201": "erc7201",
    "transient-storage": "transient-storage",
    "transient": "transient-storage",
    "yul": "yul",
    "assembly": "yul",
    "yul-memory": "yul-memory",
    "yul-storage": "yul-storage",
    "yul-calldata": "yul-calldata",
    "yul-control-flow": "yul-control-flow",
    "yul-functions": "yul-functions",
    "yul-call": "yul-call",
    "loops": "loops",
    "loop": "loops",
    "for": "for",
    "while": "while",
    "do-while": "do-while",
    "for-each": "for-each",
    "if": "if-else",
    "if-else": "if-else",
    "ternary": "ternary",
    "unchecked": "unchecked",
    "delete": "delete",
    "msg.sender": "msg.sender",
    "msg-sender": "msg.sender",
    "msg.value": "msg.value",
    "msg-value": "msg.value",
    "block.timestamp": "block.timestamp",
    "timestamp": "block.timestamp",
    "block.number": "block.number",
    "tx.origin": "tx.origin",
    "nonce-value": "nonce",
    "gasleft": "gasleft",
    "contract-balance": "contract-balance",
    "address(this).balance": "contract-balance",
    "ether-flow": "ether-flow",
    "access-control": "access-control",
    "ownership": "access-control",
    "checks-effects-interactions": "checks-effects-interactions",
    "reentrancy": "reentrancy",
    "front-running": "front-running",
    "oracle": "oracle",
    "proxy-fallback": "proxy-fallback",
    "selfdestruct": "selfdestruct",
    "destroy": "selfdestruct",
    "library": "library",
    "using-for": "using-for",
    "new": "new",
    "new-contract": "new",
    "type-metadata": "type-metadata",
    "contract-types": "contract-types",
    "function-types": "function-types",
    "user-defined-value-types": "user-defined-value-types",
    "udvt": "user-defined-value-types",
    "try-catch": "try-catch",
    "returns": "returns",
    "constant": "constant-immutable",
    "immutable": "constant-immutable",
    "constant-immutable": "constant-immutable",
    "external-function-types": "external-function-types",
    "test": "test",
    "script": "script",
    "poc": "poc",
    "forge-cheatcodes": "forge-cheatcodes",
    "forge-cheatcodes-map": "forge-cheatcodes-map",
}


_COMPOSITE_ALIASES = {
    "arrays-mappings": {"arrays", "mapping"},
    "array-mapping": {"arrays", "mapping"},
    "arrays-structs": {"arrays", "structs"},
    "array-struct": {"arrays", "structs"},
    "mapping-struct": {"mapping", "structs"},
    "mapping-array-value": {"mapping", "arrays"},
    "storage-memory-calldata": {"storage", "memory", "calldata"},
    "receive-vs-fallback": {"receive", "fallback"},
    "call-anatomy": {"call", "staticcall", "delegatecall"},
    "strings-bytes": {"string", "bytes"},
    "globals": {"msg.sender", "msg.value", "msg.data", "block.timestamp", "tx.origin"},
    "globals-map": {
        "msg.sender",
        "msg.value",
        "msg.data",
        "msg.sig",
        "block.timestamp",
        "block.number",
        "tx.origin",
        "gasleft",
        "contract-balance",
    },
    "msg-block-tx": {
        "msg.sender",
        "msg.value",
        "msg.data",
        "msg.sig",
        "block.timestamp",
        "block.number",
        "tx.origin",
    },
    "msg.value-vs-balance": {"msg.value", "contract-balance"},
    "keccak-selectors": {"keccak256", "function-selector"},
    "mapping-types": {"mapping"},
    "struct-types": {"structs"},
    "types-table": {"types"},
    "abi-call": {"function-selector", "abi.encode", "calldata", "call"},
    "function-selector-call": {"function-selector", "calldata", "call"},
    "mapping-decode-hash": {"mapping", "abi.decode", "keccak256"},
    "proxy-flow": {"proxy-fallback", "fallback", "delegatecall", "storage-layout"},
}


_EXTRA_MEANINGS = {
    "function": "A named callable operation with parameters, visibility, mutability, and optional return values.",
    "modifier": "Reusable wrapper logic that runs around a function body.",
    "mapping": "A key-to-value lookup table whose missing keys read as the value type's default.",
    "structs": "A record type that groups named fields of possibly different types.",
    "arrays": "An ordered collection indexed from zero.",
    "fixed-array": "An array with a compile-time fixed length, such as uint256[3].",
    "nested-mapping": "A mapping whose values are mappings, so a value is selected by multiple keys.",
    "enum": "A fixed set of named states represented internally as integers.",
    "bytes": "A dynamically sized byte sequence.",
    "bytes32": "A fixed 32-byte value commonly used for hashes, IDs, and compact keys.",
    "address": "An EVM account or contract address.",
    "payable": "An address/function form that is permitted to participate in ETH transfers.",
    "string": "A dynamically sized textual byte sequence.",
    "uint256": "A 256-bit unsigned integer.",
    "int256": "A 256-bit signed integer.",
    "bool": "A true/false value.",
    "constructor": "Deployment-time initialization code; it is not a normal callable function after deployment.",
    "imports": "A source-level declaration dependency; importing does not execute the imported code.",
    "inheritance": "A contract relationship that reuses or overrides parent behavior/state.",
    "interface": "A typed declaration of externally callable function shapes without implementation state.",
    "abstract": "A contract intended to be inherited rather than deployed as a complete implementation.",
    "override": "Explicitly marks a function as implementing/replacing an inherited virtual or interface function.",
    "virtual": "Allows an inherited function to be overridden.",
    "visibility": "Controls where a function or state variable can be accessed.",
    "mutability": "Describes whether a function can read state, write state, and/or receive ETH.",
    "receive": "Special empty-calldata ETH entry point.",
    "fallback": "Special entry point for unmatched function calls, and for plain ETH when no receive function exists.",
    "call": "A low-level external message call that returns a success flag and raw return bytes.",
    "low-level-call": "Raw external call syntax that exposes calldata, ETH/gas options, success, and return bytes.",
    "staticcall": "A low-level external call that is constrained from changing state.",
    "delegatecall": "Runs another contract's code with the caller's storage and call context.",
    "external-call": "A call crossing the contract boundary to another address.",
    "abi": "The data convention used to turn Solidity values and calls into EVM bytes and back.",
    "abi.encode": "ABI-encodes typed values into bytes.",
    "abi.decode": "Interprets ABI-encoded bytes as specified Solidity types.",
    "encodePacked": "ABI-style packed encoding with tighter concatenation rules; useful but collision-prone when dynamic values are combined carelessly.",
    "keccak256": "Keccak-256 hashing; Solidity returns the digest as bytes32.",
    "function-signature": "Canonical function name plus parameter types used when computing a function selector.",
    "function-selector": "The first four bytes of the Keccak-256 hash of a canonical function signature.",
    "keccak-selectors": "The combined idea of Keccak hashing and the four-byte function selector derived from a function signature.",
    "calldata": "Read-only input data supplied to an external function.",
    "msg.data": "The complete raw calldata bytes for the current call.",
    "msg.sig": "The first four bytes of the current call's calldata, normally the function selector.",
    "returndata": "Raw bytes returned by the most recent low-level external call context.",
    "events": "Log records emitted by contracts for off-chain consumers.",
    "event-indexed": "An event parameter stored in a log topic for efficient filtering rather than only in the data payload.",
    "errors": "Revert-data declarations describing failure conditions.",
    "custom-errors": "Typed, compact error values returned when execution reverts.",
    "require": "Guard a condition and revert when it is false.",
    "revert": "Explicitly abort execution and roll back the current call's state changes.",
    "assert": "Check an invariant or internal assumption that should never fail.",
    "try-catch": "Catch failures from external function calls or contract creation.",
    "storage": "Persistent contract state.",
    "memory": "Temporary, mutable data during one call.",
    "storage-memory-calldata": "The three major Solidity data-location concepts for reference-type values.",
    "storage-layout": "The rules determining how state variables occupy storage slots.",
    "storage-packing": "Compact placement of small value types into shared storage slots when layout rules allow it.",
    "mapping-slots": "The Keccak-derived storage location calculation used for mapping values.",
    "nested-mapping-slots": "Repeated Keccak slot derivation used by nested mappings.",
    "array-storage": "Storage layout for fixed and dynamic arrays, including their data locations and element offsets.",
    "custom-storage-layout": "Compiler-supported customization of the base storage layout for advanced upgrade/storage namespaces.",
    "erc7201": "A namespaced storage pattern that derives a deterministic storage root for a module/namespace.",
    "transient-storage": "Transaction-scoped storage cleared at the end of the transaction; only value types are supported.",
    "yul": "Solidity's low-level inline-assembly language for direct EVM-oriented operations.",
    "yul-memory": "Yul access to temporary byte-addressable memory.",
    "yul-storage": "Yul access to persistent storage with sload/sstore.",
    "yul-calldata": "Yul access to the raw external call payload.",
    "yul-control-flow": "Yul branching and looping primitives such as if, switch, for, break, and continue.",
    "yul-functions": "Local Yul helper functions inside an assembly block.",
    "yul-call": "Low-level EVM calls expressed through Yul call-family opcodes.",
    "loops": "Repeated execution controlled by a stopping condition.",
    "for": "Counted repetition with initializer, condition, and post-expression.",
    "while": "Repetition that tests a condition before each iteration.",
    "do-while": "Repetition that executes once before testing the condition.",
    "for-each": "A teaching pattern for iterating over a collection; Solidity uses explicit indexing rather than a native foreach keyword.",
    "ternary": "A value-producing condition ? trueValue : falseValue expression.",
    "unchecked": "A block where checked integer overflow/underflow is disabled.",
    "delete": "Reset a variable to its type's default value.",
    "msg.sender": "The immediate caller of the current message call.",
    "msg.value": "The ETH attached to the current message call.",
    "block.timestamp": "The block timestamp visible to the current execution context.",
    "block.number": "The current block number.",
    "tx.origin": "The original externally owned account that started the transaction.",
    "gasleft": "The remaining gas available to the current execution context.",
    "contract-balance": "The ETH currently held by the contract address.",
    "ether-flow": "The movement and accounting of ETH through payable entry points and outgoing calls.",
    "access-control": "Logic deciding which addresses or roles may perform sensitive actions.",
    "checks-effects-interactions": "A sequencing pattern that performs checks and state effects before risky external interactions.",
    "reentrancy": "An execution hazard where external calls allow control to re-enter a contract before the original operation finishes.",
    "front-running": "Acting on transaction information observed in the public transaction pool before the original transaction executes.",
    "oracle": "An external data source accessed by a contract, commonly through an interface.",
    "proxy-fallback": "A proxy pattern where fallback forwards calls to an implementation, often with delegatecall.",
    "selfdestruct": "The EVM mechanism historically used to remove or alter contract code/balance behavior; its effects are constrained by modern EVM semantics.",
    "library": "Reusable deployed code or inlined internal functions that can be attached to types with using-for.",
    "using-for": "Attaches library/free functions as member functions or operators for a type.",
    "new": "Creates a fresh contract instance and invokes its constructor.",
    "type-metadata": "Compile-time/runtime metadata such as type(T).max, type(C).interfaceId, or contract code properties.",
    "contract-types": "Types representing contracts/interfaces and values holding contract addresses with callable members.",
    "function-types": "First-class function values that can be stored in variables and invoked later.",
    "user-defined-value-types": "Distinct types created from an elementary value type with explicit wrapping/unwrapping.",
    "external-function-types": "Function pointer values for externally callable functions, including address and selector components.",
    "constant-immutable": "State initialization forms with values fixed at compile time or at construction.",
    "returns": "Declares and supplies the values returned from a function.",
    "ecrecover": "A built-in cryptographic primitive that recovers an address from an ECDSA signature and digest.",
    "sha256": "The SHA-256 cryptographic hash function available as a Solidity global.",
    "ripemd160": "The RIPEMD-160 cryptographic hash function available as a Solidity global.",
    "addmod": "Modular addition with overflow-safe semantics.",
    "mulmod": "Modular multiplication with overflow-safe semantics.",
    "bytes.concat": "Concatenates bytes and fixed-size byte values into one dynamic byte array.",
    "string.concat": "Concatenates strings.",
    "nonce": "A monotonically advancing account-level value used in transaction ordering and commonly included in replay protection.",
    "eip712": "Typed structured-data signing convention that commonly combines domain separation, hashing, and signature recovery.",
    "signature-verification": "A flow that validates a digest/signature pair and usually binds the result to an expected signer.",
    "test": "A Foundry test contract that executes assertions against a system under test.",
    "script": "A Foundry deployment/interaction program, typically driven by forge script.",
    "poc": "A proof-of-concept program that demonstrates a concrete contract behavior or exploit path.",
    "forge-cheatcodes": "Foundry VM helpers for manipulating execution context and state during tests/scripts.",
}


def _catalog_rows():
    rows = []
    try:
        from solidity_cheat_topics import register_topics
    except ImportError:
        try:
            from lowkey.solidity_cheat_topics import register_topics
        except ImportError:
            return rows

    def add(name, aliases, category, meaning, *args, **kwargs):
        rows.append((name, aliases or [], category, meaning))

    register_topics(add)
    return rows


_CATALOG_ROWS = _catalog_rows()
_CATALOG_ALIAS_TO_NAME = {}
_CATALOG_NAME_TO_MEANING = {}

for _name, _aliases, _category, _meaning in _CATALOG_ROWS:
    _key = _norm(_name)
    _CATALOG_ALIAS_TO_NAME[_key] = _name
    _CATALOG_NAME_TO_MEANING[_name] = _meaning
    for _alias in _aliases:
        _CATALOG_ALIAS_TO_NAME[_norm(_alias)] = _name


def canonicalize(name: str) -> str:
    key = _norm(name)

    # Composite aliases are expanded by expand_name, not here.
    if key in _COMPOSITE_ALIASES:
        return key

    if key in _EXPLICIT_ALIASES:
        return _EXPLICIT_ALIASES[key]

    catalog_name = _CATALOG_ALIAS_TO_NAME.get(key)
    if catalog_name:
        # Normalize old bundled topics into their useful connect identities.
        mapped = {
            "function-syntax": "function",
            "functions": "function",
            "modifiers": "modifier",
            "bytesN": "bytesN",
            "calls": "call",
            "abi-encode": "abi.encode",
            "abi-decode": "abi.decode",
            "keccak-selectors": "keccak-selectors",
            "strings-bytes": "string-bytes",
            "storage-memory-calldata": "storage-memory-calldata",
            "globals": "globals",
            "msg-block-tx": "msg-block-tx",
        }.get(catalog_name)
        return mapped or _norm(catalog_name)

    return key


def expand_name(name: str):
    key = _norm(name)
    if key in _COMPOSITE_ALIASES:
        return {canonicalize(item) for item in _COMPOSITE_ALIASES[key]}
    return {canonicalize(key)}


def connection_meaning(name: str) -> str:
    canonical = canonicalize(name)
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]

    for catalog_name, meaning in _CATALOG_NAME_TO_MEANING.items():
        if canonical == canonicalize(catalog_name):
            return meaning

    return "A recognized Solidity/Yul/Foundry learning concept."


# Explicit semantic edges.  They encode actual data/control/code-boundary
# relationships, not mere lexical similarity.
_SEMANTIC_EDGES = [
    ("variables", "types", "a variable has a type and a value"),
    ("types", "structs", "struct is a user-defined data type"),
    ("types", "enum", "enum is a user-defined finite type"),
    ("types", "bytesN", "bytesN is a fixed-size byte type"),
    ("types", "bytes", "bytes is a dynamic byte type"),
    ("types", "address", "address is a value type"),
    ("types", "uint256", "uint256 is an integer value type"),
    ("types", "int256", "int256 is a signed integer value type"),
    ("types", "bool", "bool stores true or false"),
    ("types", "function-types", "functions can be used as typed values"),
    ("types", "contract-types", "contracts/interfaces have contract types"),
    ("types", "user-defined-value-types", "UDVTs wrap elementary value types"),
    ("structs", "mapping", "a mapping value can be a struct"),
    ("structs", "arrays", "a struct can contain arrays"),
    ("structs", "enum", "a struct can contain enum state"),
    ("structs", "bytes", "a struct can contain dynamic bytes"),
    ("structs", "address", "a struct can contain addresses"),
    ("mapping", "nested-mapping", "a mapping value can be another mapping"),
    ("mapping", "mapping-struct", "mapping can directly select a struct record"),
    ("mapping", "mapping-array-value", "mapping can directly select an array"),
    ("mapping", "arrays", "mapping values can be arrays"),
    ("mapping", "msg.sender", "caller address is commonly used as a mapping key"),
    ("mapping", "msg.value", "ETH accounting is commonly keyed by caller"),
    ("mapping", "access-control", "roles/permissions are commonly stored in mappings"),
    ("mapping", "enum", "a mapping can store an enum as its value"),
    ("mapping", "storage", "mapping state is persistent storage"),
    ("mapping", "keccak256", "mapping IDs and storage slots commonly use Keccak"),
    ("mapping", "abi.decode", "decoded input can become a mapping key"),
    ("mapping", "events", "mapping updates are commonly mirrored in events"),
    ("mapping", "loops", "arrays and mappings are often paired for enumeration"),
    ("arrays", "loops", "indexed iteration commonly walks arrays"),
    ("arrays", "storage", "dynamic storage arrays persist and can grow"),
    ("arrays", "memory", "dynamic arrays can be copied to memory"),
    ("arrays", "calldata", "external functions can accept dynamic arrays in calldata"),
    ("arrays", "array-storage", "array element locations follow storage layout rules"),
    ("arrays", "mapping-array-value", "a mapping can select an array to index/push"),
    ("arrays", "for", "for loops commonly index arrays"),
    ("arrays", "while", "while loops can walk a collection"),
    ("arrays", "do-while", "do-while can iterate after one initial execution"),
    ("arrays", "for-each", "foreach-like iteration is implemented with indexing"),
    ("arrays", "delete", "delete can clear an array element or reset an array"),
    ("nested-mapping", "nested-mapping-slots", "each nested key adds another slot derivation"),
    ("mapping-slots", "nested-mapping-slots", "nested mapping slots recurse from mapping slot roots"),
    ("mapping-slots", "keccak256", "mapping locations are Keccak-derived"),
    ("mapping-slots", "yul-storage", "Yul sload/sstore can inspect derived mapping slots"),
    ("array-storage", "storage-layout", "array positions depend on layout"),
    ("storage-layout", "storage-packing", "layout determines whether value types share slots"),
    ("storage-layout", "structs", "struct fields have deterministic slot/offset rules"),
    ("storage-layout", "inheritance", "base contracts participate in state-variable ordering"),
    ("storage-layout", "mapping-slots", "mapping anchors are storage layout slots"),
    ("storage-layout", "transient-storage", "persistent and transient layouts are independent"),
    ("custom-storage-layout", "storage-layout", "custom layouts alter where persistent state roots begin"),
    ("erc7201", "custom-storage-layout", "namespaced storage derives a deterministic custom root"),
    ("erc7201", "structs", "namespaced state commonly uses a struct as a module root"),
    ("erc7201", "mapping", "namespaced modules can contain mappings"),
    ("erc7201", "keccak256", "namespace roots are hash-derived"),
    ("erc7201", "yul-storage", "Yul can inspect a namespaced storage root manually"),
    ("bytes", "bytes32", "dynamic bytes and fixed bytes32 solve different sizing problems"),
    ("string", "bytes", "strings and bytes are both dynamic byte sequences"),
    ("string", "abi.encode", "strings are ABI encodable"),
    ("string", "string.concat", "strings can be concatenated"),
    ("bytes", "bytes.concat", "bytes values can be concatenated"),
    ("bytes", "abi.encode", "bytes values are ABI encodable"),
    ("bytes", "abi.decode", "ABI decoding consumes bytes"),
    ("bytes", "keccak256", "hashes consume byte sequences"),
    ("bytes", "calldata", "dynamic bytes can arrive as calldata"),
    ("bytes", "storage", "dynamic bytes have special storage encoding"),
    ("string", "storage", "strings use the same storage encoding family as bytes"),
    ("address", "payable", "payable is the ETH-transfer form of an address"),
    ("address", "msg.sender", "msg.sender has address type"),
    ("address", "msg.value", "address identifies a caller/recipient while msg.value supplies ETH"),
    ("address", "contract-types", "contract-typed values are address-like contract references"),
    ("constructor", "imports", "an imported contract can define a constructor"),
    ("constructor", "inheritance", "base and child constructors chain at deployment"),
    ("constructor", "msg.sender", "the deployment caller is available in construction"),
    ("constructor", "address", "constructors commonly receive addresses"),
    ("constructor", "string", "constructors can receive strings"),
    ("constructor", "uint256", "constructors commonly receive numeric configuration"),
    ("constructor", "new", "new creates a contract and invokes its constructor"),
    ("imports", "inheritance", "imports expose declarations used by inheritance"),
    ("imports", "interface", "interfaces are commonly imported"),
    ("imports", "library", "libraries are commonly imported"),
    ("inheritance", "abstract", "abstract contracts are intended for inheritance"),
    ("inheritance", "override", "child implementations override inherited functions"),
    ("inheritance", "virtual", "virtual functions permit overrides"),
    ("override", "interface", "interface implementations are marked override"),
    ("interface", "address", "an interface reference points at a contract address"),
    ("interface", "function", "interfaces declare function shapes"),
    ("interface", "external-call", "calling an interface crosses a contract boundary"),
    ("interface", "oracle", "oracle integrations commonly use interfaces"),
    ("function", "visibility", "functions declare who can call them"),
    ("function", "mutability", "functions declare state/ETH mutability"),
    ("function", "returns", "functions declare outputs"),
    ("function", "calldata", "external functions receive input through calldata"),
    ("function", "function-signature", "name and parameter types form a canonical signature"),
    ("function", "function-selector", "a selector identifies the callable function entry point"),
    ("function", "modifier", "modifiers wrap function execution"),
    ("function", "events", "state-changing functions commonly emit events"),
    ("function", "errors", "functions can revert with errors"),
    ("function", "function-types", "function values can refer to callable functions"),
    ("function", "external-function-types", "external function pointers carry an external call shape"),
    ("function-signature", "function-selector", "selector is derived from the canonical signature"),
    ("keccak256", "function-selector", "function selectors are Keccak-derived"),
    ("keccak256", "abi.encode", "encoded values are common hash input"),
    ("keccak256", "encodePacked", "packed bytes are common hash input"),
    ("keccak256", "abi.decode", "decode can recover typed values from hashed/encoded payloads"),
    ("abi.encode", "bytes", "encoding produces bytes"),
    ("abi.encode", "abi.decode", "decode reverses a compatible encoding"),
    ("abi.encode", "calldata", "ABI encoding forms call argument bytes"),
    ("abi.encode", "function-selector", "encoded call data is prefixed with a selector"),
    ("abi.encode", "events", "event data uses ABI-style encodings"),
    ("abi.encode", "errors", "error instances use ABI-style encoding"),
    ("abi.decode", "calldata", "raw calldata can be decoded into typed values"),
    ("abi.decode", "returndata", "raw return bytes can be decoded into typed values"),
    ("abi.decode", "errors", "revert bytes can be decoded as error payloads"),
    ("abi.decode", "mapping", "decoded values can select storage"),
    ("encodePacked", "keccak256", "packed encoding is frequently hashed"),
    ("function-selector", "msg.sig", "msg.sig is normally the selector of the current call"),
    ("function-selector", "calldata", "the first four calldata bytes are normally the selector"),
    ("function-selector", "low-level-call", "low-level calls commonly build selectors manually"),
    ("function-selector", "abi.encodeWithSelector", "selector plus encoded arguments forms call data"),
    ("abi.encodeWithSelector", "calldata", "it constructs raw call bytes"),
    ("abi.encodeWithSelector", "call", "the resulting bytes can feed target.call"),
    ("abi.encodeCall", "interface", "abi.encodeCall uses a typed function reference"),
    ("abi.encodeCall", "function", "the referenced function provides compile-time type checking"),
    ("abi.encodeCall", "calldata", "the result is call-ready ABI bytes"),
    ("call", "returndata", "low-level calls return success and raw bytes"),
    ("call", "reentrancy", "external calls create a callback boundary"),
    ("call", "checks-effects-interactions", "CEI places state effects before risky external calls"),
    ("call", "address", "the target of a low-level call is an address"),
    ("call", "payable", "call options can attach ETH"),
    ("call", "try-catch", "external call failures can be handled"),
    ("call", "staticcall", "staticcall is the read-only sibling of call"),
    ("call", "delegatecall", "delegatecall is the context-preserving sibling of call"),
    ("staticcall", "returndata", "static reads still return raw bytes"),
    ("delegatecall", "storage", "delegatecall executes against caller storage"),
    ("delegatecall", "proxy-fallback", "proxies commonly forward fallback through delegatecall"),
    ("delegatecall", "storage-layout", "proxy implementations must agree on storage layout"),
    ("returndata", "abi.decode", "return bytes can be decoded"),
    ("returndata", "try-catch", "external-call failures expose revert/return bytes"),
    ("returndata", "bytes", "raw return data is bytes"),
    ("fallback", "msg.data", "fallback can inspect raw calldata"),
    ("fallback", "msg.sig", "fallback can inspect the selector"),
    ("fallback", "receive", "both are special dispatch routes"),
    ("fallback", "payable", "payable fallback can receive plain ETH"),
    ("fallback", "proxy-fallback", "proxy dispatch commonly lives in fallback"),
    ("receive", "msg.value", "receive runs for empty-calldata ETH transfers"),
    ("receive", "msg.sender", "receive can account ETH by caller"),
    ("receive", "payable", "receive must be payable"),
    ("payable", "msg.value", "payable entry points can receive msg.value"),
    ("msg.value", "contract-balance", "attached ETH contributes to contract balance during execution"),
    ("msg.sender", "access-control", "authorization commonly starts from caller identity"),
    ("msg.sender", "tx.origin", "the two caller identities differ through contract calls"),
    ("tx.origin", "access-control", "tx.origin should not replace msg.sender for authorization"),
    ("block.timestamp", "front-running", "time-dependent state can be observable before execution"),
    ("block.timestamp", "timestamp", "timestamp is the block time context"),
    ("block.timestamp", "globals", "timestamp is one of the global block variables"),
    ("nonce", "signature-verification", "nonces commonly prevent replay of signed actions"),
    ("nonce", "front-running", "commit/authorization schemes may bind actions to sequence values"),
    ("signature-verification", "keccak256", "signed messages are commonly represented by a digest"),
    ("signature-verification", "ecrecover", "ECDSA recovery yields the signing address"),
    ("signature-verification", "bytes", "signatures are passed as byte data"),
    ("signature-verification", "nonce", "signed messages often include a nonce"),
    ("eip712", "signature-verification", "EIP-712 structures are used for typed signing"),
    ("eip712", "keccak256", "EIP-712 builds hash digests"),
    ("eip712", "nonce", "typed authorization commonly includes a nonce"),
    ("events", "event-indexed", "indexed parameters become filterable topics"),
    ("events", "keccak256", "dynamic indexed values are represented by Keccak hashes"),
    ("events", "mapping", "events often mirror mapping/accounting changes"),
    ("event-indexed", "keccak256", "dynamic indexed values are hashed into topics"),
    ("errors", "revert", "errors are instantiated through revert"),
    ("errors", "require", "require can use a custom error"),
    ("errors", "try-catch", "external revert data can be caught"),
    ("custom-errors", "abi.decode", "custom-error payloads are ABI-encoded"),
    ("custom-errors", "revert", "custom errors are emitted through revert"),
    ("require", "assert", "both stop execution but have different intended roles"),
    ("require", "revert", "require is a convenience form of conditional revert"),
    ("assert", "unchecked", "unchecked arithmetic can affect which assertions are reachable"),
    ("try-catch", "new", "contract creation failures can be caught"),
    ("try-catch", "interface", "typed external function calls can be wrapped in try/catch"),
    ("storage-memory-calldata", "structs", "reference-type structs use data locations"),
    ("storage-memory-calldata", "arrays", "dynamic arrays use data locations"),
    ("storage-memory-calldata", "bytes", "dynamic bytes use data locations"),
    ("storage-memory-calldata", "abi.decode", "decoded reference values need a destination location"),
    ("calldata", "msg.data", "named calldata parameters are views over the call payload"),
    ("calldata", "calldata-slices", "calldata can be sliced without copying"),
    ("calldata-slices", "msg.data", "a slice selects part of raw calldata"),
    ("calldata-slices", "abi.decode", "a selected bytes region can be decoded"),
    ("calldata-deep", "function-selector", "raw calldata begins with the selector"),
    ("call-data-layout", "function-selector", "the ABI call layout starts with four selector bytes"),
    ("call-data-layout", "abi.encode", "arguments occupy ABI-encoded tail words"),
    ("call-data-layout", "calldata", "the call payload is physically stored as calldata"),
    ("storage", "yul-storage", "Yul sload/sstore access persistent storage"),
    ("storage", "yul", "assembly can access persistent state directly"),
    ("memory", "yul-memory", "Yul mload/mstore access memory"),
    ("calldata", "yul-calldata", "Yul calldataload/calldatacopy access input"),
    ("yul", "yul-memory", "assembly uses mload/mstore"),
    ("yul", "yul-storage", "assembly uses sload/sstore"),
    ("yul", "yul-calldata", "assembly uses calldata opcodes"),
    ("yul", "yul-call", "assembly exposes low-level call opcodes"),
    ("yul", "yul-control-flow", "Yul has its own control-flow forms"),
    ("yul", "yul-functions", "Yul supports local helper functions"),
    ("yul-storage", "mapping-slots", "manual mapping slot calculations feed sload/sstore"),
    ("yul-calldata", "abi.decode", "assembly can inspect/construct ABI payloads before decoding"),
    ("transient-storage", "reentrancy", "transaction-scoped state is commonly used for reentrancy guards"),
    ("transient-storage", "yul-storage", "Yul has tload/tstore for transient storage"),
    ("transient-storage", "storage-layout", "transient layout is separate from persistent storage layout"),
    ("reentrancy", "checks-effects-interactions", "CEI is a common reentrancy defense"),
    ("reentrancy", "call", "reentrancy requires an external callback boundary"),
    ("access-control", "modifier", "modifiers often implement authorization checks"),
    ("access-control", "enum", "role systems often encode roles as enums"),
    ("access-control", "events", "role changes are often emitted as events"),
    ("enum", "mapping", "roles/states can be stored in mappings"),
    ("enum", "events", "state transitions can be emitted"),
    ("enum", "require", "allowed transitions are commonly guarded"),
    ("library", "using-for", "using-for attaches library/free functions to types"),
    ("using-for", "user-defined-value-types", "UDVTs are commonly given domain operations"),
    ("using-for", "function", "attached functions are callable through member syntax"),
    ("new", "address", "contract creation yields a fresh contract address"),
    ("new", "constructor", "new supplies constructor arguments"),
    ("new", "try-catch", "creation can be wrapped in try/catch"),
    ("type-metadata", "contract-types", "type(C) exposes contract metadata"),
    ("type-metadata", "interface", "interfaces expose interfaceId metadata"),
    ("type-metadata", "uint256", "integer types expose min/max metadata"),
    ("function-types", "function", "function values refer to callable operations"),
    ("external-function-types", "address", "external function pointers include a target address"),
    ("external-function-types", "function-selector", "external function pointers include a selector"),
    ("external-function-types", "call", "external function pointers can be invoked across a boundary"),
    ("selfdestruct", "contract-balance", "historical selfdestruct behavior is tied to contract balance/code semantics"),
    ("selfdestruct", "address", "selfdestruct operates on the current contract address"),
    ("selfdestruct", "ether-flow", "selfdestruct is a special ETH movement edge case"),
    ("timestamp", "block.timestamp", "timestamp maps directly to the global block variable"),
    ("front-running", "calldata", "public transaction input can be observed before execution"),
    ("oracle", "interface", "oracle calls commonly use typed interfaces"),
    ("oracle", "call", "oracle reads cross a contract boundary"),
    ("oracle", "try-catch", "oracle failures can be handled"),
    ("front-running", "signature-verification", "signed authorizations can still be observed and replayed without proper binding"),
    ("front-running", "nonce", "nonces can bind a signed action to a single use"),
    ("delete", "storage", "delete resets persistent state to defaults"),
    ("delete", "mapping", "delete can reset a mapped value"),
    ("delete", "arrays", "delete can clear array elements"),
    ("unchecked", "uint256", "unchecked suppresses overflow/underflow checks for uint arithmetic"),
    ("unchecked", "addmod", "modular arithmetic is an alternative when wraparound semantics are desired"),
    ("unchecked", "mulmod", "mulmod provides modular multiplication without intermediate overflow"),
    ("addmod", "mulmod", "both perform modular arithmetic"),
    ("addmod", "uint256", "operands and result are integer values"),
    ("mulmod", "uint256", "operands and result are integer values"),
    ("bytes.concat", "bytes", "concat consumes/produces bytes"),
    ("string.concat", "string", "concat consumes/produces strings"),
    ("string.concat", "bytes", "strings have a bytes representation"),
    ("constant-immutable", "constructor", "immutable values are assigned during construction while constants are fixed at compile time"),
    ("constant-immutable", "storage", "both interact differently with the state model than ordinary mutable storage"),
    ("variables", "storage", "state variables are persistent"),
    ("variables", "memory", "locals can use memory for temporary reference data"),
    ("variables", "calldata", "external parameters can use calldata"),
    ("forge-cheatcodes", "test", "cheatcodes are primarily used in tests"),
    ("forge-cheatcodes", "script", "cheatcodes are also used by scripts"),
    ("test", "assert", "tests use assertions to express expected results"),
    ("test", "vm-prank", "prank changes caller context in tests"),
    ("vm-prank", "msg.sender", "prank directly changes the caller seen by the contract"),
    ("vm-start-prank", "msg.sender", "persistent prank changes caller context across calls"),
    ("vm-deal", "contract-balance", "deal sets an account's ETH balance in tests"),
    ("vm-warp", "block.timestamp", "warp changes block time in tests"),
    ("vm-roll", "block.number", "roll changes block number in tests"),
    ("vm-assume", "fuzz-tests", "assumptions constrain fuzz inputs"),
    ("vm-bound", "bounded-fuzz", "bound constrains fuzzed values"),
    ("vm-expect-revert", "revert", "test expects a revert"),
    ("vm-expect-emit", "events", "test expects an event"),
    ("vm-recordlogs", "events", "recordlogs exposes emitted logs"),
    ("vm-snapshot", "storage", "snapshots preserve/restore test state"),
    ("vm-storage", "storage-layout", "tests can inspect raw storage"),
    ("vm-etch", "storage", "tests can replace code at an address"),
    ("vm-fork", "fork-tests", "fork tests run against forked chain state"),
    ("vm-env", "script-env", "environment variables feed test/script configuration"),
    ("vm-expect-call", "call", "test can assert an external call shape"),
    ("vm-mockcall", "call", "mockcall intercepts an external call"),
    ("vm-hoax", "msg.sender", "hoax combines funded address setup and caller manipulation"),
    ("script-deploy", "new", "deploy scripts create contracts"),
    ("script-interaction", "call", "scripts interact with deployed contracts"),
    ("poc-reentrancy", "reentrancy", "a reentrancy PoC demonstrates a callback path"),
    ("poc-access-control", "access-control", "an access-control PoC targets authorization boundaries"),
    ("poc-accounting", "mapping", "accounting PoCs often manipulate balances/mappings"),
    ("poc-oracle", "oracle", "oracle PoCs target external data assumptions"),
    ("poc-signature", "signature-verification", "signature PoCs target signer/replay assumptions"),
    ("poc-upgrade", "proxy-fallback", "upgrade PoCs target proxy implementation boundaries"),
    ("poc-storage", "storage-layout", "storage PoCs target slot/layout assumptions"),
    ("poc-cross-contract", "external-call", "cross-contract PoCs target call boundaries"),
    ("poc-token", "mapping", "token PoCs often exercise balances/allowances mappings"),
    ("test-poc-workflow", "poc", "the test-to-PoC workflow validates a concrete exploit"),
]


# Curated learning groups add many legitimate high-level connections and make
# sure even obscure catalog topics are attached to a meaningful subsystem.
_SEMANTIC_GROUPS = [
    ("data-model", [
        "variables", "types", "uint256", "int256", "bool", "address", "bytes", "bytesN",
        "bytes32", "string", "structs", "enum", "arrays", "fixed-array",
        "mapping", "nested-mapping", "mapping-struct", "mapping-array-value",
        "storage-memory-calldata", "storage-layout", "storage-packing", "array-storage",
        "mapping-slots", "nested-mapping-slots", "delete", "transient-storage",
        "custom-storage-layout", "erc7201", "user-defined-value-types",
    ]),
    ("call-surface", [
        "function", "visibility", "mutability", "returns", "function-signature",
        "function-selector", "function-types", "external-function-types", "interface",
        "contract-types", "calldata", "calldata-deep", "calldata-slices",
        "call-data-layout", "call", "external-call", "low-level-call",
        "staticcall", "delegatecall", "returndata", "abi", "abi.encode", "abi.decode",
        "abi.encodeWithSelector", "abi.encodeCall", "encodePacked", "msg.data", "msg.sig",
    ]),
    ("dispatch-creation", [
        "imports", "constructor", "inheritance", "abstract", "override", "virtual",
        "library", "using-for", "new", "proxy-fallback", "fallback", "receive",
        "selfdestruct", "type-metadata", "constant-immutable",
    ]),
    ("error-control", [
        "if-else", "ternary", "loops", "for", "while", "do-while", "for-each", "unchecked",
        "require", "revert", "assert", "errors", "custom-errors", "try-catch",
    ]),
    ("crypto-auth", [
        "keccak256", "function-signature", "function-selector", "abi.encode", "encodePacked",
        "ecrecover", "sha256", "ripemd160", "addmod", "mulmod", "signature-verification",
        "eip712", "nonce", "front-running", "access-control", "tx.origin", "msg.sender",
    ]),
    ("eth-context", [
        "msg.sender", "msg.value", "msg.data", "msg.sig", "block.timestamp", "block.number",
        "tx.origin", "gasleft", "contract-balance", "payable", "ether-flow", "receive",
        "fallback", "call", "reentrancy", "checks-effects-interactions",
    ]),
    ("events-errors", [
        "events", "event-indexed", "keccak256", "errors", "custom-errors", "revert",
        "require", "try-catch", "returndata", "abi.decode",
    ]),
    ("yul", [
        "yul", "yul-memory", "yul-storage", "yul-calldata", "yul-control-flow",
        "yul-functions", "yul-call", "memory", "storage", "calldata", "mapping-slots",
        "nested-mapping-slots", "keccak256", "call", "returndata", "transient-storage",
    ]),
    ("security-audit", [
        "reentrancy", "checks-effects-interactions", "access-control", "tx.origin",
        "front-running", "timestamp", "block.timestamp", "oracle", "signature-verification",
        "nonce", "proxy-fallback", "delegatecall", "storage-layout", "custom-storage-layout",
        "erc7201", "selfdestruct", "unchecked", "delete", "loops", "arrays", "mapping",
    ]),
    ("foundry-test", [
        "forge-cheatcodes", "test", "test-structure", "test-arrange-act-assert",
        "test-assertions", "fuzz-tests", "bounded-fuzz", "invariant-tests", "invariant-handler",
        "fork-tests", "test-reverts", "test-events", "vm-prank", "vm-start-prank", "vm-deal",
        "vm-warp", "vm-roll", "vm-assume", "vm-bound", "vm-makeaddr", "vm-label",
        "vm-expect-revert", "vm-expect-emit", "vm-recordlogs", "vm-snapshots", "vm-storage",
        "vm-etch", "vm-fork", "vm-env", "vm-expect-call", "vm-mockcall", "vm-hoax",
        "poc", "poc-reentrancy", "poc-access-control", "poc-accounting", "poc-oracle",
        "poc-signature", "poc-upgrade", "poc-storage", "poc-token", "poc-cross-contract",
        "script", "script-structure", "script-broadcast", "script-env", "script-deploy",
        "script-interaction",
    ]),
]


def _add_edge(edges, seen, left, right, label):
    a, b = canonicalize(left), canonicalize(right)
    if a == b:
        return
    key = tuple(sorted((a, b)))
    if key in seen:
        return
    seen.add(key)
    edges.append((a, b, label))


def _build_edges():
    edges = []
    seen = set()

    for left, right, label in _SEMANTIC_EDGES:
        _add_edge(edges, seen, left, right, label)

    # Connect all concepts in each semantic group through a star.  This gives
    # the graph broad coverage without forcing every pair to pretend it has a
    # direct syntax relationship.
    for group_name, members in _SEMANTIC_GROUPS:
        unique = []
        seen_nodes = set()
        for member in members:
            node = canonicalize(member)
            if node not in seen_nodes:
                unique.append(node)
                seen_nodes.add(node)
        if len(unique) < 2:
            continue
        anchor = unique[0]
        for node in unique[1:]:
            _add_edge(
                edges,
                seen,
                anchor,
                node,
                f"same {group_name} subsystem; trace how the two concepts meet",
            )

    # Catalog-category stars guarantee that newly added cheatsheet topics are
    # graph-visible even before they get a bespoke semantic edge.
    category_groups = defaultdict(list)
    for name, _aliases, category, _meaning in _CATALOG_ROWS:
        node = canonicalize(name)
        if node not in category_groups[category]:
            category_groups[category].append(node)

    for category, members in category_groups.items():
        unique = []
        seen_nodes = set()
        for node in members:
            if node not in seen_nodes:
                unique.append(node)
                seen_nodes.add(node)
        if len(unique) >= 2:
            anchor = unique[0]
            for node in unique[1:]:
                _add_edge(
                    edges,
                    seen,
                    anchor,
                    node,
                    f"same cheatsheet area ({category}); compare their roles",
                )

    # Cross-category spine: the learner's normal path through a contract.
    spine = [
        "variables", "types", "function", "calldata", "abi.encode",
        "function-selector", "interface", "call", "returndata",
        "abi.decode", "mapping", "structs", "arrays", "storage",
        "storage-layout", "keccak256", "events", "errors",
        "constructor", "inheritance", "access-control", "msg.sender",
        "msg.value", "receive", "fallback", "delegatecall",
        "proxy-fallback", "reentrancy", "test", "poc", "yul",
    ]
    for left, right in zip(spine, spine[1:]):
        _add_edge(edges, seen, left, right, "contract lifecycle/data-flow spine")

    return edges


_COMPREHENSIVE_CONNECTION_EDGES = _build_edges()


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _COMPOSITE_ALIASES or key in _EXPLICIT_ALIASES:
        return True
    if key in _CATALOG_ALIAS_TO_NAME:
        return True
    canonical = canonicalize(key)
    if canonical in _EXTRA_MEANINGS:
        return True
    nodes = {a for a, _b, _label in _COMPREHENSIVE_CONNECTION_EDGES}
    nodes.update(b for _a, b, _label in _COMPREHENSIVE_CONNECTION_EDGES)
    return canonical in nodes


def _scene(
    keys,
    title,
    story,
    code,
    variables,
    flow,
    call,
):
    return {
        "keys": frozenset(canonicalize(k) for k in keys),
        "title": title,
        "story": story,
        "code": code.strip("\n"),
        "variables": list(variables),
        "flow": list(flow),
        "call": call,
    }


COMPREHENSIVE_MICRO_SCENES = [
    _scene(
        ["interface", "function", "arrays"],
        "An interface call returns an array",
        "An address is wrapped in an interface type. A declared external function is called, and its dynamic array result flows back.",
        """
interface IUserStore {
    function users() external view returns (address[] memory);
}

contract Reader {
    IUserStore public store;

    constructor(address store_) {
        store = IUserStore(store_);
    }

    function getUsers() external view returns (address[] memory) {
        return store.users();
    }
}
""",
        [
            ("state", "IUserStore", "store", "IUserStore(0xStore)", "Typed view of a contract address."),
            ("parameter", "address", "store_", "0xStore", "Address supplied at deployment."),
            ("interface function", "address[] memory", "users()", "[alice, bob]", "Callable function promised by the interface."),
            ("external function", "address[] memory", "getUsers()", "store.users()", "Returns the array from the target."),
        ],
        [
            "store_ is an address.",
            "IUserStore(store_) treats that address as a contract exposing users().",
            "getUsers() crosses the external call boundary.",
            "users() returns a dynamic array.",
        ],
        "reader.getUsers();",
    ),
    _scene(
        ["imports", "constructor", "inheritance"],
        "Import → base/interface → constructor chain",
        "import makes a declaration available; deployment enters the child constructor, which can pass a value into an imported base constructor.",
        """
// Owned.sol
contract Owned {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }
}

// Vault.sol
import "./Owned.sol";

contract Vault is Owned {
    string public name;

    constructor(string memory name_)
        Owned(msg.sender)
    {
        name = name_;
    }
}
""",
        [
            ("base state", "address", "owner", "msg.sender", "Stored in the imported base."),
            ("parameter", "string memory", "name_", '"Savings"', "Value supplied to Vault."),
            ("base parameter", "address", "owner_", "msg.sender", "Value supplied through Owned(...)."),
        ],
        [
            "import exposes Owned but does not execute anything.",
            "new Vault(\"Savings\") enters Vault's constructor.",
            "Owned(msg.sender) supplies the base constructor argument.",
            "Owned stores the deployment caller as owner.",
        ],
        'new Vault("Savings");',
    ),
    _scene(
        ["structs", "mapping", "nested-mapping", "arrays", "enum", "bytes", "address"],
        "Address → struct → enum/bytes/array → nested mapping",
        "One address selects a structured record. That record contains state of several types, while a second lookup uses another key.",
        """
enum Status { Open, Done }

struct Profile {
    address owner;
    uint256 score;
    Status status;
    bytes note;
    uint256[] tags;
}

mapping(address => Profile) public profiles;
mapping(address => mapping(bytes32 => uint256)) public balances;
address[] public users;

function update(
    address user_,
    uint256 score_,
    Status status_,
    bytes calldata note_,
    bytes32 id_,
    uint256[] calldata tags_
) external {
    Profile storage profile = profiles[user_];

    profile.owner = user_;
    profile.score = score_;
    profile.status = status_;
    profile.note = note_;
    profile.tags = tags_;

    balances[user_][id_] = score_;
    users.push(user_);
}
""",
        [
            ("mapping key", "address", "user_", "0xAlice", "Chooses one Profile."),
            ("storage ref", "Profile storage", "profile", "profiles[user_]", "Writes persist."),
            ("field", "Status", "status_", "Status.Done", "Named state."),
            ("field", "bytes", "note_", 'hex"6869"', "Dynamic raw bytes."),
            ("field", "uint256[]", "tags_", "[1, 2, 3]", "Dynamic array."),
            ("nested key", "bytes32", "id_", 'bytes32("A")', "Second mapping key."),
        ],
        [
            "user_ selects a Profile.",
            "Profile storage exposes persistent fields.",
            "The enum, bytes, and array become part of the record.",
            "balances[user_][id_] performs a second keyed lookup.",
            "users.push(user_) grows a dynamic array.",
        ],
        'update(alice, 22, Status.Done, hex"6869", bytes32("A"), [1, 2, 3]);',
    ),
    _scene(
        ["mapping", "keccak256"],
        "A hash becomes a mapping key",
        "The hash itself is just a bytes32 value. A mapping can use that value like any other key.",
        """
mapping(bytes32 => address) public owners;

function register(bytes calldata raw) external {
    bytes32 id = keccak256(raw);
    owners[id] = msg.sender;
}
""",
        [
            ("state", "mapping(bytes32 => address)", "owners", "owners[id]", "Keyed by a 32-byte hash."),
            ("parameter", "bytes calldata", "raw", 'hex"416c696365"', "Raw bytes being hashed."),
            ("global", "address", "msg.sender", "0xAlice", "Stored as the mapping value."),
            ("derived", "bytes32", "id", "keccak256(raw)", "Hash-derived key."),
        ],
        [
            "raw contains bytes.",
            "keccak256(raw) produces a bytes32 value.",
            "owners[id] uses that digest as the mapping key.",
            "msg.sender supplies the stored address value.",
        ],
        'register(hex"416c696365");',
    ),
    _scene(
        ["mapping", "abi.decode"],
        "Decode first, then use the decoded value as a key",
        "Raw ABI bytes are turned into a typed address, and that address is immediately used to select a mapping entry.",
        """
mapping(address => uint256) public balances;

function set(bytes calldata raw, uint256 amount_) external {
    address user_ = abi.decode(raw, (address));
    balances[user_] = amount_;
}
""",
        [
            ("state", "mapping(address => uint256)", "balances", "balances[user_]", "Address-to-balance lookup."),
            ("parameter", "bytes calldata", "raw", "abi.encode(alice)", "Raw input."),
            ("decoded", "address", "user_", "abi.decode(raw, (address))", "Typed mapping key."),
            ("parameter", "uint256", "amount_", "100", "Value written to the mapping."),
        ],
        [
            "raw arrives as bytes.",
            "abi.decode interprets those bytes as one address.",
            "user_ becomes the mapping key.",
            "amount_ becomes the mapped value.",
        ],
        "set(abi.encode(alice), 100);",
    ),
    _scene(
        ["mapping", "keccak256", "abi.decode"],
        "decode/hash/mapping",
        "One raw payload can be viewed in two ways: abi.decode extracts typed data, while keccak256 hashes the original bytes into the mapping key.",
        """
mapping(bytes32 => address) public owners;

function register(bytes calldata raw) external {
    address user_ = abi.decode(raw, (address));

    bytes32 id = keccak256(raw);
    owners[id] = user_;
}
""",
        [
            ("state", "mapping(bytes32 => address)", "owners", "owners[id]", "The hash becomes the mapping key."),
            ("parameter", "bytes calldata", "raw", "ABI-encoded address bytes", "Same bytes feed both operations."),
            ("decoded", "address", "user_", "abi.decode(raw, (address))", "Typed value extracted from raw."),
            ("derived", "bytes32", "id", "keccak256(raw)", "Hash used as mapping key."),
        ],
        [
            "raw is just bytes at the contract boundary.",
            "abi.decode interprets those bytes as an address.",
            "keccak256 hashes the same bytes without changing them.",
            "The digest becomes the mapping key; the decoded address becomes the value.",
        ],
        "register(abi.encode(alice));",
    ),
    _scene(
        ["abi.encode", "abi.decode", "keccak256"],
        "Encode ↔ bytes ↔ decode, with hashing on the wire format",
        "The encoder and decoder agree on types and order. Hashing the encoded bytes gives a stable digest for that exact payload.",
        """
function pack(address user_, uint256 amount_)
    external
    pure
    returns (bytes memory raw, bytes32 digest)
{
    raw = abi.encode(user_, amount_);
    digest = keccak256(raw);
}

function unpack(bytes calldata raw)
    external
    pure
    returns (address user_, uint256 amount_)
{
    (user_, amount_) = abi.decode(raw, (address, uint256));
}
""",
        [
            ("parameter", "address", "user_", "0xAlice", "First ABI field."),
            ("parameter", "uint256", "amount_", "100", "Second ABI field."),
            ("return", "bytes", "raw", "abi.encode(...)", "Encoded wire representation."),
            ("return", "bytes32", "digest", "keccak256(raw)", "Hash of exact bytes."),
        ],
        [
            "pack creates the bytes.",
            "keccak256 hashes exactly those bytes.",
            "unpack receives the same bytes.",
            "abi.decode restores the address and uint256 in the same order.",
        ],
        "unpack(rawFromPack);",
    ),
    _scene(
        ["function-signature", "function-selector", "calldata", "abi.decode"],
        "Signature → selector → calldata → parameters",
        "A canonical function signature determines four selector bytes; the remaining calldata encodes the parameters.",
        """
// selector = bytes4(keccak256("set(uint256)"))

function set(uint256 amount_) external {
    // amount_ was decoded from calldata by the ABI dispatcher.
}
""",
        [
            ("signature", "string", "signature", '"set(uint256)"', "Canonical name + parameter types."),
            ("selector", "bytes4", "selector", "bytes4(keccak256(signature))", "First four calldata bytes."),
            ("calldata", "bytes", "msg.data", "selector + ABI arguments", "Raw call payload."),
            ("parameter", "uint256", "amount_", "100", "Typed value decoded by the dispatcher."),
        ],
        [
            "Start with the canonical signature.",
            "Hash it and take four bytes for the selector.",
            "Place the selector at the start of calldata.",
            "ABI-encoded arguments follow it.",
        ],
        "cast calldata 'set(uint256)' 100;",
    ),
    _scene(
        ["function-selector", "abi.encodeWithSelector", "calldata", "call", "returndata"],
        "Selector + arguments → raw call → return bytes",
        "The caller builds the selector and arguments explicitly, sends raw calldata, then inspects the returned bytes.",
        """
bytes memory data =
    abi.encodeWithSelector(
        bytes4(keccak256("quote(uint256)")),
        100
    );

(bool ok, bytes memory result) = target.call(data);
require(ok);
""",
        [
            ("local", "bytes memory", "data", "selector + ABI arguments", "Raw calldata."),
            ("local", "bool", "ok", "true", "Low-level success flag."),
            ("local", "bytes memory", "result", "raw return data", "Bytes returned by target.call."),
        ],
        [
            "Derive/select four bytes for quote(uint256).",
            "Encode 100 after the selector.",
            "target.call(data) crosses the external boundary.",
            "result contains raw return bytes that can later be decoded.",
        ],
        'target.call(abi.encodeWithSelector(bytes4(keccak256("quote(uint256)")), 100));',
    ),
    _scene(
        ["abi.encodeCall", "interface", "function", "call", "calldata"],
        "ABI call path: typed function reference → call-ready bytes",
        "abi.encodeCall keeps the function expression and argument types together, then produces ABI bytes suitable for a low-level call.",
        """
interface IOracle {
    function quote(uint256 amount_) external returns (uint256);
}

function rawQuote(address oracle, uint256 amount_)
    external
    returns (uint256)
{
    bytes memory data =
        abi.encodeCall(IOracle.quote, (amount_));

    (bool ok, bytes memory out) = oracle.call(data);
    require(ok);

    return abi.decode(out, (uint256));
}
""",
        [
            ("parameter", "address", "oracle", "0xOracle", "Target contract address."),
            ("parameter", "uint256", "amount_", "100", "Typed function argument."),
            ("local", "bytes memory", "data", "abi.encodeCall(...)", "ABI call payload."),
            ("local", "bytes memory", "out", "raw return bytes", "Returned data."),
        ],
        [
            "IOracle.quote supplies the expected function type.",
            "abi.encodeCall encodes the selector and argument with type checking.",
            "oracle.call(data) performs the low-level boundary.",
            "abi.decode(out, (uint256)) restores the return value.",
        ],
        "rawQuote(oracle, 100);",
    ),
    _scene(
        ["events", "event-indexed", "keccak256"],
        "State change → indexed event → filterable topic",
        "Events turn state changes into logs. Indexed parameters become topics, and dynamic indexed values are represented by hashes.",
        """
event Deposit(
    address indexed user,
    uint256 amount,
    bytes indexed memo
);

function deposit(bytes calldata memo_) external payable {
    emit Deposit(msg.sender, msg.value, memo_);
}
""",
        [
            ("event field", "address indexed", "user", "msg.sender", "Indexed topic for filtering."),
            ("event field", "uint256", "amount", "msg.value", "Event data payload."),
            ("event field", "bytes indexed", "memo", "memo_", "Dynamic indexed value is hashed in the topic."),
        ],
        [
            "msg.sender becomes the indexed user.",
            "msg.value becomes event data.",
            "memo_ is dynamic and indexed, so the log topic carries its Keccak hash.",
        ],
        'deposit(hex"6869"); // with ETH attached',
    ),
    _scene(
        ["errors", "custom-errors", "revert", "abi.decode"],
        "Failure path → custom error bytes → external decoder",
        "Custom errors are ABI-shaped revert data. A caller can catch the revert and inspect/decode the returned bytes.",
        """
error TooSmall(uint256 actual, uint256 minimum);

function withdraw(uint256 amount_) external {
    if (amount_ < 100) revert TooSmall(amount_, 100);
}
""",
        [
            ("parameter", "uint256", "amount_", "10", "Input that fails the rule."),
            ("error field", "uint256", "actual", "10", "Observed amount."),
            ("error field", "uint256", "minimum", "100", "Required threshold."),
            ("return bytes", "bytes", "revertData", "encoded error", "External caller can inspect this."),
        ],
        [
            "The condition fails.",
            "revert TooSmall(...) creates ABI-encoded error data.",
            "The external caller receives the revert bytes.",
            "A decoder can interpret the selector and error arguments.",
        ],
        "withdraw(10); // reverts",
    ),
    _scene(
        ["require", "revert", "assert", "custom-errors"],
        "Four failure tools, four intentions",
        "require checks expected conditions, revert gives explicit branching control, custom errors structure failures, and assert checks invariants.",
        """
error NotOwner(address caller);

function withdraw(uint256 amount_) external {
    require(amount_ > 0);

    if (msg.sender != owner) {
        revert NotOwner(msg.sender);
    }

    // Internal invariant.
    assert(total >= amount_);

    total -= amount_;
}
""",
        [
            ("parameter", "uint256", "amount_", "1 ether", "External input."),
            ("global", "address", "msg.sender", "0xAlice", "Current caller."),
            ("state", "uint256", "total", "10 ether", "Accounting invariant."),
        ],
        [
            "require checks an ordinary external condition.",
            "revert explicitly chooses the custom error branch.",
            "assert checks a programmer invariant.",
            "Only the final state write occurs if all checks pass.",
        ],
        "withdraw(1 ether);",
    ),
    _scene(
        ["try-catch", "call", "returndata", "abi.decode"],
        "External call → success/revert → return bytes",
        "An external boundary can either return values or fail. Low-level call exposes both outcomes; returned bytes can then be decoded.",
        """
(bool ok, bytes memory data) =
    target.call(abi.encodeCall(ITarget.quote, (100)));

if (!ok) {
    // data contains revert bytes.
    revert();
}

uint256 price = abi.decode(data, (uint256));
""",
        [
            ("local", "bool", "ok", "true / false", "Call success."),
            ("local", "bytes", "data", "raw returndata", "Returned value or revert bytes."),
            ("decoded", "uint256", "price", "abi.decode(data, (uint256))", "Typed result on success."),
        ],
        [
            "Build the ABI call bytes.",
            "Call the target.",
            "Branch on the success flag.",
            "Decode the returned bytes only on the expected success path.",
        ],
        "quoteThroughCall(target, 100);",
    ),
    _scene(
        ["receive", "fallback", "payable", "msg.value", "msg.sender", "call"],
        "ETH enters → accounting → withdrawal",
        "receive routes empty-calldata ETH in. msg.sender identifies the caller, msg.value carries the amount, and call sends ETH back out.",
        """
mapping(address => uint256) public credit;

receive() external payable {
    credit[msg.sender] += msg.value;
}

function withdraw(uint256 amount_) external {
    credit[msg.sender] -= amount_;

    (bool ok, ) =
        payable(msg.sender).call{value: amount_}("");
    require(ok);
}
""",
        [
            ("state", "mapping(address => uint256)", "credit", "credit[msg.sender]", "Per-caller ETH accounting."),
            ("global", "address", "msg.sender", "0xAlice", "Current caller."),
            ("global", "uint256", "msg.value", "1 ether", "ETH attached to the call."),
            ("parameter", "uint256", "amount_", "0.5 ether", "Withdrawal amount."),
        ],
        [
            "Alice sends 1 ETH with empty calldata, so receive() runs.",
            "credit[Alice] increases by msg.value.",
            "Alice calls withdraw(0.5 ether).",
            "The mapping is reduced before call sends ETH back.",
        ],
        "1 ETH in → credit[Alice] = 1 ETH → withdraw(0.5 ETH) → 0.5 ETH out",
    ),
    _scene(
        ["msg.sender", "mapping", "modifier", "access-control", "enum", "events"],
        "Caller → role lookup → modifier gate → state transition",
        "An address from msg.sender selects a role from a mapping. The modifier gates the function and the state transition emits an event.",
        """
enum Role { None, Admin, Operator }

mapping(address => Role) public roles;
event RoleChanged(address indexed account, Role oldRole, Role newRole);

modifier onlyAdmin() {
    require(roles[msg.sender] == Role.Admin);
    _;
}

function setRole(address account_, Role newRole_)
    external
    onlyAdmin
{
    Role oldRole = roles[account_];
    roles[account_] = newRole_;
    emit RoleChanged(account_, oldRole, newRole_);
}
""",
        [
            ("global", "address", "msg.sender", "0xAdmin", "Immediate caller."),
            ("state", "mapping(address => Role)", "roles", "roles[msg.sender]", "Role lookup."),
            ("parameter", "address", "account_", "0xAlice", "Account being changed."),
            ("parameter", "Role", "newRole_", "Role.Operator", "New role."),
        ],
        [
            "msg.sender selects the current role.",
            "onlyAdmin checks that enum value before _.",
            "The function changes a mapped role.",
            "The event records the old and new state.",
        ],
        "setRole(alice, Role.Operator);",
    ),
    _scene(
        ["storage-memory-calldata", "structs", "arrays", "bytes"],
        "Same reference type, three data locations",
        "Storage persists, calldata is read-only input, and memory is temporary. Structs, arrays, and bytes reveal the difference clearly.",
        """
struct User {
    string name;
    uint256[] scores;
    bytes note;
}

mapping(address => User) users;

function update(User calldata input) external {
    User storage stored = users[msg.sender];
    User memory copy = input;

    stored.name = copy.name;
    stored.scores = copy.scores;
    stored.note = copy.note;
}
""",
        [
            ("parameter", "User calldata", "input", "external payload", "Read-only external input."),
            ("local", "User storage", "stored", "users[msg.sender]", "Persistent state reference."),
            ("local", "User memory", "copy", "input", "Temporary mutable copy."),
        ],
        [
            "input is read directly from calldata.",
            "stored points at persistent state.",
            "copy is a temporary memory representation.",
            "Assigning copy fields into stored fields persists the changes.",
        ],
        "update(User({name: \"Alice\", scores: [10, 20], note: hex\"6869\"}));",
    ),
    _scene(
        ["calldata", "msg.data", "msg.sig", "calldata-slices", "fallback"],
        "Raw calldata → selector + payload → slice",
        "Fallback can see the complete calldata. The first four bytes are normally the selector; slices isolate portions without first copying the whole payload.",
        """
fallback(bytes calldata input) external returns (bytes memory output) {
    bytes4 selector = bytes4(input[:4]);
    bytes calldata args = input[4:];

    if (selector == msg.sig) {
        return args;
    }
}
""",
        [
            ("calldata", "bytes calldata", "input", "msg.data", "Complete call payload."),
            ("local", "bytes4", "selector", "input[:4]", "First four bytes."),
            ("slice", "bytes calldata", "args", "input[4:]", "Payload after the selector."),
        ],
        [
            "fallback receives raw calldata.",
            "input[:4] isolates the selector bytes.",
            "input[4:] isolates the ABI argument area.",
            "msg.sig exposes the selector for the current call.",
        ],
        "send raw calldata; fallback receives it",
    ),
    _scene(
        ["mapping", "nested-mapping", "keccak256", "mapping-slots", "nested-mapping-slots", "storage"],
        "Logical lookup → physical storage slot",
        "Solidity hides mapping slot arithmetic. Each mapping key causes another Keccak-derived location.",
        """
mapping(address => mapping(bytes32 => uint256)) public balances;

function set(address user_, bytes32 id_, uint256 amount_) external {
    balances[user_][id_] = amount_;
}

// outer = keccak256(abi.encode(user_, balances.slot))
// inner = keccak256(abi.encode(id_, outer))
""",
        [
            ("state", "nested mapping", "balances", "balances[user_][id_]", "Two logical keys."),
            ("parameter", "address", "user_", "0xAlice", "Outer key."),
            ("parameter", "bytes32", "id_", 'bytes32("A")', "Inner key."),
            ("parameter", "uint256", "amount_", "100", "Stored value."),
            ("slot", "bytes32", "outer", "keccak256(...)", "Outer derived slot."),
            ("slot", "bytes32", "inner", "keccak256(...)", "Final derived slot."),
        ],
        [
            "The source expression looks like two bracket operations.",
            "The first key is combined with the mapping's anchor slot.",
            "The second key is combined with the derived outer slot.",
            "The final slot is where the uint256 value is stored.",
        ],
        "set(alice, bytes32(\"A\"), 100);",
    ),
    _scene(
        ["mapping", "structs", "storage-layout", "storage-packing"],
        "Mapping key → struct root → packed fields",
        "A mapping can select a struct whose small value-type fields pack into storage slots according to layout rules.",
        """
struct Account {
    uint128 score;
    uint128 debt;
    uint256 nonce;
}

mapping(address => Account) public accounts;

function bump(address user_) external {
    Account storage a = accounts[user_];
    a.score += 1;
}
""",
        [
            ("state", "mapping(address => Account)", "accounts", "accounts[user_]", "Mapping selects struct root."),
            ("field", "uint128", "score", "10", "Can share a slot with debt."),
            ("field", "uint128", "debt", "2", "Can share the first slot with score."),
            ("field", "uint256", "nonce", "1", "Starts in another slot."),
        ],
        [
            "The address picks one Account.",
            "The struct root determines where its fields begin.",
            "score and debt can pack into one 32-byte slot.",
            "nonce follows according to the layout rules.",
        ],
        "bump(alice);",
    ),
    _scene(
        ["arrays", "mapping", "loops", "array-storage"],
        "Mapping lookup + dynamic array + loop",
        "A mapping can select an array, then a loop can walk the selected values. This is useful but can become gas-sensitive as arrays grow.",
        """
mapping(address => uint256[]) public scores;

function total(address user_)
    external
    view
    returns (uint256 total)
{
    for (uint256 i = 0; i < scores[user_].length; i++) {
        total += scores[user_][i];
    }
}
""",
        [
            ("state", "mapping(address => uint256[])", "scores", "scores[user_]", "Address selects an array."),
            ("parameter", "address", "user_", "0xAlice", "Mapping key."),
            ("local", "uint256", "i", "0 → length - 1", "Loop index."),
            ("return", "uint256", "total", "sum", "Accumulator."),
        ],
        [
            "scores[user_] chooses Alice's dynamic array.",
            "The loop reads one index per iteration.",
            "total accumulates each value.",
            "Gas grows with the number of elements processed.",
        ],
        "total(alice);",
    ),
    _scene(
        ["bytes", "string", "storage", "keccak256"],
        "Dynamic bytes/string storage meets hashing",
        "bytes and string are dynamic byte-oriented data. Hashing their contents is common, while storage encoding depends on length.",
        """
string public name;
bytes public memo;

function set(string calldata name_, bytes calldata memo_) external {
    name = name_;
    memo = memo_;
}

function id() external view returns (bytes32) {
    return keccak256(bytes(name));
}
""",
        [
            ("state", "string", "name", '"Toji"', "Dynamic text."),
            ("state", "bytes", "memo", "hex\"6869\"", "Dynamic bytes."),
            ("parameter", "string calldata", "name_", '"Toji"', "External text."),
            ("parameter", "bytes calldata", "memo_", "raw bytes", "External bytes."),
        ],
        [
            "name_ and memo_ arrive in calldata.",
            "Assignments persist them in storage.",
            "bytes(name) exposes the text bytes.",
            "keccak256 hashes those bytes into bytes32.",
        ],
        "id();",
    ),
    _scene(
        ["transient-storage", "reentrancy", "storage", "yul"],
        "Transaction-scoped guard around an external call",
        "Transient storage can hold a guard only for the current transaction. This can pair with an external call where reentrancy is the concern.",
        """
uint256 transient entered;

modifier nonReentrant() {
    require(entered == 0);
    entered = 1;
    _;
    entered = 0;
}

function withdraw(address payable to, uint256 amount_)
    external
    nonReentrant
{
    (bool ok, ) = to.call{value: amount_}("");
    require(ok);
}

// In Yul the same storage class is exposed through tload/tstore.
""",
        [
            ("transient state", "uint256 transient", "entered", "0 → 1 → 0", "Cleared at transaction end."),
            ("parameter", "address payable", "to", "0xAlice", "ETH recipient."),
            ("parameter", "uint256", "amount_", "1 ether", "Withdrawal amount."),
        ],
        [
            "The guard starts at zero.",
            "The modifier marks the current transaction as entered.",
            "An external call crosses the reentrancy boundary.",
            "The guard resets after the body completes.",
        ],
        "withdraw(alice, 1 ether);",
    ),
    _scene(
        ["proxy-fallback", "fallback", "delegatecall", "storage-layout"],
        "Proxy flow: fallback → delegatecall → shared storage",
        "A proxy receives the call in fallback, forwards the calldata with delegatecall, and uses the proxy's storage while running implementation code.",
        """
address public implementation;

fallback() external payable {
    address impl = implementation;

    assembly {
        calldatacopy(0, 0, calldatasize())

        let ok := delegatecall(
            gas(),
            impl,
            0,
            calldatasize(),
            0,
            0
        )

        returndatacopy(0, 0, returndatasize())

        switch ok
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
""",
        [
            ("state", "address", "implementation", "0xImpl", "Target implementation."),
            ("global", "calldata", "msg.data", "function selector + args", "Forwarded bytes."),
            ("Yul", "word", "ok", "0/1", "delegatecall success flag."),
        ],
        [
            "The unknown function enters fallback.",
            "Fallback copies calldata into memory.",
            "delegatecall executes implementation code against proxy storage.",
            "returndata is copied back to the original caller.",
        ],
        "proxy.setValue(100);",
    ),
    _scene(
        ["abstract", "interface", "inheritance", "override", "virtual", "constructor"],
        "Abstract base + interface + override",
        "An abstract base can own reusable state while an interface defines a callable shape. The child wires both together through inheritance and overrides.",
        """
abstract contract Named {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function who() public view virtual returns (address) {
        return owner;
    }
}

interface ILabel {
    function label() external view returns (string memory);
}

contract Child is Named, ILabel {
    string public name;

    constructor(string memory name_) Named(msg.sender) {
        name = name_;
    }

    function who() public view override returns (address) {
        return owner;
    }

    function label() external view override returns (string memory) {
        return name;
    }
}
""",
        [
            ("base state", "address", "owner", "msg.sender", "Reusable parent state."),
            ("child state", "string", "name", '"Savings"', "Concrete child state."),
            ("child constructor", "string", "name_", '"Savings"', "Deployment input."),
        ],
        [
            "Named defines reusable behavior and state.",
            "ILabel defines the required external function shape.",
            "Child inherits both.",
            "Child overrides who() and implements label().",
        ],
        'new Child("Savings");',
    ),
    _scene(
        ["library", "using-for", "user-defined-value-types", "function"],
        "UDVT + library + using-for",
        "A user-defined value type can get domain-specific operations through a library attached with using-for.",
        """
type UserId is uint256;

library UserIdLib {
    function isZero(UserId id) internal pure returns (bool) {
        return UserId.unwrap(id) == 0;
    }
}

contract Registry {
    using UserIdLib for UserId;

    function empty(UserId id) external pure returns (bool) {
        return id.isZero();
    }
}
""",
        [
            ("type", "UserId", "id", "UserId.wrap(7)", "Distinct value type."),
            ("library", "UserIdLib", "isZero", "UserId → bool", "Domain operation."),
            ("return", "bool", "result", "false", "Operation result."),
        ],
        [
            "UserId is distinct from raw uint256 at the type level.",
            "UserIdLib defines an operation taking UserId.",
            "using-for attaches the operation to UserId values.",
            "id.isZero() becomes readable member-style syntax.",
        ],
        "registry.empty(UserId.wrap(7));",
    ),
    _scene(
        ["new", "constructor", "address", "try-catch"],
        "new → constructor → address → creation failure",
        "new creates a contract, feeds constructor arguments into it, and yields a fresh address. Creation can be wrapped in try/catch.",
        """
contract Child {
    uint256 public number;

    constructor(uint256 number_) {
        require(number_ > 0);
        number = number_;
    }
}

function deploy(uint256 number_)
    external
    returns (address child)
{
    try new Child(number_) returns (Child created) {
        child = address(created);
    } catch {
        revert();
    }
}
""",
        [
            ("parameter", "uint256", "number_", "100", "Constructor input."),
            ("local", "Child", "created", "new Child(number_)", "Fresh contract instance."),
            ("return", "address", "child", "address(created)", "Deployment result address."),
        ],
        [
            "new starts contract creation.",
            "Child's constructor receives number_.",
            "Successful creation returns a Child value.",
            "address(created) exposes the deployed contract address.",
        ],
        "deploy(100);",
    ),
    _scene(
        ["unchecked", "uint256", "assert"],
        "Proved bounds → unchecked arithmetic → invariant",
        "Unchecked arithmetic removes the runtime overflow check, so the surrounding condition or invariant must establish the bound.",
        """
function decrement(uint256 x) external pure returns (uint256) {
    assert(x > 0);

    unchecked {
        return x - 1;
    }
}
""",
        [
            ("parameter", "uint256", "x", "10", "Input."),
            ("return", "uint256", "result", "9", "Value after decrement."),
        ],
        [
            "assert proves the internal precondition.",
            "unchecked suppresses the arithmetic check.",
            "Because x > 0, x - 1 cannot underflow.",
        ],
        "decrement(10);",
    ),
    _scene(
        ["signature-verification", "keccak256", "ecrecover", "nonce"],
        "Signed message → digest → recovered signer + nonce",
        "A signature flow hashes an authorization payload, recovers the signer, and binds the action to a nonce to prevent replay.",
        """
mapping(address => uint256) public nonces;

function digest(address user_, uint256 amount_)
    public
    view
    returns (bytes32)
{
    return keccak256(
        abi.encode(user_, amount_, nonces[user_])
    );
}

// Later:
// address signer = ecrecover(digest, v, r, s);
// nonces[signer]++;
""",
        [
            ("state", "mapping(address => uint256)", "nonces", "nonces[user_]", "Replay-protection counter."),
            ("parameter", "address", "user_", "0xAlice", "Expected signer/user."),
            ("parameter", "uint256", "amount_", "100", "Authorized amount."),
            ("derived", "bytes32", "digest", "keccak256(...)", "Signed message digest."),
        ],
        [
            "The payload includes the current nonce.",
            "abi.encode creates deterministic bytes.",
            "keccak256 creates the digest.",
            "ecrecover can recover a signer address.",
            "Incrementing the nonce prevents reuse of the same authorization.",
        ],
        "digest(alice, 100);",
    ),
    _scene(
        ["front-running", "keccak256", "mapping"],
        "Commit hash now, reveal later",
        "A commitment hides the meaningful value until reveal time. The contract stores the hash first, then verifies the revealed value against it.",
        """
mapping(address => bytes32) public commitment;

function commit(bytes32 hash_) external {
    commitment[msg.sender] = hash_;
}

function reveal(string calldata secret_) external {
    require(
        commitment[msg.sender] == keccak256(bytes(secret_))
    );
}
""",
        [
            ("state", "mapping(address => bytes32)", "commitment", "commitment[msg.sender]", "Stored commitment."),
            ("parameter", "bytes32", "hash_", "keccak256(secret)", "Commitment."),
            ("parameter", "string calldata", "secret_", '"heads"', "Revealed value."),
        ],
        [
            "The secret is hashed before it is committed.",
            "Only the hash is stored publicly.",
            "Reveal hashes the later input.",
            "The two hashes must match.",
        ],
        'commit(keccak256(bytes("heads")));',
    ),
    _scene(
        ["oracle", "interface", "call", "try-catch"],
        "Oracle interface → external call → handled failure",
        "A contract can treat an oracle as a typed external dependency while explicitly handling failures from that dependency.",
        """
interface IPriceFeed {
    function latestAnswer() external view returns (int256);
}

function read(IPriceFeed feed)
    external
    view
    returns (int256 price, bool ok)
{
    try feed.latestAnswer() returns (int256 answer) {
        return (answer, true);
    } catch {
        return (0, false);
    }
}
""",
        [
            ("parameter", "IPriceFeed", "feed", "0xOracle", "Typed external dependency."),
            ("return", "int256", "price", "answer / 0", "Price or fallback value."),
            ("return", "bool", "ok", "true / false", "Success flag."),
        ],
        [
            "The interface defines the expected callable shape.",
            "The typed call crosses the external boundary.",
            "Success returns the value.",
            "A revert is caught and represented explicitly.",
        ],
        "read(oracle);",
    ),
    _scene(
        ["block.timestamp", "timestamp", "msg.sender"],
        "Block time → caller → time-sensitive state",
        "Time-sensitive functions combine block context with caller identity, which makes timestamp assumptions an audit surface.",
        """
mapping(address => uint256) public unlockAt;

function lock(uint256 duration_) external {
    unlockAt[msg.sender] = block.timestamp + duration_;
}

function unlocked() external view returns (bool) {
    return block.timestamp >= unlockAt[msg.sender];
}
""",
        [
            ("global", "uint256", "block.timestamp", "now", "Current block timestamp."),
            ("state", "mapping(address => uint256)", "unlockAt", "unlockAt[msg.sender]", "Caller-specific deadline."),
            ("parameter", "uint256", "duration_", "1 days", "Requested delay."),
        ],
        [
            "msg.sender selects whose deadline is written.",
            "block.timestamp provides the time anchor.",
            "unlockAt stores the derived deadline.",
            "A later read compares current block time to the stored value.",
        ],
        "lock(1 days);",
    ),
    _scene(
        ["tx.origin", "msg.sender", "access-control"],
        "Immediate caller vs original transaction sender",
        "msg.sender changes across contract calls; tx.origin stays tied to the transaction's original EOA. Authorization should normally use the immediate caller.",
        """
function onlyCaller(address expected) external view returns (bool) {
    return msg.sender == expected;
}

function riskyOriginCheck(address expected) external view returns (bool) {
    return tx.origin == expected;
}
""",
        [
            ("global", "address", "msg.sender", "0xContract", "Immediate caller."),
            ("global", "address", "tx.origin", "0xAlice", "Original transaction origin."),
            ("parameter", "address", "expected", "0xAlice", "Address being checked."),
        ],
        [
            "Alice calls Contract A.",
            "Contract A calls this contract, so msg.sender becomes Contract A.",
            "tx.origin remains Alice.",
            "Using tx.origin for authorization can therefore authorize a surprising caller chain.",
        ],
        "riskyOriginCheck(alice);",
    ),
    _scene(
        ["erc7201", "custom-storage-layout", "structs", "mapping", "keccak256", "yul-storage"],
        "Namespaced storage root → struct/mapping → raw slot",
        "Advanced storage designs derive a deterministic namespace root so unrelated modules can avoid colliding with ordinary sequential slots.",
        """
// Teaching sketch, not a complete ERC-7201 implementation:
bytes32 constant ROOT =
    keccak256("lowkey.example.storage");

struct State {
    uint256 total;
    mapping(address => uint256) balances;
}

function rootSlot()
    external
    pure
    returns (bytes32)
{
    return ROOT;
}

// Yul can inspect sload/sstore at a derived slot.
""",
        [
            ("constant", "bytes32", "ROOT", "keccak256(namespace)", "Namespaced storage root."),
            ("struct", "State", "state", "State(total, balances)", "Module state container."),
            ("mapping", "mapping(address => uint256)", "balances", "state.balances[user]", "Nested module accounting."),
        ],
        [
            "The namespace string is hashed into a root value.",
            "The root acts as the module's storage anchor.",
            "The struct contains ordinary state including a mapping.",
            "Yul can inspect the resulting storage coordinates directly.",
        ],
        "rootSlot();",
    ),
    _scene(
        ["bytes.concat", "string.concat", "bytes", "string"],
        "Concatenate text/bytes, then choose how to encode or hash it",
        "bytes.concat works on bytes-like values while string.concat works on text. Both produce dynamically sized values that can later be encoded or hashed.",
        """
function join(
    string memory a,
    string memory b,
    bytes memory x,
    bytes memory y
) external pure returns (string memory text, bytes memory raw) {
    text = string.concat(a, b);
    raw = bytes.concat(x, y);
}
""",
        [
            ("parameter", "string memory", "a", '"hello "', "Text prefix."),
            ("parameter", "string memory", "b", '"world"', "Text suffix."),
            ("parameter", "bytes memory", "x", "hex\"01\"", "Byte prefix."),
            ("parameter", "bytes memory", "y", "hex\"02\"", "Byte suffix."),
        ],
        [
            "string.concat joins text.",
            "bytes.concat joins raw bytes.",
            "Both results are dynamic values.",
        ],
        'join("hello ", "world", hex"01", hex"02");',
    ),
    _scene(
        ["addmod", "mulmod", "uint256"],
        "Arithmetic → modulus without intermediate overflow",
        "addmod and mulmod compute modular arithmetic directly instead of relying on unchecked wraparound.",
        """
function fee(uint256 a, uint256 b, uint256 modulus)
    external
    pure
    returns (uint256)
{
    uint256 sum = addmod(a, b, modulus);
    return mulmod(sum, 3, modulus);
}
""",
        [
            ("parameter", "uint256", "a", "10", "First operand."),
            ("parameter", "uint256", "b", "7", "Second operand."),
            ("parameter", "uint256", "modulus", "13", "Modulus."),
            ("local", "uint256", "sum", "addmod(a, b, modulus)", "Modular sum."),
        ],
        [
            "addmod computes (a + b) % modulus with modular semantics.",
            "The result feeds mulmod.",
            "mulmod computes the modular product.",
        ],
        "fee(10, 7, 13);",
    ),
    _scene(
        ["type-metadata", "contract-types", "interface"],
        "Type metadata → contract/interface identity",
        "Solidity exposes metadata about types and contract interfaces, useful for compile-time introspection and interface checks.",
        """
interface IERC165 {
    function supportsInterface(bytes4 id) external view returns (bool);
}

function metadata()
    external
    pure
    returns (string memory, bytes4)
{
    return (
        type(IERC165).name,
        type(IERC165).interfaceId
    );
}
""",
        [
            ("type", "interface type", "IERC165", "interface declaration", "The contract/interface type."),
            ("metadata", "string", "name", "type(IERC165).name", "Type name."),
            ("metadata", "bytes4", "interfaceId", "type(IERC165).interfaceId", "EIP-165 identifier."),
        ],
        [
            "IERC165 is a typed interface.",
            "type(IERC165) exposes metadata.",
            "interfaceId is derived from its function selectors.",
        ],
        "metadata();",
    ),
    _scene(
        ["selfdestruct", "contract-balance", "address", "ether-flow"],
        "Contract address + balance → special destruction semantics",
        "selfdestruct is a special EVM behavior tied to the current contract address and balance; modern EVM semantics make its effects more constrained than older tutorials suggest.",
        """
function currentBalance()
    external
    view
    returns (uint256)
{
    return address(this).balance;
}

// Historical teaching form:
// selfdestruct(payable(recipient));
""",
        [
            ("global", "address", "address(this)", "0xContract", "Current contract address."),
            ("global", "uint256", "address(this).balance", "10 ether", "Current contract balance."),
            ("parameter", "address payable", "recipient", "0xAlice", "Historical destination argument."),
        ],
        [
            "The contract address owns the current balance.",
            "selfdestruct is a special EVM operation rather than an ordinary transfer.",
            "Audit modern compiler/EVM semantics before relying on old destruction assumptions.",
        ],
        "currentBalance();",
    ),
    _scene(
        ["function-types", "external-function-types", "function", "address"],
        "Function value → stored target + callable function",
        "Function types can be stored as values. External function pointers carry enough target information to make a later call.",
        """
function add(uint256 a, uint256 b)
    external
    pure
    returns (uint256)
{
    return a + b;
}

function callLater(
    function(uint256, uint256) external pure returns (uint256) f
) external pure returns (uint256) {
    return f(2, 3);
}
""",
        [
            ("function type", "function(...)", "f", "add", "Callable function value."),
            ("parameter", "uint256", "a", "2", "First argument."),
            ("parameter", "uint256", "b", "3", "Second argument."),
            ("return", "uint256", "result", "5", "Function result."),
        ],
        [
            "A function identifier can become a function value.",
            "The function value can be stored/passed as a typed value.",
            "Invoking f(...) executes the referenced callable operation.",
        ],
        "callLater(contract.add);",
    ),
    _scene(
        ["vm-prank", "msg.sender", "test"],
        "Foundry caller manipulation → msg.sender",
        "A test can deliberately choose the caller so the contract sees a controlled msg.sender.",
        """
function testWithdrawAsAlice() public {
    vm.prank(alice);

    vault.withdraw(1 ether);
}
""",
        [
            ("test actor", "address", "alice", "0xAlice", "Caller selected by the test."),
            ("contract global", "address", "msg.sender", "alice", "What the contract sees."),
        ],
        [
            "The test selects Alice.",
            "vm.prank changes the next call's caller.",
            "The vault executes with msg.sender == Alice.",
        ],
        "vm.prank(alice); vault.withdraw(1 ether);",
    ),
    _scene(
        ["vm-deal", "contract-balance", "test"],
        "Foundry balance setup → contract ETH balance",
        "Tests can provision ETH before exercising payable code, making balance-dependent behavior deterministic.",
        """
function testFunding() public {
    vm.deal(address(vault), 10 ether);

    assertEq(address(vault).balance, 10 ether);
}
""",
        [
            ("target", "address", "address(vault)", "0xVault", "Account whose balance changes."),
            ("balance", "uint256", "address(vault).balance", "10 ether", "Observed contract balance."),
        ],
        [
            "vm.deal changes the test-state balance.",
            "address(vault).balance reads the resulting ETH held by the vault.",
        ],
        "vm.deal(address(vault), 10 ether);",
    ),
    _scene(
        ["vm-expect-call", "call", "abi.encode", "test"],
        "Expected external call → encoded arguments",
        "Foundry can assert that a dependency is called with the expected ABI-encoded payload.",
        """
vm.expectCall(
    address(token),
    abi.encodeCall(IERC20.transfer, (alice, 100))
);

vault.pay(alice, 100);
""",
        [
            ("target", "address", "token", "0xToken", "Expected call destination."),
            ("payload", "bytes", "data", "abi.encodeCall(...)", "Expected calldata."),
            ("parameter", "uint256", "100", "100", "Expected transfer amount."),
        ],
        [
            "The test defines the expected target.",
            "The expected calldata is ABI-encoded.",
            "The system call must match the expectation.",
        ],
        "vm.expectCall(address(token), data);",
    ),
    _scene(
        ["fuzz-tests", "bounded-fuzz", "vm-assume", "vm-bound"],
        "Fuzz input → constraints → bounded value",
        "Foundry fuzz tests intentionally vary inputs. Assumptions and bounds keep the generated cases inside meaningful domains.",
        """
function testFuzz(uint256 raw) public {
    vm.assume(raw != 0);
    uint256 amount = bound(raw, 1, 1000);

    vault.deposit(amount);

    assertGt(amount, 0);
    assertLe(amount, 1000);
}
""",
        [
            ("fuzz input", "uint256", "raw", "many values", "Generated candidate input."),
            ("bounded value", "uint256", "amount", "1 → 1000", "Normalized test input."),
        ],
        [
            "The fuzzer supplies raw.",
            "vm.assume rejects unwanted cases.",
            "bound maps the input into a controlled interval.",
            "The contract is exercised across many valid values.",
        ],
        "testFuzz(raw);",
    ),
    _scene(
        ["poc-reentrancy", "reentrancy", "call", "receive", "mapping"],
        "PoC: attacker callback → repeated withdrawal",
        "A reentrancy PoC combines an external call with a callback entry point and accounting stored in a mapping.",
        """
mapping(address => uint256) public credit;

function withdraw() external {
    uint256 amount = credit[msg.sender];

    (bool ok, ) = payable(msg.sender).call{value: amount}("");
    require(ok);

    credit[msg.sender] = 0;
}
""",
        [
            ("state", "mapping(address => uint256)", "credit", "credit[attacker]", "Victim accounting."),
            ("local", "uint256", "amount", "credit[msg.sender]", "Amount copied before the call."),
            ("attack surface", "call", "external send", "msg.sender.call", "Callback boundary."),
        ],
        [
            "Victim reads the balance.",
            "Victim performs the external call before zeroing storage.",
            "Attacker receive/fallback can run during that call.",
            "The callback can re-enter withdraw while credit is still nonzero.",
        ],
        "attacker.attack();",
    ),
    _scene(
        ["contract-anatomy", "constructor", "modifier", "receive", "fallback"],
        "A contract as a set of entry points",
        "State variables hold data, the constructor initializes it, modifiers wrap functions, and receive/fallback cover special call routes.",
        """
contract Wallet {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    receive() external payable {}

    fallback() external payable {}

    function sweep(address payable to) external onlyOwner {
        to.call{value: address(this).balance}("");
    }
}
""",
        [
            ("state", "address", "owner", "0xAlice", "Authorization state."),
            ("parameter", "address", "owner_", "0xAlice", "Deployment input."),
            ("parameter", "address payable", "to", "0xTreasury", "Sweep destination."),
        ],
        [
            "constructor establishes owner.",
            "modifier protects sweep.",
            "receive accepts empty-calldata ETH.",
            "fallback handles unmatched calls.",
        ],
        "sweep(treasury);",
    ),
    _scene(
        ["mapping-defaults", "mapping", "types-defaults", "delete"],
        "Missing mapping key → default value → explicit delete",
        "Mappings do not expose existence directly. A missing key reads the value type's default, and delete writes that default explicitly.",
        """
mapping(address => uint256) public balances;

function clear(address user_) external {
    delete balances[user_];
}
""",
        [
            ("state", "mapping(address => uint256)", "balances", "balances[user_]", "Stored balance."),
            ("parameter", "address", "user_", "0xAlice", "Mapping key."),
            ("default", "uint256", "balances[missing]", "0", "Read when never written."),
        ],
        [
            "A missing key returns zero.",
            "That does not prove the key was never written.",
            "delete also resets the mapped value to zero.",
        ],
        "clear(alice);",
    ),
    _scene(
        ["constant-immutable", "constructor", "storage"],
        "Constant vs immutable vs ordinary storage",
        "Constants are fixed by compilation, immutables are assigned during construction, and ordinary state can change after deployment.",
        """
uint256 public constant FEE = 1;

uint256 public immutable deployedAt;

uint256 public mutableFee;

constructor() {
    deployedAt = block.timestamp;
}
""",
        [
            ("constant", "uint256", "FEE", "1", "Compile-time fixed value."),
            ("immutable", "uint256", "deployedAt", "block.timestamp", "Construction-time fixed value."),
            ("storage", "uint256", "mutableFee", "0", "Ordinary persistent state."),
        ],
        [
            "FEE is fixed at compile time.",
            "deployedAt is assigned once in the constructor.",
            "mutableFee can change later.",
        ],
        "new Contract();",
    ),
    _scene(
        ["global-functions", "keccak256", "abi.encode", "abi.decode", "type-metadata"],
        "Solidity global helpers → bytes, hashes, and type metadata",
        "Several Solidity globals are value transformers or type introspection tools rather than contract state.",
        """
bytes32 hash = keccak256(abi.encode(user, amount));

(address decoded, uint256 value) =
    abi.decode(raw, (address, uint256));

uint256 maximum = type(uint256).max;
""",
        [
            ("value", "address", "user", "0xAlice", "Encoded input."),
            ("value", "uint256", "amount", "100", "Encoded input."),
            ("derived", "bytes32", "hash", "keccak256(...)", "Digest."),
            ("decoded", "address", "decoded", "abi.decode(...)", "Recovered typed value."),
            ("metadata", "uint256", "maximum", "type(uint256).max", "Type bound."),
        ],
        [
            "abi.encode creates bytes.",
            "keccak256 turns bytes into bytes32.",
            "abi.decode turns compatible bytes back into typed values.",
            "type(uint256).max asks the compiler for type metadata.",
        ],
        "read the three expressions left-to-right",
    ),
    _scene(
        ["call-anatomy", "call", "staticcall", "delegatecall"],
        "Three low-level call modes",
        "call changes external state normally, staticcall is read-only, and delegatecall runs target code in the caller's storage/context.",
        """
target.call(data);
target.staticcall(data);
target.delegatecall(data);
""",
        [
            ("target", "address", "target", "0xTarget", "External code address."),
            ("data", "bytes", "data", "selector + args", "Calldata passed to target."),
        ],
        [
            "call executes target code normally.",
            "staticcall forbids state changes.",
            "delegatecall keeps caller storage/context while using target code.",
        ],
        "compare the same target/data under all three call modes",
    ),
]


def _generic_bridge_scene(nodes):
    ordered = list(dict.fromkeys(nodes))
    meanings = [f"{node}: {connection_meaning(node)}" for node in ordered]
    root = ordered[0]
    goal = ordered[-1]

    # Pick a compact executable-ish sketch around the first useful bridge.
    if "mapping" in ordered and "abi.decode" in ordered:
        code = """
mapping(address => uint256) public state;

function bridge(bytes calldata raw, uint256 value_) external {
    address key = abi.decode(raw, (address));
    state[key] = value_;
}
"""
        flow = [
            "raw arrives as bytes.",
            "abi.decode turns raw into a typed key.",
            "The decoded key selects the mapping entry.",
            "value_ updates the selected state.",
        ]
        variables = [
            ("input", "bytes calldata", "raw", "ABI bytes", "Raw boundary data."),
            ("decoded", "address", "key", "abi.decode(raw, (address))", "Typed storage key."),
            ("state", "mapping(address => uint256)", "state", "state[key]", "Selected storage entry."),
            ("parameter", "uint256", "value_", "100", "Stored value."),
        ]
        call = "bridge(abi.encode(alice), 100);"
    elif "mapping" in ordered and "keccak256" in ordered:
        code = """
mapping(bytes32 => address) public state;

function bridge(bytes calldata raw) external {
    bytes32 key = keccak256(raw);
    state[key] = msg.sender;
}
"""
        flow = [
            "raw arrives as bytes.",
            "keccak256 turns those bytes into bytes32.",
            "The digest becomes the mapping key.",
            "msg.sender becomes the stored value.",
        ]
        variables = [
            ("input", "bytes calldata", "raw", "raw bytes", "Hash input."),
            ("derived", "bytes32", "key", "keccak256(raw)", "Mapping key."),
            ("state", "mapping(bytes32 => address)", "state", "state[key]", "Storage lookup."),
            ("global", "address", "msg.sender", "0xAlice", "Stored value."),
        ]
        call = 'bridge(hex"416c696365");'
    elif "interface" in ordered and "call" in ordered:
        code = """
interface ITarget {
    function value() external view returns (uint256);
}

function bridge(ITarget target) external view returns (uint256) {
    return target.value();
}
"""
        flow = [
            "An interface value points at a target address.",
            "The interface declares the external function shape.",
            "The typed call crosses the contract boundary.",
            "The returned value flows back to the caller.",
        ]
        variables = [
            ("parameter", "ITarget", "target", "0xTarget", "Typed target."),
            ("interface function", "uint256", "value()", "42", "Declared return value."),
        ]
        call = "bridge(target);"
    elif "yul" in ordered:
        code = """
function bridge(uint256 value_) external returns (uint256 result) {
    assembly {
        let x := value_
        result := add(x, 1)
    }
}
"""
        flow = [
            "A Solidity value enters the function.",
            "The assembly block exposes it to Yul.",
            "A Yul operation transforms the value.",
            "The Solidity return variable receives the result.",
        ]
        variables = [
            ("parameter", "uint256", "value_", "41", "Solidity input."),
            ("Yul local", "word", "x", "value_", "Assembly-local value."),
            ("return", "uint256", "result", "add(x, 1)", "Value returned to Solidity."),
        ]
        call = "bridge(41);"
    else:
        code = f"""
contract ConnectionBridge {{
    // Primary path:
    // {' → '.join(ordered[:5])}

    function read() external pure returns (string memory) {{
        return "{root} → {goal}";
    }}
}}
"""
        flow = [
            f"Start from {root}.",
            f"Follow the shortest known relationship path toward {goal}.",
            "Use the intermediate concepts as the bridge rather than treating the concepts as isolated vocabulary.",
        ]
        variables = [
            ("requested", "concept", root, "selected", connection_meaning(root)),
            ("requested", "concept", goal, "selected", connection_meaning(goal)),
        ]
        call = "read();"

    return {
        "keys": frozenset(ordered),
        "title": f"Guided bridge: {' → '.join(ordered[:4])}",
        "story": (
            f"No single curated pattern was required for this exact combination. "
            f"Lowkey keeps it human-sized by showing the shortest conceptual bridge "
            f"from {root} to {goal}, rather than switching to the universal contract."
        ),
        "code": code.strip("\n"),
        "variables": variables,
        "flow": flow,
        "call": call,
        "generic": True,
        "meanings": meanings,
    }


def find_micro_scene(names):
    requested = frozenset(canonicalize(name) for name in names)

    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if scene["keys"] == requested
    ]
    if exact:
        return exact[0]

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= scene["keys"]
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(scene["keys"] - requested),
                len(scene["keys"]),
            )
        )
        return candidates[0]

    return _generic_bridge_scene(list(requested))


def _shortest_path(start, goal):
    if start == goal:
        return [start]

    adjacency = defaultdict(list)
    for left, right, label in _COMPREHENSIVE_CONNECTION_EDGES:
        # Explicit semantic edges are preferred over category/group edges.
        weight = 1 if not label.startswith("same ") else 5
        adjacency[left].append((right, label, weight))
        adjacency[right].append((left, label, weight))

    heap = [(0, start, (start,), ())]
    best = {start: 0}

    while heap:
        cost, node, path, labels = heapq.heappop(heap)
        if node == goal:
            return list(path), list(labels)
        if cost != best.get(node):
            continue

        for nxt, label, weight in adjacency.get(node, ()):
            new_cost = cost + weight
            if new_cost >= best.get(nxt, 10**9):
                continue
            best[nxt] = new_cost
            heapq.heappush(
                heap,
                (new_cost, nxt, path + (nxt,), labels + (label,)),
            )

    return None, None


def connection_paths(names):
    nodes = list(dict.fromkeys(canonicalize(name) for name in names))
    if len(nodes) < 2:
        return []

    root = nodes[0]
    rows = []

    for goal in nodes[1:]:
        path, labels = _shortest_path(root, goal)
        if path:
            rows.append((root, goal, path, labels))
        else:
            rows.append(
                (
                    root,
                    goal,
                    [root, "contract-context", goal],
                    ["shared contract context; inspect each side's syntax/example"],
                )
            )

    return rows


# Compatibility names consumed by the existing cheatsheet renderer/tests.
CONNECTION_GRAPH = _COMPREHENSIVE_CONNECTION_EDGES


def list_connections():
    return [
        {
            "name": "solidity-yul-comprehensive-graph",
            "aliases": ["graph", "comprehensive", "universal"],
            "concepts": ["all recognized Solidity/Yul/Foundry concepts"],
            "summary": (
                f"{len(_COMPREHENSIVE_CONNECTION_EDGES)}+ weighted edges, "
                f"{len(COMPREHENSIVE_MICRO_SCENES)} curated teaching scenes, "
                "plus a generic bridge. Featured paths: decode/hash/mapping, "
                "ABI call path, proxy flow, storage/Yul, and security/testing flows."
            ),
        },
        {
            "name": "decode/hash/mapping",
            "aliases": [],
            "concepts": ["mapping", "keccak256", "abi.decode"],
            "summary": "Decode the same raw bytes into a typed value while hashing the original wire bytes into a mapping key.",
        },
        {
            "name": "ABI call path",
            "aliases": [],
            "concepts": ["function-selector", "abi.encodeCall", "call", "returndata"],
            "summary": "Typed function → ABI bytes → external call → raw return data → abi.decode.",
        },
        {
            "name": "proxy flow",
            "aliases": [],
            "concepts": ["proxy-fallback", "fallback", "delegatecall", "storage-layout"],
            "summary": "Fallback forwarding → delegatecall → proxy storage/context → returndata.",
        },
    ]


# The tests and renderer use this symbol to avoid importing the legacy edge list.
COMPREHENSIVE_MICRO_SCENES = COMPREHENSIVE_MICRO_SCENES
