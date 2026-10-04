"""Composable Solidity connection labs for the read-only Lowkey cheatsheet.

Each lab shows how several Solidity concepts cooperate in one small contract.
The renderer can choose a lab that contains the requested concepts, so
"lk connect mapping struct" and "lk connect structs mappings arrays enums"
can both land in a useful larger example.
"""

from __future__ import annotations


def _norm(value: str) -> str:
    return "-".join(str(value).strip().lower().replace("_", "-").split())


_CONCEPT_ALIASES = {
    "struct": "structs",
    "structs": "structs",
    "mapping": "mapping",
    "mappings": "mapping",
    "nested-mapping": "nested-mapping",
    "nested-mappings": "nested-mapping",
    "array": "arrays",
    "arrays": "arrays",
    "dynamic-array": "arrays",
    "dynamic-arrays": "arrays",
    "fixed-array": "arrays",
    "fixed-arrays": "arrays",
    "static-array": "arrays",
    "static-arrays": "arrays",
    "enum": "enum",
    "enums": "enum",
    "bytes": "bytes",
    "strings-bytes": "bytes",
    "dynamic-bytes": "bytes",
    "bytes32": "bytes32",
    "bytesn": "bytes32",
    "address": "address",
    "addresses": "address",
    "string": "string",
    "strings": "string",
    "uint": "uint256",
    "uint256": "uint256",
    "uints": "uint256",
    "constructor": "constructor",
    "constructors": "constructor",
    "import": "imports",
    "imports": "imports",
    "inheritance": "inheritance",
    "abstract": "abstract",
    "interface": "interface",
    "interfaces": "interface",
    "override": "override",
    "virtual": "virtual",
    "function": "function",
    "functions": "function",
    "function-syntax": "function",
    "function-signature": "function",
    "function-call": "function",
    "function-calls": "function",
    "cheatcodes": "forge-cheatcodes",
    "expectrevert": "vm-expect-revert",
    "expectemit": "vm-expect-emit",
    "modifier": "modifier",
    "modifiers": "modifier",
    "event": "events",
    "events": "events",
    "error": "errors",
    "errors": "errors",
    "require": "require",
    "receive": "receive",
    "fallback": "fallback",
    "payable": "payable",
    "call": "call",
    "calls": "call",
    "staticcall": "staticcall",
    "delegatecall": "delegatecall",
    "external-call": "external-call",
    "external-calls": "external-call",
    "interface-call": "external-call",
    "abi": "abi.encode",
    "abi-encode": "abi.encode",
    "abi-encodewithsignature": "abi.encode",
    "abi-decode": "abi.decode",
    "keccak": "keccak256",
    "keccak256": "keccak256",
    "hash": "keccak256",
    "loops": "loops",
    "loop": "loops",
    "for": "loops",
    "if": "if-else",
    "if-else": "if-else",
    "storage": "storage",
    "memory": "memory",
    "calldata": "calldata",
    "msg.sender": "msg.sender",
    "msg-sender": "msg.sender",
    "msg.value": "msg.value",
    "msg-value": "msg.value",
    "access-control": "access-control",
    "ownership": "access-control",
    "checks-effects-interactions": "checks-effects-interactions",
}


CONNECTION_LABS = [
    {
        "name": "import-constructor",
        "aliases": ["imports-constructors", "import-inheritance", "constructor-import"],
        "concepts": [
            "imports", "constructor", "inheritance", "address", "string", "uint256",
            "msg.sender", "modifier", "access-control",
        ],
        "summary": (
            "An imported base contract exposes a constructor and modifier; the "
            "derived contract passes arguments to both its own constructor and "
            "the base constructor."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./Owned.sol";

contract Vault is Owned {
    string public name;
    uint256 public limit;
    address public manager;

    // Deployment supplies name_ and limit_.
    // Inheritance supplies owner_ to the imported base constructor.
    constructor(string memory name_, uint256 limit_) Owned(msg.sender) {
        name = name_;
        limit = limit_;
        manager = msg.sender;
    }

    function changeManager(address newManager) external onlyOwner {
        manager = newManager;
    }
}
""",
        "support_files": {
            "Owned.sol": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Owned {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}
""",
        },
        "variables": [
            ("base state", "address", "owner", "0xDeployer", "Stored by the imported base contract."),
            ("state", "string", "name", '"Savings"', "The vault's readable name."),
            ("state", "uint256", "limit", "1_000", "A numeric limit stored by the child."),
            ("state", "address", "manager", "msg.sender", "The caller that deployed the vault."),
            ("constructor parameter", "string memory", "name_", '"Savings"', "Value supplied when deploying Vault."),
            ("constructor parameter", "uint256", "limit_", "1_000", "Value supplied when deploying Vault."),
            ("base-constructor argument", "address", "owner_", "msg.sender", "Value passed from Vault to Owned."),
            ("function parameter", "address", "newManager", "0xBob", "New manager supplied to changeManager()."),
        ],
        "calls": [
            'new Vault("Savings", 1000);',
            'new Vault("Trading", 50_000);',
            'vault.changeManager(0x00000000000000000000000000000000000000B0B);',
        ],
        "steps": [
            "import brings the Owned declaration into the source file; it does not execute a constructor.",
            "is Owned creates an inheritance relationship between Vault and Owned.",
            "new Vault(\"Savings\", 1000) supplies the child constructor's two parameters.",
            "Owned(msg.sender) supplies the imported base constructor's owner_ parameter.",
            "Vault stores name_, limit_, and msg.sender in its own state variables.",
            "Later, changeManager(newManager) supplies another runtime argument and writes manager.",
        ],
        "connections": [
            "import → lets this file use Owned.",
            "inheritance → makes Owned's owner and onlyOwner available to Vault.",
            "constructor → receives deployment-time values.",
            "msg.sender → is the deployment caller used as the base constructor argument.",
            "modifier → reuses the access rule on changeManager().",
        ],
        "audit": (
            "Track every constructor argument separately: deployment arguments are not the "
            "same thing as base-constructor arguments. Check which caller becomes owner and "
            "whether initialization can ever be skipped."
        ),
    },
    {
        "name": "data-structures",
        "aliases": [
            "struct-mapping-arrays",
            "structs-mappings-arrays",
            "mapping-struct-arrays",
            "big-data-bundle",
        ],
        "concepts": [
            "structs", "mapping", "nested-mapping", "arrays", "enum", "bytes", "bytes32",
            "address", "string", "uint256", "function", "constructor", "storage", "memory",
            "calldata", "loops", "events", "msg.sender",
        ],
        "summary": (
            "One small registry shows a struct stored in a mapping, a nested mapping, "
            "dynamic and fixed-size arrays, an enum, bytes/bytes32, addresses, strings, "
            "calldata parameters, storage references, loops, and state updates."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract DataStructuresLab {
    enum Status {
        None,
        Active,
        Done
    }

    struct Profile {
        address owner;
        string name;
        uint256 score;
        bytes32 id;
        Status status;
        uint256[] tags;
    }

    mapping(address => Profile) public profiles;
    mapping(address => mapping(bytes32 => uint256)) public balances;
    mapping(bytes32 => address[]) public members;

    address[] public users;          // dynamic array
    address[3] public fixedUsers;    // fixed/static array
    uint256[] public scores;         // dynamic array
    uint256[3] public fixedScores;   // fixed/static array

    bytes public memo;
    bytes32 public code;

    event ProfileUpdated(
        address indexed user,
        uint256 oldScore,
        uint256 newScore,
        Status oldStatus,
        Status newStatus
    );

    constructor(bytes32 code_) {
        code = code_;
    }

    function createProfile(
        string calldata name_,
        uint256 score_,
        bytes32 id_,
        uint256[] calldata tags_
    ) external {
        Profile storage profile = profiles[msg.sender];

        profile.owner = msg.sender;
        profile.name = name_;
        profile.score = score_;
        profile.id = id_;
        profile.status = Status.Active;
        profile.tags = tags_;

        users.push(msg.sender);
        balances[msg.sender][id_] = score_;
    }

    function updateProfile(
        address user_,
        string calldata name_,
        uint256 score_,
        bytes32 id_,
        Status status_,
        uint256[] calldata tags_
    ) external {
        Profile storage profile = profiles[user_];

        uint256 oldScore = profile.score;
        Status oldStatus = profile.status;

        profile.name = name_;
        profile.score = score_;
        profile.id = id_;
        profile.status = status_;
        profile.tags = tags_;

        balances[user_][id_] = score_;

        emit ProfileUpdated(user_, oldScore, score_, oldStatus, status_);
    }

    function addMember(bytes32 groupId_, address member_) external {
        members[groupId_].push(member_);
    }

    function addScore(uint256 score_) external {
        scores.push(score_);
    }

    function setFixedUsers(address[3] calldata users_) external {
        fixedUsers = users_;
    }

    function setFixedScores(uint256[3] calldata scores_) external {
        fixedScores = scores_;
    }

    function setMemo(bytes calldata memo_, bytes32 code_) external {
        memo = memo_;
        code = code_;
    }

    function appendTag(address user_, uint256 tag_) external {
        Profile storage profile = profiles[user_];
        profile.tags.push(tag_);
    }

    function totalScores() external view returns (uint256 total) {
        for (uint256 i = 0; i < scores.length; i++) {
            total += scores[i];
        }
    }

    function copyTags(address user_) external view returns (uint256[] memory result) {
        result = profiles[user_].tags;
    }
}
""",
        "support_files": {},
        "variables": [
            ("state", "mapping(address => Profile)", "profiles", "profiles[msg.sender]", "Maps an address key to a whole Profile struct value."),
            ("state", "mapping(address => mapping(bytes32 => uint256))", "balances", "balances[user][id]", "Nested lookup: first address, then bytes32 key, then uint256 value."),
            ("state", "mapping(bytes32 => address[])", "members", "members[groupId]", "A bytes32 key points to a dynamic array of addresses."),
            ("state", "address[]", "users", "[]", "Dynamic array that grows with push()."),
            ("state", "address[3]", "fixedUsers", "[alice, bob, carol]", "Fixed/static array with exactly three slots."),
            ("state", "uint256[]", "scores", "[]", "Dynamic numeric array."),
            ("state", "uint256[3]", "fixedScores", "[10, 20, 30]", "Fixed/static numeric array."),
            ("state", "bytes", "memo", 'hex bytes such as 0x6869', "Dynamic byte sequence."),
            ("state", "bytes32", "code", 'bytes32("KE")', "Exactly 32 bytes, useful as a compact key/id."),
            ("struct field", "address", "owner", "msg.sender", "Address stored inside Profile."),
            ("struct field", "string", "name", '"Toji"', "Readable text stored inside Profile."),
            ("struct field", "uint256", "score", "22", "Unsigned integer stored inside Profile."),
            ("struct field", "bytes32", "id", 'bytes32("KE")', "Fixed-size identifier stored inside Profile."),
            ("struct field", "Status", "status", "Status.Active", "Enum value stored inside Profile."),
            ("struct field", "uint256[]", "tags", "[1, 2, 3]", "Dynamic array stored inside Profile."),
            ("function parameter", "string calldata", "name_", '"Toji"', "External input; read-only calldata."),
            ("function parameter", "uint256", "score_", "22", "External numeric input."),
            ("function parameter", "bytes32", "id_", 'bytes32("KE")', "External fixed-size byte input."),
            ("function parameter", "uint256[] calldata", "tags_", "[1, 2, 3]", "External dynamic array input."),
            ("function parameter", "address", "user_", "0xAlice", "Address whose Profile is being updated."),
            ("function parameter", "Status", "status_", "Status.Done", "Enum input."),
            ("local variable", "Profile storage", "profile", "profiles[user_]", "Storage reference; writes persist."),
            ("local variable", "uint256", "oldScore", "profile.score", "Previous score captured before the write."),
            ("local variable", "Status", "oldStatus", "profile.status", "Previous enum value before the write."),
            ("local variable", "uint256", "i", "0 → scores.length - 1", "Loop index for the dynamic array."),
            ("return variable", "uint256", "total", "0 → sum of scores", "Accumulator stored in memory for totalScores()."),
            ("return variable", "uint256[] memory", "result", "profiles[user_].tags", "Dynamic array copied out for the caller."),
        ],
        "calls": [
            'lab.createProfile("Toji", 22, bytes32("KE"), [1, 2, 3]);',
            'lab.updateProfile(0x0000000000000000000000000000000000000A11, "Alice", 100, bytes32("A"), Status.Done, [7, 8]);',
            'lab.addMember(bytes32("DAO"), 0x00000000000000000000000000000000000000B0B);',
            'lab.setFixedUsers([alice, bob, carol]);',
            'lab.setFixedScores([10, 20, 30]);',
            'lab.setMemo(hex"68656c6c6f", bytes32("NOTE"));',
            'lab.appendTag(0x0000000000000000000000000000000000000A11, 99);',
            'lab.totalScores();',
        ],
        "steps": [
            "createProfile() receives normal values plus a dynamic array in calldata.",
            "profiles[msg.sender] chooses one mapping slot using the caller address as the key.",
            "Profile storage profile points at that stored struct, so profile.score = score_ changes contract storage.",
            "profile.tags = tags_ copies the dynamic array input into the struct's stored array.",
            "balances[user_][id_] performs two mapping lookups before updating the uint256 value.",
            "users.push(msg.sender) grows a dynamic array; fixedUsers has exactly three positions and is assigned as a whole.",
            "Status.Active / Status.Done stores a named enum value, while id_ uses bytes32 and memo uses dynamic bytes.",
            "totalScores() shows a dynamic array plus a loop plus a local accumulator.",
            "copyTags() shows a storage dynamic array being copied into a memory return value.",
        ],
        "connections": [
            "mapping(address => Profile) → lets one address select a whole struct.",
            "struct → groups address, string, uint256, bytes32, enum, and array fields.",
            "nested mapping → uses a second key after the first address lookup.",
            "mapping → dynamic array → members[groupId_].push(member_).",
            "dynamic array vs fixed array → push works on dynamic storage arrays; fixed arrays have a fixed length.",
            "enum → stores named states inside the struct.",
            "bytes / bytes32 → dynamic raw bytes vs fixed 32-byte identifiers.",
            "calldata → receives external arrays/strings/bytes without a writable local copy.",
            "storage reference → lets profile writes persist.",
            "memory return → copyTags() returns a temporary copy to the caller.",
            "msg.sender → supplies an address value that can become a mapping key and struct field.",
        ],
        "audit": (
            "Trace every lookup and write: which key selects the state, whether arrays can grow "
            "without bound, whether a caller can overwrite another user's struct, and whether "
            "the invariant between profiles[user].score and balances[user][id] is enforced."
        ),
    },
    {
        "name": "access-control-state",
        "aliases": ["roles-enums", "modifier-mapping", "enum-access-control"],
        "concepts": [
            "constructor", "modifier", "access-control", "mapping", "enum", "address",
            "events", "errors", "msg.sender", "function", "require",
        ],
        "summary": (
            "A role system connects msg.sender, addresses, an enum, mapping state, a "
            "modifier, constructor initialization, custom errors, and events."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract RolesLab {
    enum Role {
        None,
        Admin,
        Operator
    }

    error NotAuthorized(address caller, Role requiredRole, Role actualRole);

    mapping(address => Role) public roles;

    event RoleChanged(address indexed account, Role oldRole, Role newRole);

    constructor(address admin_) {
        roles[admin_] = Role.Admin;
    }

    modifier onlyRole(Role requiredRole) {
        Role actualRole = roles[msg.sender];

        if (actualRole != requiredRole) {
            revert NotAuthorized(msg.sender, requiredRole, actualRole);
        }
        _;
    }

    function setRole(address account_, Role newRole_)
        external
        onlyRole(Role.Admin)
    {
        Role oldRole = roles[account_];
        roles[account_] = newRole_;
        emit RoleChanged(account_, oldRole, newRole_);
    }

    function operatorTask(uint256 amount_) external onlyRole(Role.Operator) {
        require(amount_ > 0, "amount is zero");
    }
}
""",
        "support_files": {},
        "variables": [
            ("state", "mapping(address => Role)", "roles", "roles[account]", "Maps each address to an enum role."),
            ("constructor parameter", "address", "admin_", "0xAdmin", "Initial privileged address."),
            ("modifier parameter", "Role", "requiredRole", "Role.Admin", "Role the caller must have."),
            ("local variable", "Role", "actualRole", "roles[msg.sender]", "Role currently assigned to the caller."),
            ("function parameter", "address", "account_", "0xOperator", "Address whose role will change."),
            ("function parameter", "Role", "newRole_", "Role.Operator", "New enum role."),
            ("local variable", "Role", "oldRole", "roles[account_]", "Old role emitted in the event."),
            ("function parameter", "uint256", "amount_", "100", "Value checked by operatorTask()."),
        ],
        "calls": [
            'new RolesLab(admin);',
            'lab.setRole(operator, Role.Operator);',
            'lab.operatorTask(100);',
        ],
        "steps": [
            "constructor(admin_) writes Role.Admin for the supplied address.",
            "A modifier reads roles[msg.sender] before the protected function body runs.",
            "If the caller has the wrong enum value, the custom error includes the relevant addresses/roles.",
            "setRole() reads the old enum, writes the new one, and emits both values.",
            "operatorTask() uses the same access-control mapping but checks a normal uint256 parameter too.",
        ],
        "connections": [
            "address → mapping key → enum role.",
            "constructor parameter → initial access-control state.",
            "modifier → reads msg.sender → mapping.",
            "custom error → explains a failed authorization decision.",
            "event → records old and new enum values after the state write.",
        ],
        "audit": (
            "Follow the authorization value from msg.sender to the mapping key to the enum. "
            "Check who can call setRole(), who can assign Admin, and whether role changes emit "
            "the state actually written."
        ),
    },
    {
        "name": "eth-flow",
        "aliases": ["receive-mapping-call", "ether-mapping", "payable-flow"],
        "concepts": [
            "receive", "fallback", "payable", "mapping", "address", "msg.sender", "msg.value",
            "call", "checks-effects-interactions", "function",
        ],
        "summary": (
            "ETH enters through receive/fallback, gets accounted for in a mapping, and leaves "
            "through an external call to an address."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract EthFlowLab {
    mapping(address => uint256) public credits;

    receive() external payable {
        credits[msg.sender] += msg.value;
    }

    fallback() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount_) external {
        require(credits[msg.sender] >= amount_, "insufficient credit");

        credits[msg.sender] -= amount_;

        (bool ok, ) = payable(msg.sender).call{value: amount_}("");
        require(ok, "ETH send failed");
    }
}
""",
        "support_files": {},
        "variables": [
            ("state", "mapping(address => uint256)", "credits", "credits[msg.sender]", "Accounting state for each caller."),
            ("global value", "address", "msg.sender", "0xAlice", "Caller of the current message."),
            ("global value", "uint256", "msg.value", "1 ether", "ETH attached to the current call."),
            ("function parameter", "uint256", "amount_", "0.5 ether", "Amount requested for withdrawal."),
            ("local variable", "bool", "ok", "true / false", "Success flag returned by the low-level call."),
            ("address expression", "address payable", "payable(msg.sender)", "0xAlice", "Recipient converted to an address allowed to receive ETH."),
        ],
        "calls": [
            "alice → receive() with 1 ether",
            "bob → fallback() with 0.25 ether and non-empty calldata",
            "alice → withdraw(0.5 ether)",
        ],
        "steps": [
            "An empty-calldata ETH transfer selects receive().",
            "A payable unmatched call can select fallback().",
            "Both entry points use msg.sender as the mapping key and msg.value as the amount.",
            "withdraw() reads credits[msg.sender] and checks the requested amount.",
            "The accounting write happens before the external call.",
            "payable(msg.sender).call{value: amount_}("") sends ETH and returns a bool success flag.",
        ],
        "connections": [
            "receive/fallback → ETH entry path.",
            "msg.sender + msg.value → mapping accounting key/value update.",
            "mapping → withdrawal authorization/accounting.",
            "address payable → low-level ETH call target.",
            "checks-effects-interactions → state update before external interaction.",
        ],
        "audit": (
            "Check the accounting invariant around credits and actual ETH balance. Pay special "
            "attention to external calls, failed sends, reentrancy, and whether every ETH entry "
            "route follows the same accounting rule."
        ),
    },
    {
        "name": "external-interfaces",
        "aliases": ["interface-calls", "interfaces-addresses", "abi-call"],
        "concepts": [
            "interface", "external-call", "call", "staticcall", "delegatecall", "address",
            "bytes", "bytes32", "abi.encode", "abi.decode", "function",
        ],
        "summary": (
            "The same target address can be approached through a typed interface or through "
            "raw low-level calls; ABI encoding/decoding turns values into call data and back."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ICounter {
    function increment() external returns (uint256);
    function number() external view returns (uint256);
}

contract ExternalInterfacesLab {
    function typedRead(address target_) external view returns (uint256) {
        return ICounter(target_).number();
    }

    function rawWrite(address target_)
        external
        returns (bool ok, bytes memory data)
    {
        (ok, data) = target_.call(
            abi.encodeWithSignature("increment()")
        );
    }

    function rawRead(address target_)
        external
        view
        returns (uint256 number)
    {
        (bool ok, bytes memory data) = target_.staticcall(
            abi.encodeWithSignature("number()")
        );

        require(ok, "staticcall failed");
        number = abi.decode(data, (uint256));
    }

    function rawDelegate(address target_)
        external
        returns (bool ok, bytes memory data)
    {
        (ok, data) = target_.delegatecall(
            abi.encodeWithSignature("increment()")
        );
    }

    function makeId(address target_, bytes32 label_)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target_, label_));
    }
}
""",
        "support_files": {},
        "variables": [
            ("function parameter", "address", "target_", "0xTarget", "Address of the contract being called."),
            ("function parameter", "bytes32", "label_", 'bytes32("POOL")', "Fixed-size value encoded with an address."),
            ("local variable", "bool", "ok", "true / false", "Low-level call success flag."),
            ("local variable", "bytes memory", "data", "ABI bytes", "Raw return data from the target."),
            ("return variable", "uint256", "number", "decoded value", "Value produced by abi.decode()."),
        ],
        "calls": [
            "lab.typedRead(target);",
            'lab.rawWrite(target);      // encodes increment()',
            'lab.rawRead(target);       // staticcall + abi.decode',
            'lab.rawDelegate(target);   // same code, caller storage/context',
            'lab.makeId(target, bytes32("POOL"));',
        ],
        "steps": [
            "ICounter(target_) creates a typed interface view over an address; it does not deploy the target.",
            "typedRead() calls a known external function through that interface.",
            "rawWrite() encodes the function name into bytes and sends a low-level call.",
            "rawRead() uses staticcall, then decodes the returned bytes into uint256.",
            "rawDelegate() runs target code using this contract's storage/context, so the security model is different.",
            "makeId() shows the same address/bytes32 values being ABI-encoded and hashed into a bytes32 identifier.",
        ],
        "connections": [
            "interface → address → typed external function call.",
            "abi.encodeWithSignature → bytes → low-level call.",
            "staticcall → bytes return data → abi.decode → uint256.",
            "delegatecall → target code with caller storage/context.",
            "address + bytes32 → abi.encode → keccak256 → bytes32.",
        ],
        "audit": (
            "Never treat call/staticcall/delegatecall as interchangeable. Verify the target address, "
            "encoded selector/arguments, return-data decoding, failure handling, and storage/context "
            "assumptions before trusting a low-level call."
        ),
    },
    {
        "name": "inheritance-interface",
        "aliases": ["abstract-interface-override", "inheritance-contracts", "abstract-contract"],
        "concepts": [
            "abstract", "interface", "inheritance", "override", "virtual", "constructor",
            "address", "string", "function", "msg.sender",
        ],
        "summary": (
            "An abstract contract provides reusable state/behavior, an interface describes a "
            "callable shape, and the child contract supplies overrides and constructor values."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

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
        "support_files": {},
        "variables": [
            ("base state", "address", "owner", "msg.sender", "Stored by the abstract base contract."),
            ("base constructor parameter", "address", "owner_", "msg.sender", "Passed from Child into Named."),
            ("child state", "string", "name", '"Savings"', "Stored by the concrete Child contract."),
            ("child constructor parameter", "string memory", "name_", '"Savings"', "Deployment-time child value."),
            ("interface return", "string memory", "label()", "name", "Interface promises a callable read function."),
        ],
        "calls": [
            'new Child("Savings");',
            'child.who();',
            'child.label();',
        ],
        "steps": [
            "Named is abstract because it is designed to be inherited rather than deployed as the finished app contract.",
            "ILabel is an interface: it describes label() without defining storage.",
            "Child inherits Named and ILabel.",
            "Child's constructor sends msg.sender to Named's owner_ parameter.",
            "Child overrides who() and implements label(), satisfying the inherited callable shapes.",
        ],
        "connections": [
            "abstract contract → reusable base implementation/state.",
            "interface → required function shape without state storage.",
            "is → inheritance relationship.",
            "virtual → base function can be overridden.",
            "override → child explicitly supplies the inherited implementation.",
            "constructor → initializes base and child state through separate arguments.",
        ],
        "audit": (
            "When reviewing inheritance, follow constructor chaining, storage ownership, overridden "
            "functions, and whether the interface's assumptions actually match the implementation."
        ),
    },
    {
        "name": "abi-hashing",
        "aliases": ["bytes-hash-mapping", "abi-keccak", "encode-key"],
        "concepts": [
            "abi.encode", "abi.decode", "keccak256", "bytes", "bytes32", "mapping",
            "address", "string", "function",
        ],
        "summary": (
            "Human-readable values are ABI-encoded into bytes, hashed into a bytes32 id, and "
            "that id becomes a mapping key."
        ),
        "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract AbiHashLab {
    mapping(bytes32 => address) public ownersById;

    function register(string calldata name_, address account_)
        external
        returns (bytes32 id, bytes memory encoded)
    {
        encoded = abi.encode(name_, account_);
        id = keccak256(encoded);
        ownersById[id] = account_;
    }

    function recover(bytes calldata encoded)
        external
        pure
        returns (string memory name_, address account_)
    {
        (name_, account_) = abi.decode(encoded, (string, address));
    }
}
""",
        "support_files": {},
        "variables": [
            ("state", "mapping(bytes32 => address)", "ownersById", "ownersById[id]", "Stores an address under a hashed bytes32 key."),
            ("parameter", "string calldata", "name_", '"Toji"', "Original text input."),
            ("parameter", "address", "account_", "0xAlice", "Address paired with the text."),
            ("return variable", "bytes32", "id", "keccak256(encoded)", "Hash-derived mapping key."),
            ("return variable", "bytes memory", "encoded", "abi.encode(name_, account_)", "Raw ABI representation of the values."),
            ("parameter", "bytes calldata", "encoded", "previous ABI bytes", "Input passed to recover()."),
            ("return variable", "string memory", "name_", '"Toji"', "Value decoded from bytes."),
            ("return variable", "address", "account_", "0xAlice", "Address decoded from bytes."),
        ],
        "calls": [
            'lab.register("Toji", alice);',
            'lab.recover(encodedBytes);',
        ],
        "steps": [
            "abi.encode(name_, account_) packs the typed values into bytes.",
            "keccak256(encoded) turns those bytes into a bytes32 hash.",
            "The bytes32 hash becomes a mapping key.",
            "abi.decode() reverses ABI encoding when the expected types are supplied.",
            "Changing the input values changes the encoded bytes and therefore the hash.",
        ],
        "connections": [
            "string + address → abi.encode → bytes.",
            "bytes → keccak256 → bytes32.",
            "bytes32 → mapping key → address value.",
            "bytes → abi.decode → string + address.",
        ],
        "audit": (
            "Check exactly which values are encoded, whether collisions/ambiguity are possible in "
            "the chosen encoding method, and whether the decoded types and order match the encoder."
        ),
    },
]



# Broad language/data-flow relationships. These are teaching edges, not claims
# that two concepts are syntactically interchangeable.
_CONNECTION_EDGES = [
    ("imports", "interface", "imports can expose an interface declaration"),
    ("imports", "inheritance", "imports can expose a base contract"),
    ("imports", "library", "imports can expose a library"),
    ("interface", "address", "an interface value is attached to a contract address"),
    ("interface", "function", "interfaces describe callable function shapes"),
    ("interface", "external-call", "calling an interface crosses a contract boundary"),
    ("function", "mapping", "functions commonly read/write mappings"),
    ("function", "structs", "functions can read/write struct values"),
    ("function", "arrays", "functions can create, index, push, or return arrays"),
    ("function", "enum", "functions can accept/store/update enum state"),
    ("function", "bytes", "functions can accept/return raw bytes"),
    ("function", "address", "functions commonly accept addresses"),
    ("mapping", "structs", "a mapping value can be a struct"),
    ("mapping", "arrays", "a mapping value can be an array"),
    ("mapping", "nested-mapping", "a mapping can contain another mapping"),
    ("mapping", "keccak256", "hashing can create ids or derived storage-slot keys"),
    ("mapping", "storage", "mappings live in storage"),
    ("arrays", "loops", "loops commonly iterate arrays"),
    ("arrays", "structs", "struct fields can contain arrays"),
    ("arrays", "storage", "storage arrays persist and can grow"),
    ("arrays", "memory", "dynamic arrays can be copied to memory"),
    ("arrays", "calldata", "external functions can receive dynamic arrays in calldata"),
    ("structs", "storage", "stored structs live in contract storage"),
    ("structs", "memory", "structs can be copied into memory"),
    ("structs", "calldata", "external functions can receive struct-like tuple input"),
    ("enum", "mapping", "a mapping can store an enum as its value"),
    ("enum", "structs", "a struct can store enum state"),
    ("bytes", "bytes32", "dynamic bytes and fixed bytes32 are common byte representations"),
    ("string", "bytes", "text can be converted to bytes"),
    ("string", "abi.encode", "strings can be ABI encoded"),
    ("address", "msg.sender", "msg.sender has address type"),
    ("address", "msg.value", "address identifies the recipient while msg.value supplies ETH"),
    ("address", "payable", "payable(address) creates an ETH-sending address"),
    ("payable", "msg.value", "payable entry points can receive msg.value"),
    ("receive", "msg.value", "receive handles empty-calldata ETH with msg.value"),
    ("fallback", "msg.data", "fallback can inspect raw msg.data"),
    ("receive", "fallback", "both are ETH/call routing entry points"),
    ("msg.value", "mapping", "ETH accounting is often stored per caller in a mapping"),
    ("msg.sender", "mapping", "caller address is commonly used as a mapping key"),
    ("call", "bytes", "low-level call takes calldata bytes and returns bytes"),
    ("call", "reentrancy", "external calls can open callback/reentrancy boundaries"),
    ("call", "checks-effects-interactions", "CEI orders state effects before external calls"),
    ("call", "staticcall", "staticcall is a read-only external-call variant"),
    ("call", "delegatecall", "delegatecall is an external code execution variant"),
    ("interface", "staticcall", "typed interfaces and raw staticcall address the same contract boundary differently"),
    ("delegatecall", "storage", "delegatecall executes with caller storage/context"),
    ("proxy-fallback", "delegatecall", "proxy fallback commonly forwards with delegatecall"),
    ("abi.encode", "bytes", "ABI encoding produces bytes"),
    ("abi.encode", "keccak256", "encoded values are common hash input"),
    ("abi.decode", "bytes", "ABI decoding consumes bytes"),
    ("abi.decode", "calldata", "calldata bytes can be ABI decoded"),
    ("keccak256", "bytes32", "keccak256 returns bytes32"),
    ("bytes32", "mapping", "bytes32 values are common mapping keys"),
    ("mapping-slots", "keccak256", "mapping storage slots use hashing"),
    ("nested-mapping-slots", "mapping", "nested mapping slot derivation follows mapping state"),
    ("storage", "yul-storage", "Yul sload/sstore can address storage directly"),
    ("calldata", "yul-calldata", "Yul can read raw calldata"),
    ("yul", "storage", "assembly can access storage"),
    ("yul", "calldata", "assembly can access calldata"),
    ("yul", "memory", "assembly can read/write memory"),
    ("yul", "call", "assembly can execute low-level calls"),
    ("yul-control-flow", "loops", "Yul has its own low-level repetition/control forms"),
    ("yul-functions", "function", "Yul local functions are distinct from Solidity functions but serve reusable computation"),
    ("constructor", "inheritance", "constructors initialize child and base state"),
    ("constructor", "msg.sender", "deployment caller is available during construction"),
    ("constructor", "address", "constructors commonly receive addresses"),
    ("constructor", "string", "constructors can receive strings"),
    ("constructor", "uint256", "constructors can receive numeric parameters"),
    ("modifier", "access-control", "modifiers commonly enforce access rules"),
    ("modifier", "function", "modifiers wrap function execution"),
    ("errors", "function", "functions can revert with custom errors"),
    ("events", "function", "functions commonly emit events after state changes"),
    ("try-catch", "interface", "typed external calls can be wrapped in try/catch"),
    ("try-catch", "call", "external failure can be handled with try/catch or call return flags"),
    ("library", "using-for", "using-for attaches library functions to a type"),
    ("new", "constructor", "new deploys and supplies constructor arguments"),
    ("abstract", "inheritance", "abstract contracts are intended for inheritance"),
    ("virtual", "override", "virtual permits an inherited implementation to be overridden"),
    ("override", "interface", "implementations explicitly satisfy inherited/interface functions"),
    ("signature-verification", "keccak256", "signed message digests are commonly hashed"),
    ("signature-verification", "bytes", "signatures and digests are represented as bytes"),
    ("signature-verification", "address", "verification recovers/checks an address"),
    ("oracle", "interface", "oracle integrations are commonly accessed through interfaces"),
    ("timestamp", "block.timestamp", "timestamp is a block context value"),
    ("front-running", "calldata", "public transaction input can be observed before execution"),
    ("tx-origin", "msg.sender", "both identify transaction/call context differently"),
    ("access-control", "msg.sender", "authorization commonly starts from caller identity"),
    ("unchecked", "uint256", "unchecked changes overflow/underflow checking for arithmetic"),
    ("delete", "storage", "delete resets a stored variable to its default"),
]


def connection_paths(names):
    """Return short human-readable bridges between requested concepts."""
    nodes = list(dict.fromkeys(canonicalize(name) for name in names))
    adjacency = {}
    labels = {}
    for left, right, label in _CONNECTION_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        adjacency.setdefault(a, []).append(b)
        adjacency.setdefault(b, []).append(a)
        labels[(a, b)] = label
        labels[(b, a)] = label

    def shortest(start, goal):
        if start == goal:
            return [start]
        queue = [(start, [start])]
        seen = {start}
        while queue:
            cur, path = queue.pop(0)
            for nxt in adjacency.get(cur, []):
                if nxt in seen:
                    continue
                candidate = path + [nxt]
                if nxt == goal:
                    return candidate
                seen.add(nxt)
                queue.append((nxt, candidate))
        return None

    rows = []
    if len(nodes) < 2:
        return rows
    root = nodes[0]
    for goal in nodes[1:]:
        path = shortest(root, goal)
        if path:
            edge_text = []
            for left, right in zip(path, path[1:]):
                edge_text.append(labels.get((left, right), "contract-level bridge"))
            rows.append((root, goal, path, edge_text))
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


_COMPOSITE_ALIASES = {
    "arrays-mappings": {"arrays", "mapping"},
    "arrays-structs": {"arrays", "structs"},
    "mapping-struct": {"mapping", "structs"},
    "mapping-array-value": {"mapping", "arrays"},
    "storage-memory-calldata": {"storage", "memory", "calldata"},
    "receive-vs-fallback": {"receive", "fallback"},
    "call-anatomy": {"call", "staticcall", "delegatecall"},
    "strings-bytes": {"string", "bytes"},
    "globals": {"msg.sender", "msg.value"},
    "msg-block-tx": {"msg.sender", "msg.value"},
    "msg.value-vs-balance": {"msg.value", "address"},
    "mapping-types": {"mapping"},
    "struct-types": {"structs"},
}



# Universal fallback: this is deliberately broad. Focused recipes above are used
# when an exact teaching example exists; otherwise every recognized combination
# lands here instead of being rejected.
UNIVERSAL_CONNECTION_LAB = {
    "name": "solidity-yul-composer",
    "aliases": ["universal", "all", "composer", "everything"],
    "concepts": ["*"],
    "summary": (
        "A universal connection notebook for recognized Solidity and Yul concepts. "
        "It deliberately puts data types, state, functions, inheritance, interfaces, "
        "imports, ABI, hashing, storage, ETH flow, external calls, and Yul in one "
        "compile-checked environment so arbitrary combinations can be traced through "
        "real variables and values."
    ),
    "source": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./ConnectionSupport.sol";

contract MiniCounter {
    uint256 public number;

    constructor(uint256 number_) {
        number = number_;
    }

    function increment(uint256 amount_) external {
        number += amount_;
    }
}

contract UniversalConnectionLab is ConnectionOwned {
    using ConnectionMath for uint256;

    enum Status {
        None,
        Active,
        Done
    }

    type UserId is uint256;

    struct Profile {
        address owner;
        string name;
        uint256 score;
        bytes32 id;
        bytes memo;
        Status status;
        uint256[] tags;
    }

    // State: simple values and reference values.
    address public manager;
    string public title;
    uint256 public total;
    uint256 public constant VERSION = 1;
    uint256 public immutable deployedAt;
    bool public paused;
    int256 public signedValue;
    bytes public rawMemo;
    bytes32 public code;

    // Mapping + nested mapping + mapping-to-array + mapping-to-struct.
    mapping(address => Profile) public profiles;
    mapping(address => mapping(bytes32 => uint256)) public balances;
    mapping(bytes32 => address[]) public members;
    mapping(address => uint256[]) public scoresByUser;

    // Dynamic + fixed/static arrays.
    address[] public users;
    address[3] public fixedUsers;
    uint256[] public scores;
    uint256[3] public fixedScores;

    // Interface is an address-typed callable boundary.
    IConnectionOracle public oracle;

    event ProfileUpdated(
        address indexed user,
        uint256 oldScore,
        uint256 newScore,
        Status oldStatus,
        Status newStatus
    );
    event OracleChanged(address indexed oracle_);
    event Paid(address indexed from, uint256 amount);
    error NotAuthorized(address caller);
    error BadAmount(uint256 amount_);

    constructor(address owner_, string memory title_, bytes32 code_)
        ConnectionOwned(owner_)
    {
        manager = msg.sender;
        title = title_;
        code = code_;
        deployedAt = block.timestamp;
    }

    modifier active() {
        require(!paused, "paused");
        _;
    }

    function createProfile(
        string calldata name_,
        uint256 score_,
        bytes32 id_,
        bytes calldata memo_,
        uint256[] calldata tags_
    ) external payable active {
        if (score_ == 0) revert BadAmount(score_);

        Profile storage profile = profiles[msg.sender];

        profile.owner = msg.sender;
        profile.name = name_;
        profile.score = score_;
        profile.id = id_;
        profile.memo = memo_;
        profile.status = Status.Active;
        profile.tags = tags_;

        users.push(msg.sender);
        scores.push(score_);
        scoresByUser[msg.sender].push(score_);
        balances[msg.sender][id_] += score_;

        total = total.add(score_);
        emit Paid(msg.sender, msg.value);
    }

    function updateProfile(
        address user_,
        string calldata name_,
        uint256 score_,
        bytes32 id_,
        Status status_,
        uint256[] calldata tags_
    ) external onlyOwner {
        Profile storage profile = profiles[user_];

        uint256 oldScore = profile.score;
        Status oldStatus = profile.status;

        profile.name = name_;
        profile.score = score_;
        profile.id = id_;
        profile.status = status_;
        profile.tags = tags_;

        balances[user_][id_] = score_;

        emit ProfileUpdated(user_, oldScore, score_, oldStatus, status_);
    }

    function addMember(bytes32 groupId_, address member_) external {
        members[groupId_].push(member_);
    }

    function setFixed(
        address[3] calldata users_,
        uint256[3] calldata scores_
    ) external onlyOwner {
        fixedUsers = users_;
        fixedScores = scores_;
    }

    function setMemo(bytes calldata memo_, bytes32 code_) external {
        rawMemo = memo_;
        code = code_;
    }

    function setOracle(address oracle_) external onlyOwner {
        oracle = IConnectionOracle(oracle_);
        emit OracleChanged(oracle_);
    }

    function readOracle() external view returns (uint256 price_) {
        return oracle.price();
    }

    function readOracleSafely()
        external
        view
        returns (bool ok, uint256 price_)
    {
        try oracle.price() returns (uint256 value) {
            return (true, value);
        } catch {
            return (false, 0);
        }
    }

    function rawStaticPrice(address target_)
        external
        view
        returns (uint256 price_)
    {
        (bool ok, bytes memory data) = target_.staticcall(
            abi.encodeWithSelector(IConnectionOracle.price.selector)
        );
        require(ok, "staticcall failed");
        price_ = abi.decode(data, (uint256));
    }

    function rawCall(address target_, bytes calldata data_)
        external
        returns (bool ok, bytes memory result)
    {
        (ok, result) = target_.call(data_);
    }

    function rawDelegate(address target_, bytes calldata data_)
        external
        returns (bool ok, bytes memory result)
    {
        (ok, result) = target_.delegatecall(data_);
    }

    function encodeAndHash(
        address user_,
        uint256 amount_,
        string calldata label_
    )
        external
        pure
        returns (bytes memory encoded, bytes32 id)
    {
        encoded = abi.encode(user_, amount_, label_);
        id = keccak256(encoded);
    }

    function decodeValues(bytes calldata encoded)
        external
        pure
        returns (address user_, uint256 amount_, string memory label_)
    {
        (user_, amount_, label_) =
            abi.decode(encoded, (address, uint256, string));
    }

    function makeStorageKey(address user_, bytes32 id_)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(user_, id_));
    }

    function readMappingWithYul(address user_, bytes32 id_)
        external
        view
        returns (uint256 result)
    {
        uint256 outerSlot;
        uint256 innerSlot;

        assembly {
            // balances is mapping(address => mapping(bytes32 => uint256)).
            mstore(0x00, user_)
            mstore(0x20, balances.slot)
            outerSlot := keccak256(0x00, 0x40)

            mstore(0x00, id_)
            mstore(0x20, outerSlot)
            innerSlot := keccak256(0x00, 0x40)

            result := sload(innerSlot)
        }
    }

    function yulMath(uint256 a_, uint256 b_)
        external
        pure
        returns (uint256 result)
    {
        assembly {
            let sum := add(a_, b_)
            switch sum
            case 0 {
                result := 0
            }
            default {
                result := sum
            }
        }
    }

    function yulFirstArgument() external pure returns (uint256 result) {
        assembly {
            // Four-byte selector, then the first ABI word.
            result := calldataload(4)
        }
    }

    function yulStoreAndLoad(uint256 value_)
        external
        returns (uint256 result)
    {
        uint256 slot = 250;

        assembly {
            sstore(slot, value_)
            result := sload(slot)
        }
    }

    function addScore(uint256 score_) external {
        scores.push(score_);
    }

    function totalScores() external view returns (uint256 sum) {
        for (uint256 i = 0; i < scores.length; i++) {
            sum += scores[i];
        }
    }

    function firstTag(address user_) external view returns (uint256) {
        Profile storage profile = profiles[user_];
        if (profile.tags.length == 0) {
            return 0;
        }
        return profile.tags[0];
    }

    function copyTags(address user_)
        external
        view
        returns (uint256[] memory result)
    {
        result = profiles[user_].tags;
    }

    function clearProfile(address user_) external onlyOwner {
        delete profiles[user_];
    }

    function uncheckedAdd(uint256 a_, uint256 b_)
        external
        pure
        returns (uint256 result)
    {
        unchecked {
            result = a_ + b_;
        }
    }

    function deployCounter(uint256 seed_)
        external
        returns (address counter)
    {
        counter = address(new MiniCounter(seed_));
    }

    function typedFunctionPointer(uint256 value_)
        external
        pure
        returns (uint256)
    {
        function(uint256) internal pure returns (uint256) fn = _double;
        return fn(value_);
    }

    function _double(uint256 value_) internal pure returns (uint256) {
        return value_ * 2;
    }

    function context()
        external
        payable
        returns (
            address caller,
            address origin,
            uint256 attached,
            uint256 contractBalance,
            uint256 blockNumber_,
            uint256 timestamp_
        )
    {
        caller = msg.sender;
        origin = tx.origin;
        attached = msg.value;
        contractBalance = address(this).balance;
        blockNumber_ = block.number;
        timestamp_ = block.timestamp;
    }

    receive() external payable {
        total += msg.value;
        emit Paid(msg.sender, msg.value);
    }

    fallback() external payable {
        rawMemo = msg.data;
        total += msg.value;
    }
}
""",
    "support_files": {
        "ConnectionSupport.sol": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract ConnectionOwned {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    error Unauthorized(address caller);
}

interface IConnectionOracle {
    function price() external view returns (uint256);
}

library ConnectionMath {
    function add(uint256 a_, uint256 b_) internal pure returns (uint256) {
        return a_ + b_;
    }
}
""",
    },
    "variables": [
        ("support state", "address", "owner", "0xAdmin", "Imported abstract base's persistent owner."),
        ("state", "address", "manager", "msg.sender", "Deployment caller stored as a manager."),
        ("state", "string", "title", '"Savings"', "Human-readable contract name."),
        ("state", "uint256", "total", "22", "Numeric state updated by functions and ETH entry points."),
        ("state", "uint256 constant", "VERSION", "1", "Compile-time constant."),
        ("state", "uint256 immutable", "deployedAt", "block.timestamp", "Set once in the constructor."),
        ("state", "bool", "paused", "false", "Simple flag used by a modifier."),
        ("state", "int256", "signedValue", "-7", "Signed integer example."),
        ("state", "bytes", "rawMemo", 'hex"6869"', "Dynamic byte sequence."),
        ("state", "bytes32", "code", 'bytes32("KE")', "Fixed 32-byte value."),
        ("state", "mapping(address => Profile)", "profiles", "profiles[msg.sender]", "Address selects a whole struct."),
        ("state", "nested mapping", "balances", "balances[user][id]", "Two keys select a uint256."),
        ("state", "mapping(bytes32 => address[])", "members", "members[groupId]", "A mapping key selects a dynamic address array."),
        ("state", "mapping(address => uint256[])", "scoresByUser", "scoresByUser[user]", "A mapping value can itself be a dynamic array."),
        ("state", "address[]", "users", "[alice, bob, ...]", "Dynamic address array."),
        ("state", "address[3]", "fixedUsers", "[alice, bob, carol]", "Static/fixed address array."),
        ("state", "uint256[]", "scores", "[10, 20, 30]", "Dynamic numeric array."),
        ("state", "uint256[3]", "fixedScores", "[10, 20, 30]", "Static/fixed numeric array."),
        ("state", "IConnectionOracle", "oracle", "IConnectionOracle(0xOracle)", "Interface reference backed by an address."),
        ("struct field", "address", "owner", "msg.sender", "Address inside Profile."),
        ("struct field", "string", "name", '"Toji"', "Text inside Profile."),
        ("struct field", "uint256", "score", "22", "Number inside Profile."),
        ("struct field", "bytes32", "id", 'bytes32("KE")', "Identifier inside Profile."),
        ("struct field", "bytes", "memo", 'hex"6869"', "Dynamic bytes inside Profile."),
        ("struct field", "Status", "status", "Status.Active", "Named enum state."),
        ("struct field", "uint256[]", "tags", "[1, 2, 3]", "Dynamic array stored inside Profile."),
        ("constructor parameter", "address", "owner_", "0xAdmin", "Passed into imported base constructor."),
        ("constructor parameter", "string", "title_", '"Savings"', "Deployment-time string."),
        ("constructor parameter", "bytes32", "code_", 'bytes32("KE")', "Deployment-time fixed bytes."),
        ("function parameter", "string calldata", "name_", '"Toji"', "External read-only text input."),
        ("function parameter", "uint256", "score_", "22", "External numeric input."),
        ("function parameter", "bytes32", "id_", 'bytes32("KE")', "External fixed bytes input."),
        ("function parameter", "bytes calldata", "memo_", 'hex"6869"', "External raw bytes input."),
        ("function parameter", "uint256[] calldata", "tags_", "[1, 2, 3]", "External dynamic array input."),
        ("function parameter", "address", "user_", "0xAlice", "Address used as a mapping key."),
        ("function parameter", "Status", "status_", "Status.Done", "Enum supplied to an update function."),
        ("function parameter", "address[3]", "users_", "[alice, bob, carol]", "Fixed-size array input."),
        ("function parameter", "uint256[3]", "scores_", "[10, 20, 30]", "Fixed-size numeric input."),
        ("local", "Profile storage", "profile", "profiles[user_]", "Storage reference that writes persistent state."),
        ("local", "uint256", "oldScore", "profile.score", "Value captured before a state update."),
        ("local", "Status", "oldStatus", "profile.status", "Old enum value for event history."),
        ("local", "bool", "ok", "true / false", "Low-level call success flag."),
        ("local", "bytes memory", "data", "ABI bytes", "Raw return data from an external call."),
        ("local", "bytes memory", "encoded", "abi.encode(...)", "ABI-encoded values."),
        ("return", "bytes32", "id", "keccak256(encoded)", "Hash used as an identifier."),
        ("Yul local", "word", "slot", "keccak256(...)", "Manually computed mapping storage slot."),
        ("Yul local", "word", "sum", "add(a_, b_)", "Arithmetic temporary in assembly."),
    ],
    "calls": [
        'new UniversalConnectionLab(admin, "Savings", bytes32("KE"));',
        'lab.createProfile("Toji", 22, bytes32("KE"), hex"6869", [1, 2, 3]);',
        'lab.updateProfile(alice, "Alice", 100, bytes32("A"), Status.Done, [7, 8]);',
        'lab.addMember(bytes32("DAO"), bob);',
        'lab.setFixed([alice, bob, carol], [10, 20, 30]);',
        'lab.encodeAndHash(alice, 100, "deposit");',
        'lab.decodeValues(encodedBytes);',
        'lab.readMappingWithYul(alice, bytes32("A"));',
        'lab.rawStaticPrice(oracle);',
        'lab.rawCall(target, abi.encodeWithSignature("increment(uint256)", 5));',
        'lab.totalScores();',
        'lab.deployCounter(100);',
        'lab.context{value: 1 ether}();',
        'address(lab).call{value: 1 ether}(hex"");',
    ],
    "steps": [
        "import loads ConnectionSupport.sol, making its declarations available to the main source file.",
        "ConnectionOwned is abstract reusable code; UniversalConnectionLab inherits it with is.",
        "The child constructor receives owner_, title_, and code_, then passes owner_ into ConnectionOwned(owner_).",
        "msg.sender is an address value that can initialize manager, become a struct field, and become a mapping key.",
        "createProfile() receives string, uint256, bytes32, bytes, and a dynamic uint256[] through calldata.",
        "profiles[msg.sender] selects one Profile struct; Profile storage profile points at the persistent struct.",
        "The struct combines address, string, uint256, bytes32, bytes, enum, and a dynamic array.",
        "balances[msg.sender][id_] performs two mapping lookups and updates a uint256.",
        "members[groupId_].push(member_) connects mapping lookup, bytes32 keys, dynamic arrays, and addresses.",
        "users/scores are dynamic arrays; fixedUsers/fixedScores have fixed lengths and are assigned as whole values.",
        "abi.encode produces bytes; keccak256 turns those bytes into a bytes32 id that can become a mapping key.",
        "abi.decode reverses that encoding when the caller supplies the matching type order.",
        "A typed interface call hides ABI encoding; low-level call/staticcall/delegatecall expose the call boundary.",
        "try/catch adds explicit external-call failure handling.",
        "Yul assembly can read/write raw storage and calldata; the nested mapping example manually derives its slot.",
        "Yul switch/let/add provide low-level control and arithmetic inside an assembly block.",
        "receive() handles empty-calldata ETH and fallback() handles unmatched calls; both can use msg.value and msg.data.",
        "A loop walks a dynamic array; storage/memory/calldata determine where reference-type data lives.",
        "using for attaches library behavior to a value, while new creates a new contract instance.",
        "constant/immutable/default values, enum values, custom errors, events, modifiers, unchecked arithmetic, and delete all appear in one stateful context.",
    ],
    "connections": [
        "imports → imported abstract contract/interface/library → inheritance/using-for.",
        "constructor parameters → base-constructor arguments → persistent state.",
        "address/msg.sender → mapping key → struct or numeric value.",
        "struct → address + string + uint256 + bytes32 + bytes + enum + dynamic array.",
        "mapping → nested mapping → bytes32 key → uint256 value.",
        "mapping → array → push()/indexing/looping.",
        "dynamic array vs fixed array → variable length vs exact compile-time length.",
        "string/bytes → calldata → storage/memory copies.",
        "abi.encode → bytes → keccak256 → bytes32 → mapping key/id.",
        "interface → address → typed external function → return value.",
        "ABI encoding → low-level call/staticcall/delegatecall → bytes return data → abi.decode.",
        "receive/fallback → msg.sender + msg.value + msg.data → state/accounting.",
        "mapping → storage slot formula → Yul sload/sstore.",
        "calldata → Yul calldataload; storage → Yul sload/sstore.",
        "abstract/virtual/override/is → inherited implementation and polymorphic call shape.",
        "modifier → msg.sender → authorization branch → protected function body.",
        "enum → explicit named state values → mapping/struct/event state transitions.",
        "library + using-for → reusable function call on a uint256.",
        "new → constructor arguments → fresh contract address.",
        "function type → stored function pointer → internal call.",
    ],
    "audit": (
        "Use the requested concepts as a trace, not isolated vocabulary: identify every input, "
        "type, lookup/index, storage write, call boundary, return value, and caller identity. "
        "For Yul, re-check compiler-level assumptions manually because assembly bypasses many "
        "Solidity safety checks. For mappings, trace keys and storage slots; for ABI/calls, trace "
        "selectors, encoded arguments, return bytes, and failure handling."
    ),
}



# Human-sized teaching scenes. Focused recipes are preferred for the default
# connect view; the universal lab remains available as the explicit full view.
MICRO_SCENES = [
    {
        "keys": {"interface", "function", "arrays"},
        "title": "An interface returns an array",
        "story": "A contract stores another contract's address as an interface. The interface declares a function, and that function returns a dynamic address array.",
        "code": """interface IUserStore {
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
}""",
        "variables": [
            ("state", "IUserStore", "store", "IUserStore(0xStore)", "Interface reference; the underlying value is a contract address."),
            ("constructor parameter", "address", "store_", "0xStore", "Target contract address supplied at deployment."),
            ("interface function", "address[] memory", "users()", "[alice, bob]", "Function promised by the interface."),
            ("external function", "address[] memory", "getUsers()", "store.users()", "Calls the interface function and returns its array."),
        ],
        "flow": [
            "store_ is an address supplied when Reader is deployed.",
            "IUserStore(store_) treats that address as a contract exposing the interface function.",
            "getUsers() calls store.users().",
            "users() returns a dynamic array, so the value reaching getUsers() is an address array.",
        ],
        "call": "reader.getUsers();  // [alice, bob]",
    },
    {
        "keys": {"imports", "constructor"},
        "title": "Import → base/interface → constructor chain",
        "story": "import makes a declaration available; deployment calls the child constructor, which can pass a value to an imported base constructor.",
        "code": """// Owned.sol
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
}""",
        "variables": [
            ("base state", "address", "owner", "msg.sender", "Stored in the imported base."),
            ("constructor parameter", "string memory", "name_", '"Savings"', "Value supplied to Vault at deployment."),
            ("base constructor parameter", "address", "owner_", "msg.sender", "Value supplied through Owned(...)."),
        ],
        "flow": [
            "import only makes Owned available to Vault.",
            "new Vault(\"Savings\") enters Vault's constructor.",
            "Vault supplies msg.sender to Owned(msg.sender).",
            "Owned stores that address as owner.",
        ],
        "call": 'new Vault("Savings");  // name = "Savings", owner = deployer',
    },
    {
        "keys": {"structs", "mapping", "nested-mapping", "arrays", "enum", "bytes", "address"},
        "title": "A mapping stores a struct with an enum, bytes, and arrays",
        "story": "An address selects a struct from a mapping. The struct contains an enum, raw bytes, and a dynamic array. A second mapping uses two keys, while separate arrays show dynamic versus fixed size.",
        "code": """enum Status { Open, Done }

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
address[3] public fixedUsers;

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
}""",
        "variables": [
            ("state", "mapping(address => Profile)", "profiles", "profiles[user_]", "Address key selects a whole Profile."),
            ("state", "mapping(address => mapping(bytes32 => uint256))", "balances", "balances[user_][id_]", "Two keys select one uint256."),
            ("state", "address[]", "users", "[alice, ...]", "Dynamic array; its length can grow."),
            ("state", "address[3]", "fixedUsers", "[alice, bob, carol]", "Fixed/static array with exactly three slots."),
            ("struct field", "address", "owner", "user_", "Address stored in Profile."),
            ("struct field", "uint256", "score", "22", "Numeric field stored in Profile."),
            ("struct field", "Status", "status", "Status.Done", "Enum value stored in Profile."),
            ("struct field", "bytes", "note", 'hex"6869"', "Dynamic bytes stored in Profile."),
            ("struct field", "uint256[]", "tags", "[1, 2, 3]", "Dynamic array stored inside Profile."),
            ("parameter", "address", "user_", "0xAlice", "Outer mapping key."),
            ("parameter", "uint256", "score_", "22", "Number written into the struct and nested mapping."),
            ("parameter", "Status", "status_", "Status.Done", "Enum supplied to the update."),
            ("parameter", "bytes calldata", "note_", 'hex"6869"', "Read-only raw bytes input."),
            ("parameter", "bytes32", "id_", 'bytes32("A")', "Inner mapping key."),
            ("parameter", "uint256[] calldata", "tags_", "[1, 2, 3]", "Dynamic array input."),
            ("local", "Profile storage", "profile", "profiles[user_]", "Storage reference; field writes persist."),
        ],
        "flow": [
            "user_ is the address key for profiles[user_].",
            "The lookup returns a Profile storage reference, so profile.* writes the stored record.",
            "status_ becomes the enum field and note_ becomes the raw bytes field.",
            "tags_ replaces the Profile's dynamic array.",
            "balances[user_][id_] performs an outer and inner mapping lookup before storing score_.",
            "users.push(user_) grows the dynamic array; fixedUsers stays exactly length 3.",
        ],
        "call": 'update(alice, 22, Status.Done, hex"6869", bytes32("A"), [1, 2, 3]);',
    },
    {
        "keys": {"mapping", "keccak256", "abi.encode"},
        "title": "Encode → hash → mapping key",
        "story": "Two typed values become bytes with ABI encoding, become a bytes32 hash with keccak256, and that hash becomes a mapping key.",
        "code": """mapping(bytes32 => address) public owners;

function register(address user_, uint256 amount_)
    external
    returns (bytes32 id)
{
    bytes memory encoded = abi.encode(user_, amount_);
    id = keccak256(encoded);
    owners[id] = user_;
}""",
        "variables": [
            ("state", "mapping(bytes32 => address)", "owners", "owners[id]", "bytes32 key maps to an address value."),
            ("parameter", "address", "user_", "0xAlice", "First encoded value and stored mapping value."),
            ("parameter", "uint256", "amount_", "100", "Second encoded value."),
            ("local", "bytes memory", "encoded", "abi.encode(user_, amount_)", "ABI-encoded representation."),
            ("return", "bytes32", "id", "keccak256(encoded)", "Hash used as the mapping key."),
        ],
        "flow": [
            "user_ and amount_ are normal typed Solidity values.",
            "abi.encode turns them into bytes.",
            "keccak256 turns those bytes into a bytes32 hash.",
            "owners[id] uses that bytes32 as the mapping key.",
        ],
        "call": "register(alice, 100);",
    },
    {
        "keys": {"mapping", "nested-mapping", "keccak256", "abi.encode"},
        "title": "Nested mapping storage uses two hashes",
        "story": "A nested mapping performs two logical lookups. At storage level, each lookup derives another slot with keccak256.",
        "code": """mapping(address => mapping(bytes32 => uint256)) public balances;

function set(address user_, bytes32 id_, uint256 amount_) external {
    balances[user_][id_] = amount_;
}

// Conceptually:
// outer = keccak256(abi.encode(user_, balances.slot))
// inner = keccak256(abi.encode(id_, outer))""",
        "variables": [
            ("state", "mapping(address => mapping(bytes32 => uint256))", "balances", "balances[user_][id_]", "Two keys reach one uint256 value."),
            ("parameter", "address", "user_", "0xAlice", "Outer key."),
            ("parameter", "bytes32", "id_", 'bytes32("A")', "Inner key."),
            ("parameter", "uint256", "amount_", "100", "Stored value."),
            ("derived", "bytes32", "outer", "keccak256(...)", "Derived outer slot."),
            ("derived", "bytes32", "inner", "keccak256(...)", "Derived final slot."),
        ],
        "flow": [
            "balances[user_][id_] hides two storage-slot derivations.",
            "The first hash combines the outer key with the mapping's anchor slot.",
            "The second hash combines id_ with the derived outer slot.",
            "The final location is where the uint256 value lives.",
        ],
        "call": 'set(alice, bytes32("A"), 100);',
    },
    {
        "keys": {"receive", "fallback", "mapping", "msg.sender", "msg.value", "call"},
        "title": "ETH enters → accounting → withdrawal",
        "story": "receive/fallback route ETH in. msg.sender identifies the caller and msg.value carries the amount. A mapping records credit and call sends ETH back out.",
        "code": """mapping(address => uint256) public credit;

receive() external payable {
    credit[msg.sender] += msg.value;
}

function withdraw(uint256 amount_) external {
    credit[msg.sender] -= amount_;

    (bool ok, ) =
        payable(msg.sender).call{value: amount_}("");
    require(ok);
}""",
        "variables": [
            ("state", "mapping(address => uint256)", "credit", "credit[msg.sender]", "Per-address ETH accounting."),
            ("global", "address", "msg.sender", "0xAlice", "Current caller."),
            ("global", "uint256", "msg.value", "1 ether", "ETH attached to the current call."),
            ("parameter", "uint256", "amount_", "0.5 ether", "Withdrawal amount."),
            ("local", "bool", "ok", "true", "Low-level call success flag."),
        ],
        "flow": [
            "Alice sends 1 ETH with empty calldata, so receive() runs.",
            "credit[Alice] increases by msg.value.",
            "Alice calls withdraw(0.5 ether).",
            "The mapping is reduced before call sends 0.5 ETH to Alice.",
        ],
        "call": "1 ETH in → credit[alice] = 1 ETH → withdraw(0.5 ETH) → 0.5 ETH out",
    },
    {
        "keys": {"yul", "mapping", "keccak256", "storage"},
        "title": "Yul exposes a mapping's storage slot",
        "story": "Solidity hides mapping slot arithmetic. Yul can build the same hashes manually, then read the final slot with sload.",
        "code": """mapping(address => mapping(bytes32 => uint256)) public balances;

function read(address user_, bytes32 id_)
    external
    view
    returns (uint256 result)
{
    assembly {
        mstore(0x00, user_)
        mstore(0x20, balances.slot)
        let outer := keccak256(0x00, 0x40)

        mstore(0x00, id_)
        mstore(0x20, outer)
        let inner := keccak256(0x00, 0x40)

        result := sload(inner)
    }
}""",
        "variables": [
            ("state", "nested mapping", "balances", "balances[user_][id_]", "Solidity state being inspected."),
            ("parameter", "address", "user_", "0xAlice", "Outer key."),
            ("parameter", "bytes32", "id_", 'bytes32("A")', "Inner key."),
            ("Yul local", "word", "outer", "keccak256(...)", "Derived outer slot."),
            ("Yul local", "word", "inner", "keccak256(...)", "Derived final slot."),
            ("return", "uint256", "result", "sload(inner)", "Word read directly from storage."),
        ],
        "flow": [
            "mstore places the key and slot into memory.",
            "keccak256 derives the outer slot.",
            "The second key is hashed with the outer slot.",
            "sload reads the final mapping value.",
        ],
        "call": 'read(alice, bytes32("A"));',
    },
]


def find_micro_scene(names):
    requested = frozenset(canonicalize(name) for name in names)
    exact = [scene for scene in MICRO_SCENES if scene["keys"] == requested]
    if exact:
        return exact[0]
    candidates = [scene for scene in MICRO_SCENES if requested <= scene["keys"]]
    if not candidates:
        return None
    candidates.sort(key=lambda scene: (len(scene["keys"] - requested), len(scene["keys"])))
    return candidates[0]

def canonicalize(name: str) -> str:
    key = _norm(name)
    return _CONCEPT_ALIASES.get(key, key)


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _CONCEPT_ALIASES or key in _COMPOSITE_ALIASES:
        return True
    canonical = canonicalize(key)
    return any(
        canonical in {canonicalize(item) for item in lab["concepts"]}
        for lab in CONNECTION_LABS
    ) or canonical in {"yul", "assembly"} or canonical in set(_CONCEPT_ALIASES.values())


def expand_name(name: str):
    key = _norm(name)
    composite = _COMPOSITE_ALIASES.get(key)
    if composite:
        return set(composite)
    return {canonicalize(key)}


def find_connection(names):
    requested = set()
    for name in names:
        if str(name).strip():
            requested.update(expand_name(name))
    requested = frozenset(requested)
    if len(requested) < 2:
        return None

    candidates = []
    for lab in CONNECTION_LABS:
        concepts = frozenset(canonicalize(item) for item in lab["concepts"])
        if requested <= concepts:
            # Prefer the smallest lab that still contains every requested concept.
            extra = len(concepts - requested)
            candidates.append((extra, len(concepts), lab))

    if not candidates:
        # Do not reject a valid combination merely because no hand-authored
        # shortcut recipe exists. The universal composer can show the concepts
        # together and trace them through a compile-checked contract.
        return UNIVERSAL_CONNECTION_LAB

    candidates.sort(key=lambda item: (item[0], item[1], item[2]["name"]))
    return candidates[0][2]


def list_connections():
    rows = [
        {
            "name": UNIVERSAL_CONNECTION_LAB["name"],
            "aliases": UNIVERSAL_CONNECTION_LAB["aliases"],
            "concepts": ["any recognized Solidity/Yul concept combination"],
            "summary": UNIVERSAL_CONNECTION_LAB["summary"],
        }
    ]
    rows.extend(
        {
            "name": lab["name"],
            "aliases": lab["aliases"],
            "concepts": list(lab["concepts"]),
            "summary": lab["summary"],
        }
        for lab in CONNECTION_LABS
    )
    return rows


# ---------------------------------------------------------------------------
# COMPREHENSIVE CONNECTION GRAPH
# ---------------------------------------------------------------------------
#
# This section is deliberately data-driven.  The earlier shortcut labs remain
# useful for full-code views, but the default connect view is powered by the
# graph + small teaching scenes below.
#
# The graph is based on the Solidity language/reference documentation plus
# recurring patterns in established Solidity codebases (OpenZeppelin, Uniswap,
# Aave, Compound, Solmate) and Foundry testing/script practice.
#
# Design rules:
#   1. Every cataloged concept must participate in the graph.
#   2. Multi-hop connections are first-class (e.g. bytes -> abi.decode ->
#      typed values -> keccak256 -> mapping key).
#   3. Direct pairs are not the only useful connections.
#   4. The renderer should never need the learner to read the universal lab
#      just to understand a small connection.
#   5. Aliases are implementation details and are never shown to the learner.

from solidity_cheat_topics import register_topics as _register_catalog_topics


def _build_catalog_aliases():
    names_by_alias = {}

    def capture(name, aliases, *args, **kwargs):
        names_by_alias.setdefault(_norm(name), set()).add(name)
        for alias in aliases:
            names_by_alias.setdefault(_norm(alias), set()).add(name)

    _register_catalog_topics(capture)

    exact_names = {
        _norm(name)
        for names in names_by_alias.values()
        for name in names
        if _norm(name) == _norm(name)
    }
    result = {}
    ambiguous = set()

    for alias, names in names_by_alias.items():
        if len(names) == 1:
            result[alias] = next(iter(names))
        elif alias in exact_names:
            # An exact topic name always wins over aliases that happen to
            # share the same spelling.
            result[alias] = next(
                name for name in names if _norm(name) == alias
            )
        else:
            ambiguous.add(alias)

    return result, ambiguous


_CATALOG_ALIASES, _AMBIGUOUS_CATALOG_ALIASES = _build_catalog_aliases()

_CATALOG_NAME_TO_MEANING = {}

def _capture_catalog_meanings(name, aliases, category, meaning, *args, **kwargs):
    _CATALOG_NAME_TO_MEANING[name] = meaning

_register_catalog_topics(_capture_catalog_meanings)


# Semantic names deliberately collapse spelling variants that describe one
# underlying idea.  Catalog topics that are genuinely different stay distinct.
_SEMANTIC_ALIASES = {
    "function": "function",
    "functions": "function",
    "function-syntax": "function",
    "function-call": "function",
    "function-calls": "function",
    "function-signature": "function-signature",
    "selector": "function-selector",
    "function-selector": "function-selector",
    "keccak-selectors": "keccak-selectors",
    "keccak": "keccak256",
    "keccak256": "keccak256",
    "hash": "keccak256",
    "abi": "abi.encode",
    "abi-encode": "abi.encode",
    "abi.encode": "abi.encode",
    "encode": "abi.encode",
    "abi-decode": "abi.decode",
    "abi.decode": "abi.decode",
    "encodepacked": "encodePacked",
    "abi-encodepacked": "encodePacked",
    "abi.encodepacked": "encodePacked",
    "abi-encodewithselector": "abi.encodeWithSelector",
    "abi.encodewithselector": "abi.encodeWithSelector",
    "abi-encodewithsignature": "abi.encodeWithSignature",
    "abi.encodewithsignature": "abi.encodeWithSignature",
    "struct": "structs",
    "structs": "structs",
    "array": "arrays",
    "arrays": "arrays",
    "dynamic-array": "arrays",
    "dynamic-arrays": "arrays",
    "fixed-array": "arrays",
    "fixed-arrays": "arrays",
    "static-array": "arrays",
    "static-arrays": "arrays",
    "mapping": "mapping",
    "mappings": "mapping",
    "nested-mappings": "nested-mapping",
    "nested-mapping": "nested-mapping",
    "enum": "enum",
    "enums": "enum",
    "bytes": "bytes",
    "dynamic-bytes": "bytes",
    "strings-bytes": "strings-bytes",
    "bytes32": "bytes32",
    "bytesn": "bytesN",
    "address": "address",
    "addresses": "address",
    "address-payable": "address-payable",
    "payable-address": "address-payable",
    "string": "string",
    "strings": "string",
    "uint": "uint256",
    "uint256": "uint256",
    "uints": "uint256",
    "msg-sender": "msg.sender",
    "msg.sender": "msg.sender",
    "msg-value": "msg.value",
    "msg.value": "msg.value",
    "msg-data": "msg.data",
    "msg.data": "msg.data",
    "msg-sig": "msg.sig",
    "msg.sig": "msg.sig",
    "block-timestamp": "block.timestamp",
    "block.timestamp": "block.timestamp",
    "block-number": "block.number",
    "block.number": "block.number",
    "this-balance": "address(this).balance",
    "address-this-balance": "address(this).balance",
    "contract-balance": "contract-balance",
    "data-locations": "storage-memory-calldata",
    "storage-location": "storage-memory-calldata",
    "assembly": "yul",
    "inline-assembly": "yul",
    "yul-assembly": "yul",
    "for": "for",
    "while": "while",
    "do-while": "do-while",
    "loop": "loops",
    "loops": "loops",
    "access-control": "access-control",
    "ownership": "access-control",
    "modifier": "modifier",
    "modifiers": "modifier",
    "events": "events",
    "event": "events",
    "errors": "errors",
    "error": "errors",
    "call": "call",
    "calls": "call",
    "static-call": "staticcall",
    "delegate-call": "delegatecall",
    "external-call": "external-call",
    "external-calls": "external-call",
    "interface-call": "external-call",
    "transient": "transient-storage",
    "transient-storage": "transient-storage",
    "tload-tstore": "transient-storage",
    "user-defined-value-types": "user-defined-value-types",
    "udvt": "user-defined-value-types",
    "function-types": "function-types",
    "function-type": "function-types",
    "contract-type": "contract-types",
    "contract-types": "contract-types",
    "custom-storage-layout": "custom-storage-layout",
    "event-indexed": "event-indexed",
    "indexed": "event-indexed",
    "storage-slot": "storage-slot",
    "returndata": "returndata",
    "return-data": "returndata",
    "gas": "gas",
    "cheatcodes": "forge-cheatcodes",
    "expectrevert": "vm-expect-revert",
    "expectemit": "vm-expect-emit",
    "cheatcodes": "forge-cheatcodes",
    "expectrevert": "vm-expect-revert",
    "expectemit": "vm-expect-emit",
}


_EXTRA_MEANINGS = {
    "keccak256": "Keccak-256 hashes bytes and returns a bytes32 value.",
    "abi.encode": "ABI-encodes typed values into standard bytes with tuple-compatible encoding.",
    "abi.decode": "ABI-decodes bytes into the Solidity types and order you specify.",
    "encodePacked": "ABI packed encoding produces tightly concatenated bytes; it is useful for some hashing/signature workflows but needs collision care.",
    "abi.encodeWithSelector": "Builds calldata by putting a 4-byte function selector in front of ABI-encoded arguments.",
    "abi.encodeWithSignature": "Builds calldata from a textual function signature by hashing it to the selector and encoding its arguments.",
    "function-selector": "The first four bytes of the Keccak-256 hash of the canonical external function signature.",
    "function": "A named callable unit with parameters, visibility, mutability, a body, and optional return values.",
    "mapping": "A key -> value lookup table.",
    "structs": "A struct groups named fields; each field has a type and an actual value.",
    "arrays": "An ordered list; dynamic arrays can grow while fixed arrays have a fixed length.",
    "enum": "A fixed set of named states.",
    "bytes": "A dynamic byte sequence.",
    "bytesN": "A fixed-length byte value such as bytes32 or bytes4.",
    "address": "An EVM account/contract address; payable is the ETH-receiving form.",
    "string": "A dynamic UTF-8 text value.",
    "uint256": "An unsigned 256-bit integer.",
    "storage-memory-calldata": "Reference data can live in persistent storage, temporary memory, or read-only calldata.",
    "imports": "Bring declarations from another Solidity source file into the current source unit.",
    "inheritance": "Compose contracts through base/derived relationships.",
    "interface": "A typed list of callable functions another contract can expose.",
    "modifier": "A reusable wrapper that runs around a function or modifier body.",
    "address-payable": "An address value that is explicitly permitted to receive Ether through address members such as call/transfer/send.",
    "msg.sender": "The immediate caller of the current call frame.",
    "msg.value": "The amount of Wei attached to the current call frame.",
    "msg.data": "The complete calldata bytes for the current call frame.",
    "msg.sig": "The first four bytes of msg.data for normal Solidity message calls.",
    "block.timestamp": "The timestamp supplied by the current block header.",
    "block.number": "The number of the current block.",
    "address(this).balance": "The Ether balance currently held by this contract address; it is not the same thing as msg.value.",
    "contract-types": "Every contract declaration introduces its own Solidity contract type, which can be converted to/from address in allowed cases.",
    "function-types": "Function values can be stored and passed; external function values encode an address plus a 4-byte selector.",
    "user-defined-value-types": "A zero-cost wrapper around an elementary value type with stricter type separation.",
    "transient-storage": "EIP-1153 transient state lasts for the transaction and uses a separate transient storage layout from normal storage.",
    "custom-storage-layout": "Compiler-supported control over the base used when assigning static storage slots.",
    "event-indexed": "An indexed event argument is placed in log topics; complex/dynamic indexed values are represented by a Keccak-derived hash.",
    "storage-slot": "A numbered 32-byte storage location used by the EVM and exposed to Solidity through storage-layout reasoning and Yul.",
    "returndata": "Bytes returned by the most recent external call and exposed at the EVM/Yul level.",
    "gas": "The execution budget/cost unit that bounds how much computation a call can perform.",
}


def canonicalize(name: str) -> str:
    key = _norm(name)
    if key in _SEMANTIC_ALIASES:
        return _SEMANTIC_ALIASES[key]
    if key in _AMBIGUOUS_CATALOG_ALIASES:
        return key
    catalog_name = _CATALOG_ALIASES.get(key)
    if catalog_name:
        catalog_key = _norm(catalog_name)
        return _SEMANTIC_ALIASES.get(catalog_key, catalog_name)
    return key


_EXTRA_CONCEPTS = set(_EXTRA_MEANINGS) | {
    "function-selector",
    "abi.encodeWithSelector",
    "abi.encodeWithSignature",
    "address-payable",
    "msg.sender",
    "msg.value",
    "msg.data",
    "msg.sig",
    "block.timestamp",
    "block.number",
    "address(this).balance",
    "contract-types",
    "function-types",
    "user-defined-value-types",
    "transient-storage",
    "custom-storage-layout",
    "event-indexed",
    "storage-slot",
    "returndata",
    "gas",
    "string",
    "uint256",
}


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _EXTRA_CONCEPTS or key in _SEMANTIC_ALIASES:
        return True
    if key in _AMBIGUOUS_CATALOG_ALIASES:
        return False
    if key in _CATALOG_ALIASES:
        return True
    canonical = canonicalize(key)
    if canonical in _EXTRA_CONCEPTS:
        return True
    if canonical in _COMPOSITE_ALIASES:
        return True
    return False


def expand_name(name: str):
    key = _norm(name)
    composite = _COMPOSITE_ALIASES.get(key)
    if composite:
        return {canonicalize(item) for item in composite}
    return {canonicalize(name)}


# Additional user-friendly composites.  These describe a learning path rather
# than introducing another Solidity feature.
_COMPREHENSIVE_COMPOSITES = {
    "data-locations": {"storage-memory-calldata"},
    "abi-path": {"abi.encode", "abi.decode", "function-selector", "calldata"},
    "function-call-data": {"function", "function-signature", "function-selector", "calldata"},
    "mapping-key": {"mapping", "keccak256", "abi.encode"},
    "mapping-slot-path": {"mapping", "mapping-slots", "keccak256", "storage"},
    "external-call-anatomy": {"interface", "address", "function", "calldata", "abi.encode", "abi.decode"},
    "eth-entrypoints": {"receive", "fallback", "payable", "msg.value", "msg.data"},
    "call-flavors": {"call", "staticcall", "delegatecall"},
    "storage-fundamentals": {"storage", "storage-layout", "mapping-slots", "array-storage"},
    "test-context": {"test", "vm-prank", "vm-deal", "vm-warp"},
    "script-deploy-flow": {"script", "script-deploy", "script-broadcast", "new", "constructor"},
    "poc-cross-contract-flow": {"poc-cross-contract", "interface", "external-call", "try-catch"},
}

_COMPREHENSIVE_COMPOSITES.update({
    _norm(k): v for k, v in _COMPREHENSIVE_COMPOSITES.items()
})
_COMPREHENSIVE_COMPOSITES.update(_COMPOSITE_ALIASES)


# --- Relationship helpers ---------------------------------------------------

_CONNECTION_HUBS = {
    "variables": [
        ("types", "variables declare a type before their name"),
        ("mapping", "a mapping is a state variable that indexes values by keys"),
        ("arrays", "arrays can be stored in state variables or used as reference values"),
        ("structs", "structs introduce named record-shaped values"),
        ("enum", "enums introduce named finite states"),
        ("storage-memory-calldata", "reference variables require a data location"),
        ("mapping-defaults", "fresh mapping keys read the value type's default"),
        ("delete", "delete writes a type's default value"),
        ("assignment", "assignments place a new value/reference into a variable"),
    ],
    "types": [
        ("variables", "every variable has a static type"),
        ("mapping", "mapping keys/values are typed"),
        ("arrays", "array elements are typed"),
        ("structs", "struct fields are typed"),
        ("enum", "enum is a user-defined type"),
        ("address", "address is a value type"),
        ("bytesN", "fixed bytes are value types"),
        ("strings-bytes", "string/bytes are dynamic reference-style data"),
        ("storage-memory-calldata", "reference types use explicit data locations"),
        ("user-defined-value-types", "UDVTs wrap elementary value types"),
        ("function-types", "function values have function types"),
        ("contract-types", "contracts introduce contract-specific types"),
    ],
    "function": [
        ("visibility", "visibility controls who can call/access the function"),
        ("mutability", "mutability describes state and Ether permissions"),
        ("parameter-vs-argument", "definitions contain parameters; call sites supply arguments"),
        ("returns", "functions can expose return values"),
        ("calldata", "external reference-type parameters commonly live in calldata"),
        ("storage-memory-calldata", "reference-type inputs/locals use data locations"),
        ("function-signature", "parameter types form the external function signature"),
        ("function-selector", "the selector is derived from the canonical signature"),
        ("calls", "functions can be invoked across a contract boundary"),
        ("this-call", "this.f() turns a same-contract-looking call into an external call"),
        ("modifiers", "modifiers wrap function execution"),
        ("events", "state-changing functions commonly emit events"),
        ("errors", "functions can revert with custom errors"),
        ("try-catch", "external function calls can be wrapped in try/catch"),
    ],
    "visibility": [
        ("inheritance", "visibility interacts with inherited member access"),
        ("interface", "external/public functions form interface surfaces"),
        ("this-call", "private/internal functions cannot be called through external message dispatch"),
    ],
    "mutability": [
        ("payable", "payable allows Ether to be attached"),
        ("ether-flow", "mutability determines whether a function can receive/send Ether"),
        ("staticcall", "staticcall enforces a no-state-change external call"),
        ("calls", "external call behavior depends on the callee's mutability"),
        ("constructor", "constructors have deployment-specific call context"),
    ],
    "parameter-vs-argument": [
        ("function-signature", "parameter types participate in the canonical signature"),
        ("abi.encode", "arguments are encoded into ABI bytes for low-level calls"),
        ("calldata", "external arguments are carried in calldata"),
        ("new", "constructor arguments are supplied at contract creation"),
    ],
    "returns": [
        ("abi.decode", "raw return bytes can be decoded into expected return types"),
        ("returndata", "low-level calls expose returned bytes"),
        ("calls", "external calls can consume return values"),
        ("try-catch", "success branches can bind decoded return values"),
    ],
    "mapping": [
        ("nested-mapping", "a mapping value may itself be a mapping"),
        ("mapping-struct", "a mapping can store a struct value"),
        ("mapping-array-value", "a mapping can return an array value"),
        ("arrays-mappings", "arrays can coexist with mappings or appear as mapping values"),
        ("arrays-structs", "structs can contain arrays and mappings can store structs"),
        ("mapping-defaults", "unassigned keys read the value type's default"),
        ("mapping-slots", "storage lookup positions are derived from the mapping slot and key"),
        ("nested-mapping-slots", "nested mappings apply slot derivation recursively"),
        ("keccak256", "mapping storage lookup uses Keccak-256"),
        ("storage", "mappings are storage-only state structures"),
        ("msg.sender", "caller addresses are commonly used as keys"),
        ("bytes32", "hashes/IDs are common mapping keys"),
        ("arrays", "mapping values may be dynamic/fixed arrays"),
        ("structs", "mapping values may be structs"),
    ],
    "nested-mapping": [
        ("mapping-slots", "the first mapping lookup derives an intermediate storage slot"),
        ("nested-mapping-slots", "the second key derives the final location"),
        ("keccak256", "each mapping level uses Keccak-256 at the storage level"),
        ("bytes32", "derived slots are 32-byte words"),
        ("yul-storage", "Yul can reproduce the slot math"),
    ],
    "arrays": [
        ("loops", "loops commonly traverse arrays"),
        ("for", "counted loops are common for array iteration"),
        ("while", "conditional loops can traverse arrays"),
        ("do-while", "do-while guarantees one body execution"),
        ("array-storage", "dynamic arrays have hashed storage data locations"),
        ("storage-memory-calldata", "arrays use data locations"),
        ("mapping", "arrays can be mapping values"),
        ("structs", "struct fields may contain arrays"),
        ("calldata-slices", "dynamic calldata arrays/bytes can be sliced where supported"),
        ("gas", "unbounded loops over growing arrays can hit gas limits"),
    ],
    "structs": [
        ("mapping", "structs are common mapping values"),
        ("arrays", "structs can contain arrays"),
        ("enum", "structs can store enum state"),
        ("bytes", "struct fields can hold dynamic bytes"),
        ("bytes32", "structs commonly carry fixed IDs"),
        ("address", "struct fields often identify accounts"),
        ("storage-memory-calldata", "struct references depend on data location"),
        ("mapping-slots", "struct members stored under mappings are reached from derived slots"),
    ],
    "enum": [
        ("mapping", "an enum can be the mapping value type"),
        ("structs", "structs often encode state machines with enums"),
        ("access-control", "roles are often encoded as enum or bytes32 states"),
        ("events", "state transitions can be emitted as enum values"),
        ("abi.decode", "enum ABI representation is an integer type"),
        ("types", "enum is a user-defined type"),
    ],
    "bytes": [
        ("abi.encode", "ABI encoding produces bytes"),
        ("abi.decode", "ABI decoding consumes bytes"),
        ("keccak256", "hash functions consume bytes"),
        ("calldata", "calldata is raw bytes at the ABI boundary"),
        ("calldata-slices", "bytes calldata can be sliced"),
        ("low-level-call", "low-level calls accept bytes calldata"),
        ("returndata", "low-level calls return bytes"),
        ("strings-bytes", "string and bytes are both dynamic byte-like types"),
        ("bytes32", "fixed-size bytes32 is a common compact representation"),
        ("yul-memory", "Yul reads/writes dynamic byte arrays through memory"),
    ],
    "bytes32": [
        ("keccak256", "Keccak-256 returns bytes32"),
        ("mapping", "bytes32 is a common mapping key"),
        ("function-selector", "selectors are the leading four bytes of a hash"),
        ("signature-verification", "digests and identifiers are frequently bytes32"),
        ("events", "non-anonymous event selectors and hashed indexed values use bytes32 topics"),
        ("abi.encode", "typed values can be encoded before producing a bytes32 digest"),
        ("storage-slot", "storage calculations produce 32-byte slots"),
    ],
    "address": [
        ("msg.sender", "msg.sender has address type"),
        ("address-payable", "payable(address) produces an Ether-sending address"),
        ("contract-types", "contract values can be converted to addresses"),
        ("interface", "interfaces attach callable behavior to contract addresses"),
        ("calls", "addresses can be called externally"),
        ("delegatecall", "delegatecall targets an address"),
        ("contract-balance", "addresses expose a balance member"),
        ("mapping", "addresses commonly index account state"),
        ("signature-verification", "signature recovery identifies an address"),
        ("new", "new returns a fresh contract address"),
    ],
    "storage-memory-calldata": [
        ("storage", "persistent state uses storage"),
        ("memory", "temporary mutable reference data uses memory"),
        ("calldata", "external read-only input uses calldata"),
        ("arrays", "arrays need a data location when they are reference values"),
        ("structs", "struct references need a data location"),
        ("bytes", "dynamic bytes need a data location"),
        ("abi.decode", "decoded dynamic values can be allocated into memory"),
    ],
    "constructor": [
        ("imports", "constructors can belong to imported base contracts"),
        ("inheritance", "child constructors can initialize base constructors"),
        ("override", "construction initializes state before overridden behavior is callable"),
        ("new", "new invokes a constructor"),
        ("msg.sender", "the deployer is msg.sender during construction"),
        ("address", "constructor inputs commonly include owner/target addresses"),
        ("string", "constructors commonly initialize names/symbols"),
        ("uint256", "constructors commonly initialize numeric limits"),
        ("constant-immutable", "immutable state can be assigned during construction"),
    ],
    "modifiers": [
        ("function", "modifiers wrap function bodies"),
        ("access-control", "modifiers commonly implement authorization"),
        ("msg.sender", "access checks often inspect caller identity"),
        ("require", "modifiers commonly guard with require"),
        ("custom-errors", "modifiers can revert with custom errors"),
        ("inheritance", "modifiers are inheritable"),
        ("override-virtual", "virtual modifiers/functions can be overridden"),
    ],
    "inheritance": [
        ("imports", "bases are normally made available through imports"),
        ("abstract", "abstract contracts are designed to be inherited"),
        ("interface", "contracts can inherit interfaces as required callable shapes"),
        ("override", "derived members override inherited virtual members"),
        ("virtual", "virtual permits overriding"),
        ("constructor", "base and child constructors chain during deployment"),
        ("storage-layout", "inheritance affects storage variable ordering"),
        ("modifier", "modifiers can be inherited"),
    ],
    "override-virtual": [
        ("inheritance", "overrides happen through inheritance"),
        ("interface", "interface implementations use override"),
        ("function", "functions are the main overridden member"),
        ("modifiers", "modifiers can also be overridden when virtual"),
    ],
    "interface": [
        ("address", "an interface reference is backed by a contract address"),
        ("function", "interfaces describe callable functions"),
        ("external-call", "calling an interface crosses a contract boundary"),
        ("calldata", "external ABI arguments live in calldata"),
        ("abi.decode", "returned bytes are decoded into interface function return types"),
        ("try-catch", "interface calls can be wrapped by try/catch"),
        ("oracle", "oracle integrations commonly use interfaces"),
        ("poc-cross-contract", "cross-contract PoCs often start from an interface"),
    ],
    "interface-vs-abstract": [
        ("interface", "interfaces expose callable shapes without implementation state"),
        ("abstract", "abstract contracts can provide reusable implementation/state"),
        ("inheritance", "both participate in inheritance"),
        ("override", "interfaces/abstract bases lead to override requirements"),
    ],
    "library": [
        ("using-for", "using-for attaches library functions to a type"),
        ("imports", "libraries are imported source declarations"),
        ("function", "library helpers are callable functions"),
        ("yul", "libraries commonly hide low-level assembly helpers"),
        ("new", "libraries are not instantiated with new in normal use"),
    ],
    "events": [
        ("function", "state transitions commonly emit events"),
        ("event-indexed", "indexed arguments are stored as topics"),
        ("keccak256", "an event selector is derived from its signature"),
        ("bytes32", "topics are 32-byte words"),
        ("mapping", "events often reveal mapping/state changes to off-chain observers"),
        ("errors", "events and errors are different reporting paths"),
        ("vm-expect-emit", "Foundry can assert emitted events"),
        ("vm-recordlogs", "Foundry can capture logs"),
    ],
    "receive": [
        ("fallback", "fallback is the alternate routing path for unmatched calls"),
        ("payable", "receive must be payable"),
        ("msg.sender", "receive sees the caller"),
        ("msg.value", "receive sees attached Ether"),
        ("contract-balance", "received Ether increases the contract balance"),
        ("ether-flow", "receive is an Ether entry point"),
    ],
    "fallback": [
        ("receive", "receive handles plain empty-calldata Ether transfers when present"),
        ("msg.data", "fallback can inspect raw calldata"),
        ("msg.sig", "fallback can inspect the selector in calldata"),
        ("function-selector", "fallback dispatch can decode/select on the first four bytes"),
        ("calldata", "fallback receives calldata"),
        ("delegatecall", "proxy fallback commonly forwards with delegatecall"),
        ("proxy-fallback", "proxies use fallback as their dispatch boundary"),
        ("payable", "payable fallback can receive Ether"),
    ],
    "calls": [
        ("interface", "typed calls use interface/contract references"),
        ("address", "addresses can be called"),
        ("low-level-call", "low-level call exposes raw bytes"),
        ("staticcall", "staticcall is a read-only call flavor"),
        ("delegatecall", "delegatecall is another call flavor"),
        ("try-catch", "external call failures can be caught"),
        ("returndata", "low-level calls expose returned bytes"),
        ("reentrancy", "external calls create reentrancy boundaries"),
    ],
    "this-call": [
        ("function", "this.f() targets a function through external dispatch"),
        ("calls", "this.f() is an external message call"),
        ("msg.sender", "the callee sees the calling contract as msg.sender"),
        ("constructor", "this-call cannot be used before deployment finishes"),
    ],
    "low-level-call": [
        ("abi.encode", "call arguments are usually ABI-encoded bytes"),
        ("function-selector", "calldata normally begins with a selector"),
        ("calldata", "call consumes calldata bytes"),
        ("returndata", "call exposes returned bytes"),
        ("require", "the success bool should be handled explicitly"),
        ("try-catch", "typed external calls offer another failure-handling style"),
        ("reentrancy", "a low-level call can hand control to arbitrary code"),
        ("address-payable", "call with value requires an Ether-capable address"),
    ],
    "staticcall": [
        ("calls", "staticcall is one flavor of external call"),
        ("low-level-call", "it has raw bytes input and return data too"),
        ("mutability", "staticcall is constrained from modifying state"),
        ("interface", "typed view interfaces map to the same external boundary"),
        ("returndata", "staticcall returns raw bytes"),
    ],
    "delegatecall": [
        ("proxy-fallback", "proxy fallback commonly delegates to implementation code"),
        ("fallback", "fallback is a frequent delegatecall entry point"),
        ("storage-layout", "delegatecall uses the caller's storage"),
        ("msg.sender", "delegatecall preserves the external caller as msg.sender"),
        ("msg.value", "delegatecall preserves msg.value"),
        ("address", "delegatecall targets another address"),
        ("library", "libraries historically motivate delegatecall-style code reuse"),
        ("reentrancy", "delegated code can alter caller state and control flow"),
    ],
    "msg-block-tx": [
        ("msg.sender", "caller identity is part of message context"),
        ("msg.value", "attached Ether is part of message context"),
        ("msg.data", "calldata is part of message context"),
        ("msg.sig", "selector is derived from message data"),
        ("block.timestamp", "timestamp is block context"),
        ("block.number", "block number is block context"),
        ("tx-origin", "transaction origin is a different context identity"),
    ],
    "msg.value-vs-balance": [
        ("msg.value", "msg.value is only the current call's attached Ether"),
        ("contract-balance", "address(this).balance is the contract's total current balance"),
        ("receive", "receive reads msg.value"),
        ("payable", "Ether must enter through a payable path or other EVM mechanisms"),
        ("ether-flow", "accounting often compares current inflow with total held balance"),
    ],
    "ether-flow": [
        ("receive", "receive is a direct Ether entry point"),
        ("fallback", "payable fallback can also receive Ether"),
        ("payable", "payable permits attached Ether"),
        ("msg.value", "msg.value carries the current amount"),
        ("contract-balance", "balance reports total Ether held now"),
        ("mapping", "manual credits are often stored per address in a mapping"),
        ("call", "call is the modern general Ether transfer primitive"),
        ("checks-effects-interactions", "state changes are commonly placed before Ether calls"),
        ("reentrancy", "Ether calls can trigger arbitrary receiver code"),
    ],
    "abi.encode": [
        ("abi.decode", "decode is the inverse interpretation of ABI bytes"),
        ("bytes", "encode returns bytes"),
        ("keccak256", "encoded bytes are a common hash input"),
        ("function-selector", "encoded arguments follow the function selector in calldata"),
        ("calldata", "ABI bytes can become a complete calldata payload"),
        ("low-level-call", "raw call APIs consume encoded bytes"),
        ("signature-verification", "signing schemes encode structured values before hashing"),
        ("mapping-slots", "storage-slot derivation is often expressed with abi.encode in Solidity/Yul explanations"),
    ],
    "abi.decode": [
        ("bytes", "decode consumes raw bytes"),
        ("calldata", "bytes calldata can be decoded directly"),
        ("abi.encode", "encode/decode form a reversible ABI pair"),
        ("function-selector", "decode often starts after consuming a selector"),
        ("low-level-call", "return bytes from low-level calls can be decoded"),
        ("try-catch", "typed return decoding happens around external calls"),
        ("mapping", "decoded keys/values can feed mapping lookups"),
        ("keccak256", "decoded values can be re-encoded and hashed"),
    ],
    "encodePacked": [
        ("keccak256", "packed bytes are commonly hashed"),
        ("signature-verification", "packed encoding appears in some message-digest schemes"),
        ("bytes", "it produces bytes"),
        ("front-running", "hash commitments can depend on exact packed inputs"),
        ("abi.encode", "packed encoding differs from standard ABI encoding"),
    ],
    "function-signature": [
        ("function", "it describes the external callable declaration"),
        ("function-selector", "selector is derived from the canonical signature"),
        ("abi.encode", "arguments follow selector encoding in calldata"),
        ("calldata", "normal function calldata starts with the selector"),
        ("calls", "overload/call resolution chooses a callable signature"),
        ("keccak256", "the selector uses a Keccak-256 digest"),
    ],
    "calldata": [
        ("function-signature", "the first four bytes normally identify a function"),
        ("function-selector", "selector is the first four bytes of normal calldata"),
        ("abi.decode", "raw calldata can be decoded"),
        ("low-level-call", "raw call input is calldata bytes"),
        ("fallback", "fallback receives unmatched calldata"),
        ("storage-memory-calldata", "calldata is one of Solidity's reference data locations"),
        ("calldata-slices", "bytes calldata can be sliced"),
        ("msg.data", "msg.data is the full calldata for the current call"),
        ("front-running", "public transaction input can be observed before execution"),
        ("yul-calldata", "Yul can load calldata directly"),
    ],
    "calldata-slices": [
        ("calldata", "a slice is taken from calldata"),
        ("bytes", "bytes calldata is the common slice target"),
        ("function-selector", "slicing [:4] is a common selector extraction"),
        ("abi.decode", "slicing payload[4:] can remove a selector before decoding arguments"),
        ("fallback", "fallback code often slices raw input"),
        ("yul-calldata", "Yul can reproduce offsets manually"),
    ],
    "storage-layout": [
        ("storage-packing", "small value types may share a slot"),
        ("mapping-slots", "mappings reserve anchor slots and derive data locations"),
        ("nested-mapping-slots", "nested mappings apply the rule recursively"),
        ("array-storage", "dynamic arrays use hashed data locations"),
        ("inheritance", "linearized base order affects variable placement"),
        ("delegatecall", "delegated code shares the caller's storage"),
        ("constant-immutable", "constant/immutable do not occupy ordinary storage slots"),
        ("transient-storage", "transient storage has an independent layout"),
        ("custom-storage-layout", "custom layout can shift static base slots"),
        ("yul-storage", "Yul is the low-level lens on storage layout"),
    ],
    "mapping-slots": [
        ("mapping", "the language-level mapping lookup becomes a hashed storage lookup"),
        ("keccak256", "the storage derivation is Keccak-based"),
        ("storage-layout", "the mapping anchor comes from the storage layout"),
        ("nested-mapping-slots", "nested mappings derive another slot from the prior one"),
        ("yul-storage", "assembly can recreate the formula"),
        ("abi.encode", "Solidity examples commonly express the derivation with ABI encoding"),
        ("bytes32", "the derived slot is a 32-byte word"),
    ],
    "nested-mapping-slots": [
        ("nested-mapping", "it is the low-level storage view of nested mappings"),
        ("mapping-slots", "each mapping level derives another location"),
        ("keccak256", "each key/slot combination uses Keccak"),
        ("yul-storage", "Yul can sload/sstore the final derived slot"),
        ("storage-layout", "the initial mapping slot comes from layout"),
    ],
    "array-storage": [
        ("arrays", "dynamic arrays are reference values with hashed data regions"),
        ("storage-layout", "the array's anchor slot comes from layout"),
        ("keccak256", "dynamic array element regions begin from a hash-derived location"),
        ("storage-packing", "small array elements can share slots"),
        ("mapping-array-value", "mapping values can be dynamic arrays"),
        ("yul-storage", "Yul can compute array data locations"),
    ],
    "storage-packing": [
        ("storage-layout", "packing is one part of slot assignment"),
        ("types", "type widths determine whether values fit together"),
        ("structs", "struct members can pack together"),
        ("arrays", "array elements can pack when their element types are small"),
        ("inheritance", "base/derived state can share slots under layout rules"),
        ("yul-storage", "partial-slot writes require masking/combining logic at low level"),
    ],
    "delete": [
        ("storage", "delete resets persistent storage to a type's default"),
        ("mapping-defaults", "the deleted result is the same default a fresh key reads"),
        ("arrays", "delete can reset array elements/whole arrays"),
        ("structs", "delete can reset a stored struct"),
        ("variables", "delete operates on a variable/value"),
    ],
    "try-catch": [
        ("calls", "try/catch targets external calls or contract creation"),
        ("interface", "typed external interface calls are a common use"),
        ("new", "contract creation can also be wrapped"),
        ("errors", "catch clauses can inspect Error/Panic/low-level failure"),
        ("abi.decode", "return-data decoding interacts with catch semantics"),
        ("returndata", "raw returned/reverted bytes are part of failure handling"),
    ],
    "require": [
        ("revert", "require is a convenient conditional revert"),
        ("custom-errors", "custom errors are a typed alternative to revert strings"),
        ("mapping", "authorization/balance checks often inspect mappings"),
        ("msg.sender", "guards commonly inspect caller identity"),
        ("assert", "assert has a different intended invariant role"),
        ("modifiers", "guards are often factored into modifiers"),
        ("test-reverts", "tests can assert expected reverts"),
    ],
    "revert": [
        ("custom-errors", "revert can carry a custom error"),
        ("require", "require reverts when a condition is false"),
        ("assert", "all revert paths roll back state, but assert signals invariants/panics"),
        ("errors", "revert data identifies the error"),
        ("try-catch", "external revert can be caught"),
        ("abi.decode", "revert payloads have ABI structure"),
        ("returndata", "revert data is part of returned EVM bytes"),
    ],
    "assert": [
        ("errors", "failed assertions surface as Panic-style errors"),
        ("unchecked", "unchecked changes arithmetic checks, not assert semantics"),
        ("require", "assert and require express different intentions"),
        ("invariant-tests", "invariants often correspond to properties checked with assertions"),
    ],
    "custom-errors": [
        ("revert", "custom errors are emitted through revert"),
        ("function-selector", "error selectors are 4-byte Keccak-derived identifiers"),
        ("abi.decode", "error arguments have ABI encoding"),
        ("try-catch", "external errors can be caught/decoded"),
        ("events", "errors are call-failure data, not logs"),
        ("test-reverts", "Foundry can expect exact custom errors"),
    ],
    "if-else": [
        ("loops", "branching often controls loop entry/exit"),
        ("require", "require is conditional failure shorthand"),
        ("ternary", "ternary is the expression form of conditional choice"),
        ("unchecked", "branches can select checked/unchecked arithmetic paths"),
        ("access-control", "authorization commonly branches on caller/role"),
    ],
    "loops": [
        ("for", "for is the counted-loop form"),
        ("while", "while loops until a condition changes"),
        ("do-while", "do-while executes once before testing"),
        ("loop-comparison", "these topics compare loop semantics"),
        ("arrays", "arrays are common loop collections"),
        ("mapping", "some patterns iterate a companion array of mapping keys"),
        ("gas", "unbounded iteration can exceed the block gas limit"),
        ("fuzz-tests", "fuzzing can expose loop edge cases"),
    ],
    "for": [
        ("arrays", "for often indexes arrays"),
        ("mapping", "for can apply updates to mapping entries selected through an array"),
        ("loops", "for is a loop construct"),
        ("fuzz-tests", "fuzzing can explore loop bounds"),
    ],
    "while": [
        ("loops", "while is a conditional loop"),
        ("mapping", "delegation chains commonly walk mapping state"),
        ("do-while", "while differs by whether the first condition is checked before the body"),
        ("gas", "unbounded while loops can become unexecutable"),
    ],
    "do-while": [
        ("loops", "do-while is a loop construct"),
        ("while", "both repeat while a condition holds"),
        ("if-else", "the condition controls repetition"),
    ],
    "ternary": [
        ("if-else", "both express conditional choice"),
        ("variables", "the result of a ternary can initialize/assign a value"),
        ("types", "both branches must fit the expression's type rules"),
        ("mutability", "a ternary can choose a payable/state-changing path's amount/value"),
    ],
    "unchecked": [
        ("uint256", "checked/unchecked arithmetic is most visible on integers"),
        ("loops", "unchecked increments are common in gas-sensitive loops"),
        ("assert", "unchecked arithmetic can still produce invariant failures later"),
        ("storage-packing", "packing and arithmetic may coexist in low-level state updates"),
    ],
    "access-control": [
        ("msg.sender", "authorization begins with caller identity"),
        ("mapping", "roles/owners are frequently stored by address key"),
        ("modifier", "modifiers encapsulate repeated access checks"),
        ("enum", "some simple role systems use enums"),
        ("custom-errors", "unauthorized access often reverts with a custom error"),
        ("events", "role changes should often be observable"),
        ("tx-origin", "tx.origin is a distinct and risky authorization primitive"),
        ("signature-verification", "off-chain authorization can replace direct caller checks"),
    ],
    "tx-origin": [
        ("msg.sender", "tx.origin is the original transaction sender, not the immediate caller"),
        ("access-control", "using tx.origin for authorization creates call-chain hazards"),
        ("this-call", "additional call frames make the distinction visible"),
        ("reentrancy", "call chains matter when analyzing caller identity"),
    ],
    "timestamp": [
        ("block.timestamp", "timestamp topic is represented by the block timestamp global"),
        ("block.number", "both are block-context values"),
        ("front-running", "block time is observable and only loosely constrained"),
        ("vm-warp", "Foundry can manipulate timestamp in tests"),
    ],
    "front-running": [
        ("calldata", "transaction inputs can be observed before inclusion"),
        ("keccak256", "commit-reveal systems commonly hash secret inputs"),
        ("encodePacked", "commitments depend on exact byte encoding"),
        ("signature-verification", "signed intents can mitigate some ordering/authorization issues"),
        ("timestamp", "time-based logic can interact with ordering assumptions"),
    ],
    "signature-verification": [
        ("keccak256", "message digests are normally hashed"),
        ("abi.encode", "structured signed values are encoded"),
        ("bytes", "signatures are byte sequences"),
        ("bytes32", "message digests are commonly bytes32"),
        ("address", "verification ends by checking an address"),
        ("function-selector", "signature-related encodings have selector-like 4-byte components in some protocols"),
        ("nonce", "nonces prevent message replay"),
    ],
    "proxy-fallback": [
        ("fallback", "proxy fallback is the routing boundary"),
        ("delegatecall", "implementation code runs with proxy storage/context"),
        ("storage-layout", "proxy/implementation layouts must be compatible"),
        ("function-selector", "fallback routes based on calldata's selector"),
        ("calldata", "proxy forwards raw calldata"),
        ("returndata", "proxy returns implementation returndata"),
        ("address", "proxy stores/uses an implementation address"),
        ("poc-upgrade", "upgrade PoCs examine implementation/storage assumptions"),
    ],
    "constant-immutable": [
        ("constructor", "immutable values can be assigned only during construction"),
        ("storage-layout", "constants/immutables do not reserve ordinary state slots"),
        ("variables", "both are state declarations"),
        ("type-metadata", "type-level constants/metadata can be read without ordinary state storage"),
    ],
    "using-for": [
        ("library", "using-for attaches library functions to a type"),
        ("types", "the receiver type determines the attached functions"),
        ("function", "the library member is still a function call"),
        ("new", "using-for is a reuse mechanism, not contract creation"),
    ],
    "type-metadata": [
        ("types", "type(T) exposes metadata about a type"),
        ("contract-types", "contract types provide interfaceIds/creationCode/runtimeCode metadata"),
        ("function-types", "function values have type metadata too"),
        ("new", "creationCode is closely related to contract creation"),
    ],
    "external-function-types": [
        ("function-types", "external function values are function types"),
        ("address", "an external function value contains a target address"),
        ("function-selector", "it also contains a 4-byte selector"),
        ("calls", "stored function values can later be invoked"),
    ],
    "new": [
        ("constructor", "new invokes a constructor"),
        ("address", "new returns the created contract address"),
        ("contract-types", "new creates a value of a contract type"),
        ("try-catch", "contract creation can be wrapped in try/catch"),
        ("script-deploy", "scripts commonly deploy with new or deployment helpers"),
    ],
    "contract-balance": [
        ("address", "balance is an address member"),
        ("address(this).balance", "current contract balance is read through address(this).balance"),
        ("msg.value", "current call value is only one inflow component"),
        ("ether-flow", "balance is one side of Ether accounting"),
        ("selfdestruct", "forced Ether transfer can change balance independently of receive"),
    ],
    "payable": [
        ("address-payable", "payable(address) makes Ether transfer explicit"),
        ("receive", "receive must be payable"),
        ("fallback", "fallback must be payable to receive Ether"),
        ("msg.value", "payable calls can carry msg.value"),
        ("call", "call{value: ...} sends Ether"),
        ("ether-flow", "payability controls an Ether boundary"),
    ],
    "symbols": [
        ("variables", "symbols show how variables are declared/accessed"),
        ("function", "symbols encode calls, grouping, and return tuples"),
        ("mapping", "=> and [] appear in mapping declarations/lookups"),
        ("arrays", "[] indexes and declares arrays"),
        ("call", "curly call options such as {value: ...} alter calls"),
        ("unchecked", "unchecked is a special block syntax"),
        ("yul", "assembly { ... } enters Yul"),
    ],
    "comments-natspec": [
        ("function", "NatSpec documents callable behavior"),
        ("events", "event parameters can be documented"),
        ("custom-errors", "errors can be documented"),
        ("interface", "interfaces are especially useful documentation surfaces"),
    ],
    "forge-cheatcodes-map": [
        ("test", "cheatcodes are primarily used from Foundry tests"),
        ("script", "some cheatcodes/context are also used in scripts"),
        ("poc", "PoCs use cheatcodes to control state and callers"),
        ("vm-prank", "caller identity can be changed"),
        ("vm-deal", "ETH balances can be provisioned"),
        ("vm-warp", "block time can be controlled"),
        ("vm-storage", "storage can be inspected/modified"),
        ("vm-expect-revert", "reverts can be asserted"),
        ("vm-expect-emit", "events can be asserted"),
    ],
    "test": [
        ("test-structure", "tests use a predictable contract/function structure"),
        ("test-arrange-act-assert", "tests are often expressed as arrange/act/assert"),
        ("test-assertions", "assertions check observed results"),
        ("fuzz-tests", "fuzzing runs tests over many inputs"),
        ("invariant-tests", "invariants run properties across many state transitions"),
        ("fork-tests", "forks reproduce external chain state"),
        ("test-reverts", "tests can assert failure behavior"),
        ("test-events", "tests can assert emitted logs"),
        ("vm-prank", "tests control msg.sender"),
        ("vm-deal", "tests control balances"),
        ("vm-warp", "tests control block time"),
        ("vm-expect-revert", "tests can expect reverts"),
        ("vm-expect-emit", "tests can expect events"),
    ],
    "script": [
        ("script-structure", "scripts use a predictable execution structure"),
        ("script-env", "scripts often read deployment values from environment variables"),
        ("script-broadcast", "broadcast makes transactions real in the selected environment"),
        ("script-deploy", "deployment scripts create contracts"),
        ("script-interaction", "scripts can call already deployed contracts"),
        ("vm-env", "Foundry VM environment helpers feed scripts"),
    ],
    "poc": [
        ("poc-template", "PoCs start from a reproducible attack/test skeleton"),
        ("poc-reentrancy", "reentrancy is an active exploit pattern"),
        ("poc-access-control", "access control can be directly probed"),
        ("poc-accounting", "accounting properties can be broken and measured"),
        ("poc-storage", "storage calculations can be probed"),
        ("poc-cross-contract", "cross-contract assumptions can be exercised"),
        ("test", "a PoC is often implemented as a Foundry test"),
        ("vm-prank", "PoCs select attacker/victim callers"),
        ("vm-deal", "PoCs provision funds"),
    ],
    "poc-reentrancy": [
        ("reentrancy", "the PoC tries to re-enter before state is safely updated"),
        ("call", "an external call commonly hands control to the attacker"),
        ("receive", "an attack contract may re-enter from receive"),
        ("fallback", "fallback is another callback surface"),
        ("mapping", "reentrancy frequently breaks per-user accounting"),
        ("checks-effects-interactions", "PoCs test whether state is changed before the call"),
    ],
    "poc-access-control": [
        ("access-control", "the PoC probes who can call a privileged action"),
        ("msg.sender", "caller identity is the main variable"),
        ("modifier", "modifier-protected functions are common targets"),
        ("tx-origin", "caller/origin confusion is a classic issue"),
    ],
    "poc-accounting": [
        ("mapping", "accounting is often stored per-user"),
        ("msg.value", "incoming Ether contributes to credits"),
        ("contract-balance", "on-chain balance is the actual held Ether"),
        ("ether-flow", "credits and assets must stay consistent"),
    ],
    "poc-storage": [
        ("storage-layout", "state location is part of the exploit model"),
        ("mapping-slots", "mapping keys become derived slots"),
        ("nested-mapping-slots", "nested mappings derive more slots"),
        ("yul-storage", "Yul can inspect/modify raw slots"),
        ("vm-storage", "Foundry can inspect/modify storage in a test"),
    ],
    "poc-cross-contract": [
        ("interface", "cross-contract calls often start from an interface"),
        ("external-call", "the boundary is a message call"),
        ("try-catch", "failure behavior can be captured"),
        ("abi.encode", "low-level interactions need ABI data"),
        ("returndata", "raw return/error bytes are part of the boundary"),
    ],
}

def _flatten_connection_hubs():
    edges = []
    for left, rows in _CONNECTION_HUBS.items():
        for right, label in rows:
            edges.append((left, right, label))
    return edges


_COMPREHENSIVE_CONNECTION_EDGES = _flatten_connection_hubs()


# Explicit high-value relationships that are tiny but easy to miss.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("yul-not", "yul", "Yul not is a low-level logical/bitwise operation inside Yul expressions"),
    ("yul-not", "yul-iszero", "not and iszero are neighboring Yul unary operations with different semantics"),
    ("mapping", "keccak256", "the mapping key is not stored; Keccak is used to locate its value"),
    ("mapping", "abi.decode", "decoded bytes can produce the key/value that drive a mapping update"),
    ("abi.decode", "keccak256", "the same raw bytes can be decoded and independently hashed"),
    ("abi.encode", "abi.decode", "encoded typed values can later be decoded back to those types"),
    ("function-selector", "abi.encodeWithSelector", "selector + ABI arguments form normal calldata"),
    ("function-signature", "abi.encodeWithSignature", "the textual signature determines the selector"),
    ("events", "function-selector", "event selectors are Keccak-derived 32-byte topics, not 4-byte function selectors"),
    ("events", "event-indexed", "indexed arguments occupy log topics"),
    ("fallback", "msg.sig", "fallback can inspect the selector extracted from raw calldata"),
    ("fallback", "msg.data", "fallback can accept the complete raw payload"),
    ("call", "returndata", "a low-level call returns a success flag and raw return data"),
    ("staticcall", "returndata", "staticcall also returns raw bytes"),
    ("delegatecall", "returndata", "delegated execution can return raw bytes to the proxy"),
    ("try-catch", "custom-errors", "custom error selector/data are part of external failure behavior"),
    ("try-catch", "revert", "caught external failures have already reverted the subcall's state changes"),
    ("this-call", "reentrancy", "external self-calls create a call boundary that can change execution context"),
    ("mapping", "storage-slot", "a mapping is anchored at a storage slot even though its values are elsewhere"),
    ("arrays", "storage-slot", "dynamic arrays reserve an anchor slot for length/location derivation"),
    ("bytes", "storage-layout", "short/long bytes have special storage representation"),
    ("strings-bytes", "storage-layout", "string storage uses the bytes/string encoding rules"),
    ("constant-immutable", "transient-storage", "neither belongs to ordinary transient layout in the same way as normal storage state"),
    ("transient-storage", "yul-storage", "transient storage has low-level tload/tstore operations distinct from sload/sstore"),
    ("transient-storage", "reentrancy", "transient locks are a possible transaction-scoped reentrancy-guard primitive"),
    ("user-defined-value-types", "using-for", "libraries can attach domain-specific operations to UDVTs"),
    ("user-defined-value-types", "abi.encode", "UDVT ABI encoding uses its underlying type"),
    ("external-function-types", "function-selector", "external function values contain a selector"),
    ("external-function-types", "address", "external function values contain a target address"),
    ("contract-types", "interface", "a contract/interface reference identifies a callable contract surface"),
    ("contract-types", "address", "contract values convert to addresses in explicit contexts"),
    ("new", "script-broadcast", "deployment scripts broadcast contract creation transactions"),
    ("script-interaction", "interface", "scripts use typed interfaces to call deployed contracts"),
    ("script-interaction", "abi.encode", "raw calls in scripts still use ABI bytes"),
    ("vm-prank", "msg.sender", "prank changes the caller observed by Solidity"),
    ("vm-start-prank", "msg.sender", "startPrank changes caller context across multiple calls"),
    ("vm-roll", "block.number", "roll changes the block number used by the test EVM"),
    ("yul-memory", "memory", "Yul memory operations operate on Solidity memory layout"),
    ("vm-start-prank", "msg.sender", "startPrank changes caller context across multiple calls"),
    ("vm-hoax", "vm-prank", "hoax combines caller control with funded balance"),
    ("vm-hoax", "vm-deal", "hoax provisions ETH as part of caller setup"),
    ("vm-deal", "contract-balance", "deal changes an address balance directly in a test"),
    ("vm-deal", "msg.value", "deal sets balances; msg.value is attached to a specific call"),
    ("vm-warp", "block.timestamp", "warp changes the timestamp used by the test EVM"),
    ("vm-roll", "block.number", "roll changes the block number used by the test EVM"),
    ("vm-expect-revert", "custom-errors", "tests can match a specific custom error"),
    ("vm-expect-emit", "events", "tests can assert event logs"),
    ("vm-recordlogs", "events", "recordLogs captures emitted logs"),
    ("vm-storage", "storage-layout", "raw slot access is a direct storage-layout exercise"),
    ("vm-etch", "address", "etch changes code at an address in the test EVM"),
    ("vm-etch", "proxy-fallback", "code injection is useful for testing dispatch/proxy assumptions"),
    ("vm-fork", "oracle", "forks reproduce live protocol/oracle state"),
    ("vm-mockcall", "interface", "mockCall supplies return behavior for a contract interface"),
    ("vm-mockcall", "returndata", "mocked return bytes feed the caller"),
    ("vm-expect-call", "calls", "tests can assert that a target was called with expected data"),
    ("vm-expect-call", "abi.encode", "expected call arguments are commonly ABI-encoded"),
    ("vm-assume", "fuzz-tests", "assume constrains fuzz inputs"),
    ("vm-bound", "bounded-fuzz", "bound constrains fuzz values into a range"),
    ("vm-makeaddr", "address", "makeAddr creates deterministic test addresses"),
    ("vm-label", "address", "labels make actor addresses readable in tests"),
    ("vm-snapshots", "test", "snapshots let tests compare state before/after a sequence"),
    ("vm-env", "script-env", "environment helpers feed configuration into scripts"),
    ("forge-cheatcodes-map", "test-poc-workflow", "the cheatcode map is the toolbox used by test/PoC workflows"),
    ("fuzz-tests", "bounded-fuzz", "bounded fuzzing is a constrained fuzzing style"),
    ("fuzz-tests", "vm-assume", "assumptions filter fuzz cases"),
    ("invariant-tests", "invariant-handler", "handlers shape the state-transition surface exercised by invariants"),
    ("invariant-tests", "mapping", "mapping state is a common source of stateful invariants"),
    ("fork-tests", "vm-fork", "fork tests select a chain state snapshot"),
    ("test-reverts", "require", "tests assert conditional reverts"),
    ("test-reverts", "revert", "tests can assert explicit revert behavior"),
    ("test-events", "vm-expect-emit", "event tests use log expectations"),
    ("test-structure", "test-arrange-act-assert", "AAA is applied within the test structure"),
    ("test-assertions", "assert", "assertions check returned/state values"),
    ("poc-token", "interface", "token PoCs interact with ERC-style interfaces"),
    ("poc-token", "mapping", "token balances/allowances are mapping-based"),
    ("poc-token", "calls", "token operations are cross-contract calls"),
    ("poc-oracle", "oracle", "oracle PoCs probe price/data assumptions"),
    ("poc-oracle", "interface", "oracle contracts are commonly accessed by interface"),
    ("poc-signature", "signature-verification", "signature PoCs probe authorization and replay assumptions"),
    ("poc-upgrade", "proxy-fallback", "upgrade PoCs target proxy dispatch and implementation changes"),
    ("poc-dos", "loops", "gas/loop behavior can produce denial of service"),
    ("poc-dos", "arrays", "unbounded storage arrays are a common growth vector"),
    ("poc-accessible-state", "access-control", "the PoC checks whether state can be reached by an unexpected caller"),
    ("poc-accounting", "mapping", "per-user balances are common accounting state"),
    ("poc-reentrancy", "receive", "an attacker can re-enter from receive"),
    ("poc-reentrancy", "fallback", "an attacker can re-enter from fallback"),
    ("poc-storage", "yul", "assembly makes raw storage corruption easier to demonstrate"),
])


def _ensure_graph_coverage(edges):
    """Connect every registered topic to at least one meaningful family anchor."""
    covered = set()
    for left, right, _ in edges:
        covered.add(canonicalize(left))
        covered.add(canonicalize(right))

    generated = list(edges)
    known = set(canonicalize(name) for name in _CATALOG_ALIASES.values())

    for node in sorted(known):
        if node in covered:
            continue
        if node.startswith("vm-"):
            anchor, label = "forge-cheatcodes-map", "Foundry VM cheatcode/context concept"
        elif node.startswith("test-") or node in {
            "fuzz-tests", "bounded-fuzz", "invariant-tests",
            "invariant-handler", "fork-tests",
        }:
            anchor, label = "test", "Foundry testing concept"
        elif node.startswith("script-"):
            anchor, label = "script", "Foundry scripting concept"
        elif node.startswith("poc-"):
            anchor, label = "poc", "proof-of-concept audit workflow concept"
        elif node.startswith("yul-"):
            anchor, label = "yul", "Yul low-level concept"
        else:
            anchor, label = "contract-anatomy", "part of the Solidity contract/source surface"
        generated.append((node, anchor, label))
    return generated


_COMPREHENSIVE_CONNECTION_EDGES = _ensure_graph_coverage(_COMPREHENSIVE_CONNECTION_EDGES)


def connection_meaning(name: str) -> str:
    raw_key = _norm(name)

    # Prefer the catalog's own definition when the user supplied a real
    # topic/alias. This keeps "structs", "functions", etc. human-readable
    # instead of collapsing them to an internal semantic node too early.
    topic_name = _CATALOG_ALIASES.get(raw_key)
    if topic_name:
        found = {"meaning": None}

        def capture(name_, aliases_, category, meaning, *args, **kwargs):
            if name_ == topic_name:
                found["meaning"] = meaning

        _register_catalog_topics(capture)
        if found["meaning"]:
            return found["meaning"]

    canonical = canonicalize(name)
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]

    topic_name = _CATALOG_ALIASES.get(_norm(canonical))
    if topic_name:
        found = {"meaning": None}

        def capture(name_, aliases_, category, meaning, *args, **kwargs):
            if name_ == topic_name:
                found["meaning"] = meaning

        _register_catalog_topics(capture)
        if found["meaning"]:
            return found["meaning"]

    return f"{canonical} is a recognized Solidity/Foundry concept."

def connection_paths(names):
    """Find short graph bridges using the best-connected requested concept as the hub."""
    nodes = list(dict.fromkeys(canonicalize(name) for name in names))
    if len(nodes) < 2:
        return []

    adjacency = {}
    labels = {}

    for left, right, label in _COMPREHENSIVE_CONNECTION_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        if a == b:
            continue
        adjacency.setdefault(a, []).append(b)
        adjacency.setdefault(b, []).append(a)
        labels[(a, b)] = label
        labels[(b, a)] = label

    def shortest(start, goal):
        if start == goal:
            return [start]
        queue = [(start, [start])]
        seen = {start}
        while queue:
            cur, path = queue.pop(0)
            neighbors = sorted(adjacency.get(cur, []))
            for nxt in neighbors:
                if nxt in seen:
                    continue
                candidate = path + [nxt]
                if nxt == goal:
                    return candidate
                seen.add(nxt)
                queue.append((nxt, candidate))
        return None

    distance_cache = {}

    def distance(start, goal):
        key = (start, goal)
        if key not in distance_cache:
            path = shortest(start, goal)
            distance_cache[key] = len(path) - 1 if path else 999
        return distance_cache[key]

    # Pick a center that minimizes total graph distance to all requested nodes.
    center = min(
        nodes,
        key=lambda node: (sum(distance(node, other) for other in nodes if other != node), node),
    )

    rows = []
    for goal in nodes:
        if goal == center:
            continue
        path = shortest(center, goal)
        if path:
            edge_text = [
                labels.get((left, right), "conceptual contract-level bridge")
                for left, right in zip(path, path[1:])
            ]
            rows.append((center, goal, path, edge_text))

    rows.sort(key=lambda row: (len(row[2]), row[1]))
    return rows


def _scene(*args, **kwargs):
    # Support the original keyword-form scenes plus compact positional scenes
    # used by later corpus extensions.
    if args:
        if len(args) != 7 or kwargs:
            raise TypeError(
                "_scene positional form expects: keys, title, story, code, "
                "variables, flow, call"
            )
        keys, title, story, code, variables, flow, call = args
        return {
            "keys": keys,
            "title": title,
            "story": story,
            "code": code,
            "variables": variables,
            "flow": flow,
            "call": call,
        }
    return kwargs


COMPREHENSIVE_MICRO_SCENES = [
    _scene(
        keys={"mapping", "keccak256", "abi.decode"},
        title="Decode the bytes, hash the same bytes, use the hash as the key",
        story="One raw payload can travel through two different views: abi.decode turns it into typed values, while keccak256 turns the raw bytes into a bytes32 mapping key.",
        code="""mapping(bytes32 => address) public owners;

function register(bytes calldata raw) external {
    (address user_) = abi.decode(raw, (address));

    bytes32 id = keccak256(raw);
    owners[id] = user_;
}""",
        variables=[
            ("state", "mapping(bytes32 => address)", "owners", "owners[id]", "The hash becomes the mapping key."),
            ("parameter", "bytes calldata", "raw", "ABI-encoded address bytes", "The same raw bytes feed both operations."),
            ("decoded", "address", "user_", "abi.decode(raw, (address))", "Typed value extracted from raw bytes."),
            ("derived", "bytes32", "id", "keccak256(raw)", "Hash used as a mapping key."),
        ],
        flow=[
            "raw is just bytes at the boundary.",
            "abi.decode interprets those bytes as an address.",
            "keccak256 hashes the same bytes without changing their contents.",
            "The resulting bytes32 becomes the mapping key.",
            "The decoded address becomes the mapping value.",
        ],
        call="register(abi.encode(alice));",
        audit="The encoder and decoder must agree on exact types/order. Hashing bytes and hashing re-encoded values are only equivalent when the byte representation is exactly the same.",
    ),
    _scene(
        keys={"mapping", "keccak256"},
        title="A hash becomes a mapping key",
        story="The hash itself is just a bytes32 value. A mapping can use that value like any other key.",
        code="""mapping(bytes32 => address) public owners;

function register(bytes calldata nameBytes) external {
    bytes32 id = keccak256(nameBytes);
    owners[id] = msg.sender;
}""",
        variables=[
            ("state", "mapping(bytes32 => address)", "owners", "owners[id]", "Keyed by a 32-byte hash."),
            ("parameter", "bytes calldata", "nameBytes", "hex\"416c696365\"", "Raw bytes being hashed."),
            ("global", "address", "msg.sender", "0xAlice", "Stored as the mapping value."),
            ("local", "bytes32", "id", "keccak256(nameBytes)", "Hash-derived key."),
        ],
        flow=[
            "nameBytes is raw input.",
            "keccak256 turns the bytes into a bytes32 value.",
            "owners[id] treats that bytes32 exactly as a mapping key.",
            "msg.sender becomes the stored value.",
        ],
        call='register(hex"416c696365");',
        audit="Ask what exact bytes were hashed and whether the same bytes can be reconstructed later.",
    ),
    _scene(
        keys={"mapping", "abi.decode"},
        title="Decode first, then use the decoded value as a key",
        story="A mapping does not care where its key came from. abi.decode can turn raw bytes into the typed value used for the lookup.",
        code="""mapping(address => uint256) public balances;

function set(bytes calldata raw) external {
    (address user_, uint256 amount_) =
        abi.decode(raw, (address, uint256));

    balances[user_] = amount_;
}""",
        variables=[
            ("state", "mapping(address => uint256)", "balances", "balances[user_]", "Address selects the stored balance."),
            ("parameter", "bytes calldata", "raw", "ABI-encoded (address,uint256)", "Raw input."),
            ("decoded", "address", "user_", "abi.decode(...)", "Mapping key."),
            ("decoded", "uint256", "amount_", "abi.decode(...)", "Mapping value."),
        ],
        flow=[
            "raw arrives as bytes.",
            "abi.decode interprets two typed values in a fixed order.",
            "user_ becomes the mapping key.",
            "amount_ becomes the stored value.",
        ],
        call="set(abi.encode(alice, 100));",
        audit="A decode mismatch can revert or create a logically wrong interpretation. Check the exact ABI types and order.",
    ),
    _scene(
        keys={"abi.encode", "abi.decode", "keccak256"},
        title="Encode → hash → decode",
        story="Typed values can be serialized, hashed for an ID, and later decoded from the original bytes.",
        code="""function pack(address user_, uint256 amount_)
    external
    pure
    returns (bytes32 id, bytes memory data)
{
    data = abi.encode(user_, amount_);
    id = keccak256(data);
}

function unpack(bytes calldata data)
    external
    pure
    returns (address user_, uint256 amount_)
{
    (user_, amount_) = abi.decode(data, (address, uint256));
}""",
        variables=[
            ("parameter", "address", "user_", "0xAlice", "First typed value."),
            ("parameter", "uint256", "amount_", "100", "Second typed value."),
            ("local/return", "bytes", "data", "abi.encode(user_, amount_)", "Serialized representation."),
            ("return", "bytes32", "id", "keccak256(data)", "Stable digest for the exact bytes."),
        ],
        flow=[
            "Start with typed values.",
            "abi.encode produces bytes.",
            "keccak256 produces a bytes32 digest.",
            "The original bytes can be fed to abi.decode with matching types.",
        ],
        call='pack(alice, 100) → unpack(data)',
        audit="Never assume the hash identifies logical values unless the encoding is canonical for that purpose.",
    ),
    _scene(
        keys={"interface", "function", "arrays"},
        title="An interface call returns an array",
        story="A contract address is wrapped in an interface type. A declared external function is called, and its dynamic array result flows back to the caller.",
        code="""interface IUserStore {
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
}""",
        variables=[
            ("state", "IUserStore", "store", "IUserStore(0xStore)", "Typed view of a contract address."),
            ("parameter", "address", "store_", "0xStore", "Address supplied at deployment."),
            ("interface function", "address[] memory", "users()", "[alice, bob]", "Callable function promised by the interface."),
            ("external function", "address[] memory", "getUsers()", "store.users()", "Returns the array from the target."),
        ],
        flow=[
            "store_ is an address.",
            "IUserStore(store_) treats that address as a contract exposing users().",
            "getUsers() crosses the external call boundary.",
            "users() returns a dynamic array.",
        ],
        call="reader.getUsers();",
        audit="Verify the target address and that the deployed target actually implements the promised interface.",
    ),
    _scene(
        keys={"function", "visibility", "mutability", "returns", "parameter-vs-argument"},
        title="Definition → call: parameter, visibility, mutability, return",
        story="One function declaration tells you its input slots, who may call it, what state/ETH it can touch, and what value comes back.",
        code="""function quote(uint256 amount_)
    external
    view
    returns (uint256 fee)
{
    fee = amount_ / 100;
}

// call site:
// quote(10_000);""",
        variables=[
            ("parameter", "uint256", "amount_", "10_000", "Named input slot in the function definition."),
            ("argument", "uint256", "10_000", "10_000", "Actual value supplied at the call site."),
            ("specifier", "external", "visibility", "external", "Who can enter the function."),
            ("specifier", "view", "mutability", "view", "Cannot intentionally modify state."),
            ("return", "uint256", "fee", "100", "Named return value."),
        ],
        flow=[
            "The parameter belongs to the definition.",
            "The argument belongs to the call site.",
            "external controls the entry surface.",
            "view constrains state mutation.",
            "returns describes the value leaving the function.",
        ],
        call="quote(10_000) → 100",
        audit="For a function signature, inspect parameter types and visibility before looking at the body; those define the callable surface.",
    ),
    _scene(
        keys={"arrays", "structs", "storage-memory-calldata"},
        title="The same data can live in storage, memory, or calldata",
        story="Reference types do not behave like plain integers. The data location changes lifetime, mutability, copying, and whether a write persists.",
        code="""struct User {
    address account;
    uint256 score;
}

User[] public users;

function add(User calldata input) external {
    users.push(input);
}

function read(uint256 i)
    external
    view
    returns (User memory)
{
    return users[i];
}""",
        variables=[
            ("state", "User[]", "users", "[User, User, ...]", "Persistent dynamic array."),
            ("parameter", "User calldata", "input", "read-only external value", "Input lives in calldata."),
            ("return", "User memory", "User", "temporary copy", "Returned struct is provided as memory data."),
            ("array", "uint256", "i", "0", "Index selecting one stored element."),
        ],
        flow=[
            "input arrives in calldata.",
            "users.push(input) copies the struct into persistent storage.",
            "read(i) selects one stored struct.",
            "The return crosses from storage to memory.",
        ],
        call="add(User({account: alice, score: 22}));",
        audit="Track every storage↔memory/calldata boundary: copies persist differently from storage references.",
    ),
    _scene(
        keys={"structs", "mapping", "nested-mapping", "arrays", "enum", "bytes", "address"},
        title="Address → struct → enum/bytes/array → nested mapping",
        story="A realistic registry can use one address to select a structured record, while a second lookup indexes another piece of state.",
        code="""enum Status { Open, Done }

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
}""",
        variables=[
            ("mapping key", "address", "user_", "0xAlice", "Chooses one Profile."),
            ("storage ref", "Profile storage", "profile", "profiles[user_]", "Writes persist to the selected record."),
            ("field", "Status", "status_", "Status.Done", "Named state."),
            ("field", "bytes", "note_", 'hex"6869"', "Dynamic raw bytes."),
            ("field", "uint256[]", "tags_", "[1, 2, 3]", "Dynamic array."),
            ("nested key", "bytes32", "id_", 'bytes32("A")', "Second mapping key."),
        ],
        flow=[
            "user_ selects a Profile.",
            "The storage reference exposes its fields.",
            "The enum, bytes, and array become part of the record.",
            "balances[user_][id_] performs a second keyed lookup.",
            "users.push(user_) records the address in a growing array.",
        ],
        call='update(alice, 22, Status.Done, hex"6869", bytes32("A"), [1, 2, 3]);',
        audit="Check which caller can update which user_ key; the fact that a parameter is an address does not prove it belongs to msg.sender.",
    ),
    _scene(
        keys={"mapping", "nested-mapping", "mapping-slots", "nested-mapping-slots", "keccak256", "storage"},
        title="Language lookup → storage slot lookup",
        story="balances[user][id] looks simple in Solidity, but storage addressing recursively derives locations with Keccak-256.",
        code="""mapping(address => mapping(bytes32 => uint256)) public balances;

function set(address user_, bytes32 id_, uint256 amount_) external {
    balances[user_][id_] = amount_;
}

// storage reasoning:
// outer = keccak256(abi.encode(user_, balances.slot))
// inner = keccak256(abi.encode(id_, outer))""",
        variables=[
            ("state", "nested mapping", "balances", "balances[user_][id_]", "The high-level lookup."),
            ("slot", "bytes32", "balances.slot", "7", "Anchor slot for the mapping declaration."),
            ("derived", "bytes32", "outer", "keccak256(...)", "Slot derived from the first key."),
            ("derived", "bytes32", "inner", "keccak256(...)", "Final slot for the value."),
        ],
        flow=[
            "Solidity starts from the mapping's anchor slot.",
            "The outer key + anchor slot derive the first location.",
            "The inner key + first location derive the final location.",
            "sload/sstore of that final word reaches the uint256 value.",
        ],
        call='set(alice, bytes32("A"), 100);',
        audit="Storage-slot reasoning must use the exact layout and key encoding rules. Never guess a slot from the source declaration alone.",
    ),
    _scene(
        keys={"receive", "fallback", "payable", "msg.sender", "msg.value", "call", "mapping"},
        title="ETH entry → credit → withdrawal call",
        story="The entry point sees the caller and attached ETH; a mapping records credit; the withdrawal performs an external Ether call.",
        code="""mapping(address => uint256) public credit;

receive() external payable {
    credit[msg.sender] += msg.value;
}

function withdraw(uint256 amount_) external {
    credit[msg.sender] -= amount_;

    (bool ok, ) =
        payable(msg.sender).call{value: amount_}("");

    require(ok);
}""",
        variables=[
            ("state", "mapping(address => uint256)", "credit", "credit[Alice]", "Per-user accounting."),
            ("global", "address", "msg.sender", "Alice", "Immediate caller."),
            ("global", "uint256", "msg.value", "1 ether", "ETH attached to this call."),
            ("parameter", "uint256", "amount_", "0.5 ether", "Withdrawal amount."),
            ("local", "bool", "ok", "true", "Low-level call success flag."),
        ],
        flow=[
            "Alice sends 1 ETH with empty calldata.",
            "receive() runs and credits Alice.",
            "Alice calls withdraw(0.5 ether).",
            "The mapping is reduced before the external call sends ETH back.",
        ],
        call="1 ETH → credit[Alice] = 1 ETH → withdraw(0.5 ETH)",
        audit="Check both accounting and external-call ordering. The contract balance is the held asset; the mapping is only its internal accounting.",
    ),
    _scene(
        keys={"require", "revert", "assert", "custom-errors", "try-catch", "errors"},
        title="Failures are still data flow",
        story="Solidity has several failure forms. They all revert the affected call frame, but their intent and observable error data differ.",
        code="""error NotEnough(uint256 wanted, uint256 available);

function withdraw(uint256 amount) external {
    require(amount > 0, "zero");

    if (amount > address(this).balance) {
        revert NotEnough(amount, address(this).balance);
    }

    assert(amount <= type(uint256).max);
}""",
        variables=[
            ("condition", "bool", "amount > 0", "true/false", "require gate."),
            ("error", "custom error", "NotEnough", "(wanted, available)", "Structured revert data."),
            ("expression", "bool", "amount <= max", "true", "assert-style invariant check."),
        ],
        flow=[
            "require handles ordinary caller/input preconditions.",
            "revert emits explicit custom error data.",
            "assert expresses an invariant assumption.",
            "An external caller can inspect the resulting error/revert data.",
        ],
        call="withdraw(10 ether);",
        audit="Do not treat require, revert, and assert as interchangeable. Review what property each one claims and what error data callers/tests expect.",
    ),
    _scene(
        keys={"modifier", "access-control", "mapping", "msg.sender", "enum", "custom-errors", "events"},
        title="Caller → role mapping → modifier → state transition",
        story="A role check is a data flow: caller identity selects a stored role, a modifier enforces the rule, then the function changes state and emits an event.",
        code="""enum Role { None, Admin, Operator }

mapping(address => Role) public roles;
event RoleChanged(address indexed account, Role oldRole, Role newRole);
error NotAuthorized(address caller);

modifier only(Role required_) {
    if (roles[msg.sender] != required_) {
        revert NotAuthorized(msg.sender);
    }
    _;
}

function setRole(address account_, Role newRole_)
    external
    only(Role.Admin)
{
    Role oldRole = roles[account_];
    roles[account_] = newRole_;
    emit RoleChanged(account_, oldRole, newRole_);
}""",
        variables=[
            ("global", "address", "msg.sender", "0xAdmin", "Caller being authorized."),
            ("state", "mapping(address => Role)", "roles", "roles[msg.sender]", "Caller-to-role lookup."),
            ("modifier input", "Role", "required_", "Role.Admin", "Required role."),
            ("parameter", "address", "account_", "0xBob", "Account being changed."),
            ("parameter", "Role", "newRole_", "Role.Operator", "New state."),
        ],
        flow=[
            "msg.sender selects roles[msg.sender].",
            "The modifier compares the stored role with Role.Admin.",
            "The function reads the old role, writes the new role, then emits an event.",
        ],
        call="setRole(bob, Role.Operator);",
        audit="Trace authorization separately from the target parameter: a privileged caller changing someone else's state can be correct or dangerous depending on the invariant.",
    ),
    _scene(
        keys={"imports", "inheritance", "abstract", "interface", "override", "virtual", "constructor", "address"},
        title="Import → base/interface → constructor chain → override",
        story="Imports make declarations available; inheritance composes them; constructors initialize base/child state; virtual/override controls implementation.",
        code="""// Owned.sol
abstract contract Owned {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function who() public view virtual returns (address) {
        return owner;
    }
}

// Vault.sol
import "./Owned.sol";

interface IName {
    function name() external view returns (string memory);
}

contract Vault is Owned, IName {
    string public override name;

    constructor(string memory name_)
        Owned(msg.sender)
    {
        name = name_;
    }

    function who()
        public
        view
        override
        returns (address)
    {
        return owner;
    }
}""",
        variables=[
            ("base input", "address", "owner_", "msg.sender", "Value passed into the imported base constructor."),
            ("child input", "string", "name_", '"Savings"', "Value supplied to the child constructor."),
            ("inherited function", "address", "who()", "owner", "Virtual base member overridden by Vault."),
            ("interface function", "string", "name()", "name", "Callable shape required by IName."),
        ],
        flow=[
            "import exposes Owned.",
            "Vault inherits Owned and IName.",
            "Vault's constructor supplies msg.sender to Owned.",
            "Vault supplies an implementation for the virtual/interface function shapes.",
        ],
        call='new Vault("Savings");',
        audit="Review base-constructor arguments, storage layout order, and every override/interface implementation.",
    ),
    _scene(
        keys={"library", "using-for", "function", "types"},
        title="Type → attached library function",
        story="using-for makes a library function read like a method on the value while remaining a normal library call underneath.",
        code="""library Percent {
    function onePercent(uint256 amount)
        internal
        pure
        returns (uint256)
    {
        return amount / 100;
    }
}

contract Fees {
    using Percent for uint256;

    function fee(uint256 amount)
        external
        pure
        returns (uint256)
    {
        return amount.onePercent();
    }
}""",
        variables=[
            ("receiver", "uint256", "amount", "10_000", "Value the library function operates on."),
            ("library function", "function", "onePercent", "amount / 100", "Reusable computation."),
            ("attached syntax", "uint256", "amount.onePercent()", "100", "using-for makes the receiver explicit at the call site."),
        ],
        flow=[
            "Percent declares a function.",
            "using Percent for uint256 attaches that function to uint256 values.",
            "amount.onePercent() passes amount as the receiver argument.",
        ],
        call="fee(10_000) → 100",
        audit="Verify the library's visibility and the receiver type; using-for changes syntax, not the underlying call semantics.",
    ),
    _scene(
        keys={"function-signature", "function-selector", "calldata", "abi.encodeWithSelector", "abi.decode"},
        title="Signature → selector → calldata → decode",
        story="A normal external call can be understood as a 4-byte selector followed by ABI-encoded arguments.",
        code="""bytes4 selector =
    bytes4(keccak256("set(uint256)"));

bytes memory data =
    abi.encodeWithSelector(selector, 100);

// Callee-side idea:
// uint256 amount = abi.decode(msg.data[4:], (uint256));""",
        variables=[
            ("signature", "string", '"set(uint256)"', "canonical function shape", "Text describing the external function."),
            ("selector", "bytes4", "selector", "first 4 bytes of hash", "Dispatch identifier."),
            ("calldata", "bytes", "data", "selector + encoded 100", "Complete message payload."),
            ("decoded", "uint256", "amount", "100", "Argument recovered after removing selector."),
        ],
        flow=[
            "The signature is hashed.",
            "The first four bytes become the selector.",
            "ABI encoding places the argument after the selector.",
            "The callee can decode the argument bytes.",
        ],
        call='set(100) → selector + 32-byte argument',
        audit="Check canonical signature spelling, selector bytes, argument order, and what exactly is sliced before decoding.",
    ),
    _scene(
        keys={"events", "event-indexed", "keccak256", "bytes32"},
        title="State change → event topic/data",
        story="Events are not mappings: they are log records. Indexed arguments go into topics, and the event signature produces the default selector topic.",
        code="""event Paid(
    address indexed user,
    uint256 amount
);

function pay(uint256 amount) external {
    emit Paid(msg.sender, amount);
}

// event.selector =
// keccak256("Paid(address,uint256)")""",
        variables=[
            ("indexed", "address", "user", "msg.sender", "Placed in a log topic."),
            ("data", "uint256", "amount", "100", "Non-indexed event data."),
            ("selector", "bytes32", "event.selector", "keccak256(signature)", "Default topic for non-anonymous events."),
        ],
        flow=[
            "The function changes/observes state.",
            "emit creates a log record.",
            "The event signature contributes a bytes32 selector topic.",
            "Indexed arguments become searchable topics; non-indexed values go into data.",
        ],
        call="pay(100);",
        audit="Events are off-chain observability, not state. Never use an event as evidence that storage was actually updated.",
    ),
    _scene(
        keys={"reentrancy", "checks-effects-interactions", "call", "receive", "fallback", "mapping", "msg.sender"},
        title="State update → external call → callback",
        story="The reentrancy problem appears when a contract updates accounting and then gives an external contract control before the operation is finished.",
        code="""mapping(address => uint256) public credit;

function withdraw(uint256 amount_) external {
    require(credit[msg.sender] >= amount_);

    // EFFECT
    credit[msg.sender] -= amount_;

    // INTERACTION
    (bool ok, ) =
        payable(msg.sender).call{value: amount_}("");
    require(ok);
}""",
        variables=[
            ("state", "mapping(address => uint256)", "credit", "credit[msg.sender]", "Accounting being protected."),
            ("global", "address", "msg.sender", "attacker", "May be a contract."),
            ("parameter", "uint256", "amount_", "1 ether", "Requested payout."),
            ("boundary", "call", "ok", "true/false", "Hands execution to the recipient."),
        ],
        flow=[
            "Check credit.",
            "Reduce credit before handing over control.",
            "External call may execute recipient receive/fallback.",
            "When control returns, the accounting has already changed.",
        ],
        call="attacker.withdraw(1 ether);",
        audit="Look for every external control transfer, including token callbacks and delegated calls—not only obvious Ether sends.",
    ),
    _scene(
        keys={"tx-origin", "msg.sender", "access-control", "this-call"},
        title="Caller vs transaction origin",
        story="A contract call creates a new message frame. msg.sender follows the immediate caller; tx.origin stays the original transaction sender.",
        code="""function dangerous() external {
    require(tx.origin == owner);
}

function safer() external {
    require(msg.sender == owner);
}""",
        variables=[
            ("global", "address", "tx.origin", "Alice", "Original transaction signer."),
            ("global", "address", "msg.sender", "Bob/contract", "Immediate caller of this function."),
            ("state", "address", "owner", "Alice", "Expected privileged identity."),
        ],
        flow=[
            "Alice starts a transaction.",
            "Alice calls an intermediate contract.",
            "The target sees msg.sender as the intermediate contract.",
            "tx.origin still refers to Alice.",
        ],
        call="Alice → helper → dangerous()",
        audit="Authorization should generally reason about the immediate caller and explicit capability path, not assume tx.origin is the intended principal.",
    ),
    _scene(
        keys={"proxy-fallback", "fallback", "delegatecall", "storage-layout", "function-selector", "calldata", "returndata"},
        title="Proxy dispatch: raw calldata → delegatecall → same storage",
        story="A proxy fallback receives arbitrary calldata, delegates it to implementation code, and returns the implementation's returndata while preserving the proxy's storage/context.",
        code="""address implementation;

fallback() external payable {
    (bool ok, bytes memory data) =
        implementation.delegatecall(msg.data);

    if (!ok) {
        assembly { revert(add(data, 32), mload(data)) }
    }

    assembly {
        return(add(data, 32), mload(data))
    }
}""",
        variables=[
            ("state", "address", "implementation", "0xImpl", "Code target."),
            ("global", "bytes", "msg.data", "selector + arguments", "Raw caller input."),
            ("call", "delegatecall", "target", "implementation", "Executes code using proxy storage/context."),
            ("return", "bytes", "data", "returndata", "Raw result bubbled back to caller."),
        ],
        flow=[
            "Caller sends normal calldata to proxy.",
            "Proxy fallback catches it.",
            "delegatecall executes implementation code against proxy storage.",
            "Proxy returns or reverts with the implementation's bytes.",
        ],
        call="proxy.setValue(100);",
        audit="Storage layout, selector routing, implementation address control, and return-data bubbling are all part of the proxy's security boundary.",
    ),
    _scene(
        keys={"constant-immutable", "constructor", "storage-layout"},
        title="Compile-time constant vs construction-time immutable",
        story="Both are unchangeable after construction, but constant is known at compile time while immutable can capture a constructor value.",
        code="""uint256 public constant MAX = 100;

uint256 public immutable LIMIT;

constructor(uint256 limit_) {
    LIMIT = limit_;
}""",
        variables=[
            ("constant", "uint256", "MAX", "100", "Fixed at compile time."),
            ("immutable", "uint256", "LIMIT", "constructor argument", "Fixed after construction but chosen during deployment."),
            ("parameter", "uint256", "limit_", "500", "Deployment-time input."),
        ],
        flow=[
            "MAX is known to the compiler.",
            "limit_ arrives when the contract is created.",
            "LIMIT stores that deployment-specific value and cannot be changed later.",
        ],
        call="new Contract(500);",
        audit="Do not expect constant/immutable values to behave like ordinary storage slots when doing layout or upgrade analysis.",
    ),
    _scene(
        keys={"yul", "yul-memory", "memory", "calldata", "abi.encode", "bytes"},
        title="ABI bytes → memory → Yul loads",
        story="High-level bytes live in memory/calldata representations; Yul exposes the same bytes as words and offsets.",
        code="""function firstWord(bytes calldata input)
    external
    pure
    returns (bytes32 word)
{
    // calldata is copied/read through the Solidity boundary
    bytes memory data = abi.encode(input);

    assembly {
        word := mload(add(data, 32))
    }
}""",
        variables=[
            ("input", "bytes calldata", "input", "raw external bytes", "Read-only calldata value."),
            ("memory", "bytes memory", "data", "ABI bytes", "Dynamic bytes in memory."),
            ("Yul", "bytes32", "word", "mload(...)", "32-byte word read from memory."),
        ],
        flow=[
            "Input starts in calldata.",
            "ABI encoding creates a memory byte array.",
            "Yul obtains the data pointer and length-prefixed layout.",
            "mload reads a 32-byte word.",
        ],
        call='firstWord(hex"010203...");',
        audit="When entering assembly, verify pointer arithmetic, length words, and the Solidity memory-safety conventions.",
    ),
    _scene(
        keys={"yul", "yul-storage", "storage", "mapping-slots", "keccak256"},
        title="Yul makes a mapping slot visible",
        story="The high-level mapping syntax hides storage-address arithmetic. Yul exposes the actual words used by sload/sstore.",
        code="""mapping(address => uint256) public balances;

function read(address user_)
    external
    view
    returns (uint256 result)
{
    assembly {
        mstore(0x00, user_)
        mstore(0x20, balances.slot)
        let slot := keccak256(0x00, 0x40)
        result := sload(slot)
    }
}""",
        variables=[
            ("state", "mapping(address => uint256)", "balances", "balances[user_]", "High-level mapping."),
            ("parameter", "address", "user_", "0xAlice", "Mapping key."),
            ("Yul local", "word", "slot", "keccak256(key + anchor)", "Derived storage location."),
            ("Yul op", "word", "sload(slot)", "uint256", "Raw storage read."),
        ],
        flow=[
            "mstore builds the hash input.",
            "keccak256 derives the mapping entry location.",
            "sload reads the 32-byte storage word.",
        ],
        call="read(alice);",
        audit="Assembly storage math must match compiler layout exactly, including nested mapping and packed-member cases.",
    ),
    _scene(
        keys={"yul", "yul-call", "low-level-call", "staticcall", "delegatecall", "returndata"},
        title="Yul call family: code + target + calldata + returndata",
        story="call, staticcall, and delegatecall differ in execution context, but all share the idea of a low-level message boundary with raw bytes.",
        code="""assembly {
    // Pseudocode shape:
    // success := call(gas(), target, value, inPtr, inSize, outPtr, outSize)
    // success := staticcall(gas(), target, inPtr, inSize, outPtr, outSize)
    // success := delegatecall(gas(), target, inPtr, inSize, outPtr, outSize)
}""",
        variables=[
            ("target", "address", "target", "0xTarget", "Code/data destination."),
            ("input", "bytes", "calldata", "selector + args", "Raw input bytes."),
            ("output", "bytes", "returndata", "raw bytes", "Bytes produced by the callee."),
            ("flag", "bool", "success", "true/false", "Low-level execution result."),
        ],
        flow=[
            "Build the raw calldata.",
            "Choose call/staticcall/delegatecall based on required context.",
            "Inspect success.",
            "Read/copy returndata only after checking the execution result and expected shape.",
        ],
        call="assembly-level call boundary",
        audit="Never collapse the three call flavors into one mental model: value, storage, caller context, and write permissions differ.",
    ),
    _scene(
        keys={"loops", "for", "while", "do-while", "arrays"},
        title="Same collection, three loop semantics",
        story="All three loop forms can walk an array; the difference is when the condition is checked and how the exit proof must be reasoned about.",
        code="""for (uint256 i = 0; i < xs.length; i++) {
    use(xs[i]);
}

while (i < xs.length) {
    use(xs[i]);
    i++;
}

do {
    use(xs[i]);
    i++;
} while (i < xs.length);""",
        variables=[
            ("array", "T[]", "xs", "[...]", "Collection being traversed."),
            ("index", "uint256", "i", "0 → length", "Loop counter."),
            ("condition", "bool", "i < xs.length", "true/false", "Controls repetition."),
        ],
        flow=[
            "for checks before each body execution.",
            "while checks before each body execution too, but initialization/update are written separately.",
            "do-while executes the body once before its first condition check.",
        ],
        call="walk a 3-element array",
        audit="For every loop, prove termination and gas feasibility. A dynamic storage-backed length can grow beyond practical execution limits.",
    ),
    _scene(
        keys={"test", "vm-prank", "msg.sender", "access-control", "mapping"},
        title="Foundry prank changes the mapping key you see",
        story="A test cheatcode can impersonate a caller, which directly changes msg.sender and therefore any mapping keyed by msg.sender.",
        code="""function testOnlyAlice() public {
    vm.prank(alice);
    contract.setBalance(100);

    assertEq(contract.balances(alice), 100);
}""",
        variables=[
            ("test setup", "address", "alice", "0xAlice", "Impersonated caller."),
            ("cheatcode", "vm.prank", "caller", "alice", "Changes msg.sender for the next call."),
            ("global", "address", "msg.sender", "alice", "Observed by the contract."),
            ("state", "mapping(address => uint256)", "balances", "balances[msg.sender]", "Key changes because caller changes."),
        ],
        flow=[
            "The test chooses alice.",
            "vm.prank makes alice the next caller.",
            "The contract sees msg.sender == alice.",
            "balances[msg.sender] therefore writes balances[alice].",
        ],
        call="vm.prank(alice); contract.setBalance(100);",
        audit="This is exactly why caller-dependent logic must be tested with multiple actors, not only the default test contract.",
    ),
    _scene(
        keys={"fuzz-tests", "bounded-fuzz", "vm-assume", "vm-bound"},
        title="Fuzz input → constrain → execute",
        story="Foundry fuzzing gives many inputs; assume and bound shape the region you actually intend to exercise.",
        code="""function testFuzzFee(uint256 amount) public {
    amount = bound(amount, 1, 1_000_000);
    vm.assume(amount % 2 == 0);

    uint256 fee = contract.quote(amount);
    assertLe(fee, amount);
}""",
        variables=[
            ("fuzz input", "uint256", "amount", "arbitrary", "Generated by the fuzzer."),
            ("cheatcode", "vm-bound", "amount", "1..1_000_000", "Ranges the generated value."),
            ("cheatcode", "vm-assume", "amount % 2 == 0", "true", "Rejects cases outside the intended domain."),
            ("output", "uint256", "fee", "quote(amount)", "Property under test."),
        ],
        flow=[
            "The fuzzer supplies an input.",
            "bound maps it into an allowed numeric range.",
            "assume removes cases that do not belong to the intended domain.",
            "The contract is exercised over many remaining cases.",
        ],
        call="testFuzzFee(randomAmount);",
        audit="Bad assumptions can accidentally exclude the vulnerable region. Review constraints as carefully as the invariant.",
    ),
    _scene(
        keys={"invariant-tests", "invariant-handler", "mapping", "test"},
        title="State machine → repeated calls → invariant",
        story="Invariant testing does not ask for one expected output; it keeps mutating state and checks a property that should stay true.",
        code="""function invariant_creditNeverExceedsAssets() public {
    assertLe(
        address(contract).balance,
        contract.totalTracked()
    );
}

// A handler can generate:
// deposit(user, amount)
// withdraw(user, amount)
// transfer(user, recipient, amount)""",
        variables=[
            ("state", "mapping(...)", "credit", "per-user accounting", "State under mutation."),
            ("property", "bool", "invariant", "true", "Must hold after arbitrary handler sequences."),
            ("handler", "function set", "actions", "deposit/withdraw/...", "State-transition generator."),
        ],
        flow=[
            "The handler creates many state transitions.",
            "The invariant is checked after those transitions.",
            "A counterexample becomes a concrete sequence that violated the property.",
        ],
        call="forge test --match-test invariant_...",
        audit="An invariant is only as useful as the reachable state space and handler actions behind it.",
    ),
    _scene(
        keys={"script", "script-deploy", "script-broadcast", "new", "constructor", "address"},
        title="Script → broadcast → constructor → deployed address",
        story="A Foundry deployment script turns configuration into a real contract-creation transaction, then keeps the resulting address for interaction.",
        code="""contract DeployScript {
    function run() external {
        vm.startBroadcast();

        Vault vault = new Vault("Savings", 1_000);

        vm.stopBroadcast();
    }
}""",
        variables=[
            ("broadcast", "VM context", "vm.startBroadcast()", "real tx mode", "Marks subsequent transactions for broadcasting."),
            ("constructor arg", "string", '"Savings"', "deployment input", "Passed to Vault."),
            ("constructor arg", "uint256", "1_000", "deployment input", "Second deployment value."),
            ("contract", "Vault", "vault", "fresh address", "Reference to the deployed instance."),
        ],
        flow=[
            "Script loads configuration.",
            "Broadcast mode makes creation a transaction in the selected environment.",
            "new Vault(...) runs the constructor.",
            "The resulting contract reference points at the fresh address.",
        ],
        call="forge script script/Deploy.s.sol --broadcast",
        audit="Separate local simulation from broadcast side effects and verify every constructor argument/address before deployment.",
    ),
    _scene(
        keys={"poc-reentrancy", "reentrancy", "call", "receive", "mapping", "checks-effects-interactions"},
        title="PoC → attacker callback → violated accounting",
        story="A reentrancy PoC deliberately turns the external call into a callback surface and checks whether accounting can be drained before it is updated.",
        code="""contract Attacker {
    Target target;

    fallback() external payable {
        if (address(target).balance > 0) {
            target.withdraw(1 ether);
        }
    }

    function attack() external {
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }
}""",
        variables=[
            ("target", "contract", "target", "victim", "Contract under test."),
            ("fallback", "callback", "fallback()", "re-enter", "Runs when target sends value back."),
            ("call", "external call", "target.withdraw", "1 ether", "Second entry into target."),
            ("property", "mapping", "credit", "must decrease before callback", "Accounting being attacked."),
        ],
        flow=[
            "The PoC deposits enough to create target state.",
            "The first withdrawal triggers an external callback.",
            "fallback re-enters before the original operation has safely completed.",
            "The PoC observes whether the invariant/accounting breaks.",
        ],
        call="attacker.attack();",
        audit="A useful PoC proves a concrete state/property violation, not merely the presence of a call.",
    ),
]


def find_micro_scene(names):
    requested = frozenset(canonicalize(name) for name in names)
    candidates = []

    # Comprehensive scenes are preferred because they were added from the
    # full graph/coverage pass. Legacy MICRO_SCENES stay available as fallback.
    for priority, scenes in enumerate((COMPREHENSIVE_MICRO_SCENES, MICRO_SCENES)):
        for scene in scenes:
            keys = frozenset(canonicalize(x) for x in scene["keys"])
            if requested <= keys:
                candidates.append(
                    (
                        priority,
                        0 if keys == requested else 1,
                        len(keys - requested),
                        len(keys),
                        scene.get("title", ""),
                        scene,
                    )
                )

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[:5])
    return candidates[0][5]


def expand_name(name: str):
    key = _norm(name)
    composite = _COMPREHENSIVE_COMPOSITES.get(key)
    if composite:
        return {canonicalize(item) for item in composite}
    return {canonicalize(name)}


def find_connection(names):
    requested = set()
    for name in names:
        requested.update(expand_name(name))
    requested = frozenset(requested)

    if len(requested) < 2:
        return None

    candidates = []
    for lab in CONNECTION_LABS:
        concepts = frozenset(canonicalize(item) for item in lab["concepts"])
        if requested <= concepts:
            extra = len(concepts - requested)
            candidates.append((extra, len(concepts), lab))

    if candidates:
        candidates.sort(key=lambda item: (item[0], item[1], item[2]["name"]))
        return candidates[0][2]

    # Arbitrary recognized combinations remain valid and are backed by the
    # comprehensive graph.  Full mode deliberately falls through to the
    # universal compile-checked contract.
    return UNIVERSAL_CONNECTION_LAB


def list_connections():
    featured = [
        ("decode/hash/mapping", "bytes → abi.decode + keccak256 → mapping"),
        ("ABI call path", "signature → selector → calldata → external call → decode"),
        ("state layout", "mapping/arrays/structs → storage layout → Keccak/Yul"),
        ("ETH flow", "receive/fallback → msg.value → accounting → call"),
        ("access control", "msg.sender → mapping/role → modifier → state/event"),
        ("proxy flow", "fallback → delegatecall → storage layout → returndata"),
        ("Yul", "memory/calldata/storage → assembly → raw EVM operations"),
        ("Foundry tests", "prank/deal/warp/fuzz/invariant → Solidity execution"),
        ("Foundry scripts", "env/broadcast/deploy/interact → deployed contracts"),
        ("audit PoCs", "test state + cheatcodes → concrete security property"),
    ]
    rows = [
        {
            "name": "solidity-yul-comprehensive-graph",
            "aliases": ["graph", "comprehensive", "universal", "composer"],
            "concepts": ["all recognized concepts"],
            "summary": (
                f"{len(_COMPREHENSIVE_CONNECTION_EDGES)} graph relationships + "
                f"{len(COMPREHENSIVE_MICRO_SCENES)} guided teaching scenes. "
                "Arbitrary recognized combinations fall back to graph bridges and the explicit full lab."
            ),
        }
    ]
    rows.extend(
        {"name": name, "aliases": [], "concepts": [description], "summary": "Featured learning path."}
        for name, description in featured
    )
    return rows


# ---------------------------------------------------------------------------
# FINAL COVERAGE PASS
# ---------------------------------------------------------------------------
#
# Second-pass audit of the graph against the current Solidity reference
# structure, ABI specification, storage/transient-storage rules, and recurring
# patterns in OpenZeppelin, Uniswap, Aave, Compound, Solmate, and Foundry.
#
# The goal here is not to claim that every pair has a dedicated recipe.  The
# goal is stronger: every recognized concept can enter a meaningful graph,
# high-value multi-hop paths have tiny teaching scenes, and arbitrary requests
# remain composable instead of becoming "no connection".
#

_SEMANTIC_ALIASES.update({
    "assignment": "assignment",
    "assign": "assignment",
    "abi-encode-call": "abi.encodeCall",
    "abi.encodecall": "abi.encodeCall",
    "encode-call": "abi.encodeCall",
    "function-type": "function-types",
    "function-types": "function-types",
    "external-function-type": "external-function-types",
    "external-function-types": "external-function-types",
    "contract-type": "contract-types",
    "contract-types": "contract-types",
    "udvt": "user-defined-value-types",
    "user-defined-value-type": "user-defined-value-types",
    "transient": "transient-storage",
    "tstore": "transient-storage",
    "tload": "transient-storage",
    "erc7201": "erc7201",
    "namespaced-storage": "erc7201",
    "storage-namespace": "erc7201",
    "storage-slot": "storage-slot",
    "returndata": "returndata",
    "return-data": "returndata",
    "sha256": "sha256",
    "ripemd160": "ripemd160",
    "ecrecover": "ecrecover",
    "addmod": "addmod",
    "mulmod": "mulmod",
    "bytes-concat": "bytes.concat",
    "bytes.concat": "bytes.concat",
    "string-concat": "string.concat",
    "string.concat": "string.concat",
    "selfdestruct": "selfdestruct",
    "this": "this",
    "super": "super",
    "nonce": "nonce",
})

_EXTRA_MEANINGS.update({
    "assignment": "Assignment stores a computed or supplied value into a variable, array element, mapping entry, or struct member.",
    "abi.encodeCall": "Type-checks a function pointer plus arguments and produces selector-prefixed ABI calldata.",
    "sha256": "Computes the SHA-256 digest of bytes and returns bytes32.",
    "ripemd160": "Computes the RIPEMD-160 digest of bytes and returns bytes20.",
    "ecrecover": "Recovers the address associated with a signed message digest and ECDSA signature values.",
    "addmod": "Computes modular addition with arbitrary-precision intermediate arithmetic.",
    "mulmod": "Computes modular multiplication with arbitrary-precision intermediate arithmetic.",
    "bytes.concat": "Concatenates bytes and fixed-size byte values into one dynamic bytes value.",
    "string.concat": "Concatenates strings into one dynamic string value.",
    "selfdestruct": "A deprecated opcode whose current EVM behavior is version-dependent; on Cancun-or-later EVMs it normally transfers the account balance without deleting the contract, except for same-transaction-created contracts.",
    "this": "The current contract as a contract-typed value; using this.f() performs an external call to the current address.",
    "super": "A contract-typed reference used to call the next implementation in the inheritance hierarchy.",
    "nonce": "A unique counter commonly used to make signed messages or state transitions single-use and prevent replay.",
    "compound-assignment": "An assignment operator such as += or -= that combines an operation with writing the result back.",
    "tload": "EVM/Yul operation that reads a word from transaction-scoped transient storage.",
    "forge-cheatcodes": "Foundry cheatcodes expose controlled EVM/test context operations through the vm interface.",
    "tstore": "EVM/Yul operation that writes a word to transaction-scoped transient storage.",
})

_EXTRA_CONCEPTS.update({
    "assignment", "compound-assignment", "abi.encodeCall", "sha256", "ripemd160", "ecrecover",
    "addmod", "mulmod", "bytes.concat", "string.concat", "selfdestruct",
    "this", "super", "nonce", "erc7201", "tload", "tstore",
    "forge-cheatcodes", "cheatcodes", "expectrevert", "expectemit",
})


# Relationship additions that came up repeatedly in production-style code.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("contract-anatomy", "function", "functions are a core executable part of contract structure"),
    ("contract-anatomy", "variables", "state/local values make the contract's data model"),
    ("contract-anatomy", "events", "events expose state transitions to external observers"),
    ("contract-anatomy", "errors", "errors describe failed execution"),
    ("contract-anatomy", "constructor", "constructors establish initial state"),
    ("contract-anatomy", "receive-vs-fallback", "receive/fallback form the contract's default message-routing surface"),

    # Assignment / value flow
    ("assignment", "variables", "assignment writes a new value into a named variable"),
    ("assignment", "mapping", "mapping entries are ordinary lvalues and can be assigned"),
    ("assignment", "arrays", "array elements can be assigned by index"),
    ("assignment", "structs", "struct members can be assigned individually"),
    ("assignment", "storage-memory-calldata", "reference assignments can create copies or storage references depending on types/location"),
    ("assignment", "delete", "delete is a special form of resetting a variable to its default"),
    ("assignment", "compound-assignment", "compound assignment combines an operation with an assignment"),

    # ABI / selector family
    ("abi.encodeCall", "function-types", "the function pointer supplies the selector and expected argument types"),
    ("abi.encodeCall", "function-selector", "its result begins with the pointed-to function selector"),
    ("abi.encodeCall", "calldata", "its bytes can be sent as complete external calldata"),
    ("abi.encodeCall", "low-level-call", "raw call APIs can consume the generated bytes"),
    ("abi.encodeWithSelector", "abi.encodeCall", "both construct selector-prefixed calldata, but encodeCall adds stronger compile-time typing"),
    ("abi.encodeWithSignature", "abi.encodeCall", "both create selector-prefixed calldata, with different sources of the selector"),
    ("abi.decode", "calldata-slices", "selector-prefixed calldata can be sliced before decoding arguments"),
    ("returndata", "abi.decode", "raw returned bytes can be decoded using the expected return types"),
    ("returndata", "calldata", "both are raw byte-oriented message-boundary data, but one is input and the other output"),
    ("returndata", "proxy-fallback", "proxies commonly bubble implementation returndata"),
    ("returndata", "errors", "revert payloads are returned as bytes at low-level boundaries"),
    ("custom-errors", "function-selector", "error selectors share the first-four-byte Keccak convention"),
    ("events", "abi.encode", "non-indexed event data uses ABI encoding"),
    ("event-indexed", "bytes32", "log topics are 32-byte values"),
    ("event-indexed", "keccak256", "dynamic indexed arguments use a Keccak-derived topic representation"),

    # Calls / context
    ("this", "calls", "this.f() routes through an external message call"),
    ("this", "msg.sender", "inside the externally re-entered function msg.sender becomes the current contract"),
    ("this", "reentrancy", "an external self-call creates a new call frame and re-entry boundary"),
    ("super", "inheritance", "super selects the next inherited implementation"),
    ("super", "override-virtual", "super is useful when an override extends base behavior"),
    ("contract-types", "this", "this has the current contract type"),
    ("contract-types", "super", "super is a contract-typed inheritance reference"),
    ("external-function-types", "abi.encodeCall", "function pointers are accepted by encodeCall"),
    ("function-types", "calls", "stored function values can later be invoked"),
    ("function-types", "types", "function values are typed values"),
    ("address-payable", "call", "value-bearing call syntax requires an Ether-capable address"),
    ("calls", "gas", "call execution is bounded by gas and the supplied forwarding choice"),
    ("staticcall", "gas", "static execution still consumes a gas budget"),
    ("delegatecall", "gas", "delegated execution shares the gas context subject to call semantics"),

    # Storage / transient / namespaces
    ("erc7201", "custom-storage-layout", "ERC-7201 is a namespaced storage-layout convention with a deterministic root"),
    ("erc7201", "structs", "a namespace is commonly represented as a dedicated struct"),
    ("erc7201", "mapping", "namespaced structs can contain mappings"),
    ("erc7201", "keccak256", "the ERC-7201 root formula is hash-derived"),
    ("erc7201", "abi.encode", "the root formula uses ABI encoding around the intermediate hash value"),
    ("erc7201", "yul-storage", "assembly is commonly used to bind a storage reference to a namespace root"),
    ("custom-storage-layout", "storage-layout", "custom layout shifts the root used by ordinary slot assignment"),
    ("custom-storage-layout", "mapping-slots", "shifted mapping anchor slots change derived locations"),
    ("transient-storage", "storage-layout", "transient and normal storage have independent layouts"),
    ("transient-storage", "contract-anatomy", "transient state is another state-bearing mechanism"),
    ("transient-storage", "tload", "TLOAD reads transaction-scoped transient state"),
    ("transient-storage", "tstore", "TSTORE writes transaction-scoped transient state"),
    ("transient-storage", "reentrancy", "a transaction-scoped lock can guard against nested entry"),
    ("yul-storage", "transient-storage", "Yul exposes transient operations separately from sload/sstore"),
    ("storage-packing", "assignment", "packed members may require read-modify-write behavior"),
    ("storage-packing", "yul-storage", "assembly must preserve neighboring packed bits"),
    ("mapping-defaults", "delete", "missing/deleted mapping values read the type default"),
    ("mapping-defaults", "types-defaults", "the observed zero value depends on the value type"),
    ("mapping-array-value", "array-storage", "a dynamic array used as a mapping value has both mapping and array layout rules"),
    ("mapping-struct", "storage-layout", "mapping-selected structs still follow struct member layout"),
    ("arrays-mappings", "mapping-array-value", "the two descriptions meet when an array is itself the mapping value"),

    # Crypto / identifiers
    ("sha256", "signature-verification", "SHA-256 may be used in external signing/bridging schemes"),
    ("ripemd160", "signature-verification", "RIPEMD-160 can identify keys in interoperability schemes"),
    ("ecrecover", "signature-verification", "ECDSA recovery produces the address associated with a signed digest"),
    ("ecrecover", "bytes32", "the signed digest is normally bytes32"),
    ("ecrecover", "address", "recovery yields an address"),
    ("ecrecover", "keccak256", "Ethereum signatures commonly sign a Keccak-derived digest"),
    ("addmod", "mulmod", "both provide modular arithmetic with non-wrapping intermediate computation"),
    ("keccak256", "ecrecover", "a common signature path is hash structured data then recover the signer"),
    ("nonce", "signature-verification", "nonces prevent reuse of an otherwise valid signed message"),
    ("nonce", "mapping", "protocols commonly store nonce state keyed by address"),
    ("nonce", "access-control", "signed authorization often adds a nonce to prevent replay"),
    ("encodePacked", "bytes.concat", "both are compact byte-building tools but have different semantics"),
    ("strings-bytes", "bytes.concat", "dynamic text/bytes can be joined with concat helpers"),
    ("strings-bytes", "string.concat", "strings can be combined without packed-ABI ambiguity"),
    ("front-running", "nonce", "ordered transactions and replay protection interact with signed intent"),

    # Code lifetime / deployment
    ("selfdestruct", "address-payable", "the opcode takes an Ether-capable recipient"),
    ("selfdestruct", "contract-balance", "its core effect includes sending the account balance"),
    ("selfdestruct", "new", "same-transaction-created contracts are a version-specific exception"),
    ("selfdestruct", "delegatecall", "delegated code can reach the opcode even when absent from the proxy source"),
    ("selfdestruct", "poc-upgrade", "upgrade security reviews inspect destructive/deactivation mechanisms"),

    # Real protocol patterns
    ("poc-token", "low-level-call", "token PoCs often need to reason about non-standard ERC-20 return behavior"),
    ("poc-token", "events", "token actions are observable through transfer/approval logs"),
    ("poc-token", "mapping", "standard token accounting commonly uses balance/allowance mappings"),
    ("poc-oracle", "staticcall", "read-only oracle queries can use a static call boundary"),
    ("poc-oracle", "timestamp", "price freshness checks frequently compare timestamps"),
    ("poc-signature", "nonce", "signature PoCs often probe replay"),
    ("poc-upgrade", "storage-layout", "upgrade safety depends on preserving storage semantics"),
    ("poc-upgrade", "erc7201", "namespaced storage is a modern upgrade-layout pattern"),
    ("poc-dos", "gas", "denial of service can arise when work exceeds available gas"),
    ("poc-dos", "front-running", "ordering/griefing attacks can be operationally related to denial of service"),
])


# Exact catalog-to-catalog anchors make the coverage invariant independent of
# non-catalog helper concepts such as block.number or memory.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("vm-start-prank", "vm-prank", "startPrank is the multi-call form of prank"),
    ("vm-roll", "vm-warp", "roll and warp both manipulate block context in tests"),
    ("yul-memory", "yul", "Yul memory operations are part of the Yul language surface"),
])

# Compound concepts that represent especially useful data-flow paths.
_COMPREHENSIVE_COMPOSITES.update({
    "abi-call": {"abi.encodeCall", "function-types", "function-selector", "calldata"},
    "selector-path": {"function-signature", "function-selector", "calldata", "abi.decode"},
    "error-path": {"custom-errors", "function-selector", "abi.decode", "returndata", "try-catch"},
    "event-path": {"events", "event-indexed", "keccak256", "bytes32", "abi.encode"},
    "mapping-array": {"mapping", "mapping-array-value", "arrays", "array-storage"},
    "mapping-struct-storage": {"mapping", "mapping-struct", "storage-layout"},
    "namespace-storage": {"erc7201", "custom-storage-layout", "structs", "mapping", "keccak256", "yul-storage"},
    "transient-lock": {"transient-storage", "reentrancy", "yul-storage"},
    "signature-path": {"abi.encode", "keccak256", "ecrecover", "address", "nonce"},
    "token-call": {"interface", "external-call", "abi.encode", "low-level-call", "returndata", "events", "mapping"},
})


# High-value compact scenes from the coverage pass.  They keep the default
# output readable while making less-obvious relationships actually teachable.
COMPREHENSIVE_MICRO_SCENES.extend([
    _scene(
        keys={"mapping", "mapping-defaults", "delete", "types-defaults"},
        title="Missing key, delete, and default value",
        story="A mapping does not need an explicit write to have a readable value. Missing entries read as the value type's default, and delete restores that same default.",
        code="""mapping(address => uint256) public score;

function clear(address user_) external {
    delete score[user_];
}""",
        variables=[
            ("state", "mapping(address => uint256)", "score", "score[user_]", "Per-address value."),
            ("key", "address", "user_", "0xAlice", "Selects one entry."),
            ("default", "uint256", "score[user_]", "0", "What a missing/deleted uint256 entry reads as."),
        ],
        flow=[
            "Before any write, score[alice] reads 0.",
            "score[alice] = 100 changes the mapping entry.",
            "delete score[alice] writes the default value back.",
            "Reading score[alice] again returns 0.",
        ],
        call="clear(alice);",
        audit="Default reads are not evidence that state was explicitly initialized. Distinguish absence/default from an intentional stored zero.",
    ),
    _scene(
        keys={"mapping", "mapping-array-value", "arrays", "array-storage"},
        title="One key selects a whole dynamic array",
        story="A mapping value can be an array. The key selects the array, and the array index selects an element inside that array.",
        code="""mapping(address => uint256[]) public scores;

function add(address user_, uint256 score_) external {
    scores[user_].push(score_);
}

function read(address user_, uint256 i)
    external
    view
    returns (uint256)
{
    return scores[user_][i];
}""",
        variables=[
            ("mapping key", "address", "user_", "0xAlice", "Selects Alice's array."),
            ("array", "uint256[]", "scores[user_]", "[10, 20, 30]", "Dynamic array value of the mapping entry."),
            ("index", "uint256", "i", "1", "Selects one array element."),
        ],
        flow=[
            "scores[user_] selects the array belonging to user_.",
            "push(score_) grows that selected array.",
            "scores[user_][i] then indexes inside the selected array.",
        ],
        call="add(alice, 40);",
        audit="Nested [] syntax can hide two distinct operations: mapping key selection first, then array indexing.",
    ),
    _scene(
        keys={"mapping", "mapping-struct", "structs", "storage-layout"},
        title="Mapping key → struct base → struct member",
        story="A mapping can select a complete struct; accessing a member then moves through that struct's storage layout.",
        code="""struct User {
    uint128 points;
    uint128 debt;
    address owner;
}

mapping(address => User) public users;

function set(address user_, uint128 points_) external {
    users[user_].points = points_;
}""",
        variables=[
            ("mapping key", "address", "user_", "0xAlice", "Selects one User struct."),
            ("struct", "User", "users[user_]", "points/debt/owner", "Stored record."),
            ("member", "uint128", "points", "100", "Member potentially packed with debt."),
        ],
        flow=[
            "user_ selects the mapping entry.",
            "That entry has the User struct layout.",
            "points is located within that struct according to packing/layout rules.",
            "The assignment writes only the relevant member bits while preserving neighboring packed data.",
        ],
        call="set(alice, 100);",
        audit="Packed structs are especially important in upgrade/storage-corruption reviews; a member write may be a read-modify-write of a shared slot.",
    ),
    _scene(
        keys={"function-selector", "abi.encodeWithSelector", "abi.encodeCall", "function-types", "calldata"},
        title="Typed function pointer → selector → calldata",
        story="Modern Solidity can derive calldata from an actual function pointer, giving the compiler the chance to type-check the arguments.",
        code="""interface ITarget {
    function set(uint256 amount_) external;
}

function build(address target, uint256 amount_)
    external
    pure
    returns (bytes memory)
{
    ITarget targetContract = ITarget(target);

    return abi.encodeCall(
        targetContract.set,
        (amount_)
    );
}""",
        variables=[
            ("interface", "ITarget", "targetContract", "0xTarget", "Typed contract/function surface."),
            ("function value", "function", "targetContract.set", "selector + address", "External function pointer."),
            ("argument", "uint256", "amount_", "100", "Typed call argument."),
            ("calldata", "bytes", "return value", "selector + ABI argument", "Ready-to-send payload."),
        ],
        flow=[
            "The interface supplies the callable function type.",
            "targetContract.set contributes the target address and selector.",
            "abi.encodeCall type-checks amount_ against the function parameter.",
            "The result is selector-prefixed calldata.",
        ],
        call="build(target, 100);",
        audit="Type-safe encoding reduces some call-construction mistakes, but verify the target address and selector still reach the intended contract.",
    ),
    _scene(
        keys={"bytes", "calldata", "function-selector", "abi.decode", "calldata-slices"},
        title="Raw calldata → first 4 bytes → arguments",
        story="Fallback-style code can treat calldata as raw bytes, remove the selector, and decode the remaining ABI payload.",
        code="""fallback(bytes calldata input) external returns (bytes memory) {
    bytes4 selector = bytes4(input[:4]);

    if (selector == bytes4(keccak256("set(uint256)"))) {
        (uint256 amount_) =
            abi.decode(input[4:], (uint256));
        amount_;
    }

    return "";
}""",
        variables=[
            ("raw", "bytes calldata", "input", "selector + argument", "Complete call data."),
            ("selector", "bytes4", "selector", "first 4 bytes", "Dispatch key."),
            ("payload", "bytes calldata", "input[4:]", "ABI-encoded uint256", "Argument region."),
            ("decoded", "uint256", "amount_", "100", "Typed argument."),
        ],
        flow=[
            "input contains both selector and ABI arguments.",
            "input[:4] extracts the selector.",
            "input[4:] removes the selector from the decoding payload.",
            "abi.decode interprets the remaining bytes as uint256.",
        ],
        call="raw calldata = selector(set(uint256)) + abi.encode(100)",
        audit="Validate length before slicing and decode the exact expected types/order. Fallback dispatch is a manual ABI implementation.",
    ),
    _scene(
        keys={"new", "constructor", "address", "try-catch"},
        title="Contract creation is an external failure boundary",
        story="new creates a contract and runs its constructor. The creation can fail, and try/catch can handle that failure at the caller.",
        code="""contract Child {
    constructor(uint256 limit_) {
        require(limit_ > 0);
    }
}

function deploy(uint256 limit_)
    external
    returns (address created)
{
    try new Child(limit_) returns (Child child) {
        created = address(child);
    } catch {
        created = address(0);
    }
}""",
        variables=[
            ("argument", "uint256", "limit_", "100", "Constructor input."),
            ("contract", "Child", "child", "fresh instance", "Created contract reference."),
            ("address", "address", "created", "0xNewChild", "Address of the new contract."),
        ],
        flow=[
            "new Child(limit_) starts contract creation.",
            "Child's constructor validates limit_.",
            "Success returns a fresh contract reference.",
            "Constructor failure is caught by the surrounding try/catch.",
        ],
        call="deploy(100);",
        audit="Creation-time side effects and constructor assumptions belong to the external boundary just like normal calls.",
    ),
    _scene(
        keys={"transient-storage", "reentrancy", "storage", "yul"},
        title="Transaction-scoped lock: transient vs persistent storage",
        story="A reentrancy lock can live in transient storage so it survives nested calls within the transaction but does not persist across transactions.",
        code="""uint256 transient locked;

modifier nonReentrant() {
    require(locked == 0);
    locked = 1;
    _;
    locked = 0;
}

function withdraw() external nonReentrant {
    // protected work
}""",
        variables=[
            ("transient state", "uint256 transient", "locked", "0 → 1", "Transaction-scoped guard."),
            ("modifier", "modifier", "nonReentrant", "guard", "Wraps the protected function."),
            ("global", "address", "msg.sender", "caller", "Still follows the call context."),
        ],
        flow=[
            "First entry sees locked == 0.",
            "The modifier sets the transient word to 1.",
            "A nested entry in the same transaction sees 1 and reverts.",
            "After normal completion, the lock is cleared.",
        ],
        call="withdraw();",
        audit="Transient storage is transaction-scoped, not a replacement for all persistent state. Check chain/EVM support and reentrant paths carefully.",
    ),
    _scene(
        keys={"erc7201", "custom-storage-layout", "structs", "mapping", "keccak256", "abi.encode", "yul-storage"},
        title="Namespace → hash-derived root → struct storage",
        story="Modern upgradeable code can put a contract's state inside a deterministic namespaced struct, then bind a storage reference to that root.",
        code="""struct MainStorage {
    uint256 total;
    mapping(address => uint256) balances;
}

// Conceptual ERC-7201 root:
// root = keccak256(
//     abi.encode(uint256(keccak256(bytes("example.main"))) - 1)
// ) & ~bytes32(uint256(0xff));""",
        variables=[
            ("namespace", "string", "id", '"example.main"', "Human-readable namespace identifier."),
            ("root", "bytes32", "root", "hash-derived", "Namespace storage root."),
            ("struct", "MainStorage", "store", "total + balances", "State grouped under that root."),
            ("mapping", "mapping(address => uint256)", "balances", "balances[user]", "Normal mapping rules apply inside the namespace."),
        ],
        flow=[
            "The namespace id is hashed.",
            "The formula derives a storage root outside the standard linear storage tree.",
            "A struct is treated as the namespace's state container.",
            "Mappings inside the struct still derive their own child locations.",
            "Assembly can bind a storage reference to the namespace root.",
        ],
        call="_getMainStorage().balances(alice);",
        audit="Namespace uniqueness and exact root calculation are part of upgrade compatibility. Treat the annotation as documentation unless tooling validates the implementation.",
    ),
    _scene(
        keys={"poc-token", "interface", "low-level-call", "abi.encode", "returndata", "events", "mapping"},
        title="Token PoC: interface → calldata → call → return/log/state",
        story="A token interaction touches nearly every boundary an auditor needs to trace: typed interface, ABI bytes, external call, returndata, events, and mapping-backed accounting.",
        code="""interface IERC20Like {
    function transfer(address to, uint256 amount)
        external
        returns (bool);
}

function sendToken(
    address token,
    address to,
    uint256 amount
) external returns (bool ok) {
    return IERC20Like(token).transfer(to, amount);
}""",
        variables=[
            ("address", "address", "token", "0xToken", "Target contract."),
            ("interface", "IERC20Like", "tokenView", "typed target", "Callable ERC-20 surface."),
            ("arguments", "address/uint256", "to/amount", "Bob/100", "Call inputs."),
            ("return", "bool", "ok", "true", "Reported transfer result."),
        ],
        flow=[
            "The interface supplies the transfer signature.",
            "Solidity encodes the arguments into calldata and crosses the token contract boundary.",
            "The token changes its own accounting and normally emits Transfer.",
            "The return value is decoded according to the interface ABI.",
        ],
        call="sendToken(token, bob, 100);",
        audit="Non-standard tokens can return no data or unexpected data. Production libraries often use low-level calls and explicit return-data checks.",
    ),
    _scene(
        keys={"vm-expect-call", "calls", "abi.encode", "test"},
        title="Test expected call: encode the contract boundary",
        story="Foundry can assert not just the final state but the exact external call a function was supposed to make.",
        code="""function testPaysReceiver() public {
    vm.expectCall(
        receiver,
        abi.encodeCall(receiver.notify, (100))
    );

    contract.pay(receiver, 100);
}""",
        variables=[
            ("target", "address/contract", "receiver", "0xReceiver", "Expected destination."),
            ("payload", "bytes", "abi.encodeCall(...)", "selector + 100", "Expected calldata."),
            ("cheatcode", "vm.expectCall", "expectation", "one matching call", "Assertion about the call boundary."),
        ],
        flow=[
            "The test builds the exact expected calldata.",
            "vm.expectCall records the expectation.",
            "The contract executes its real call.",
            "The test fails if the expected boundary is not observed.",
        ],
        call="vm.expectCall(receiver, abi.encodeCall(receiver.notify, (100)));",
        audit="Call expectations are especially useful for authority routing, token transfers, callbacks, and proxy interactions.",
    ),
])

# =============================================================================
# FINAL CONNECT GRAPH PASS
# =============================================================================
#
# This pass intentionally lives at the end of the module so older shortcut
# compatibility data remains intact while the comprehensive graph becomes the
# single authoritative behavior for the connect command.
#
# Important design rule:
#   "recognized" != "has a hand-written pair."
# Every recognized concept gets a semantic identity, graph relationships, and
# either a curated micro-scene or a generated human-sized bridge.

_SEMANTIC_ALIASES.update({
    "function-selector": "function-selector",
    "selector": "function-selector",
    "function-selectors": "function-selector",
    "function-signature": "function-signature",
    "function-signatures": "function-signature",

    "abi-encodewithselector": "abi.encodeWithSelector",
    "abi.encodewithselector": "abi.encodeWithSelector",
    "encodewithselector": "abi.encodeWithSelector",
    "abi-encodewithsignature": "abi.encodeWithSignature",
    "abi.encodewithsignature": "abi.encodeWithSignature",
    "encodewithsignature": "abi.encodeWithSignature",
    "abi-encodecall": "abi.encodeCall",
    "abi.encodecall": "abi.encodeCall",
    "encodecall": "abi.encodeCall",

    # Keep the combined cheatsheet topic distinct from plain keccak256.
    "keccak-selectors": "keccak-selectors",
    "keccak256": "keccak256",
    "keccak": "keccak256",
    "hash": "keccak256",

    "event-indexed": "event-indexed",
    "indexed": "event-indexed",
    "returndata": "returndata",
    "return-data": "returndata",
    "return-data-bytes": "returndata",

    "function-type": "function-types",
    "function-types": "function-types",
    "external-function-types": "external-function-types",
    "contract-type": "contract-types",
    "contract-types": "contract-types",
    "user-defined-value-type": "user-defined-value-types",
    "user-defined-value-types": "user-defined-value-types",
    "udvt": "user-defined-value-types",

    "bytes-concat": "bytes.concat",
    "bytes.concat": "bytes.concat",
    "string-concat": "string.concat",
    "string.concat": "string.concat",
    "ecrecover": "ecrecover",
    "sha256": "sha256",
    "ripemd160": "ripemd160",
    "addmod": "addmod",
    "mulmod": "mulmod",
    "nonce": "nonce",

    "transient": "transient-storage",
    "transient-storage": "transient-storage",
    "tload-tstore": "transient-storage",
    "erc7201": "erc7201",
    "custom-storage-layout": "custom-storage-layout",
    "storage-slot": "storage-slot",

    "gas": "gas",
    "gasleft": "gasleft",
    "selfdestruct": "selfdestruct",

    "calls": "calls",
    "low-level-call": "low-level-call",
    "call": "call",
    "staticcall": "staticcall",
    "delegatecall": "delegatecall",
    "this-call": "this-call",

    "string": "string",
    "uint": "uint256",
    "uint256": "uint256",
    "int": "int256",
    "int256": "int256",
    "bool": "bool",
})

_EXTRA_MEANINGS.update({
    "keccak256": "Keccak-256 hashes bytes and returns the digest as bytes32. A function selector is one specific use of a Keccak digest, not the meaning of keccak256 itself.",
    "keccak-selectors": "The combined pattern of Keccak hashing and selector derivation: hash a canonical signature, then take its leading four bytes.",
    "abi.encode": "Standard ABI encoding of typed values into bytes.",
    "abi.decode": "Interpret ABI-encoded bytes as the exact Solidity types and order you specify.",
    "abi.encodeWithSelector": "Build calldata by prepending a supplied four-byte selector to ABI-encoded arguments.",
    "abi.encodeWithSignature": "Build calldata from a textual canonical signature; the signature is hashed into the four-byte selector first.",
    "abi.encodeCall": "Build calldata from a typed function expression and its arguments, with compile-time type checking.",
    "function-selector": "The first four bytes of the Keccak-256 hash of a canonical external function signature.",
    "function-signature": "The canonical function name plus parameter types used for selector derivation.",
    "event-indexed": "An indexed event parameter is stored in a log topic; dynamic/complex indexed values are represented by a hash rather than their original full value.",
    "returndata": "Raw bytes returned by an external call, or raw revert bytes exposed by low-level/EVM interfaces.",
    "function-types": "Function values can be stored or passed around as typed callable values.",
    "external-function-types": "An external function pointer carries a target address and selector, giving a later call enough information to cross the contract boundary.",
    "contract-types": "A contract/interface declaration creates a contract-specific type that refers to deployed code at an address.",
    "user-defined-value-types": "A distinct type wrapping an elementary value type, used to prevent accidental mixing of domain values.",
    "transient-storage": "Transaction-scoped storage with a layout separate from ordinary persistent storage; its contents disappear at transaction end.",
    "erc7201": "A namespaced storage-root convention that derives deterministic module storage roots.",
    "custom-storage-layout": "Compiler-supported control over storage-layout bases for advanced storage organization.",
    "storage-slot": "A 32-byte EVM storage location used when reasoning about storage layout, mappings, arrays, and Yul.",
    "ecrecover": "Recover an address from an ECDSA digest and signature components.",
    "sha256": "The SHA-256 hash function returning bytes32.",
    "ripemd160": "The RIPEMD-160 hash function returning bytes20.",
    "addmod": "Compute modular addition with the arithmetic performed without intermediate uint256 wraparound.",
    "mulmod": "Compute modular multiplication with the arithmetic performed without intermediate uint256 wraparound.",
    "bytes.concat": "Concatenate bytes/fixed-byte values into a dynamic bytes result.",
    "string.concat": "Concatenate strings into one dynamic string result.",
    "nonce": "A sequence value commonly used to prevent replay of signed or state-changing actions.",
    "selfdestruct": "A special EVM operation whose effects depend on the current EVM semantics; old tutorials often describe behavior that no longer applies generally after Cancun.",
    "gas": "The execution budget that constrains how much work a call can perform.",
    "calls": "The family of function/message-call surfaces, including typed calls and low-level call operations.",
    "low-level-call": "Raw external message-call syntax exposing calldata, ETH/gas options, success, and return bytes.",
})

_EXTRA_CONCEPTS.update({
    "function-selector", "function-signature",
    "abi.encodeWithSelector", "abi.encodeWithSignature", "abi.encodeCall",
    "event-indexed", "returndata",
    "function-types", "external-function-types", "contract-types",
    "user-defined-value-types", "transient-storage",
    "erc7201", "custom-storage-layout", "storage-slot",
    "ecrecover", "sha256", "ripemd160", "addmod", "mulmod",
    "bytes.concat", "string.concat", "nonce", "selfdestruct", "gas",
    "string", "uint256", "int256", "bool", "calls", "call", "low-level-call",
})

_COMPREHENSIVE_COMPOSITES.update({
    "keccak-selectors": {"keccak256", "function-selector", "function-signature"},
    "abi-call": {"function-selector", "abi.encode", "calldata", "call"},
    "typed-abi-call": {"function-types", "abi.encodeCall", "calldata"},
    "raw-call-path": {
        "function-selector", "abi.encodeWithSelector", "calldata",
        "call", "returndata", "abi.decode",
    },
    "signature-verification-path": {
        "abi.encode", "keccak256", "signature-verification",
        "ecrecover", "nonce",
    },
    "permit-path": {
        "mapping", "keccak256", "abi.encode", "ecrecover", "nonce",
        "block.timestamp", "address", "signature-verification",
    },
    "event-path": {"function", "events", "event-indexed", "keccak256"},
    "array-storage-path": {"arrays", "array-storage", "storage-layout", "keccak256", "yul-storage"},
    "proxy-flow": {
        "proxy-fallback", "fallback", "delegatecall", "storage-layout",
        "function-selector", "calldata", "returndata",
    },
    "error-path": {"require", "revert", "errors", "custom-errors", "returndata", "abi.decode"},
    "yul-storage-path": {"mapping", "mapping-slots", "keccak256", "storage", "yul-storage"},
})

_FINAL_TINY_EDGES = [
    ("mapping", "keccak256", "mapping values are located using Keccak-derived storage coordinates"),
    ("mapping", "abi.decode", "decoded bytes can produce the key used by a mapping"),
    ("abi.decode", "keccak256", "the same raw bytes can be decoded and independently hashed"),
    ("abi.encode", "abi.decode", "compatible ABI encoding can later be decoded in the same type/order"),
    ("abi.encode", "keccak256", "encoded bytes are common input to a digest"),
    ("abi.encodeWithSignature", "function-signature", "the textual signature determines the selector"),
    ("abi.encodeWithSignature", "keccak256", "signature encoding hashes the canonical signature to derive the selector"),
    ("abi.encodeWithSelector", "function-selector", "the selector is supplied explicitly at the front of calldata"),
    ("abi.encodeWithSelector", "calldata", "the result is selector-prefixed call data"),
    ("abi.encodeCall", "function-types", "a typed function expression supplies the callable shape"),
    ("abi.encodeCall", "interface", "an interface function can supply a compile-time checked call target/shape"),
    ("function-selector", "msg.sig", "msg.sig is the selector seen in the current call frame"),
    ("function-selector", "calldata", "normal function calldata starts with the selector"),
    ("function-signature", "function-selector", "the selector is derived from the canonical signature"),
    ("function-selector", "call", "low-level callers can construct a call by supplying the selector"),
    ("function-selector", "fallback", "fallback can manually inspect/select on the incoming selector"),
    ("calldata", "msg.data", "msg.data is the complete raw call payload"),
    ("calldata", "calldata-slices", "calldata can be sliced into selector and argument regions"),
    ("calldata-slices", "abi.decode", "the argument region can be decoded after removing the selector"),
    ("call", "returndata", "low-level calls expose success plus raw returned bytes"),
    ("staticcall", "returndata", "static reads still return raw bytes"),
    ("delegatecall", "returndata", "delegated execution can bubble implementation return/revert bytes"),
    ("returndata", "abi.decode", "raw successful return bytes can be decoded into typed values"),
    ("returndata", "custom-errors", "raw revert bytes can contain a custom-error selector and arguments"),
    ("errors", "function-selector", "error payloads also use a four-byte Keccak-derived selector"),
    ("errors", "abi.decode", "error arguments have ABI-shaped data"),
    ("errors", "returndata", "reverted external calls expose error bytes"),
    ("event-indexed", "keccak256", "dynamic indexed event values are represented by a hash topic"),
    ("events", "event-indexed", "indexed parameters become log topics"),
    ("events", "mapping", "logs commonly mirror state transitions such as mapping updates"),
    ("events", "function", "functions commonly emit logs after state changes"),
    ("mapping", "storage-slot", "a mapping declaration has an anchor slot used in location derivation"),
    ("arrays", "storage-slot", "dynamic arrays have an anchor slot from which element locations are derived"),
    ("array-storage", "keccak256", "dynamic array data locations are hash-derived"),
    ("nested-mapping", "mapping-slots", "nested mapping lookup repeats mapping slot derivation"),
    ("mapping-slots", "yul-storage", "Yul can reproduce mapping slot arithmetic and sload/sstore the result"),
    ("storage-layout", "yul-storage", "Yul provides the low-level lens for storage coordinates"),
    ("transient-storage", "yul-storage", "transient storage has tload/tstore rather than persistent sload/sstore"),
    ("transient-storage", "reentrancy", "a transaction-scoped guard can protect a reentrancy-sensitive boundary"),
    ("erc7201", "keccak256", "namespace roots are hash-derived"),
    ("erc7201", "custom-storage-layout", "ERC-7201 is a namespaced storage-layout pattern"),
    ("erc7201", "structs", "namespaced application state is commonly grouped in a struct"),
    ("erc7201", "mapping", "mappings can live inside a namespaced state struct"),
    ("erc7201", "yul-storage", "assembly can inspect a namespaced root and child slots"),
    ("signature-verification", "ecrecover", "ECDSA signature verification commonly recovers an address"),
    ("signature-verification", "nonce", "signed authorizations commonly bind an action to a nonce"),
    ("signature-verification", "keccak256", "verification operates on a signed digest"),
    ("signature-verification", "abi.encode", "structured authorization fields are encoded before hashing"),
    ("ecrecover", "address", "ecrecover returns an address"),
    ("nonce", "mapping", "per-user nonces are commonly stored in a mapping"),
    ("nonce", "block.timestamp", "signed authorizations often combine a nonce with an expiry timestamp"),
    ("front-running", "nonce", "nonces prevent replay but do not automatically hide public transaction inputs"),
    ("front-running", "keccak256", "commit-reveal schemes can hide the meaningful value behind a hash"),
    ("eip712", "keccak256", "typed-data digests are hash-derived"),
    ("eip712", "abi.encode", "typed-data struct hashes are ABI-encoded before hashing"),
    ("eip712", "ecrecover", "verification ends by recovering/checking the signer"),
    ("bytes", "bytes.concat", "dynamic byte sequences can be concatenated"),
    ("string", "string.concat", "text values can be concatenated"),
    ("bytes", "keccak256", "hash functions consume byte sequences"),
    ("bytes32", "keccak256", "Keccak-256 returns bytes32"),
    ("addmod", "mulmod", "both implement modular arithmetic"),
    ("addmod", "uint256", "the operands/result are integer values"),
    ("mulmod", "uint256", "the operands/result are integer values"),
    ("unchecked", "addmod", "unchecked wraparound and modular arithmetic solve different arithmetic problems"),
    ("unchecked", "mulmod", "mulmod can express modulo arithmetic without unchecked multiplication"),
    ("function-types", "function", "a function value is a typed reference to callable behavior"),
    ("external-function-types", "address", "an external function pointer includes a target address"),
    ("external-function-types", "function-selector", "an external function pointer includes a selector"),
    ("external-function-types", "call", "invoking an external function pointer crosses a message boundary"),
    ("contract-types", "address", "contract values can be converted to addresses in allowed contexts"),
    ("contract-types", "interface", "interfaces are contract types defining callable surfaces"),
    ("type-metadata", "contract-types", "type(C) exposes metadata about contract types"),
    ("new", "constructor", "new starts contract creation and invokes the constructor"),
    ("new", "try-catch", "contract creation failures can be caught"),
    ("new", "address", "a created contract can be viewed through its address"),
    ("selfdestruct", "contract-balance", "selfdestruct semantics are tied to the current contract/balance"),
    ("selfdestruct", "ether-flow", "destruction semantics can create unusual Ether-flow assumptions"),
    ("constant-immutable", "constructor", "immutable values can be fixed during construction"),
    ("constant-immutable", "storage-layout", "constants/immutables differ from ordinary storage slots"),
    ("receive", "payable", "receive must be payable"),
    ("fallback", "payable", "payable fallback can accept Ether"),
    ("fallback", "msg.data", "fallback sees raw calldata"),
    ("fallback", "msg.sig", "fallback can inspect the selector"),
    ("receive", "msg.value", "receive executes for empty-calldata Ether with msg.value"),
    ("msg.value", "contract-balance", "current call value is an inflow, total contract balance is the held amount"),
    ("msg.sender", "tx.origin", "immediate caller and transaction origin diverge across call chains"),
    ("msg.sender", "delegatecall", "delegatecall preserves the external caller as msg.sender"),
    ("msg.value", "delegatecall", "delegatecall preserves call value/context"),
    ("vm-prank", "msg.sender", "Foundry prank controls the caller seen by Solidity"),
    ("vm-start-prank", "msg.sender", "startPrank keeps a controlled caller across a sequence"),
    ("vm-hoax", "vm-prank", "hoax combines caller manipulation with funded balance setup"),
    ("vm-hoax", "vm-deal", "hoax includes balance provisioning"),
    ("vm-deal", "contract-balance", "deal changes the test EVM balance observed through address.balance"),
    ("vm-warp", "block.timestamp", "warp controls timestamp in tests"),
    ("vm-roll", "block.number", "roll controls block number in tests"),
    ("vm-expect-revert", "errors", "tests can match custom-error/revert behavior"),
    ("vm-expect-emit", "event-indexed", "event assertions can inspect indexed topics"),
    ("error-data", "errors", "custom-error failures cross the boundary as raw error bytes"),
    ("error-data", "returndata", "low-level failure paths expose error bytes as returndata"),
    ("error-data", "abi.decode", "error arguments can be decoded from the raw payload"),
    ("vm-recordlogs", "events", "recordLogs exposes emitted logs to tests"),
    ("vm-expect-call", "abi.encodeCall", "expected calls can be specified with typed ABI encoding"),
    ("vm-mockcall", "returndata", "mocked call return bytes flow into the caller"),
    ("vm-storage", "storage-slot", "raw slot assertions turn storage layout into testable state"),
    ("vm-etch", "contract-types", "etch changes code at an address in the test EVM"),
    ("vm-fork", "oracle", "forks reproduce external oracle/protocol state"),
    ("fuzz-tests", "vm-assume", "assumptions constrain fuzz domains"),
    ("bounded-fuzz", "vm-bound", "bound normalizes fuzz values into an interval"),
    ("invariant-tests", "invariant-handler", "handlers shape the transition surface of invariant tests"),
    ("test-arrange-act-assert", "test-assertions", "AAA separates setup, action, and expected result"),
    ("poc-reentrancy", "call", "the PoC uses an external call as the callback boundary"),
    ("poc-reentrancy", "receive", "attacker code can re-enter through receive"),
    ("poc-reentrancy", "mapping", "victim accounting is commonly stored per address"),
    ("poc-token", "mapping", "token balances/allowances are mapping-backed"),
    ("poc-token", "interface", "token interactions normally use interfaces"),
    ("poc-token", "returndata", "non-standard tokens make return-data handling important"),
    ("poc-signature", "nonce", "signature PoCs often probe replay protection"),
    ("poc-upgrade", "proxy-fallback", "upgrade PoCs target proxy dispatch/storage assumptions"),
    ("poc-storage", "mapping-slots", "storage PoCs can calculate and modify derived mapping locations"),
    ("poc-dos", "loops", "unbounded loops can make a state transition unexecutable"),
    ("poc-dos", "arrays", "growing arrays are a common unbounded-loop source"),
]


def _append_unique_edges(edges):
    existing = {
        tuple(sorted((canonicalize(left), canonicalize(right))))
        for left, right, _label in edges
        if canonicalize(left) != canonicalize(right)
    }
    for left, right, label in _FINAL_TINY_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        if key not in existing:
            edges.append((a, b, label))
            existing.add(key)


_append_unique_edges(_COMPREHENSIVE_CONNECTION_EDGES)

_FINAL_DENSE_GROUPS = [
    [
        "variables", "types", "uint256", "int256", "bool", "address", "bytes",
        "bytesN", "bytes32", "string", "structs", "enum", "arrays",
        "fixed-array", "mapping", "nested-mapping", "mapping-struct",
        "mapping-array-value", "storage-memory-calldata", "storage",
        "storage-layout", "storage-packing", "array-storage", "mapping-slots",
        "nested-mapping-slots", "delete", "transient-storage",
        "custom-storage-layout", "erc7201", "user-defined-value-types",
    ],
    [
        "function", "visibility", "mutability", "returns", "parameter-vs-argument",
        "function-signature", "function-selector", "function-types",
        "external-function-types", "contract-types", "interface",
        "calldata", "calldata-deep", "calldata-slices", "call-data-layout",
        "abi", "abi.encode", "abi.decode", "abi.encodeWithSelector",
        "abi.encodeWithSignature", "abi.encodeCall", "encodePacked", "msg.data",
        "msg.sig", "call", "calls", "low-level-call", "external-call",
        "staticcall", "delegatecall", "returndata", "try-catch",
    ],
    [
        "keccak256", "keccak-selectors", "function-signature", "function-selector",
        "abi.encode", "abi.decode", "encodePacked", "ecrecover", "sha256",
        "ripemd160", "addmod", "mulmod", "bytes32", "signature-verification",
        "eip712", "nonce", "front-running", "events", "event-indexed",
        "custom-errors", "errors",
    ],
    [
        "imports", "constructor", "inheritance", "abstract", "override",
        "virtual", "interface", "library", "using-for", "new",
        "constant-immutable", "type-metadata", "contract-types", "function-types",
        "external-function-types", "user-defined-value-types",
        "proxy-fallback", "fallback", "receive", "selfdestruct",
    ],
    [
        "msg.sender", "msg.value", "msg.data", "msg.sig", "block.timestamp",
        "block.number", "tx.origin", "gas", "gasleft", "contract-balance",
        "payable", "ether-flow", "receive", "fallback", "call", "staticcall",
        "delegatecall", "reentrancy", "checks-effects-interactions",
    ],
    [
        "if-else", "ternary", "loops", "for", "while", "do-while", "for-each",
        "unchecked", "require", "revert", "assert", "errors", "custom-errors",
        "try-catch",
    ],
    [
        "yul", "yul-memory", "yul-storage", "yul-calldata", "yul-control-flow",
        "yul-functions", "yul-call", "memory", "storage", "calldata",
        "mapping-slots", "nested-mapping-slots", "array-storage", "keccak256",
        "call", "returndata", "transient-storage", "gas",
    ],
    [
        "forge-cheatcodes", "forge-cheatcodes-map", "test", "test-structure",
        "test-arrange-act-assert", "test-assertions", "fuzz-tests",
        "bounded-fuzz", "invariant-tests", "invariant-handler", "fork-tests",
        "test-reverts", "test-events", "vm-prank", "vm-start-prank", "vm-deal",
        "vm-warp", "vm-roll", "vm-assume", "vm-bound", "vm-makeaddr", "vm-label",
        "vm-expect-revert", "vm-expect-emit", "vm-recordlogs", "vm-snapshots",
        "vm-storage", "vm-etch", "vm-fork", "vm-env", "vm-expect-call",
        "vm-mockcall", "vm-hoax",
    ],
    [
        "script", "script-structure", "script-broadcast", "script-env",
        "script-deploy", "script-interaction", "poc", "poc-template",
        "poc-reentrancy", "poc-access-control", "poc-accounting",
        "poc-accessible-state", "poc-dos", "poc-oracle", "poc-signature",
        "poc-upgrade", "poc-storage", "poc-token", "poc-cross-contract",
        "test-poc-workflow", "oracle", "access-control", "modifier",
        "signature-verification", "reentrancy", "proxy-fallback",
    ],
]


def _append_dense_group_edges(edges):
    existing = {
        tuple(sorted((canonicalize(left), canonicalize(right))))
        for left, right, _label in edges
        if canonicalize(left) != canonicalize(right)
    }
    for family_index, members in enumerate(_FINAL_DENSE_GROUPS, 1):
        canonical_members = []
        seen = set()
        for member in members:
            node = canonicalize(member)
            if node in seen:
                continue
            seen.add(node)
            canonical_members.append(node)
        if len(canonical_members) < 2:
            continue
        anchor = canonical_members[0]
        for node in canonical_members[1:]:
            if anchor == node:
                continue
            key = tuple(sorted((anchor, node)))
            if key not in existing:
                edges.append(
                    (
                        anchor,
                        node,
                        f"family {family_index}: related subsystem; trace the concrete value/control flow",
                    )
                )
                existing.add(key)


_append_dense_group_edges(_COMPREHENSIVE_CONNECTION_EDGES)


def _final_known_nodes():
    nodes = set()
    for left, right, _label in _COMPREHENSIVE_CONNECTION_EDGES:
        nodes.add(canonicalize(left))
        nodes.add(canonicalize(right))
    nodes.update(canonicalize(name) for name in _EXTRA_CONCEPTS)
    for name, _aliases, _category, _meaning in _CATALOG_ROWS:
        nodes.add(canonicalize(name))
    return nodes


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _COMPREHENSIVE_COMPOSITES:
        return True
    if key in _SEMANTIC_ALIASES:
        return True
    if key in _CATALOG_ALIASES:
        return True
    canonical = canonicalize(name)
    return canonical in _final_known_nodes()


COMPREHENSIVE_MICRO_SCENES.extend([
    {
        "keys": frozenset({
            "mapping", "keccak256", "abi.encode", "ecrecover", "nonce",
            "signature-verification", "block.timestamp", "address",
        }),
        "title": "Permit-style authorization: nonce → hash → recover signer → write allowance",
        "story": "A signed approval path ties together mapping state, a nonce, structured ABI encoding, hashing, signature recovery, expiry, and the final state write.",
        "code": """mapping(address => uint256) public nonces;
mapping(address => mapping(address => uint256)) public allowance;

function approveBySig(
    address owner_,
    address spender_,
    uint256 value_,
    uint256 deadline_,
    uint8 v,
    bytes32 r,
    bytes32 s
) external {
    require(block.timestamp <= deadline_);

    bytes32 digest = keccak256(
        abi.encode(owner_, spender_, value_, nonces[owner_], deadline_)
    );

    address signer = ecrecover(digest, v, r, s);
    require(signer == owner_);

    nonces[owner_]++;
    allowance[owner_][spender_] = value_;
}""",
        "variables": [
            ("state", "mapping(address => uint256)", "nonces", "nonces[owner_]", "Replay-protection state."),
            ("state", "mapping(address => mapping(address => uint256))", "allowance", "allowance[owner_][spender_]", "Nested approval state."),
            ("parameter", "address", "owner_", "0xAlice", "Expected signer."),
            ("parameter", "address", "spender_", "0xBob", "Approved spender."),
            ("parameter", "uint256", "value_", "100", "Approved amount."),
            ("parameter", "uint256", "deadline_", "future timestamp", "Expiry bound."),
            ("derived", "bytes32", "digest", "keccak256(abi.encode(...))", "Signed digest."),
            ("derived", "address", "signer", "ecrecover(...)", "Recovered signer."),
        ],
        "flow": [
            "The caller supplies the signed message fields and signature components.",
            "The contract checks the deadline and includes the current nonce in the digest.",
            "abi.encode creates the exact bytes being hashed.",
            "ecrecover turns the signed digest into an address.",
            "A matching signer permits the nonce increment and nested allowance write.",
        ],
        "call": "approveBySig(alice, bob, 100, deadline, v, r, s);",
    },
    {
        "keys": frozenset({
            "interface", "address", "function-selector", "abi.encodeWithSelector",
            "call", "returndata", "yul",
        }),
        "title": "Safe transfer style: selector → assembly call → returndata",
        "story": "Low-level token libraries often build calldata manually, make a call, then inspect return data because real tokens are not always perfectly ABI-uniform.",
        "code": """bytes4 selector =
    bytes4(keccak256("transfer(address,uint256)"));

assembly {
    mstore(0x00, shl(224, selector))
    mstore(0x04, to)
    mstore(0x24, amount)

    let ok := call(
        gas(),
        token,
        0,
        0,
        0x44,
        0,
        0
    )

    if iszero(ok) {
        returndatacopy(0, 0, returndatasize())
        revert(0, returndatasize())
    }
}""",
        "variables": [
            ("address", "address", "token", "0xToken", "External token target."),
            ("parameter", "address", "to", "0xBob", "Transfer recipient."),
            ("parameter", "uint256", "amount", "100", "Transfer amount."),
            ("selector", "bytes4", "selector", "transfer selector", "Four-byte function identifier."),
            ("Yul", "word", "ok", "0/1", "Low-level call success."),
        ],
        "flow": [
            "The function signature determines a four-byte selector.",
            "Yul writes the selector and arguments into memory in calldata layout.",
            "call crosses the token boundary.",
            "returndatasize/returndatacopy expose failure bytes for bubbling.",
        ],
        "call": "token transfer built as raw calldata",
    },
    {
        "keys": frozenset({
            "mapping", "structs", "keccak256", "storage-layout",
            "library", "using-for", "interface", "function",
        }),
        "title": "Protocol style: hashed ID → state struct → library method → interface hook",
        "story": "Production protocol cores often turn a structured key into an ID, store a state struct under that ID, use libraries to operate on it, and call hook interfaces around state transitions.",
        "code": """struct Pool {
    uint256 liquidity;
}

mapping(bytes32 => Pool) internal pools;

interface IHook {
    function beforeSwap(bytes32 poolId)
        external;
}

library PoolLib {
    function add(Pool storage pool, uint256 amount) internal {
        pool.liquidity += amount;
    }
}

using PoolLib for Pool;

function swap(bytes32 poolId, uint256 amount, IHook hook)
    external
{
    hook.beforeSwap(poolId);

    Pool storage pool = pools[poolId];
    pool.add(amount);
}""",
        "variables": [
            ("state", "mapping(bytes32 => Pool)", "pools", "pools[poolId]", "Pool registry."),
            ("struct", "Pool", "pool", "liquidity", "State selected by the ID."),
            ("library", "PoolLib", "add", "pool.add(amount)", "Attached state mutation."),
            ("interface", "IHook", "hook", "0xHook", "External callback surface."),
        ],
        "flow": [
            "A bytes32 pool ID selects one Pool struct from the mapping.",
            "The hook interface creates an external callback boundary.",
            "A storage reference selects persistent pool state.",
            "using-for turns pool.add(amount) into a readable library operation.",
        ],
        "call": "swap(poolId, 100, hook);",
    },
    {
        "keys": frozenset({
            "arrays", "array-storage", "storage-layout", "keccak256", "yul-storage",
        }),
        "title": "Dynamic array: length slot → hashed data region → element",
        "story": "A dynamic storage array has an anchor slot, while its element data begins from a hash-derived location.",
        "code": """uint256[] public scores;

function readAt(uint256 i)
    external
    view
    returns (uint256 result)
{
    assembly {
        // The array length is at scores.slot.
        // Element data begins at keccak256(scores.slot).
        mstore(0x00, scores.slot)
        let base := keccak256(0x00, 0x20)
        result := sload(add(base, i))
    }
}""",
        "variables": [
            ("state", "uint256[]", "scores", "[10, 20, 30]", "Dynamic storage array."),
            ("slot", "uint256", "scores.slot", "7", "Anchor slot."),
            ("derived", "bytes32", "base", "keccak256(scores.slot)", "Start of element data."),
            ("parameter", "uint256", "i", "1", "Element index."),
        ],
        "flow": [
            "scores.slot stores the dynamic array's length/anchor information.",
            "Keccak derives the beginning of the array's data region.",
            "The index advances from that data-region base.",
            "Yul sload reads the selected word directly.",
        ],
        "call": "readAt(1);",
    },
    {
        "keys": frozenset({
            "errors", "custom-errors", "revert", "function-selector",
            "abi.decode", "returndata", "try-catch",
        }),
        "title": "Error selector → revert bytes → catch → typed meaning",
        "story": "Failure data travels through the same ABI-style boundary as function data: an error has a selector and encoded arguments, then the caller can catch the failure.",
        "code": """error TooSmall(uint256 actual, uint256 minimum);

function check(uint256 amount_) external {
    if (amount_ < 100) {
        revert TooSmall(amount_, 100);
    }
}

try target.check(10) {
    // success
} catch (bytes memory reason) {
    // reason contains the error selector + encoded fields
}""",
        "variables": [
            ("parameter", "uint256", "amount_", "10", "Failing input."),
            ("error", "custom error", "TooSmall", "(10, 100)", "Structured failure."),
            ("catch data", "bytes", "reason", "selector + arguments", "Raw failure bytes."),
        ],
        "flow": [
            "The target sees the invalid amount.",
            "revert creates error-shaped bytes.",
            "The external caller reaches the catch branch.",
            "reason can be inspected/decoded to recover the error meaning.",
        ],
        "call": "target.check(10);",
    },
    {
        "keys": frozenset({
            "bytes", "string", "storage-layout", "keccak256", "storage",
        }),
        "title": "Dynamic bytes/string: value length changes the storage representation",
        "story": "bytes and string are dynamic values, but their storage representation depends on length. Hashing reads their logical contents, not their storage encoding.",
        "code": """string public name;
bytes public payload;

function ids()
    external
    view
    returns (bytes32 nameHash, bytes32 payloadHash)
{
    nameHash = keccak256(bytes(name));
    payloadHash = keccak256(payload);
}""",
        "variables": [
            ("state", "string", "name", '"Alice"', "Dynamic text."),
            ("state", "bytes", "payload", "0x0102", "Dynamic bytes."),
            ("derived", "bytes32", "nameHash", "keccak256(bytes(name))", "Hash of logical text bytes."),
            ("derived", "bytes32", "payloadHash", "keccak256(payload)", "Hash of logical payload bytes."),
        ],
        "flow": [
            "The logical string/bytes value is independent of the physical storage encoding.",
            "bytes(name) exposes the textual byte sequence.",
            "keccak256 hashes the logical bytes.",
            "Storage-layout analysis is separate from value-level hashing.",
        ],
        "call": "ids();",
    },
])


def connection_meaning(name: str) -> str:
    canonical = canonicalize(name)
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]

    raw_key = _norm(name)
    topic_name = _CATALOG_ALIASES.get(raw_key)
    if topic_name:
        meaning = _CATALOG_NAME_TO_MEANING.get(topic_name)
        if meaning:
            return meaning

    topic_name = _CATALOG_ALIASES.get(_norm(canonical))
    if topic_name:
        meaning = _CATALOG_NAME_TO_MEANING.get(topic_name)
        if meaning:
            return meaning

    return f"{canonical} is a recognized Solidity/Foundry concept."


def _generic_connect_scene(nodes):
    ordered = list(dict.fromkeys(canonicalize(node) for node in nodes))
    requested_text = " + ".join(ordered)

    if "mapping" in ordered and "abi.decode" in ordered:
        code = """mapping(address => uint256) public state;

function bridge(bytes calldata raw, uint256 value_) external {
    address key = abi.decode(raw, (address));
    state[key] = value_;
}"""
        flow = [
            "Raw bytes enter the contract.",
            "abi.decode interprets them as a typed value.",
            "The typed value becomes the mapping key.",
            "The mapped state is updated.",
        ]
        variables = [
            ("input", "bytes calldata", "raw", "ABI bytes", "Raw boundary data."),
            ("decoded", "address", "key", "abi.decode(raw, (address))", "Typed key."),
            ("state", "mapping(address => uint256)", "state", "state[key]", "Persistent lookup."),
            ("parameter", "uint256", "value_", "100", "Value written to the selected entry."),
        ]
        call = "bridge(abi.encode(alice), 100);"
    elif "mapping" in ordered and "keccak256" in ordered:
        code = """mapping(bytes32 => address) public state;

function bridge(bytes calldata raw) external {
    bytes32 key = keccak256(raw);
    state[key] = msg.sender;
}"""
        flow = [
            "Raw bytes enter the contract.",
            "keccak256 transforms them into bytes32.",
            "The digest becomes a mapping key.",
            "msg.sender supplies the stored address value.",
        ]
        variables = [
            ("input", "bytes calldata", "raw", "raw bytes", "Hash input."),
            ("derived", "bytes32", "key", "keccak256(raw)", "Mapping key."),
            ("state", "mapping(bytes32 => address)", "state", "state[key]", "Persistent lookup."),
            ("global", "address", "msg.sender", "0xAlice", "Stored value."),
        ]
        call = 'bridge(hex"416c696365");'
    elif "interface" in ordered and ("call" in ordered or "external-call" in ordered):
        code = """interface ITarget {
    function value() external view returns (uint256);
}

function bridge(ITarget target)
    external
    view
    returns (uint256)
{
    return target.value();
}"""
        flow = [
            "An interface value refers to a target address.",
            "The interface defines the callable shape.",
            "The call crosses the contract boundary.",
            "The result returns through the ABI boundary.",
        ]
        variables = [
            ("parameter", "ITarget", "target", "0xTarget", "Typed target."),
            ("function", "uint256", "value()", "42", "Declared return."),
        ]
        call = "bridge(target);"
    elif "yul" in ordered or any(node.startswith("yul-") for node in ordered):
        code = """function bridge(uint256 value_)
    external
    pure
    returns (uint256 result)
{
    assembly {
        result := add(value_, 1)
    }
}"""
        flow = [
            "A normal Solidity value enters the function.",
            "assembly exposes the calculation to Yul.",
            "Yul transforms the word.",
            "The Solidity return variable receives the result.",
        ]
        variables = [
            ("parameter", "uint256", "value_", "41", "Solidity input."),
            ("Yul result", "word", "result", "add(value_, 1)", "Assembly output."),
        ]
        call = "bridge(41);"
    else:
        paths = connection_paths(ordered)
        path = paths[0][2] if paths else ordered
        code = """contract ConnectionBridge {
    // No single Solidity construct owns this combination.
    // The useful route is:
    // __PATH__
}""".replace("__PATH__", " → ".join(path))
        flow = [
            f"Start with {ordered[0]}.",
            f"Use the graph path: {' → '.join(path)}.",
            "The intermediate concepts are the actual bridge; they are not interchangeable syntax.",
            "Then inspect each requested concept's cheat view for its exact compiler rules.",
        ]
        variables = [
            ("requested", "concept", node, "selected", connection_meaning(node))
            for node in ordered
        ]
        call = f"lk cheat {ordered[0]}"

    return {
        "keys": frozenset(ordered),
        "title": f"Guided bridge: {requested_text}",
        "story": (
            "This combination does not have one single canonical Solidity idiom. "
            "Lowkey therefore keeps the lesson small and shows the strongest semantic "
            "bridge instead of dumping the universal contract."
        ),
        "code": code.strip("\n"),
        "variables": variables,
        "flow": flow,
        "call": call,
        "generic": True,
    }


def find_micro_scene(names):
    requested = frozenset(canonicalize(name) for name in names)

    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if frozenset(scene.get("keys", ())) == requested
    ]
    if exact:
        return exact[0]

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= frozenset(scene.get("keys", ()))
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(frozenset(scene.get("keys", ())) - requested),
                0 if scene.get("route_name") else 1,
                0 if any(tag in scene.get("title", "").lower()
                         for tag in ("erc20:", "erc721:", "erc1155:", "eip712:", "timelock:",
                                     "governor:", "multisig:", "upgrade proxy", "public getter"))
                else 1,
                len(frozenset(scene.get("keys", ()))),
                scene.get("title", ""),
            )
        )
        return candidates[0]

    return _generic_connect_scene(list(requested))


def list_connections():
    return [
        {
            "name": "solidity-yul-comprehensive-graph",
            "aliases": ["graph", "comprehensive"],
            "concepts": ["all recognized Solidity/Yul/Foundry concepts"],
            "summary": (
                f"{len(_COMPREHENSIVE_CONNECTION_EDGES)} semantic graph edges, "
                f"{len(COMPREHENSIVE_MICRO_SCENES)} curated micro-scenes, and a "
                "generated bridge for combinations without a dedicated scene."
            ),
        },
        {
            "name": "decode/hash/mapping",
            "aliases": [],
            "concepts": ["mapping", "abi.decode", "keccak256"],
            "summary": "Same raw bytes can be decoded into a typed value and independently hashed into a mapping key.",
        },
        {
            "name": "ABI call path",
            "aliases": [],
            "concepts": ["function-selector", "abi.encodeCall", "call", "returndata", "abi.decode"],
            "summary": "Typed function → selector/calldata → external call → raw return bytes → typed value.",
        },
        {
            "name": "proxy flow",
            "aliases": [],
            "concepts": ["proxy-fallback", "fallback", "delegatecall", "storage-layout", "returndata"],
            "summary": "Fallback routing → delegatecall → proxy storage/context → returndata.",
        },
        {
            "name": "permit path",
            "aliases": [],
            "concepts": ["mapping", "nonce", "abi.encode", "keccak256", "ecrecover"],
            "summary": "Signed approval data → digest → recovered signer → nonce/allowance state.",
        },
        {
            "name": "storage path",
            "aliases": [],
            "concepts": ["mapping-slots", "array-storage", "storage-layout", "keccak256", "yul-storage"],
            "summary": "High-level state expression → derived storage coordinates → Yul sload/sstore.",
        },
        {
            "name": "error path",
            "aliases": [],
            "concepts": ["custom-errors", "function-selector", "returndata", "try-catch"],
            "summary": "Error selector/data → revert bytes → catch → decoded meaning.",
        },
        {
            "name": "Foundry boundary path",
            "aliases": [],
            "concepts": ["vm-prank", "msg.sender", "vm-deal", "contract-balance", "vm-expect-call"],
            "summary": "Test-controlled actor/balance → contract call context → observed external call.",
        },
    ]

# Final correctness fixes after CI cross-check.
def _catalog_meaning_for(name: str):
    target = _CATALOG_ALIASES.get(_norm(name))
    if not target:
        return None
    found = {"meaning": None}

    def capture(topic_name, aliases, category, meaning, *args, **kwargs):
        if topic_name == target:
            found["meaning"] = meaning

    _register_catalog_topics(capture)
    return found["meaning"]


def _final_known_nodes():
    nodes = set()
    for left, right, _label in _COMPREHENSIVE_CONNECTION_EDGES:
        nodes.add(canonicalize(left))
        nodes.add(canonicalize(right))
    nodes.update(canonicalize(name) for name in _EXTRA_CONCEPTS)
    nodes.update(canonicalize(name) for name in _CATALOG_ALIASES.values())
    return nodes


def connection_meaning(name: str) -> str:
    canonical = canonicalize(name)

    # Always prefer the semantic definition for the canonical node.
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]

    meaning = _catalog_meaning_for(name)
    if meaning:
        return meaning

    meaning = _catalog_meaning_for(canonical)
    if meaning:
        return meaning

    return f"{canonical} is a recognized Solidity/Foundry concept."


# Keep the legacy combined selector topic connected after semantic
# canonicalization. This edge is intentionally redundant if an equivalent edge
# already exists, but harmless and makes the invariant explicit.
_COMPREHENSIVE_CONNECTION_EDGES.append(
    (
        "keccak-selectors",
        "keccak256",
        "combined selector/hash topic: selector derivation is a specific Keccak use",
    )
)


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _COMPREHENSIVE_COMPOSITES:
        return True
    if key in _SEMANTIC_ALIASES:
        return True
    if key in _CATALOG_ALIASES:
        return True
    return canonicalize(name) in _final_known_nodes()

def find_micro_scene(names):
    ordered = []
    seen = set()
    for name in names:
        node = canonicalize(name)
        if node not in seen:
            ordered.append(node)
            seen.add(node)

    requested = frozenset(ordered)

    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if frozenset(scene.get("keys", ())) == requested
    ]
    if exact:
        return exact[0]

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= frozenset(scene.get("keys", ()))
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(frozenset(scene.get("keys", ())) - requested),
                len(frozenset(scene.get("keys", ()))),
                scene.get("title", ""),
            )
        )
        return candidates[0]

    return _generic_connect_scene(ordered)

# ---------------------------------------------------------------------------
# Final language/reference coverage: globals, address members, and Yul atoms.
# ---------------------------------------------------------------------------
#
# These are useful connect nodes even when they are not standalone cheatsheet
# pages yet. They come directly from the Solidity reference's global variables,
# address members, and Yul vocabulary.

_SEMANTIC_ALIASES.update({
    "chainid": "block.chainid",
    "block.chainid": "block.chainid",
    "basefee": "block.basefee",
    "block.basefee": "block.basefee",
    "prevrandao": "block.prevrandao",
    "block.prevrandao": "block.prevrandao",
    "blobbasefee": "block.blobbasefee",
    "block.blobbasefee": "block.blobbasefee",
    "blobhash": "blobhash",
    "blockhash": "blockhash",
    "coinbase": "block.coinbase",
    "block.coinbase": "block.coinbase",
    "gaslimit": "block.gaslimit",
    "block.gaslimit": "block.gaslimit",
    "gasprice": "tx.gasprice",
    "tx.gasprice": "tx.gasprice",
    "address.balance": "address.balance",
    "balance": "address.balance",
    "address.code": "address.code",
    "code": "address.code",
    "address.codehash": "address.codehash",
    "codehash": "address.codehash",
    "transfer": "transfer",
    "send": "send",
    "this": "this",
    "super": "super",
    "type": "type-metadata",

    "mload": "mload",
    "mstore": "mstore",
    "mstore8": "mstore8",
    "sload": "sload",
    "sstore": "sstore",
    "tload": "tload",
    "tstore": "tstore",
    "calldataload": "calldataload",
    "calldatacopy": "calldatacopy",
    "calldatasize": "calldatasize",
    "returndatasize": "returndatasize",
    "returndatacopy": "returndatacopy",
    "codesize": "codesize",
    "codecopy": "codecopy",
    "extcodesize": "extcodesize",
    "extcodehash": "extcodehash",
    "log0": "log0",
    "log1": "log1",
    "log2": "log2",
    "log3": "log3",
    "log4": "log4",
    "chainid-opcode": "chainid",
    "basefee-opcode": "basefee",
    "origin-opcode": "origin",
    "gasprice-opcode": "gasprice",
    "timestamp-opcode": "timestamp",
    "number-opcode": "number",
    "prevrandao-opcode": "prevrandao",
})

_EXTRA_MEANINGS.update({
    "block.chainid": "The chain ID of the current execution environment.",
    "block.basefee": "The current block's base fee.",
    "block.prevrandao": "The block randomness value exposed in post-Merge EVMs.",
    "block.blobbasefee": "The current block's blob base fee on blob-enabled EVMs.",
    "blobhash": "A versioned hash for a transaction blob, when present.",
    "blockhash": "The hash of a recent block within the EVM-supported range.",
    "block.coinbase": "The current block's beneficiary address.",
    "block.gaslimit": "The current block gas limit.",
    "tx.gasprice": "The gas price associated with the transaction.",
    "address.balance": "The Wei balance held by an address.",
    "address.code": "The runtime bytecode at an address, returned as bytes.",
    "address.codehash": "The code hash of an address.",
    "transfer": "A payable-address Ether transfer operation that reverts on failure.",
    "send": "A payable-address Ether transfer operation that reports failure as a boolean.",
    "this": "The current contract instance/type; it can be used for an external self-call.",
    "super": "The next base-contract implementation in the inheritance hierarchy.",
    "mload": "Yul loads 32 bytes from memory.",
    "mstore": "Yul stores 32 bytes into memory.",
    "mstore8": "Yul stores the low byte of a value into memory.",
    "sload": "Yul reads a 32-byte word from persistent storage.",
    "sstore": "Yul writes a 32-byte word to persistent storage.",
    "tload": "Yul reads a word from transient storage.",
    "tstore": "Yul writes a word to transient storage.",
    "calldataload": "Yul reads a 32-byte word from calldata.",
    "calldatacopy": "Yul copies a calldata region into memory.",
    "calldatasize": "Yul returns the size of the current calldata.",
    "returndatasize": "Yul returns the size of the latest external-call return data.",
    "returndatacopy": "Yul copies external-call return data into memory.",
    "codesize": "Yul returns the current contract runtime-code size.",
    "codecopy": "Yul copies the current contract's runtime code into memory.",
    "extcodesize": "Yul returns the runtime-code size at an external address.",
    "extcodehash": "Yul returns the code hash at an external address.",
    "log0": "Yul emits a log with no topics.",
    "log1": "Yul emits a log with one topic.",
    "log2": "Yul emits a log with two topics.",
    "log3": "Yul emits a log with three topics.",
    "log4": "Yul emits a log with four topics.",
    "chainid": "Yul reads the executing chain ID.",
    "basefee": "Yul reads the current block base fee.",
    "origin": "Yul reads the transaction origin.",
    "gasprice": "Yul reads the transaction gas price.",
    "timestamp": "Yul reads the current block timestamp.",
    "number": "Yul reads the current block number.",
    "prevrandao": "Yul reads the block randomness value.",
})

_EXTRA_CONCEPTS.update({
    "block.chainid", "block.basefee", "block.prevrandao", "block.blobbasefee",
    "blobhash", "blockhash", "block.coinbase", "block.gaslimit", "tx.gasprice",
    "address.balance", "address.code", "address.codehash", "transfer", "send",
    "this", "super", "mload", "mstore", "mstore8", "sload", "sstore", "tload",
    "tstore", "calldataload", "calldatacopy", "calldatasize", "returndatasize",
    "returndatacopy", "codesize", "codecopy", "extcodesize", "extcodehash",
    "log0", "log1", "log2", "log3", "log4", "chainid", "basefee", "origin",
    "gasprice", "timestamp", "number", "prevrandao",
})

_FINAL_REFERENCE_EDGES = [
    ("block.chainid", "eip712", "domain separation commonly binds signatures to a chain ID"),
    ("block.chainid", "signature-verification", "signed authorizations can bind to a chain ID"),
    ("block.basefee", "gas", "base fee contributes to transaction gas economics"),
    ("block.blobbasefee", "gas", "blob base fee is part of blob transaction fee context"),
    ("block.prevrandao", "front-running", "block randomness is execution context rather than secret user input"),
    ("blockhash", "keccak256", "both are bytes32 hash-valued primitives with different trust/availability semantics"),
    ("block.coinbase", "ether-flow", "the block beneficiary is an address in the EVM context"),
    ("block.gaslimit", "gas", "the block limit bounds aggregate transaction execution"),
    ("tx.gasprice", "gas", "transaction gas price is distinct from the remaining gas budget"),
    ("address.balance", "ether-flow", "balance is the held ETH total"),
    ("address.balance", "contract-balance", "address(this).balance is the contract's address balance"),
    ("address.code", "address.codehash", "runtime code and its code hash describe deployed code"),
    ("address.code", "contract-types", "code presence helps distinguish deployed contracts from plain accounts"),
    ("address.code", "extcodesize", "Solidity address.code and EVM code-size inspection expose runtime code"),
    ("address.codehash", "extcodehash", "Solidity codehash corresponds to the EVM's code-hash view"),
    ("transfer", "payable", "transfer requires a payable recipient address"),
    ("send", "payable", "send requires a payable recipient address"),
    ("transfer", "msg.value", "Ether transfer moves Wei rather than changing the current msg.value"),
    ("send", "call", "send is a restricted Ether-call mechanism; low-level call exposes more control"),
    ("this", "call", "external self-calls cross the message boundary"),
    ("this", "msg.sender", "an external self-call changes the immediate caller to this contract"),
    ("super", "inheritance", "super resolves the next base implementation"),
    ("super", "override", "super is used to reach inherited implementations"),
    ("mload", "memory", "Yul reads memory with mload"),
    ("mstore", "memory", "Yul writes memory with mstore"),
    ("mstore8", "memory", "Yul writes one byte into memory"),
    ("mstore", "abi.encode", "ABI call payloads are assembled in memory"),
    ("mstore", "function-selector", "raw calldata construction commonly places selectors in memory"),
    ("sload", "storage", "Yul reads persistent storage"),
    ("sstore", "storage", "Yul writes persistent storage"),
    ("sload", "mapping-slots", "mapping slot derivation feeds sload"),
    ("sstore", "mapping-slots", "mapping slot derivation feeds sstore"),
    ("tload", "transient-storage", "Yul tload reads transaction-scoped state"),
    ("tstore", "transient-storage", "Yul tstore writes transaction-scoped state"),
    ("tload", "reentrancy", "transient guards are commonly read before external boundaries"),
    ("tstore", "reentrancy", "transient guards are commonly written before external boundaries"),
    ("calldataload", "calldata", "Yul reads raw calldata words"),
    ("calldatacopy", "calldata", "Yul copies call input into memory"),
    ("calldatasize", "calldata", "the size of msg.data is available at the EVM level"),
    ("calldataload", "function-selector", "the first calldata word contains the selector in its leading bytes"),
    ("returndatasize", "returndata", "Yul reads the latest return-data length"),
    ("returndatacopy", "returndata", "Yul copies returned bytes into memory"),
    ("returndatacopy", "revert", "revert data can be copied and bubbled unchanged"),
    ("codesize", "yul", "Yul can inspect the current runtime code size"),
    ("codecopy", "yul-memory", "runtime bytecode can be copied into memory"),
    ("extcodesize", "address.code", "code-size checks inspect whether an address has runtime code"),
    ("extcodehash", "address.codehash", "both expose deployed-code identity"),
    ("log0", "events", "Yul logs are the low-level basis for event emission"),
    ("log1", "event-indexed", "one log topic can represent an indexed event field"),
    ("log2", "event-indexed", "multiple indexed event fields become multiple topics"),
    ("log3", "event-indexed", "three topics can represent multiple indexed fields"),
    ("log4", "event-indexed", "four topics are the maximum topic count for a LOG opcode"),
    ("log1", "keccak256", "event signature hashes and dynamic indexed values can become topics"),
    ("chainid", "block.chainid", "Yul chainid reads the same chain identity exposed by Solidity"),
    ("basefee", "block.basefee", "Yul basefee reads the Solidity block base fee"),
    ("origin", "tx.origin", "Yul origin reads the transaction origin"),
    ("gasprice", "tx.gasprice", "Yul gasprice reads the transaction gas price"),
    ("timestamp", "block.timestamp", "Yul timestamp reads the Solidity block timestamp"),
    ("number", "block.number", "Yul number reads the Solidity block number"),
    ("prevrandao", "block.prevrandao", "Yul prevrandao reads the Solidity randomness context"),
]


def _append_reference_edges(edges):
    existing = {
        tuple(sorted((canonicalize(left), canonicalize(right))))
        for left, right, _label in edges
    }
    for left, right, label in _FINAL_REFERENCE_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        if key not in existing:
            edges.append((a, b, label))
            existing.add(key)


_append_reference_edges(_COMPREHENSIVE_CONNECTION_EDGES)


def _ensure_final_connect_coverage(edges):
    graph_nodes = set()
    for left, right, _label in edges:
        graph_nodes.add(canonicalize(left))
        graph_nodes.add(canonicalize(right))

    required = set(_EXTRA_CONCEPTS)
    required.update(
        canonicalize(name)
        for name in _CATALOG_ALIASES.values()
    )

    anchor_order = [
        "function", "variables", "storage", "calldata", "yul",
        "test", "poc",
    ]
    anchors = [canonicalize(a) for a in anchor_order]
    anchor = next((a for a in anchors if a in graph_nodes), "function")

    for node in sorted(required):
        if node in graph_nodes:
            continue
        edges.append(
            (
                node,
                anchor,
                "catalog coverage bridge; use the concept-specific edge/path next",
            )
        )
        graph_nodes.add(node)


_ensure_final_connect_coverage(_COMPREHENSIVE_CONNECTION_EDGES)

def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _COMPREHENSIVE_COMPOSITES:
        return True
    if key in _SEMANTIC_ALIASES:
        return True
    if key in _CATALOG_ALIASES:
        return True
    if key in _AMBIGUOUS_CATALOG_ALIASES:
        return True
    return canonicalize(name) in _final_known_nodes()


def _ensure_final_connect_coverage(edges):
    graph_nodes = set()
    for left, right, _label in edges:
        graph_nodes.add(canonicalize(left))
        graph_nodes.add(canonicalize(right))

    required = set(_EXTRA_CONCEPTS)
    required.update(
        canonicalize(name)
        for name in _CATALOG_ALIASES.values()
    )
    required.update(
        canonicalize(name)
        for name in _AMBIGUOUS_CATALOG_ALIASES
    )

    anchor_order = [
        "function", "variables", "storage", "calldata", "yul",
        "test", "poc",
    ]
    anchors = [canonicalize(a) for a in anchor_order]
    anchor = next((a for a in anchors if a in graph_nodes), "function")

    for node in sorted(required):
        if node in graph_nodes:
            continue
        edges.append(
            (
                node,
                anchor,
                "catalog coverage bridge; use the concept-specific edge/path next",
            )
        )
        graph_nodes.add(node)


_ensure_final_connect_coverage(_COMPREHENSIVE_CONNECTION_EDGES)

# ---------------------------------------------------------------------------
# Deep cross-check layer
# ---------------------------------------------------------------------------
#
# This section was built after checking the Solidity language/reference model
# against representative production code patterns.  It intentionally favors
# semantic connections over a combinatorial list of pair-specific recipes.
#
# Important: these edges mean "these concepts meet in real Solidity", not
# "these two tokens are interchangeable".
#
_DEEP_ALIASES = {
    "abi.encodewithselector": "abi.encodeWithSelector",
    "abi.encodewithsignature": "abi.encodeWithSignature",
    "abi.encodecall": "abi.encodeCall",
    "encode-with-selector": "abi.encodeWithSelector",
    "encode-with-signature": "abi.encodeWithSignature",
    "encode-call": "abi.encodeCall",
    "function-selector": "function-selector",
    "selector": "function-selector",
    "error-selector": "error-selector",
    "event-indexed": "event-indexed",
    "indexed": "event-indexed",
    "event": "events",
    "log": "events",
    "parameter": "parameter-vs-argument",
    "argument": "parameter-vs-argument",
    "parameters": "parameter-vs-argument",
    "arguments": "parameter-vs-argument",
    "overload": "function-overloading",
    "overloading": "function-overloading",
    "function-overloads": "function-overloading",
    "self-call": "this-call",
    "external-self-call": "this-call",
    "create": "create",
    "create2": "create2",
    "salt": "create2",
    "init-code": "init-code",
    "creation-code": "init-code",
    "runtime-code": "runtime-code",
    "code": "address.code",
    "codehash": "address.codehash",
    "extcodecopy": "extcodecopy",
    "selfbalance": "selfbalance",
    "caller": "caller",
    "callvalue": "callvalue",
    "mcopy": "mcopy",
    "memory-copy": "mcopy",
    "pc": "pc",
    "msize": "msize",
    "memoryguard": "memoryguard",
    "verbatim": "verbatim",
    "datasize": "datasize",
    "dataoffset": "dataoffset",
    "datacopy": "datacopy",
    "linkersymbol": "linkersymbol",
    "gas": "gas",
    "gasleft": "gasleft",
    "erc20": "erc20-pattern",
    "erc721": "erc721-pattern",
    "permit": "permit-pattern",
    "permit2": "permit-pattern",
    "safe": "safe-pattern",
    "multisig": "safe-pattern",
}

_SEMANTIC_ALIASES.update(_DEEP_ALIASES)

_DEEP_EXTRA_MEANINGS = {
    "abi.encodeWithSelector": "Build call bytes by prepending a supplied four-byte selector to ABI-encoded arguments.",
    "abi.encodeWithSignature": "Hash a canonical function signature to four selector bytes, then ABI-encode the arguments.",
    "abi.encodeCall": "Build ABI call bytes from a typed function reference and arguments with compile-time type checking.",
    "function-overloading": "Multiple functions may share a name when their parameter lists differ; the selector depends on the full signature.",
    "parameter-vs-argument": "A parameter is the named slot in a function definition; an argument is the actual value supplied at the call site.",
    "error-selector": "The first four bytes of a custom error's canonical signature hash.",
    "create": "The Yul/EVM contract-creation primitive that executes init code and returns a new address.",
    "create2": "Deterministic contract creation using deployer address, salt, and init-code hash.",
    "init-code": "Contract-creation bytecode that runs during deployment and returns runtime bytecode.",
    "runtime-code": "Bytecode that remains at a contract address after creation finishes.",
    "address.code": "Runtime bytecode associated with an address, exposed by Solidity as bytes.",
    "address.codehash": "The code hash associated with an address.",
    "extcodecopy": "Yul copies runtime code from an external address into memory.",
    "selfbalance": "Yul reads the current contract balance without specifying an address.",
    "caller": "Yul reads the immediate caller, corresponding to Solidity msg.sender.",
    "callvalue": "Yul reads the Wei attached to the current call, corresponding to Solidity msg.value.",
    "mcopy": "Yul copies a byte range from memory to memory.",
    "pc": "Yul reads the current program counter.",
    "msize": "Yul reports the highest accessed memory size in bytes, rounded to a word boundary.",
    "memoryguard": "Yul optimizer memory-safety marker that constrains the optimizer's use of memory.",
    "verbatim": "Yul escape hatch for emitting raw opcode bytes unknown to the Yul compiler.",
    "datasize": "Yul object helper returning the size of a named data object.",
    "dataoffset": "Yul object helper returning the offset of a named data object.",
    "datacopy": "Yul object helper copying bytes from an object data section into memory.",
    "linkersymbol": "Yul object placeholder replaced by the linker with a library address.",
    "gas": "Yul returns the remaining gas available to the current execution context.",
    "erc20-pattern": "Fungible-token pattern using balances, allowances, transfer state changes, and Transfer/Approval events.",
    "erc721-pattern": "NFT pattern using tokenId ownership, per-owner balance, approvals/operators, and transfer events.",
    "permit-pattern": "Signature-authorized token operation combining typed data, hashing, nonces, signer recovery, and state updates.",
    "safe-pattern": "Multisignature execution pattern combining owners, threshold, transaction hashing, nonce, signatures, modules, and fallback handling.",
}

# Plain keccak should explain hashing itself. Selector derivation is a separate graph node.
_EXTRA_MEANINGS["keccak256"] = "Keccak-256 hashes bytes and returns the digest as bytes32."
_EXTRA_MEANINGS.update(_DEEP_EXTRA_MEANINGS)
_EXTRA_CONCEPTS.update(_DEEP_EXTRA_MEANINGS)

_DEEP_EDGES = [
    ("function", "parameter-vs-argument", "function definitions name parameters while call sites supply arguments"),
    ("function", "function-overloading", "overloads share a name but differ by parameter types"),
    ("function-overloading", "function-signature", "the full parameter list distinguishes an overload"),
    ("function-overloading", "function-selector", "different overload signatures normally have different selectors"),
    ("function-signature", "abi.encodeWithSignature", "the canonical signature is used to derive the selector"),
    ("function-signature", "abi.encodeCall", "the typed function reference corresponds to a concrete signature"),
    ("function-selector", "abi.encodeWithSelector", "a supplied selector becomes the first four calldata bytes"),
    ("abi.encodeWithSignature", "abi.encodeWithSelector", "encodeWithSignature is conceptually selector derivation plus ABI encoding"),
    ("abi.encodeWithSelector", "abi.encode", "arguments after the selector use standard ABI encoding"),
    ("abi.encodeCall", "abi.encode", "the arguments use ABI encoding after the typed selector"),
    ("abi.encodeCall", "abi.decode", "call output can be decoded after the typed call is made"),
    ("error-selector", "keccak256", "error selectors are Keccak-derived"),
    ("error-selector", "errors", "custom errors expose a four-byte selector"),
    ("error-selector", "returndata", "revert bytes begin with an error selector"),
    ("error-selector", "abi.decode", "error arguments can be decoded after removing the selector"),
    ("errors", "function-selector", "error payloads use the same four-byte selector shape as function calls"),
    ("events", "abi.encode", "non-indexed event data uses ABI-style encoding"),
    ("event-indexed", "bytes", "indexed dynamic values use hashes rather than raw dynamic bytes"),
    ("event-indexed", "arrays", "indexed dynamic arrays are represented by hashed topics"),
    ("event-indexed", "structs", "indexed struct values use a Keccak topic representation"),
    ("this-call", "function", "this.f() performs an external self-call to function f"),
    ("this-call", "msg.sender", "the immediate caller observed inside the self-call becomes this contract"),
    ("this-call", "call", "an external self-call crosses a message boundary"),
    ("this-call", "reentrancy", "self-calls can create externally visible re-entry boundaries"),
    ("this-call", "function-selector", "the self-call still has normal calldata/selector dispatch"),
    ("returns", "abi.decode", "raw return bytes can be decoded into declared return types"),
    ("visibility", "function-selector", "only externally callable functions participate in external selector dispatch"),
    ("mutability", "payable", "payable functions can receive ETH while nonpayable functions cannot accept nonzero msg.value"),
    ("payable", "call", "call options can attach ETH to an outgoing message"),
    ("payable", "transfer", "transfer requires a payable address"),
    ("payable", "send", "send requires a payable address"),
    ("transfer", "contract-balance", "successful Ether transfer decreases the sender's balance and increases the recipient's"),
    ("send", "contract-balance", "send attempts an Ether transfer and exposes failure as false"),
    ("call", "contract-balance", "a call with value moves ETH between address balances"),
    ("address.balance", "contract-balance", "address(this).balance is the current contract address balance"),
    ("address.balance", "msg.value", "balance is a cumulative address state while msg.value belongs to the current call"),
    ("address.code", "runtime-code", "address.code exposes deployed runtime bytecode"),
    ("address.codehash", "runtime-code", "codehash identifies the deployed runtime code"),
    ("address.code", "extcodesize", "both inspect whether runtime code exists"),
    ("address.code", "extcodecopy", "both expose external contract code"),
    ("address.codehash", "extcodehash", "both expose external code identity"),
    ("create", "new", "new is the high-level contract creation path"),
    ("create", "constructor", "contract creation runs constructor/init code"),
    ("create2", "new", "deterministic deployment is an alternate creation primitive"),
    ("create2", "keccak256", "CREATE2 address derivation hashes deployer/salt/init-code"),
    ("create2", "salt", "the salt selects a deterministic creation address"),
    ("create2", "init-code", "the init-code hash is part of CREATE2 address derivation"),
    ("create2", "address", "successful CREATE2 returns a contract address"),
    ("init-code", "constructor", "constructor execution happens during contract creation"),
    ("init-code", "runtime-code", "init code returns the runtime bytecode stored after deployment"),
    ("extcodesize", "address", "code-size inspection takes an address"),
    ("extcodecopy", "address", "external code copy takes an address"),
    ("selfbalance", "contract-balance", "selfbalance is the Yul form of current contract balance"),
    ("caller", "msg.sender", "Yul caller corresponds to Solidity msg.sender"),
    ("callvalue", "msg.value", "Yul callvalue corresponds to Solidity msg.value"),
    ("gas", "gasleft", "Yul gas reports remaining gas while Solidity gasleft exposes the same context"),
    ("gas", "call", "low-level Yul calls explicitly receive a gas argument"),
    ("mcopy", "memory", "mcopy copies data inside temporary memory"),
    ("pc", "yul", "pc is a low-level execution-position primitive"),
    ("msize", "memory", "msize reports memory expansion size"),
    ("memoryguard", "memory-safe", "memoryguard is an optimizer-oriented memory discipline marker"),
    ("verbatim", "yul", "verbatim emits raw bytes beyond ordinary Yul builtins"),
    ("datasize", "datacopy", "object data is addressed by size/offset and copied into memory"),
    ("dataoffset", "datacopy", "object data is copied from a named data offset"),
    ("linkersymbol", "library", "Yul linker symbols resolve library addresses"),
    ("linkersymbol", "imports", "imported libraries can require linker-resolved addresses"),
    ("mload", "mcopy", "both operate on Yul memory"),
    ("calldatacopy", "mcopy", "both move byte ranges, from calldata or memory"),
    ("returndatacopy", "mcopy", "both copy byte ranges into memory"),
    ("sload", "mapping-slots", "derived mapping coordinates are read with sload"),
    ("sstore", "mapping-slots", "derived mapping coordinates are written with sstore"),
    ("sload", "storage-layout", "raw storage reads depend on layout"),
    ("sstore", "storage-layout", "raw storage writes depend on layout"),
    ("tload", "tstore", "transient state is read and written as a separate storage class"),
    ("transient-storage", "modifier", "reentrancy guards can be implemented as reusable modifiers"),
    ("transient-storage", "nonReentrant", "transaction-scoped guards can prevent nested entry"),
    ("delegatecall", "msg.sender", "delegatecall preserves the caller context while changing executed code"),
    ("delegatecall", "msg.value", "delegatecall preserves call value/context"),
    ("delegatecall", "address", "delegatecall targets code at an address"),
    ("delegatecall", "returndata", "delegatecall returns success and raw return/revert bytes"),
    ("proxy-fallback", "function-selector", "proxy fallback routes unknown selectors"),
    ("proxy-fallback", "calldata", "proxy forwarding copies calldata"),
    ("proxy-fallback", "returndata", "proxy forwarding copies implementation returndata back"),
    ("proxy-fallback", "abi.decode", "decoded upgrade/config data can cross the proxy boundary"),
    ("erc20-pattern", "mapping", "ERC20-style balances and allowances are mappings"),
    ("erc20-pattern", "nested-mapping", "allowances are commonly owner -> spender -> amount"),
    ("erc20-pattern", "address", "token balances and recipients are keyed/represented by addresses"),
    ("erc20-pattern", "msg.sender", "transferFrom/approve flows use caller identity"),
    ("erc20-pattern", "events", "Transfer and Approval expose state changes to off-chain observers"),
    ("erc20-pattern", "event-indexed", "token transfer parties are commonly indexed"),
    ("erc20-pattern", "errors", "token operations can report typed failure"),
    ("erc721-pattern", "mapping", "NFT ownership and balances are commonly mapped state"),
    ("erc721-pattern", "arrays", "operator/token enumeration implementations may maintain arrays"),
    ("erc721-pattern", "bytes32", "token identifiers/signature or interface metadata may use fixed bytes"),
    ("erc721-pattern", "events", "Transfer/Approval events describe NFT state transitions"),
    ("erc721-pattern", "access-control", "minting/burning privileges often use access control"),
    ("permit-pattern", "mapping", "nonces/allowances are stored in mappings"),
    ("permit-pattern", "structs", "signed permit payloads are often structs"),
    ("permit-pattern", "bytes", "signatures and witness data are byte arrays"),
    ("permit-pattern", "keccak256", "the signed payload becomes a digest"),
    ("permit-pattern", "ecrecover", "the signer address can be recovered from the digest"),
    ("permit-pattern", "nonce", "the authorization is bound to a sequence value"),
    ("permit-pattern", "block.timestamp", "deadlines bind authorization to time"),
    ("permit-pattern", "front-running", "signatures are observable before execution and need binding/replay protection"),
    ("safe-pattern", "mapping", "Safe maintains address-based authorization structures"),
    ("safe-pattern", "structs", "transaction data is represented as structured fields"),
    ("safe-pattern", "keccak256", "Safe transaction hashes use EIP-712 hashing"),
    ("safe-pattern", "nonce", "Safe transactions use nonces"),
    ("safe-pattern", "signature-verification", "owner signatures authorize transaction hashes"),
    ("safe-pattern", "proxy-fallback", "fallback handlers/modules extend execution boundaries"),
    ("safe-pattern", "modules", "modules add separate execution surfaces"),
    ("modules", "access-control", "enabled modules form an authorization boundary"),
    ("modules", "external-call", "modules can trigger Safe execution"),
    ("modules", "events", "module changes can be observable through events"),
    ("signature-verification", "abi.encode", "signed payloads are encoded before hashing"),
    ("signature-verification", "function-selector", "signature/authentication paths are distinct from calldata selectors even though both use bytes4/hash machinery"),
    ("signature-verification", "address", "verification resolves an expected signer address"),
    ("eip712", "structs", "typed-data signing mirrors structured Solidity values"),
    ("eip712", "string", "type strings/domain text participate in typed-data encoding"),
    ("eip712", "bytes32", "domain/type hashes are bytes32 values"),
    ("eip712", "block.chainid", "domain separation can bind signatures to a chain"),
    ("eip712", "address", "domain separation can bind a verifying contract address"),
    ("nonce", "mapping", "nonces are commonly per-user mapped state"),
    ("nonce", "storage", "nonce state persists"),
    ("mapping-defaults", "delete", "both expose/default mapped values to zero-like defaults"),
    ("mapping", "public", "public mappings generate getters with recursive key parameters for nested values"),
    ("mapping", "types-defaults", "a mapping's missing key reads the value type's default"),
    ("arrays", "mapping-defaults", "arrays can be used as per-key state values whose empty state is significant"),
    ("arrays", "mapping-struct", "arrays can contain structs and mappings can select either"),
    ("mapping-struct", "storage-layout", "mapped structs have deterministic field offsets beneath derived roots"),
    ("mapping-array-value", "array-storage", "mapped dynamic arrays combine mapping roots with array storage rules"),
    ("struct-types", "storage-packing", "struct field types determine whether fields share storage slots"),
    ("types-defaults", "delete", "delete restores the default representation"),
    ("constructor", "constant-immutable", "immutable state is assigned during construction while constants are compile-time fixed"),
    ("constructor", "type-metadata", "creation code can inspect contract/type metadata"),
    ("constructor", "new", "new invokes constructors"),
    ("constructor", "try-catch", "contract creation can fail and be caught externally"),
    ("imports", "using-for", "imported libraries are commonly attached with using-for"),
    ("library", "mapping", "libraries can implement operations over mapping storage references"),
    ("library", "structs", "libraries often mutate struct storage references"),
    ("using-for", "mapping", "using-for can attach library operations to mapping types"),
    ("using-for", "structs", "using-for can attach library operations to struct values"),
    ("interface", "abi.encodeCall", "typed interface functions provide compile-time call shapes"),
    ("interface", "abi.decode", "interface return values cross an ABI boundary even when the caller uses typed syntax"),
    ("interface", "try-catch", "typed interface calls can be wrapped in try/catch"),
    ("oracle", "staticcall", "oracle reads are commonly read-only external calls"),
    ("oracle", "returndata", "oracle adapters must interpret returned bytes/values"),
    ("oracle", "block.timestamp", "oracle-dependent protocols often combine data freshness with time"),
    ("tx.origin", "this-call", "caller chains distinguish original origin from immediate self/contract callers"),
    ("tx.origin", "reentrancy", "origin does not change during nested contract calls"),
    ("front-running", "commit-reveal", "commitments can hide a choice until a later reveal"),
    ("commit-reveal", "keccak256", "commitments are commonly hash values"),
    ("commit-reveal", "mapping", "commitments are often stored per participant"),
    ("timestamp", "block.timestamp", "timestamp is the concrete global variable used by time checks"),
    ("timestamp", "front-running", "block time is visible execution context, not secret input"),
    ("reentrancy", "checks-effects-interactions", "CEI orders persistent effects before external interaction"),
    ("reentrancy", "access-control", "reentrancy defenses do not replace authorization checks"),
    ("reentrancy", "storage", "reentrant behavior often exploits state that remains temporarily stale"),
    ("reentrancy", "events", "events can help trace repeated externalized effects"),
    ("checks-effects-interactions", "mapping", "accounting mappings are commonly updated in the effects phase"),
    ("checks-effects-interactions", "call", "calls are the interaction phase"),
    ("require", "mapping", "authorization/accounting checks often read mappings"),
    ("require", "msg.sender", "permission conditions often inspect caller identity"),
    ("custom-errors", "function-selector", "custom error selectors identify structured failures"),
    ("custom-errors", "events", "both are typed ABI-facing observability mechanisms with different execution semantics"),
    ("try-catch", "errors", "caught failures may expose custom error bytes"),
    ("try-catch", "new", "creation failures can be caught"),
    ("try-catch", "interface", "typed external interfaces can use try/catch"),
    ("test", "vm-prank", "tests manipulate caller context"),
    ("test", "vm-deal", "tests provision ETH"),
    ("test", "vm-warp", "tests control time"),
    ("test", "vm-roll", "tests control block number"),
    ("test", "vm-expect-revert", "tests assert expected failure paths"),
    ("test", "vm-expect-emit", "tests assert emitted logs"),
    ("test", "vm-expect-call", "tests assert external call behavior"),
    ("test", "vm-storage", "tests can inspect raw storage"),
    ("test", "vm-etch", "tests can replace code at an address"),
    ("test", "vm-fork", "tests can exercise real forked state"),
    ("test", "fuzz-tests", "tests can generate varied inputs"),
    ("test", "invariant-tests", "tests can check properties across sequences"),
    ("vm-prank", "vm-start-prank", "both manipulate caller identity with different lifetimes"),
    ("vm-deal", "contract-balance", "deal establishes deterministic ETH balances in tests"),
    ("vm-warp", "block.timestamp", "warp changes the timestamp observed by the contract"),
    ("vm-roll", "block.number", "roll changes the block number observed by the contract"),
    ("vm-assume", "vm-bound", "both constrain fuzz input domains"),
    ("vm-expect-revert", "custom-errors", "tests can assert typed revert paths"),
    ("vm-expect-emit", "event-indexed", "event expectations include topic/indexed behavior"),
    ("vm-expect-call", "abi.encodeCall", "expected call payloads can use typed ABI encoding"),
    ("vm-mockcall", "interface", "mocked external dependencies often satisfy an interface"),
    ("vm-hoax", "vm-prank", "hoax combines funding with caller manipulation"),
    ("fork-tests", "oracle", "fork tests can exercise real oracle state"),
    ("vm-storage", "mapping-slots", "raw slot inspection helps validate mapping calculations"),
    ("vm-etch", "address.code", "etch changes the runtime code at an address in test state"),
    ("script-deploy", "new", "deployment scripts create contract instances"),
    ("script-deploy", "constructor", "deployment scripts supply constructor arguments"),
    ("script-interaction", "call", "scripts call deployed contracts"),
    ("script-env", "vm-env", "environment variables configure execution"),
    ("script-broadcast", "script", "broadcast controls sending script transactions"),
    ("poc-accessible-state", "mapping", "an accessible-state PoC targets readable/writable state"),
    ("poc-dos", "loops", "DoS PoCs often target gas-growing loops"),
    ("poc-dos", "storage", "state growth can create persistent cost/availability pressure"),
    ("poc-token", "erc20-pattern", "token PoCs exercise balance/allowance accounting"),
    ("poc-token", "erc721-pattern", "token PoCs can target NFT ownership/approval state"),
    ("poc-cross-contract", "interface", "cross-contract PoCs exercise typed boundaries"),
    ("poc-upgrade", "delegatecall", "upgrade PoCs target implementation execution context"),
    ("poc-upgrade", "storage-layout", "upgrade safety depends on compatible storage layout"),
    ("poc-storage", "sload", "storage PoCs can inspect raw words"),
    ("poc-signature", "nonce", "signature PoCs commonly test replay"),
    ("poc-signature", "eip712", "typed signing is a common authorization surface"),
    ("poc-oracle", "oracle", "oracle PoCs target external data assumptions"),
    ("poc-accounting", "mapping", "accounting PoCs target stored balances/credits"),
    ("poc-reentrancy", "receive", "reentrant attackers often use receive/fallback callbacks"),
    ("poc-access-control", "modifier", "authorization PoCs target modifier/permission boundaries"),
    ("poc-access-control", "msg.sender", "caller identity is a core authorization input"),
    ("poc-upgrade", "proxy-fallback", "proxy upgrade behavior is exposed through forwarding"),
    ("poc-cross-contract", "returndata", "cross-contract PoCs can target ignored or malformed return data"),
    ("poc-dos", "gasleft", "gas-sensitive behavior can become a denial-of-service surface"),
    ("unchecked", "assert", "unchecked arithmetic shifts the burden to surrounding invariants"),
    ("addmod", "mulmod", "both provide modular arithmetic"),
    ("addmod", "keccak256", "modular arithmetic can appear in cryptographic/math-heavy protocols"),
    ("mulmod", "keccak256", "modular arithmetic can appear in cryptographic/math-heavy protocols"),
    ("bytes.concat", "abi.encode", "concatenated bytes can become ABI input"),
    ("string.concat", "abi.encode", "concatenated strings can be ABI encoded"),
    ("bytes.concat", "keccak256", "concatenated byte sequences can be hashed"),
    ("string.concat", "keccak256", "text concatenation can feed hashing after conversion to bytes"),
    ("selfdestruct", "address.balance", "destruction semantics historically affected a contract's balance"),
    ("selfdestruct", "ether-flow", "destruction is a special ETH/code-flow edge case"),
    ("selfdestruct", "address", "the operation concerns the current contract address"),
    ("block.chainid", "nonce", "chain ID and nonce can jointly bind an authorization"),
    ("block.chainid", "function-selector", "both are execution/call-context metadata but serve different roles"),
    ("block.basefee", "tx.gasprice", "base fee and transaction gas price are distinct fee-context values"),
    ("block.prevrandao", "front-running", "randomness context is observable only within execution and should not be treated as secret"),
    ("blockhash", "block.number", "blockhash takes a recent block number"),
]


def _deep_add_edges():
    existing = {
        tuple(sorted((canonicalize(left), canonicalize(right))))
        for left, right, _label in _COMPREHENSIVE_CONNECTION_EDGES
    }
    for left, right, label in _DEEP_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        if key not in existing:
            _COMPREHENSIVE_CONNECTION_EDGES.append((a, b, label))
            existing.add(key)

    # Attach newly introduced low-level nodes to their real conceptual parents.
    for source, target, label in [
        ("create2", "yul-call", "Yul CREATE2 is a low-level creation primitive"),
        ("create", "yul-call", "Yul CREATE is a low-level creation primitive"),
        ("init-code", "yul", "creation code is directly manipulated in low-level deployment"),
        ("runtime-code", "yul", "runtime code is the deployed execution artifact"),
        ("address.code", "bytes", "runtime code is exposed as bytes"),
        ("address.codehash", "bytes32", "code hashes are bytes32 values"),
        ("selfbalance", "yul", "selfbalance is a Yul builtin"),
        ("caller", "yul", "caller is a Yul builtin"),
        ("callvalue", "yul", "callvalue is a Yul builtin"),
        ("mcopy", "yul", "mcopy is a Yul memory builtin"),
        ("pc", "yul", "pc is a Yul builtin"),
        ("msize", "yul", "msize is a Yul builtin"),
        ("memoryguard", "yul", "memoryguard belongs to Yul's optimizer-oriented memory model"),
        ("verbatim", "yul", "verbatim is a Yul low-level escape hatch"),
        ("datasize", "yul", "datasize is a Yul object builtin"),
        ("dataoffset", "yul", "dataoffset is a Yul object builtin"),
        ("datacopy", "yul", "datacopy is a Yul object builtin"),
        ("linkersymbol", "library", "linkersymbol resolves library addresses"),
        ("erc20-pattern", "test", "token behavior is routinely exercised in tests"),
        ("erc721-pattern", "test", "NFT behavior is routinely exercised in tests"),
        ("permit-pattern", "test", "signature authorization needs behavioral tests"),
        ("safe-pattern", "test", "multisig execution needs sequence/state tests"),
    ]:
        a, b = canonicalize(source), canonicalize(target)
        key = tuple(sorted((a, b)))
        if key not in existing:
            _COMPREHENSIVE_CONNECTION_EDGES.append((a, b, label))
            existing.add(key)


_deep_add_edges()


# ---------------------------------------------------------------------------
# Production-derived micro scenes.
# ---------------------------------------------------------------------------

COMPREHENSIVE_MICRO_SCENES.extend([
    {
        "keys": frozenset({"function", "visibility", "mutability", "returns", "parameter-vs-argument"}),
        "title": "Function definition → call site → return value",
        "story": "A function definition declares parameter slots and rules for access/state. A caller supplies arguments, and the function returns typed values.",
        "code": """function quote(uint256 amount_)
    external
    view
    returns (uint256 fee)
{
    fee = amount_ / 100;
}

// Call site:
// uint256 fee = quote(10_000);""",
        "variables": [
            ("parameter", "uint256", "amount_", "10_000", "Named input slot in the definition."),
            ("argument", "uint256", "10_000", "10_000", "Actual value supplied at the call site."),
            ("return", "uint256", "fee", "100", "Typed output declared by returns."),
        ],
        "flow": [
            "The definition names amount_ as a parameter.",
            "The caller supplies 10_000 as the argument.",
            "external/view describe the call surface and state permissions.",
            "The calculation produces fee = 100 and returns it.",
        ],
        "call": "quote(10_000);",
    },
    {
        "keys": frozenset({"function-overloading", "function-signature", "function-selector", "keccak256"}),
        "title": "Overload → full signature → selector",
        "story": "Two functions can share a name, but their parameter types make different canonical signatures and therefore normally different selectors.",
        "code": """function set(uint256 value_) external {}
function set(address user_) external {}

// set(uint256)
// set(address)
// selector = bytes4(keccak256(canonicalSignature))""",
        "variables": [
            ("function", "set(uint256)", "first overload", "set(uint256)", "One callable shape."),
            ("function", "set(address)", "second overload", "set(address)", "Another callable shape."),
            ("derived", "bytes4", "selector", "keccak256(signature)[0:4]", "External dispatch identifier."),
        ],
        "flow": [
            "The function name alone is not enough to identify an overload.",
            "Parameter types produce the canonical signature.",
            "Keccak hashes the signature.",
            "The first four bytes identify the external entry point.",
        ],
        "call": "call the correct overload by supplying the matching argument type",
    },
    {
        "keys": frozenset({"abi.encodeWithSignature", "function-signature", "function-selector", "calldata", "call"}),
        "title": "Signature string → selector → raw call",
        "story": "A low-level caller can build calldata from a canonical signature string, then pass the bytes to call().",
        "code": """bytes memory data =
    abi.encodeWithSignature("quote(uint256)", 100);

(bool ok, bytes memory out) =
    target.call(data);

require(ok);""",
        "variables": [
            ("signature", "string", "signature", '"quote(uint256)"', "Canonical function signature."),
            ("calldata", "bytes", "data", "selector + ABI(100)", "Raw call payload."),
            ("local", "bool", "ok", "true", "External call success."),
            ("return", "bytes", "out", "raw returndata", "Return bytes from target."),
        ],
        "flow": [
            "quote(uint256) is hashed to derive the selector.",
            "100 is ABI-encoded after the selector.",
            "target.call(data) crosses the external boundary.",
            "out contains raw return bytes.",
        ],
        "call": 'target.call(abi.encodeWithSignature("quote(uint256)", 100));',
    },
    {
        "keys": frozenset({"fallback", "msg.sig", "calldata", "abi.decode", "function-selector"}),
        "title": "Fallback dispatch → selector → decoded arguments",
        "story": "A fallback function can inspect raw calldata, separate the four-byte selector, and decode the argument tail.",
        "code": """fallback(bytes calldata input)
    external
    returns (bytes memory)
{
    bytes4 selector = bytes4(input[:4]);

    if (selector == this.set.selector) {
        (uint256 amount_) =
            abi.decode(input[4:], (uint256));

        return abi.encode(amount_);
    }

    return "";
}""",
        "variables": [
            ("calldata", "bytes calldata", "input", "selector + ABI arguments", "Raw fallback input."),
            ("selector", "bytes4", "selector", "input[:4]", "First four bytes."),
            ("decoded", "uint256", "amount_", "abi.decode(input[4:], (uint256))", "Typed argument."),
        ],
        "flow": [
            "fallback receives the raw calldata payload.",
            "The first four bytes identify the attempted function selector.",
            "The slice after byte 4 contains ABI-encoded arguments.",
            "abi.decode turns those bytes into typed values.",
        ],
        "call": "send calldata for set(100) to the fallback",
    },
    {
        "keys": frozenset({"this-call", "msg.sender", "call", "function-selector"}),
        "title": "External self-call changes the caller context",
        "story": "this.foo(...) is not an internal jump. It is a real external message call back into the same address, so dispatch and msg.sender change.",
        "code": """function outer() external {
    this.inner();
}

function inner() external {
    // msg.sender == address(this)
}""",
        "variables": [
            ("external call", "function", "this.inner()", "external message call", "Self-call through the contract address."),
            ("global", "address", "msg.sender", "address(this)", "Caller seen inside inner()."),
        ],
        "flow": [
            "outer() starts with the original external caller.",
            "this.inner() sends a new external call to the same contract.",
            "inner() sees address(this) as msg.sender.",
            "The call therefore crosses the message boundary rather than staying internal.",
        ],
        "call": "outer();",
    },
    {
        "keys": frozenset({"address", "payable", "transfer", "send", "call", "contract-balance", "msg.value"}),
        "title": "Address → ETH transfer mechanism → balance",
        "story": "An address identifies the recipient, while transfer/send/call differ in how ETH is sent and how failure is reported.",
        "code": """function pay(
    address payable to,
    uint256 amount_
) external payable {
    require(msg.value >= amount_);

    (bool ok, ) =
        to.call{value: amount_}("");
    require(ok);
}""",
        "variables": [
            ("parameter", "address payable", "to", "0xBob", "ETH recipient."),
            ("parameter", "uint256", "amount_", "1 ether", "Amount to send."),
            ("global", "uint256", "msg.value", "1 ether", "ETH attached to this call."),
            ("balance", "uint256", "to.balance", "old + 1 ether", "Recipient balance after success."),
        ],
        "flow": [
            "to is the recipient address.",
            "msg.value is ETH attached to the current call; it is not the recipient's total balance.",
            "call{value: amount_} sends ETH and returns a success flag.",
            "The recipient balance changes if the call succeeds.",
        ],
        "call": "pay{value: 1 ether}(alice, 1 ether);",
    },
    {
        "keys": frozenset({"erc20-pattern", "mapping", "nested-mapping", "msg.sender", "events"}),
        "title": "ERC20 shape: balance + allowance + events",
        "story": "Fungible tokens combine one mapping for balances, a nested mapping for allowances, caller identity, and events that describe state transitions.",
        "code": """mapping(address => uint256) public balanceOf;
mapping(address => mapping(address => uint256)) public allowance;

event Transfer(address indexed from, address indexed to, uint256 value);
event Approval(address indexed owner, address indexed spender, uint256 value);

function approve(address spender, uint256 amount_) external {
    allowance[msg.sender][spender] = amount_;
    emit Approval(msg.sender, spender, amount_);
}

function transfer(address to, uint256 amount_) external {
    balanceOf[msg.sender] -= amount_;
    balanceOf[to] += amount_;
    emit Transfer(msg.sender, to, amount_);
}""",
        "variables": [
            ("state", "mapping(address => uint256)", "balanceOf", "balanceOf[msg.sender]", "Token balances."),
            ("state", "mapping(address => mapping(address => uint256))", "allowance", "allowance[owner][spender]", "Nested spending approvals."),
            ("global", "address", "msg.sender", "0xAlice", "Current token caller."),
            ("event", "Approval/Transfer", "logs", "old → new", "Off-chain state-change signal."),
        ],
        "flow": [
            "msg.sender selects the owner's balance/allowance row.",
            "allowance[msg.sender][spender] uses two keys.",
            "transfer changes two balance entries.",
            "Approval/Transfer events mirror those state changes.",
        ],
        "call": "approve(bob, 100); transfer(bob, 10);",
    },
    {
        "keys": frozenset({"erc721-pattern", "mapping", "address", "events", "access-control"}),
        "title": "ERC721 shape: tokenId → owner + approvals",
        "story": "An NFT contract commonly maps token IDs to owners, tracks owner balances, and exposes approval/transfer events behind authorization rules.",
        "code": """mapping(uint256 => address) internal _ownerOf;
mapping(address => uint256) internal _balanceOf;
mapping(uint256 => address) internal _tokenApprovals;

event Transfer(
    address indexed from,
    address indexed to,
    uint256 indexed tokenId
);

function ownerOf(uint256 tokenId)
    external
    view
    returns (address)
{
    return _ownerOf[tokenId];
}""",
        "variables": [
            ("state", "mapping(uint256 => address)", "_ownerOf", "_ownerOf[tokenId]", "Token ownership."),
            ("state", "mapping(address => uint256)", "_balanceOf", "_balanceOf[owner]", "Per-owner NFT count."),
            ("state", "mapping(uint256 => address)", "_tokenApprovals", "_tokenApprovals[tokenId]", "Approved operator for one token."),
            ("event", "Transfer", "tokenId", "1", "Indexed NFT state change."),
        ],
        "flow": [
            "tokenId selects an owner address.",
            "Owner state is paired with owner balance state.",
            "Approvals add another address keyed by tokenId.",
            "Transfer events expose the ownership transition.",
        ],
        "call": "ownerOf(1);",
    },
    {
        "keys": frozenset({"mapping", "structs", "library", "using-for", "interface", "call"}),
        "title": "Protocol pattern: mapped struct → library operation → hook call",
        "story": "Protocol code often stores complex state in a mapping, passes a storage reference into a library, and invokes an external hook through an interface.",
        "code": """struct Pool {
    uint256 liquidity;
}

mapping(bytes32 => Pool) internal pools;

library PoolLib {
    function add(Pool storage pool, uint256 amount_) internal {
        pool.liquidity += amount_;
    }
}

interface IHook {
    function beforeSwap(bytes32 poolId) external;
}

using PoolLib for Pool;

function swap(bytes32 poolId, uint256 amount_, IHook hook) external {
    hook.beforeSwap(poolId);
    Pool storage pool = pools[poolId];
    pool.add(amount_);
}""",
        "variables": [
            ("state", "mapping(bytes32 => Pool)", "pools", "pools[poolId]", "Protocol state registry."),
            ("local", "Pool storage", "pool", "pools[poolId]", "Persistent state reference."),
            ("library", "PoolLib", "add", "pool.add(amount_)", "Attached state operation."),
            ("interface", "IHook", "hook", "0xHook", "External callback target."),
        ],
        "flow": [
            "poolId selects a Pool struct.",
            "The interface call crosses a contract boundary.",
            "The storage reference points at persistent state.",
            "using-for turns the library operation into pool.add(amount_).",
        ],
        "call": "swap(poolId, 100, hook);",
    },
    {
        "keys": frozenset({"mapping", "bytes32", "interface", "access-control", "events", "proxy-fallback", "delegatecall", "abi.encodeWithSignature"}),
        "title": "Registry pattern: bytes32 ID → address → proxy",
        "story": "A protocol registry can map fixed IDs to addresses, gate updates with ownership, emit events, and create/update proxies whose initialization is encoded as calldata.",
        "code": """mapping(bytes32 => address) internal registry;

event AddressSet(bytes32 indexed id, address indexed oldAddress, address indexed newAddress);

function setAddress(bytes32 id, address newAddress) external onlyOwner {
    address oldAddress = registry[id];
    registry[id] = newAddress;
    emit AddressSet(id, oldAddress, newAddress);
}

// Proxy initialization data:
// bytes memory data = abi.encodeWithSignature(
//     "initialize(address)", address(this)
// );
// proxyAddress.delegatecall(data);""",
        "variables": [
            ("state", "mapping(bytes32 => address)", "registry", "registry[id]", "Protocol address book."),
            ("key", "bytes32", "id", 'bytes32("POOL")', "Stable identifier."),
            ("parameter", "address", "newAddress", "0xImpl", "New dependency/implementation."),
            ("event", "AddressSet", "old/new", "0xOld → 0xImpl", "Auditable update record."),
        ],
        "flow": [
            "A bytes32 identifier selects an address.",
            "Access control determines who can change it.",
            "The state change emits an indexed event.",
            "A proxy can receive initialization bytes and execute implementation code through delegatecall.",
        ],
        "call": 'setAddress(bytes32("POOL"), implementation);',
    },
    {
        "keys": frozenset({"permit-pattern", "structs", "mapping", "keccak256", "ecrecover", "nonce", "block.timestamp", "bytes"}),
        "title": "Permit-style flow: struct → digest → signer → nonce",
        "story": "Signature-authorized token actions combine structured data, hashing, recovered signer identity, per-user nonce state, deadline checks, and byte signatures.",
        "code": """struct Permit {
    address owner;
    address spender;
    uint256 value;
    uint256 nonce;
    uint256 deadline;
}

mapping(address => uint256) public nonces;

function digest(Permit memory permit)
    public
    pure
    returns (bytes32)
{
    return keccak256(
        abi.encode(
            permit.owner,
            permit.spender,
            permit.value,
            permit.nonce,
            permit.deadline
        )
    );
}

// address signer = ecrecover(digest(permit), v, r, s);
""",
        "variables": [
            ("struct", "Permit", "permit", "owner/spender/value/nonce/deadline", "Signed structured message."),
            ("state", "mapping(address => uint256)", "nonces", "nonces[owner]", "Replay protection."),
            ("derived", "bytes32", "digest", "keccak256(abi.encode(...))", "Signed digest."),
            ("signature", "bytes", "signature", "r/s/v data", "Authorization proof."),
        ],
        "flow": [
            "The permit struct holds the fields the owner authorizes.",
            "abi.encode makes deterministic bytes.",
            "keccak256 makes the digest.",
            "ecrecover can recover the signer address.",
            "The nonce prevents the same authorization from being used again.",
        ],
        "call": "digest(permit);",
    },
    {
        "keys": frozenset({"vm-prank", "vm-deal", "vm-expect-call", "msg.sender", "contract-balance", "test"}),
        "title": "Foundry test → caller + balance + expected call",
        "story": "One test can control who calls the contract, fund an account, then assert the external call the contract makes.",
        "code": """function testWithdraw() public {
    vm.deal(alice, 2 ether);
    vm.prank(alice);

    vm.expectCall(
        address(token),
        abi.encodeCall(IERC20.transfer, (bob, 100))
    );

    vault.withdraw(bob, 100);
}""",
        "variables": [
            ("test actor", "address", "alice", "0xAlice", "Controlled caller/funded account."),
            ("contract global", "address", "msg.sender", "alice", "What the vault sees."),
            ("balance", "uint256", "alice.balance", "2 ether", "Provisioned test balance."),
            ("expected payload", "bytes", "data", "abi.encodeCall(...)", "Expected external calldata."),
        ],
        "flow": [
            "vm.deal provisions Alice with ETH in test state.",
            "vm.prank makes Alice the caller.",
            "The contract executes with msg.sender == Alice.",
            "vm.expectCall checks the external token call and ABI payload.",
        ],
        "call": "vm.deal(alice, 2 ether); vm.prank(alice); vault.withdraw(bob, 100);",
    },
    {
        "keys": frozenset({"fuzz-tests", "bounded-fuzz", "vm-assume", "vm-bound", "invariant-tests", "test"}),
        "title": "Fuzz input → constraints → invariant",
        "story": "Foundry can explore many inputs, constrain the domain, and then check a property rather than one hand-picked example.",
        "code": """function testFuzzDeposit(uint256 raw) public {
    vm.assume(raw != 0);
    uint256 amount = bound(raw, 1, 1_000);

    vault.deposit(amount);

    assertEq(vault.total(), amount);
}""",
        "variables": [
            ("fuzz input", "uint256", "raw", "many candidates", "Generated candidate."),
            ("bounded", "uint256", "amount", "1..1000", "Meaningful input range."),
            ("property", "uint256", "vault.total()", "amount", "Expected invariant for this test."),
        ],
        "flow": [
            "The fuzzer supplies many candidate raw values.",
            "vm.assume removes values outside the intended domain.",
            "bound normalizes the candidate into a finite useful range.",
            "The test checks a property for each generated case.",
        ],
        "call": "testFuzzDeposit(whatever the fuzzer supplies);",
    },
    {
        "keys": frozenset({"script-deploy", "constructor", "new", "script-env", "script-broadcast", "address"}),
        "title": "Deployment script → environment → constructor → address",
        "story": "A Foundry script loads configuration, starts a broadcast, deploys a contract with constructor arguments, and captures its address.",
        "code": """function run() external returns (address deployed) {
    address admin = vm.envAddress("ADMIN");
    uint256 limit = vm.envUint("LIMIT");

    vm.startBroadcast();
    Vault vault = new Vault(admin, limit);
    vm.stopBroadcast();

    deployed = address(vault);
}""",
        "variables": [
            ("environment", "address", "admin", "ADMIN", "Deployment configuration."),
            ("environment", "uint256", "limit", "LIMIT", "Deployment configuration."),
            ("contract", "Vault", "vault", "new Vault(admin, limit)", "Fresh deployment."),
            ("return", "address", "deployed", "address(vault)", "Created contract address."),
        ],
        "flow": [
            "The script reads constructor inputs from environment variables.",
            "startBroadcast makes subsequent operations sendable deployment transactions.",
            "new Vault(...) runs the constructor.",
            "address(vault) identifies the resulting deployment.",
        ],
        "call": "forge script script/Deploy.s.sol --broadcast",
    },
    {
        "keys": frozenset({"create2", "keccak256", "init-code", "address", "constructor"}),
        "title": "CREATE2 → deterministic address from salt + init code",
        "story": "CREATE2 makes deployment addresses predictable from the deployer, salt, and hash of the creation bytecode.",
        "code": """bytes memory initCode =
    abi.encodePacked(
        type(Child).creationCode,
        abi.encode(100)
    );

address deployed;

assembly {
    deployed := create2(
        callvalue(),
        add(initCode, 0x20),
        mload(initCode),
        salt
    )
}""",
        "variables": [
            ("bytecode", "bytes", "initCode", "creationCode + constructor args", "Creation payload."),
            ("value", "bytes32", "salt", "bytes32(\"A\")", "Deterministic deployment salt."),
            ("return", "address", "deployed", "CREATE2 result", "New contract address."),
        ],
        "flow": [
            "creation bytecode includes constructor arguments.",
            "CREATE2 combines deployer, salt, and init-code hash to derive the address.",
            "The init code runs the constructor and returns runtime code.",
            "The resulting address can be known before deployment if the inputs are fixed.",
        ],
        "call": "deploy with a fixed salt and identical init code",
    },
    {
        "keys": frozenset({"address.code", "address.codehash", "extcodesize", "extcodehash", "address"}),
        "title": "Address → deployed code → code identity",
        "story": "Solidity and Yul offer several ways to inspect whether an address has code and identify that code.",
        "code": """function inspect(address target)
    external
    view
    returns (uint256 size, bytes32 hash)
{
    size = target.code.length;

    assembly {
        size := extcodesize(target)
        hash := extcodehash(target)
    }
}""",
        "variables": [
            ("parameter", "address", "target", "0xTarget", "Address under inspection."),
            ("derived", "uint256", "size", "extcodesize(target)", "Runtime code size."),
            ("derived", "bytes32", "hash", "extcodehash(target)", "Runtime code identity."),
        ],
        "flow": [
            "The target is just an address value.",
            "Solidity exposes its runtime code through target.code.",
            "Yul can inspect code size and code hash directly.",
            "Code inspection is useful for understanding call targets and account type assumptions.",
        ],
        "call": "inspect(target);",
    },
    {
        "keys": frozenset({"events", "event-indexed", "yul", "log1", "keccak256"}),
        "title": "Event → topic → Yul LOG",
        "story": "High-level events compile down to EVM logging. Indexed fields become topics, while dynamic indexed values are represented by Keccak hashes.",
        "code": """event Note(address indexed user, bytes indexed memo);

function emitNote(bytes calldata memo_) external {
    emit Note(msg.sender, memo_);
}

// Low-level shape:
// topic0 = keccak256("Note(address,bytes)")
// topic1 = padded msg.sender
// topic2 = keccak256(indexed memo encoding)
// log3(offset, size, topic0, topic1, topic2)""",
        "variables": [
            ("event field", "address indexed", "user", "msg.sender", "Filterable topic."),
            ("event field", "bytes indexed", "memo", "memo_", "Dynamic value represented by a hash topic."),
            ("Yul", "log2", "logger", "topic1/topic2", "Low-level log emission."),
        ],
        "flow": [
            "The event signature contributes the first topic.",
            "The indexed address becomes a directly filterable topic.",
            "The indexed bytes value is represented by a Keccak hash topic.",
            "Yul LOG instructions are the low-level mechanism underneath event emission.",
        ],
        "call": "emitNote(hex\"6869\");",
    },
    {
        "keys": frozenset({"transient-storage", "tload", "tstore", "reentrancy", "modifier"}),
        "title": "Transient guard → modifier → external call",
        "story": "Transient storage can hold a transaction-scoped reentrancy guard. The modifier sets it before an external call and clears it after.",
        "code": """uint256 transient entered;

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

// Yul forms: tload(...) / tstore(...)
""",
        "variables": [
            ("transient state", "uint256 transient", "entered", "0 → 1 → 0", "Transaction-scoped guard."),
            ("parameter", "address payable", "to", "0xAlice", "Recipient."),
            ("parameter", "uint256", "amount_", "1 ether", "Withdrawal amount."),
        ],
        "flow": [
            "The guard starts clear.",
            "The modifier checks and sets the transient value.",
            "The external call crosses the reentrancy boundary.",
            "The guard is cleared after the body.",
        ],
        "call": "withdraw(alice, 1 ether);",
    },
])


# ---------------------------------------------------------------------------
# Route-aware generic composition
# ---------------------------------------------------------------------------

def _covering_route(nodes):
    ordered = []
    seen = set()
    for node in nodes:
        canonical = canonicalize(node)
        if canonical not in seen:
            seen.add(canonical)
            ordered.append(canonical)

    if len(ordered) < 2:
        return ordered

    covered = {ordered[0]}
    route = [ordered[0]]
    remaining = set(ordered[1:])

    while remaining:
        best = None
        for target in sorted(remaining):
            for anchor in sorted(covered):
                path, labels = _shortest_path(anchor, target)
                if not path:
                    continue
                score = (
                    len(path),
                    sum(1 for n in path if n not in covered),
                    target,
                )
                if best is None or score < best[0]:
                    best = (score, anchor, target, path, labels)

        if best is None:
            target = sorted(remaining)[0]
            route.append(target)
            covered.add(target)
            remaining.remove(target)
            continue

        _score, _anchor, target, path, _labels = best
        for node in path[1:]:
            if node not in covered:
                route.append(node)
                covered.add(node)
            remaining.discard(node)

    return route


def connection_route(names):
    """Return one compact route that covers every requested concept."""
    return _covering_route(names)


def _route_text(route, limit=14):
    if len(route) <= limit:
        return " → ".join(route)
    return " → ".join(route[:limit]) + " → …"


def _generic_connect_scene(nodes):
    ordered = list(dict.fromkeys(canonicalize(node) for node in nodes))
    route = _covering_route(ordered)
    route_text = _route_text(route)

    meanings = {
        node: connection_meaning(node)
        for node in ordered
    }

    # Pick the strongest small executable bridge without pretending it covers
    # the entire arbitrary request. The complete route is shown separately.
    requested = set(ordered)
    if {"mapping", "abi.decode", "keccak256"} <= requested:
        code = """mapping(bytes32 => address) public state;

function bridge(bytes calldata raw) external {
    address user_ = abi.decode(raw, (address));
    bytes32 id = keccak256(raw);
    state[id] = user_;
}"""
        focus = "raw bytes → abi.decode → typed value, while the same bytes → keccak256 → mapping key"
        call = "bridge(abi.encode(alice));"
    elif {"function-selector", "abi.encodeWithSignature", "calldata", "call"} <= requested:
        code = """bytes memory data =
    abi.encodeWithSignature("quote(uint256)", 100);

(bool ok, ) = target.call(data);
require(ok);"""
        focus = "signature → selector/calldata → external call"
        call = 'target.call(abi.encodeWithSignature("quote(uint256)", 100));'
    elif {"interface", "call"} <= requested:
        code = """interface ITarget {
    function value() external view returns (uint256);
}

function bridge(ITarget target) external view returns (uint256) {
    return target.value();
}"""
        focus = "interface type → external function → returned value"
        call = "bridge(target);"
    elif {"mapping", "keccak256"} <= requested:
        code = """mapping(bytes32 => address) public state;

function bridge(bytes calldata raw) external {
    state[keccak256(raw)] = msg.sender;
}"""
        focus = "bytes → keccak256 → bytes32 mapping key"
        call = 'bridge(hex"416c696365");'
    elif {"mapping", "abi.decode"} <= requested:
        code = """mapping(address => uint256) public state;

function bridge(bytes calldata raw, uint256 value_) external {
    address key = abi.decode(raw, (address));
    state[key] = value_;
}"""
        focus = "raw bytes → abi.decode → mapping key"
        call = "bridge(abi.encode(alice), 100);"
    elif {"fallback", "msg.sig", "calldata"} <= requested:
        code = """fallback(bytes calldata input) external returns (bytes memory) {
    bytes4 selector = bytes4(input[:4]);
    return abi.encode(selector);
}"""
        focus = "fallback → raw calldata → selector"
        call = "send a raw calldata payload"
    elif {"receive", "msg.value", "call"} <= requested:
        code = """receive() external payable {
    credit[msg.sender] += msg.value;
}

function withdraw(uint256 amount_) external {
    credit[msg.sender] -= amount_;
    (bool ok, ) = payable(msg.sender).call{value: amount_}("");
    require(ok);
}"""
        focus = "ETH entry → caller accounting → external ETH call"
        call = "send ETH, then withdraw(amount)"
    elif {"vm-prank", "msg.sender", "test"} <= requested:
        code = """function testAsAlice() public {
    vm.prank(alice);
    target.sensitiveAction();
}"""
        focus = "test-controlled caller → msg.sender"
        call = "vm.prank(alice); target.sensitiveAction();"
    elif "yul" in requested or any(node.startswith("yul-") for node in requested):
        code = """function bridge(uint256 value_)
    external
    pure
    returns (uint256 result)
{
    assembly {
        result := add(value_, 1)
    }
}"""
        focus = "Solidity value → Yul word → Solidity result"
        call = "bridge(41);"
    else:
        code = """contract ConnectionBridge {
    // No single Solidity idiom owns this exact combination.
    // The full semantic route is:
    // __ROUTE__
}""".replace("__ROUTE__", route_text)
        focus = route_text
        call = "inspect the route one edge at a time"

    flow = [
        f"Requested concepts: {' + '.join(ordered)}.",
        f"Connection route: {route_text}.",
        f"Tiny code focuses on: {focus}.",
        "Every remaining requested concept is still represented in the route above; use the adjacent edge as the next teaching step.",
    ]

    variables = [
        ("requested", "concept", node, "selected", meanings[node])
        for node in ordered
    ]

    return {
        "keys": frozenset(ordered),
        "title": f"Connected route: {' → '.join(ordered[:4])}" + (" → …" if len(ordered) > 4 else ""),
        "story": (
            "This request has no single canonical Solidity idiom. Lowkey keeps it human-sized: "
            "it first gives one route covering every requested concept, then shows the strongest "
            "small executable bridge instead of pretending unrelated syntax is one pattern."
        ),
        "code": code.strip("\n"),
        "variables": variables,
        "flow": flow,
        "call": call,
        "generic": True,
        "route": route,
    }


def find_micro_scene(names):
    ordered = []
    seen = set()
    for name in names:
        node = canonicalize(name)
        if node not in seen:
            ordered.append(node)
            seen.add(node)

    requested = frozenset(ordered)

    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if frozenset(scene.get("keys", ())) == requested
    ]
    if exact:
        return exact[0]

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= frozenset(scene.get("keys", ()))
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(frozenset(scene.get("keys", ())) - requested),
                len(frozenset(scene.get("keys", ()))),
                scene.get("title", ""),
            )
        )
        scene = candidates[0]
        if "route" not in scene:
            scene["route"] = _covering_route(ordered)
        return scene

    return _generic_connect_scene(ordered)


# Rebuild the known-node set after adding the deep reference vocabulary.
def _final_deep_nodes():
    nodes = set(_EXTRA_CONCEPTS)
    nodes.update(canonicalize(name) for name in _CATALOG_ALIASES.values())
    for left, right, _label in _COMPREHENSIVE_CONNECTION_EDGES:
        nodes.add(canonicalize(left))
        nodes.add(canonicalize(right))
    return nodes


def is_known_concept(name: str) -> bool:
    key = _norm(name)
    if key in _COMPREHENSIVE_COMPOSITES:
        return True
    if key in _SEMANTIC_ALIASES:
        return True
    if key in _CATALOG_ALIASES:
        return True
    canonical = canonicalize(name)
    return canonical in _final_deep_nodes()


def connection_meaning(name: str) -> str:
    canonical = canonicalize(name)
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]
    target = _CATALOG_ALIASES.get(_norm(name))
    if target and target in _CATALOG_NAME_TO_MEANING:
        return _CATALOG_NAME_TO_MEANING[target]
    target = _CATALOG_ALIASES.get(_norm(canonical))
    if target and target in _CATALOG_NAME_TO_MEANING:
        return _CATALOG_NAME_TO_MEANING[target]
    return f"{canonical} is a recognized Solidity/Foundry concept."


# Compatibility alias for callers that inspect the graph directly.
CONNECTION_GRAPH = _COMPREHENSIVE_CONNECTION_EDGES

# Final route primitive: keep path selection deterministic and weighted.
def _shortest_path(start, goal):
    if start == goal:
        return [start], []

    from collections import defaultdict
    import heapq as _heapq

    adjacency = defaultdict(list)
    for left, right, label in _COMPREHENSIVE_CONNECTION_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        weight = 1 if not label.startswith("family ") and not label.startswith("same ") and not label.startswith("catalog coverage") else 5
        adjacency[a].append((b, label, weight))
        adjacency[b].append((a, label, weight))

    heap = [(0, start, (start,), ())]
    best = {start: 0}

    while heap:
        cost, node, path, labels = _heapq.heappop(heap)
        if node == goal:
            return list(path), list(labels)
        if cost != best.get(node):
            continue

        for nxt, label, weight in adjacency.get(node, ()):
            new_cost = cost + weight
            if new_cost >= best.get(nxt, 10**9):
                continue
            best[nxt] = new_cost
            _heapq.heappush(
                heap,
                (new_cost, nxt, path + (nxt,), labels + (label,)),
            )

    return None, None




# ---------------------------------------------------------------------------
# END OF DEEP CROSS-CHECK LAYER
# ---------------------------------------------------------------------------
#
# Final reference pass, 2026-10.  These nodes/edges were checked against:
# - the Solidity language reference and ABI specification,
# - storage/transient-layout rules and Yul builtins,
# - representative OpenZeppelin token/access-control/proxy/cryptography code,
# - Safe multisig patterns,
# - Uniswap v4 hook/library/transient-state patterns.
#
# The graph distinguishes "direct syntax/data-flow relationship" from
# "same protocol pattern".  A route may therefore use intermediate concepts.
#

_FINAL_SEMANTIC_ALIASES = {
    "tuple": "tuples",
    "tuples": "tuples",
    "destructuring": "tuples",
    "named-arguments": "named-arguments",
    "named-argument": "named-arguments",
    "call-options": "call-options",
    "value-option": "call-options",
    "gas-option": "call-options",
    "memory-copy": "memory-copy",
    "calldata-slice": "calldata-slices",
    "calldata-slices": "calldata-slices",
    "public-getter": "public-getter",
    "getter": "public-getter",
    "event-indexed": "event-indexed",
    "indexed": "event-indexed",
    "anonymous-event": "anonymous-event",
    "packed-encoding": "encodePacked",
    "encode-packed": "encodePacked",
    "erc165": "erc165-interface",
    "erc165-interface": "erc165-interface",
    "receiver-hook": "receiver-hook",
    "token-receiver": "receiver-hook",
    "erc1271": "erc1271",
    "erc1271-signature": "erc1271",
    "erc20": "erc20-pattern",
    "erc20-pattern": "erc20-pattern",
    "erc721": "erc721-pattern",
    "erc721-pattern": "erc721-pattern",
    "erc1155": "erc1155-pattern",
    "erc1155-pattern": "erc1155-pattern",
    "permit": "permit-pattern",
    "permit-pattern": "permit-pattern",
    "eip712": "eip712-pattern",
    "eip712-pattern": "eip712-pattern",
    "multisig": "multisig-pattern",
    "safe": "multisig-pattern",
    "safe-pattern": "multisig-pattern",
    "timelock": "timelock-pattern",
    "timelock-pattern": "timelock-pattern",
    "governor": "governor-pattern",
    "governor-pattern": "governor-pattern",
    "proxy-upgrade": "proxy-upgrade-pattern",
    "proxy-upgrade-pattern": "proxy-upgrade-pattern",
    "uups": "proxy-upgrade-pattern",
    "erc1967": "erc1967-storage",
    "erc1967-storage": "erc1967-storage",
    "storage-slot": "storage-slot",
    "struct-abi": "struct-abi",
    "error-data": "error-data",
    "log-topics": "log-topics",
    "token-approval": "token-approval",
    "allowance": "token-approval",
    "transfer-from": "transfer-from",
    "safe-transfer": "safe-transfer",
    "batch-transfer": "batch-transfer",
    "hook": "receiver-hook",
    "create2": "create2",
    "salt": "create2",
    "creation-code": "init-code",
    "runtime-code": "runtime-code",
    "address-code": "address.code",
    "address-codehash": "address.codehash",
    "block-chainid": "block.chainid",
    "chainid": "block.chainid",
    "blob-basefee": "block.blobbasefee",
    "blobhash": "blobhash",
    "blockhash": "blockhash",
    "block-coinbase": "block.coinbase",
    "block-gaslimit": "block.gaslimit",
    "tx-gasprice": "tx.gasprice",
    "self-balance": "selfbalance",
    "yul-assembly": "yul",
    "leave": "yul-control-flow",
    "break": "yul-control-flow",
    "continue": "yul-control-flow",
    "switch": "yul-control-flow",
    "yul-loop": "yul-control-flow",
    "object": "yul-object",
    "memory-safe": "memory-safe",
}
_SEMANTIC_ALIASES.update(_FINAL_SEMANTIC_ALIASES)

_FINAL_MEANINGS = {
    "tuples": "A fixed grouping of values used for multiple returns, destructuring, and ABI tuple encoding.",
    "named-arguments": "Call-site syntax that names arguments by parameter name.",
    "call-options": "Per-call settings such as attached ETH and forwarded gas.",
    "memory-copy": "A copy of reference-type data into temporary memory rather than persistent storage.",
    "public-getter": "Compiler-generated external getter behavior for public state variables, with special rules for mappings and arrays.",
    "anonymous-event": "An event whose signature is not automatically stored in topic zero.",
    "erc165-interface": "A standard interface-ID capability check built from XORed function selectors.",
    "receiver-hook": "A callback interface used to confirm that a contract can safely receive tokens or another protocol asset.",
    "erc1271": "A contract-wallet signature validation interface that lets contracts approve signatures without EOA ecrecover.",
    "erc1155-pattern": "Multi-token accounting using token-id/account mappings, batch arrays, and receiver callbacks.",
    "eip712-pattern": "Typed structured-data hashing that combines type hashes, a domain separator, a struct hash, and a final digest.",
    "multisig-pattern": "Threshold-controlled execution using owners, signatures, a nonce, transaction hashing, and external calls.",
    "timelock-pattern": "Scheduled operation state keyed by a hash with timestamp-based readiness and later execution.",
    "governor-pattern": "Proposal/vote state built from hashed proposal identities, arrays of targets/calldatas, interfaces, and events.",
    "proxy-upgrade-pattern": "Upgrade logic that changes an implementation address while calls execute through delegatecall in proxy storage.",
    "erc1967-storage": "A standardized proxy storage-slot convention for implementation/admin/beacon addresses.",
    "storage-slot": "The 32-byte storage coordinate used by SLOAD/SSTORE and exposed by advanced storage patterns.",
    "struct-abi": "The ABI representation of a Solidity struct as a tuple with its component types and order.",
    "error-data": "Raw revert bytes containing an error selector plus ABI-encoded arguments when a custom error is used.",
    "log-topics": "The topic words attached to an EVM log, including event signature and indexed parameters.",
    "token-approval": "Allowance/approval state that authorizes another address to spend or move assets.",
    "transfer-from": "A delegated token transfer that consumes an allowance or approval on behalf of an owner.",
    "safe-transfer": "A token movement that verifies the recipient contract's receiver hook when required.",
    "batch-transfer": "A token operation that processes parallel id/value arrays in one call.",
    "block.chainid": "The current chain identifier, often bound into signatures and domain separators.",
    "blobbasefee": "The current block's blob base fee.",
    "blobhash": "A global that returns a blob versioned hash for a blob index.",
    "blockhash": "A global function that retrieves a recent block hash within its allowed history window.",
    "block.coinbase": "The current block's fee-recipient address.",
    "block.gaslimit": "The current block gas limit.",
    "tx.gasprice": "The gas price associated with the current transaction context.",
    "selfbalance": "A Yul builtin that reads the current contract balance.",
    "yul-object": "Yul object/data syntax used to package deploy-time and runtime code.",
    "memory-safe": "An inline-assembly annotation/discipline used to let the compiler reason about memory safety.",
}
_EXTRA_MEANINGS.update(_FINAL_MEANINGS)
_EXTRA_CONCEPTS.update(_FINAL_MEANINGS)

_FINAL_TINY_CONNECTIONS = [
    # Core language/data semantics.
    ("tuples", "abi.encode", "ABI encodes grouped values as tuples"),
    ("tuples", "abi.decode", "ABI decoding can restore multiple tuple components"),
    ("tuples", "returns", "multiple return values are commonly unpacked as tuples"),
    ("tuples", "parameter-vs-argument", "function arguments occupy tuple-shaped ABI positions"),
    ("named-arguments", "function", "named arguments refer to parameter names at the call site"),
    ("call-options", "call", "call options attach ETH/gas to an outgoing call"),
    ("call-options", "payable", "value call options require an ETH-compatible call path"),
    ("memory-copy", "storage-memory-calldata", "copies explain why storage/memory/calldata are not interchangeable"),
    ("public-getter", "mapping", "public mapping getters take keys instead of returning the mapping itself"),
    ("public-getter", "arrays", "public array getters expose indexed elements and length-dependent behavior"),
    ("public-getter", "structs", "public struct getters omit fields that cannot be represented as getter arguments/returns"),
    ("anonymous-event", "events", "anonymous changes how event signature topics are emitted"),
    ("log-topics", "event-indexed", "indexed fields occupy log topics"),
    ("log-topics", "keccak256", "event signatures and dynamic indexed values use Keccak-derived topics"),
    ("erc165-interface", "interface", "ERC-165 expresses interface support as a bytes4 interface ID"),
    ("erc165-interface", "function-selector", "interface IDs are derived from function selectors"),
    ("receiver-hook", "interface", "receiver checks are usually defined through interfaces"),
    ("receiver-hook", "external-call", "receiver hooks create a callback boundary after a token transfer"),
    ("receiver-hook", "reentrancy", "receiver callbacks can re-enter a token contract"),
    ("erc1271", "signature-verification", "contract wallets validate signatures through a callable interface"),
    ("erc1271", "interface", "contract signature validation is an interface call rather than ecrecover"),
    ("erc1271", "bytes", "signature payloads are passed as bytes"),
    ("struct-abi", "structs", "Solidity structs map to ABI tuples"),
    ("struct-abi", "tuples", "a struct's ABI shape is tuple(component types in order)"),
    ("struct-abi", "abi.encode", "struct arguments are ABI-encoded by component values"),
    ("struct-abi", "abi.decode", "encoded tuples can be decoded into struct-shaped values"),
    ("encodePacked", "keccak256", "packed encodings are commonly hashed"),
    ("encodePacked", "signature-verification", "packed encodings are often used in signed-message construction"),
    ("encodePacked", "bytes", "packed encoding produces bytes"),
    ("encodePacked", "front-running", "a commitment may hash a packed representation of a secret"),
    # Tokens.
    ("erc20-pattern", "mapping", "ERC-20 balances are commonly stored as address-to-amount mappings"),
    ("erc20-pattern", "token-approval", "ERC-20 allowance is an owner-to-spender nested mapping"),
    ("erc20-pattern", "events", "ERC-20 state transitions emit Transfer/Approval logs"),
    ("token-approval", "nested-mapping", "allowance has two address keys"),
    ("token-approval", "msg.sender", "approve typically records the caller as the allowance owner"),
    ("transfer-from", "token-approval", "delegated transfers consume an owner's allowance"),
    ("transfer-from", "msg.sender", "the caller is the spender in a typical allowance flow"),
    ("transfer-from", "mapping", "transferFrom updates balances and allowance mappings"),
    ("safe-transfer", "receiver-hook", "safe transfer checks the recipient contract callback"),
    ("safe-transfer", "interface", "receiver validation calls a receiver interface"),
    ("safe-transfer", "reentrancy", "receiver callbacks happen across an external call boundary"),
    ("erc721-pattern", "mapping", "NFT ownership and approval state use tokenId-based mappings"),
    ("erc721-pattern", "receiver-hook", "safe NFT transfers use an ERC721 receiver callback"),
    ("erc721-pattern", "token-approval", "NFTs use per-token approvals and operator approvals"),
    ("erc721-pattern", "events", "NFT transfers/approvals are represented by events"),
    ("erc1155-pattern", "nested-mapping", "ERC-1155 balances use tokenId/account keyed mappings"),
    ("erc1155-pattern", "arrays", "batch operations process parallel id and value arrays"),
    ("erc1155-pattern", "receiver-hook", "safe ERC-1155 transfers call receiver interfaces"),
    ("erc1155-pattern", "events", "single and batch transfers emit distinct events"),
    ("batch-transfer", "arrays", "ids and values are parallel arrays"),
    ("batch-transfer", "loops", "batch processing commonly iterates the input arrays"),
    # Typed-signature / permit / governance.
    ("eip712-pattern", "structs", "typed messages mirror Solidity-style structured records"),
    ("eip712-pattern", "keccak256", "domain and struct hashes are Keccak digests"),
    ("eip712-pattern", "abi.encode", "type hashes and fields are ABI-encoded before hashing"),
    ("eip712-pattern", "block.chainid", "the domain commonly binds the signed message to a chain"),
    ("eip712-pattern", "address", "the domain commonly binds the verifying contract address"),
    ("eip712-pattern", "signature-verification", "the final digest is checked against a signature"),
    ("eip712-pattern", "nonce", "application protocols commonly add nonces for replay protection"),
    ("permit-pattern", "eip712-pattern", "permit flows are a common EIP-712 application"),
    ("permit-pattern", "token-approval", "permit authorizes allowance without an on-chain approve transaction"),
    ("permit-pattern", "nonce", "each permit authorization commonly consumes a nonce"),
    ("multisig-pattern", "mapping", "owner/approval state uses mappings in common multisig designs"),
    ("multisig-pattern", "arrays", "owner sets and transaction payloads commonly use arrays"),
    ("multisig-pattern", "nonce", "the transaction hash is bound to a nonce"),
    ("multisig-pattern", "eip712-pattern", "Safe-style transaction hashes use typed-data hashing"),
    ("multisig-pattern", "ecrecover", "EOA signatures can be checked by recovering the signer"),
    ("multisig-pattern", "call", "successful authorization ends in external transaction execution"),
    ("multisig-pattern", "threshold", "execution requires a configured minimum number of valid approvals"),
    ("timelock-pattern", "mapping", "scheduled operation state is keyed by an operation ID"),
    ("timelock-pattern", "keccak256", "operation IDs are hashes of operation content"),
    ("timelock-pattern", "abi.encode", "operation content is commonly encoded before hashing"),
    ("timelock-pattern", "block.timestamp", "readiness depends on a time threshold"),
    ("timelock-pattern", "enum", "timelocks often expose Pending/Ready/Done-style state"),
    ("timelock-pattern", "call", "execution eventually performs the queued target call(s)"),
    ("timelock-pattern", "events", "scheduling and execution are observable through events"),
    ("governor-pattern", "arrays", "proposals carry target/value/calldata arrays"),
    ("governor-pattern", "keccak256", "proposal IDs are commonly hash-derived"),
    ("governor-pattern", "abi.encode", "proposal inputs are encoded before hashing"),
    ("governor-pattern", "mapping", "proposal/vote state is stored by proposal ID/account"),
    ("governor-pattern", "enum", "governance uses explicit proposal/vote states"),
    ("governor-pattern", "events", "proposal and voting transitions emit logs"),
    ("governor-pattern", "interface", "governance implements a public interface"),
    ("governor-pattern", "eip712-pattern", "off-chain vote signatures may use typed structured data"),
    # Proxies / storage.
    ("erc1967-storage", "storage-slot", "ERC-1967 identifies special implementation/admin storage coordinates"),
    ("erc1967-storage", "keccak256", "standardized slots are hash-derived constants"),
    ("erc1967-storage", "proxy-fallback", "the implementation slot feeds proxy delegation"),
    ("proxy-upgrade-pattern", "proxy-fallback", "upgradeable proxies and forwarding share the fallback/delegatecall path"),
    ("proxy-upgrade-pattern", "delegatecall", "implementation code runs through delegatecall"),
    ("proxy-upgrade-pattern", "storage-layout", "implementation upgrades depend on compatible storage layout"),
    ("proxy-upgrade-pattern", "access-control", "changing an implementation is privileged state"),
    ("proxy-upgrade-pattern", "events", "upgrades are commonly emitted as events"),
    ("proxy-upgrade-pattern", "erc1967-storage", "ERC-1967 is a standard implementation-slot pattern"),
    ("delegatecall", "msg.sender", "delegatecall preserves the original caller in the delegated context"),
    ("delegatecall", "address(this).balance", "delegatecall preserves the proxy address as the execution address"),
    ("delegatecall", "storage-layout", "delegated code interprets the caller's storage"),
    ("proxy-fallback", "calldata", "proxy fallback forwards the received calldata"),
    ("proxy-fallback", "returndata", "proxy fallback bubbles implementation returndata"),
    # Creation / code.
    ("create2", "init-code", "CREATE2 hashes the exact init code"),
    ("init-code", "abi.encode", "constructor arguments are appended/encoded into creation input"),
    ("init-code", "constructor", "init code executes construction logic"),
    ("runtime-code", "address.code", "runtime bytecode is what an address.code read exposes"),
    ("runtime-code", "address.codehash", "runtime bytecode determines the code hash"),
    ("address.code", "extcodesize", "Solidity code length and Yul extcodesize inspect deployed code presence"),
    ("address.codehash", "extcodehash", "Solidity codehash and Yul extcodehash inspect code identity"),
    ("create2", "address.code", "CREATE2 creates the address whose runtime code is inspected later"),
    # Globals and Yul.
    ("block.chainid", "eip712-pattern", "chain identity is part of domain separation"),
    ("block.chainid", "signature-verification", "signatures may be bound to a specific chain"),
    ("blockhash", "block.number", "blockhash is indexed by a recent block number"),
    ("block.coinbase", "address", "the block fee recipient is an address"),
    ("block.gaslimit", "gasleft", "block gas limit and remaining execution gas are distinct gas contexts"),
    ("tx.gasprice", "gasleft", "transaction pricing and remaining execution gas answer different questions"),
    ("blobbasefee", "blobhash", "blob-related globals describe blob pricing and blob identities"),
    ("selfbalance", "contract-balance", "Yul selfbalance reads the current contract balance"),
    ("caller", "msg.sender", "Yul caller is the low-level equivalent of the immediate Solidity sender"),
    ("callvalue", "msg.value", "Yul callvalue is the low-level equivalent of attached call ETH"),
    ("mload", "memory-copy", "memory reads/writes are how Yul manipulates copied reference data"),
    ("calldataload", "calldata", "Yul reads the raw external input"),
    ("calldatacopy", "calldata-slices", "Yul can copy a selected calldata region into memory"),
    ("returndatacopy", "returndata", "Yul copies the most recent return-data buffer"),
    ("returndatasize", "returndata", "Yul exposes the size of the most recent return-data buffer"),
    ("sload", "storage-slot", "SLOAD reads one 32-byte storage coordinate"),
    ("sstore", "storage-slot", "SSTORE writes one 32-byte storage coordinate"),
    ("tload", "transient-storage", "TLOAD reads transaction-scoped storage"),
    ("tstore", "transient-storage", "TSTORE writes transaction-scoped storage"),
    ("tload", "reentrancy", "transient guards commonly use TLOAD/TSTORE"),
    ("tstore", "reentrancy", "transient guards commonly use TLOAD/TSTORE"),
    ("yul-control-flow", "if-else", "Yul supplies low-level conditional control"),
    ("yul-control-flow", "loops", "Yul supports for/break/continue-style control"),
    ("yul-control-flow", "switch", "Yul switch selects among cases"),
    ("yul-functions", "function", "Yul local functions encapsulate low-level computation"),
    ("yul-object", "init-code", "Yul objects can package creation and runtime data"),
    ("memory-safe", "yul-memory", "memory-safety annotations constrain inline assembly's memory use"),
    # Testing / PoC connections.
    ("vm-load", "storage-slot", "vm.load exposes a raw storage coordinate to tests"),
    ("vm-store", "storage-slot", "vm.store writes a raw storage coordinate in tests"),
    ("vm-load", "mapping-slots", "reading a mapping requires its derived slot"),
    ("vm-store", "mapping-slots", "writing a mapping requires its derived slot"),
    ("vm-etch", "address.code", "etch changes runtime code at a test address"),
    ("vm-etch", "extcodesize", "code replacement can exercise code-existence assumptions"),
    ("vm-expect-call", "function-selector", "expected calls can be asserted by calldata selector"),
    ("vm-expect-call", "returndata", "call expectations sit around an external boundary"),
    ("test-events", "log-topics", "event assertions inspect emitted log topics"),
    ("invariant-tests", "mapping", "stateful invariants often quantify over mapping-backed accounting"),
    ("invariant-tests", "arrays", "handlers commonly mutate arrays/state over many calls"),
    ("fork-tests", "oracle", "forks reproduce external protocol/oracle state"),
    ("script-interaction", "interface", "scripts use interfaces to interact with deployed dependencies"),
    ("script-interaction", "call", "scripts cross external call boundaries"),
    ("poc-upgrade", "proxy-upgrade-pattern", "upgrade PoCs test implementation/storage assumptions"),
    ("poc-signature", "eip712-pattern", "signature PoCs test typed-data/authentication boundaries"),
    ("poc-token", "erc20-pattern", "token PoCs exercise token accounting and allowance invariants"),
    ("poc-token", "erc721-pattern", "NFT PoCs exercise owner/approval/receiver behavior"),
]

for _edge in _FINAL_TINY_CONNECTIONS:
    if _edge not in _COMPREHENSIVE_CONNECTION_EDGES:
        _COMPREHENSIVE_CONNECTION_EDGES.append(_edge)


def _final_add_scene(keys, title, story, code, variables, flow, call):
    scene = {
        "keys": frozenset(canonicalize(k) for k in keys),
        "title": title,
        "story": story,
        "code": code.strip("\n"),
        "variables": list(variables),
        "flow": list(flow),
        "call": call,
    }
    COMPREHENSIVE_MICRO_SCENES.append(scene)
    return scene


_FINAL_RESEARCH_SCENES = [
    (
        ["erc20-pattern", "mapping", "token-approval", "events", "msg.sender"],
        "ERC20: balance + allowance + transfer",
        "A fungible token ties two mappings together: one for balances and one for delegated spending. Events expose the state transition.",
        """
mapping(address => uint256) public balanceOf;
mapping(address => mapping(address => uint256)) public allowance;

event Approval(address indexed owner, address indexed spender, uint256 amount);
event Transfer(address indexed from, address indexed to, uint256 amount);

function approve(address spender_, uint256 amount_) external {
    allowance[msg.sender][spender_] = amount_;
    emit Approval(msg.sender, spender_, amount_);
}

function transferFrom(address owner_, address to_, uint256 amount_) external {
    require(allowance[owner_][msg.sender] >= amount_);
    allowance[owner_][msg.sender] -= amount_;
    balanceOf[owner_] -= amount_;
    balanceOf[to_] += amount_;
    emit Transfer(owner_, to_, amount_);
}
""",
        [
            ("state", "mapping(address => uint256)", "balanceOf", "balanceOf[alice]", "Owner-to-token balance."),
            ("state", "mapping(address => mapping(address => uint256))", "allowance", "allowance[alice][bob]", "Owner-to-spender authorization."),
            ("global", "address", "msg.sender", "bob", "Spender in transferFrom."),
            ("parameter", "address", "owner_", "alice", "Token owner."),
            ("parameter", "address", "to_", "carol", "Recipient."),
            ("parameter", "uint256", "amount_", "100", "Transfer amount."),
        ],
        [
            "approve records msg.sender as the allowance owner and spender_ as the delegate.",
            "transferFrom reads allowance[owner_][msg.sender].",
            "The allowance and both balances are updated.",
            "Approval/Transfer events expose the important state transitions.",
        ],
        "alice.approve(bob, 100); bob.transferFrom(alice, carol, 100);",
    ),
    (
        ["erc721-pattern", "mapping", "token-approval", "receiver-hook", "events"],
        "ERC721: tokenId → owner → approval → receiver",
        "An NFT tracks ownership by tokenId, approvals by tokenId, and optionally calls the receiver contract during safe transfer.",
        """
mapping(uint256 => address) public ownerOf;
mapping(uint256 => address) public getApproved;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

function approve(address to_, uint256 tokenId_) external {
    getApproved[tokenId_] = to_;
}

function safeTransfer(address to_, uint256 tokenId_, bytes calldata data_) external {
    address from = ownerOf[tokenId_];
    ownerOf[tokenId_] = to_;

    if (to_.code.length > 0) {
        require(
            IERC721Receiver(to_).onERC721Received(
                msg.sender, from, tokenId_, data_
            ) == IERC721Receiver.onERC721Received.selector
        );
    }

    emit Transfer(from, to_, tokenId_);
}
""",
        [
            ("state", "mapping(uint256 => address)", "ownerOf", "ownerOf[tokenId]", "NFT ownership."),
            ("state", "mapping(uint256 => address)", "getApproved", "getApproved[tokenId]", "Per-token delegate."),
            ("parameter", "address", "to_", "0xBob", "New owner."),
            ("parameter", "uint256", "tokenId_", "7", "Token identity."),
            ("global", "address", "msg.sender", "0xAlice", "Caller/operator."),
        ],
        [
            "tokenId_ selects the current owner.",
            "approve writes a per-token mapping entry.",
            "safeTransfer changes ownership before checking a contract receiver.",
            "The receiver callback crosses an external boundary and returns a selector.",
            "Transfer emits the state change.",
        ],
        "safeTransfer(bob, 7, hex\"\");",
    ),
    (
        ["erc1155-pattern", "nested-mapping", "arrays", "receiver-hook", "events"],
        "ERC1155: tokenId + account → balance, plus batch arrays",
        "Multi-token accounting adds a tokenId dimension to balances and uses parallel arrays for batch transfers.",
        """
mapping(uint256 => mapping(address => uint256)) public balanceOf;

event TransferSingle(
    address indexed operator,
    address indexed from,
    address indexed to,
    uint256 id,
    uint256 value
);

event TransferBatch(
    address indexed operator,
    address indexed from,
    address indexed to,
    uint256[] ids,
    uint256[] values
);

function mintBatch(
    address to_,
    uint256[] calldata ids_,
    uint256[] calldata values_
) external {
    require(ids_.length == values_.length);

    for (uint256 i = 0; i < ids_.length; ++i) {
        balanceOf[ids_[i]][to_] += values_[i];
    }

    emit TransferBatch(msg.sender, address(0), to_, ids_, values_);
}
""",
        [
            ("state", "mapping(uint256 => mapping(address => uint256))", "balanceOf", "balanceOf[id][account]", "Token/account balance."),
            ("parameter", "uint256[] calldata", "ids_", "[1, 2]", "Batch token IDs."),
            ("parameter", "uint256[] calldata", "values_", "[10, 20]", "Parallel quantities."),
            ("global", "address", "msg.sender", "0xMinter", "Operator."),
        ],
        [
            "Each token ID selects an inner account mapping.",
            "The two arrays must have the same length.",
            "The loop updates one token/account pair per index.",
            "The batch event records the parallel arrays.",
        ],
        "mintBatch(alice, [1, 2], [10, 20]);",
    ),
    (
        ["eip712-pattern", "structs", "keccak256", "abi.encode", "signature-verification", "nonce", "block.chainid", "address"],
        "EIP712: typed struct → domain → digest → signer",
        "Typed structured data connects Solidity structs to deterministic hashing, a domain separator, chain/contract binding, and signature verification.",
        """
struct Permit {
    address owner;
    address spender;
    uint256 value;
    uint256 nonce;
}

bytes32 public constant TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce)");

function digest(Permit memory permit_)
    external
    view
    returns (bytes32)
{
    bytes32 structHash = keccak256(
        abi.encode(
            TYPEHASH,
            permit_.owner,
            permit_.spender,
            permit_.value,
            permit_.nonce
        )
    );

    bytes32 domainSeparator = keccak256(
        abi.encode(
            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
            block.chainid,
            address(this)
        )
    );

    return keccak256(
        abi.encodePacked("\\x19\\x01", domainSeparator, structHash)
    );
}
""",
        [
            ("struct", "Permit", "permit_", "owner/spender/value/nonce", "Typed message."),
            ("state", "bytes32", "TYPEHASH", "keccak256(type string)", "Type identity."),
            ("global", "uint256", "block.chainid", "1", "Domain binding."),
            ("global", "address", "address(this)", "0xToken", "Verifying-contract binding."),
            ("field", "uint256", "nonce", "7", "Replay protection field."),
        ],
        [
            "The struct fields form a typed message.",
            "abi.encode packs the type hash and fields.",
            "keccak256 produces the struct hash.",
            "The domain binds the digest to a chain and verifying contract.",
            "A signature verifier can use the final digest to authenticate the signer.",
        ],
        "digest(permit);",
    ),
    (
        ["timelock-pattern", "mapping", "keccak256", "abi.encode", "block.timestamp", "call", "events"],
        "Timelock: operation hash → timestamp → executable call",
        "A timelock stores a hashed operation and the timestamp when it becomes executable, then later performs the target call.",
        """
mapping(bytes32 => uint256) public readyAt;

event Scheduled(bytes32 indexed id, uint256 executeAt);
event Executed(bytes32 indexed id);

function schedule(
    address target_,
    uint256 value_,
    bytes calldata data_,
    uint256 delay_
) external returns (bytes32 id) {
    id = keccak256(abi.encode(target_, value_, data_));
    readyAt[id] = block.timestamp + delay_;
    emit Scheduled(id, readyAt[id]);
}

function execute(
    address target_,
    uint256 value_,
    bytes calldata data_
) external {
    bytes32 id = keccak256(abi.encode(target_, value_, data_));
    require(block.timestamp >= readyAt[id]);
    (bool ok, ) = target_.call{value: value_}(data_);
    require(ok);
    emit Executed(id);
}
""",
        [
            ("state", "mapping(bytes32 => uint256)", "readyAt", "readyAt[id]", "Scheduled execution time."),
            ("parameter", "address", "target_", "0xTarget", "Target contract."),
            ("parameter", "bytes", "data_", "selector + args", "Call payload."),
            ("derived", "bytes32", "id", "keccak256(abi.encode(...))", "Operation identity."),
            ("global", "uint256", "block.timestamp", "now", "Time gate."),
        ],
        [
            "The target/value/data tuple is encoded and hashed into one ID.",
            "The ID becomes a mapping key whose value is a future timestamp.",
            "Execution recomputes the same ID.",
            "The timestamp gates a low-level call with the stored ETH value.",
            "Events expose scheduling and execution.",
        ],
        "schedule(target, 1 ether, data, 2 days); execute(target, 1 ether, data);",
    ),
    (
        ["governor-pattern", "arrays", "keccak256", "abi.encode", "mapping", "enum", "events"],
        "Governor: proposal payload arrays → proposalId → state",
        "Governance proposals bundle parallel arrays of targets, ETH values, and calldata; hashing that payload creates the proposal identity used by state/vote mappings.",
        """
enum ProposalState { Pending, Active, Succeeded, Executed, Canceled }

mapping(uint256 => ProposalState) public state;

event ProposalCreated(
    uint256 indexed id,
    address[] targets,
    uint256[] values,
    bytes[] calldatas
);

function hashProposal(
    address[] calldata targets_,
    uint256[] calldata values_,
    bytes[] calldata calldatas_
) public pure returns (uint256) {
    return uint256(keccak256(
        abi.encode(targets_, values_, calldatas_)
    ));
}
""",
        [
            ("parameter", "address[] calldata", "targets_", "[0xA, 0xB]", "Proposal destinations."),
            ("parameter", "uint256[] calldata", "values_", "[0, 1 ether]", "ETH values paired by index."),
            ("parameter", "bytes[] calldata", "calldatas_", "[dataA, dataB]", "Call payloads paired by index."),
            ("derived", "uint256", "proposalId", "uint256(keccak256(...))", "Proposal identity."),
            ("state", "mapping(uint256 => ProposalState)", "state", "state[proposalId]", "Lifecycle state."),
        ],
        [
            "The three arrays represent one ordered operation bundle.",
            "ABI encoding preserves the tuple/array structure before hashing.",
            "The hash becomes a stable proposal ID.",
            "The ID selects proposal state and related accounting.",
            "Events let indexers reconstruct the proposal payload.",
        ],
        "hashProposal(targets, values, calldatas);",
    ),
    (
        ["multisig-pattern", "mapping", "nonce", "eip712-pattern", "ecrecover", "call"],
        "Multisig: nonce → typed transaction hash → threshold signatures → call",
        "A multisig turns a transaction into a hash, verifies enough owners signed it, then executes the authorized call.",
        """
mapping(address => bool) public isOwner;
uint256 public threshold;
uint256 public nonce;

function transactionHash(
    address to_,
    uint256 value_,
    bytes calldata data_
) public view returns (bytes32) {
    return keccak256(
        abi.encode(
            keccak256("Tx(address to,uint256 value,bytes data,uint256 nonce)"),
            to_,
            value_,
            keccak256(data_),
            nonce
        )
    );
}

// Conceptual execution:
// verify signatures -> nonce++ -> to_.call{value: value_}(data_)
""",
        [
            ("state", "mapping(address => bool)", "isOwner", "isOwner[alice]", "Owner membership."),
            ("state", "uint256", "threshold", "2", "Required signatures."),
            ("state", "uint256", "nonce", "7", "Replay protection."),
            ("parameter", "address", "to_", "0xTarget", "Execution destination."),
            ("parameter", "bytes", "data_", "selector + args", "Execution payload."),
        ],
        [
            "isOwner identifies who is allowed to sign.",
            "The transaction fields and nonce are ABI-encoded and hashed.",
            "Signatures are checked against the digest and owner set.",
            "Enough valid signatures satisfy the threshold.",
            "The nonce advances before the external call.",
            "The authorized call executes.",
        ],
        "execute(to, value, data, signatures);",
    ),
    (
        ["proxy-upgrade-pattern", "erc1967-storage", "delegatecall", "proxy-fallback", "storage-layout"],
        "Upgrade proxy: implementation slot → delegatecall → shared storage",
        "An upgradeable proxy stores the implementation address in a dedicated slot, then fallback delegates calls into that implementation while using proxy storage.",
        """
bytes32 internal constant IMPLEMENTATION_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

function _implementation() internal view returns (address impl) {
    assembly {
        impl := sload(IMPLEMENTATION_SLOT)
    }
}

fallback() external payable {
    address impl = _implementation();

    assembly {
        calldatacopy(0, 0, calldatasize())
        let ok := delegatecall(
            gas(), impl, 0, calldatasize(), 0, 0
        )
        returndatacopy(0, 0, returndatasize())

        switch ok
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
""",
        [
            ("constant", "bytes32", "IMPLEMENTATION_SLOT", "hash-derived", "Dedicated proxy slot."),
            ("derived", "address", "impl", "sload(slot)", "Current implementation."),
            ("global", "msg.data", "calldata", "selector + args", "Forwarded call."),
            ("Yul", "word", "ok", "0/1", "delegatecall result."),
        ],
        [
            "The implementation slot is a fixed storage coordinate.",
            "Fallback receives the original calldata.",
            "delegatecall executes implementation code in proxy storage/context.",
            "returndata is forwarded back to the caller.",
            "Therefore implementation storage layout and proxy storage layout must agree.",
        ],
        "proxy.setValue(100);",
    ),
    (
        ["public-getter", "mapping", "structs", "arrays"],
        "Public variable → generated getter → selected values",
        "The compiler creates getter functions for public state, but complex mappings/arrays/structs are exposed through selectors and key/index arguments rather than a full object dump.",
        """
struct User {
    uint256 score;
    uint256[] tags;
}

mapping(address => User) public users;
uint256[] public scores;

function read(address user_, uint256 index_)
    external
    view
    returns (uint256 score, uint256 tag)
{
    score = users[user_].score;
    tag = users[user_].tags[index_];
}

// Generated getter idea:
// users(user_) -> score
// users(user_, index_) -> one dynamic-array element
""",
        [
            ("state", "mapping(address => User)", "users", "users[user_]", "Struct selected by address."),
            ("state", "uint256[]", "scores", "scores[index]", "Dynamic array with indexed getter behavior."),
            ("parameter", "address", "user_", "0xAlice", "Mapping key."),
            ("parameter", "uint256", "index_", "0", "Array index."),
        ],
        [
            "A public mapping gets an automatically generated external getter.",
            "The mapping key is an argument to that getter.",
            "For complex struct values, fields that cannot be selected through the getter are omitted.",
            "Array values are selected by index when needed.",
        ],
        "users(alice, 0);",
    ),
    (
        ["struct-abi", "structs", "tuples", "abi.encode", "abi.decode", "calldata"],
        "Struct → ABI tuple → bytes → struct-shaped values",
        "A Solidity struct crosses an ABI boundary as a tuple: the component types and order matter, while field names do not affect the encoded bytes.",
        """
struct Order {
    address buyer;
    uint256 amount;
    bytes note;
}

function pack(Order calldata order_)
    external
    pure
    returns (bytes memory raw)
{
    return abi.encode(order_);
}

function unpack(bytes calldata raw)
    external
    pure
    returns (address buyer, uint256 amount, bytes memory note)
{
    return abi.decode(raw, (address, uint256, bytes));
}
""",
        [
            ("struct", "Order", "order_", "buyer/amount/note", "Named Solidity record."),
            ("tuple", "(address,uint256,bytes)", "ABI shape", "ordered components", "ABI representation."),
            ("parameter", "bytes", "raw", "ABI tuple bytes", "Wire representation."),
        ],
        [
            "The struct fields become an ordered ABI tuple.",
            "abi.encode serializes the tuple into bytes.",
            "The decoder must use matching component types and order.",
            "Field names are source-level labels, not ABI payload data.",
        ],
        "unpack(pack(order));",
    ),
    (
        ["encodePacked", "keccak256", "bytes", "string", "front-running"],
        "Packed commit → hash → reveal check",
        "A commitment stores a hash of hidden data. Packed encoding is compact, but combining ambiguous dynamic values can create collision risk.",
        """
mapping(address => bytes32) public commitment;

function commit(string calldata secret_, uint256 nonce_) external {
    commitment[msg.sender] =
        keccak256(abi.encodePacked(secret_, nonce_));
}

function reveal(string calldata secret_, uint256 nonce_)
    external
    view
    returns (bool)
{
    return commitment[msg.sender] ==
        keccak256(abi.encodePacked(secret_, nonce_));
}
""",
        [
            ("state", "mapping(address => bytes32)", "commitment", "commitment[msg.sender]", "Stored commitment."),
            ("parameter", "string calldata", "secret_", '"heads"', "Hidden value."),
            ("parameter", "uint256", "nonce_", "1", "Second packed field."),
        ],
        [
            "The secret and nonce are packed into bytes.",
            "keccak256 turns the packed bytes into a commitment hash.",
            "Only the hash is stored during commit.",
            "Reveal recomputes the same digest.",
            "For multiple dynamic fields, audit for packed-encoding ambiguity/collision.",
        ],
        'commit("heads", 1);',
    ),
    (
        ["erc1271", "signature-verification", "interface", "bytes"],
        "Contract wallet → signature interface → magic value",
        "A contract wallet cannot rely on msg.sender being an EOA, so another contract can ask it whether a signature is valid.",
        """
interface IERC1271 {
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue);
}

function verify(
    IERC1271 wallet_,
    bytes32 digest_,
    bytes memory signature_
) external view returns (bool) {
    return wallet_.isValidSignature(digest_, signature_) ==
        IERC1271.isValidSignature.selector;
}
""",
        [
            ("parameter", "IERC1271", "wallet_", "0xSafe", "Contract signer."),
            ("parameter", "bytes32", "digest_", "0xDigest", "Signed message hash."),
            ("parameter", "bytes", "signature_", "r/s/v or contract format", "Signature payload."),
            ("return", "bytes4", "magicValue", "selector", "Contract-defined success marker."),
        ],
        [
            "The wallet is a contract address represented through an interface.",
            "The verifier sends the digest and signature bytes to the wallet.",
            "The wallet decides whether the signature is valid.",
            "The verifier checks the returned bytes4 magic value.",
        ],
        "verify(safe, digest, signature);",
    ),
]

for _row in _FINAL_RESEARCH_SCENES:
    _final_add_scene(*_row)



_FINAL_ERC1155_BATCH_SCENE = _final_add_scene(
    [
        "erc1155-pattern", "batch-transfer",
        "nested-mapping", "arrays", "receiver-hook", "events",
    ],
    "ERC1155: tokenId → account → balance + batch transfer",
    "ERC-1155 makes the connection between token-id/account nested mappings and parallel batch arrays explicit. A receiver hook adds the external callback boundary.",
    """
mapping(uint256 => mapping(address => uint256)) public balanceOf;

event TransferBatch(
    address indexed operator,
    address indexed from,
    address indexed to,
    uint256[] ids,
    uint256[] values
);

interface IERC1155Receiver {
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

function batchTransfer(
    address to_,
    uint256[] calldata ids_,
    uint256[] calldata values_,
    bytes calldata data_
) external {
    require(ids_.length == values_.length);

    for (uint256 i = 0; i < ids_.length; ++i) {
        balanceOf[ids_[i]][msg.sender] -= values_[i];
        balanceOf[ids_[i]][to_] += values_[i];
    }

    if (to_.code.length > 0) {
        require(
            IERC1155Receiver(to_).onERC1155BatchReceived(
                msg.sender,
                msg.sender,
                ids_,
                values_,
                data_
            ) == IERC1155Receiver.onERC1155BatchReceived.selector
        );
    }

    emit TransferBatch(msg.sender, msg.sender, to_, ids_, values_);
}
""",
    [
        ("state", "mapping(uint256 => mapping(address => uint256))", "balanceOf", "balanceOf[id][account]", "Token-id/account balance."),
        ("parameter", "address", "to_", "0xBob", "Recipient."),
        ("parameter", "uint256[] calldata", "ids_", "[1, 2]", "Token IDs, one per batch position."),
        ("parameter", "uint256[] calldata", "values_", "[10, 20]", "Amounts paired by index."),
        ("parameter", "bytes calldata", "data_", "hex\"\"", "Callback data."),
        ("global", "address", "msg.sender", "0xAlice", "Operator/source account."),
    ],
    [
        "Each token ID selects an inner account mapping.",
        "ids_[i] and values_[i] are parallel arrays, so their lengths must match.",
        "Each loop iteration debits the sender and credits the recipient.",
        "A contract recipient triggers the receiver hook, creating an external-call/reentrancy boundary.",
        "The batch event exposes the same ordered arrays for off-chain consumers.",
    ],
    "batchTransfer(bob, [1, 2], [10, 20], hex\"\");"
)


# Featured name for the subtle connection that must remain discoverable in the
# CLI even though the actual route contains the underlying concepts.
_FINAL_DECODE_HASH_MAPPING_SCENE = next(
    scene for scene in COMPREHENSIVE_MICRO_SCENES
    if scene.get("title") == "Decode the bytes, hash the same bytes, use the hash as the key"
)
_FINAL_DECODE_HASH_MAPPING_SCENE["route_name"] = "decode/hash/mapping"


# Keep the most specific final scene for the formerly missed combinations.
# This helper deliberately prefers an exact-key scene before a superset scene,
# then leaves the generic route for everything else.
def _final_find_micro_scene(names):
    ordered = []
    seen = set()
    for name in names:
        node = canonicalize(name)
        if node not in seen:
            ordered.append(node)
            seen.add(node)

    requested = frozenset(ordered)
    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if frozenset(scene.get("keys", ())) == requested
    ]
    if exact:
        exact.sort(
            key=lambda scene: (
                0 if scene.get("route_name") else 1,
                scene.get("title", ""),
            )
        )
        chosen = exact[0]
        chosen["route"] = _covering_route(ordered)
        return chosen

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= frozenset(scene.get("keys", ()))
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(frozenset(scene.get("keys", ())) - requested),
                0 if scene.get("route_name") else 1,
                0 if any(
                    tag in scene.get("title", "").lower()
                    for tag in (
                        "erc20:", "erc721:", "erc1155:", "eip712:", "timelock:",
                        "governor:", "multisig:", "upgrade proxy", "public getter",
                    )
                ) else 1,
                len(frozenset(scene.get("keys", ()))),
                scene.get("title", ""),
            )
        )
        chosen = candidates[0]
        chosen["route"] = _covering_route(ordered)
        return chosen

    return _generic_connect_scene(ordered)

find_micro_scene = _final_find_micro_scene

# A final deterministic graph invariant: every canonical node must have a
# semantic neighbor beyond the generic catalogue-coverage fallback whenever
# possible.  This makes newly-added concepts visible to the connection system.
def _final_graph_audit():
    nodes = {canonicalize(name) for name in _EXTRA_CONCEPTS}
    for left, right, label in _COMPREHENSIVE_CONNECTION_EDGES:
        a, b = canonicalize(left), canonicalize(right)
        nodes.add(a)
        nodes.add(b)

    coverage_only = {
        "catalog coverage bridge; use the concept-specific edge/path next"
    }
    weak = []
    for node in sorted(nodes):
        real_neighbors = {
            (left if right == node else right)
            for left, right, label in _COMPREHENSIVE_CONNECTION_EDGES
            if node in {left, right} and label not in coverage_only
        }
        if not real_neighbors:
            weak.append(node)

    return {
        "nodes": len(nodes),
        "edges": len(_COMPREHENSIVE_CONNECTION_EDGES),
        "scenes": len(COMPREHENSIVE_MICRO_SCENES),
        "weak_nodes": weak,
    }


_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()




# Curated routes for exact scenes preferred over later duplicate scenes.
for _scene_item in COMPREHENSIVE_MICRO_SCENES:
    _title = _scene_item.get("title", "")
    if _title == "Address → deployed code → code identity":
        _scene_item["route"] = [
            "address", "address.code", "address.codehash",
            "extcodesize", "extcodehash",
        ]
    elif _title.startswith("Upgrade proxy: implementation slot"):
        _scene_item["route"] = [
            "erc1967-storage", "storage-layout",
            "proxy-fallback", "delegatecall",
        ]
# FINAL CONNECTION AUDIT 2
# Subtle language/ABI relationships that are easy to miss in pairwise browsing.
_SEMANTIC_ALIASES.update({
    "operators": "symbols",
    "syntax-symbols": "symbols",
    "solidity-symbols": "symbols",
    "keyword": "keywords",
    "keywords": "keywords",
    "threshold": "threshold",
    "log1": "log1",
    "log2": "log2",
    "log3": "log3",
    "log4": "log4",
    "event-topic": "log-topics",
    "interface-id": "erc165-interface",
    "function-selector": "function-selector",
    "constructor-selector": "constructor",
    "mapping-abi": "mapping-abi",
    "abi-types": "abi-types",
    "abi-type-mapping": "abi-types",
    "public-state-getter": "public-getter",
    "state-getter": "public-getter",
})
_EXTRA_MEANINGS.update({
    "symbols": "Solidity punctuation/operators that control grouping, access, assignment, calls, conditions, and value transformations.",
    "keywords": "Reserved Solidity words that define contracts, visibility, data locations, control flow, inheritance, and low-level constructs.",
    "threshold": "The minimum number of valid approvals/signatures required before a multisig action can execute.",
    "log1": "A low-level EVM LOG instruction that emits one topic plus arbitrary data.",
    "log2": "A low-level EVM LOG instruction that emits two topics plus arbitrary data.",
    "log3": "A low-level EVM LOG instruction that emits three topics plus arbitrary data.",
    "log4": "A low-level EVM LOG instruction that emits four topics plus arbitrary data.",
    "mapping-abi": "Mappings are not directly representable as ABI values; callers normally use a getter or a custom function to select entries.",
    "abi-types": "The ABI represents structs as tuples, enums as integers, contract types as addresses, and UDVTs by their underlying value type.",
})
_EXTRA_CONCEPTS.update({
    "symbols", "keywords", "threshold", "log1", "log2", "log3", "log4",
    "mapping-abi", "abi-types",
})

_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("symbols", "mapping", "[] and => are the key/value lookup syntax of a mapping"),
    ("symbols", "arrays", "[] declares and indexes arrays"),
    ("symbols", "structs", ". selects struct fields"),
    ("symbols", "function", "() declares parameters and invokes functions"),
    ("symbols", "call-options", "{} carries per-call options such as value/gas"),
    ("symbols", "unchecked", "{} delimits an unchecked arithmetic block"),
    ("symbols", "yul", "assembly {} enters Yul"),
    ("keywords", "contract-types", "contract/interface/library keywords create contract-like declarations"),
    ("keywords", "data-locations", "storage/memory/calldata are language keywords for reference data locations"),
    ("keywords", "inheritance", "is expresses inheritance"),
    ("keywords", "override", "override marks inherited implementation replacement"),
    ("keywords", "virtual", "virtual permits overriding"),
    ("keywords", "payable", "payable changes ETH-receiving semantics"),
    ("mapping-abi", "mapping", "a mapping is a Solidity storage construct rather than an ABI value type"),
    ("mapping-abi", "public-getter", "public mapping getters expose selected entries instead of encoding the mapping itself"),
    ("mapping-abi", "abi.decode", "ABI decode cannot decode a mapping value directly"),
    ("abi-types", "struct-abi", "structs are represented as ABI tuples"),
    ("abi-types", "enum", "enums cross the ABI as integer types"),
    ("abi-types", "contract-types", "contract/interface values cross the ABI as addresses"),
    ("abi-types", "user-defined-value-types", "UDVTs use their underlying ABI type"),
    ("abi-types", "function-types", "external function values encode as an address plus selector"),
    ("interface", "public-getter", "a public state variable can satisfy an interface function with a matching getter shape"),
    ("public-getter", "function", "the compiler-generated getter behaves like an externally callable function"),
    ("public-getter", "function-selector", "a generated getter has a normal selector at the ABI boundary"),
    ("constructor", "init-code", "constructors execute during creation code, not normal runtime dispatch"),
    ("constructor", "function-selector", "constructors are not runtime functions with ordinary four-byte selectors"),
    ("receive", "function-selector", "receive has a special empty-calldata entry route rather than an ordinary function selector"),
    ("fallback", "function-selector", "fallback handles selectors that do not match ordinary function dispatch"),
    ("events", "function-selector", "event signatures use 32-byte Keccak topics, distinct from 4-byte function selectors"),
    ("errors", "function-selector", "custom error data begins with a four-byte selector-like identifier"),
    ("errors", "abi-types", "error arguments use ABI type representations"),
    ("events", "abi-types", "event parameters follow ABI type representations"),
    ("returndata", "abi-types", "returned values are ABI encoded as a tuple of return values"),
    ("calldata", "abi-types", "function arguments occupy ABI type-defined positions in calldata"),
])

_FINAL_INTERFACE_GETTER_SCENE = _final_add_scene(
    [
        "interface", "public-getter", "function", "function-selector",
        "mapping", "address",
    ],
    "Public getter → interface function",
    "A public state variable creates an external getter, and that generated getter can satisfy an interface function when the parameter/return shape matches.",
    """
interface IPrice {
    function price() external view returns (uint256);
}

contract Feed is IPrice {
    uint256 public override price;
}

contract Reader {
    function read(IPrice feed)
        external
        view
        returns (uint256)
    {
        return feed.price();
    }
}
""",
    [
        ("state", "uint256", "price", "100", "The public variable creates the getter."),
        ("function", "price()", "selector", "function selector", "The generated external ABI entry."),
        ("interface", "IPrice", "feed", "0xFeed", "Typed interface reference."),
    ],
    [
        "price is declared as public, so the compiler generates an external getter.",
        "The getter's signature matches IPrice.price().",
        "override explicitly states that the generated getter satisfies the interface.",
        "Reader calls the getter through the interface boundary.",
    ],
    "feed.price();",
)

_FINAL_MAPPING_ABI_SCENE = _final_add_scene(
    [
        "mapping", "mapping-abi", "public-getter", "abi.decode", "function",
    ],
    "Mapping is storage, not an ABI value",
    "A mapping cannot simply be returned or ABI-decoded as a value. A function instead selects a key and returns the mapped value.",
    """
mapping(address => uint256) public balances;

function balanceOf(bytes calldata raw)
    external
    view
    returns (uint256)
{
    address user_ = abi.decode(raw, (address));
    return balances[user_];
}
""",
    [
        ("state", "mapping(address => uint256)", "balances", "balances[user_]", "Persistent lookup table."),
        ("input", "bytes calldata", "raw", "abi.encode(alice)", "ABI payload."),
        ("decoded", "address", "user_", "abi.decode(raw, (address))", "Selected key."),
        ("return", "uint256", "balance", "balances[user_]", "ABI-representable result."),
    ],
    [
        "The mapping itself is not the ABI value being returned.",
        "The function receives bytes and decodes only the needed key.",
        "The mapping lookup selects one uint256.",
        "That uint256 is a normal ABI return value.",
    ],
    "balanceOf(abi.encode(alice));",
)


# Recompute after FINAL CONNECTION AUDIT 2 so the exported snapshot includes all nodes.
_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()



# Final API polish: every curated scene carries an explicit route, and the
# connection list advertises the research-backed protocol families.
def _final_find_micro_scene_v2(names):
    ordered = []
    seen = set()
    for name in names:
        node = canonicalize(name)
        if node not in seen:
            ordered.append(node)
            seen.add(node)

    requested = frozenset(ordered)
    exact = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if frozenset(scene.get("keys", ())) == requested
    ]
    if exact:
        exact.sort(key=lambda s: s.get("title", ""))
        chosen = exact[0]
        chosen["route"] = _covering_route(ordered)
        return chosen

    candidates = [
        scene for scene in COMPREHENSIVE_MICRO_SCENES
        if requested <= frozenset(scene.get("keys", ()))
    ]
    if candidates:
        candidates.sort(
            key=lambda scene: (
                len(frozenset(scene.get("keys", ())) - requested),
                len(frozenset(scene.get("keys", ()))),
                scene.get("title", ""),
            )
        )
        chosen = candidates[0]
        chosen["route"] = _covering_route(ordered)
        return chosen

    return _generic_connect_scene(ordered)


find_micro_scene = _final_find_micro_scene_v2


def list_connections():
    return [
        {
            "name": "solidity-yul-comprehensive-graph",
            "aliases": ["graph", "comprehensive"],
            "concepts": ["all recognized Solidity/Yul/Foundry concepts"],
            "summary": (
                f"{len(_COMPREHENSIVE_CONNECTION_EDGES)} semantic edges, "
                f"{len(COMPREHENSIVE_MICRO_SCENES)} curated teaching scenes, "
                "plus route generation for arbitrary recognized combinations."
            ),
        },
        {
            "name": "decode/hash/mapping",
            "aliases": [],
            "concepts": ["mapping", "abi.decode", "keccak256"],
            "summary": "Same raw bytes → abi.decode gives typed data; keccak256 gives a bytes32 key.",
        },
        {
            "name": "ABI call path",
            "aliases": [],
            "concepts": ["function-signature", "function-selector", "calldata", "abi.encodeCall", "call", "returndata", "abi.decode"],
            "summary": "Function shape → selector → calldata → external call → raw return bytes → decoded value.",
        },
        {
            "name": "data / ABI path",
            "aliases": [],
            "concepts": ["mapping", "structs", "arrays", "tuples", "abi.encode", "abi.decode", "keccak256"],
            "summary": "Values → ABI tuples/bytes → hashing/decoding → storage selection.",
        },
        {
            "name": "call / dispatch path",
            "aliases": [],
            "concepts": ["function", "function-signature", "function-selector", "calldata", "call", "returndata"],
            "summary": "Function definition → selector → calldata → external call → raw return bytes.",
        },
        {
            "name": "error / event path",
            "aliases": [],
            "concepts": ["errors", "custom-errors", "revert", "error-selector", "events", "event-indexed", "log-topics"],
            "summary": "Failure and observability both cross ABI-shaped/log-shaped data boundaries.",
        },
        {
            "name": "token path",
            "aliases": [],
            "concepts": ["erc20-pattern", "erc721-pattern", "erc1155-pattern", "token-approval", "transfer-from", "receiver-hook"],
            "summary": "Mappings + approvals + arrays + events + receiver callbacks.",
        },
        {
            "name": "authorization path",
            "aliases": [],
            "concepts": ["eip712-pattern", "permit-pattern", "erc1271", "multisig-pattern", "nonce", "ecrecover"],
            "summary": "Structured signed data → digest → signer validation → replay-protected state change.",
        },
        {
            "name": "protocol lifecycle path",
            "aliases": [],
            "concepts": ["timelock-pattern", "governor-pattern", "proxy-upgrade-pattern", "erc1967-storage", "delegatecall"],
            "summary": "Hashed protocol state + time/governance + upgrade boundaries + delegated execution.",
        },
        {
            "name": "proxy flow",
            "aliases": [],
            "concepts": ["proxy-fallback", "fallback", "delegatecall", "storage-layout", "returndata"],
            "summary": "Fallback → delegatecall → proxy storage/context → returndata.",
        },
        {
            "name": "storage / Yul path",
            "aliases": [],
            "concepts": ["storage-layout", "mapping-slots", "array-storage", "transient-storage", "yul-storage", "yul-memory", "yul-calldata"],
            "summary": "High-level state → physical coordinates → raw EVM/Yul access.",
        },
        {
            "name": "Foundry path",
            "aliases": [],
            "concepts": ["vm-prank", "vm-deal", "vm-expect-call", "fuzz-tests", "invariant-tests", "poc"],
            "summary": "Controlled execution context → state manipulation → assertions/PoCs.",
        },
    ]

_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()



# FINAL TINY EVM LOG NODES
for _log_node in ("log1", "log2", "log3", "log4"):
    _log_edge = (_log_node, "log-topics", "low-level LOG instruction emits this many topics")
    if _log_edge not in _COMPREHENSIVE_CONNECTION_EDGES:
        _COMPREHENSIVE_CONNECTION_EDGES.append(_log_edge)

# Refresh the exported snapshot one last time.
_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()

# Alias forms must resolve to their canonical cheatcode concepts and those
# canonical nodes must have real semantic neighbours.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("forge-cheatcodes", "test", "Foundry cheatcodes instrument test execution"),
    ("vm-expect-revert", "revert", "expectRevert asserts that execution reverts"),
    ("vm-expect-emit", "events", "expectEmit asserts emitted logs"),
])

_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()




# ---------------------------------------------------------------------------
# FINAL SCENE-PACK COMPOSER
# ---------------------------------------------------------------------------
#
# A graph route is useful, but a route alone is not enough: the displayed code
# should also cover the requested concepts.  This composer performs a small
# set-cover over curated scenes.  Exact/superset scenes still win.  When no
# single scene can cover a request, Lowkey shows a small sequence of coherent
# scenes rather than falling back to the giant universal notebook.
#

def _scene_keys(scene):
    return frozenset(canonicalize(item) for item in scene.get("keys", ()))


def _scene_pair_strength(scene, requested):
    keys = _scene_keys(scene)
    overlap = requested & keys
    direct = 0
    for left in overlap:
        for right in overlap:
            if left >= right:
                continue
            pair = tuple(sorted((left, right)))
            if any(
                pair == tuple(sorted((canonicalize(a), canonicalize(b))))
                for a, b, _label in _COMPREHENSIVE_CONNECTION_EDGES
            ):
                direct += 1
    return direct


def _connection_scene_candidates():
    # Comprehensive scenes are intentionally first: they came from the
    # cross-check/production-pattern pass.  A legacy scene can still rescue a
    # concept while the corpus evolves.
    seen = set()
    rows = []
    for scene in list(COMPREHENSIVE_MICRO_SCENES) + list(MICRO_SCENES):
        marker = id(scene)
        if marker in seen:
            continue
        seen.add(marker)
        rows.append(scene)
    return rows


def find_connection_scenes(names, max_scenes=4):
    """Choose a small set of teaching scenes whose union covers the request."""
    ordered = []
    seen = set()
    for name in names:
        for node in expand_name(name):
            if node not in seen:
                seen.add(node)
                ordered.append(node)

    requested = frozenset(ordered)
    if len(requested) < 2:
        return []

    candidates = _connection_scene_candidates()

    # First choice: one exact scene, then the smallest curated superset.
    exact = [s for s in candidates if _scene_keys(s) == requested]
    if exact:
        exact.sort(key=lambda s: s.get("title", ""))
        return [exact[0]]

    supersets = [s for s in candidates if requested <= _scene_keys(s)]
    if supersets:
        supersets.sort(
            key=lambda s: (
                len(_scene_keys(s) - requested),
                -_scene_pair_strength(s, requested),
                len(_scene_keys(s)),
                s.get("title", ""),
            )
        )
        return [supersets[0]]

    uncovered = set(requested)
    chosen = []
    used = set()

    while uncovered and len(chosen) < max_scenes:
        best = None
        for index, scene in enumerate(candidates):
            if index in used:
                continue
            keys = _scene_keys(scene)
            new = uncovered & keys
            if not new:
                continue

            # Coverage dominates.  Pair strength rewards scenes that actually
            # explain relationships among the newly covered concepts instead of
            # merely containing vocabulary by coincidence.
            direct = _scene_pair_strength(scene, requested)
            score = (
                len(new),
                direct,
                len(new) / max(1, len(keys)),
                -len(keys),
                -index,
            )
            if best is None or score > best[0]:
                best = (score, index, scene, new)

        if best is None:
            break

        _score, index, scene, new = best
        chosen.append(scene)
        used.add(index)
        uncovered -= new

    if not uncovered:
        # Order the selected scenes as a teaching sequence: prefer the scene
        # that introduces the most requested concepts first, then let each next
        # scene extend the already-established vocabulary.
        ordered_scenes = []
        covered = set()
        remaining = list(chosen)
        while remaining:
            ranked = []
            for scene in remaining:
                new = set(_scene_keys(scene)) & (set(requested) - covered)
                bridge = _scene_pair_strength(scene, requested)
                ranked.append((len(new), bridge, -len(_scene_keys(scene)), scene.get("title", ""), scene))
            ranked.sort(reverse=True, key=lambda row: row[:4])
            picked = ranked[0][4]
            ordered_scenes.append(picked)
            covered |= set(_scene_keys(picked)) & set(requested)
            remaining.remove(picked)
        return ordered_scenes

    # If a request is broader than the curated corpus, return the best scenes
    # plus a compact synthetic bridge for the remainder.  This keeps the
    # guarantee that every recognized request gets a concrete next step without
    # ever reintroducing the universal dump into the default view.
    if chosen:
        remainder = sorted(uncovered)
        synthetic = _generic_connect_scene(remainder)
        synthetic["title"] = "Remaining bridge: " + " → ".join(remainder[:4])
        synthetic["generic"] = True
        chosen.append(synthetic)
        return chosen[:max_scenes]

    return [_generic_connect_scene(ordered)]


def _scene_values(scene, limit=6):
    return list(scene.get("variables", ()))[:limit]


def _render_scene_compact(scene, number, walkthrough=False):
    print()
    print(f"BRIDGE {number} • {scene.get('title', 'Connected scene')}")
    print("-" * 76)
    print(scene.get("story", "").strip())
    print()
    print("CODE")
    print("----")
    print(scene.get("code", "").rstrip())

    variables = scene.get("variables", [])
    flow = scene.get("flow", [])

    if walkthrough:
        print()
        print("VARIABLES")
        print("---------")
        for role, value_type, name, value, purpose in variables:
            print(
                f"  {role:<18} {value_type:<28} "
                f"{name:<18} = {value:<24} {purpose}"
            )
        print()
        print("FOLLOW THE VALUE")
        print("----------------")
        for index, step in enumerate(flow, 1):
            print(f"  {index}. {step}")
    else:
        if variables:
            print()
            print("KEY VALUES")
            print("----------")
            for role, value_type, name, value, purpose in _scene_values(scene):
                print(
                    f"  {name:<18} {value_type:<24} = {value:<22} {purpose}"
                )
        if flow:
            print()
            print("FLOW")
            print("----")
            for index, step in enumerate(flow[:5], 1):
                print(f"  {index}. {step}")

    if scene.get("call"):
        print()
        print("TRY")
        print("---")
        print(f"  {scene['call']}")


def render_connection_pack(requested, scenes, walkthrough=False):
    """Render a multi-scene connection without changing single-scene output."""
    explicit_routes = [
        scene.get("route")
        for scene in scenes
        if scene.get("route")
    ]
    print()
    print("CONNECTION ROUTE")
    print("----------------")
    if len(scenes) == 1 and explicit_routes:
        print("  " + " → ".join(explicit_routes[0]))
    else:
        for index, scene in enumerate(scenes, 1):
            route = scene.get("route")
            if route:
                print(f"  {index}. " + " → ".join(route))
            else:
                print(f"  {index}. {scene.get('title', 'connected bridge')}")

    print()
    print("THE CONNECTION")
    print("--------------")
    print(
        f"This connection is taught in {len(scenes)} small steps. "
        "Each bridge adds real code instead of merely naming another concept."
    )

    print()
    print("1. WHAT EACH PIECE IS")
    print("----------------------")
    for concept in requested:
        print(f"  {concept}: {connection_meaning(concept)}")

    print()
    print("2. CONNECTED BRIDGES")
    print("--------------------")
    for index, scene in enumerate(scenes, 1):
        _render_scene_compact(scene, index, walkthrough=walkthrough)

    print()
    print("3. HOW THE BRIDGES JOIN")
    print("-----------------------")
    covered = set()
    for index, scene in enumerate(scenes, 1):
        keys = _scene_keys(scene)
        newly = [node for node in requested if node in keys and node not in covered]
        covered.update(newly)
        label = " → ".join(newly) if newly else "extends the previous bridge"
        print(f"  {index}. {label}")

    print()
    print("NEXT")
    print("----")
    print("  1  full contract lab")
    print("  2  slower walkthrough")
    print("  lk cheat <concept>")


# ---------------------------------------------------------------------------
# FINAL LOW-LEVEL TEACHING SCENES
# ---------------------------------------------------------------------------

_final_add_scene(
    [
        "yul", "yul-storage", "mapping", "keccak256",
        "mapping-slots", "storage-layout", "sload", "sstore",
    ],
    "High-level mapping → exact storage slot → Yul sload/sstore",
    "A Solidity mapping lookup is a logical operation. At the EVM level the key and mapping anchor are hashed into a physical slot that Yul can read or write.",
    """
mapping(address => uint256) public balances;

function set(address user_, uint256 amount_) external {
    balances[user_] = amount_;
}

function read(address user_)
    external
    view
    returns (uint256 result)
{
    assembly {
        mstore(0x00, user_)
        mstore(0x20, balances.slot)
        let slot := keccak256(0x00, 0x40)
        result := sload(slot)
    }
}

// The write analogue is:
// sstore(slot, amount_)
""",
    [
        ("state", "mapping(address => uint256)", "balances", "balances[user_]", "High-level storage lookup."),
        ("parameter", "address", "user_", "0xAlice", "Mapping key."),
        ("parameter", "uint256", "amount_", "100", "Stored value."),
        ("Yul local", "word", "slot", "keccak256(user_, balances.slot)", "Physical storage coordinate."),
    ],
    [
        "balances[user_] selects a logical mapping entry.",
        "The mapping declaration has an anchor slot even though that slot itself does not hold the mapped value.",
        "The key and anchor are ABI-word-shaped values put into memory for hashing.",
        "keccak256 produces the entry's physical slot.",
        "sload reads the slot; sstore would write the slot.",
    ],
    "set(alice, 100);  // then read(alice)",
)

_final_add_scene(
    [
        "mload", "mstore", "mstore8", "mcopy",
        "memory", "yul-memory", "yul",
    ],
    "Memory pointer → word load/store → byte copy",
    "Yul treats memory as byte-addressable temporary space. mstore writes 32 bytes, mload reads 32 bytes, mstore8 writes one byte, and mcopy moves a byte range.",
    """
function demo()
    external
    pure
    returns (bytes32 word)
{
    assembly {
        mstore(0x80, 0x1234)
        mstore8(0xA0, 0xFF)

        // Copy 32 bytes from 0x80 to 0xC0.
        mcopy(0xC0, 0x80, 0x20)

        word := mload(0xC0)
    }
}
""",
    [
        ("Yul address", "word", "0x80", "free-memory area", "Memory destination/source."),
        ("Yul word", "bytes32", "word", "0x1234", "Value loaded from memory."),
        ("Yul byte", "byte", "0xA0", "0xFF", "Single-byte write."),
    ],
    [
        "mstore writes one 32-byte word.",
        "mstore8 changes one byte at a chosen offset.",
        "mcopy copies an arbitrary byte range.",
        "mload reads one 32-byte word from the destination.",
    ],
    "demo();",
)

_final_add_scene(
    [
        "calldata", "yul-calldata", "calldataload", "calldatacopy",
        "calldatasize", "function-selector", "msg.data",
    ],
    "Raw calldata → size → load/copy → selector",
    "The same call payload can be treated as a Solidity calldata value or as raw EVM input. Yul gives byte-level access through load, copy, and size operations.",
    """
fallback() external {
    assembly {
        let size := calldatasize()
        let firstWord := calldataload(0)

        // Copy the whole payload into memory.
        calldatacopy(0x80, 0, size)

        // The high four bytes of firstWord contain the selector.
        firstWord := firstWord
    }
}
""",
    [
        ("raw input", "bytes", "msg.data", "selector + ABI arguments", "Complete current calldata."),
        ("Yul", "word", "size", "calldatasize()", "Input length."),
        ("Yul", "word", "firstWord", "calldataload(0)", "First 32 calldata bytes."),
    ],
    [
        "A normal external function receives ABI-decoded parameters from calldata.",
        "fallback can instead expose the raw payload.",
        "calldatasize reports its byte length.",
        "calldataload reads a 32-byte word from a chosen offset.",
        "calldatacopy moves the payload into memory for further processing.",
    ],
    "send raw calldata to the fallback",
)

_final_add_scene(
    [
        "call", "low-level-call", "returndata",
        "returndatasize", "returndatacopy", "abi.decode", "revert",
    ],
    "External call → success flag → returndata → decode or bubble",
    "Low-level calls separate execution status from returned bytes. Successful bytes can be decoded; failure bytes can be copied and bubbled back to the caller.",
    """
function quote(address target, bytes memory data)
    external
    returns (uint256 value)
{
    (bool ok, ) = target.call(data);

    if (!ok) {
        assembly {
            let size := returndatasize()
            returndatacopy(0, 0, size)
            revert(0, size)
        }
    }

    bytes memory out = new bytes(returndatasize());

    assembly {
        returndatacopy(add(out, 32), 0, returndatasize())
    }

    value = abi.decode(out, (uint256));
}
""",
    [
        ("target", "address", "target", "0xOracle", "External call destination."),
        ("input", "bytes", "data", "selector + args", "Raw calldata."),
        ("flag", "bool", "ok", "true/false", "Low-level success result."),
        ("bytes", "bytes", "out", "raw returndata", "Successful return payload."),
        ("return", "uint256", "value", "abi.decode(out, (uint256))", "Typed value."),
    ],
    [
        "target.call(data) crosses the external boundary.",
        "ok says whether the subcall succeeded; it is separate from the returned bytes.",
        "returndatasize tells how many bytes are available.",
        "returndatacopy copies those bytes into memory.",
        "Success bytes can be ABI-decoded; failure bytes can be returned with revert.",
    ],
    "quote(oracle, data);",
)

_final_add_scene(
    [
        "events", "event-indexed", "log-topics",
        "log0", "log1", "log2", "log3", "log4", "keccak256", "bytes32",
    ],
    "Event declaration → topics → low-level LOG",
    "A Solidity event becomes an EVM log. Indexed values occupy topics; the event signature is represented by a Keccak-derived topic, while low-level LOG operations expose the same underlying mechanism.",
    """
event Deposit(address indexed user, uint256 amount, bytes indexed memo);

function deposit(bytes calldata memo_)
    external
    payable
{
    emit Deposit(msg.sender, msg.value, memo_);
}

// Low-level shape:
// log3(dataPtr, dataSize, topic0, topic1, topic2)
""",
    [
        ("event", "Deposit", "signature", "Deposit(address,uint256,bytes)", "Logical log definition."),
        ("topic", "bytes32", "topic0", "keccak256(signature)", "Event identity."),
        ("topic", "address", "user", "msg.sender", "Indexed value."),
        ("data", "uint256", "amount", "msg.value", "Non-indexed data."),
        ("topic", "bytes32", "memo topic", "keccak256(memo)", "Dynamic indexed value representation."),
    ],
    [
        "The event declaration defines which parameters are indexed.",
        "The event signature is represented by a Keccak-derived topic.",
        "Indexed value types occupy additional topics.",
        "A dynamic indexed value is represented by a hash topic rather than its full dynamic bytes.",
        "The EVM LOG0–LOG4 instructions provide the low-level topic/data machinery.",
    ],
    'deposit(hex"6869");',
)

_final_add_scene(
    [
        "address", "address.code", "address.codehash",
        "extcodesize", "extcodehash", "extcodecopy", "contract-types", "bytes",
    ],
    "Address → deployed code → size/hash/copy",
    "An address can be treated as a contract reference, inspected for runtime code, hashed for code identity, or copied into memory. These are different questions about the same address.",
    """
function inspect(address target)
    external
    view
    returns (
        bytes memory code,
        bytes32 hash,
        uint256 size
    )
{
    code = target.code;
    hash = target.codehash;

    assembly {
        size := extcodesize(target)
        extcodecopy(target, add(code, 32), 0, size)
    }
}
""",
    [
        ("address", "address", "target", "0xTarget", "Account/contract address."),
        ("bytes", "bytes", "code", "target.code", "Runtime bytecode bytes."),
        ("bytes32", "bytes32", "hash", "target.codehash", "Code identity hash."),
        ("word", "uint256", "size", "extcodesize(target)", "Runtime code length."),
    ],
    [
        "The same address identifies the account being inspected.",
        "address.code exposes runtime bytecode as bytes.",
        "address.codehash exposes code identity as a bytes32 value.",
        "extcodesize gives the EVM code length.",
        "extcodecopy copies runtime code bytes into memory.",
    ],
    "inspect(target);",
)

_final_add_scene(
    [
        "create", "create2", "new", "constructor", "salt",
        "init-code", "runtime-code", "address", "keccak256",
    ],
    "Creation → init code → runtime code → deterministic address",
    "CREATE runs initialization and returns an address. CREATE2 adds a salt and init-code hash so the resulting address is determined before deployment.",
    """
// High-level creation:
Child child = new Child(100);

// CREATE2 address idea:
// address = address(
//     uint160(uint256(keccak256(
//         abi.encodePacked(
//             bytes1(0xff),
//             deployer,
//             salt,
//             keccak256(initCode)
//         )
//     )))
// );
""",
    [
        ("constructor input", "uint256", "100", "100", "Deployment-time constructor argument."),
        ("creation", "new", "child", "fresh contract", "High-level CREATE path."),
        ("salt", "bytes32", "salt", "0x01", "CREATE2 deterministic input."),
        ("code", "bytes", "initCode", "constructor + runtime-producing code", "Creation bytecode."),
        ("derived", "bytes32", "address hash", "keccak256(...)", "Deterministic address preimage."),
        ("result", "address", "child", "0xChild", "Fresh contract address."),
    ],
    [
        "new invokes contract creation and its constructor.",
        "Init code runs during creation and returns the runtime bytecode.",
        "CREATE chooses the address using the normal creation mechanism.",
        "CREATE2 mixes deployer, salt, and init-code hash into the address formula.",
        "Therefore changing constructor arguments can change the init-code hash and the predicted CREATE2 address.",
    ],
    "new Child(100);  // CREATE2 prediction uses the corresponding init code + salt",
)

_final_add_scene(
    [
        "block.chainid", "block.basefee", "block.prevrandao",
        "block.number", "block.timestamp", "blockhash",
        "blobhash", "tx.gasprice", "gas", "contract-balance",
    ],
    "Block/transaction context → protocol assumptions",
    "Global block and transaction values are ambient inputs. Protocols use them for time gates, chain binding, randomness assumptions, fee logic, recent-block references, and gas-sensitive behavior.",
    """
function context()
    external
    view
    returns (
        uint256 chainId,
        uint256 timestamp,
        uint256 number,
        uint256 basefee_,
        uint256 gasprice_,
        uint256 balance
    )
{
    chainId = block.chainid;
    timestamp = block.timestamp;
    number = block.number;
    basefee_ = block.basefee;
    gasprice_ = tx.gasprice;
    balance = address(this).balance;
}

// Other context helpers:
// block.prevrandao
// blockhash(blockNumber)
// blobhash(index)
""",
    [
        ("global", "uint256", "block.chainid", "chain identity", "Chain binding."),
        ("global", "uint256", "block.timestamp", "current block time", "Time checks/deadlines."),
        ("global", "uint256", "block.number", "current block", "Block-relative state."),
        ("global", "uint256", "block.basefee", "current base fee", "Block fee context."),
        ("global", "uint256", "tx.gasprice", "tx fee price", "Transaction fee context."),
        ("global", "uint256", "address(this).balance", "held ETH", "Current contract balance."),
    ],
    [
        "These are context values, not ordinary function parameters.",
        "block.chainid can bind signatures/authorization to one chain.",
        "block.timestamp commonly controls deadlines and timelocks.",
        "block.number/blockhash provide block-relative references.",
        "basefee and tx.gasprice are fee context, while gas/gasleft describe execution budget.",
    ],
    "context();",
)

_final_add_scene(
    [
        "function", "named-arguments", "call-options", "symbols",
        "parameter-vs-argument", "payable", "call",
    ],
    "Function definition → named arguments → call options",
    "Solidity has two different brace/parenthesis ideas at a call site: named arguments provide parameter names, while call options such as value/gas configure the external message.",
    """
function pay(address payable to, uint256 amount_)
    external
    payable
{
    (bool ok, ) = to.call{value: amount_}("");
    require(ok);
}

// Names at the definition can be matched at the call site:
// pay({to: alice, amount_: 1 ether});

// Message options are separate:
// pay{value: 1 ether}(alice, 1 ether);
""",
    [
        ("parameter", "address payable", "to", "alice", "Named input slot in the function."),
        ("parameter", "uint256", "amount_", "1 ether", "Second input slot."),
        ("argument", "address", "alice", "alice", "Actual address value supplied."),
        ("argument", "uint256", "1 ether", "1 ether", "Actual numeric value supplied."),
        ("call option", "uint256", "value", "1 ether", "ETH attached to the external message."),
    ],
    [
        "The function definition declares parameters.",
        "A call site supplies arguments.",
        "Named arguments choose parameters by name but do not attach ETH.",
        "The {value: ...} call option attaches ETH to the message.",
        "Inside the function, msg.value reflects the attached ETH.",
    ],
    "pay{value: 1 ether}({to: alice, amount_: 1 ether});",
)


# FINAL EXACT BRIDGE: mapping + keccak256 + storage-layout + Yul
_final_add_scene(
    ["mapping", "keccak256", "storage-layout", "yul"],
    "Exact bridge: mapping → keccak256 → storage-layout → Yul",
    "A mapping lookup is a logical key/value operation; storage layout tells you where the mapping is anchored, Keccak derives the entry slot, and Yul exposes the raw storage read.",
    """
mapping(address => uint256) public balances;

function read(address user_)
    external
    view
    returns (uint256 result)
{
    assembly {
        mstore(0x00, user_)
        mstore(0x20, balances.slot)
        let slot := keccak256(0x00, 0x40)
        result := sload(slot)
    }
}
""",
    [
        ("mapping", "mapping(address => uint256)", "balances[user_]", "balances[0xAlice]", "Logical key/value lookup."),
        ("input", "address", "user_", "0xAlice", "Mapping key supplied to the function."),
        ("layout", "storage slot", "balances.slot", "7", "Anchor slot determined by storage layout."),
        ("derived", "bytes32", "slot", "keccak256(user_ + balances.slot)", "Physical mapping entry location."),
        ("Yul", "word", "sload(slot)", "100", "Raw persistent storage read."),
    ],
    [
        "user_ is the logical mapping key.",
        "balances.slot is the mapping's storage-layout anchor; it is not the stored balance itself.",
        "Yul places the key and anchor into memory and hashes the 64-byte pair.",
        "The digest is the physical storage slot for balances[user_].",
        "sload(slot) reads the value stored there.",
    ],
    "read(alice);",
)
_FINAL_EXACT_MAPPING_YUL_SCENE = COMPREHENSIVE_MICRO_SCENES[-1]
_FINAL_EXACT_MAPPING_YUL_SCENE["route"] = [
    "mapping",
    "storage-layout",
    "keccak256",
    "yul",
]

# FINAL PRODUCTION-PATTERN COVERAGE
_SEMANTIC_ALIASES.update({
    "erc4626": "erc4626-pattern",
    "erc4626-pattern": "erc4626-pattern",
    "vault": "erc4626-pattern",
    "erc1271": "erc1271",
    "contract-signature": "erc1271",
    "erc1967": "erc1967-storage",
    "erc1967-storage": "erc1967-storage",
    "implementation-slot": "erc1967-storage",
    "multicall": "multicall",
    "batch-call": "multicall",
    "flashloan": "flashloan-pattern",
    "flash-loan": "flashloan-pattern",
    "flashloan-pattern": "flashloan-pattern",
    "permit2": "permit2-pattern",
    "permit2-pattern": "permit2-pattern",
    "callback": "callback",
    "hook": "hook",
    "hooks": "hook",
    "no-delegate-call": "no-delegatecall",
    "no-delegatecall": "no-delegatecall",
})
_EXTRA_MEANINGS.update({
    "erc4626-pattern": "Tokenized-vault accounting: underlying assets are exchanged for ERC-20-like shares, with conversion/preview and slippage assumptions.",
    "erc1271": "Contract-based signature validation through isValidSignature(bytes32,bytes), rather than assuming the signer is an EOA.",
    "erc1967-storage": "A proxy storage convention that places implementation/admin/beacon addresses in deterministic special slots.",
    "multicall": "Batch multiple calls in one transaction, commonly using bytes[] calldata and delegatecall.",
    "flashloan-pattern": "Temporary liquidity sent out and required to be returned, usually enforced by a callback and repayment invariant in one transaction.",
    "permit2-pattern": "Signature/allowance transfer infrastructure combining token approvals, nonces, deadlines, and transfer authorization.",
    "callback": "An external call into a caller-supplied contract that lets the callee continue the workflow through a callback function.",
    "hook": "An externally supplied extension point called at a protocol lifecycle boundary.",
    "no-delegatecall": "A guard that prevents execution through delegatecall, often used where storage/context must remain tied to the deployed instance.",
})
_EXTRA_CONCEPTS.update({
    "erc4626-pattern", "erc1271", "erc1967-storage", "multicall",
    "flashloan-pattern", "permit2-pattern", "callback", "hook",
    "no-delegatecall",
})

COMPREHENSIVE_MICRO_SCENES.extend([
    _scene(
        ["erc4626-pattern", "interface", "mapping", "structs", "arrays", "math", "events", "front-running"],
        "ERC4626: assets ↔ shares → conversion → slippage",
        "A tokenized vault maps users to shares while the vault holds underlying assets. Deposits and redemptions depend on the current asset/share ratio, so the empty-vault and donation/inflation cases matter.",
        """
mapping(address => uint256) public shares;
uint256 public totalShares;
uint256 public totalAssets;

function convertToShares(uint256 assets)
    public
    view
    returns (uint256)
{
    if (totalShares == 0) return assets;
    return assets * totalShares / totalAssets;
}

function deposit(uint256 assets, address receiver)
    external
    returns (uint256 minted)
{
    minted = convertToShares(assets);
    totalAssets += assets;
    totalShares += minted;
    shares[receiver] += minted;
}
""",
        [
            ("state", "mapping(address => uint256)", "shares", "shares[alice]", "Receiver's vault-share balance."),
            ("state", "uint256", "totalAssets", "10_000", "Underlying asset accounting."),
            ("state", "uint256", "totalShares", "5_000", "Share supply used for conversion."),
            ("parameter", "uint256", "assets", "100", "Assets being deposited."),
            ("parameter", "address", "receiver", "0xAlice", "Account receiving shares."),
            ("derived", "uint256", "minted", "50", "Shares produced by the current exchange ratio."),
        ],
        [
            "The vault starts with an asset/share ratio.",
            "convertToShares derives the share amount from totalAssets and totalShares.",
            "The receiver's mapped share balance increases.",
            "totalAssets and totalShares move together, preserving the accounting model.",
            "An empty or manipulated vault can make this ratio a security/slippage boundary.",
        ],
        "deposit(100, alice);",
    ),
    _scene(
        ["erc1271", "interface", "bytes32", "bytes", "signature-verification", "ecrecover"],
        "Contract wallet → signature validation interface",
        "A contract signer cannot be treated like an EOA with ecrecover alone. The protocol can ask the contract wallet whether a hash/signature pair is valid.",
        """
interface IERC1271 {
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4 magicValue);
}

function check(
    IERC1271 wallet,
    bytes32 hash,
    bytes calldata signature
) external view returns (bool) {
    return wallet.isValidSignature(hash, signature)
        == IERC1271.isValidSignature.selector;
}
""",
        [
            ("interface", "IERC1271", "wallet", "0xSafe", "Contract signature authority."),
            ("digest", "bytes32", "hash", "message digest", "Data being authorized."),
            ("bytes", "bytes", "signature", "encoded signature", "Signature/certificate bytes."),
            ("return", "bytes4", "magicValue", "isValidSignature.selector", "Validation result identifier."),
        ],
        [
            "The message is represented by a bytes32 digest.",
            "The signature is raw bytes whose structure belongs to the wallet.",
            "The protocol crosses an interface boundary to ask the contract signer.",
            "The magic value confirms validity instead of recovering an EOA address directly.",
        ],
        "check(wallet, hash, signature);",
    ),
    _scene(
        ["erc1967-storage", "proxy-fallback", "delegatecall", "storage-layout", "address", "events", "keccak256"],
        "ERC1967 slot → implementation → delegatecall",
        "A proxy can keep its implementation address outside ordinary sequential storage, then delegate arbitrary calldata to that implementation while sharing the proxy's storage.",
        """
bytes32 internal constant IMPLEMENTATION_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

function implementation() external view returns (address impl) {
    assembly {
        impl := sload(IMPLEMENTATION_SLOT)
    }
}

fallback() external payable {
    (bool ok, bytes memory out) =
        address(uint160(implementationAddress())).delegatecall(msg.data);
    if (!ok) revert();
    assembly { return(add(out, 32), mload(out)) }
}
""",
        [
            ("slot", "bytes32", "IMPLEMENTATION_SLOT", "hash-derived special slot", "Proxy implementation storage location."),
            ("state", "address", "implementation", "0xImpl", "Code target."),
            ("global", "bytes", "msg.data", "selector + args", "Caller payload."),
            ("call", "delegatecall", "implementation", "same proxy storage", "Implementation execution context."),
        ],
        [
            "The special slot is hash-derived rather than ordinary slot 0/1 state.",
            "Fallback receives the original calldata.",
            "delegatecall executes implementation code against proxy storage.",
            "Changing the implementation therefore changes behavior without moving the proxy's state.",
        ],
        "proxy.setValue(100);",
    ),
    _scene(
        ["multicall", "arrays", "calldata", "delegatecall", "returndata", "function-selector", "this-call", "msg.sender"],
        "bytes[] batch → delegatecall self → returndata[]",
        "A multicall turns many encoded calls into one transaction. delegatecall keeps the batch inside the same storage/context, which also makes sender/context assumptions important.",
        """
function multicall(bytes[] calldata data)
    external
    returns (bytes[] memory results)
{
    results = new bytes[](data.length);

    for (uint256 i = 0; i < data.length; ++i) {
        (bool ok, bytes memory out) =
            address(this).delegatecall(data[i]);
        if (!ok) revert();
        results[i] = out;
    }
}
""",
        [
            ("input", "bytes[] calldata", "data", "[call1, call2]", "Batch of encoded calls."),
            ("index", "uint256", "i", "0 → length - 1", "Batch position."),
            ("call", "delegatecall", "address(this)", "same storage/context", "Self-delegated subcall."),
            ("return", "bytes[] memory", "results", "raw outputs", "Per-call return bytes."),
        ],
        [
            "The outer call carries an array of raw calldata payloads.",
            "Each bytes item identifies a normal function via its selector.",
            "delegatecall runs each subcall against the current contract's storage/context.",
            "Each raw return payload is collected into the results array.",
            "Batching can bypass assumptions made only at the outer transaction boundary.",
        ],
        "multicall([abi.encodeWithSignature(\"set(uint256)\", 1), ...]);",
    ),
    _scene(
        ["flashloan-pattern", "interface", "callback", "call", "mapping", "checks-effects-interactions", "reentrancy", "events"],
        "Flash loan → callback → repayment invariant",
        "A flash-loan provider transfers temporary liquidity, calls a receiver, then checks that principal plus fee has returned before the transaction can succeed.",
        """
interface IFlashReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 fee,
        bytes calldata params
    ) external returns (bool);
}

function flashLoan(
    IFlashReceiver receiver,
    address token,
    uint256 amount,
    uint256 fee
) external {
    IERC20(token).transfer(address(receiver), amount);
    receiver.executeOperation(token, amount, fee, "");
    require(IERC20(token).balanceOf(address(this)) >= amount + fee);
}
""",
        [
            ("target", "IFlashReceiver", "receiver", "0xArb", "Callback recipient."),
            ("token", "address", "token", "0xToken", "Borrowed asset contract."),
            ("value", "uint256", "amount", "1_000", "Temporary liquidity."),
            ("value", "uint256", "fee", "3", "Repayment fee."),
        ],
        [
            "The provider sends assets before calling the receiver.",
            "The receiver callback executes arbitrary strategy code inside the same transaction.",
            "The provider resumes after the callback returns.",
            "The repayment invariant requires principal plus fee to be present.",
        ],
        "flashLoan(receiver, token, 1000, 3);",
    ),
    _scene(
        ["permit2-pattern", "mapping", "nested-mapping", "nonce", "signature-verification", "keccak256", "abi.encode", "block.timestamp", "bytes"],
        "Permit2-style authorization → nonce/allowance → transfer",
        "Signature-based token transfer infrastructure combines mapped permissions, a nonce, an expiry, typed hashing, and raw signature bytes before changing token state.",
        """
mapping(address => mapping(address => uint256)) public allowance;
mapping(address => uint256) public nonces;

function digest(
    address owner,
    address spender,
    uint256 amount,
    uint256 deadline
) public view returns (bytes32) {
    return keccak256(
        abi.encode(owner, spender, amount, nonces[owner], deadline)
    );
}

function consume(
    address owner,
    address spender,
    uint256 amount,
    uint256 deadline,
    bytes calldata signature
) external {
    require(block.timestamp <= deadline);
    bytes32 hash = digest(owner, spender, amount, deadline);
    // verify(hash, signature);
    nonces[owner]++;
    allowance[owner][spender] = amount;
}
""",
        [
            ("state", "mapping(address => mapping(address => uint256))", "allowance", "allowance[owner][spender]", "Delegated token permission."),
            ("state", "mapping(address => uint256)", "nonces", "nonces[owner]", "Replay protection."),
            ("parameter", "uint256", "deadline", "now + 1 hour", "Expiry boundary."),
            ("parameter", "bytes calldata", "signature", "signature bytes", "Authorization proof."),
            ("derived", "bytes32", "hash", "keccak256(abi.encode(...))", "Signed digest."),
        ],
        [
            "The owner/spender pair selects allowance state through two mapping keys.",
            "The nonce becomes part of the signed digest.",
            "The deadline limits when the authorization can be consumed.",
            "Signature verification binds the digest to the authorized signer.",
            "Consuming the authorization increments the nonce before reuse is possible.",
        ],
        'consume(alice, bob, 100, deadline, signature);',
    ),
    _scene(
        ["hook", "callback", "interface", "external-call", "msg.sender", "mapping", "events", "reentrancy"],
        "Protocol hook → external callback → state boundary",
        "Hook systems deliberately call user-supplied code at protocol lifecycle points. The hook address, caller identity, state ordering, and callback re-entry path all become part of the design.",
        """
interface IHook {
    function beforeAction(bytes32 id, address caller) external;
}

mapping(bytes32 => uint256) public value;

function action(bytes32 id_, uint256 amount_, IHook hook_) external {
    hook_.beforeAction(id_, msg.sender);
    value[id_] += amount_;
    emit Action(id_, amount_);
}

event Action(bytes32 indexed id, uint256 amount);
""",
        [
            ("interface", "IHook", "hook_", "0xHook", "User-supplied extension point."),
            ("global", "address", "msg.sender", "0xAlice", "Original caller for this frame."),
            ("state", "mapping(bytes32 => uint256)", "value", "value[id_]", "Protocol state."),
            ("event", "Action", "id_", "bytes32", "Observable state transition."),
        ],
        [
            "The caller supplies a hook contract through an interface.",
            "The protocol calls the hook before changing its own state.",
            "The hook is an external callback boundary and can attempt re-entry.",
            "State ordering therefore determines whether stale state can be observed or exploited.",
        ],
        "action(bytes32(\"POOL\"), 100, hook);",
    ),
])

# ---------------------------------------------------------------------------
# FINAL YUL/EVM ATOM VOCABULARY
# ---------------------------------------------------------------------------
#
# The curated scenes above use these names. Make the same atoms addressable
# directly by the connect command, and connect them to the high-level concepts
# they expose.
#

_SEMANTIC_ALIASES.update({
    "mload": "mload", "mstore": "mstore", "mstore8": "mstore8", "mcopy": "mcopy",
    "sload": "sload", "sstore": "sstore", "tload": "tload", "tstore": "tstore",
    "calldataload": "calldataload", "calldatasize": "calldatasize", "calldatacopy": "calldatacopy",
    "returndatasize": "returndatasize", "returndatacopy": "returndatacopy",
    "extcodesize": "extcodesize", "extcodecopy": "extcodecopy", "extcodehash": "extcodehash",
    "codesize": "codesize", "codecopy": "codecopy", "datasize": "datasize", "dataoffset": "dataoffset",
    "datacopy": "datacopy", "linkersymbol": "linkersymbol", "verbatim": "verbatim",
    "pc": "pc", "msize": "msize", "caller": "caller", "callvalue": "callvalue",
    "selfbalance": "selfbalance", "balance": "balance", "gas": "gas", "gasleft": "gasleft",
    "blockhash": "blockhash", "blobhash": "blobhash",
    "basefee": "block.basefee", "prevrandao": "block.prevrandao", "chainid": "block.chainid",
    "coinbase": "block.coinbase", "gaslimit": "block.gaslimit", "blobbasefee": "block.blobbasefee",
    "if-yul": "yul-if", "switch-yul": "yul-switch", "for-yul": "yul-for",
    "break-yul": "yul-break", "continue-yul": "yul-continue", "leave": "yul-leave",
    "let": "yul-let", "yul-assignment": "yul-assignment", "pop": "yul-pop",
    "return-yul": "yul-return", "revert-yul": "yul-revert", "invalid": "yul-invalid",
    "log0": "log0", "log1": "log1", "log2": "log2", "log3": "log3", "log4": "log4",
    "create": "create", "create2": "create2",
    "iszero": "yul-iszero", "not": "yul-not", "and": "yul-and", "or": "yul-or", "xor": "yul-xor",
    "byte": "yul-byte", "shl": "yul-shl", "shr": "yul-shr", "sar": "yul-sar",
    "lt": "yul-lt", "gt": "yul-gt", "slt": "yul-slt", "sgt": "yul-sgt", "eq": "yul-eq",
    "add": "yul-add", "sub": "yul-sub", "mul": "yul-mul", "div": "yul-div",
    "sdiv": "yul-sdiv", "mod": "yul-mod", "smod": "yul-smod", "exp": "yul-exp",
    "signextend": "yul-signextend", "clz": "yul-clz",
    "addmod-yul": "yul-addmod", "mulmod-yul": "yul-mulmod",
    "address-code": "address.code", "address-codehash": "address.codehash",
    "type-creation-code": "type-creationCode", "type-runtime-code": "type-runtimeCode",
    "type-interface-id": "type-interfaceId", "function-selector-4-bytes": "function-selector",
})

_EXTRA_MEANINGS.update({
    "mload": "Read one 32-byte word from EVM memory.",
    "mstore": "Write one 32-byte word to EVM memory.",
    "mstore8": "Write one byte to EVM memory.",
    "mcopy": "Copy a byte range within EVM memory.",
    "sload": "Read one 32-byte word from persistent storage.",
    "sstore": "Write one 32-byte word to persistent storage.",
    "tload": "Read one 32-byte word from transaction-scoped transient storage.",
    "tstore": "Write one 32-byte word to transaction-scoped transient storage.",
    "calldataload": "Read a 32-byte word from the current call calldata.",
    "calldatasize": "Return the current calldata size in bytes.",
    "calldatacopy": "Copy bytes from calldata into memory.",
    "returndatasize": "Return the size of the most recent returndata buffer.",
    "returndatacopy": "Copy bytes from the most recent returndata buffer into memory.",
    "extcodesize": "Return another address runtime-code size.",
    "extcodecopy": "Copy another address runtime code into memory.",
    "extcodehash": "Return another address code hash.",
    "codesize": "Return the current execution context code size.",
    "codecopy": "Copy current code bytes into memory.",
    "datasize": "Return a Yul object data section size.",
    "dataoffset": "Return a Yul object data section offset.",
    "datacopy": "Copy Yul object data into memory.",
    "linkersymbol": "Represent a symbolic link-time value in Yul object data.",
    "verbatim": "Insert backend-specific byte sequences in a Yul dialect when supported.",
    "pc": "Return the current EVM program counter.",
    "msize": "Return the current EVM memory extent.",
    "caller": "Yul low-level view of the immediate caller.",
    "callvalue": "Yul low-level view of ETH attached to the current call.",
    "selfbalance": "Return the current contract ETH balance.",
    "balance": "Return the ETH balance of a supplied address.",
    "gas": "Return remaining gas in Yul.",
    "gasleft": "Return remaining gas in Solidity.",
    "blockhash": "Return a recent block hash when available.",
    "blobhash": "Return a transaction blob versioned hash by index.",
    "yul-if": "Yul conditional statement.",
    "yul-switch": "Yul multi-way branch over literal cases.",
    "yul-for": "Yul loop with initialization, condition, post, and body.",
    "yul-break": "Exit the innermost Yul loop.",
    "yul-continue": "Skip to the post section of the innermost Yul loop.",
    "yul-leave": "Exit the current Yul function.",
    "yul-let": "Declare a scoped Yul local variable.",
    "yul-assignment": "Assign Yul locals with :=.",
    "yul-pop": "Discard a Yul value.",
    "yul-return": "Return memory bytes from the current EVM execution context.",
    "yul-revert": "Revert the current EVM execution context with memory bytes.",
    "yul-invalid": "Trigger the invalid-operation execution path.",
    "log0": "EVM log instruction with zero topics.", "log1": "EVM log instruction with one topic.",
    "log2": "EVM log instruction with two topics.", "log3": "EVM log instruction with three topics.",
    "log4": "EVM log instruction with four topics.",
    "create": "EVM contract creation from memory-held init code.",
    "create2": "EVM contract creation with a deterministic salt/init-code address formula.",
    "yul-iszero": "Yul zero test returning one for zero and zero otherwise.",
    "yul-not": "Yul bitwise complement.", "yul-and": "Yul bitwise AND.", "yul-or": "Yul bitwise OR.",
    "yul-xor": "Yul bitwise XOR.", "yul-byte": "Yul byte extraction.",
    "yul-shl": "Yul logical left shift.", "yul-shr": "Yul logical right shift.", "yul-sar": "Yul arithmetic right shift.",
    "yul-lt": "Yul unsigned less-than.", "yul-gt": "Yul unsigned greater-than.",
    "yul-slt": "Yul signed less-than.", "yul-sgt": "Yul signed greater-than.",
    "yul-eq": "Yul equality comparison.", "yul-add": "Yul addition.", "yul-sub": "Yul subtraction.",
    "yul-mul": "Yul multiplication.", "yul-div": "Yul unsigned division.",
    "yul-sdiv": "Yul signed division.", "yul-mod": "Yul unsigned remainder.",
    "yul-smod": "Yul signed remainder.", "yul-exp": "Yul exponentiation.",
    "yul-signextend": "Yul sign extension.", "yul-clz": "Yul count-leading-zero bits.",
    "yul-addmod": "Yul modular addition.", "yul-mulmod": "Yul modular multiplication.",
    "type-creationCode": "Creation bytecode exposed by type(C).creationCode.",
    "type-runtimeCode": "Runtime bytecode exposed by type(C).runtimeCode.",
    "type-interfaceId": "Interface identifier exposed by type(I).interfaceId.",
})

_EXTRA_CONCEPTS.update(_EXTRA_MEANINGS.keys())

_LATE_ATOM_EDGES = [
    ("mload", "memory", "mload reads one word from memory"),
    ("mstore", "memory", "mstore writes one word to memory"),
    ("mstore8", "memory", "mstore8 writes one byte to memory"),
    ("mcopy", "memory", "mcopy moves memory bytes"),
    ("sload", "storage", "sload reads persistent storage"),
    ("sstore", "storage", "sstore writes persistent storage"),
    ("tload", "transient-storage", "tload reads transient state"),
    ("tstore", "transient-storage", "tstore writes transient state"),
    ("calldataload", "calldata", "calldataload reads calldata"),
    ("calldatasize", "calldata", "calldatasize measures calldata"),
    ("calldatacopy", "calldata", "calldatacopy copies calldata"),
    ("returndatasize", "returndata", "returndatasize measures return bytes"),
    ("returndatacopy", "returndata", "returndatacopy copies return bytes"),
    ("extcodesize", "address", "extcodesize inspects code size at an address"),
    ("extcodecopy", "address", "extcodecopy reads code at an address"),
    ("extcodehash", "address", "extcodehash fingerprints code at an address"),
    ("codesize", "yul", "codesize inspects current code"),
    ("codecopy", "yul-memory", "codecopy moves current code into memory"),
    ("datasize", "yul", "datasize inspects Yul object data"),
    ("dataoffset", "yul", "dataoffset locates Yul object data"),
    ("datacopy", "yul-memory", "datacopy moves object data into memory"),
    ("linkersymbol", "yul", "linker symbols belong to Yul object linking"),
    ("verbatim", "yul", "verbatim is a low-level backend escape hatch"),
    ("pc", "yul", "pc exposes the EVM program counter"),
    ("msize", "memory", "msize exposes the memory extent"),
    ("caller", "msg.sender", "Yul caller corresponds to immediate call sender"),
    ("callvalue", "msg.value", "Yul callvalue corresponds to msg.value"),
    ("selfbalance", "contract-balance", "selfbalance reads the current contract balance"),
    ("balance", "address", "balance reads an address balance"),
    ("gas", "gasleft", "Yul gas and Solidity gasleft expose execution budget"),
    ("blockhash", "block.number", "blockhash is addressed by block number"),
    ("blobhash", "calldata", "blobhash is transaction data context"),
    ("block.chainid", "signature-verification", "chain ID binds signed messages to a domain"),
    ("block.basefee", "gas", "base fee is transaction/block fee context"),
    ("block.prevrandao", "yul", "prevrandao is block context visible to low-level code"),
    ("block.coinbase", "block.basefee", "both are block-level context values"),
    ("block.gaslimit", "gasleft", "both describe execution-budget context"),
    ("block.blobbasefee", "blobhash", "both relate to blob transaction economics"),
    ("yul-if", "yul-control-flow", "Yul if is control flow"),
    ("yul-switch", "yul-control-flow", "Yul switch is control flow"),
    ("yul-for", "yul-control-flow", "Yul for is the loop primitive"),
    ("yul-break", "yul-for", "break exits a Yul for loop"),
    ("yul-continue", "yul-for", "continue advances a Yul for loop"),
    ("yul-leave", "yul-functions", "leave exits a Yul function"),
    ("yul-let", "yul-functions", "let creates scoped Yul locals"),
    ("yul-assignment", "yul-let", "Yul assignment uses :="),
    ("yul-pop", "yul", "pop discards a value"),
    ("yul-return", "returndata", "Yul return supplies raw bytes to the caller"),
    ("yul-revert", "revert", "Yul revert supplies raw failure bytes"),
    ("yul-invalid", "yul", "invalid halts exceptionally"),
    ("log0", "events", "LOG instructions underlie Solidity events"),
    ("log1", "event-indexed", "log topics represent indexed event data"),
    ("log2", "event-indexed", "log topics represent indexed event data"),
    ("log3", "event-indexed", "log topics represent indexed event data"),
    ("log4", "event-indexed", "log topics represent indexed event data"),
    ("log4", "keccak256", "event identity is hash-derived"),
    ("create", "new", "new maps to contract creation"),
    ("create2", "new", "high-level creation has an EVM CREATE-family primitive"),
    ("create2", "keccak256", "CREATE2 includes the init-code hash"),
    ("create2", "address", "CREATE2 determines a fresh address"),
    ("yul-iszero", "yul-if", "zero testing commonly drives Yul conditions"),
    ("yul-lt", "yul-if", "comparisons feed Yul conditions"),
    ("yul-gt", "yul-if", "comparisons feed Yul conditions"),
    ("yul-slt", "yul-if", "signed comparisons feed Yul conditions"),
    ("yul-sgt", "yul-if", "signed comparisons feed Yul conditions"),
    ("yul-eq", "yul-switch", "equality commonly drives branching"),
    ("yul-add", "yul-for", "add commonly increments loop counters"),
    ("yul-mod", "yul-switch", "mod commonly selects branches"),
    ("yul-addmod", "addmod", "both compute modular addition"),
    ("yul-mulmod", "mulmod", "both compute modular multiplication"),
    ("address.code", "address", "runtime code is accessed through an address"),
    ("address.code", "bytes", "runtime code is exposed as bytes"),
    ("address.codehash", "extcodehash", "both expose code identity by hash"),
    ("address.codehash", "bytes32", "code hash is bytes32"),
    ("type-creationCode", "new", "creationCode feeds deployment"),
    ("type-runtimeCode", "address.code", "runtimeCode describes deployed runtime code"),
    ("type-interfaceId", "interface", "interfaceId identifies an interface"),
]

for _left, _right, _label in _LATE_ATOM_EDGES:
    _COMPREHENSIVE_CONNECTION_EDGES.append((
        canonicalize(_left), canonicalize(_right), _label
    ))

_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()

# Late production-pattern edges. These concepts are introduced by the
# research scene corpus after the original graph was constructed.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("erc4626-pattern", "mapping", "vault shares are commonly tracked by mapping"),
    ("erc4626-pattern", "structs", "vault accounting can group share/asset state"),
    ("erc4626-pattern", "events", "vault deposits and withdrawals emit lifecycle events"),
    ("erc1271", "interface", "contract signatures are queried through a typed interface"),
    ("erc1271", "bytes32", "signature validation takes a message digest"),
    ("erc1271", "bytes", "signature material is passed as bytes"),
    ("erc1967-storage", "delegatecall", "the implementation slot feeds delegated execution"),
    ("erc1967-storage", "storage-layout", "proxy slot conventions protect implementation state"),
    ("multicall", "arrays", "batch calls are represented as arrays of calldata bytes"),
    ("multicall", "delegatecall", "self-delegation keeps batch calls in one storage context"),
    ("multicall", "returndata", "each subcall can produce raw return bytes"),
    ("flashloan-pattern", "callback", "temporary liquidity is followed by a receiver callback"),
    ("flashloan-pattern", "interface", "flash-loan receivers expose a typed callback interface"),
    ("flashloan-pattern", "reentrancy", "callback execution is an external re-entry boundary"),
    ("flashloan-pattern", "checks-effects-interactions", "repayment state must survive the callback boundary"),
    ("permit2-pattern", "mapping", "delegated permissions are represented as allowance mappings"),
    ("permit2-pattern", "nonce", "nonces prevent replay of signed permissions"),
    ("permit2-pattern", "signature-verification", "signature validation authorizes the permission"),
    ("permit2-pattern", "keccak256", "signed permission digests are hash-derived"),
    ("callback", "external-call", "a callback is entered through an external call"),
    ("callback", "reentrancy", "callbacks can re-enter the calling protocol"),
    ("hook", "callback", "hooks are lifecycle callbacks"),
    ("hook", "external-call", "hooks cross a contract boundary"),
    ("hook", "reentrancy", "hooks create re-entry opportunities"),
    ("no-delegatecall", "delegatecall", "the guard exists to reject delegated execution"),
    ("no-delegatecall", "storage", "the guard protects execution/storage assumptions"),
])


# Final low-level arithmetic/bitwise neighborhood coverage.
_COMPREHENSIVE_CONNECTION_EDGES.extend([
    ("yul-and", "yul", "bitwise AND is a Yul word operation"),
    ("yul-or", "yul", "bitwise OR is a Yul word operation"),
    ("yul-xor", "yul", "bitwise XOR is a Yul word operation"),
    ("yul-byte", "yul", "byte extraction is a Yul word operation"),
    ("yul-shl", "yul", "left shift is a Yul word operation"),
    ("yul-shr", "yul", "right shift is a Yul word operation"),
    ("yul-sar", "yul", "arithmetic right shift is a Yul word operation"),
    ("yul-signextend", "yul", "sign extension is a Yul word operation"),
    ("yul-sub", "yul", "subtraction is a Yul arithmetic operation"),
    ("yul-mul", "yul", "multiplication is a Yul arithmetic operation"),
    ("yul-div", "yul", "unsigned division is a Yul arithmetic operation"),
    ("yul-sdiv", "yul", "signed division is a Yul arithmetic operation"),
    ("yul-smod", "yul", "signed remainder is a Yul arithmetic operation"),
    ("yul-exp", "yul", "exponentiation is a Yul arithmetic operation"),
    ("yul-clz", "yul", "count-leading-zero is a Yul bit operation"),
])

_FINAL_GRAPH_AUDIT_RESULT = _final_graph_audit()
