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
        "title": "An import exposes a base constructor",
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
    result = {}

    def capture(name, aliases, *args):
        result[_norm(name)] = name
        for alias in aliases:
            result[_norm(alias)] = name

    _register_catalog_topics(capture)
    return result


_CATALOG_ALIASES = _build_catalog_aliases()


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
    "keccak-selectors": "function-selector",
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
    "calls": "calls",
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
    canonical = canonicalize(name)
    if canonical in _EXTRA_MEANINGS:
        return _EXTRA_MEANINGS[canonical]

    topic_name = _CATALOG_ALIASES.get(_norm(canonical))
    if topic_name:
        # Re-run the catalog registration locally to get the authoritative
        # meaning without importing the cheatsheet module (which would cycle).
        found = {"meaning": None}

        def capture(name_, aliases_, category, meaning, *args):
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


def _scene(**kwargs):
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
    for scene in COMPREHENSIVE_MICRO_SCENES:
        keys = frozenset(canonicalize(x) for x in scene["keys"])
        if requested <= keys:
            candidates.append(scene)

    # Keep the old small scenes as a compatibility fallback.
    for scene in MICRO_SCENES:
        keys = frozenset(canonicalize(x) for x in scene["keys"])
        if requested <= keys:
            candidates.append(scene)

    if not candidates:
        return None

    # Exact matches win. Otherwise prefer the scene with the fewest concepts
    # that were not explicitly requested, then the smallest total scene.
    candidates.sort(
        key=lambda scene: (
            0 if frozenset(canonicalize(x) for x in scene["keys"]) == requested else 1,
            len(frozenset(canonicalize(x) for x in scene["keys"]) - requested),
            len(scene["keys"]),
            scene.get("title", ""),
        )
    )
    return candidates[0]


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
    "tstore": "EVM/Yul operation that writes a word to transaction-scoped transient storage.",
})

_EXTRA_CONCEPTS.update({
    "assignment", "compound-assignment", "abi.encodeCall", "sha256", "ripemd160", "ecrecover",
    "addmod", "mulmod", "bytes.concat", "string.concat", "selfdestruct",
    "this", "super", "nonce", "erc7201", "tload", "tstore",
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
