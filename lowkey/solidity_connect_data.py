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
