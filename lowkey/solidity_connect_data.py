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
    "bytes32": "bytes32",
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


def canonicalize(name: str) -> str:
    key = _norm(name)
    return _CONCEPT_ALIASES.get(key, key)


def find_connection(names):
    requested = frozenset(canonicalize(name) for name in names if str(name).strip())
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
        return None

    candidates.sort(key=lambda item: (item[0], item[1], item[2]["name"]))
    return candidates[0][2]


def list_connections():
    return [
        {
            "name": lab["name"],
            "aliases": lab["aliases"],
            "concepts": list(lab["concepts"]),
            "summary": lab["summary"],
        }
        for lab in CONNECTION_LABS
    ]
