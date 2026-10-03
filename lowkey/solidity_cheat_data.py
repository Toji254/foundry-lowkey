"""Static contract labs and glossary data for the read-only Solidity cheatsheet."""

CONTRACT_LABS = {
    "loops": """contract LoopLab {
    function demo(uint256[] memory xs)
        external
        pure
        returns (uint256 total)
    {
        for (uint256 i = 0; i < xs.length; i++) {
            total += xs[i];
        }
    }
}""",
    "receive": """contract ReceiveLab {
    event Received(address indexed from, uint256 amount, uint256 dataLength);

    receive() external payable {
        emit Received(msg.sender, msg.value, msg.data.length);
    }
}""",
    "fallback": """contract FallbackLab {
    event Routed(bytes4 selector, uint256 dataLength, uint256 value);

    fallback(bytes calldata input) external payable {
        bytes4 selector =
            input.length >= 4 ? bytes4(input[:4]) : bytes4(0);
        emit Routed(selector, input.length, msg.value);
    }
}""",
    "receive-vs-fallback": """contract ReceiveFallbackLab {
    event Path(string which, uint256 value, uint256 dataLength);

    receive() external payable {
        emit Path("receive", msg.value, msg.data.length);
    }

    fallback(bytes calldata input) external payable {
        emit Path("fallback", msg.value, input.length);
    }
}""",
    "calls": """interface ITarget {
    function ping(uint256 x) external returns (uint256);
}

contract CallsLab {
    function use(ITarget target, uint256 x)
        external
        returns (uint256)
    {
        return target.ping(x);
    }
}""",
    "calldata": """contract CalldataLab {
    function set(uint256 amount) external {
        amount;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        return input;
    }
}""",
    "msg-block-tx": """contract ContextLab {
    function inspect() external payable returns (
        address,
        uint256,
        bytes calldata,
        bytes4
    ) {
        return (msg.sender, msg.value, msg.data, msg.sig);
    }
}""",
    "msg.value-vs-balance": """contract BalanceLab {
    function observe() external payable returns (
        uint256 sentNow,
        uint256 totalHeld
    ) {
        return (msg.value, address(this).balance);
    }
}""",
    "ternary": """contract TernaryLab {
    function fee(uint256 amount, bool vip)
        external
        pure
        returns (uint256)
    {
        return amount * (vip ? 1 : 2) / 100;
    }
}""",
    "types": """contract TypesLab {
    uint256 public amount;
    bool public active;
    address public owner;
    bytes32 public id;
    string public note;
    uint256[] public scores;

    enum Status { Open, Paid }
    Status public status;

    struct User {
        address account;
        uint256 score;
    }

    User public user;
}""",
    "symbols": """contract SymbolsLab {
    mapping(address => uint256) public balances;
    uint256 public count;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function demo(uint256 amount, bool vip)
        external
        returns (uint256 result)
    {
        uint256 fee = vip ? 1 ether : 0;
        if (amount > fee && amount != 0) {
            count++;
        }
        for (uint256 i = 0; i < 3; i++) {
            result += i;
        }
        return result;
    }
}""",
    "for": """contract ForExample {
    uint256[] public numbers;

    function fill(uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            numbers.push(i);
        }
    }
}""",
    "while": """contract WhileLab {
    function count(uint256 limit)
        external
        pure
        returns (uint256 i)
    {
        while (i < limit) {
            i++;
        }
    }
}""",
    "do-while": """contract DoWhileLab {
    function count(uint256 limit)
        external
        pure
        returns (uint256 i)
    {
        do {
            i++;
        } while (i < limit);
    }
}""",
    "for-each": """contract ForEachLab {
    address[] public users;
    mapping(address => uint256) public points;

    function reward(uint256 amount) external {
        for (uint256 i = 0; i < users.length; i++) {
            points[users[i]] += amount;
        }
    }
}""",
    "loop-comparison": """contract LoopComparisonLab {
    function counted(uint256[] memory xs)
        external
        pure
        returns (uint256 total)
    {
        for (uint256 i = 0; i < xs.length; i++) {
            total += xs[i];
        }
    }

    function conditional(uint256 target)
        external
        pure
        returns (uint256 i)
    {
        while (i < target) {
            i++;
        }
    }

    function guaranteedFirst(uint256 target)
        external
        pure
        returns (uint256 i)
    {
        do {
            i++;
        } while (i < target);
    }
}""",
    "globals": """contract GlobalsLab {
    function inspect() external payable returns (
        address sender,
        uint256 value,
        bytes calldata data,
        bytes4 sig,
        uint256 timestamp,
        uint256 number,
        uint256 balance
    ) {
        return (
            msg.sender,
            msg.value,
            msg.data,
            msg.sig,
            block.timestamp,
            block.number,
            address(this).balance
        );
    }
}""",
    "globals-map": """contract GlobalsMapLab {
    function payment()
        external
        payable
        returns (address caller, uint256 sent, uint256 held)
    {
        return (msg.sender, msg.value, address(this).balance);
    }
}""",
    "global-functions": """contract GlobalFunctionsLab {
    function makeId(address user, uint256 amount)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(user, amount));
    }

    function maxValue()
        external
        pure
        returns (uint256)
    {
        return type(uint256).max;
    }
}""",
    "mapping-types": """contract MappingTypesLab {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;

    function setBalance(uint256 amount) external {
        balances[msg.sender] = amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
}""",
    "struct-types": """contract StructTypesLab {
    enum Status { Open, Paid }

    struct Bounty {
        address creator;
        uint256 amount;
        string description;
        Status status;
    }

    mapping(bytes32 => Bounty) public bounties;

    function create(bytes32 id, uint256 amount, string calldata description)
        external
    {
        bounties[id] = Bounty({
            creator: msg.sender,
            amount: amount,
            description: description,
            status: Status.Open
        });
    }
}""",
    "types-table": """contract TypesTableLab {
    uint256 public amount;
    bool public active;
    address public owner;
    bytes32 public id;
    string public note;
    uint256[] public scores;

    enum Status { Open, Paid }
    Status public status;

    struct User {
        address account;
        uint256 score;
    }

    User public user;
}""",
    "calldata-deep": """contract CalldataDeepLab {
    uint256 public lastAmount;

    function setAmount(uint256 amount) external {
        lastAmount = amount;
    }

    fallback(bytes calldata input) external {
        bytes4 selector =
            input.length >= 4 ? bytes4(input[:4]) : bytes4(0);
        selector;
    }
}""",
    "call-data-layout": """contract CalldataLayoutLab {
    function set(uint256 amount, address user) external {
        amount;
        user;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        return input;
    }
}""",
    "ternary-deep": """contract TernaryDeepLab {
    function fee(uint256 amount, bool vip)
        external
        pure
        returns (uint256)
    {
        uint256 rate = vip ? 1 : 2;
        return amount * rate / 100;
    }
}""",
    "parameter-vs-argument": """contract ParameterArgumentLab {
    function withdraw(uint256 amount) external {
        require(amount > 0);
    }

    function demo() external {
        this.withdraw(1 ether);
    }
}""",,
    "require": """contract RequireLab {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }
}"""
}

TERM_DEFINITIONS = {
    "ternary": "Compact if/else expression that produces a value.",
    "parameter": "Named input slot in a function definition.",
    "argument": "Actual value passed to a function parameter.",
    "expression": "Code that evaluates to or refers to a value.",
    "statement": "An executable instruction.",
    "state variable": "Contract-level data that persists in storage.",
    "local variable": "Temporary variable declared inside a function or scope.",
    "value type": "A type whose values are copied when assigned or passed.",
    "reference type": "A type whose data is handled through a data location.",
    "calldata": "Raw bytes supplied to a contract call; calldata as a data location is read-only external input.",
    "ABI": "The rules used to encode typed values into bytes and decode returned bytes.",
    "selector": "The first four bytes of normal function calldata.",
    "callback": "A call made back into a contract during another operation.",
    "mutability": "A function's state/ETH permission: pure, view, nonpayable, payable.",
    "visibility": "Who or where a function/state variable can be accessed.",
    "storage slot": "A numbered 32-byte persistent storage location.",
    "packing": "Storing multiple small state variables in one slot when possible.",
    "reentrancy": "Re-entering a contract before an earlier interaction has finished.",
    "delegatecall": "Running another contract's code while using the caller's storage/context.",
    "interface": "A description of callable functions without their implementation.",
    "modifier": "Reusable wrapper/check logic around a function.",
    "invariant": "A property that should remain true across state transitions.",
    "PoC": "A proof-of-concept reproduction of a security claim.",
    "value": "The actual data stored in or returned by a variable/field.",
    "keyword": "A reserved or context-sensitive language word with special compiler meaning.",
    "contract anatomy": "The structural pieces of a contract: inheritance, state, events, errors, modifiers, constructor, functions, and ETH fallbacks.",
    "call": "An external message sent to another contract/address.",
    "staticcall": "An external call constrained from modifying state in the called execution.",
    "parameter vs argument": "Parameter is the named input in a function definition; argument is the actual value supplied at the call site.",
    "default value": "The zero-equivalent value Solidity gives fresh or deleted data of a type.",
    "pattern": "A recurring code shape used for a common design or control-flow task.",
    "pragma": "A compiler/version directive such as pragma solidity ^0.8.20;.",
}
