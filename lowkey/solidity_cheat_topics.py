"""Solidity cheat topic catalog for LowkeyCast.

The main cheatsheet owns the CLI/renderer; this module owns the large
reference catalog so future learning additions stay isolated from runtime logic.
"""

def register_topics(add):
    add(
        "symbols", ["operators", "punctuation", "syntax-symbols", "solidity-symbols"], "CHEATSHEET",
        "Core Solidity punctuation, operators, delimiters, and syntax marks you will repeatedly see.",
        "Do not read symbols as decoration. Each one tells Solidity how values are grouped, accessed, compared, changed, called, or routed.",
        """STATEMENT / DELIMITERS
    ;       end a statement
    ,       separate items
    ()      group expressions / function parameters / function calls
    {}      block of statements / contract body / call options
    []      array type / array index / bytes or calldata slice
    .       member access
    :       ternary separator / named-argument separator / slice separator
    =>      mapping key -> value
    
    ASSIGNMENT
    =       assign
    +=      add, then assign
    -=      subtract, then assign
    *=      multiply, then assign
    /=      divide, then assign
    %=      remainder, then assign
    |=      bitwise OR, then assign
    ^=      bitwise XOR, then assign
    &=      bitwise AND, then assign
    <<=     shift left, then assign
    >>=     shift right, then assign
    
    ARITHMETIC
    +       add
    -       subtract / unary negative
    *       multiply
    /       divide
    %       remainder
    **      exponentiation
    ++      increment by 1
    --      decrement by 1
    
    COMPARISON
    ==      equal
    !=      not equal
    <       less than
    <=      less than or equal
    >       greater than
    >=      greater than or equal
    
    LOGICAL
    !       NOT
    &&      AND
    ||      OR
    ? :     ternary: choose one of two values
    
    BITWISE
    &       bitwise AND
    |       bitwise OR
    ^       bitwise XOR
    ~       bitwise NOT
    <<      shift left
    >>      shift right
    
    ACCESS / RANGE
    a[i]    index element i
    a[i:j]  slice from i up to j
    a[:]    whole slice
    a.b     read member b
    f(x)    call f with x
    
    TUPLES
    (a, b)              group multiple values
    (x, , z)            ignore one returned position
    (uint a, bool ok)   declare and unpack returns
    
    CALL OPTIONS
    f{value: amount}()  attach ETH
    f{gas: 50000}()    choose forwarded gas
    f{value: 1 ether, gas: 50000}()
    
    NAMED ARGUMENTS
    f({amount: 100, user: alice})
    
    CONVERSIONS / TYPE EXPRESSIONS
    address(x)          convert to address
    payable(x)           payable address conversion
    type(T)              type information
    new T(...)           contract creation
    
    SPECIAL BLOCK SYNTAX
    unchecked { ... }   arithmetic without checked overflow/underflow
    assembly { ... }    inline Yul/EVM assembly
    try ... catch ...   handle failure from an external call/contract creation
    
    COMMENTS / NATSPEC
    // comment
    /* block comment */
    /// NatSpec line
    /** NatSpec block */
    @param              NatSpec parameter tag
    @return             NatSpec return tag
    @notice             NatSpec notice tag
    @dev                NatSpec developer note
    """,
        """contract SymbolsLab {
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
    
            (uint256 a, bool ok) = this.check(amount);
            return ok ? a : 0;
        }
    
        function check(uint256 x)
            external
            pure
            returns (uint256, bool)
        {
            return (x, x > 0 && x < 100);
        }
    }""",
        [
            "Read punctuation by role: grouping (), indexing [], member access ., block {}, assignment =, and key/value =>.",
            "Read comparison operators as questions that produce true or false.",
            "Read compound assignment such as += as 'calculate, then put the result back into the left variable'.",
            "Read ? : as a value-producing if/else.",
            "Read call options such as {value: amount} as settings attached to that call, not as a new block statement.",
            "When auditing, parentheses, brackets, dots, and braces often tell you exactly where a value comes from and whether a call crosses a boundary.",
        ],
        audit="Operator precedence and call options can change behavior. Parenthesize complicated expressions instead of relying on readers remembering precedence.",
    )
    
    add(
        "variables", ["variable", "state-variable", "local-variable"], "CORE",
        "A named place holding a value.",
        "Think of a labeled M-Pesa balance box.",
        """uint256 amount = 100;
    address owner = msg.sender;
    bool paused = false;""",
        """contract Bank {
        uint256 public balance;
    
        function set(uint256 amount) external {
            balance = amount;
        }
    }""",
        [
            "Type comes first.",
            "Name comes next.",
            "Assignment gives it a value.",
            "At contract scope, the variable normally becomes persistent state.",
        ],
    )
    
    add(
        "types", ["datatypes", "primitive-types"], "CORE",
        "The kind of data: number, address, bool, bytes, text, list, record, and so on.",
        "Think of choosing the right container before putting the value inside.",
        """uint256 amount;
    int256 debt;
    bool paused;
    address user;
    bytes32 id;
    string note;
    bytes payload;""",
        """uint256 count;
    address owner;
    bool active;
    bytes32 orderId;""",
        [
            "uint is for non-negative integers.",
            "int is for signed integers.",
            "address identifies an EVM account/contract.",
            "bytes32 is common for hashes/IDs; string and bytes are dynamic.",
        ],
    )
    
    add(
        "function-syntax", ["function", "functions"], "CORE",
        "A function is a named action with inputs, visibility, mutability, and optional outputs.",
        "Think: a machine with input slots, an access gate, and an output tray.",
        """function withdraw(uint256 amount)
        external
        returns (bool ok)
    {
        ...
    }""",
        """function deposit() external payable {
        balances[msg.sender] += msg.value;
    }""",
        [
            "Name + parameter types define the callable shape.",
            "Visibility controls who can call it.",
            "Mutability describes ETH/state permissions.",
            "returns declares outputs.",
        ],
    )
    
    add(
        "visibility", ["public", "external", "internal", "private"], "CORE",
        "Visibility controls where a function or state variable can be accessed.",
        "Public desk, outside gate, staff hallway, private drawer.",
        """public
    external
    internal
    private""",
        """function deposit() external payable {}
    function helper() internal pure returns (uint256) {
        return 7;
    }""",
        [
            "public functions can be called externally and internally.",
            "external is for external message calls.",
            "internal is usable by the contract and derived contracts.",
            "private is limited to the defining contract.",
        ],
        gotchas="private does not mean secret. Chain state can still be inspected.",
    )
    
    add(
        "mutability", ["view", "pure", "payable", "nonpayable"], "CORE",
        "Mutability says whether a function can read state, write state, or receive ETH.",
        "Calculator, read-only screen, cash counter, or normal transaction.",
        """pure       no blockchain-state reads
    view        may read state
    payable     may receive ETH
    nonpayable  default""",
        """function add(uint256 a, uint256 b)
        external
        pure
        returns (uint256)
    {
        return a + b;
    }""",
        [
            "pure is for calculations independent of contract state.",
            "view can read state but is not supposed to write it.",
            "payable allows ETH to arrive with the call.",
        ],
    )
    
    add(
        "require", ["require-condition", "conditions"], "ERRORS",
        "Require a rule to be true; otherwise stop and revert.",
        "Read require(A, B) as: A must pass, otherwise B explains the failure.",
        """require(condition);
    require(condition, "message");
    require(condition, CustomError(args));""",
        """function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }""",
        [
            "First argument is the condition and must be boolean.",
            "Second argument is optional failure information.",
            "False condition reverts the call frame and rolls back its state changes.",
            "Use it for input, permission, and external-condition checks.",
        ],
        audit="Ask whether the condition is actually sufficient for the sensitive action.",
        gotchas="The first slot is the condition. The message is not the condition.",
    )
    
    add(
        "revert", ["revert-if", "revert-statement"], "ERRORS",
        "Explicitly abort execution and revert state changes.",
        "Think: cancel this transaction here.",
        "revert ErrorName(args);",
        """error NotEnough(uint256 available, uint256 needed);
    
    function pay(uint256 needed) external {
        if (balance < needed) {
            revert NotEnough(balance, needed);
        }
    }""",
        [
            "Detect the failure case.",
            "Use revert with a custom error or string when useful.",
            "Execution stops and the reverted state changes roll back.",
        ],
    )
    
    add(
        "assert", ["assertion", "panic"], "ERRORS",
        "Check an internal invariant that should never be false.",
        "Think: an emergency alarm for a programmer assumption.",
        "assert(condition);",
        """function invariantCheck() internal view {
        assert(totalSupply >= burned);
    }""",
        [
            "Use require for user/input/external conditions.",
            "Use assert for internal invariants.",
            "A failed assert produces a Solidity Panic.",
        ],
        audit="A reachable assert failure can indicate a serious bug or denial of service.",
    )
    
    add(
        "custom-errors", ["custom-error", "errors"], "ERRORS",
        "Structured revert reasons with a name and typed arguments.",
        "Think: a structured failure receipt instead of a long paragraph.",
        """error NotOwner(address caller);
    error InsufficientBalance(uint256 available, uint256 needed);""",
        """if (amount > available) {
        revert InsufficientBalance(available, amount);
    }""",
        [
            "Declare the error.",
            "Revert with error name + arguments.",
            "Callers can decode the typed revert data.",
        ],
    )
    
    add(
        "if-else", ["if", "else"], "CONTROL FLOW",
        "Choose different code paths based on a boolean condition.",
        "If the door is locked, reject; otherwise continue.",
        """if (condition) {
        ...
    } else {
        ...
    }""",
        """if (amount > 1 ether) {
        fee = amount / 100;
    } else {
        fee = 0;
    }""",
        [
            "Evaluate the condition.",
            "Run the if block when true.",
            "Run else when false.",
        ],
    )
    
    add(
        "loops", ["for", "while", "do-while"], "CONTROL FLOW",
        "Repeat code.",
        "Process item 0, then 1, then 2 until the stopping rule.",
        """for (uint256 i = 0; i < users.length; i++) {
        ...
    }
    
    while (x < 10) {
        x++;
    }""",
        """for (uint256 i = 0; i < recipients.length; i++) {
        pay(recipients[i]);
    }""",
        [
            "for is common for counted loops.",
            "while repeats while its condition stays true.",
            "do while runs the body once before checking.",
        ],
        audit="Unbounded user-controlled loops can become gas/DoS problems.",
    )
    
    add(
        "ternary", ["conditional-operator"], "CONTROL FLOW",
        "Compact if/else that produces a value.",
        "condition ? trueValue : falseValue",
        "uint256 fee = vip ? 0 : 1 ether;",
        """function fee(bool vip) external pure returns (uint256) {
        return vip ? 0 : 1;
    }""",
        [
            "Check condition.",
            "Use the left value when true.",
            "Use the right value when false.",
        ],
    )
    
    add(
        "unchecked", ["overflow", "underflow"], "CONTROL FLOW",
        "Skip checked integer overflow/underflow inside one block.",
        "Think: I proved the arithmetic is in bounds.",
        "unchecked { counter++; }",
        """function dec(uint256 x) external pure returns (uint256) {
        unchecked {
            return x - 1;
        }
    }""",
        [
            "Normal modern Solidity checks integer overflow/underflow.",
            "unchecked turns that protection off inside the block.",
            "Use it only when bounds are already proven.",
        ],
        audit="Every unchecked block deserves a manual proof of its bounds.",
    )
    
    add(
        "arrays", ["array", "dynamic-array", "fixed-array"], "DATA STRUCTURES",
        "An ordered list.",
        "Think numbered drawers starting at index 0.",
        """uint256[] public amounts;
    uint256[3] public fixed;""",
        """address[] public users;
    
    function add(address user) external {
        users.push(user);
    }
    
    function removeLast() external {
        users.pop();
    }""",
        [
            "T[] is dynamic.",
            "T[N] is fixed-size.",
            "Storage dynamic arrays support push, pop, and length.",
            "Index with array[index].",
        ],
    )
    
    add(
        "mapping", ["mappings", "map", "mapping-basics"], "DATA STRUCTURES",
        "A key -> value lookup table.",
        "Think M-Pesa account number -> balance.",
        """mapping(address => uint256) public balances;""",
        """function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }""",
        [
            "mapping(KEY => VALUE) puts key type before =>.",
            "Square brackets perform the lookup.",
            "balances[msg.sender] reads one user's value.",
            "Assign with =, +=, -=, and similar operators.",
        ],
        audit="Missing keys return defaults. Do not interpret a default as proof that the entry was never written.",
        gotchas="Mappings are not directly enumerable. Track keys separately when enumeration is required.",
    )
    
    add(
        "nested-mapping", ["nested-mappings", "mapping-of-mapping"], "DATA STRUCTURES",
        "A mapping whose value is another mapping.",
        "Think owner -> spender -> allowance.",
        """mapping(address => mapping(address => uint256)) public allowance;""",
        """function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
    
    uint256 x = allowance[owner][spender];""",
        [
            "First key selects the inner mapping.",
            "Second key selects the inner value.",
            "owner and spender together identify the value.",
        ],
    )
    
    add(
        "mapping-struct", ["mapping+struct", "mapping-of-struct"], "DATA STRUCTURES",
        "One structured record per key.",
        "Think account number -> complete customer record.",
        """struct User {
        uint256 balance;
        bool active;
    }
    mapping(address => User) public users;""",
        """users[msg.sender] = User({
        balance: 0,
        active: true
    });
    
    users[msg.sender].balance += 10;""",
        [
            "Mapping picks the record.",
            "Struct stores multiple fields.",
            "Dot notation selects a field.",
        ],
    )
    
    add(
        "mapping-array-value", ["mapping-to-array", "mapping+array"], "DATA STRUCTURES",
        "A mapping can point to an array.",
        "Think user -> list of that user's orders.",
        "mapping(address => uint256[]) public orders;",
        """function addOrder(uint256 id) external {
        orders[msg.sender].push(id);
    }""",
        [
            "First use the mapping key.",
            "Then use array operations on that mapped value.",
        ],
    )
    
    add(
        "arrays-mappings", ["array+mapping", "array-mapping", "arrays+mapping"], "DATA STRUCTURES",
        "Use mappings for direct lookup and arrays for order/enumeration.",
        "Think address book search + physical contact list.",
        """address[] users;
    mapping(address => uint256) balance;""",
        """function addUser(address user) external {
        if (balance[user] == 0) users.push(user);
        balance[user] += 1;
    }""",
        [
            "Mapping answers 'what is this key's value?'",
            "Array answers 'which keys/items do I have?'",
            "Keeping both requires consistency.",
        ],
        audit="Check that updates cannot desynchronize the array and mapping.",
    )
    
    add(
        "arrays-structs", ["array+struct", "array-struct", "struct-array"], "DATA STRUCTURES",
        "A list of complete records.",
        "Think spreadsheet rows, where each row is a struct.",
        """struct Bounty {
        address creator;
        uint256 amount;
    }
    Bounty[] public bounties;""",
        """bounties.push(Bounty({
        creator: msg.sender,
        amount: 1 ether
    }));""",
        [
            "Define the record.",
            "Create an array of that struct.",
            "Push a new record.",
        ],
    )
    
    add(
        "mapping-defaults", ["mapping-default", "missing-key"], "DATA STRUCTURES",
        "A missing mapping key reads as the type's default value.",
        "An empty account box can read zero even when no entry was created.",
        """uint mapping -> 0
    bool mapping -> false
    address mapping -> address(0)""",
        """mapping(address => uint256) balances;
    
    function looksKnown(address user) external view returns (bool) {
        return balances[user] != 0;
    }""",
        [
            "Look up the key.",
            "If it was never written, Solidity still returns a default.",
            "Therefore value == default does not prove the key is absent.",
        ],
        audit="Use an explicit existence flag when default values are valid data.",
    )
    
    add(
        "enum", ["enums", "state-machine"], "DATA STRUCTURES",
        "A fixed set of named states.",
        "Think order: Open -> Claimed -> Paid.",
        "enum Status { Open, Claimed, Paid, Cancelled }",
        """if (status == Status.Open) {
        status = Status.Claimed;
    }""",
        [
            "Declare allowed states.",
            "Store one state.",
            "Compare and transition between states.",
        ],
        audit="Review every function that writes the enum and every allowed transition.",
    )
    
    add(
        "strings-bytes", ["string", "bytes", "dynamic-bytes"], "DATA TYPES",
        "Dynamic text or byte sequences.",
        "Think a note or binary blob whose size can vary.",
        """string name;
    bytes payload;""",
        """function setName(string calldata name_) external {
        name = name_;
    }""",
        [
            "string is intended for text.",
            "bytes is a dynamic byte sequence.",
            "External functions commonly receive them in calldata.",
        ],
        gotchas="Complex string manipulation can be costly on-chain.",
    )
    
    add(
        "bytesN", ["bytes32", "fixed-bytes"], "DATA TYPES",
        "Fixed-length byte values.",
        "Think exactly N bytes, not a growable blob.",
        """bytes32 id;
    bytes4 selector;""",
        "bytes32 id = keccak256(abi.encode(user, amount));",
        [
            "bytes32 is common for hashes and IDs.",
            "bytes4 is common for function selectors.",
        ],
    )
    
    add(
        "address", ["address-payable", "payable-address"], "DATA TYPES",
        "An EVM account/contract address; payable is the ETH-receiving form.",
        "Think wallet/account number.",
        """address user;
    address payable treasury;""",
        """function pay(address payable to) external payable {
        (bool ok,) = to.call{value: msg.value}("");
        require(ok);
    }""",
        [
            "address identifies the destination.",
            "Use address payable where Solidity must send ETH through payable operations.",
            "payable(addressValue) can perform the conversion.",
        ],
    )
    
    add(
        "storage-memory-calldata", ["data-locations", "memory-storage-calldata"], "DATA LOCATIONS",
        "Storage is persistent, memory is temporary, calldata is temporary read-only input.",
        "Storage = filing cabinet; memory = scratch paper; calldata = read-only envelope.",
        """User storage u = users[user];
    User memory copy = users[user];
    function f(User calldata input) external {}""",
        """function update(address user) external {
        User storage u = users[user];
        u.balance += 10;
    }""",
        [
            "storage points to persistent state.",
            "memory creates a temporary copy.",
            "calldata is read-only external input.",
            "A storage reference can modify the original state.",
        ],
        audit="Reference-type data-location mistakes can change whether code writes state.",
    )
    
    add(
        "constructor", ["constructors"], "CONTRACTS",
        "Runs once during deployment.",
        "Think setup day before the shop opens.",
        "constructor(address owner_) { owner = owner_; }",
        """contract Vault {
        address public owner;
        constructor(address owner_) {
            owner = owner_;
        }
    }""",
        [
            "Deployment supplies constructor arguments.",
            "Constructor initializes state.",
            "It is not a normal callable function afterward.",
        ],
    )
    
    add(
        "modifiers", ["modifier", "underscore"], "CONTRACTS",
        "Reusable wrapper logic around a function.",
        "Think security guard before entering a building.",
        """modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }""",
        """function sweep(address payable to, uint256 amount)
        external
        onlyOwner
    {
        to.transfer(amount);
    }""",
        [
            "Code before _ runs first.",
            "_ means run the wrapped function body.",
            "Code after _ runs after the body.",
        ],
        audit="Modifier behavior is part of the function's security boundary.",
    )
    
    add(
        "inheritance", ["inherit", "is", "multiple-inheritance"], "CONTRACTS",
        "Reuse/extend parent contract behavior.",
        "Think child class receiving selected parent behavior.",
        "contract Child is Parent { ... }",
        """contract Base {
        uint256 public x;
    }
    
    contract Child is Base {
        function set(uint256 value) external {
            x = value;
        }
    }""",
        [
            "is declares inheritance.",
            "Inherited members are usable subject to visibility.",
            "Multiple inheritance needs careful override rules.",
        ],
    )
    
    add(
        "override-virtual", ["override", "virtual"], "CONTRACTS",
        "virtual allows replacement; override marks the replacement.",
        "Parent says customizable; child supplies the custom version.",
        "function fee() public virtual returns (uint256) { ... }",
        """contract Base {
        function fee() public pure virtual returns (uint256) {
            return 10;
        }
    }
    
    contract Child is Base {
        function fee() public pure override returns (uint256) {
            return 5;
        }
    }""",
        [
            "Parent marks virtual.",
            "Child marks override.",
            "Derived behavior follows the inheritance hierarchy.",
        ],
    )
    
    add(
        "interface", ["interfaces", "IERC20", "contract-interface"], "CONTRACTS",
        "A typed list of callable functions another contract can expose.",
        "Think restaurant menu: what you can order, not how the kitchen works.",
        """interface IERC20 {
        function transfer(address to, uint256 amount)
            external
            returns (bool);
    }""",
        """interface IPriceFeed {
        function latestAnswer() external view returns (int256);
    }
    
    contract Trader {
        IPriceFeed public feed;
    
        constructor(address feed_) {
            feed = IPriceFeed(feed_);
        }
    
        function price() external view returns (int256) {
            return feed.latestAnswer();
        }
    }""",
        [
            "Write function signatures without bodies.",
            "Point an interface variable at a contract address.",
            "Call the interface.",
            "The call crosses an external contract boundary.",
        ],
        audit="The interface is your type assumption. Verify the actual target address and behavior.",
    )
    
    add(
        "interface-vs-abstract", ["abstract-contract", "interfaces-vs-abstract"], "CONTRACTS",
        "Interface is an API shell; abstract contract is partial implementation.",
        "Think menu versus half-built restaurant.",
        """interface IThing {
        function ping() external;
    }
    
    abstract contract Base {
        uint256 public x;
        function ping() public virtual;
    }""",
        """abstract contract Base {
        uint256 public x;
    
        function ping() public virtual;
        function helper() internal {
            x += 1;
        }
    }""",
        [
            "Use interfaces for callable boundaries.",
            "Use abstract contracts when shared storage/code matters.",
            "Abstract contracts can contain implemented helpers and state.",
        ],
    )
    
    add(
        "library", ["libraries", "using-for"], "CONTRACTS",
        "Reusable helper code.",
        "Think toolbox shared by several contracts.",
        """library MathLib {
        function double(uint256 x) internal pure returns (uint256) {
            return x * 2;
        }
    }""",
        """using MathLib for uint256;
    
    uint256 result = amount.double();""",
        [
            "Put reusable helper logic in the library.",
            "using Library for Type attaches compatible helpers.",
            "Call through the value when the library API supports it.",
        ],
    )
    
    add(
        "events", ["event", "emit", "indexed"], "LOGS",
        "Transaction logs used by off-chain observers.",
        "Think receipt book, not the actual ledger.",
        "event Deposit(address indexed user, uint256 amount);",
        """function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }""",
        [
            "Declare the event.",
            "Emit it when the interesting action happens.",
            "indexed arguments become searchable topics.",
        ],
        audit="Events are evidence, not authorization or storage.",
    )
    
    add(
        "receive", ["receive()", "receive-ether", "plain-ether"], "ETH FLOW",
        "The special function for empty calldata, commonly plain ETH transfers.",
        "Think someone drops cash at the door without naming an office.",
        "receive() external payable { ... }",
        """contract TipJar {
        event Deposit(address indexed from, uint256 amount);
    
        receive() external payable {
            emit Deposit(msg.sender, msg.value);
        }
    }""",
        [
            "Look at calldata.",
            "If it is empty and receive exists, receive handles the call.",
            "receive is external payable with no arguments or returns.",
            "msg.value tells you the ETH attached to that call.",
        ],
        audit="Check whether ETH received here is reflected in accounting.",
    )
    
    add(
        "fallback", ["fallback()", "fallback-function"], "ETH FLOW",
        "Catch-all special function when no normal function matches the calldata.",
        "Think general reception desk when no named office matches.",
        "fallback() external payable { ... }",
        """contract RouterLike {
        fallback() external payable {
            // inspect msg.data or route elsewhere
        }
    }""",
        [
            "The call arrives with calldata.",
            "Normal function selector matching happens first.",
            "If nothing matches, fallback runs.",
            "It must be payable to accept ETH through that path.",
        ],
        audit="Fallbacks deserve extra scrutiny in proxies, routers, and arbitrary-call contracts.",
    )
    
    add(
        "receive-vs-fallback", ["fallback-receive", "receive-fallback"], "ETH FLOW",
        "Empty calldata prefers receive; unmatched calldata goes to fallback.",
        "Check the envelope before deciding which door gets the call.",
        """empty calldata       -> receive(), if present
    unknown selector       -> fallback()
    unknown selector + ETH -> payable fallback()
    msg.data               -> complete calldata in normal/fallback calls
    receive()              -> cannot access msg.data""",
        """contract Example {
        receive() external payable {}
        fallback() external payable {}
    }""",
        [
            "Empty calldata: receive gets priority when defined.",
            "Non-empty unmatched data: fallback.",
            "Without receive, payable fallback can handle empty data too.",
        ],
    )
    
    add(
        "calls", ["calling", "contract-calls"], "CALLS",
        "Calls can stay internal, cross an external boundary, or use raw low-level calls.",
        "Same office hallway versus phoning another company.",
        """foo();
    this.foo();
    other.foo();
    address(other).call(data);""",
        """interface IToken {
        function transfer(address to, uint256 amount) external returns (bool);
    }
    
    function pay(IToken token, address to, uint256 amount) external {
        token.transfer(to, amount);
    }""",
        [
            "foo() is an internal-style call in the same contract.",
            "this.foo() creates an external call back to this contract.",
            "other.foo() crosses into another contract.",
            "address.call gives raw success/data handling.",
        ],
        audit="Every external call is a trust boundary and possible reentrancy point.",
    )
    
    add(
        "this-call", ["this.foo", "external-self-call"], "CALLS",
        "this.foo() is an external message call to this contract.",
        "Think phone yourself instead of walking down the hallway.",
        "foo(); versus this.foo();",
        """function inc() public {
        count++;
    }
    
    function externalInc() external {
        this.inc();
    }""",
        [
            "foo() stays in the current execution context.",
            "this.foo() crosses the external-call boundary.",
            "That changes call context and can introduce reentrancy concerns.",
        ],
    )
    
    add(
        "low-level-call", ["call", "address.call", "call-with-value"], "CALLS",
        "Raw external call returning success and bytes.",
        "Think send an envelope and get accepted/rejected plus raw data.",
        "(bool success, bytes memory data) = target.call(payload);",
        """(bool ok,) = payable(recipient).call{value: amount}("");
    require(ok, "send failed");""",
        [
            "Prepare calldata.",
            "Call the address.",
            "Check success.",
            "Decode returned bytes only when you know the format.",
        ],
        audit="Ignoring the success result is a classic failure mode.",
    )
    
    add(
        "staticcall", ["address.staticcall"], "CALLS",
        "Low-level external call intended for read-only execution.",
        "Ask another contract a question without letting it write.",
        "(bool ok, bytes memory data) = target.staticcall(payload);",
        """(bool ok, bytes memory data) =
        address(feed).staticcall(
            abi.encodeWithSignature("latestAnswer()")
        );
    require(ok);""",
        [
            "Build the payload.",
            "Use staticcall.",
            "Check success.",
            "Decode the returned bytes.",
        ],
    )
    
    add(
        "delegatecall", ["delegate-call"], "CALLS",
        "Execute another contract's code using the caller's storage/context.",
        "Borrow another worker but make them use your office and records.",
        "(bool ok, bytes memory data) = implementation.delegatecall(payload);",
        """fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }""",
        [
            "Caller sends calldata to the proxy.",
            "Fallback catches it.",
            "Implementation code runs against proxy storage.",
            "That makes layout compatibility critical.",
        ],
        audit="Review implementation trust, upgrades, storage collisions, initialization, selector routing.",
    )
    
    add(
        "msg-block-tx", ["globals", "global-values"], "GLOBAL VALUES",
        "Built-in context values for caller, transaction, call data, and block.",
        "Think current call receipt + current block information.",
        """msg.sender
    msg.value
    msg.data
    msg.sig
    block.timestamp
    block.number
    tx.origin""",
        """function deposit() external payable {
        balances[msg.sender] += msg.value;
    }""",
        [
            "msg.sender is the immediate caller.",
            "msg.value is ETH attached to the current call.",
            "msg.data is raw calldata; msg.sig is normally its first four bytes.",
            "block values come from the current block context.",
        ],
    )
    
    add(
        "msg.value-vs-balance", ["address-this-balance", "eth-balance"], "ETH FLOW",
        "msg.value is this call's ETH; address(this).balance is the contract's current total ETH.",
        "Think today's deposit versus the account's whole balance.",
        "msg.value versus address(this).balance",
        """function deposit() external payable {
        uint256 sentNow = msg.value;
        uint256 totalHeld = address(this).balance;
    }""",
        [
            "Use msg.value for the current call.",
            "Use address(this).balance for the current contract balance.",
            "Previous deposits and other transfers affect the total.",
        ],
    )
    
    add(
        "ether-flow", ["eth", "send-eth", "transfer-send-call"], "ETH FLOW",
        "Ways a contract moves ETH.",
        "Debit the ledger, then hand over the cash.",
        """payable(to).call{value: amount}("");
    to.transfer(amount);  // legacy/deprecated
    to.send(amount);      // legacy/deprecated""",
        """function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "failed");
    }""",
        [
            "Check the withdrawal.",
            "Update accounting.",
            "Make the external ETH call.",
            "Check the result.",
        ],
        audit="ETH sends can execute receiver code and create reentrancy risk.",
    )
    
    add(
        "abi-encode", ["abi.encode", "abi.encodeWithSelector", "abi.encodeWithSignature"], "ABI",
        "Encode typed values into bytes for calls or hashing.",
        "Think machine-readable envelope.",
        """abi.encode(a, b)
    abi.encodeWithSelector(selector, a, b)
    abi.encodeWithSignature("foo(uint256)", a)""",
        """bytes memory payload =
        abi.encodeWithSignature(
            "transfer(address,uint256)",
            to,
            amount
        );""",
        [
            "abi.encode gives encoded values.",
            "WithSelector adds a selector you supply.",
            "WithSignature derives the selector from the canonical signature.",
        ],
    )
    
    add(
        "abi-decode", ["abi.decode", "decode-bytes"], "ABI",
        "Decode ABI-encoded bytes into expected Solidity types.",
        "Think unpack the envelope using the exact schema.",
        "(uint256 amount, address user) = abi.decode(data, (uint256, address));",
        """uint256 amount =
        abi.decode(returnData, (uint256));""",
        [
            "Know how the bytes were encoded.",
            "Provide matching types to abi.decode.",
            "A mismatch can revert or produce nonsense.",
        ],
    )
    
    add(
        "encodePacked", ["abi.encodePacked", "packed-encoding"], "ABI / HASHING",
        "Tightly pack values into bytes.",
        "Think squeeze fields together with fewer boundaries.",
        "abi.encodePacked(a, b)",
        """bytes32 id = keccak256(
        abi.encodePacked(msg.sender, block.timestamp)
    );""",
        [
            "Values are tightly packed.",
            "The result can be hashed.",
            "Know ambiguity risks with multiple dynamic values.",
        ],
        audit="Use abi.encode for unambiguous structured hashing unless packing is deliberate.",
    )
    
    add(
        "keccak-selectors", ["keccak256", "function-selector", "selector"], "ABI / HASHING",
        "Keccak hashes data; a selector is the first four bytes of the hash of a canonical function signature.",
        "Think function name + parameter types -> four-byte fingerprint.",
        """keccak256(abi.encode(user, amount))
    bytes4(keccak256("transfer(address,uint256)"))""",
        """bytes4 selector = bytes4(keccak256("withdraw(uint256)"));""",
        [
            "Write the canonical signature.",
            "Hash it with Keccak-256.",
            "Take the first four bytes for the selector.",
        ],
    )
    
    add(
        "function-signature", ["signature", "function-selector-signature"], "ABI",
        "A function signature uses the function name plus parameter TYPES, not actual values.",
        """withdraw(uint256)
    transfer(address,uint256)
    createbounty(address,uint256)""",
        "function name(types...)",
        """function transfer(address to, uint256 amount) external returns (bool) {
        ...
    }""",
        [
            "Write function name.",
            "Write parameter types.",
            "Do not put real argument values in the signature.",
        ],
    )
    
    add(
        "calldata", ["msg.data", "call-data"], "ABI",
        "Raw bytes sent to an external function call.",
        "Think the entire machine-readable envelope.",
        "bytes calldata input",
        """fallback(bytes calldata input) external {
        bytes4 selector = bytes4(input[:4]);
    }""",
        [
            "External call data normally starts with a four-byte selector.",
            "Remaining bytes normally carry ABI-encoded arguments.",
            "Calldata is read-only.",
        ],
    )
    
    add(
        "calldata-slices", ["bytes-slice", "input-slice"], "ABI",
        "Take part of a bytes/calldata value.",
        "Cut the selector off the front of the envelope.",
        "input[:4] and input[4:]",
        """fallback(bytes calldata input) external {
        bytes4 selector = bytes4(input[:4]);
        bytes calldata body = input[4:];
    }""",
        [
            "First four bytes normally identify the function.",
            "The remainder normally contains arguments.",
            "Slicing is bounds-sensitive.",
        ],
    )
    
    add(
        "storage-layout", ["storage", "storage-slots", "slots"], "STORAGE",
        "Persistent contract state is stored in numbered 32-byte slots.",
        "Think giant row of numbered lockers.",
        "slot 0, slot 1, slot 2, ...",
        """uint256 a;
    uint256 b;""",
        [
            "Compiler assigns storage locations.",
            "Small values may share a slot.",
            "Mappings and dynamic arrays derive their data locations.",
        ],
        audit="Use the compiler's real storage layout for upgrades and forensics.",
    )
    
    add(
        "mapping-slots", ["mapping-storage", "mapping-slot-formula"], "STORAGE",
        "Mapping storage is derived from the mapping key and its anchor slot.",
        "Locker number = hash(key + mapping slot).",
        "keccak256(abi.encode(key, mappingSlot))",
        """// balances is at slot 3
    bytes32 aliceSlot =
        keccak256(abi.encode(alice, uint256(3)));""",
        [
            "Find the mapping's slot.",
            "Encode key first.",
            "Encode mapping slot second.",
            "Hash the pair.",
        ],
    )
    
    add(
        "nested-mapping-slots", ["nested-mapping-storage"], "STORAGE",
        "Nested mappings derive the inner slot from the outer derived slot.",
        "A locker inside another locker.",
        """outer = keccak256(abi.encode(key1, slot))
    inner = keccak256(abi.encode(key2, outer))""",
        """// mapping(address => mapping(address => uint256)) at slot 5
    bytes32 ownerSlot =
        keccak256(abi.encode(owner, uint256(5)));
    
    bytes32 spenderSlot =
        keccak256(abi.encode(spender, ownerSlot));""",
        [
            "Start with the outer mapping slot.",
            "Hash key one with it.",
            "Use that result as the inner slot.",
            "Hash key two with the inner slot.",
        ],
    )
    
    add(
        "array-storage", ["dynamic-array-storage", "array-slots"], "STORAGE",
        "Dynamic arrays derive element storage from a hashed anchor slot.",
        "The array slot is an index card pointing to another storage region.",
        "base = keccak256(abi.encode(arraySlot))",
        "uint256[] values;",
        [
            "Find the dynamic array anchor slot.",
            "Hash the anchor slot to reach the data area.",
            "For simple one-slot elements, index advances from that base.",
            "Packed or multi-slot elements need the compiler's exact layout.",
        ],
    )
    
    add(
        "storage-packing", ["packed-storage", "slot-packing"], "STORAGE",
        "Small compatible values can share one 32-byte storage slot.",
        "Several small files fit in one locker.",
        """uint128 a;
    uint128 b;
    bool active;""",
        """contract Packed {
        uint128 public a;
        uint128 public b;
        bool public active;
    }""",
        [
            "Compiler may pack smaller values.",
            "Exact packing should be confirmed with the compiled storage layout.",
        ],
        audit="Never hand-wave slot positions in upgrade/storage-collision review.",
    )
    
    add(
        "delete", ["delete-statement", "reset"], "STATE",
        "Reset a storage value toward its type's default.",
        "Erase the stored value back to zero/false/zero-address.",
        "delete balances[user];",
        """uint256 public count = 10;
    
    function reset() external {
        delete count;
    }""",
        [
            "Identify the value.",
            "Know its default.",
            "delete writes the reset state when applied to storage.",
        ],
    )
    
    add(
        "try-catch", ["try", "catch"], "ERROR HANDLING",
        "Handle failure from an external call.",
        "Call another service and handle its failure locally.",
        """try target.doThing() returns (uint256 value) {
        ...
    } catch {
        ...
    }""",
        """try oracle.latestAnswer() returns (int256 price) {
        require(price > 0);
    } catch {
        revert OracleUnavailable();
    }""",
        [
            "The call must be external.",
            "Success runs the returns block.",
            "Failure enters catch.",
        ],
        audit="Revert data can bubble up from deeper calls and should not be treated as identity proof.",
    )
    
    add(
        "using-for", ["using", "library-methods"], "ADVANCED",
        "Attach library functions to a type.",
        "Teach a value a helper method from a toolbox.",
        "using MathLib for uint256;",
        """using MathLib for uint256;
    
    uint256 result = amount.double();""",
        [
            "Write the helper in a library.",
            "Declare using Library for Type.",
            "Call the helper through the value.",
        ],
    )
    
    add(
        "type-metadata", ["type(T)", "type-max", "interfaceId"], "ADVANCED",
        "Inspect bounds or metadata about a type.",
        "Ask Solidity about the type itself.",
        """type(uint256).max
    type(uint256).min
    type(IERC165).interfaceId""",
        "uint256 constant MAX = type(uint256).max;",
        [
            "Put the type inside type(...).",
            "Use supported members such as max, min, or interfaceId.",
        ],
    )
    
    add(
        "external-function-types", ["function-pointers", "function-values"], "ADVANCED",
        "A variable can hold a typed function reference.",
        "Think store the phone number of a callable action.",
        "function(uint256) external returns (bool) action;",
        """function run(
        function(uint256) external returns (bool) action
    ) external returns (bool) {
        return action(10);
    }""",
        [
            "Describe inputs and outputs.",
            "Store a compatible function reference.",
            "Call the variable like a function.",
        ],
    )
    
    add(
        "new", ["contract-creation", "deploy-from-contract"], "CONTRACTS",
        "Create a new contract from Solidity.",
        "Think a factory opens a fresh branch.",
        "Child child = new Child(arg1, arg2);",
        """contract Factory {
        function create() external returns (address) {
            Child child = new Child();
            return address(child);
        }
    }""",
        [
            "Choose the contract type.",
            "Provide constructor arguments.",
            "Deployment returns the new contract address/reference.",
        ],
    )
    
    add(
        "reentrancy", ["reentrant", "re-entrancy"], "SECURITY",
        "External control can come back into you before your function finishes.",
        "Think bank teller hands out cash before updating the ledger.",
        """// dangerous
    send ETH
    then reduce balance""",
        """function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok);
    }""",
        [
            "Find external calls.",
            "Find state that must change before those calls.",
            "Ask whether the receiver can call back.",
            "Use CEI and/or a guard when appropriate.",
        ],
        audit="Check cross-function and cross-contract reentrancy too.",
    )
    
    add(
        "checks-effects-interactions", ["CEI"], "SECURITY",
        "Checks first, state effects second, external interactions last.",
        "Verify -> update ledger -> hand over cash.",
        """require(condition);
    state = newState;
    externalCall();""",
        """function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok);
    }""",
        [
            "Checks = permissions/bounds.",
            "Effects = state/accounting.",
            "Interactions = external calls.",
        ],
    )
    
    add(
        "access-control", ["only-owner", "authorization", "permissions"], "SECURITY",
        "Restrict sensitive actions to the correct caller or role.",
        "Think only the treasury manager has the vault key.",
        """require(msg.sender == owner, "not owner");""",
        """modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }""",
        [
            "Identify the sensitive action.",
            "Identify the intended caller.",
            "Check the caller before the action.",
            "Search for alternate public paths that bypass the check.",
        ],
        audit="A strong modifier is useless if another function reaches the same state change without it.",
    )
    
    add(
        "tx-origin", ["tx.origin", "origin-auth"], "SECURITY",
        "The original transaction EOA, not the immediate caller.",
        "Think who started the journey, not who is knocking at your door.",
        "tx.origin",
        """function withdraw() external {
        require(msg.sender == owner, "not owner");
    }""",
        [
            "Direct EOA calls often have msg.sender == tx.origin.",
            "Contract-to-contract calls make them different.",
            "Authorization normally uses msg.sender or a deliberate role system.",
        ],
        audit="tx.origin authorization is a classic security smell.",
    )
    
    add(
        "timestamp", ["block.timestamp", "time"], "SECURITY",
        "The current block timestamp.",
        "Think chain-reported time, not a perfect wall clock.",
        "block.timestamp",
        """require(block.timestamp >= deadline, "too early");""",
        [
            "Useful for broad deadlines and windows.",
            "Do not treat it as exact time or secure randomness.",
        ],
    )
    
    add(
        "front-running", ["MEV", "mempool", "ordering"], "SECURITY",
        "Public pending transactions can sometimes be copied or reordered for profit.",
        "Think someone sees the order before the clerk processes it.",
        """commit = keccak256(abi.encode(secret, amount));
    reveal(secret, amount);""",
        """mapping(address => bytes32) public commitments;
    
    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
    }
    
    function reveal(uint256 amount, bytes32 secret) external {
        require(commitments[msg.sender] == keccak256(abi.encode(secret, amount)));
    }""",
        [
            "Identify information visible before execution.",
            "Ask whether another actor profits by reacting first.",
            "Consider commit-reveal or other protocol-specific mitigations.",
        ],
    )
    
    add(
        "signature-verification", ["signatures", "ecrecover", "ECDSA"], "SECURITY",
        "Verify a signed message came from the intended signer and resist replay.",
        "Think signed paper + correct signer + exact message + nonce.",
        "ecrecover(digest, v, r, s)",
        """mapping(address => uint256) public nonces;
    
    require(nonce == nonces[owner]);
    require(ecrecover(digest, v, r, s) == owner);
    nonces[owner]++;""",
        [
            "Define exactly what is signed.",
            "Bind the message to the intended domain/context.",
            "Use nonce/deadline/replay protection where needed.",
            "Verify the recovered signer.",
        ],
        audit="Domain separation and nonce bugs are common signature vulnerabilities.",
    )
    
    add(
        "proxy-fallback", ["proxy", "delegatecall-fallback"], "ADVANCED / SECURITY",
        "A proxy fallback routes arbitrary calldata to implementation code.",
        "Think receptionist forwards every unknown request to a backend using the receptionist's records.",
        """fallback() external payable {
        implementation.delegatecall(msg.data);
    }""",
        """fallback() external payable {
        (bool ok, bytes memory result) =
            implementation.delegatecall(msg.data);
        require(ok);
    }""",
        [
            "Caller sends calldata to proxy.",
            "Fallback catches it.",
            "Delegatecall executes implementation code with proxy storage.",
            "Return/revert data must be handled correctly.",
        ],
        audit="Review upgrade authority, initialization, storage collisions, selector clashes, and forwarding.",
    )
    
    add(
        "contract-balance", ["address-this-balance", "code-length"], "FORENSICS",
        "Read an address balance or see whether an address currently has code.",
        "Think inspect the account's cash and whether it has deployed code.",
        """address(this).balance
    address(target).code.length""",
        """uint256 held = address(this).balance;
    bool hasCode = target.code.length > 0;""",
        [
            "Balance is current ETH held by the address.",
            "code.length is current runtime code size.",
            "Neither proves that an address is trustworthy.",
        ],
    )
    
    add(
        "payable", ["payable-function"], "ETH FLOW",
        "Marks a function as able to receive ETH.",
        "Think this counter accepts cash.",
        "function deposit() external payable {}",
        """function deposit() external payable {
        balances[msg.sender] += msg.value;
    }""",
        [
            "Call can attach ETH.",
            "msg.value tells you how much arrived.",
        ],
    )
    
    add(
        "returns", ["return", "return-values"], "CORE",
        "Declare outputs with returns and send them back with return.",
        "Think output tray.",
        "function f() external pure returns (uint256) { return 7; }",
        """function split(uint256 x)
        external
        pure
        returns (uint256 half, uint256 rest)
    {
        half = x / 2;
        rest = x - half;
    }""",
        [
            "returns declares types.",
            "return supplies values.",
            "Named outputs can be assigned directly.",
        ],
    )
    
    add(
        "constant-immutable", ["constant", "immutable"], "CORE",
        "constant is fixed by compilation; immutable is assigned during construction and then fixed.",
        "Think printed label versus label filled during setup and laminated.",
        """uint256 public constant FEE = 1;
    address public immutable owner;""",
        """contract Config {
        uint256 public constant FEE = 1;
        address public immutable owner;
    
        constructor() {
            owner = msg.sender;
        }
    }""",
        [
            "constant never changes.",
            "immutable is set during construction and then cannot change.",
        ],
    )
    
    add(
        "imports", ["import", "import-alias"], "PROJECT",
        "Bring declarations from another Solidity source file into the current file.",
        "Think bring another toolbox into the room.",
        """import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";""",
        """import {ERC721URIStorage} from
        "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";""",
        [
            "Named import selects a declaration.",
            "Whole-file import imports a path without selecting symbols.",
            "Remappings make package paths readable.",
        ],
    )
    
    add(
        "comments-natspec", ["comments", "natspec"], "SYNTAX",
        "Comments explain code; NatSpec documents public code for people/tools.",
        "Think sticky note versus official documentation.",
        """// comment
    /* block comment */
    /// @notice Public documentation""",
        """/// @notice Withdraw your recorded balance.
    function withdraw(uint256 amount) external {
        ...
    }""",
        [
            "// is a line comment.",
            "/* ... */ is a block comment.",
            "/// is commonly used for NatSpec documentation.",
        ],
    )
    
    add(
        "forge-cheatcodes", ["cheatcodes", "vm"], "FOUNDRY",
        "Foundry test helpers, not production Solidity features.",
        "Think laboratory equipment.",
        """vm.prank(alice);
    vm.deal(attacker, 100 ether);
    vm.warp(block.timestamp + 7 days);
    vm.store(address(target), slot, value);""",
        """function testWithdraw() public {
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        target.deposit{value: 1 ether}();
    }""",
        [
            "Use them in Foundry test/script contexts.",
            "They can alter the test environment.",
            "Do not confuse them with normal Solidity language features.",
        ],
    )
    
    
    # ---------------------------------------------------------------------------
    # FOUNDRY TEST / SCRIPT / POC DICTIONARY
    # ---------------------------------------------------------------------------
    
    add(
        "test", ["tests", "foundry-test", "solidity-tests"], "FOUNDRY TESTING",
        "A Foundry test is a Solidity contract whose functions exercise another contract and prove properties about it.",
        "Think of a lab notebook: set up the machine, do one action, then check what happened.",
        """import {Test} from "forge-std/Test.sol";
    
    contract BankTest is Test {
        Bank bank;
    
        function setUp() public {
            bank = new Bank();
        }
    
        function testDeposit() public {
            bank.deposit{value: 1 ether}();
            assertEq(address(bank).balance, 1 ether);
        }
    }""",
        """// test/Bank.t.sol
    pragma solidity ^0.8.20;
    
    import {Test} from "forge-std/Test.sol";
    import {Bank} from "../src/Bank.sol";
    
    contract BankTest is Test {
        Bank bank;
    
        function setUp() public {
            bank = new Bank();
        }
    
        function testDeposit() public {
            bank.deposit{value: 1 ether}();
            assertEq(address(bank).balance, 1 ether);
        }
    }""",
        [
            "Put tests under test/ and normally give them a .t.sol suffix.",
            "Import forge-std/Test.sol and inherit Test to get assertions and vm cheatcodes.",
            "setUp() runs before each test function.",
            "A normal test function commonly starts with test and makes the expected result explicit.",
            "Run it with forge test or the matching LowkeyCast/Foundsry workflow.",
        ],
        audit="For auditing, a test should turn a security hypothesis into repeatable evidence rather than merely showing the happy path.",
        gotchas="A test passing does not prove the contract is secure; it proves only the behavior you actually checked.",
    )
    
    add(
        "test-structure", ["test-file", "test-contract", "setUp", "setup"], "FOUNDRY TESTING",
        "The standard shape of a Foundry test file.",
        "Imports -> test contract -> fixtures -> individual experiments.",
        """contract MyTest is Test {
        Target target;
    
        function setUp() public {
            target = new Target();
        }
    
        function testSomething() public {
            ...
        }
    }""",
        """// test/Target.t.sol
    pragma solidity ^0.8.20;
    import {Test} from "forge-std/Test.sol";
    import {Target} from "../src/Target.sol";
    
    contract TargetTest is Test {
        Target target;
        address alice = makeAddr("alice");
    
        function setUp() public {
            target = new Target();
        }
    
        function testHappyPath() public {
            ...
        }
    }""",
        [
            "Import Test.sol.",
            "Inherit Test.",
            "Declare target, actors, constants, and fixtures.",
            "Create/reset state in setUp().",
            "Keep each test focused on one behavior or property.",
        ],
    )
    
    add(
        "test-arrange-act-assert", ["AAA", "arrange-act-assert"], "FOUNDRY TESTING",
        "A simple pattern for writing readable tests: prepare, act, verify.",
        "Prepare the room -> press the button -> check the result.",
        """// Arrange
    // Act
    // Assert""",
        """function testWithdraw() public {
        // Arrange
        vm.deal(alice, 10 ether);
        vm.startPrank(alice);
        target.deposit{value: 1 ether}();
        vm.stopPrank();
    
        // Act
        vm.prank(alice);
        target.withdraw(1 ether);
    
        // Assert
        assertEq(alice.balance, 10 ether);
    }""",
        [
            "Arrange creates the state and actors needed for the experiment.",
            "Act performs the action under investigation.",
            "Assert checks the property that must hold.",
            "For a PoC, the Assert section is usually the concrete exploit evidence.",
        ],
    )
    
    add(
        "test-assertions", ["assertions", "forge-std-assertions", "assertEq"], "FOUNDRY TESTING",
        "Assertions fail a test when the observed result does not match the expected property.",
        "A referee checking whether the scoreboard matches the rule.",
        """assertEq(actual, expected);
    assertTrue(condition);
    assertGt(a, b);
    assertLt(a, b);
    assertGe(a, b);
    assertLe(a, b);""",
        """uint256 beforeBal = alice.balance;
    target.withdraw(1 ether);
    uint256 afterBal = alice.balance;
    
    assertEq(afterBal, beforeBal + 1 ether);
    assertTrue(afterBal > beforeBal);
    assertGe(afterBal, beforeBal);""",
        [
            "Calculate or read the actual value.",
            "State the expected value or relationship.",
            "Use the assertion that expresses the property most clearly.",
        ],
    )
    
    add(
        "fuzz-tests", ["fuzz", "fuzzing", "testFuzz"], "FOUNDRY TESTING",
        "A fuzz test lets Foundry try many input values against one test property.",
        "Instead of checking one key, hand the tester a whole key ring and see which key breaks the door.",
        """function testFuzz_deposit(uint256 amount) public {
        ...
    }""",
        """function testFuzz_noFreeMoney(uint256 amount) public {
        vm.assume(amount > 0);
        vm.deal(alice, amount);
    
        vm.prank(alice);
        target.deposit{value: amount}();
    
        assertEq(target.balanceOf(alice), amount);
    }""",
        [
            "Write the test as a function with input parameters.",
            "Restrict impossible or irrelevant values with vm.assume when necessary.",
            "Assert the invariant/property that should hold for every accepted input.",
            "Run forge test; Foundry supplies many values and reports a counterexample when one fails.",
        ],
        audit="Fuzzing is strong for arithmetic boundaries, accounting conservation, authorization inputs, and unexpected values.",
        gotchas="Do not use vm.assume to hide the interesting attack surface. Bound or constrain only values that are genuinely out of scope.",
    )
    
    add(
        "bounded-fuzz", ["bound", "vm.bound", "bounded-fuzzing"], "FOUNDRY TESTING",
        "Bound a fuzzed value into an inclusive range instead of discarding cases.",
        "Turn any random number into one that fits the test's allowed lane.",
        """amount = bound(amount, 1, 100 ether);""",
        """function testFuzz_withinRange(uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        vm.deal(alice, amount);
        ...
    }""",
        [
            "Foundry gives you a fuzzed value.",
            "bound maps it into the requested inclusive range.",
            "The test still explores many values without throwing away values through repeated assumptions.",
        ],
    )
    
    add(
        "invariant-tests", ["invariant", "invariants"], "FOUNDRY TESTING",
        "An invariant test checks that a property remains true across many generated calls and states.",
        "A rule the bank must never break, no matter which valid customer action happens next.",
        """function invariant_totalSupplyMatchesBalances() public {
        assertEq(..., ...);
    }""",
        """contract Handler {
        Target target;
    
        function deposit(uint256 amount) external {
            ...
        }
    }
    
    contract TargetInvariantTest is Test {
        Target target;
        Handler handler;
    
        function setUp() public {
            target = new Target();
            handler = new Handler(target);
            targetContract(address(handler));
        }
    
        function invariant_accounting() public view {
            assertEq(target.totalAssets(), target.recordedAssets());
        }
    }""",
        [
            "Define a property that must survive sequences of actions.",
            "Create a target or handler that exposes meaningful actions.",
            "Register the handler/target for invariant execution.",
            "Assert the property from the resulting state.",
        ],
        audit="For security work, invariants often catch accounting drift or state combinations that hand-written examples miss.",
    )
    
    add(
        "invariant-handler", ["handler", "handler-pattern"], "FOUNDRY TESTING",
        "A handler turns messy fuzzed calls into controlled protocol actions for invariant testing.",
        "A test operator chooses realistic buttons instead of letting the machine smash random keyboard keys.",
        """function deposit(uint256 amount) external {
        amount = bound(amount, 1, 10 ether);
        ...
    }
    
    function withdraw(uint256 amount) external {
        ...
    }""",
        """contract Handler {
        Target internal target;
        address internal alice;
    
        constructor(Target _target) {
            target = _target;
            alice = makeAddr("alice");
        }
    
        function deposit(uint256 amount) external {
            amount = bound(amount, 1, 10 ether);
            vm.deal(alice, amount);
            vm.prank(alice);
            target.deposit{value: amount}();
        }
    }""",
        [
            "Expose one function per meaningful action.",
            "Bound inputs into realistic domains.",
            "Control actors explicitly.",
            "Use the invariant contract to assert system-wide properties.",
        ],
    )
    
    add(
        "fork-tests", ["fork", "mainnet-fork", "fork-testing"], "FOUNDRY TESTING",
        "Fork testing runs tests against a copy of a real chain state.",
        "Freeze a copy of the real M-Pesa ledger at a moment, then experiment without changing the real ledger.",
        """vm.createSelectFork(vm.envString("RPC_URL"));
    address forked = ...;""",
        """function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"));
        target = IERC20(0x...);
    }""",
        [
            "Choose an RPC endpoint.",
            "Create or select a fork.",
            "Interact with real deployed addresses against copied state.",
            "Optionally pin a block for deterministic historical conditions.",
            "Run the test locally; the fork itself is the sandbox.",
        ],
        audit="Fork tests are useful for reproducing bugs involving real integrations, balances, oracle state, and upgrade paths.",
        gotchas="A fork is local execution against copied state; it does not automatically broadcast your test transaction to the real network.",
    )
    
    add(
        "test-reverts", ["expectRevert", "revert-tests", "custom-errors-test"], "FOUNDRY TESTING",
        "Tell Foundry that the next call is expected to revert, optionally with a specific reason or error.",
        "You tell the referee: the next play is supposed to be rejected.",
        """vm.expectRevert();
    vm.expectRevert("Not owner");
    vm.expectRevert(MyError.selector);""",
        """vm.prank(attacker);
    vm.expectRevert(NotOwner.selector);
    target.withdraw(1 ether);""",
        [
            "Set the expected revert before the call that should fail.",
            "Execute the call.",
            "The test passes when the expected revert occurs.",
            "Use exact revert data when the reason itself matters.",
        ],
        audit="A PoC can use expectRevert to prove that a protection blocks an attack path; the opposite is useful when proving a missing check.",
    )
    
    add(
        "test-events", ["expectEmit", "events-test", "event-tests"], "FOUNDRY TESTING",
        "Check that an emitted event matches the fields your protocol promises.",
        "Listen at the counter and verify the receipt says the right thing.",
        """vm.expectEmit(true, true, true, true);
    emit Withdraw(alice, 1 ether);""",
        """vm.expectEmit(true, true, false, true);
    emit Withdraw(alice, 1 ether);
    vm.prank(alice);
    target.withdraw(1 ether);""",
        [
            "Tell Foundry which event fields to compare.",
            "Emit the expected event in the test.",
            "Call the target.",
            "Foundry compares the actual emitted log with the expected event.",
        ],
    )
    
    add(
        "vm-prank", ["prank", "vm.prank", "change-sender"], "FOUNDRY CHEATCODES",
        "Make the next external call appear to come from a chosen address.",
        "Put on Alice's caller-ID for one phone call.",
        """vm.prank(alice);
    target.withdraw(1 ether);""",
        """vm.deal(alice, 1 ether);
    vm.prank(alice);
    target.deposit{value: 1 ether}();""",
        [
            "Choose the actor address.",
            "Call vm.prank(actor).",
            "The next call uses that actor as msg.sender.",
            "After the one call, normal caller identity returns.",
        ],
    )
    
    add(
        "vm-start-prank", ["startPrank", "stopPrank", "persistent-prank"], "FOUNDRY CHEATCODES",
        "Make calls from a chosen address until you stop the prank.",
        "Keep the same caller badge on for several interactions.",
        """vm.startPrank(alice);
    ...
    vm.stopPrank();""",
        """vm.startPrank(alice);
    target.deposit{value: 1 ether}();
    target.withdraw(1 ether);
    vm.stopPrank();""",
        [
            "Start with vm.startPrank(actor).",
            "Every applicable call uses the selected caller.",
            "Call vm.stopPrank() when finished.",
        ],
        gotchas="For calls involving contract recipients, distinguish msg.sender from tx.origin and choose prank overloads deliberately.",
    )
    
    add(
        "vm-deal", ["deal", "vm.deal", "set-balance"], "FOUNDRY CHEATCODES",
        "Directly set an address's ETH balance inside the test environment.",
        "Give Alice test money instantly instead of mining a faucet transaction.",
        """vm.deal(alice, 100 ether);""",
        """vm.deal(alice, 10 ether);
    vm.prank(alice);
    target.deposit{value: 1 ether}();""",
        [
            "Pick the address.",
            "Set its test ETH balance.",
            "Use the account normally in the test.",
        ],
    )
    
    add(
        "vm-warp", ["warp", "time-travel", "block.timestamp-test"], "FOUNDRY CHEATCODES",
        "Set the simulated block timestamp.",
        "Move the laboratory clock forward.",
        """vm.warp(block.timestamp + 7 days);""",
        """uint256 deadline = block.timestamp + 1 days;
    vm.warp(deadline + 1);
    assertTrue(block.timestamp > deadline);""",
        [
            "Read the current test timestamp.",
            "Choose the new timestamp.",
            "Call vm.warp(newTimestamp).",
            "The following EVM execution sees the new block timestamp.",
        ],
    )
    
    add(
        "vm-roll", ["roll", "block-number-test"], "FOUNDRY CHEATCODES",
        "Set the simulated block number.",
        "Move the lab to a later block height.",
        """vm.roll(block.number + 100);""",
        """uint256 beforeBlock = block.number;
    vm.roll(beforeBlock + 100);
    assertEq(block.number, beforeBlock + 100);""",
        [
            "Read the current block number.",
            "Call vm.roll(newBlockNumber).",
            "Later execution sees the changed block number.",
        ],
    )
    
    add(
        "vm-assume", ["assume", "fuzz-filter"], "FOUNDRY CHEATCODES",
        "Discard fuzz inputs that do not satisfy a condition.",
        "Tell the tester: do not waste runs on impossible cases.",
        """vm.assume(amount > 0 && amount < 1 ether);""",
        """function testFuzz_fee(uint256 amount) public {
        vm.assume(amount > 0);
        ...
    }""",
        [
            "Write the domain condition.",
            "Call vm.assume(condition).",
            "Foundry keeps only inputs satisfying the condition.",
        ],
        gotchas="Overusing assume can cause excessive rejected inputs and can accidentally exclude the bug.",
    )
    
    add(
        "vm-bound", ["bound-cheatcode"], "FOUNDRY CHEATCODES",
        "Transform a fuzz value into an inclusive numeric range.",
        "Put a giant random number through a gate that returns a permitted value.",
        """amount = bound(amount, 1, 100);""",
        """function testFuzz_withdraw(uint256 amount) public {
        amount = bound(amount, 1, 10 ether);
        ...
    }""",
        [
            "Take the fuzzed variable.",
            "Supply lower and upper limits.",
            "Use the returned value in the test.",
        ],
    )
    
    add(
        "vm-makeaddr", ["makeAddr", "make-address"], "FOUNDRY CHEATCODES",
        "Create a deterministic test address from a readable label.",
        "Turn the name alice into a repeatable fake wallet address.",
        """address alice = makeAddr("alice");""",
        """address public alice;
    function setUp() public {
        alice = makeAddr("alice");
    }""",
        [
            "Give makeAddr a stable label.",
            "Use the returned address as an actor.",
            "Combine it with vm.label or vm.deal when useful.",
        ],
    )
    
    add(
        "vm-label", ["label", "vm.label"], "FOUNDRY CHEATCODES",
        "Give an address a human-readable label in Foundry traces.",
        "Put a sticky name on a wallet so traces stop showing raw hex everywhere.",
        """vm.label(alice, "Alice");""",
        """alice = makeAddr("alice");
    vm.label(alice, "Alice");
    vm.label(address(target), "Target");""",
        [
            "Choose an address.",
            "Assign a label.",
            "Verbose traces can display the label for easier reading.",
        ],
    )
    
    add(
        "vm-expect-revert", ["expect-revert", "expectRevert"], "FOUNDRY CHEATCODES",
        "Configure the next call to be expected to revert.",
        "Set the referee's expected result before the play.",
        """vm.expectRevert();
    vm.expectRevert(bytes4(MyError.selector));
    vm.expectRevert(abi.encodeWithSelector(MyError.selector, 7));""",
        """vm.prank(attacker);
    vm.expectRevert(Unauthorized.selector);
    target.adminAction();""",
        [
            "Choose the revert shape you need to check.",
            "Set the expectation before the target call.",
            "Execute the target call.",
            "Foundry fails the test if the expected revert does not happen.",
        ],
    )
    
    add(
        "vm-expect-emit", ["expect-emit", "expectEmit"], "FOUNDRY CHEATCODES",
        "Configure the next log assertion and compare an expected event with the real event.",
        "Put a receipt template on the desk and compare it with what the contract emits.",
        """vm.expectEmit(true, true, true, true);
    emit Transfer(from, to, amount);""",
        """vm.expectEmit(true, false, false, true);
    emit Deposit(alice, 1 ether);
    target.deposit{value: 1 ether}();""",
        [
            "Set which indexed/data fields matter.",
            "Emit the expected event.",
            "Call the target.",
            "Foundry compares the corresponding log.",
        ],
    )
    
    add(
        "vm-recordlogs", ["recordLogs", "getRecordedLogs", "logs"], "FOUNDRY CHEATCODES",
        "Record emitted logs so a test can inspect them after a call.",
        "Turn on a camera before the transaction, then review the footage.",
        """vm.recordLogs();
    target.doThing();
    Vm.Log[] memory entries = vm.getRecordedLogs();""",
        """vm.recordLogs();
    target.deposit{value: 1 ether}();
    Vm.Log[] memory logs = vm.getRecordedLogs();
    
    assertGt(logs.length, 0);""",
        [
            "Start recording before the target call.",
            "Execute the action.",
            "Read the recorded logs afterward.",
            "Inspect topics and data when exact event decoding matters.",
        ],
    )
    
    add(
        "vm-snapshots", ["snapshot", "revertTo", "snapshotState"], "FOUNDRY CHEATCODES",
        "Save test state and later restore it.",
        "Take a save-game before the experiment, then load it again.",
        """uint256 snap = vm.snapshotState();
    ...
    vm.revertTo(snap);""",
        """uint256 snap = vm.snapshotState();
    target.deposit{value: 1 ether}();
    
    vm.revertTo(snap);
    assertEq(address(target).balance, 0);""",
        [
            "Capture the state before the experiment.",
            "Perform any number of actions.",
            "Revert to the snapshot when you want the earlier state back.",
        ],
    )
    
    add(
        "vm-storage", ["vm.store", "vm.load", "storage-cheatcodes"], "FOUNDRY CHEATCODES",
        "Read or directly write raw storage slots in a test environment.",
        "Open the bank's ledger drawer by slot number instead of using the normal app interface.",
        """bytes32 raw = vm.load(address(target), slot);
    vm.store(address(target), slot, raw);""",
        """bytes32 beforeValue = vm.load(address(target), 0);
    vm.store(address(target), 0, bytes32(uint256(42)));
    bytes32 afterValue = vm.load(address(target), 0);
    assertTrue(afterValue != beforeValue);""",
        [
            "Determine the storage slot carefully.",
            "vm.load reads the raw 32-byte word.",
            "vm.store overwrites a raw storage word in the test environment.",
            "Use storage layout knowledge to decode the word.",
        ],
        audit="This is extremely useful for reproducing slot-sensitive bugs, but a PoC should explain how the real attacker reaches the state rather than pretending vm.store is an attacker primitive.",
        gotchas="vm.store is a test-environment power tool, not something an external user can call on a real deployed contract.",
    )
    
    add(
        "vm-etch", ["etch", "vm.etch", "replace-code"], "FOUNDRY CHEATCODES",
        "Replace an address's runtime bytecode in the test environment.",
        "Swap the machine installed at an address in the sandbox.",
        """vm.etch(target, runtimeCode);""",
        """bytes memory fakeCode = hex"6000";
    vm.etch(address(target), fakeCode);""",
        [
            "Prepare bytecode bytes.",
            "Choose the address to modify.",
            "Call vm.etch(address, code).",
            "Test behavior under the changed code.",
        ],
        audit="Useful for simulating hostile or unusual dependencies; it is a testing primitive, not an ordinary mainnet exploit.",
    )
    
    add(
        "vm-fork", ["createSelectFork", "selectFork", "rollFork"], "FOUNDRY CHEATCODES",
        "Create and control local chain forks during tests.",
        "Choose which copied chain universe the test is currently inside.",
        """uint256 forkId = vm.createFork(rpcUrl);
    vm.selectFork(forkId);
    vm.rollFork(forkId, blockNumber);""",
        """uint256 forkId = vm.createFork(vm.envString("RPC_URL"), 18000000);
    vm.selectFork(forkId);""",
        [
            "Create a fork from an RPC endpoint.",
            "Keep the returned fork identifier when using multiple forks.",
            "Select the fork before interacting with it.",
            "Pin or roll the block when the test requires a deterministic state.",
        ],
    )
    
    add(
        "vm-env", ["env", "envUint", "envAddress", "environment-variables"], "FOUNDRY CHEATCODES",
        "Read environment variables from a test or script.",
        "Read configuration from the machine instead of hard-coding secrets or endpoints.",
        """string memory rpc = vm.envString("RPC_URL");
    uint256 amount = vm.envUint("AMOUNT");
    address owner = vm.envAddress("OWNER");""",
        """string memory rpc = vm.envString("RPC_URL");
    address whale = vm.envAddress("WHALE");""",
        [
            "Set the variable in your shell or .env workflow.",
            "Read it with the type-specific vm.env... helper.",
            "Keep secrets out of source code and commits.",
        ],
        gotchas="Environment variables can affect reproducibility. Document required variables clearly.",
    )
    
    add(
        "script", ["scripts", "forge-script", "solidity-script"], "FOUNDRY SCRIPTING",
        "A Foundry script is Solidity code that automates deployment or on-chain interaction.",
        "A test runs experiments in a lab; a script performs a real sequence of actions against the selected network when broadcast.",
        """import {Script} from "forge-std/Script.sol";
    
    contract Deploy is Script {
        function run() external {
            vm.startBroadcast();
            ...
            vm.stopBroadcast();
        }
    }""",
        """// script/Deploy.s.sol
    pragma solidity ^0.8.20;
    
    import {Script} from "forge-std/Script.sol";
    import {MyToken} from "../src/MyToken.sol";
    
    contract Deploy is Script {
        function run() external returns (MyToken token) {
            vm.startBroadcast();
            token = new MyToken();
            vm.stopBroadcast();
        }
    }""",
        [
            "Put deployment/interaction automation under script/ and commonly use .s.sol.",
            "Import forge-std/Script.sol and inherit Script.",
            "Expose a run() entry point.",
            "Wrap intended real transactions in vm.startBroadcast() and vm.stopBroadcast().",
            "Run with forge script script/Deploy.s.sol plus the network/broadcast options appropriate to the task.",
        ],
        audit="For audit labs, scripts are useful for setting up repeatable deployment and interaction flows, but broadcasting must be an explicit choice.",
        gotchas="A script is not a test. A broadcast-enabled script can send real transactions to the selected network.",
    )
    
    add(
        "script-structure", ["script-file", "run-function", "broadcast-script"], "FOUNDRY SCRIPTING",
        "The basic shape of a deployment or interaction script.",
        "Configuration -> prepare -> broadcast -> act -> finish.",
        """contract MyScript is Script {
        function run() external {
            vm.startBroadcast();
            ...
            vm.stopBroadcast();
        }
    }""",
        """contract Interact is Script {
        function run() external {
            uint256 key = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(key);
    
            Target target = Target(vm.envAddress("TARGET"));
            target.setValue(7);
    
            vm.stopBroadcast();
        }
    }""",
        [
            "Load configuration.",
            "Start broadcasting with the intended signer context.",
            "Deploy or interact.",
            "Stop broadcasting.",
            "Return addresses or values you need for the next step.",
        ],
    )
    
    add(
        "script-broadcast", ["startBroadcast", "stopBroadcast", "broadcast"], "FOUNDRY SCRIPTING",
        "Control which script operations become broadcast transactions.",
        "Flip the switch: these actions are intended to be sent, then flip it back off.",
        """vm.startBroadcast();
    ...
    vm.stopBroadcast();""",
        """vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
    MyToken token = new MyToken();
    token.transfer(vm.envAddress("TREASURY"), 1000);
    vm.stopBroadcast();""",
        [
            "Select the signer/account context.",
            "Start broadcasting.",
            "Perform the intended deployment/calls.",
            "Stop broadcasting.",
        ],
        gotchas="Never treat a broadcast block as a harmless dry run. Network, signer, gas, and target addresses matter.",
    )
    
    add(
        "script-env", ["script environment", "script-config"], "FOUNDRY SCRIPTING",
        "Scripts commonly read RPCs, private keys, addresses, and other settings from environment variables.",
        "Keep machine-specific configuration outside source code.",
        """uint256 privateKey = vm.envUint("PRIVATE_KEY");
    address target = vm.envAddress("TARGET");
    string memory rpc = vm.envString("RPC_URL");""",
        """uint256 key = vm.envUint("PRIVATE_KEY");
    address owner = vm.envAddress("OWNER");
    address target = vm.envAddress("TARGET");
    
    vm.startBroadcast(key);
    Target(target).setOwner(owner);
    vm.stopBroadcast();""",
        [
            "Name each required variable.",
            "Read it with the matching vm.env helper.",
            "Fail clearly when required configuration is missing or malformed.",
            "Keep actual secrets outside git.",
        ],
    )
    
    add(
        "script-deploy", ["deployment-script", "deploy-script"], "FOUNDRY SCRIPTING",
        "Use a script to deploy a contract and expose the deployed address for later steps.",
        "A factory checklist for creating the contract in a repeatable way.",
        """vm.startBroadcast();
    Target target = new Target(args);
    vm.stopBroadcast();""",
        """contract DeployTarget is Script {
        function run() external returns (address) {
            vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            Target target = new Target(vm.envAddress("OWNER"));
            vm.stopBroadcast();
            return address(target);
        }
    }""",
        [
            "Load constructor inputs/configuration.",
            "Broadcast the constructor deployment.",
            "Capture the resulting address/reference.",
            "Record that address for subsequent calls or verification.",
        ],
    )
    
    add(
        "script-interaction", ["script-call", "script-admin", "interaction-script"], "FOUNDRY SCRIPTING",
        "Use a script after deployment to call real contract functions in a repeatable order.",
        "A checklist for pressing several buttons on the deployed protocol.",
        """Target target = Target(vm.envAddress("TARGET"));
    vm.startBroadcast();
    target.setValue(7);
    vm.stopBroadcast();""",
        """Target target = Target(vm.envAddress("TARGET"));
    
    vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
    target.configure(vm.envAddress("ORACLE"), 1 days);
    target.pause();
    vm.stopBroadcast();""",
        [
            "Load the deployed target address.",
            "Start broadcasting with the intended signer.",
            "Call functions in the required sequence.",
            "Stop broadcasting and inspect the receipts.",
        ],
    )
    
    add(
        "poc", ["poc-test", "proof-of-concept", "exploit-poc"], "AUDIT POC",
        "A PoC is a small reproducible program that demonstrates a concrete security claim.",
        "A burglary demonstration: show the exact door, the exact trick, and the measurable result.",
        """function testPoC() public {
        // setup
        // attacker action
        // prove impact
    }""",
        """function testPoC_reentrancyDrains() public {
        // 1. Set up attacker funds/state.
        // 2. Give the victim contract the required ETH.
        // 3. Trigger the vulnerable entry point.
        // 4. Re-enter during the external call.
        // 5. Assert attacker profit or invariant break.
    }""",
        [
            "State the security property in one sentence.",
            "Set up only the state an attacker can realistically reach.",
            "Perform the attacker-controlled sequence.",
            "Capture the before/after state, balance, role, or other impact.",
            "Assert the concrete violation.",
            "Keep the PoC deterministic and easy for another reviewer to replay.",
        ],
        audit="A strong PoC separates attacker actions from test-only setup such as vm.store or vm.deal and explains every privileged test primitive used.",
    )
    
    add(
        "poc-template", ["poc-format", "poc-skeleton", "audit-poc"], "AUDIT POC",
        "A reusable structure for writing audit PoCs.",
        "Claim -> setup -> trigger -> exploit path -> impact proof.",
        """function testPoC_<claim>() public {
        // GIVEN
        // WHEN
        // THEN
    }""",
        """function testPoC_unauthorizedWithdraw() public {
        // GIVEN: only owner should withdraw
        uint256 before = attacker.balance;
    
        // WHEN: attacker reaches the sensitive path
        vm.prank(attacker);
        target.withdrawAll();
    
        // THEN: unauthorized value moved
        assertGt(attacker.balance, before);
    }""",
        [
            "Name the test after the concrete security claim.",
            "Write GIVEN as attacker-reachable setup.",
            "Write WHEN as the exact exploit sequence.",
            "Write THEN as measurable impact.",
            "Avoid unrelated helpers that make the exploit harder to audit.",
        ],
    )
    
    add(
        "poc-reentrancy", ["reentrancy-poc", "reentry-poc"], "AUDIT POC",
        "A PoC for proving an external callback can re-enter a vulnerable state transition.",
        "The attacker calls the vault, the vault calls the attacker, and the attacker calls the vault again before the ledger is safe.",
        """receive() external payable {
        if (...) target.withdraw();
    }""",
        """contract Attacker {
        Target target;
    
        constructor(Target _target) {
            target = _target;
        }
    
        receive() external payable {
            if (address(target).balance > 0) {
                target.withdraw();
            }
        }
    
        function attack() external {
            target.deposit{value: 1 ether}();
            target.withdraw();
        }
    }""",
        [
            "Identify the victim function that makes an external call.",
            "Create an attacker contract with a callback.",
            "Make the callback call back into the victim.",
            "Track recursion/termination so the test remains deterministic.",
            "Assert stolen value or a broken accounting invariant.",
        ],
        audit="The key evidence is state/control returning to the victim before the original operation has safely completed.",
    )
    
    add(
        "poc-access-control", ["authorization-poc", "access-control-poc"], "AUDIT POC",
        "A PoC proving an unauthorized actor can reach a privileged action.",
        "Try the locked door with the wrong key, then prove the door actually opened.",
        """vm.prank(attacker);
    target.adminAction();""",
        """uint256 before = target.sensitiveValue();
    
    vm.prank(attacker);
    target.adminAction();
    
    assertTrue(target.sensitiveValue() != before);""",
        [
            "Identify the privileged state change.",
            "Choose an attacker address with no intended privilege.",
            "Call the exact reachable entry point.",
            "Prove the privileged state changed.",
        ],
    )
    
    add(
        "poc-accounting", ["accounting-poc", "balance-poc", "asset-accounting"], "AUDIT POC",
        "A PoC showing recorded balances no longer match actual assets or allowed conservation rules.",
        "Compare the paper ledger to the cash in the drawer.",
        """before = address(target).balance;
    ...
    after = address(target).balance;""",
        """uint256 recordedBefore = target.totalLiabilities();
    uint256 assetsBefore = address(target).balance;
    
    vm.prank(attacker);
    target.exploit();
    
    assertTrue(
        target.totalLiabilities() > address(target).balance
    );""",
        [
            "Write the accounting invariant in plain language.",
            "Measure both sides before the attack.",
            "Execute only attacker-reachable actions.",
            "Measure both sides after the attack.",
            "Assert the mismatch or unauthorized gain.",
        ],
    )
    
    add(
        "poc-accessible-state", ["realistic-poc", "attacker-reachable"], "AUDIT POC",
        "Separate realistic attacker actions from test-only powers used to arrange the initial state.",
        "The tester may reset the stage before the play, but the attacker should not get backstage keys during the play.",
        """// TEST SETUP ONLY
    vm.deal(victim, 100 ether);
    
    // ATTACKER ACTION
    vm.startPrank(attacker);
    target.withdraw(...);
    vm.stopPrank();""",
        """// Stage the protocol into a state a real attacker could plausibly encounter.
    vm.deal(address(target), 10 ether);
    
    // From here, use only the attacker's normal capabilities.
    vm.startPrank(attacker);
    target.withdraw(1 ether);
    vm.stopPrank();
    
    assertGt(attacker.balance, 0);""",
        [
            "Mark every vm.* operation used only to arrange starting state.",
            "Do not use vm.store, vm.etch, or privileged identities as part of the attacker path unless the real bug grants that power.",
            "Make the exploit sequence use only public/externally reachable behavior.",
            "Document why each setup step is realistic.",
        ],
        audit="This is one of the most important habits for audit PoCs: prove exploitability without accidentally giving the attacker supernatural test powers.",
    )
    
    add(
        "poc-dos", ["dos-poc", "denial-of-service-poc", "griefing-poc"], "AUDIT POC",
        "A PoC for a state or gas condition that blocks a required function from completing.",
        "Fill the doorway with something until the legitimate user cannot get through.",
        """// trigger the blocking state
    // attempt the required action
    // prove it consistently reverts or becomes unusable""",
        """function testPoC_withdrawBlocked() public {
        // attacker reaches the griefing condition
        vm.prank(attacker);
        target.grief();
    
        // required user path now fails
        vm.expectRevert();
        vm.prank(user);
        target.withdraw();
    }""",
        [
            "Identify the function that must remain callable.",
            "Create the blocker using attacker-reachable actions.",
            "Attempt the legitimate action.",
            "Prove the block is reproducible and materially affects the protocol.",
        ],
    )
    
    add(
        "poc-oracle", ["oracle-poc", "price-poc"], "AUDIT POC",
        "A PoC for an unsafe price/oracle assumption.",
        "Change the information source the protocol trusts and see whether money follows the bad number.",
        """// attacker influences or exploits the oracle assumption
    // trigger the priced action
    // prove value moves incorrectly""",
        """function testPoC_badPrice() public {
        // Use a fork or protocol-supported oracle manipulation path.
        // Trigger the victim calculation.
        uint256 received = ...;
        assertGt(received, fairAmount);
    }""",
        [
            "Identify the exact oracle assumption.",
            "Choose a realistic way the attacker can influence or exploit it.",
            "Trigger the consumer function.",
            "Compare the resulting value with the intended pricing rule.",
        ],
        gotchas="Do not fake an oracle by vm.store unless the vulnerability itself is a storage-integrity issue; on a realistic PoC, model the real integration path.",
    )
    
    add(
        "poc-signature", ["signature-poc", "replay-poc"], "AUDIT POC",
        "A PoC for forged, replayed, wrongly scoped, or incorrectly validated signed authorization.",
        "Copy a signed permission into the wrong context and see whether it is still accepted.",
        """sign -> submit -> replay/change-domain -> prove acceptance""",
        """function testPoC_signatureReplay() public {
        // Prepare a valid signature once.
        // Submit it successfully.
        // Re-submit the same signature in the context that should reject it.
        vm.prank(attacker);
        target.execute(signature, payload);
    
        vm.prank(attacker);
        target.execute(signature, payload);
    
        // Assert the second use was accepted when it should not be.
    }""",
        [
            "Define exactly what a valid signature is supposed to authorize.",
            "Create a valid signed payload.",
            "Use it once.",
            "Replay or alter only the context that should be bound by the design.",
            "Assert the invalid second use succeeds.",
        ],
    )
    
    add(
        "poc-upgrade", ["upgrade-poc", "proxy-poc", "initialization-poc"], "AUDIT POC",
        "A PoC for an upgrade, proxy, initializer, or storage-layout security failure.",
        "The building manager changes the machine behind the front desk without the right key, or the new machine reads the wrong drawers.",
        """proxy -> implementation -> upgrade/init -> impact""",
        """function testPoC_unauthorizedUpgrade() public {
        address beforeImpl = proxy.implementation();
    
        vm.prank(attacker);
        proxy.upgradeTo(attackerImplementation);
    
        assertTrue(proxy.implementation() != beforeImpl);
    }""",
        [
            "Identify the privileged upgrade/initialization boundary.",
            "Choose an attacker with only normal public permissions.",
            "Reach the upgrade or initialization path.",
            "Prove implementation, storage, or control changed.",
        ],
        audit="Check upgrade authority, initializer replay, delegatecall storage ownership, selector collisions, and storage compatibility.",
    )
    
    add(
        "poc-storage", ["storage-poc", "slot-poc", "storage-collision-poc"], "AUDIT POC",
        "A PoC for a storage-layout or slot-collision consequence.",
        "Two machines believe drawer 3 contains different things, so one machine overwrites the other's ledger.",
        """slot = keccak256(abi.encode(key, mappingSlot));""",
        """function testPoC_storageCollision() public {
        // Trigger the real proxy/upgrade path that causes layout overlap.
        // Then prove the victim variable changed unexpectedly.
        uint256 beforeValue = target.ownerSetting();
        triggerUpgradePath();
        assertTrue(target.ownerSetting() != beforeValue);
    }""",
        [
            "Map the storage layout of each relevant contract.",
            "Identify the overlapping slot or incompatible packing.",
            "Trigger the real path that causes the layouts to coexist.",
            "Prove the wrong variable changed.",
        ],
    )
    
    add(
        "poc-token", ["erc20-poc", "erc721-poc", "token-integration-poc"], "AUDIT POC",
        "A PoC for incorrect token-standard assumptions or accounting around ERC20/ERC721-like integrations.",
        "The protocol assumes the cashier always behaves exactly like its manual, but the token can behave differently.",
        """transfer / transferFrom / safeTransferFrom
    check return / callback / allowance / decimals""",
        """function testPoC_tokenAssumption() public {
        // Use a realistic token implementation or a forked token.
        // Trigger the victim's transfer/accounting path.
        // Assert the protocol's recorded result matches the actual token state.
    }""",
        [
            "Identify which standard behavior the protocol assumes.",
            "Check return values, callbacks, decimals, approvals, and receiver behavior as relevant.",
            "Use a realistic token or forked deployment.",
            "Assert the mismatch in balances, ownership, or accounting.",
        ],
    )
    
    add(
        "poc-cross-contract", ["cross-contract-poc", "integration-poc", "callback-poc"], "AUDIT POC",
        "A PoC for a bug that appears only when two or more contracts interact.",
        "The broken part is not one machine; it is the handoff between machines.",
        """A -> B -> callback/response -> A""",
        """function testPoC_callbackReachesSensitiveState() public {
        // Arrange integration state.
        // Trigger A.
        // B calls back into A.
        // Prove A's protected state changed unexpectedly.
    }""",
        [
            "Draw the call chain.",
            "Identify where control crosses the contract boundary.",
            "Choose the callback or external response that creates the unexpected path.",
            "Assert the final state/asset change.",
        ],
    )
    
    add(
        "forge-test-cli", ["forge test commands", "test-cli"], "FOUNDRY CLI",
        "Core forge test commands for running, filtering, tracing, fuzzing, and measuring tests.",
        "Start broad, then zoom into the failing experiment.",
        """forge test
    forge test --match-test testName
    forge test --match-contract ContractName
    forge test -vvvv
    forge test --gas-report
    forge coverage""",
        """forge test --match-test testPoC -vvvv
    forge test --match-contract BankTest
    forge test --gas-report
    forge coverage""",
        [
            "Run forge test for the whole suite.",
            "Use --match-test or --match-contract to focus.",
            "Increase -v levels to inspect traces.",
            "Use coverage/gas options when evaluating test depth or cost.",
        ],
    )
    
    add(
        "forge-script-cli", ["forge script commands", "script-cli"], "FOUNDRY CLI",
        "Core forge script commands and flags for simulating or broadcasting Solidity scripts.",
        "Choose the script, choose the network, then decide whether to broadcast.",
        """forge script script/Deploy.s.sol
    forge script script/Deploy.s.sol --rpc-url $RPC_URL
    forge script script/Deploy.s.sol --broadcast --rpc-url $RPC_URL""",
        """forge script script/Deploy.s.sol --rpc-url $RPC_URL
    forge script script/Deploy.s.sol --broadcast --rpc-url $RPC_URL""",
        [
            "Select the .s.sol script file.",
            "Choose the RPC/network explicitly.",
            "Run without --broadcast when you only want script execution/simulation.",
            "Add --broadcast only when you intend to send the transactions.",
        ],
    )
    
    add(
        "forge-cheatcodes-map", ["cheatcode-map", "vm-cheatsheet", "cheatcodes"], "FOUNDRY CHEATCODES",
        "A quick map of the Foundry cheatcodes you will repeatedly use in tests and PoCs.",
        "Cheatcodes are test-lab controls: actor, money, time, blocks, reverts, logs, storage, forks, and state snapshots.",
        """ACTOR: prank / startPrank / stopPrank / deal
    TIME: warp / roll
    ERRORS: expectRevert
    EVENTS: expectEmit / recordLogs / getRecordedLogs
    STATE: load / store / snapshotState / revertTo / etch
    FORKS: createFork / createSelectFork / selectFork / rollFork
    INPUT: assume / bound / makeAddr / env...""",
        """vm.deal(alice, 10 ether);
    vm.prank(alice);
    target.deposit{value: 1 ether}();
    
    vm.warp(block.timestamp + 1 days);
    vm.expectRevert();
    target.withdraw(2 ether);""",
        [
            "Actor control answers: who is calling?",
            "deal answers: how much test ETH does the actor have?",
            "warp/roll answer: what time/block does the test see?",
            "expectRevert/expectEmit answer: what execution result should happen?",
            "load/store/etch/snapshots answer: what controlled state do I need?",
            "fork controls answer: which copied chain state am I testing?",
        ],
        audit="Learn the cheatcodes as testing instruments, then keep exploit execution realistic. A PoC that only succeeds because vm.store or vm.prank gives it impossible privileges is not strong evidence of real exploitability.",
    )
    
    add(
        "test-poc-workflow", ["audit-test-workflow", "write-poc"], "AUDIT WORKFLOW",
        "A practical workflow for turning an audit suspicion into a Foundry test and then a PoC.",
        "Read -> hypothesis -> reproduce -> assert -> minimize -> document.",
        """1. Read the code.
    2. State the property.
    3. Build the smallest test.
    4. Try normal actors.
    5. Add fuzz/forking if needed.
    6. Assert impact.
    7. Minimize the PoC.""",
        """// Hypothesis:
    // "attacker can withdraw more than their recorded balance"
    
    // Reproduce
    function testPoC_overwithdraw() public {
        // setup reachable state
        ...
        // attacker path
        ...
        // impact proof
        assertGt(attackerGain, 0);
    }""",
        [
            "Write the suspected bug in one sentence.",
            "Identify the exact entry point and state variables involved.",
            "Build a minimal deterministic test.",
            "Use realistic actors and calls.",
            "Escalate to fuzzing, invariants, or a fork only when the basic path is insufficient.",
            "Assert a concrete impact or broken invariant.",
            "Keep only the steps needed to reproduce the claim.",
        ],
    )
    
    add(
        "test-cheatsheet", ["test-cheats", "testing-cheatsheet", "forge-test-cheatsheet"], "FOUNDRY TESTING",
        "The compact dictionary for writing Foundry tests: setup, actors, actions, assertions, reverts, fuzzing, invariants, forks, traces, and evidence.",
        "Think: build a safe lab experiment, perform the action, then prove one property.",
        """// test/Bank.t.sol
    pragma solidity ^0.8.20;
    
    import {Test} from "forge-std/Test.sol";
    import {Bank} from "../src/Bank.sol";
    
    contract BankTest is Test {
        Bank bank;
        address alice = makeAddr("alice");
    
        function setUp() public {
            bank = new Bank();
        }
    
        function test_deposit() public {
            vm.deal(alice, 10 ether);
            vm.prank(alice);
            bank.deposit{value: 1 ether}();
    
            assertEq(address(bank).balance, 1 ether);
        }
    }""",
        """UNIT:
    function test_X() public { ... }
    
    FUZZ:
    function testFuzz_X(uint256 x) public { ... }
    
    INVARIANT:
    function invariant_X() public { ... }
    
    REVERT:
    vm.expectRevert(Error.selector);
    target.action();
    
    EVENT:
    vm.expectEmit(true, false, false, true);
    emit Deposit(alice, 1 ether);
    target.deposit{value: 1 ether}();
    
    ACTOR:
    vm.prank(alice);
    vm.startPrank(alice);
    vm.stopPrank();
    
    MONEY:
    vm.deal(alice, 10 ether);
    
    TIME / BLOCK:
    vm.warp(newTimestamp);
    vm.roll(newBlock);
    
    STATE:
    uint256 snap = vm.snapshotState();
    vm.revertTo(snap);
    vm.load(address(target), slot);
    vm.store(address(target), slot, value);
    
    LOGS:
    vm.recordLogs();
    Vm.Log[] memory logs = vm.getRecordedLogs();
    
    FORK:
    vm.createSelectFork(vm.envString("RPC_URL"));""",
        [
            "Put tests under test/ and commonly use a .t.sol suffix.",
            "Import forge-std/Test.sol and inherit Test.",
            "Use setUp() for state every test needs; Foundry runs it before each test.",
            "Use test_ for deterministic tests, testFuzz_ for fuzzed inputs, and invariant_ for state properties checked across sequences.",
            "Create actors with makeAddr(), fund them with vm.deal(), and choose msg.sender with vm.prank() or vm.startPrank().",
            "Arrange state, perform the action, then assert the exact property you care about.",
            "Use vm.expectRevert before an expected failure and vm.expectEmit before checking an event.",
            "Use vm.assume() only for genuinely invalid fuzz inputs; use bound() when you want values inside a range.",
            "Use snapshots, logs, raw storage, and traces when the final state alone does not explain behavior.",
            "Use a fork when real deployed integrations or real chain state are part of the hypothesis.",
            "Run forge test, then narrow with --match-test/--match-contract and raise verbosity with -vv/-vvvv when debugging.",
        ],
        audit="For an audit, turn a suspicious rule into an executable property. A passing test only proves the exact property and path you wrote.",
        gotchas="Do not give the attacker powers in setup that a real attacker does not have. vm.deal/vm.store/vm.etch are lab controls, not normal on-chain attacker capabilities.",
    )
    
    add(
        "script-cheatsheet", ["script-cheats", "scripting-cheatsheet", "forge-script-cheatsheet"], "FOUNDRY SCRIPTING",
        "The compact dictionary for writing Foundry deployment and interaction scripts.",
        "Think: a repeatable checklist that can either simulate actions or deliberately broadcast them.",
        """// script/Deploy.s.sol
    pragma solidity ^0.8.20;
    
    import {Script} from "forge-std/Script.sol";
    import {MyToken} from "../src/MyToken.sol";
    
    contract Deploy is Script {
        function run() external returns (MyToken token) {
            address owner = vm.envAddress("OWNER");
    
            vm.startBroadcast();
            token = new MyToken(owner);
            vm.stopBroadcast();
    
            return token;
        }
    }""",
        """BASIC SHAPE:
    contract MyScript is Script {
        function run() external {
            // load config
            // prepare
            // broadcast intended transactions
            // finish
        }
    }
    
    DEPLOY:
    vm.startBroadcast();
    Target target = new Target(arg1);
    vm.stopBroadcast();
    
    INTERACT:
    Target target = Target(vm.envAddress("TARGET"));
    vm.startBroadcast();
    target.setValue(7);
    vm.stopBroadcast();
    
    SIGNER:
    vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
    
    ENV:
    vm.envString("RPC_URL");
    vm.envAddress("TARGET");
    vm.envUint("PRIVATE_KEY");""",
        [
            "Create the file in script/ and commonly name it Something.s.sol.",
            "Import Script from forge-std and inherit Script.",
            "Put automation in run().",
            "Read addresses, RPCs, keys, and other configuration from environment variables instead of hard-coding secrets.",
            "Use vm.startBroadcast(...) to mark intended transactions and vm.stopBroadcast() to end that broadcast section.",
            "Deploy with new Contract(args) or interact with an existing address cast to a contract/interface type.",
            "Run without --broadcast when you are inspecting or simulating the flow; add --broadcast only when you deliberately want transactions sent to the selected network.",
            "Keep the signer, target, order of operations, and expected post-state obvious to the next reviewer.",
        ],
        audit="Scripts are useful for repeatable deployment and integration flows. Keep it obvious which steps are simulation-only and which would become real transactions.",
        gotchas="Broadcasting is real network activity. Verify RPC, chain, signer, target, constructor arguments, and network before using --broadcast.",
    )
    
    add(
        "poc-cheatsheet", ["poc-cheats", "poc-dictionary", "audit-poc-cheatsheet"], "AUDIT POC",
        "The compact dictionary for writing a security proof-of-concept in Foundry.",
        "Think: make one claim, reproduce one attack path, and measure one concrete impact.",
        """function testPoC_reentrancy() public {
        // GIVEN: attacker can reach a funded target
        vm.deal(address(target), 10 ether);
    
        // WHEN: attacker performs the malicious sequence
        attacker.attack();
    
        // THEN: prove the security property was broken
        assertGt(attacker.balance, 1 ether);
    }""",
        """POC SHAPE:
    CLAIM  -> what security property is supposed to hold?
    GIVEN  -> attacker-reachable starting state
    WHEN   -> exact attacker sequence
    THEN   -> measurable impact
    EVIDENCE -> balances / storage / events / traces
    REPLAY -> deterministic, minimal reproduction
    
    COMMON CLAIMS:
    access control
    reentrancy
    accounting
    DoS / griefing
    oracle assumptions
    signature replay
    proxy / upgrade / storage
    token integration
    cross-contract callbacks""",
        [
            "Write the security claim in one sentence before coding.",
            "Identify the smallest victim function and state needed to test it.",
            "Arrange starting state with test-only powers when necessary, and clearly separate that setup from the attacker path.",
            "Run the attack path with a normal actor, interface, or attacker contract.",
            "Measure before/after balances, storage values, ownership, supply, shares, or another concrete impact.",
            "Assert the violated invariant or unauthorized gain. Do not stop at 'the call succeeded'.",
            "Use a callback contract for reentrancy, a wrong actor for access control, realistic token/oracle state for integration bugs, and a fork when real chain state matters.",
            "Minimize the final PoC so the exploit path is obvious and reproducible.",
        ],
        audit="A PoC is evidence, not a verdict. Strong PoCs prove impact with attacker-reachable execution and identify which setup operations were only laboratory controls.",
        gotchas="Do not use vm.prank(owner), vm.store(), vm.etch(), or other privileged test controls as part of the exploit unless the real vulnerability gives the attacker that capability.",
    )
    
    add(
        "vm-expect-call", ["expectCall", "expected-call", "call-expectation"], "FOUNDRY CHEATCODES",
        "Check that the target makes an expected external call with expected calldata or value.",
        "Put a 'this phone call must happen' rule on the test before the transaction.",
        """vm.expectCall(
        address(token),
        abi.encodeCall(IERC20.transfer, (treasury, amount))
    );""",
        """vm.expectCall(
        address(token),
        abi.encodeCall(IERC20.transfer, (treasury, 100))
    );
    vault.sweep(treasury, 100);""",
        [
            "Choose the external contract whose call must happen.",
            "Encode the expected calldata.",
            "Set the expectation before the action.",
            "Run the action and let Foundry fail the test when the call is missing or mismatched.",
        ],
        audit="Useful for proving that protocol actions actually route calls and value through the dependency you think they do.",
    )
    
    add(
        "vm-mockcall", ["mockCall", "mock-call", "mocked-dependency"], "FOUNDRY CHEATCODES",
        "Return controlled data for a selected external call in the test environment.",
        "Replace a dependency's answer in your lab without changing the real contract.",
        """vm.mockCall(
        address(feed),
        abi.encodeWithSignature("latestAnswer()"),
        abi.encode(int256(2000))
    );""",
        """vm.mockCall(
        address(feed),
        abi.encodeWithSignature("latestAnswer()"),
        abi.encode(int256(2000))
    );
    
    int256 price = feed.latestAnswer();
    assertEq(price, 2000);""",
        [
            "Choose the external dependency.",
            "Match the call data you want to intercept.",
            "Provide the bytes that should be returned.",
            "Execute the path that calls the dependency.",
            "Assert the protocol behavior under the mocked response.",
        ],
        audit="Useful for isolating an oracle or integration assumption while developing a hypothesis; replace the mock with a realistic fork/integration path for exploit proof.",
        gotchas="A mock proves your code responds to the mocked behavior. It does not prove that a real attacker can make the real dependency return that value.",
    )
    
    add(
        "vm-hoax", ["hoax", "startHoax"], "FOUNDRY CHEATCODES",
        "A forge-std helper that combines funding and caller impersonation for a test actor.",
        "Give the actor ETH and put their caller-ID on in one helper.",
        """hoax(alice, 10 ether);
    target.deposit{value: 1 ether}();""",
        """hoax(alice, 10 ether);
    target.deposit{value: 1 ether}();
    
    stopHoax();""",
        [
            "Choose the test actor.",
            "hoax gives the actor test ETH and starts the prank/caller context.",
            "Perform the target calls.",
            "Use stopHoax() when the persistent caller context is finished.",
        ],
        gotchas="This is a Foundry testing helper, not a Solidity language feature or a real permission-escalation primitive.",
    )
    
    
    
    # ---------------------------------------------------------------------------
    # LEARNING-FIRST EXTENSIONS
    # ---------------------------------------------------------------------------
    
    add(
        "for", ["for-loop", "counted-loop"], "CONTROL FLOW",
        "A counted loop with an initializer, a condition, an update step, and a body.",
        "Start at 0, check whether you may continue, do the work, then move to the next item.",
        """for (uint256 i = 0; i < users.length; i++) {
        // users[i]
    }""",
        """contract ForExample {
        uint256[] public numbers;
    
        function addNumbers(uint256 count) external {
            for (uint256 i = 0; i < count; i++) {
                numbers.push(i);
            }
        }
    
        function sum() external view returns (uint256 total) {
            for (uint256 i = 0; i < numbers.length; i++) {
                total += numbers[i];
            }
        }
    }""",
        [
            "Initializer runs once: uint256 i = 0.",
            "Condition is checked before each iteration: i < numbers.length.",
            "Body runs when the condition is true.",
            "Post step runs after the body: i++.",
            "When the condition becomes false, the loop ends.",
        ],
        audit="A loop bounded by attacker-controlled data can become a gas or denial-of-service problem.",
        gotchas="Solidity has no native foreach keyword; 'for each' is normally an indexed for loop.",
    )
    
    add(
        "while", ["while-loop"], "CONTROL FLOW",
        "A loop that checks its condition before every pass.",
        "Ask the guard first: should I keep going?",
        """while (i < limit) {
        i++;
    }""",
        """contract WhileExample {
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
        [
            "Check the condition.",
            "Run the body when true.",
            "Change the state used by the condition.",
            "Check again.",
        ],
        audit="An unreachable or attacker-controlled exit condition can make a while loop consume all available gas.",
    )
    
    add(
        "do-while", ["do while", "do-while-loop"], "CONTROL FLOW",
        "A loop that executes its body once before checking whether it should repeat.",
        "Do it once, then ask whether another round is needed.",
        """do {
        i++;
    } while (i < limit);""",
        """contract DoWhileExample {
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
        [
            "Enter the body immediately.",
            "Run the body once.",
            "Evaluate the while condition.",
            "Repeat only when the condition is true.",
        ],
        gotchas="With limit == 0, the body still executes once. That is the key difference from while.",
    )
    
    add(
        "for-each", ["foreach", "for-every", "iterate-array"], "CONTROL FLOW",
        "Solidity has no foreach keyword. The usual pattern is for with an index.",
        "For every item, use its array index to fetch that item.",
        """for (uint256 i = 0; i < users.length; i++) {
        address user = users[i];
    }""",
        """contract ForEachExample {
        address[] public users;
        mapping(address => uint256) public points;
    
        function reward(uint256 amount) external {
            for (uint256 i = 0; i < users.length; i++) {
                points[users[i]] += amount;
            }
        }
    }""",
        [
            "Keep the iterable items in an array.",
            "Start at index zero.",
            "Stop at users.length.",
            "Read the current item with users[i].",
            "Perform the same action for that item.",
        ],
        audit="Large arrays make this pattern a common gas and DoS review point.",
        gotchas="Mappings are not enumerable: they do not expose a list of keys you can loop over.",
    )
    
    add(
        "loop-comparison", ["for-vs-while", "loop-compare"], "CONTROL FLOW",
        "A side-by-side comparison of for, while, and do-while.",
        "for = counted checklist; while = condition first; do-while = guaranteed first pass.",
        """for (init; condition; update) { ... }
    
    while (condition) { ... }
    
    do { ... } while (condition);""",
        """contract LoopComparison {
        function useFor(uint256[] memory xs)
            external
            pure
            returns (uint256 total)
        {
            for (uint256 i = 0; i < xs.length; i++) {
                total += xs[i];
            }
        }
    
        function useWhile(uint256 target)
            external
            pure
            returns (uint256 i)
        {
            while (i < target) {
                i++;
            }
        }
    
        function useDoWhile(uint256 target)
            external
            pure
            returns (uint256 i)
        {
            do {
                i++;
            } while (i < target);
        }
    }""",
        [
            "Use for when an index or count naturally controls the loop.",
            "Use while when the condition is the main idea and the number of passes is less direct.",
            "Use do-while when one pass must happen before the first condition check.",
            "For auditing, always identify how the loop eventually stops and whether an attacker controls its size.",
        ],
    )
    
    add(
        "globals", ["global-variables", "global-vars", "special-variables"], "GLOBAL VALUES",
        "Special values and functions Solidity exposes without declaring them yourself.",
        "Every call arrives with context: who called, what ETH arrived, what bytes arrived, and which block/transaction is executing.",
        """msg.sender
    msg.value
    msg.data
    msg.sig
    block.timestamp
    block.number
    block.chainid
    tx.origin
    tx.gasprice
    gasleft()
    address(this).balance""",
        """contract GlobalsExample {
        function inspect() external payable returns (
            address sender,
            uint256 value,
            bytes memory data,
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
        [
            "msg.sender = immediate caller of this message call.",
            "msg.value = wei attached to this message call.",
            "msg.data = complete calldata bytes.",
            "msg.sig = first four bytes of msg.data, normally the function selector.",
            "block.timestamp and block.number describe the current block context.",
            "block.chainid identifies the chain.",
            "tx.origin is the original transaction sender, not necessarily the immediate caller.",
            "gasleft() reports remaining gas.",
            "address(this).balance is the contract's current native-coin balance. address(this).amount is not a Solidity global.",
        ],
        audit="Treat msg.sender, tx.origin, msg.value, and block values as call context, not persistent state.",
    )
    
    add(
        "globals-map", ["global-variable-map", "global-map"], "GLOBAL VALUES",
        "A table you can scan when a contract uses a built-in context value.",
        "Quick-reference card for the built-in context attached to an execution.",
        """NAME                 WHAT IT MEANS / WHEN YOU USE IT
    msg.sender             immediate caller
    msg.value              wei attached to this call
    msg.data               complete raw calldata
    msg.sig                first four calldata bytes
    block.timestamp        current block timestamp
    block.number           current block number
    block.chainid           current chain ID
    block.coinbase          current block beneficiary/address
    block.gaslimit          current block gas limit
    block.basefee           current base fee
    block.prevrandao        current beacon-derived value
    block.blobbasefee       current blob base fee (Cancun-era)
    tx.origin               original transaction sender
    tx.gasprice             transaction gas price
    gasleft()               gas remaining
    blobhash(index)         version-dependent blob hash helper
    blockhash(blockNumber)  recent block hash helper
    address(this).balance  current contract native-coin balance""",
        """contract GlobalMapExample {
        function payment()
            external
            payable
            returns (address who, uint256 sent, uint256 held)
        {
            return (msg.sender, msg.value, address(this).balance);
        }
    }""",
        [
            "msg.* describes the current message/call frame.",
            "block.* describes the current block.",
            "tx.* describes transaction-wide context.",
            "address(this).balance asks how much native currency this contract holds now.",
            "Always ask whether you need the current call value or the contract's total balance.",
        ],
    )
    
    add(
        "global-functions", ["global-functions-map", "builtin-functions", "special-functions"], "GLOBAL VALUES",
        "Built-in functions and helpers Solidity makes available without declaring them in your contract.",
        "Global variables give you context; global functions let you ask the EVM/Solidity to perform a built-in operation.",
        """keccak256(data)
    sha256(data)
    ripemd160(data)
    ecrecover(hash, v, r, s)
    addmod(x, y, k)
    mulmod(x, y, k)
    blockhash(blockNumber)
    gasleft()
    type(T).max
    type(IContract).interfaceId
    abi.encode(...)
    abi.decode(...)
    abi.encodeCall(...)
    abi.encodeWithSelector(...)
    abi.encodeWithSignature(...)""",
        """contract GlobalFunctionsLab {
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
        [
            "keccak256 hashes bytes and is commonly used for IDs, commitments, and storage-slot formulas.",
            "abi.encode and the related helpers turn typed values into bytes.",
            "abi.decode turns ABI-formatted bytes back into typed values.",
            "type(T) exposes compile-time type information and members such as max for integers.",
            "gasleft() reports the remaining gas at the point where it is evaluated.",
            "blockhash(n) can retrieve a recent block hash subject to the EVM's availability rules.",
        ],
        audit="Hashing and ABI encoding are security primitives. A small change in what is encoded can change an ID, signature, selector, or storage location.",
    )
    
    add(
        "mapping-types", ["mapping-type", "mapping-table", "mapping-reference"], "TYPES",
        "A mapping type has a key type on the left and a value type on the right.",
        "The key is the label you put inside []; the value is what the lookup gives you.",
        """KEY TYPE        VALID?   WHAT GOES INSIDE []        EXAMPLE
    address         YES      an address                 balances[user]
    uint256         YES      a uint256                  balances[userId]
    bytes32         YES      a bytes32                  votes[id]
    bool            YES      true / false               flags[active]
    enum            YES      an enum member             status[user]
    string          NO       dynamic text               not valid as key
    bytes           NO       dynamic bytes              not valid as key
    struct          NO       struct value               not valid as key
    mapping         NO       another mapping            not valid as key
    dynamic array   NO       T[] value                  not valid as key
    
    SYNTAX
    mapping(KeyType => ValueType) name;
    
    MEANING
    KeyType   = what you put inside []
    ValueType = what the lookup stores/returns""",
        """contract MappingTypesExample {
        mapping(address => uint256) public balances;
    
        mapping(address => mapping(address => uint256))
            public allowance;
    
        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }
    
        function approve(address spender, uint256 amount) external {
            allowance[msg.sender][spender] = amount;
        }
    
        function read() external view returns (uint256) {
            return balances[msg.sender];
        }
    }""",
        [
            "For mapping(address => uint256), the thing inside [] must be an address value.",
            "The lookup result is a uint256 value.",
            "In balances[msg.sender] = 100, msg.sender is the key and 100 is the value being stored.",
            "A nested mapping uses another lookup: allowance[owner][spender].",
            "Mappings are storage-only and do not give you an enumerable list of keys.",
        ],
        audit="Remember that a mapping can return a default value even when you never explicitly stored that key.",
    )
    
    add(
        "struct-types", ["struct-type", "struct-table", "struct-fields"], "TYPES",
        "A struct groups named fields; each field has a type and an actual value.",
        "Think a form with named boxes. The type tells you what kind of thing each box accepts; the value is the data currently inside it.",
        """FIELD NAME       FIELD TYPE       WHAT IS THE VALUE?                 EXAMPLE
    creator            address        actual address stored in field       creator = msg.sender
    amount             uint256        actual number stored in field        amount = 100
    address           actual address stored in field       creator = msg.sender
    uint256           actual number stored in field        amount = 100
    string            actual text stored in field          description = "bug"
    bytes32           actual 32-byte value                 solutionHash = hash
    enum              one enum member                      status = Status.Open
    
    STRUCT SYNTAX
    struct Bounty {
        address creator;
        uint256 amount;
    }
    
    VALUE MEANS
    The value is the actual data currently placed in the field.
    In amount: amount, left side = field name, right side = value.""",
        """contract StructTypesExample {
        enum Status { Open, Claimed, Paid }
    
        struct Bounty {
            address creator;
            address hunter;
            uint256 amount;
            string description;
            bytes32 solutionHash;
            Status status;
        }
    
        mapping(bytes32 => Bounty) public bounties;
    
        function create(
            bytes32 id,
            uint256 amount,
            string calldata description
        ) external {
            bounties[id] = Bounty({
                creator: msg.sender,
                hunter: address(0),
                amount: amount,
                description: description,
                solutionHash: keccak256(bytes(description)),
                status: Status.Open
            });
        }
    
        function claim(bytes32 id) external {
            Bounty storage b = bounties[id];
            b.hunter = msg.sender;
            b.status = Status.Claimed;
        }
    }""",
        [
            "creator is a field and address is its field type.",
            "msg.sender is the actual value assigned to creator.",
            "amount is a field name in one place and a function parameter/value in another; context matters.",
            "In amount: amount, the left amount is the struct field and the right amount is the value being put into it.",
            "Bounty storage b is a reference to the real stored struct; changing b changes the stored record.",
        ],
    )
    
    add(
        "types-table", ["type-table", "type-map", "solidity-types"], "TYPES",
        "A practical map of the Solidity type families you will repeatedly see.",
        "Think of choosing the shape of the box before putting data into it.",
        """FAMILY         EXAMPLES                         WHAT IT HOLDS
    uint / int      uint256 / int128                  numbers
    bool            bool                              true or false
    address         address / address payable         account/contract address
    bytesN          bytes32 / bytes4                  fixed-size bytes
    bytes / string  bytes / string                    dynamic bytes / text
    array           uint256[] / address[3]            ordered elements
    mapping         mapping(address => uint256)       key -> value lookup
    struct          struct User { ... }               named fields
    enum            enum Status { Open, Paid }        one named option
    contract        MyToken / IERC20                  contract-typed reference""",
        """contract TypesTableExample {
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
        [
            "Ask what kind of thing you need to store or pass.",
            "Simple copied values are usually value types.",
            "Compound or dynamically-sized data uses reference types such as arrays, structs, bytes, and strings.",
            "Use mappings for key-based lookup.",
            "Use structs when several named fields describe one record.",
        ],
    )
    
    add(
        "calldata-deep", ["calldata-101", "call-data-explained"], "ABI",
        "Calldata is the raw byte payload supplied with a contract call. The word is also used as a data location for read-only external input.",
        "M-Pesa analogy: think of the API request body arriving as bytes. The first four bytes normally choose the function; the remaining bytes carry ABI-encoded arguments.",
        """0x
    [4-byte function selector]
    [ABI-encoded argument 1]
    [ABI-encoded argument 2]
    ...""",
        """contract CalldataDeepExample {
        uint256 public lastAmount;
    
        function setAmount(uint256 amount) external {
            lastAmount = amount;
        }
    
        function raw() external view returns (bytes memory) {
            return msg.data;
        }
    
        fallback(bytes calldata input) external {
            bytes4 selector =
                input.length >= 4 ? bytes4(input[:4]) : bytes4(0);
            selector;
        }
    }""",
        [
            "A caller supplies a raw byte payload to the contract.",
            "The first four bytes normally identify a normal function.",
            "The remaining bytes normally contain ABI-encoded arguments.",
            "msg.data exposes the complete payload.",
            "A parameter such as string calldata note is a read-only view of external call input.",
            "Do not confuse the calldata data location with msg.data: one is a type/location declaration, the other is the complete current payload.",
        ],
        audit="Manual calldata parsing is security-sensitive around selectors, lengths, decoding, fallback routing, and arbitrary forwarding.",
    )
    
    add(
        "call-data-layout", ["calldata-layout", "msg.data-layout", "abi-call-layout"], "ABI",
        "A small visual model for how a normal ABI function call is laid out in calldata.",
        "Selector first, arguments after it, all encoded into bytes.",
        """CALL DATA
    0x
    |---- 4 bytes ----|-------------------------------|
    | function sig    | ABI-encoded arguments         |
    | selector        | uint/address/bytes/etc.       |
    """,
        """contract CalldataLayout {
        function set(uint256 amount, address user) external {
            amount;
            user;
        }
    
        fallback(bytes calldata input) external returns (bytes memory) {
            bytes4 selector =
                input.length >= 4 ? bytes4(input[:4]) : bytes4(0);
    
            // input[4:] is the ABI-encoded body.
            return abi.encode(selector, input[4:]);
        }
    }""",
        [
            "Selector = first four bytes.",
            "Argument bytes start immediately after the selector.",
            "msg.sig gives the first four bytes.",
            "msg.data gives the whole byte sequence.",
            "A fallback bytes parameter receives that same full payload as input.",
        ],
    )
    
    add(
        "terminology", ["glossary", "terms", "solidity-glossary", "jargon"], "GLOSSARY",
        "Plain-English explanations for the fancy words that show up in Solidity documentation and audits.",
        "When a word sounds complicated, translate it into what data, control flow, storage, or calls are actually doing.",
        """TERM                 PLAIN ENGLISH
    ternary              compact if/else that produces a value
    parameter            named input slot in a function definition
    argument              actual value passed to that slot
    expression            code that produces/refers to a value
    statement             an instruction
    state variable        persistent contract-level data
    local variable        temporary function-level data
    value type            copied value
    reference type        data handled through a location
    calldata              raw byte payload from an external call
    ABI                    encoding/decoding rules for contract calls
    selector               first four calldata bytes
    callback               a call made back into another contract
    mutability             pure/view/payable/nonpayable permission
    visibility             who/where can access something
    storage slot            numbered persistent storage location
    packing                putting small values into one slot
    reentrancy              entering again before the first operation finishes
    delegatecall            run other code using this contract's storage
    invariant               property that should remain true""",
        """contract TerminologyExample {
        uint256 public stored; // state variable
    
        function set(uint256 amount) external {
            uint256 next = amount + 1; // local variable
            stored = next;
        }
    
        function pick(bool ok)
            external
            pure
            returns (uint256)
        {
            return ok ? 1 : 0; // ternary expression
        }
    }""",
        [
            "Parameter = named slot in the function definition.",
            "Argument = actual value supplied at the call site.",
            "Expression = code that produces/refers to a value.",
            "Statement = an executable instruction.",
            "Calldata = raw incoming call bytes; calldata as a data location is read-only.",
            "A ternary is just a value-producing condition: condition ? A : B.",
        ],
    )
    
    add(
        "ternary-deep", ["ternary-operator", "conditional-expression", "terniary"], "GLOSSARY",
        "The ternary operator is a compact condition that chooses one of two values.",
        "It is a tiny if/else that returns a value instead of opening a whole block.",
        """condition ? valueWhenTrue : valueWhenFalse""",
        """contract TernaryExample {
        function fee(uint256 amount, bool vip)
            external
            pure
            returns (uint256)
        {
            uint256 rate = vip ? 1 : 2;
            return amount * rate / 100;
        }
    }""",
        [
            "Evaluate the condition.",
            "True -> choose the value before the colon.",
            "False -> choose the value after the colon.",
            "Because the expression produces a value, it can be assigned or returned.",
        ],
        gotchas="Use normal if/else when branches perform several statements or become difficult to read.",
    )
    
    add(
        "parameter-vs-argument", ["parameter-argument", "params-vs-args"], "GLOSSARY",
        "Parameter and argument are different parts of a function call.",
        "Function definition = empty form. Function call = completed form.",
        """function withdraw(uint256 amount) external { ... }
    // amount = parameter
    
    withdraw(1 ether);
    // 1 ether = argument""",
        """contract ParameterArgumentExample {
        function withdraw(uint256 amount) external {
            require(amount > 0);
        }
    
        function demo() external {
            this.withdraw(1 ether);
        }
    }""",
        [
            "Look at the function definition: amount is the parameter.",
            "Look at the call: 1 ether is the argument.",
            "At execution time, the argument supplies the parameter's value.",
        ],
    )
    
    
    add(
        "keywords", ["keyword", "language-keywords", "solidity-keywords"], "SYNTAX",
        "Solidity keywords are words with special meaning in the language.",
        "Read a keyword as an instruction to the compiler: contract declares a contract, external marks external-call access, and storage/calldata/memory choose where reference data lives.",
        """contract, interface, library, abstract, is, import, using
    constant, immutable, transient, type, fixed, ufixed
    function, constructor, fallback, receive, modifier, returns, return
    public, external, internal, private, view, pure, payable
    memory, calldata, storage
    mapping, struct, enum, bytes, string, address
    if, else, for, while, do, break, continue, unchecked
    try, catch, assert, require, revert, emit, new, delete
    call, staticcall, delegatecall
    assembly, error, event, virtual, override, super, this""",
        """contract KeywordsLab {
        uint256 public value;
    
        modifier nonZero(uint256 x) {
            require(x != 0);
            _;
        }
    
        constructor() {
            value = 1;
        }
    
        function set(uint256 next) external nonZero(next) {
            value = next;
        }
    
        receive() external payable {}
        fallback() external payable {}
    }""",
        [
            "First classify the keyword: structure, access, data location, control flow, or execution.",
            "Then read the surrounding symbols and types; keywords rarely work alone.",
            "external + payable, for example, means an externally callable function that may receive ETH.",
            "Punctuation such as => or [] is separate from keywords such as mapping or external.",
        ],
        audit="Keywords can change access control, data location, state/ETH permissions, execution routing, or inheritance behavior.",
    );
    
    add(
        "contract-anatomy", ["contract-structure", "contract-layout", "solidity-contract-anatomy"], "ARCHITECTURE",
        "A contract is easier to audit when you read its persistent state and trust boundaries before the business logic.",
        "Think of a shop: state is the ledger, modifiers are door checks, events are receipts, and functions are actions.",
        """contract Store is Parent {
        // state
        uint256 public price;
    
        // event
        event Bought(address indexed buyer, uint256 amount);
    
        // error
        error TooSmall(uint256 sent, uint256 needed);
    
        // modifier
        modifier enough(uint256 sent) {
            if (sent < price) revert TooSmall(sent, price);
            _;
        }
    
        // constructor
        constructor(uint256 startingPrice) {
            price = startingPrice;
        }
    
        // function + ETH routing
        function buy() external payable enough(msg.value) {
            emit Bought(msg.sender, msg.value);
        }
    
        receive() external payable {}
        fallback() external payable {}
    }""",
        """contract ContractAnatomyLab {
        uint256 public price;
        event Bought(address indexed buyer, uint256 amount);
        error TooSmall(uint256 sent, uint256 needed);
    
        constructor(uint256 startingPrice) {
            price = startingPrice;
        }
    
        modifier enough(uint256 sent) {
            if (sent < price) revert TooSmall(sent, price);
            _;
        }
    
        function buy() external payable enough(msg.value) {
            emit Bought(msg.sender, msg.value);
        }
    
        receive() external payable {}
        fallback() external payable {}
    }""",
        [
            "Read inheritance first: is tells you which base contract/interface relationships matter.",
            "Find state variables: these are persistent storage.",
            "Find the constructor and initialization assumptions.",
            "Inspect modifiers because they wrap function execution.",
            "Mark ETH movement and external calls as trust boundaries.",
            "Only then read each state-changing function as a state transition.",
        ],
        audit="Map storage writes, authorization checks, ETH movement, events, and external calls before reasoning about business rules.",
    );
    
    add(
        "call-anatomy", ["calls-anatomy", "external-call-anatomy", "call-patterns"], "CALLS",
        "A contract call can be typed or low-level, and call, staticcall, and delegatecall deliberately produce different execution contexts.",
        "Think phone calls: a typed call uses a known menu, call sends a raw request, staticcall is read-only, delegatecall runs someone else's code with your storage.",
        """target.ping(7);
    
    target.call(
        abi.encodeWithSignature("ping(uint256)", 7)
    );
    
    target.staticcall(
        abi.encodeWithSignature("price()")
    );
    
    target.delegatecall(
        abi.encodeWithSignature("set(uint256)", 7)
    );""",
        """interface ITarget {
        function ping(uint256 x) external returns (uint256);
    }
    
    contract CallAnatomyLab {
        function typed(ITarget target) external returns (uint256) {
            return target.ping(7);
        }
    
        function raw(address target)
            external
            returns (bool ok, bytes memory data)
        {
            return target.call(
                abi.encodeWithSignature("ping(uint256)", 7)
            );
        }
    
        function read(address target)
            external
            view
            returns (bool ok, bytes memory data)
        {
            return target.staticcall(
                abi.encodeWithSignature("price()")
            );
        }
    }""",
        [
            "A typed interface call encodes the function selector and arguments for you.",
            "Low-level call returns success plus raw return bytes.",
            "staticcall constrains the called execution from changing state.",
            "delegatecall runs target code using the caller's storage and address context.",
            "Decode raw return bytes before treating them as typed values.",
        ],
        audit="Check target control, return-success handling, msg.sender/msg.value behavior, and delegatecall storage compatibility.",
    );
    
    add(
        "types-defaults", ["defaults", "default-values", "solidity-defaults"], "TYPES",
        "Every Solidity type has a default value, which matters for fresh storage, mapping misses, zeroed structs, and delete.",
        "Every empty box already contains the type's zero-equivalent: numbers 0, bool false, address(0), empty dynamic data.",
        """uint256       -> 0
    int256          -> 0
    bool            -> false
    address         -> address(0)
    bytes32         -> bytes32(0)
    string          -> ""
    bytes           -> 0x
    T[]             -> empty array
    enum Status     -> Status(0)
    struct User     -> every field at its default""",
        """contract TypesDefaultsLab {
        enum Status { Open, Paid }
    
        struct User {
            address account;
            uint256 score;
            bool active;
            Status status;
        }
    
        mapping(address => uint256) public balances;
        User public user;
    
        function reset() external {
            delete user;
        }
    }""",
        [
            "Read the declared type.",
            "Ask what its zero/default representation is.",
            "A missing mapping key can return the default without having been explicitly written.",
            "delete restores the targeted storage value to its default.",
        ],
        audit="Zero, false, empty, and address(0) are often valid values; do not mistake them for proof that data does not exist.",
    );
    
    add(
        "expression-reader", ["expressions", "read-expression", "expression-decode"], "LEARNING TOOL",
        "A small expression reader that teaches you to trace the value source, lookup, operator, and destination.",
        "Read a line as a sentence. For balances[msg.sender] += msg.value: choose the caller's balance, add the ETH sent now, then store the new balance.",
        """balances[msg.sender] += msg.value
    │        │             │
    │        │             └─ current call's ETH
    │        └────────────── caller becomes mapping key
    └────────────────────── mapping lookup
    
    target.call{value: amount}(data)
          │       │          │
          │       │          └─ argument bytes
          │       └──────────── call option: send ETH
          └──────────────────── external call""",
        """contract ExpressionReaderLab {
        mapping(address => uint256) public balances;
    
        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }
    
        function send(address target, uint256 amount) external {
            (bool ok,) = target.call{value: amount}("");
            require(ok);
        }
    }""",
        [
            "Start with the base name.",
            "Read [] as an indexed/mapping lookup.",
            "Read += as calculate-then-store-back.",
            "Translate globals such as msg.sender and msg.value using the current call context.",
            "At a call, separately identify the target, call options, and arguments.",
        ],
        audit="Expression reading is a core audit skill: trace each value source and each state write before judging the line.",
    );
    
    add(
        "practice", ["exercises", "questions", "practice-mode"], "LEARNING TOOL",
        "Prediction-first drills that make you reason before copying a result.",
        "Predict first. Then run the smallest local test you can build and compare the observed state with your prediction.",
        """PREDICT FIRST
    1. Missing mapping key?
    2. do-while with an immediately false condition?
    3. Which bytes form the function selector?
    4. Is msg.value the same as address(this).balance?
    5. What changes when a reference uses storage vs memory?""",
        """contract PracticeLab {
        mapping(address => uint256) public balances;
    
        receive() external payable {
            balances[msg.sender] += msg.value;
        }
    
        function loop(uint256 limit) external pure returns (uint256 i) {
            do {
                i++;
            } while (i < limit);
        }
    }""",
        [
            "Write down the result before executing anything.",
            "Explain why you predicted it.",
            "Run the smallest local test or call.",
            "Compare prediction vs observation.",
            "Turn surprises into a new test or cheat topic.",
        ],
    );
    
    add(
        "confused", ["commonly-confused", "confusion-index", "confusions"], "LEARNING TOOL",
        "A quick map of Solidity terms that sound interchangeable but control different things.",
        "When terms look similar, compare the question each one answers: data location, caller identity, ETH amount, storage, or execution context.",
        """parameter vs argument
    msg.value vs address(this).balance
    calldata vs msg.data
    receive vs fallback
    for vs while vs do-while
    require vs revert vs assert
    call vs staticcall vs delegatecall
    storage vs memory vs calldata""",
        """contract ConfusedLab {
        function compare(address target) external payable {
            msg.value;
            address(this).balance;
            target.call("");
            target.staticcall("");
            target.delegatecall("");
        }
    }""",
        [
            "Name the two concepts.",
            "Write the question each one answers.",
            "Find the smallest example where their behavior diverges.",
            "Only then choose which concept belongs in your code.",
        ],
    );
    
    add(
        "patterns", ["solidity-patterns", "common-patterns", "audit-patterns"], "PATTERNS",
        "Recurring Solidity code shapes that are useful to recognize instantly.",
        "Patterns are templates, not proof. Verify the concrete state transition and trust boundary.",
        """CHECK -> EFFECT -> INTERACTION
    require(...);
    balances[msg.sender] -= amount;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    
    PULL PAYMENT
    claimable[user] += amount;
    ...
    claimable[msg.sender] = 0;
    pay(msg.sender, amount);
    
    MAPPING + ARRAY INDEX
    if (!seen[user]) {
        seen[user] = true;
        users.push(user);
    }""",
        """contract PatternsLab {
        mapping(address => uint256) public claimable;
        mapping(address => bool) public seen;
        address[] public users;
    
        function register() external {
            if (!seen[msg.sender]) {
                seen[msg.sender] = true;
                users.push(msg.sender);
            }
        }
    
        function claim() external {
            uint256 amount = claimable[msg.sender];
            claimable[msg.sender] = 0;
    
            (bool ok,) = msg.sender.call{value: amount}("");
            require(ok);
        }
    }""",
        [
            "Recognize the shape.",
            "Classify each line as state read, state write, external interaction, or event.",
            "Check whether the implementation actually preserves the intended invariant.",
            "Never accept a pattern name as proof of correctness.",
        ],
        audit="Use patterns to navigate quickly, then verify the exact implementation and threat model.",
    );
    
    add(
        "versioning", ["versions", "compiler-version", "version-compatibility"], "REFERENCE",
        "Solidity syntax and EVM globals evolve, so compiler and EVM version are part of the meaning of a snippet.",
        "Read pragma first. Then distinguish language support from the EVM fork selected by the project.",
        """pragma solidity ^0.8.20;
    
    BLOCK / EVM ERA EXAMPLES
    block.basefee       London-era
    block.prevrandao    Paris-era
    block.blobbasefee   Cancun-era
    blobhash(i)          Cancun-era
    block.slotnum       Amsterdam-era / experimental in current docs""",
        """contract VersioningLab {
        function baseFee() external view returns (uint256) {
            return block.basefee;
        }
    
        function randao() external view returns (uint256) {
            return block.prevrandao;
        }
    }""",
        [
            "Read the pragma.",
            "Check the compiler version actually installed by the project.",
            "Check the selected evmVersion when a global depends on a fork.",
            "Compile in the project settings before treating a current-docs feature as available.",
        ],
        audit="Version drift can cause compile failures or different EVM behavior.",
        gotchas="EVM-era labels are intentionally broad; exact availability depends on the Solidity release and selected evmVersion.",
    );
    
    add(
        "lab-workflow", ["runnable-labs", "lab-guide", "contract-labs"], "LEARNING TOOL",
        "A repeatable workflow for turning any cheat contract into a tiny local experiment.",
        "The cheat command prints code only. You decide when to copy it into a scratch Foundry project and run it.",
        """lk cheat <topic> 1
    copy contract into src/
    write one tiny test
    forge test -vv
    change one line
    run again
    explain the state transition""",
        """contract LabWorkflowExample {
        uint256 public value;
    
        function set(uint256 next) external {
            value = next;
        }
    }""",
        [
            "Start from the smallest contract lab.",
            "Copy it into your own scratch project.",
            "Write a test that proves your prediction.",
            "Change one thing and observe the difference.",
        ],
        gotchas="Cheat remains read-only: it does not create files, start Anvil, or modify your project.",
    );
    


    add(
        "yul", ["yul-assembly", "assembly-language", "evm-assembly"], "YUL / ASSEMBLY",
        "The low-level language used inside Solidity assembly blocks.",
        "Solidity is the safer wrapper; Yul is the lower-level toolbox where you manipulate words, memory, storage, calldata, and EVM calls directly.",
        """assembly {
        let x := add(a, b)
    }""",
        """function addLowLevel(uint256 a, uint256 b)
        external
        pure
        returns (uint256 result)
    {
        assembly {
            result := add(a, b)
        }
    }""",
        [
            "Enter Yul with assembly { ... }.",
            "Yul values are EVM words; let creates a Yul local.",
            "Built-ins such as add, mload, sload, sstore, calldataload, call, and revert operate close to the EVM.",
            "Use assembly when the lower-level control is intentional and understood.",
        ],
        audit="Assembly bypasses many Solidity checks. Verify memory pointers, storage slots, bounds, return data, and call results manually.",
    )

    add(
        "yul-memory", ["assembly-memory", "mstore", "mload"], "YUL / ASSEMBLY",
        "Reading and writing 32-byte words in EVM memory.",
        "Memory is temporary scratch space; Yul mstore writes a word and mload reads one.",
        """assembly {
        mstore(0x00, value)
        result := mload(0x00)
    }""",
        """function memoryRoundTrip(uint256 value)
        external
        pure
        returns (uint256 result)
    {
        assembly {
            mstore(0x00, value)
            result := mload(0x00)
        }
    }""",
        [
            "Pick a memory offset such as 0x00.",
            "mstore(offset, value) writes 32 bytes.",
            "mload(offset) reads 32 bytes.",
            "ABI return data is also ultimately represented in memory before returning.",
        ],
        audit="Overlapping or incorrectly managed memory can corrupt ABI data and return values.",
    )

    add(
        "yul-storage", ["assembly-storage", "sload", "sstore"], "YUL / ASSEMBLY",
        "Direct access to EVM storage slots.",
        "Solidity names a state variable; Yul can address the slot directly.",
        """assembly {
        sstore(slot, value)
        result := sload(slot)
    }""",
        """function storageRoundTrip(uint256 slot, uint256 value)
        external
        returns (uint256 result)
    {
        assembly {
            sstore(slot, value)
            result := sload(slot)
        }
    }""",
        [
            "Choose a slot deliberately.",
            "sstore writes a 32-byte word to that slot.",
            "sload reads the word back.",
            "Mappings and dynamic arrays use derived slots, so their slot formulas matter.",
        ],
        audit="A wrong slot is not a local bug; it can overwrite unrelated protocol state.",
    )

    add(
        "yul-calldata", ["assembly-calldata", "calldataload", "calldatacopy"], "YUL / ASSEMBLY",
        "Reading raw external call input at the byte level.",
        "The first four calldata bytes are normally the selector; later words contain ABI arguments.",
        """assembly {
        selector := shr(224, calldataload(0))
        value := calldataload(4)
    }""",
        """function firstArgument() external pure returns (uint256 value) {
        assembly {
            value := calldataload(4)
        }
    }""",
        [
            "calldataload(offset) reads a 32-byte word from calldata.",
            "Normal function calldata begins with a four-byte selector.",
            "ABI arguments start after those four bytes.",
            "calldatacopy can copy arbitrary calldata ranges into memory.",
        ],
        audit="Check offsets and lengths manually; malformed calldata can expose assumptions that typed Solidity parameters normally hide.",
    )

    add(
        "yul-control-flow", ["assembly-if", "assembly-switch", "assembly-for", "yul-if", "yul-switch"], "YUL / ASSEMBLY",
        "Yul's low-level control-flow constructs.",
        "Yul has if, switch, and for constructs, but their semantics are lower-level than Solidity's syntax.",
        """assembly {
        switch x
        case 0 { result := 0 }
        default { result := 1 }
    }""",
        """function choose(uint256 x) external pure returns (uint256 result) {
        assembly {
            switch x
            case 0 {
                result := 10
            }
            default {
                result := 20
            }
        }
    }""",
        [
            "let declares a Yul local.",
            "if executes a block when its condition is non-zero.",
            "switch selects one case or default.",
            "for combines initialization, condition, post-expression, and body at Yul level.",
        ],
        audit="Low-level loops and memory/storage operations still carry gas and correctness risks.",
    )

    add(
        "yul-functions", ["assembly-functions", "yul-function"], "YUL / ASSEMBLY",
        "Local reusable Yul functions inside an assembly block.",
        "A Yul function is a local low-level helper; it is not a Solidity external/public function.",
        """assembly {
        function twice(x) -> y {
            y := mul(x, 2)
        }
        result := twice(value)
    }""",
        """function doubleLowLevel(uint256 value)
        external
        pure
        returns (uint256 result)
    {
        assembly {
            function twice(x) -> y {
                y := mul(x, 2)
            }
            result := twice(value)
        }
    }""",
        [
            "Define a Yul function inside the assembly block.",
            "Its parameters and return values are Yul variables.",
            "Call it like a local low-level function.",
            "Do not confuse it with a Solidity function declaration.",
        ],
        audit="Track Yul function inputs/outputs and memory/storage side effects just like inline assembly code.",
    )

    add(
        "yul-call", ["assembly-call", "yul-staticcall", "yul-delegatecall"], "YUL / ASSEMBLY",
        "Low-level EVM call operations from Yul.",
        "Yul exposes call, staticcall, delegatecall, returndatacopy, and returndatasize directly.",
        """assembly {
        ok := staticcall(gas(), target, ptr, 4, ptr, 32)
    }""",
        """function lowLevelStaticRead(address target, bytes4 selector)
        external
        view
        returns (bool ok, uint256 value)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, selector))
            ok := staticcall(gas(), target, ptr, 4, ptr, 32)
            value := mload(ptr)
        }
    }""",
        [
            "Build input bytes in memory.",
            "Pass gas, target, input pointer/length, and output pointer/length to the call opcode.",
            "Check the success flag.",
            "Read or copy return data explicitly.",
        ],
        audit="Verify target, calldata layout, gas assumptions, return-data size, and failure handling. Delegatecall additionally shares caller storage/context.",
    )
