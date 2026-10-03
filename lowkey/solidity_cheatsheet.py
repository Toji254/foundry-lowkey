#!/usr/bin/env python3
"""Read-only Solidity learning dictionary for LowkeyCast."""
from __future__ import annotations

import difflib


HELP = """
LOWKEY // SOLIDITY CHEATSHEET
==============================

Read-only lookup. No RPC, Anvil, target, config, Forge, or audit state.

Usage:
  lk cheat
  lk cheat <topic>
  lk cheat symbols
  lk cheat search <word>
  lk cheat --help

Examples:
  lk cheat mapping
  lk cheat nested-mapping
  lk cheat arrays-mappings
  lk cheat require
  lk cheat receive
  lk cheat fallback
  lk cheat interface
  lk cheat calls
  lk cheat storage
  lk cheat symbols
"""

TOPICS = []


def add(name, aliases, category, meaning, mental, syntax, example, steps,
        audit="", gotchas=""):
    TOPICS.append({
        "name": name,
        "aliases": aliases,
        "category": category,
        "meaning": meaning,
        "mental": mental,
        "syntax": syntax,
        "example": example,
        "steps": steps,
        "audit": audit,
        "gotchas": gotchas,
    })


add(
    "symbols", ["operators", "punctuation", "syntax-symbols"], "CHEATSHEET",
    "The Solidity punctuation and keywords you will see constantly.",
    "Read the symbols literally: choose data, access it, compare it, then update or call.",
    """{}    block / contract / function body
()    parameters or call
[]    array type / array index
;     end statement
,     separate items
.     member access
:     named call option / ternary separator
=>    mapping key -> value
=     assignment
+= -= *= /= %=  compound assignment
++ -- increment / decrement
!     NOT
&&    AND
||    OR
== != equality
< > <= >= comparisons
+ - * / % arithmetic
**    exponentiation
& | ^ ~ bitwise operators
<< >> bit shifts
? :   ternary
is    inheritance
virtual / override  inheritance customization
returns              function outputs
emit                 write event log
new                  create contract
delete               reset toward default
unchecked { }        skip arithmetic checks in that block
assembly { }         low-level Yul/EVM code
try / catch          handle external-call failure
using X for Y        attach library helpers to a type
type(T)              inspect type metadata
payable(address)     payable address conversion
{value: amount}      attach ETH to a call""",
    """mapping(address => uint256) balances;
balances[msg.sender] += msg.value;
uint256 fee = vip ? 0 : 1 ether;
payable(treasury).call{value: fee}("");""",
    [
        "mapping(address => uint256) has key type before => and value type after it.",
        "balances[msg.sender] means look up balances using msg.sender as the key.",
        "The dot means member access: msg.sender, address(this).balance.",
        "Braces after a call hold call options such as value or gas.",
    ],
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
    "bytes32 id;
bytes4 selector;",
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
    "address user;
address payable treasury;",
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
unknown selector + ETH -> payable fallback()""",
    """contract Example {
    receive() external payable {}
    fallback() external payable {}
}""",
    [
        "Empty data: receive gets priority when defined.",
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
    "bytes4 selector = bytes4(keccak256("withdraw(uint256)"));",
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
    """// Signature:
createbounty(address,uint256)

// Call values:
createbounty(0x1234..., 100 ether)""",
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
    "require(msg.sender == owner, "not owner");",
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
    "require(block.timestamp >= deadline, "too early");",
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
    "address(this).balance
address(target).code.length",
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
    "import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";",
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


_ALIAS = {}
for _topic in TOPICS:
    _ALIAS[_topic["name"].lower()] = _topic
    for _alias in _topic["aliases"]:
        _ALIAS[_alias.lower()] = _topic


def _norm(value: str) -> str:
    return "-".join(
        value.strip().lower().replace("_", "-").split()
    )


def find_topic(query: str):
    key = _norm(query)
    direct = _ALIAS.get(key)
    if direct:
        return direct

    ranked = []
    for topic in TOPICS:
        names = [topic["name"]] + topic["aliases"]
        score = max(
            difflib.SequenceMatcher(None, key, _norm(name)).ratio()
            for name in names
        )
        hay = " ".join(names).lower()
        if key and key in _norm(hay):
            score = max(score, 0.9)
        ranked.append((score, topic))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1] if ranked and ranked[0][0] >= 0.45 else None


def search(query: str):
    key = _norm(query)
    ranked = []
    for topic in TOPICS:
        hay = " ".join(
            [topic["name"]] + topic["aliases"] + [topic["meaning"]]
        ).lower()
        score = difflib.SequenceMatcher(
            None, key, _norm(topic["name"])
        ).ratio()
        if key and key in _norm(hay):
            score = max(score, 0.9)
        if score >= 0.4:
            ranked.append((score, topic))
    ranked.sort(key=lambda item: (-item[0], item[1]["name"]))
    return [topic for _, topic in ranked[:20]]


def render_index():
    print("LOWKEY // SOLIDITY CHEATSHEET")
    print("==============================")
    print("READ-ONLY • no RPC • no Anvil • no target • no project/audit state")
    print()
    current = None
    for topic in TOPICS:
        if topic["category"] != current:
            current = topic["category"]
            print(current)
            print("-" * len(current))
        print(f"  {topic['name']:<28} {topic['meaning']}")
    print()
    print("Use:")
    print("  lk cheat <topic>          detailed beginner explanation")
    print("  lk cheat symbols           punctuation/operators")
    print("  lk cheat search <word>     topic search")
    print("  lk cheat --help            cheatsheet help")


def render_topic(topic):
    print()
    print(f"LOWKEY // CHEAT • {topic['name']}")
    print("=" * 76)
    print(f"Category : {topic['category']}")
    print(f"Meaning  : {topic['meaning']}")
    print()
    print("MENTAL MODEL")
    print("------------")
    print(topic["mental"])
    print()
    print("SYNTAX")
    print("------")
    print(topic["syntax"])
    print()
    print("REAL EXAMPLE")
    print("------------")
    print(topic["example"])
    print()
    print("STEP BY STEP")
    print("------------")
    for index, step in enumerate(topic["steps"], 1):
        print(f"  {index}. {step}")
    if topic["audit"]:
        print()
        print("AUDIT LOOKOUT")
        print("-------------")
        print(topic["audit"])
    if topic["gotchas"]:
        print()
        print("WATCH OUT")
        print("---------")
        print(topic["gotchas"])
    related = [
        item["name"]
        for item in TOPICS
        if item["name"] != topic["name"]
        and item["category"] == topic["category"]
    ]
    if related:
        print()
        print("RELATED")
        print("-------")
        print("  " + ", ".join(related[:8]))
    print()
    print("Educational lookup. Verify exact details against your compiler/version.")


def run(args=None):
    args = list(args or [])
    if not args:
        render_index()
        return 0

    if args[0].lower() in {"--help", "--h", "-h", "help"}:
        print(HELP.strip())
        return 0

    if args[0].lower() in {"list", "all"}:
        render_index()
        return 0

    if args[0].lower() == "search":
        query = " ".join(args[1:]).strip()
        if not query:
            print("Usage: lk cheat search <word or phrase>")
            return 2
        rows = search(query)
        print(f"CHEATSHEET SEARCH • {query}")
        print("===========================")
        if not rows:
            print("No matching topics.")
            return 0
        for index, topic in enumerate(rows, 1):
            print(f"  {index:>2}. {topic['name']:<28} {topic['meaning']}")
        print()
        print("Open one with: lk cheat <topic>")
        return 0

    query = " ".join(args).strip()
    topic = find_topic(query)
    if topic:
        render_topic(topic)
        return 0

    print(f"No Solidity cheat topic matched: {query}")
    rows = search(query)
    if rows:
        print("Did you mean:")
        for topic in rows[:5]:
            print(f"  - {topic['name']}")
    else:
        print("Try: lk cheat search <word>")
    return 2


if __name__ == "__main__":
    raise SystemExit(run())
