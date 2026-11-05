// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Deliberately vulnerable fixture: a recipient array drives payout and
/// credit is cleared only after the external call, allowing callback replay.
contract P0ArrayBreakTarget {
    mapping(address => uint256) public credit;

    constructor() payable {}

    function deposit(address[] calldata recipients) external payable {
        require(recipients.length != 0, "NO_RECIPIENTS");
        uint256 each = msg.value / recipients.length;
        for (uint256 i; i < recipients.length; ++i) {
            credit[recipients[i]] += each;
        }
    }

    function withdraw(address[] calldata recipients) external {
        for (uint256 i; i < recipients.length; ++i) {
            address recipient = recipients[i];
            uint256 amount = credit[recipient];
            require(amount != 0, "NO_CREDIT");
            (bool ok,) = payable(recipient).call{value: amount}("");
            require(ok, "TRANSFER_FAILED");
            // Intentionally vulnerable ordering for the red-team acceptance test.
            credit[recipient] = 0;
        }
    }

    receive() external payable {}
}

interface IP0BoolToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract P0USDCStyleToken {
    string public constant name = "P0 Six Decimal Token";
    string public constant symbol = "P0USDC";
    uint8 public constant decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 permitted = allowance[from][msg.sender];
        require(permitted >= amount, "ALLOWANCE");
        if (permitted != type(uint256).max) allowance[from][msg.sender] = permitted - amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @dev Intentionally pays three times the recorded claim.
contract P0USDCStyleVault {
    P0USDCStyleToken private immutable token;
    mapping(address => uint256) public balances;

    constructor() payable {
        token = new P0USDCStyleToken();
        token.mint(address(this), 1_000_000_000);
    }

    function stakeToken() external view returns (address) {
        return address(token);
    }

    function deposit(uint256 amount) external {
        require(IP0BoolToken(address(token)).transferFrom(msg.sender, address(this), amount), "DEPOSIT");
        balances[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount != 0, "NO_CREDIT");
        require(IP0BoolToken(address(token)).transfer(msg.sender, amount * 3), "PAYOUT");
        balances[msg.sender] = 0;
    }
}

interface IP0NoReturnToken {
    function transfer(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external;
}

contract P0USDTStyleToken {
    string public constant name = "P0 No Return Token";
    string public constant symbol = "P0USDT";
    uint8 public constant decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    // Deliberately return no data, as some legacy tokens do.
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function transfer(address to, uint256 amount) external {
        _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 permitted = allowance[from][msg.sender];
        require(permitted >= amount, "ALLOWANCE");
        if (permitted != type(uint256).max) allowance[from][msg.sender] = permitted - amount;
        _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) private {
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @dev Intentionally pays three times the recorded claim.
contract P0USDTStyleVault {
    P0USDTStyleToken private immutable token;
    mapping(address => uint256) public balances;

    constructor() payable {
        token = new P0USDTStyleToken();
        token.mint(address(this), 1_000_000_000);
    }

    function stakeToken() external view returns (address) {
        return address(token);
    }

    function deposit(uint256 amount) external {
        IP0NoReturnToken(address(token)).transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount != 0, "NO_CREDIT");
        IP0NoReturnToken(address(token)).transfer(msg.sender, amount * 3);
        balances[msg.sender] = 0;
    }
}
