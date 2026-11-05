// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Compat {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract AddressArrayTarget {
    address public lastRecipient;
    uint256 public recipientCount;

    function setRecipients(address[] calldata recipients) external {
        require(recipients.length != 0, "EMPTY_RECIPIENTS");
        lastRecipient = recipients[recipients.length - 1];
        recipientCount = recipients.length;
    }
}

contract MockUSDC {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        require(balanceOf[from] >= amount, "BALANCE");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract USDCVault {
    address public immutable asset;
    mapping(address => uint256) public credit;

    constructor(address token) {
        asset = token;
    }

    function deposit(uint256 amount) external {
        require(IERC20Compat(asset).transferFrom(msg.sender, address(this), amount), "TRANSFER");
        credit[msg.sender] += amount;
    }
}

contract MockUSDTNoReturn {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    // Deliberately returns no data, as some deployed tokens do.
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    // Deliberately returns no data.
    function transferFrom(address from, address to, uint256 amount) external {
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        require(balanceOf[from] >= amount, "BALANCE");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

interface INoReturnToken {
    function transferFrom(address from, address to, uint256 amount) external;
}

contract USDTPayer {
    address public immutable asset;
    mapping(address => uint256) public credit;

    constructor(address token) {
        asset = token;
    }

    function deposit(uint256 amount) external {
        INoReturnToken(asset).transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
}

contract LowkeyReceiver {
    uint256 public erc777Received;
    uint256 public erc1155Received;
    uint256 public erc1155BatchReceived;
    uint256 public erc721Received;

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x4e2312e0;
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        erc777Received++;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4)
    {
        erc1155Received++;
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external returns (bytes4)
    {
        erc1155BatchReceived++;
        return 0xbc197c81;
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external returns (bytes4)
    {
        erc721Received++;
        return 0x150b7a02;
    }
}

contract MockReceiverTokenDriver {
    function deliverERC1155(LowkeyReceiver receiver) external {
        bytes4 result = receiver.onERC1155Received(address(this), address(this), 1, 1, "");
        require(result == 0xf23a6e61, "ERC1155_SELECTOR");
    }

    function deliverERC1155Batch(LowkeyReceiver receiver) external {
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = 1;
        amounts[0] = 1;
        bytes4 result = receiver.onERC1155BatchReceived(address(this), address(this), ids, amounts, "");
        require(result == 0xbc197c81, "ERC1155_BATCH_SELECTOR");
    }

    function deliverERC721(LowkeyReceiver receiver) external {
        bytes4 result = receiver.onERC721Received(address(this), address(this), 1, "");
        require(result == 0x150b7a02, "ERC721_SELECTOR");
    }

    function deliverERC777(LowkeyReceiver receiver) external {
        receiver.tokensReceived(address(this), address(this), address(this), 1, "", "");
    }
}
