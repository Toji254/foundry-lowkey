// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1820RegistryFixture {
    function setInterfaceImplementer(address account, bytes32 interfaceHash, address implementer) external;
    function getInterfaceImplementer(address account, bytes32 interfaceHash) external view returns (address);
}

interface IERC1820ImplementerFixture {
    function canImplementInterfaceForAddress(bytes32 interfaceHash, address account) external view returns (bytes32);
}

interface IERC777RecipientFixture {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

interface IERC1155ReceiverFixture {
    function onERC1155Received(address operator, address from, uint256 id, uint256 amount, bytes calldata data)
        external returns (bytes4);
    function onERC1155BatchReceived(
        address operator, address from, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data
    ) external returns (bytes4);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IERC721ReceiverFixture {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external returns (bytes4);
}

contract MockERC1820Registry is IERC1820RegistryFixture {
    bytes32 private constant ACCEPT_MAGIC = keccak256("ERC1820_ACCEPT_MAGIC");
    mapping(address => mapping(bytes32 => address)) private implementers;

    function setInterfaceImplementer(address account, bytes32 interfaceHash, address implementer) external {
        require(msg.sender == account, "NOT_INTERFACE_MANAGER");
        if (implementer != address(0)) {
            require(
                IERC1820ImplementerFixture(implementer).canImplementInterfaceForAddress(interfaceHash, account)
                    == ACCEPT_MAGIC,
                "IMPLEMENTER_REJECTED"
            );
        }
        implementers[account][interfaceHash] = implementer;
    }

    function getInterfaceImplementer(address account, bytes32 interfaceHash)
        external view returns (address)
    {
        return implementers[account][interfaceHash];
    }
}

contract LowkeyReceiverFixture is
    IERC1820ImplementerFixture,
    IERC777RecipientFixture,
    IERC1155ReceiverFixture,
    IERC721ReceiverFixture
{
    uint256 public erc777Received;
    uint256 public erc1155SingleReceived;
    uint256 public erc1155BatchReceived;
    uint256 public erc721Received;

    function registerERC777(address registry) external returns (bool) {
        (bool ok, bytes memory result) = registry.call(abi.encodeWithSignature(
            "setInterfaceImplementer(address,bytes32,address)",
            address(this), keccak256("ERC777TokensRecipient"), address(this)
        ));
        return ok && result.length == 0;
    }

    function canImplementInterfaceForAddress(bytes32 interfaceHash, address account)
        external view returns (bytes32)
    {
        if (account == address(this) && interfaceHash == keccak256("ERC777TokensRecipient")) {
            return keccak256("ERC1820_ACCEPT_MAGIC");
        }
        return bytes32(0);
    }

    function tokensReceived(address, address, address, uint256 amount, bytes calldata, bytes calldata)
        external
    {
        erc777Received += amount;
    }

    function onERC1155Received(address, address, uint256, uint256 amount, bytes calldata)
        external returns (bytes4)
    {
        erc1155SingleReceived += amount;
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata amounts, bytes calldata)
        external returns (bytes4)
    {
        for (uint256 i; i < amounts.length; ++i) {
            erc1155BatchReceived += amounts[i];
        }
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x4e2312e0;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        ++erc721Received;
        return this.onERC721Received.selector;
    }
}

contract MockERC777Fixture {
    IERC1820RegistryFixture public immutable registry;

    constructor(address registry_) {
        registry = IERC1820RegistryFixture(registry_);
    }

    function send(address recipient, uint256 amount) external {
        address implementer = registry.getInterfaceImplementer(
            recipient, keccak256("ERC777TokensRecipient")
        );
        require(implementer != address(0), "RECIPIENT_NOT_REGISTERED");
        IERC777RecipientFixture(implementer).tokensReceived(
            msg.sender, msg.sender, recipient, amount, "", ""
        );
    }
}

contract MockERC1155Fixture {
    function safeTransferFrom(address to, uint256 id, uint256 amount) external {
        require(IERC1155ReceiverFixture(to).supportsInterface(0x4e2312e0), "NO_ERC1155_INTERFACE");
        require(
            IERC1155ReceiverFixture(to).onERC1155Received(msg.sender, address(0), id, amount, "")
                == 0xf23a6e61,
            "BAD_SINGLE_SELECTOR"
        );
    }

    function safeBatchTransferFrom(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(ids.length == amounts.length, "LENGTH_MISMATCH");
        require(IERC1155ReceiverFixture(to).supportsInterface(0x4e2312e0), "NO_ERC1155_INTERFACE");
        require(
            IERC1155ReceiverFixture(to).onERC1155BatchReceived(msg.sender, address(0), ids, amounts, "")
                == 0xbc197c81,
            "BAD_BATCH_SELECTOR"
        );
    }
}

contract MockERC721Fixture {
    function safeTransfer(address to, uint256 tokenId) external {
        require(
            IERC721ReceiverFixture(to).onERC721Received(msg.sender, address(0), tokenId, "") == 0x150b7a02,
            "BAD_ERC721_SELECTOR"
        );
    }
}

contract MockUSDTNoReturnFixture {
    uint8 public constant decimals = 6;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external {
        uint256 current = allowance[msg.sender][spender];
        require(amount == 0 || current == 0, "RESET_REQUIRED");
        allowance[msg.sender][spender] = amount;
    }
}

interface INoReturnApprovalFixture {
    function approve(address spender, uint256 amount) external;
}

contract MockFalseApprovalFixture {
    function approve(address, uint256) external pure returns (bool) {
        return false;
    }
}

contract MockMalformedApprovalFixture {
    fallback() external {
        assembly {
            mstore(0, 1)
            return(31, 1)
        }
    }
}

contract LowkeySafeApproveFixture {
    function prime(address token, address spender, uint256 amount) external {
        require(_approveCall(token, spender, amount), "PRIME_FAILED");
    }

    function safeApprove(address token, address spender, uint256 amount) external returns (bool) {
        if (_approveCall(token, spender, amount)) return true;
        if (!_approveCall(token, spender, 0)) return false;
        return _approveCall(token, spender, amount);
    }

    function _approveCall(address token, address spender, uint256 amount) private returns (bool) {
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSignature("approve(address,uint256)", spender, amount)
        );
        if (!ok) return false;
        if (data.length == 0) return true;
        if (data.length != 32) return false;
        uint256 returned = abi.decode(data, (uint256));
        return returned == 1;
    }
}

contract P0CompatibilityAcceptance {
    function test_optional_return_approval_resets_existing_allowance() external {
        MockUSDTNoReturnFixture token = new MockUSDTNoReturnFixture();
        LowkeySafeApproveFixture probe = new LowkeySafeApproveFixture();
        probe.prime(address(token), address(probe), 7);
        require(probe.safeApprove(address(token), address(probe), 99), "SAFE_APPROVE_FAILED");
        require(token.allowance(address(probe), address(probe)) == 99, "RESET_RETRY_FAILED");
    }

    function test_false_approval_return_fails_closed_without_reverting() external {
        MockFalseApprovalFixture token = new MockFalseApprovalFixture();
        LowkeySafeApproveFixture probe = new LowkeySafeApproveFixture();
        require(!probe.safeApprove(address(token), address(probe), 99), "FALSE_RETURN_ACCEPTED");
    }

    function test_malformed_approval_return_fails_closed_without_reverting() external {
        MockMalformedApprovalFixture token = new MockMalformedApprovalFixture();
        LowkeySafeApproveFixture probe = new LowkeySafeApproveFixture();
        require(!probe.safeApprove(address(token), address(probe), 99), "MALFORMED_RETURN_ACCEPTED");
    }

    function test_optional_decimals_metadata_sets_six_decimal_funding_unit() external {
        MockUSDTNoReturnFixture token = new MockUSDTNoReturnFixture();
        uint256 oneWholeToken = 10 ** uint256(token.decimals());
        require(oneWholeToken == 1_000_000, "WRONG_DECIMAL_SCALE");
    }

    function test_erc777_uses_erc1820_registration_and_tokens_received() external {
        MockERC1820Registry registry = new MockERC1820Registry();
        LowkeyReceiverFixture receiver = new LowkeyReceiverFixture();
        require(receiver.registerERC777(address(registry)), "ERC1820_REGISTRATION_FAILED");
        MockERC777Fixture token = new MockERC777Fixture(address(registry));
        token.send(address(receiver), 7);
        require(receiver.erc777Received() == 7, "ERC777_HOOK_NOT_CALLED");
    }

    function test_erc1155_single_and_batch_hooks_and_erc165() external {
        LowkeyReceiverFixture receiver = new LowkeyReceiverFixture();
        MockERC1155Fixture token = new MockERC1155Fixture();
        token.safeTransferFrom(address(receiver), 1, 3);
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        amounts[0] = 4;
        amounts[1] = 5;
        token.safeBatchTransferFrom(address(receiver), ids, amounts);
        require(receiver.erc1155SingleReceived() == 3, "ERC1155_SINGLE_MISSING");
        require(receiver.erc1155BatchReceived() == 9, "ERC1155_BATCH_MISSING");
    }

    function test_erc721_safe_receiver_selector() external {
        LowkeyReceiverFixture receiver = new LowkeyReceiverFixture();
        MockERC721Fixture token = new MockERC721Fixture();
        token.safeTransfer(address(receiver), 42);
        require(receiver.erc721Received() == 1, "ERC721_HOOK_MISSING");
    }
}
