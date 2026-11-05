// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SetupTargets.sol";

contract SetupCompatibilityTest {
    function testAddressArrayInputIsCallable() external {
        AddressArrayTarget target = new AddressArrayTarget();
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBEEF);
        target.setRecipients(recipients);
        require(target.recipientCount() == 1, "ARRAY_LENGTH");
        require(target.lastRecipient() == address(0xBEEF), "ARRAY_VALUE");
    }

    function testUSDCVaultUsesSixDecimalTokenUnits() external {
        MockUSDC token = new MockUSDC();
        USDCVault vault = new USDCVault(address(token));
        token.mint(address(this), 1_000_000);
        require(token.decimals() == 6, "USDC_DECIMALS");
        require(token.approve(address(vault), 1_000_000), "USDC_APPROVE");
        vault.deposit(1_000_000);
        require(vault.credit(address(this)) == 1_000_000, "USDC_CREDIT");
        require(token.balanceOf(address(vault)) == 1_000_000, "USDC_VAULT_BALANCE");
    }

    function testUSDTStyleNoReturnApprovalAndTransferFrom() external {
        MockUSDTNoReturn token = new MockUSDTNoReturn();
        USDTPayer payer = new USDTPayer(address(token));
        token.mint(address(this), 1_000_000);

        (bool approved, bytes memory returndata) = address(token).call(
            abi.encodeWithSignature("approve(address,uint256)", address(payer), 1_000_000)
        );
        require(approved, "USDT_APPROVE_CALL");
        require(returndata.length == 0, "USDT_MUST_RETURN_NO_DATA");

        payer.deposit(1_000_000);
        require(payer.credit(address(this)) == 1_000_000, "USDT_CREDIT");
        require(token.balanceOf(address(payer)) == 1_000_000, "USDT_PAYER_BALANCE");
    }

    function testUSDTAllowanceCanBeResetBeforeReapproval() external {
        MockUSDTNoReturn token = new MockUSDTNoReturn();
        token.mint(address(this), 1_000_000);

        (bool first, bytes memory firstData) = address(token).call(
            abi.encodeWithSignature("approve(address,uint256)", address(this), 5)
        );
        require(first && firstData.length == 0, "FIRST_APPROVE");

        (bool reset, bytes memory resetData) = address(token).call(
            abi.encodeWithSignature("approve(address,uint256)", address(this), 0)
        );
        require(reset && resetData.length == 0, "RESET_APPROVE");

        (bool second, bytes memory secondData) = address(token).call(
            abi.encodeWithSignature("approve(address,uint256)", address(this), 9)
        );
        require(second && secondData.length == 0, "SECOND_APPROVE");
    }

    function testERC777ERC1155AndERC721ReceiverHooks() external {
        LowkeyReceiver receiver = new LowkeyReceiver();
        MockReceiverTokenDriver driver = new MockReceiverTokenDriver();

        driver.deliverERC777(receiver);
        driver.deliverERC1155(receiver);
        driver.deliverERC1155Batch(receiver);
        driver.deliverERC721(receiver);

        require(receiver.erc777Received() == 1, "ERC777_HOOK");
        require(receiver.erc1155Received() == 1, "ERC1155_HOOK");
        require(receiver.erc1155BatchReceived() == 1, "ERC1155_BATCH_HOOK");
        require(receiver.erc721Received() == 1, "ERC721_HOOK");
        require(receiver.supportsInterface(0x01ffc9a7), "ERC165");
        require(receiver.supportsInterface(0x4e2312e0), "ERC1155_RECEIVER");
    }
}
