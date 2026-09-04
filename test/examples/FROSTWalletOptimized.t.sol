// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import {Test, Vm} from "forge-std/Test.sol";
import {FROSTOffchain, SigningKey} from "src/FROSTOffchain.sol";
import {FROSTWalletOptimized} from "test/examples/FROSTWalletOptimized.sol";
import {FROSTWalletOptimizedTestHelper} from "test/examples/FROSTWalletOptimizedTestHelper.sol";
import {ReentrancyAttackToFROSTWalletOptimized} from "test/examples/ReentrancyAttackToFROSTWalletOptimized.sol";

contract FROSTWalletOptimizedTest is Test {
    using FROSTOffchain for SigningKey;
    using FROSTWalletOptimizedTestHelper for FROSTWalletOptimized;

    SigningKey signingKey;
    FROSTWalletOptimized frostWallet;

    function setUp() public {
        uint256 scalar = 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E;
        signingKey = FROSTOffchain.signingKeyFromScalar(scalar);

        Vm.Wallet memory wallet = vm.createWallet(signingKey.asScalar());

        uint256 publicKeyX = wallet.publicKeyX;
        uint256 publicKeyY = wallet.publicKeyY;

        assertEq(publicKeyX, 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09);
        assertEq(publicKeyY, 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF);

        // forge-lint: disable-next-item(arbitrary-send-eth)
        frostWallet = new FROSTWalletOptimized{value: 100 ether}();
    }

    function test_ExecuteTransaction() public {
        (address to, uint256 value, bytes memory data) = FROSTWalletOptimizedTestHelper.getTranscationData();
        bytes32 messageHash = frostWallet.getMessageHash(to, value, data);
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostWallet.executeTransaction5112088248(
            to, value, data, signatureCommitmentX, signatureCommitmentY, signatureZ
        );
    }

    function test_ExecuteTransactionWithSignatureReplayAttack() public {
        (address to, uint256 value, bytes memory data) = FROSTWalletOptimizedTestHelper.getTranscationData();
        bytes32 messageHash = frostWallet.getMessageHash(to, value, data);
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostWallet.executeTransaction5112088248(
            to, value, data, signatureCommitmentX, signatureCommitmentY, signatureZ
        );

        vm.expectRevert();
        frostWallet.executeTransaction5112088248(
            to, value, data, signatureCommitmentX, signatureCommitmentY, signatureZ
        );
    }

    function test_ExecuteTransactionWithReentrancyAttack() public {
        ReentrancyAttackToFROSTWalletOptimized proxy =
            new ReentrancyAttackToFROSTWalletOptimized(signingKey, frostWallet);
        try proxy.executeTransaction5112088248() {} catch {}
        assertEq(address(proxy).balance, 0 ether);
    }
}
