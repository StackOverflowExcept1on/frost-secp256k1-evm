// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {FROSTWalletOptimized} from "./FROSTWalletOptimized.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {FROSTOffchain, SigningKey} from "src/FROSTOffchain.sol";

library FROSTWalletOptimizedTestHelper {
    /// forge-lint: disable-next-item(screaming-snake-case-const)
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    using FROSTWalletOptimizedTestHelper for FROSTWalletOptimized;

    function getNonce(FROSTWalletOptimized frostWallet) internal view returns (uint256) {
        return uint256(vm.load(address(frostWallet), bytes32(uint256(0))));
    }

    function getMessageHash(FROSTWalletOptimized frostWallet, address to, uint256 value, bytes memory data)
        public
        view
        returns (bytes32)
    {
        uint256 nonce = frostWallet.getNonce();
        return getMessageHashWithNonce(frostWallet, to, value, data, nonce);
    }

    function getMessageHashWithNonce(
        FROSTWalletOptimized frostWallet,
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce
    ) public view returns (bytes32) {
        bytes32 dataHash = keccak256(data);
        return keccak256(
            abi.encodePacked(
                block.chainid, uint256(uint160(address(frostWallet))), nonce, uint256(uint160(to)), value, dataHash
            )
        );
    }

    function getTranscationData() public pure returns (address to, uint256 value, bytes memory data) {
        return (0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 1 ether, "");
    }
}

contract ReentrancyAttackToFROSTWalletOptimized {
    using FROSTOffchain for SigningKey;
    using FROSTWalletOptimizedTestHelper for FROSTWalletOptimized;

    SigningKey signingKey;
    FROSTWalletOptimized frostWallet;

    uint256 nonce;

    constructor(SigningKey _signingKey, FROSTWalletOptimized _frostWallet) {
        signingKey = _signingKey;
        frostWallet = _frostWallet;

        nonce = frostWallet.getNonce();
    }

    function executeTransaction5112088248() public {
        (address to, uint256 value, bytes memory data) = (address(this), 1 ether, "");
        bytes32 messageHash = frostWallet.getMessageHashWithNonce(to, value, data, nonce);
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostWallet.executeTransaction5112088248(
            to, value, data, signatureCommitmentX, signatureCommitmentY, signatureZ
        );
    }

    receive() external payable {
        if (address(frostWallet).balance > 0) {
            executeTransaction5112088248();
        }
    }
}

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
