// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {SigningKey, FROSTOffchain} from "src/FROSTOffchain.sol";
import {FROSTCounterOptimized} from "./FROSTCounterOptimized.sol";

contract FROSTCounterOptimizedTest is Test {
    using FROSTOffchain for SigningKey;

    SigningKey signingKey;
    FROSTCounterOptimized frostCounter;

    function setUp() public {
        uint256 scalar = 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E;
        signingKey = FROSTOffchain.signingKeyFromScalar(scalar);

        Vm.Wallet memory wallet = vm.createWallet(signingKey.asScalar());

        uint256 publicKeyX = wallet.publicKeyX;
        uint256 publicKeyY = wallet.publicKeyY;

        assertEq(publicKeyX, 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09);
        assertEq(publicKeyY, 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF);

        frostCounter = new FROSTCounterOptimized();
    }

    function test_SetNumber() public {
        uint128 nonce = uint128(uint256(vm.load(address(frostCounter), bytes32(uint256(0)))));
        uint128 newNumber = 42;
        bytes32 messageHash = keccak256(
            abi.encodePacked(block.chainid, uint256(uint160(address(frostCounter))), uint256(nonce), uint256(newNumber))
        );
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostCounter.setNumber(newNumber, signatureCommitmentX, signatureCommitmentY, signatureZ);
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(1))
        );

        nonce = uint128(uint256(vm.load(address(frostCounter), bytes32(uint256(0)))));
        newNumber = 43;
        messageHash = keccak256(
            abi.encodePacked(block.chainid, uint256(uint160(address(frostCounter))), uint256(nonce), uint256(newNumber))
        );
        (signatureCommitmentX, signatureCommitmentY, signatureZ) = signingKey.createSignature(messageHash);
        frostCounter.setNumber(newNumber, signatureCommitmentX, signatureCommitmentY, signatureZ);
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(2))
        );
    }
}
