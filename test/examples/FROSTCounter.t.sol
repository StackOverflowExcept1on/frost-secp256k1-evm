// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {SigningKey, FROSTOffchain} from "src/FROSTOffchain.sol";
import {FROSTCounter} from "./FROSTCounter.sol";

contract FROSTCounterTest is Test {
    using FROSTOffchain for SigningKey;

    SigningKey signingKey;
    FROSTCounter frostCounter;

    function setUp() public {
        uint256 scalar = 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E;
        signingKey = FROSTOffchain.signingKeyFromScalar(scalar);

        Vm.Wallet memory wallet = vm.createWallet(signingKey.asScalar());

        uint256 publicKeyX = wallet.publicKeyX;
        uint256 publicKeyY = wallet.publicKeyY;

        assertEq(publicKeyX, 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09);
        assertEq(publicKeyY, 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF);

        frostCounter = new FROSTCounter(publicKeyX, publicKeyY);
    }

    function test_SetNumber() public {
        uint256 nonce = frostCounter.nonce();
        uint256 newNumber = 42;
        bytes32 messageHash =
            keccak256(abi.encodePacked(block.chainid, uint256(uint160(address(frostCounter))), nonce, newNumber));
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostCounter.setNumber(newNumber, signatureCommitmentX, signatureCommitmentY, signatureZ);
        assertEq(frostCounter.number(), newNumber);
        assertEq(frostCounter.nonce(), 1);

        nonce = frostCounter.nonce();
        newNumber = 43;
        messageHash =
            keccak256(abi.encodePacked(block.chainid, uint256(uint160(address(frostCounter))), nonce, newNumber));
        (signatureCommitmentX, signatureCommitmentY, signatureZ) = signingKey.createSignature(messageHash);
        frostCounter.setNumber(newNumber, signatureCommitmentX, signatureCommitmentY, signatureZ);
        assertEq(frostCounter.number(), newNumber);
        assertEq(frostCounter.nonce(), 2);
    }
}
