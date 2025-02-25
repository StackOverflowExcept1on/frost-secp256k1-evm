// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Schnorr} from "src/utils/cryptography/Schnorr.sol";
import {Secp256k1} from "src/utils/cryptography/Secp256k1.sol";
import {Memory} from "src/utils/Memory.sol";
import {FROST} from "src/FROST.sol";

contract SchnorrTest is Test {
    function test_IsValidPublicKey() public pure {
        assertFalse(
            Schnorr.isValidPublicKey(
                0x0000000000000000000000000000000000000000000000000000000000000000,
                0x8F537EEFDFC1606A0727CD69B4A7333D38ED44E3932A7179EECB4B6FBA9360DC
            )
        );
        assertTrue(
            Schnorr.isValidPublicKey(
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE
            )
        );
        assertTrue(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F,
                0x3D46AAE46A6F4DCAACFE1578992912987E8163D89AE03ADB5A15889213AB2B8C
            )
        );
        // invalid because `publicKeyX < Secp256k1.N` is not satisfied
        assertFalse(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E
            )
        );
        assertFalse(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2C,
                0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D
            )
        );
    }

    function test_VerifySignature() public view {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        uint256 publicKeyX = 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09;
        uint256 publicKeyY = 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF;
        assertTrue(Schnorr.isValidPublicKey(publicKeyX, publicKeyY));

        uint256 signatureRX = 0xDF70C2D9D0BC0711BD338F95527A4545F8BB3530B3A90E07B34DF5B0F298DED1;
        uint256 signatureRY = 0xA84975B1488E6EA60530A3BDB74B2E7C9F0217769CBF0F2565744A353B919554;
        assertTrue(Secp256k1.isOnCurve(signatureRX, signatureRY));

        uint256 signatureZ = 0xB164EC237AF7EA1AF309EBDB6AA9588FCB821FB1E3AD32315A95D59A7F0A4600;
        assertTrue(signatureZ % Secp256k1.N != 0);

        bytes32 messageHash = bytes32(uint256(0x4141414141414141414141414141414141414141414141414141414141414141));
        (uint256 memPtr, uint256 challenge) =
            FROST.computeChallenge(publicKeyX, publicKeyY, signatureRX, signatureRY, messageHash);
        assertTrue(challenge % Secp256k1.N != 0);

        assertTrue(
            Schnorr.verifySignature(memPtr, publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, challenge)
        );
    }
}
