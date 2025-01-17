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
        uint256 publicKeyX = 0x355EEDCBB159977FA7F08B97D32BA7E413345FF9F3BB6FF9D48A857BCD429D52;
        uint256 publicKeyY = 0x3EC6F7DA9AE3EFCEC9F84EE894E840D672E9BF3E91C3025AFC4FDACE3DC0E0DC;
        assertTrue(Schnorr.isValidPublicKey(publicKeyX, publicKeyY));

        uint256 signatureRX = 0x920C53E3750C5D00AC46627E9B38BE025CC38C32651791AE231912CB2C078956;
        uint256 signatureRY = 0x01477EC8424AD9DC3C2C528DF3D9CC929719C15AF3D4B75EF5955CE39FFE4C77;
        assertTrue(Secp256k1.isOnCurve(signatureRX, signatureRY));

        uint256 signatureZ = 0x640D1DDE956D3DCE68499F102B87A2FEE6F18DA105916F003930A53F97786AEC;
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
