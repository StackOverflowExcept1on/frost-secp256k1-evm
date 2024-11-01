// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Schnorr} from "src/utils/cryptography/Schnorr.sol";
import {Secp256k1} from "src/utils/cryptography/Secp256k1.sol";
import {Memory} from "src/utils/Memory.sol";
import {FROST} from "src/FROST.sol";

contract SchnorrTest is Test {
    function test_IsValidPublicKey() public pure {
        vm.assertFalse(
            Schnorr.isValidPublicKey(
                0x0000000000000000000000000000000000000000000000000000000000000000,
                0x8F537EEFDFC1606A0727CD69B4A7333D38ED44E3932A7179EECB4B6FBA9360DC
            )
        );
        vm.assertTrue(
            Schnorr.isValidPublicKey(
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE
            )
        );
        vm.assertTrue(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F,
                0x3D46AAE46A6F4DCAACFE1578992912987E8163D89AE03ADB5A15889213AB2B8C
            )
        );
        // invalid because `publicKeyX < Secp256k1.N` is not satisfied
        vm.assertFalse(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E
            )
        );
        vm.assertFalse(
            Schnorr.isValidPublicKey(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2C,
                0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D
            )
        );
    }

    function test_VerifySignature() public view {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        uint256 publicKeyX = 0xBC5E83C1F1B03CBB9CC4BAB889E6A970E1F4C5C65C5F89E8D9723D73B726CC3E;
        uint256 publicKeyY = 0xDBED58A60A09B1BAB5B9AA6601F6B0B71B3F7AD9172D110F4AF1904FBDBC6A34;
        vm.assertTrue(Schnorr.isValidPublicKey(publicKeyX, publicKeyY));

        uint256 signatureRX = 0xFEAEDAC471D34A127CB52CAA1B01549E21EFAC0E30DFDE9173E6DC739C1982D0;
        uint256 signatureRY = 0xA3E8E852ED62DFB12DA5C0C0A555CAF0DE99C4B568EF217ABBA765B7C7AFB2F8;
        vm.assertTrue(Secp256k1.isOnCurve(signatureRX, signatureRY));

        uint256 signatureZ = 0xBDD6B6C184BAE9468F68A56ECB54EB768E6A369E4E1162F46B992FCEBE3B3CA2;
        vm.assertTrue(signatureZ % Secp256k1.N != 0);

        bytes32 messageHash = bytes32(uint256(0x4141414141414141414141414141414141414141414141414141414141414141));
        (uint256 memPtr, uint256 challenge) =
            FROST.computeChallenge(publicKeyX, publicKeyY, signatureRX, signatureRY, messageHash);
        vm.assertTrue(challenge % Secp256k1.N != 0);

        vm.assertTrue(
            Schnorr.verifySignature(memPtr, publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, challenge)
        );
    }
}
