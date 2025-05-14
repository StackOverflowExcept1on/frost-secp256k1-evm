// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {Secp256k1} from "src/utils/cryptography/Secp256k1.sol";

contract Secp256k1Test is Test {
    function test_IsOnCurve() public pure {
        assertFalse(
            Secp256k1.isOnCurve(
                0x0000000000000000000000000000000000000000000000000000000000000000,
                0x8F537EEFDFC1606A0727CD69B4A7333D38ED44E3932A7179EECB4B6FBA9360DC
            )
        );
        assertTrue(
            Secp256k1.isOnCurve(
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE
            )
        );
        assertTrue(
            Secp256k1.isOnCurve(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F,
                0x3D46AAE46A6F4DCAACFE1578992912987E8163D89AE03ADB5A15889213AB2B8C
            )
        );
        assertTrue(
            Secp256k1.isOnCurve(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
                0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E
            )
        );
        assertTrue(
            Secp256k1.isOnCurve(
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2C,
                0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D
            )
        );
    }

    function test_IsValidScalar() public pure {
        assertTrue(Secp256k1.isValidScalar(0));
        assertTrue(Secp256k1.isValidScalar(Secp256k1.N - 1));
        assertFalse(Secp256k1.isValidScalar(Secp256k1.N));
    }

    function test_IsValidNonZeroScalar() public pure {
        assertFalse(Secp256k1.isValidNonZeroScalar(0));
        assertTrue(Secp256k1.isValidNonZeroScalar(Secp256k1.N - 1));
        assertFalse(Secp256k1.isValidNonZeroScalar(Secp256k1.N));
    }

    function test_YParity() public pure {
        assertEq(Secp256k1.yParity(0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E), 0);
        assertEq(Secp256k1.yParity(0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D), 1);
    }

    function test_YParityEthereum() public pure {
        assertEq(Secp256k1.yParityEthereum(0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E), 27);
        assertEq(Secp256k1.yParityEthereum(0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D), 28);
    }

    function test_YCompressed() public pure {
        assertEq(Secp256k1.yCompressed(0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E), 2);
        assertEq(Secp256k1.yCompressed(0x0E994B14EA72F8C3EB95C71EF692575E775058332D7E52D0995CF8038871B67D), 3);
    }

    function test_ToAddress() public pure {
        // public key taken from https://github.com/ethereum/eth-keys/blob/main/README.md#quickstart
        assertEq(
            Secp256k1.toAddress(
                0x1B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F,
                0x70BEAF8F588B541507FED6A642C5AB42DFDF8120A7F639DE5122D47A69A8E8D1
            ),
            uint256(uint160(address(0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1)))
        );
    }
}
