// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test, Vm} from "forge-std/Test.sol";
import {ChaChaRngOffchain} from "src/utils/cryptography/ChaChaRngOffchain.sol";
import {Secp256k1} from "src/utils/cryptography/Secp256k1.sol";
import {Secp256k1Arithmetic} from "src/utils/cryptography/Secp256k1Arithmetic.sol";
import {Memory} from "src/utils/Memory.sol";

contract Secp256k1ArithmeticWrapper {
    function decompressToAffinePoint(uint256 memPtr, uint256 x, uint256 yCompressed)
        external
        view
        returns (uint256, uint256)
    {
        return Secp256k1Arithmetic.decompressToAffinePoint(memPtr, x, yCompressed);
    }
}

contract Secp256k1ArithmeticTest is Test {
    function test_IdentityAffinePoint() public pure {
        (uint256 x, uint256 y) = Secp256k1Arithmetic.identityAffinePoint();
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x, y));
        assertEq(x, 0);
        assertEq(y, 0);
    }

    function test_IsIdentityAffinePoint() public pure {
        (uint256 x, uint256 y) = Secp256k1Arithmetic.identityAffinePoint();
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x, y));
        assertFalse(Secp256k1Arithmetic.isIdentityAffinePoint(type(uint256).max, type(uint256).max));
    }

    function test_ConvertAffinePointToProjectivePointIdentity() public pure {
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.identityAffinePoint();
        (uint256 x2,, uint256 z2) = Secp256k1Arithmetic.convertAffinePointToProjectivePoint(x1, y1);
        assertTrue(Secp256k1Arithmetic.isIdentityProjectivePoint(x2, z2));
    }

    function test_ConvertAffinePointToProjectivePointNotIdentity() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        (uint256 x2, uint256 y2, uint256 z2) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(wallet.publicKeyX, wallet.publicKeyY);
        assertEq(x2, wallet.publicKeyX);
        assertEq(y2, wallet.publicKeyY);
        assertEq(z2, 1);
    }

    function test_IdentityProjectivePoint() public pure {
        (uint256 x, uint256 y, uint256 z) = Secp256k1Arithmetic.identityProjectivePoint();
        assertTrue(Secp256k1Arithmetic.isIdentityProjectivePoint(x, z));
        assertEq(x, 0);
        assertEq(y, 1);
        assertEq(z, 0);
    }

    function test_IsIdentityProjectivePoint() public pure {
        (uint256 x,, uint256 z) = Secp256k1Arithmetic.identityProjectivePoint();
        assertTrue(Secp256k1Arithmetic.isIdentityProjectivePoint(x, z));
        assertFalse(Secp256k1Arithmetic.isIdentityProjectivePoint(type(uint256).max, type(uint256).max));
    }

    function test_ConvertProjectivePointToAffinePointIdentity() public view {
        (uint256 x1, uint256 y1, uint256 z1) = Secp256k1Arithmetic.identityProjectivePoint();
        uint256 memPtr = Memory.allocate(192);
        (uint256 x2, uint256 y2) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x1, y1, z1);
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x2, y2));
    }

    function test_ConvertProjectivePointToAffinePointZEqOne() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        uint256 memPtr = Memory.allocate(192);
        uint256 x1 = wallet.publicKeyX;
        uint256 y1 = wallet.publicKeyY;
        uint256 z1 = 1;
        (uint256 x2, uint256 y2) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x1, y1, z1);
        assertEq(x2, x1);
        assertEq(y2, y1);
    }

    function test_ConvertProjectivePointToAffinePointZNotEqOne() public {
        uint256 scalar = 2;
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(Secp256k1.GX, Secp256k1.GY);
        (uint256 x2, uint256 y2, uint256 z2) = Secp256k1Arithmetic.doubleProjectivePoint(x1, y1, z1);
        assertNotEq(z2, 1);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x3, uint256 y3) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x2, y2, z2);
        assertEq(x3, wallet.publicKeyX);
        assertEq(y3, wallet.publicKeyY);
    }

    function test_DecompressToAffinePoint() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.decompressToAffinePoint(
            memPtr, wallet.publicKeyX, Secp256k1.yCompressed(wallet.publicKeyY)
        );
        assertEq(x1, wallet.publicKeyX);
        assertEq(y1, wallet.publicKeyY);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_DecompressToAffinePointIncorrectYCompressed() public {
        uint256 memPtr = Memory.allocate(192);
        uint256 x = 1; // x = 1 is on curve
        uint256 yCompressed = 0; // invalid yCompressed
        vm.expectRevert();
        Secp256k1Arithmetic.decompressToAffinePoint(memPtr, x, yCompressed);
    }

    function test_DecompressToAffinePointIncorrectX() public {
        // unfortunately, here we have to use wrapper contract to test revert
        Secp256k1ArithmeticWrapper wrapper = new Secp256k1ArithmeticWrapper();
        uint256 memPtr = Memory.allocate(192);
        uint256 x = 0; // x = 0 is not on curve
        uint256 yCompressed = 2; // valid yCompressed
        vm.expectRevert();
        wrapper.decompressToAffinePoint(memPtr, x, yCompressed);
    }

    function test_AddProjectivePoint() public {
        uint256 scalar1 = 2;
        Vm.Wallet memory wallet1 = vm.createWallet(scalar1);
        uint256 scalar2 = 3;
        Vm.Wallet memory wallet2 = vm.createWallet(scalar2);
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(Secp256k1.GX, Secp256k1.GY);
        (uint256 x2, uint256 y2, uint256 z2) = Secp256k1Arithmetic.addProjectivePoint(x1, y1, z1, x1, y1, z1);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x3, uint256 y3) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x2, y2, z2);
        assertEq(x3, wallet1.publicKeyX);
        assertEq(y3, wallet1.publicKeyY);
        (uint256 x4, uint256 y4, uint256 z4) = Secp256k1Arithmetic.addProjectivePoint(x2, y2, z2, x1, y1, z1);
        (uint256 x5, uint256 y5) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x4, y4, z4);
        assertEq(x5, wallet2.publicKeyX);
        assertEq(y5, wallet2.publicKeyY);
    }

    function test_DoubleProjectivePoint() public {
        uint256 scalar = 2;
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(Secp256k1.GX, Secp256k1.GY);
        (uint256 x2, uint256 y2, uint256 z2) = Secp256k1Arithmetic.doubleProjectivePoint(x1, y1, z1);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x3, uint256 y3) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x2, y2, z2);
        assertEq(x3, wallet.publicKeyX);
        assertEq(y3, wallet.publicKeyY);
    }

    function test_MulProjectivePointZeroScalar() public pure {
        uint256 scalar = 0;
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(Secp256k1.GX, Secp256k1.GY);
        (uint256 x2,, uint256 z2) = Secp256k1Arithmetic.mulProjectivePoint(x1, y1, z1, scalar);
        assertTrue(Secp256k1Arithmetic.isIdentityProjectivePoint(x2, z2));
    }

    function test_MulProjectivePointNonZeroScalar() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(Secp256k1.GX, Secp256k1.GY);
        (uint256 x2, uint256 y2, uint256 z2) = Secp256k1Arithmetic.mulProjectivePoint(x1, y1, z1, scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x3, uint256 y3) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x2, y2, z2);
        assertEq(x3, wallet.publicKeyX);
        assertEq(y3, wallet.publicKeyY);
    }

    function test_MulAffinePointAsProjectiveIdentityAffinePoint() public view {
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.identityAffinePoint();
        uint256 scalar = 1;
        (uint256 x2, uint256 y2, uint256 z2) = Secp256k1Arithmetic.mulAffinePointAsProjective(x1, y1, scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x3, uint256 y3) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x2, y2, z2);
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x3, y3));
    }

    function test_MulAffinePointAsProjectiveZeroScalar() public view {
        uint256 scalar = 0;
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.mulAffinePointAsProjective(Secp256k1.GX, Secp256k1.GY, scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x2, uint256 y2) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x1, y1, z1);
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x2, y2));
    }

    function test_MulAffinePointAsProjectiveNonZeroScalar() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        (uint256 x1, uint256 y1, uint256 z1) =
            Secp256k1Arithmetic.mulAffinePointAsProjective(Secp256k1.GX, Secp256k1.GY, scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x2, uint256 y2) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(memPtr, x1, y1, z1);
        assertEq(x2, wallet.publicKeyX);
        assertEq(y2, wallet.publicKeyY);
    }

    function test_MulAffinePointIdentityAffinePoint() public view {
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.identityAffinePoint();
        uint256 scalar = 1;
        uint256 memPtr = Memory.allocate(192);
        (uint256 x2, uint256 y2) = Secp256k1Arithmetic.mulAffinePoint(memPtr, x1, y1, scalar);
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x2, y2));
    }

    function test_MulAffinePointZeroScalar() public view {
        uint256 scalar = 0;
        uint256 memPtr = Memory.allocate(192);
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.mulAffinePoint(memPtr, Secp256k1.GX, Secp256k1.GY, scalar);
        assertTrue(Secp256k1Arithmetic.isIdentityAffinePoint(x1, y1));
    }

    function test_MulAffinePointNonZeroScalar() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        uint256 memPtr = Memory.allocate(192);
        (uint256 x1, uint256 y1) = Secp256k1Arithmetic.mulAffinePoint(memPtr, Secp256k1.GX, Secp256k1.GY, scalar);
        assertEq(x1, wallet.publicKeyX);
        assertEq(y1, wallet.publicKeyY);
    }
}
