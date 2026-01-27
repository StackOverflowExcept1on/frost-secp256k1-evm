// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {Memory} from "src/utils/Memory.sol";
import {ModExp} from "src/utils/cryptography/ModExp.sol";

contract ModExpTest is Test {
    function test_ModExpSimpleMod1024() public view {
        uint256 memPtr = Memory.allocate(192);
        uint256 base = 2;
        uint256 exponent = 9;
        uint256 modulus = 1024;
        assertEq(ModExp.modexp(memPtr, base, exponent, modulus), 512);
    }

    function test_ModExpSimpleMod10() public view {
        uint256 memPtr = Memory.allocate(192);
        uint256 base = 2;
        uint256 exponent = 9;
        uint256 modulus = 10;
        assertEq(ModExp.modexp(memPtr, base, exponent, modulus), 2);
    }

    function test_ModExpZeroToThePowerOfZero() public view {
        uint256 memPtr = Memory.allocate(192);
        uint256 base = 0;
        uint256 exponent = 0;
        uint256 modulus = 42;
        assertEq(ModExp.modexp(memPtr, base, exponent, modulus), 1);
    }

    function test_ModExpMod0() public view {
        uint256 memPtr = Memory.allocate(192);
        uint256 base = 2;
        uint256 exponent = 9;
        uint256 modulus = 0;
        assertEq(ModExp.modexp(memPtr, base, exponent, modulus), 0);
    }
}
