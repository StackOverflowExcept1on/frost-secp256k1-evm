// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {Hashes} from "src/utils/cryptography/Hashes.sol";
import {Memory} from "src/utils/Memory.sol";

contract HashesTest is Test {
    function test_efficientKeccak256WithMemory() public pure {
        uint256 memPtr = Memory.allocate(32);
        Memory.writeWord(memPtr, 0x00, 42);
        assertEq(Hashes.efficientKeccak256(memPtr, 0x00, 32), uint256(keccak256(abi.encodePacked(uint256(42)))));
    }

    function test_efficientKeccak256WithoutMemory1() public pure {
        assertEq(Hashes.efficientKeccak256(41), uint256(keccak256(abi.encodePacked(uint256(41)))));
    }

    function test_efficientKeccak256WithoutMemory2() public pure {
        assertEq(Hashes.efficientKeccak256(41, 42), uint256(keccak256(abi.encodePacked(uint256(41), uint256(42)))));
    }
}
