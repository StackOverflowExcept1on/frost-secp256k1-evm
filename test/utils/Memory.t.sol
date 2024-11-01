// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Memory} from "src/utils/Memory.sol";

contract MemoryTest is Test {
    function test_Allocate() public pure {
        Memory.allocate(41);
    }

    function test_AllocateWithPointerCheck() public pure {
        uint256 memPtr1 = Memory.allocate(41);
        vm.assertEq(memPtr1, 0x80);

        uint256 memPtr2 = Memory.allocate(42);
        vm.assertEq(memPtr2, 0xC0);
    }

    function testFails_AllocateWithOverflow() public pure {
        Memory.allocate(type(uint64).max);
    }

    function test_Zeroize() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeWord(memPtr, 0x00, 42);
        vm.assertEq(Memory.readWord(memPtr, 0x00), 42);

        Memory.zeroize(memPtr, 32);
        vm.assertEq(Memory.readWord(memPtr, 0x00), 0);
    }

    function test_ReadWriteWord() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeWord(memPtr, 0x00, 42);
        vm.assertEq(Memory.readWord(memPtr, 0x00), 42);
    }

    function test_ReadWriteByte() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeByte(memPtr, 31, 0xffee);
        vm.assertEq(Memory.readWord(memPtr, 0x00), 0xee);
    }
}
