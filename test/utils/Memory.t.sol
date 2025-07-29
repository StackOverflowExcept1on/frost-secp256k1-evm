// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Memory} from "src/utils/Memory.sol";

contract MemoryTest is Test {
    function test_AllocateUnbounded() public pure {
        Memory.allocateUnbounded();
    }

    function test_AllocateUnboundedWithPointerCheck() public pure {
        uint256 memPtr1 = Memory.allocateUnbounded();
        assertEq(memPtr1, 0x80);

        uint256 memPtr2 = Memory.allocateUnbounded();
        assertEq(memPtr2, 0x80);
    }

    function test_Allocate() public pure {
        Memory.allocate(41);
    }

    function test_AllocateWithPointerCheck() public pure {
        uint256 memPtr1 = Memory.allocate(41);
        assertEq(memPtr1, 0x80);

        uint256 memPtr2 = Memory.allocate(42);
        assertEq(memPtr2, 0xC0);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_AllocateWithOverflow() public {
        vm.expectRevert();
        Memory.allocate(type(uint64).max);
    }

    function test_Zeroize() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeWord(memPtr, 0x00, 42);
        assertEq(Memory.readWord(memPtr, 0x00), 42);

        Memory.zeroize(memPtr, 32);
        assertEq(Memory.readWord(memPtr, 0x00), 0);
    }

    function test_ReadWriteWord() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeWord(memPtr, 0x00, 42);
        assertEq(Memory.readWord(memPtr, 0x00), 42);
    }

    function test_ReadWriteByte() public pure {
        uint256 memPtr = Memory.allocate(32);

        Memory.writeByte(memPtr, 31, 0xffee);
        assertEq(Memory.readWord(memPtr, 0x00), 0xee);
    }
}
