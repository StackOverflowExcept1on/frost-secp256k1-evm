// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library Memory {
    function allocate(uint256 size) internal pure returns (uint256 memPtr) {
        assembly ("memory-safe") {
            memPtr := mload(0x40)
            let newFreePtr := add(memPtr, and(add(size, 31), not(31)))
            if or(gt(newFreePtr, 0xffffffffffffffff), lt(newFreePtr, memPtr)) { revert(0, 0) }
            mstore(0x40, newFreePtr)
        }
    }

    function zeroize(uint256 dataStart, uint256 dataSizeInBytes) internal pure {
        assembly ("memory-safe") {
            calldatacopy(dataStart, calldatasize(), dataSizeInBytes)
        }
    }

    function writeWord(uint256 memPtr, uint256 offset, uint256 value) internal pure {
        assembly ("memory-safe") {
            mstore(add(memPtr, offset), value)
        }
    }

    function writeByte(uint256 memPtr, uint256 offset, uint256 value) internal pure {
        assembly ("memory-safe") {
            mstore8(add(memPtr, offset), value)
        }
    }
}
