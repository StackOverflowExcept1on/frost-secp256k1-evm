// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @dev Library for low-level memory interaction.
 */
library Memory {
    /**
     * @dev Allocates chunk of memory of given size, size aligned to 32 bytes.
     * @dev Reverts if aligned size + free memory pointer exceeds `type(uint64).max`.
     * @param size Size of memory chunk to allocate.
     * @return memPtr Pointer to allocated memory.
     */
    function allocate(uint256 size) internal pure returns (uint256 memPtr) {
        // https://github.com/ethereum/solidity/blob/v0.8.28/libsolidity/codegen/YulUtilFunctions.cpp#L3194
        assembly ("memory-safe") {
            // https://github.com/ethereum/solidity/blob/v0.8.28/libsolidity/codegen/YulUtilFunctions.cpp#L3211
            memPtr := mload(0x40)
            // https://github.com/ethereum/solidity/blob/v0.8.28/libsolidity/codegen/YulUtilFunctions.cpp#L3226
            // https://github.com/ethereum/solidity/blob/v0.8.28/libsolidity/codegen/YulUtilFunctions.cpp#L693
            let newFreePtr := add(memPtr, and(add(size, 31), not(31)))
            if or(gt(newFreePtr, 0xFFFFFFFFFFFFFFFF), lt(newFreePtr, memPtr)) { revert(0x00, 0x00) }
            mstore(0x40, newFreePtr)
        }
    }

    /**
     * @dev Zeroizes chunk of memory.
     * @param dataStart Pointer to memory.
     * @param dataSizeInBytes Size of memory chunk to zeroize.
     */
    function zeroize(uint256 dataStart, uint256 dataSizeInBytes) internal pure {
        // https://github.com/ethereum/solidity/blob/v0.8.28/libsolidity/codegen/YulUtilFunctions.cpp#L3253
        assembly ("memory-safe") {
            calldatacopy(dataStart, calldatasize(), dataSizeInBytes)
        }
    }

    /**
     * @dev Reads word from memory at given offset.
     * @param memPtr Pointer to memory.
     * @param offset Offset in memory.
     * @return word Word from memory.
     */
    function readWord(uint256 memPtr, uint256 offset) internal pure returns (uint256 word) {
        // https://evm.codes/#51
        assembly ("memory-safe") {
            word := mload(add(memPtr, offset))
        }
    }

    /**
     * @dev Writes word to memory at given offset.
     * @param memPtr Pointer to memory.
     * @param offset Offset in memory.
     * @param value Word to write.
     */
    function writeWord(uint256 memPtr, uint256 offset, uint256 value) internal pure {
        // https://evm.codes/#52
        assembly ("memory-safe") {
            mstore(add(memPtr, offset), value)
        }
    }

    /**
     * @dev Writes byte to memory at given offset.
     * @param memPtr Pointer to memory.
     * @param offset Offset in memory.
     * @param value Byte to write.
     */
    function writeByte(uint256 memPtr, uint256 offset, uint256 value) internal pure {
        // https://evm.codes/#53
        assembly ("memory-safe") {
            mstore8(add(memPtr, offset), value)
        }
    }
}
