// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @dev Library for low-level interaction with standard hash functions.
 */
library Hashes {
    /**
     * @dev Hashes memory chunk using `keccak256` instruction.
     * @param memPtr Pointer to memory.
     * @param offset Offset in memory.
     * @param size Size of memory chunk to hash.
     * @return value Hash of memory chunk.
     */
    function efficientKeccak256(uint256 memPtr, uint256 offset, uint256 size) internal pure returns (uint256 value) {
        assembly ("memory-safe") {
            // https://evm.codes/#20
            value := keccak256(add(memPtr, offset), size)
        }
    }

    /**
     * @dev Implementation of `keccak256(abi.encode(a, b))` that doesn't allocate or expand memory.
     * @param a First value to hash.
     * @param b Second value to hash.
     * @return value Hash of first and second values.
     */
    function efficientKeccak256(uint256 a, uint256 b) internal pure returns (uint256 value) {
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.2.0/contracts/utils/cryptography/Hashes.sol
        assembly ("memory-safe") {
            // https://evm.codes/#52
            mstore(0x00, a)
            mstore(0x20, b)
            // https://evm.codes/#20
            value := keccak256(0x00, 0x40)
        }
    }
}
