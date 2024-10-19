// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library Hashes {
    function rawKeccak256(uint256 memPtr, uint256 offset, uint256 size) internal pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := keccak256(add(memPtr, offset), size)
        }
    }
}
