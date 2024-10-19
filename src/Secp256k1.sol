// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library Secp256k1 {
    uint256 internal constant B = 7;
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        return mulmod(y, y, P) == addmod(mulmod(x, mulmod(x, x, P), P), B, P);
    }

    function yParity(uint256 y) internal pure returns (uint256) {
        return y & 1;
    }

    function yCompressed(uint256 y) internal pure returns (uint256) {
        uint256 compressedY;
        unchecked {
            compressedY = yParity(y) + 2;
        }
        return compressedY;
    }

    function toAddress(uint256 x, uint256 y) internal pure returns (uint256 addr) {
        assembly ("memory-safe") {
            mstore(0x00, x)
            mstore(0x20, y)
            addr := and(keccak256(0x00, 0x40), sub(shl(160, 1), 1))
        }
    }
}
