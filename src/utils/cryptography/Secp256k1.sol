// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Hashes} from "./Hashes.sol";

/**
 * @dev Library for interaction with secp256k1 elliptic curve,
 *      described by equation `y^2 = x^3 + ax + b (mod p)`
 *      where `a = 0` and `b = 7`.
 * @dev Curve parameters taken from:
 *      - https://en.bitcoin.it/wiki/Secp256k1
 *      - https://github.com/ethereum/go-ethereum/blob/v1.16.7/crypto/secp256k1/curve.go#L263
 */
library Secp256k1 {
    /**
     * @dev Curve parameter `a = 0`.
     */
    uint256 internal constant A = 0x0000000000000000000000000000000000000000000000000000000000000000;
    /**
     * @dev Curve parameter `b = 7`.
     */
    uint256 internal constant B = 0x0000000000000000000000000000000000000000000000000000000000000007;
    /**
     * @dev Prime number, public key `(x, y)`, where `(x, y)` must be in `[0, Secp256k1.P)`.
     */
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    /**
     * @dev Prime number, scalar `s` must be in `[0, Secp256k1.N)`, non-zero scalar must be in `[1, Secp256k1.N)`.
     */
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /**
     * @dev X coordinate of generator point (`G`).
     */
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    /**
     * @dev Y coordinate of generator point (`G`).
     */
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /**
     * @dev Checks if public key `(x, y)` is on curve.
     * @param x Public key x.
     * @param y Public key y.
     * @return isOnCurve `true` if public key is on curve, `false` otherwise.
     */
    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        // https://github.com/ethereum/go-ethereum/blob/v1.16.7/crypto/secp256k1/curve.go#L75
        return mulmod(y, y, P) == addmod(mulmod(x, mulmod(x, x, P), P), B, P);
    }

    /**
     * @dev Checks if `scalar` is valid (`scalar` in `[0, Secp256k1.N)`).
     * @param scalar Scalar.
     * @return isValidScalar `true` if `scalar` is valid, `false` otherwise.
     */
    function isValidScalar(uint256 scalar) internal pure returns (bool) {
        return scalar < N;
    }

    /**
     * @dev Checks if `scalar` is valid non-zero scalar (`scalar` in `[1, Secp256k1.N)`).
     * @param scalar Scalar.
     * @return isValidNonZeroScalar `true` if `scalar` is valid non-zero scalar, `false` otherwise.
     */
    function isValidNonZeroScalar(uint256 scalar) internal pure returns (bool) {
        return scalar != 0 && scalar < N;
    }

    /**
     * @dev Calculates `yParity` from public key y.
     * @param y Public key y.
     * @return yParity `0` if `y` is even, `1` if `y` is odd.
     */
    function yParity(uint256 y) internal pure returns (uint256) {
        return y & 1;
    }

    /**
     * @dev Calculates `yParity` for Ethereum from public key y.
     * @param y Public key y.
     * @return ethereumYParity `27` if `y` is even, `28` if `y` is odd.
     */
    function yParityEthereum(uint256 y) internal pure returns (uint256) {
        // https://github.com/ethereum/go-ethereum/blob/v1.16.7/core/vm/contracts.go#L294
        uint256 ethereumYParity;
        unchecked {
            ethereumYParity = yParity(y) + 27;
        }
        return ethereumYParity;
    }

    /**
     * @dev Calculates compressed `y`.
     * @param y Public key y.
     * @return compressedY Compressed `y`, `2` if `y` is even, `3` if `y` is odd.
     */
    function yCompressed(uint256 y) internal pure returns (uint256) {
        // https://github.com/ethereum/go-ethereum/blob/v1.16.7/crypto/secp256k1/libsecp256k1/src/eckey_impl.h#L46
        // https://github.com/ethereum/go-ethereum/blob/v1.16.7/crypto/secp256k1/libsecp256k1/include/secp256k1.h#L215-L217
        uint256 compressedY;
        unchecked {
            compressedY = yParity(y) + 2;
        }
        return compressedY;
    }

    /**
     * @dev Computes Ethereum address from full public key `(x, y)`.
     * @param x Public key x.
     * @param y Public key y.
     * @return addr Ethereum address.
     */
    function toAddress(uint256 x, uint256 y) internal pure returns (uint256 addr) {
        // https://github.com/ethereum/go-ethereum/blob/v1.16.7/core/vm/contracts.go#L313
        uint256 fullHash = Hashes.efficientKeccak256(x, y);
        assembly ("memory-safe") {
            // addr = fullHash & ((1 << 160) - 1)
            addr := and(fullHash, sub(shl(160, 1), 1))
        }
    }
}
