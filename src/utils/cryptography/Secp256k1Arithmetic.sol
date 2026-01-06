// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ModExp} from "./ModExp.sol";
import {Secp256k1} from "./Secp256k1.sol";

/**
 * @dev Library for interaction with secp256k1 elliptic curve arithmetic.
 */
library Secp256k1Arithmetic {
    /**
     * @dev Curve parameter `b = 7`.
     */
    uint256 internal constant B = Secp256k1.B;
    /**
     * @dev Prime number, public key `(x, y)`, where `(x, y)` must be in `[0, Secp256k1.P)`.
     */
    uint256 internal constant P = Secp256k1.P;
    /**
     * @dev Auxiliary constant $b_3 = 3 \cdot b$, used in Renes-Costello-Batina 2015.
     * @dev Renes-Costello-Batina 2015 ("Complete addition formulas for prime order elliptic curves"):
     *      - https://eprint.iacr.org/2015/1060.pdf
     */
    uint256 internal constant B3 = 3 * B;
    /**
     * @dev Auxiliary constant $p - 2$, used to calculate modular inversion
     *      by formula $a^{p - 2} = a^{-1}$.
     * @dev Dubois 2023 ("Speeding up elliptic computations for Ethereum Account Abstraction"):
     *      (section 2.2 "Additional dedicated optimizations", subsection "Modular inversion")
     *      - https://eprint.iacr.org/2023/939.pdf
     */
    uint256 internal constant P_MINUS_2 = P - 2;
    /**
     * @dev Auxiliary constant $\frac{p + 1}{4}$, used during point decompression.
     * @dev Square root of an secp256k1 field element `x` can be computed via `modexp(x, SQRT_EXPONENT, P)`:
     *      - https://github.com/ethereum/eth-keys/blob/v0.7.0/eth_keys/backends/native/ecdsa.py#L164
     *      - https://github.com/RustCrypto/elliptic-curves/blob/k256/v0.13.4/k256/src/arithmetic/field.rs#L206
     */
    uint256 internal constant SQRT_EXPONENT = (P + 1) / 4;

    /**
     * @dev Returns additive identity in affine coordinates.
     *      The identity point in affine coordinates is represented as `(x, y) = (0, 0)`,
     *      but this point is not on curve: `Secp256k1.isOnCurve(0, 0) == false`
     *      (identity point is not valid public key).
     * @return x Affine point x.
     * @return y Affine point y.
     */
    function identityAffinePoint() internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    /**
     * @dev Returns whether point `(x, y)` is identity in affine coordinates.
     * @param x Affine point x.
     * @param y Affine point y.
     * @return isIdentity `true` if point is identity, `false` otherwise.
     */
    function isIdentityAffinePoint(uint256 x, uint256 y) internal pure returns (bool) {
        return (x | y) == 0;
    }

    /**
     * @dev Converts affine point `(x1, y1)` to projective point `(x2, y2, z2)`.
     * @param x1 Affine point x1.
     * @param y1 Affine point y1.
     * @return x2 Projective point x2.
     * @return y2 Projective point y2.
     * @return z2 Projective point z2.
     */
    function convertAffinePointToProjectivePoint(uint256 x1, uint256 y1)
        internal
        pure
        returns (uint256, uint256, uint256)
    {
        if (isIdentityAffinePoint(x1, y1)) {
            return identityProjectivePoint();
        }

        return (x1, y1, 1);
    }

    /**
     * @dev Returns additive identity in projective coordinates.
     *      The identity point in projective coordinates is represented as `(x, y, z) = (0, 1, 0)`.
     * @return x Projective point x.
     * @return y Projective point y.
     * @return z Projective point z.
     */
    function identityProjectivePoint() internal pure returns (uint256, uint256, uint256) {
        return (0, 1, 0);
    }

    /**
     * @dev Returns whether point `(x, z)` is identity in projective coordinates.
     * @param x Projective point x.
     * @param z Projective point z.
     * @return isIdentity `true` if point is identity, `false` otherwise.
     */
    function isIdentityProjectivePoint(uint256 x, uint256 z) internal pure returns (bool) {
        return (x | z) == 0;
    }

    /**
     * @dev Converts projective point `(x1, y1, z1)` to affine point `(x2, y2)`.
     * @param memPtr Memory pointer for writing 192 bytes of input data.
     * @param x1 Projective point x1.
     * @param y1 Projective point y1.
     * @param z1 Projective point z1.
     * @return x2 Affine point x2.
     * @return y2 Affine point y2.
     */
    function convertProjectivePointToAffinePoint(uint256 memPtr, uint256 x1, uint256 y1, uint256 z1)
        internal
        view
        returns (uint256, uint256)
    {
        if (isIdentityProjectivePoint(x1, z1)) {
            return identityAffinePoint();
        }

        // `z1 != 0` because `isIdentityProjectivePoint(x1, z1)` is checked above.
        // see Dubois 2023 ("Speeding up elliptic computations for Ethereum Account Abstraction")
        // for details about modular inversion optimization.
        uint256 z1Inv = ModExp.modexp(memPtr, z1, P_MINUS_2, P);

        uint256 x2 = mulmod(x1, z1Inv, P);
        uint256 y2 = mulmod(y1, z1Inv, P);

        return (x2, y2);
    }

    /**
     * @dev Decompresses compressed affine point `(x, yCompressed)` to affine point `(x2, y2)`.
     * @dev Reverts if `yCompressed` is not `2` or `3`, or if decompressed point is not on curve.
     * @param memPtr Memory pointer for writing 192 bytes of input data.
     * @param x Affine point x.
     * @param yCompressed Affine point y (compressed).
     * @return x2 Affine point x2.
     * @return y2 Affine point y2.
     */
    function decompressToAffinePoint(uint256 memPtr, uint256 x, uint256 yCompressed)
        internal
        view
        returns (uint256, uint256)
    {
        require(yCompressed == 2 || yCompressed == 3);

        // https://github.com/RustCrypto/elliptic-curves/blob/k256/v0.13.4/k256/src/arithmetic/affine.rs#L187
        uint256 alpha = addmod(mulmod(x, mulmod(x, x, P), P), B, P);
        // https://github.com/ethereum/eth-keys/blob/v0.7.0/eth_keys/backends/native/ecdsa.py#L165
        uint256 beta = ModExp.modexp(memPtr, alpha, SQRT_EXPONENT, P);

        uint256 y;
        unchecked {
            y = beta & 1 == yCompressed & 1 ? beta : P - beta;
        }

        require(Secp256k1.isOnCurve(x, y));

        return (x, y);
    }

    /**
     * @dev Returns sum of projective points `(x1, y1, z1)` and `(x2, y2, z2)`
     *      as projective point `(x3, y3, z3)`.
     * @dev Uses algorithm 7 from Renes-Costello-Batina 2015 based on a
     *      complete addition formula for Weierstrass curves with a = 0.
     * @param x1 Projective point x1.
     * @param y1 Projective point y1.
     * @param z1 Projective point z1.
     * @param x2 Projective point x2.
     * @param y2 Projective point y2.
     * @param z2 Projective point z2.
     * @return x3 Projective point x3.
     * @return y3 Projective point y3.
     * @return z3 Projective point z3.
     */
    function addProjectivePoint(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2, uint256 z2)
        internal
        pure
        returns (uint256, uint256, uint256)
    {
        if (isIdentityProjectivePoint(x1, z1)) {
            return (x2, y2, z2);
        }

        if (isIdentityProjectivePoint(x2, z2)) {
            return (x1, y1, z1);
        }

        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060.pdf Algorithm 7).

        uint256 x3;
        uint256 y3;
        uint256 z3;

        uint256 t0;
        uint256 t1;
        uint256 t2;
        uint256 t3;
        uint256 t4;

        t0 = mulmod(x1, x2, P);
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = addmod(x2, y2, P);
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        unchecked {
            t3 = addmod(t3, P - t4, P);
        }
        t4 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P);
        t4 = mulmod(t4, x3, P);
        x3 = addmod(t1, t2, P);
        unchecked {
            t4 = addmod(t4, P - x3, P);
        }
        x3 = addmod(x1, z1, P);
        y3 = addmod(x2, z2, P);
        x3 = mulmod(x3, y3, P);
        y3 = addmod(t0, t2, P);
        unchecked {
            y3 = addmod(x3, P - y3, P);
        }
        x3 = addmod(t0, t0, P);
        t0 = addmod(x3, t0, P);
        t2 = mulmod(B3, t2, P);
        z3 = addmod(t1, t2, P);
        unchecked {
            t1 = addmod(t1, P - t2, P);
        }
        y3 = mulmod(B3, y3, P);
        x3 = mulmod(t4, y3, P);
        t2 = mulmod(t3, t1, P);
        unchecked {
            x3 = addmod(t2, P - x3, P);
        }
        y3 = mulmod(y3, t0, P);
        t1 = mulmod(t1, z3, P);
        y3 = addmod(t1, y3, P);
        t0 = mulmod(t0, t3, P);
        z3 = mulmod(z3, t4, P);
        z3 = addmod(z3, t0, P);

        return (x3, y3, z3);
    }

    /**
     * @dev Returns doubled projective point `(x, y, z)`
     *      as projective point `(x1, y1, z1)`.
     * @dev Uses algorithm 9 from Renes-Costello-Batina 2015 based on a
     *      point doubling formula Weierstrass curves with a = 0.
     * @param x Projective point x.
     * @param y Projective point y.
     * @param z Projective point z.
     * @return x1 Projective point x1.
     * @return y1 Projective point y1.
     * @return z1 Projective point z1.
     */
    function doubleProjectivePoint(uint256 x, uint256 y, uint256 z) internal pure returns (uint256, uint256, uint256) {
        if (isIdentityProjectivePoint(x, z)) {
            return (x, y, z);
        }

        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060.pdf Algorithm 9).

        uint256 x3;
        uint256 y3;
        uint256 z3;

        uint256 t0;
        uint256 t1;
        uint256 t2;

        t0 = mulmod(y, y, P);
        z3 = addmod(t0, t0, P);
        z3 = addmod(z3, z3, P);
        z3 = addmod(z3, z3, P);
        t1 = mulmod(y, z, P);
        t2 = mulmod(z, z, P);
        t2 = mulmod(B3, t2, P);
        x3 = mulmod(t2, z3, P);
        y3 = addmod(t0, t2, P);
        z3 = mulmod(t1, z3, P);
        t1 = addmod(t2, t2, P);
        t2 = addmod(t1, t2, P);
        unchecked {
            t0 = addmod(t0, P - t2, P);
        }
        y3 = mulmod(t0, y3, P);
        y3 = addmod(x3, y3, P);
        t1 = mulmod(x, y, P);
        x3 = mulmod(t0, t1, P);
        x3 = addmod(x3, x3, P);

        return (x3, y3, z3);
    }

    /**
     * @dev Returns product of projective point `(x1, y1, z1)` and scalar `scalar`
     *      as projective point.
     * @dev Uses the repeated double-and-add algorithm:
     *      - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
     * @param x1 Projective point x1.
     * @param y1 Projective point y1.
     * @param z1 Projective point z1.
     * @param scalar Scalar.
     * @return x2 Projective point x2.
     * @return y2 Projective point y2.
     * @return z2 Projective point z2.
     */
    function mulProjectivePoint(uint256 x1, uint256 y1, uint256 z1, uint256 scalar)
        internal
        pure
        returns (uint256, uint256, uint256)
    {
        (uint256 resultX, uint256 resultY, uint256 resultZ) = identityProjectivePoint();

        while (scalar != 0) {
            if (scalar & 1 == 1) {
                (resultX, resultY, resultZ) = addProjectivePoint(resultX, resultY, resultZ, x1, y1, z1);
            }
            scalar >>= 1;
            (x1, y1, z1) = doubleProjectivePoint(x1, y1, z1);
        }

        return (resultX, resultY, resultZ);
    }

    /**
     * @dev Returns product of affine point `(x1, y1)` and scalar `scalar`
     *      as projective point.
     * @param x1 Affine point x1.
     * @param y1 Affine point y1.
     * @param scalar Scalar.
     * @return x2 Projective point x2.
     * @return y2 Projective point y2.
     * @return z2 Projective point z2.
     */
    function mulAffinePointAsProjective(uint256 x1, uint256 y1, uint256 scalar)
        internal
        pure
        returns (uint256, uint256, uint256)
    {
        (uint256 x1Projective, uint256 y1Projective, uint256 z1Projective) = convertAffinePointToProjectivePoint(x1, y1);
        return mulProjectivePoint(x1Projective, y1Projective, z1Projective, scalar);
    }

    /**
     * @dev Returns product of affine point `(x1, y1)` and scalar `scalar`
     *      as affine point.
     * @param memPtr Memory pointer for writing 192 bytes of input data.
     * @param x1 Affine point x1.
     * @param y1 Affine point y1.
     * @param scalar Scalar.
     * @return x2 Affine point x2.
     * @return y2 Affine point y2.
     */
    function mulAffinePoint(uint256 memPtr, uint256 x1, uint256 y1, uint256 scalar)
        internal
        view
        returns (uint256, uint256)
    {
        (uint256 x2Projective, uint256 y2Projective, uint256 z2Projective) = mulAffinePointAsProjective(x1, y1, scalar);
        (uint256 x2, uint256 y2) = convertProjectivePointToAffinePoint(memPtr, x2Projective, y2Projective, z2Projective);
        return (x2, y2);
    }
}
