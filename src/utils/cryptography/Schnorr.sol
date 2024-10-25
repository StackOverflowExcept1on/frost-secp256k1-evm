// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "./ECDSA.sol";
import {Secp256k1} from "./Secp256k1.sol";

/**
 * @dev Library for verifying Schnorr's signatures.
 */
library Schnorr {
    /**
     * @dev Checks if public key `(x, y)` is on curve and that `x < Secp256k1.N`.
     *      It also checks that `x % Secp256k1.N != 0`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @return isValidPublicKey `true` if public key is valid, `false` otherwise.
     */
    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool) {
        // `publicKeyX` is always in `[1, Secp256k1.N)` and valid non-zero scalar because:
        // 1. since `publicKeyX < Secp256k1.N`, then `publicKeyX % Secp256k1.N != 0`
        // 2. but what about `publicKeyX = 0`?
        //    since we also check `Secp256k1.isOnCurve(publicKeyX, publicKeyY)`,
        //    checking `publicKeyX != 0` is not needed because `publicKeyX = 0` is not on curve.
        //
        //    this statement can also be verified using script: based on
        //    ```python
        //    A = 0
        //    B = 7
        //    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        //    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        //
        //    x = 0
        //
        //    xcubedaxb = (x * x * x + A * x + B) % P
        //    beta = pow(xcubedaxb, (P + 1) // 4, P)
        //    y = beta # it can be `beta` or `beta - P`
        //    if (xcubedaxb - y * y) % P != 0:
        //        print("not on curve")
        //    ```
        //
        //    this script is based on code from eth-keys:
        //    https://github.com/ethereum/eth-keys/blob/d8d1ecc6e159dd1dd7b12d7a203f8a276fa2a8ba/eth_keys/backends/native/ecdsa.py#L165

        return publicKeyX < Secp256k1.N && Secp256k1.isOnCurve(publicKeyX, publicKeyY);
    }

    /**
     * @dev Checks if `signature.R` public key `(x, y)` is on curve.
     * @param signatureRX Public key x.
     * @param signatureRY Public key y.
     * @return isValidSignatureR `true` if `signature.R` public key is on curve, `false` otherwise.
     */
    function isValidSignatureR(uint256 signatureRX, uint256 signatureRY) internal pure returns (bool) {
        return Secp256k1.isOnCurve(signatureRX, signatureRY);
    }

    /**
     * @dev Checks if `multiplier % Secp256k1.N != 0`.
     * @param multiplier Multiplier.
     * @return isValidMultiplier `true` if `multiplier % Secp256k1.N != 0`, `false` otherwise.
     */
    function isValidMultiplier(uint256 multiplier) internal pure returns (bool) {
        return multiplier % Secp256k1.N != 0;
    }

    /**
     * @dev Verifies Schnorr signature by formula $zG - cX = R$.
     *      - Public key ($X$) must be checked with `Schnorr.isValidPublicKey(publicKeyX, publicKeyY)`.
     *      - Signature R ($R$) must be checked with `Schnorr.isValidSignatureR(signatureRX, signatureRY)`.
     *      - Signature Z ($z$) must be checked with `Schnorr.isValidMultiplier(signatureZ)`.
     *      - Challenge ($c$) must be checked with `Schnorr.isValidMultiplier(challenge)`.
     * @param memPtr Memory pointer for writing 128 bytes of input data.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @param signatureRX Signature R x.
     * @param signatureRY Signature R y.
     * @param signatureZ Signature Z.
     * @param challenge Challenge.
     * @return `true` if signature is valid, `false` otherwise.
     */
    function verifySignature(
        uint256 memPtr,
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        uint256 signatureZ,
        uint256 challenge
    ) internal view returns (bool) {
        // `e` is always in `[1, Secp256k1.N)` and is valid non-zero scalar because:
        //
        // `mulmod(a, b, Secp256k1.N)` or `(a * b) % N` is always in `[0, N)` for any `a`, `b`.
        // `(a * b) % N` can be simplified to `product % N`, right? `product % N` is always in `[0, N)`.
        // consider `product % 2`. remainder of division is `0` or `1`, but not `2`.
        //
        // consider `mulmod(a, b, Secp256k1.N)`:
        // - case 1 - minimum value of `mulmod(a, b, Secp256k1.N)` is `0`.
        // - case 2 - maximum value of `mulmod(a, b, Secp256k1.N)` is `Secp256k1.N - 1`.
        //
        // 1. minimum value of `mulmod(a, b, Secp256k1.N)` is `0`. it's not good because:
        //    `e` can go beyond valid non-zero scalar if `mulmod(a, b, Secp256k1.N) = 0`,
        //    then `e = Secp256k1.N - 0 = Secp256k1.N`, but `e` must be in `[1, Secp256k1.N)`.
        //
        //    when `mulmod(a, b, Secp256k1.N) = 0`?
        //    - `a = 0` or `b = 0`.
        //    - `a = 1` and `b = Secp256k1.N`.
        //    - `a = Secp256k1.N` and `b = 1`.
        //    - `a = k` and `b = Secp256k1.N`.
        //    - `a = Secp256k1.N` and `b = k`.
        //
        //    keep in mind that `Secp256k1.N` is prime number, i.e. it has 2 divisors: `1` and `Secp256k1.N`.
        //    `Secp256k1.N` can be obtained by multiplying it by `1` and no other way.
        //    `mulmod(k, Secp256k1.N, Secp256k1.N) = 0`, where `k` is any number, right?
        //    because product of `k` and `Secp256k1.N` always has `0` in remainder when divided by `Secp256k1.N`.
        //
        //    when `mulmod(a, b, Secp256k1.N) = 0`? it can be simplified to:
        //    - `a % Secp256k1.N = 0` or `b % Secp256k1.N = 0`.
        //
        //    this statement can also be verified using script:
        //    ```python
        //    p = 101 # prime number
        //
        //    for a in range(200):
        //        for b in range(200):
        //            if (a * b) % p == 0:
        //                assert a % p == 0 or b % p == 0
        //    ```
        //
        //    but `a % Secp256k1.N != 0` and `b % Secp256k1.N != 0` because it's checked with:
        //    - `Schnorr.isValidMultiplier(signatureZ)`.
        //    - `Schnorr.isValidPublicKey(publicKeyX, publicKeyY)`.
        //       it also checks `Schnorr.isValidMultiplier(publicKeyX)`
        //       (see `isValidPublicKey` implementation).
        //
        //    thus `mulmod(a, b, Secp256k1.N) != 0`.
        //
        //    minimum value of `mulmod(a, b, Secp256k1.N)` is `1`, not `0`.
        //    maximum value of `e` is `Secp256k1.N - 1`.
        //
        // 2. maximum value of `mulmod(a, b, Secp256k1.N)` is `Secp256k1.N - 1`. it's good because:
        //    minimum value of `e` is `e = Secp256k1.N - (Secp256k1.N - 1) = 1`.
        //
        // thus `e` is always in `[1, Secp256k1.N)` and is valid non-zero scalar if:
        // - `a % Secp256k1.N != 0` and `b % Secp256k1.N != 0`.
        //
        // since `e < Secp256k1.N` we can do `negmod(A) = (N - A) mod N)` without `mod N`.
        // `e = Secp256k1.N - mulmod_result` should be read as `-mulmod_result % Secp256k1.N`.
        // also see: https://us.metamath.org/mpeuni/negmod.html.
        uint256 e;
        unchecked {
            e = Secp256k1.N - mulmod(signatureZ, publicKeyX, Secp256k1.N);
        }

        // `v` is always `27` or `28`.
        uint256 v = Secp256k1.yParityEthereum(publicKeyY);

        // `r` is always in `[1, Secp256k1.N)` and valid non-zero scalar because
        // it's checked with `Schnorr.isValidPublicKey(publicKeyX, publicKeyY)`.
        uint256 r = publicKeyX;

        // `s` is always in `[1, Secp256k1.N)` and valid non-zero scalar because
        // it's described in more detail above (see `e`).
        uint256 s;
        unchecked {
            s = Secp256k1.N - mulmod(challenge, publicKeyX, Secp256k1.N);
        }

        // based on Vitalik Buterin's post about abusing `ecrecover` to do `ecmul`:
        // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384

        // Schnorr's signature structure:
        // https://github.com/ZcashFoundation/frost/blob/2d88edf1623ee29f671a43966aae0bd4ead2ea7a/frost-core/src/signature.rs#L9
        // Schnorr's challenge structure:
        // https://github.com/ZcashFoundation/frost/blob/2d88edf1623ee29f671a43966aae0bd4ead2ea7a/frost-core/src/lib.rs#L69

        // Schnorr's signature verification formula: $zG - cX = R$:
        // https://github.com/ZcashFoundation/frost/blob/2d88edf1623ee29f671a43966aae0bd4ead2ea7a/frost-core/src/verifying_key.rs#L54
        // $zG - cX$ is calculated using `ECDSA.recover(memPtr, e, v, r, s)`.
        // $R$ is calculated using `Secp256k1.toAddress(signatureRX, signatureRY)`.

        // how $zG - cX$ is calculated using `ECDSA.recover(memPtr, e, v, r, s)`?
        // `ecrecover(e, v, r, s)` works according to formula $Q = r^{-1} \( sR - eG \)$.
        // we need to substitute following parameters:
        // - `e = -(signature.z * publicKeyX)` (modular arithmetic is used everywhere).
        // - `v = (publicKeyY & 1) + 27`.
        // - `r = publicKeyX`.
        // - `s = -(challenge * publicKeyX)` (modular arithmetic is used everywhere).
        // we rewrite it like this:
        // - `e = -(signature.z * r)`.
        // - `v = (publicKeyY & 1) + 27`.
        // - `r = publicKeyX`.
        // - `s = -(challenge * r)`.
        // if we substitute this into $Q$, notice that $r^{-1} \cdot r = 1$.
        // so we calculate `-challenge * R - (-signature.z) * G`, not $Q$.
        // it can be simplified to `signature.z * G - challenge * R` or $zG - cX$.
        // point $R$ is public key, see `ECDSA.recover(memPtr, e, v, r, s)` documentation for details.

        // `ECDSA.recover(memPtr, e, v, r, s)` returns 160-bit Ethereum address instead of public key,
        // so we also need to convert Signature R to Ethereum address using `Secp256k1.toAddress(signatureRX, signatureRY)`.

        // we also previously checked that Signature R is on curve using
        // `Schnorr.isValidSignatureR(signatureRX, signatureRY)`.

        return ECDSA.recover(memPtr, e, v, r, s) == Secp256k1.toAddress(signatureRX, signatureRY);
    }
}
