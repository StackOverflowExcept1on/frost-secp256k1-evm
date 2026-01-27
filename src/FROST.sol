// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Memory} from "./utils/Memory.sol";
import {Hashes} from "./utils/cryptography/Hashes.sol";
import {Schnorr} from "./utils/cryptography/Schnorr.sol";
import {Secp256k1} from "./utils/cryptography/Secp256k1.sol";

/**
 * @dev Library for verifying `FROST-secp256k1-KECCAK256` signatures.
 */
library FROST {
    uint256 internal constant KECCAK256_BLOCK_SIZE = 136;

    uint256 internal constant PUBLIC_KEY_Y_PARITY_SIZE = 1;
    uint256 internal constant PUBLIC_KEY_X_SIZE = 32;
    uint256 internal constant PUBLIC_KEY_SIZE = 33;

    uint256 internal constant MESSAGE_HASH_SIZE = 32;

    uint256 internal constant LEN_IN_BYTES_U16_SIZE = 2;
    uint256 internal constant ZERO_BYTE_SIZE = 1;

    uint256 internal constant DOMAIN_SIZE = 32;
    uint256 internal constant DOMAIN_PART1_SIZE = 29;
    uint256 internal constant DOMAIN_PART2_SIZE = 3;

    uint256 internal constant DOMAIN_LENGTH_SIZE = 1;

    uint256 internal constant CHALLENGE_SIZE = KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE
        + MESSAGE_HASH_SIZE + LEN_IN_BYTES_U16_SIZE + ZERO_BYTE_SIZE + DOMAIN_SIZE + DOMAIN_LENGTH_SIZE;

    uint256 internal constant INPUT_HASH_SIZE = 32;
    uint256 internal constant RESERVED_BYTE_SIZE = 1;

    uint256 internal constant OUTPUT_HASH_SIZE = INPUT_HASH_SIZE + RESERVED_BYTE_SIZE + DOMAIN_SIZE
        + DOMAIN_LENGTH_SIZE;

    // "\x00\x30" - len_in_bytes_u16
    // "\x00" - zero byte
    // "FROST-secp256k1-KECCAK256-v1c" - domain
    uint256 internal constant DOMAIN_SEPARATOR1 = 0x00300046524F53542D736563703235366B312D4B454343414B3235362D763163;
    // "hal" - domain
    // "\x20" - domain length
    uint256 internal constant DOMAIN_SEPARATOR2 = 0x68616C2000000000000000000000000000000000000000000000000000000000;

    uint256 internal constant F_2_192 = 0x0000000000000001000000000000000000000000000000000000000000000000;
    uint256 internal constant MASK_64 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF;

    /**
     * @dev Checks if public key `(x, y)` is on curve and that `x < Secp256k1.N`.
     *      It also checks that `x % Secp256k1.N != 0`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @return isValidPublicKey `true` if public key is valid, `false` otherwise.
     */
    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool) {
        return Schnorr.isValidPublicKey(publicKeyX, publicKeyY);
    }

    /**
     * @dev Computes challenge for `FROST-secp256k1-KECCAK256` signature.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @param signatureCommitmentX Signature commitment R x.
     * @param signatureCommitmentY Signature commitment R y.
     * @param messageHash Message hash.
     * @return memPtr Pointer to allocated memory, memory size is `FROST.CHALLENGE_SIZE`.
     * @return challenge Challenge.
     */
    function computeChallenge(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureCommitmentX,
        uint256 signatureCommitmentY,
        bytes32 messageHash
    ) internal pure returns (uint256, uint256) {
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/lib.rs#L118
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-secp256k1/src/lib.rs#L196
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-secp256k1/src/lib.rs#L161

        uint256 publicKeyYCompressed = Secp256k1.yCompressed(publicKeyY);
        uint256 signatureCommitmentYCompressed = Secp256k1.yCompressed(signatureCommitmentY);

        // https://github.com/RustCrypto/traits/blob/elliptic-curve-v0.13.8/elliptic-curve/src/hash2curve/hash2field.rs#L35
        // https://github.com/RustCrypto/traits/blob/elliptic-curve-v0.13.8/elliptic-curve/src/hash2curve/hash2field/expand_msg/xmd.rs#L43

        uint256 memPtr = Memory.allocate(CHALLENGE_SIZE);

        Memory.zeroize(memPtr, KECCAK256_BLOCK_SIZE);

        Memory.writeByte(memPtr, KECCAK256_BLOCK_SIZE, signatureCommitmentYCompressed);
        Memory.writeWord(memPtr, KECCAK256_BLOCK_SIZE + PUBLIC_KEY_Y_PARITY_SIZE, signatureCommitmentX);

        Memory.writeByte(memPtr, KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE, publicKeyYCompressed);
        Memory.writeWord(memPtr, KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_Y_PARITY_SIZE, publicKeyX);

        Memory.writeWord(memPtr, KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE, uint256(messageHash));

        uint256 offset = KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + MESSAGE_HASH_SIZE;
        Memory.writeWord(memPtr, offset, DOMAIN_SEPARATOR1);
        Memory.writeWord(memPtr, offset + LEN_IN_BYTES_U16_SIZE + ZERO_BYTE_SIZE + DOMAIN_PART1_SIZE, DOMAIN_SEPARATOR2);

        uint256 b0 = Hashes.efficientKeccak256(memPtr, 0x00, CHALLENGE_SIZE);

        // https://github.com/RustCrypto/traits/blob/elliptic-curve-v0.13.8/elliptic-curve/src/hash2curve/hash2field/expand_msg/xmd.rs#L140
        // https://github.com/RustCrypto/traits/blob/elliptic-curve-v0.13.8/elliptic-curve/src/hash2curve/hash2field/expand_msg/xmd.rs#L110

        uint256 offset1 = KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + 2;
        uint256 offset2 =
            KECCAK256_BLOCK_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + MESSAGE_HASH_SIZE + LEN_IN_BYTES_U16_SIZE;

        Memory.writeWord(memPtr, offset1, b0);
        Memory.writeByte(memPtr, offset2, 1);

        uint256 bVals = Hashes.efficientKeccak256(memPtr, offset1, OUTPUT_HASH_SIZE);
        uint256 tmp = b0 ^ bVals;

        Memory.writeWord(memPtr, offset1, tmp);
        Memory.writeByte(memPtr, offset2, 2);

        uint256 bVals2 = Hashes.efficientKeccak256(memPtr, offset1, OUTPUT_HASH_SIZE);

        // https://github.com/RustCrypto/elliptic-curves/blob/k256/v0.13.4/k256/src/arithmetic/hash2curve.rs#L150

        uint256 d0 = bVals >> 64;
        uint256 d1 = ((bVals & MASK_64) << 128) | (bVals2 >> 128);

        return (memPtr, addmod(mulmod(d0, F_2_192, Secp256k1.N), d1, Secp256k1.N));
    }

    /**
     * @dev Verifies `FROST-secp256k1-KECCAK256` signature by formula $zG - cX = R$.
     *      - Public key ($X$) must be checked with `FROST.isValidPublicKey(publicKeyX, publicKeyY)`.
     *      - Signature R ($R$) must be on curve.
     *      - Signature Z ($z$) must be in `[1, Secp256k1.N)`.
     *      - Challenge ($c$) is computed via `FROST.computeChallenge(...)`,
     *        must be in `[1, Secp256k1.N)`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @param signatureCommitmentX Signature commitment R x.
     * @param signatureCommitmentY Signature commitment R y.
     * @param signatureZ Signature Z.
     * @param messageHash Message hash.
     * @return isValidSignature `true` if signature is valid, `false` otherwise.
     */
    function verifySignature(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureCommitmentX,
        uint256 signatureCommitmentY,
        uint256 signatureZ,
        bytes32 messageHash
    ) internal view returns (bool) {
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/verifying_key.rs#L77
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/traits.rs#L252
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/verifying_key.rs#L56

        if (!Secp256k1.isOnCurve(signatureCommitmentX, signatureCommitmentY)) {
            return false;
        }

        // `signatureZ` is always in `[1, Secp256k1.N)` and valid non-zero scalar because:
        // 1. `signatureZ = 0` is checked.
        // 2. `signatureZ >= Secp256k1.N` is checked.
        // thus `signatureZ % Secp256k1.N != 0`.
        if (signatureZ == 0) {
            return false;
        }

        if (signatureZ >= Secp256k1.N) {
            return false;
        }

        (uint256 memPtr, uint256 challenge) =
            computeChallenge(publicKeyX, publicKeyY, signatureCommitmentX, signatureCommitmentY, messageHash);

        // `challenge` is always in `[1, Secp256k1.N)` and valid non-zero scalar because:
        // 1. `FROST.computeChallenge(...)` returns `challenge < Secp256k1.N`
        //    (it uses modular arithmetic).
        // 2. `challenge = 0` is checked.
        // thus `challenge % Secp256k1.N != 0`.
        if (challenge == 0) {
            return false;
        }

        return Schnorr.verifySignature(
            memPtr, publicKeyX, publicKeyY, signatureCommitmentX, signatureCommitmentY, signatureZ, challenge
        );
    }
}
