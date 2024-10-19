// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "./utils/cryptography/ECDSA.sol";
import {Hashes} from "./utils/cryptography/Hashes.sol";
import {Schnorr} from "./utils/cryptography/Schnorr.sol";
import {Secp256k1} from "./utils/cryptography/Secp256k1.sol";
import {Memory} from "./utils/Memory.sol";

library FROST {
    uint256 internal constant CHALLENGE_SIZE = 136 + 33 + 33 + 32 + 3 + 32 + 1;

    uint256 internal constant CHALLENGE_STRING1 = 0x00300046524f53542d736563703235366b312d4b454343414b3235362d763163;
    uint256 internal constant CHALLENGE_STRING2 = 0x68616c2000000000000000000000000000000000000000000000000000000000;

    uint256 internal constant F_2_192 = 0x0000000000000001000000000000000000000000000000000000000000000000;
    uint256 internal constant MASK_64 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF;

    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool) {
        return Schnorr.isValidPublicKey(publicKeyX, publicKeyY);
    }

    function computateChallenge(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        bytes32 message
    ) internal pure returns (uint256, uint256) {
        uint256 publicKeyYCompressed = Secp256k1.yCompressed(publicKeyY);
        uint256 signatureRYCompressed = Secp256k1.yCompressed(signatureRY);

        uint256 memPtr = Memory.allocate(CHALLENGE_SIZE);

        Memory.zeroize(memPtr, 136);

        Memory.writeByte(memPtr, 136, signatureRYCompressed);
        Memory.writeWord(memPtr, 137, signatureRX);

        Memory.writeByte(memPtr, 169, publicKeyYCompressed);
        Memory.writeWord(memPtr, 170, publicKeyX);

        Memory.writeWord(memPtr, 202, uint256(message));

        Memory.writeWord(memPtr, 234, CHALLENGE_STRING1);
        Memory.writeWord(memPtr, 266, CHALLENGE_STRING2);

        uint256 b0 = Hashes.rawKeccak256(memPtr, 0, CHALLENGE_SIZE);

        Memory.writeWord(memPtr, 204, b0);
        Memory.writeByte(memPtr, 236, 1);

        uint256 b_vals = Hashes.rawKeccak256(memPtr, 204, 66);
        uint256 tmp = b0 ^ b_vals;

        Memory.writeWord(memPtr, 204, tmp);
        Memory.writeByte(memPtr, 236, 2);

        uint256 b_vals2 = Hashes.rawKeccak256(memPtr, 204, 66);

        uint256 d0 = b_vals >> 64;
        uint256 d1 = ((b_vals & MASK_64) << 128) | (b_vals2 >> 128);

        return (memPtr, addmod(mulmod(d0, F_2_192, Secp256k1.N), d1, Secp256k1.N));
    }

    function verifySignature(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        uint256 signatureZ,
        bytes32 message
    ) internal view returns (bool) {
        // NOTE: publicKeyX and publicKeyY must be checked before calling this function

        if (!Schnorr.isValidSignatureR(signatureRX, signatureRY)) {
            return false;
        }

        if (!Schnorr.isValidMultiplier(signatureZ)) {
            return false;
        }

        (uint256 memPtr, uint256 challenge) =
            computateChallenge(publicKeyX, publicKeyY, signatureRX, signatureRY, message);

        if (!Schnorr.isValidMultiplier(challenge)) {
            return false;
        }

        return Schnorr.verifySignature(memPtr, publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, challenge);
    }
}
