// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Hashes} from "./Hashes.sol";
import {Memory} from "./Memory.sol";
import {Secp256k1} from "./Secp256k1.sol";

library FROST {
    uint256 internal constant CHALLENGE_SIZE = 136 + 33 + 33 + 32 + 3 + 32 + 1;

    uint256 internal constant CHALLENGE_STRING1 = 0x00300046524f53542d736563703235366b312d4b454343414b3235362d763163;
    uint256 internal constant CHALLENGE_STRING2 = 0x68616c2000000000000000000000000000000000000000000000000000000000;

    uint256 internal constant F_2_192 = 0x0000000000000001000000000000000000000000000000000000000000000000;
    uint256 internal constant MASK_64 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF;

    function verifySignature(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        uint256 signatureZ,
        bytes32 message
    ) internal view returns (bool) {
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

        uint256 challenge = addmod(mulmod(d0, F_2_192, Secp256k1.N), d1, Secp256k1.N);

        uint256 e;
        unchecked {
            e = Secp256k1.N - mulmod(signatureZ, publicKeyX, Secp256k1.N);
        }

        uint256 v;
        unchecked {
            v = publicKeyYCompressed + 25;
        }

        uint256 r = publicKeyX;

        uint256 s;
        unchecked {
            s = Secp256k1.N - mulmod(challenge, publicKeyX, Secp256k1.N);
        }

        Memory.writeWord(memPtr, 0x00, e);
        Memory.writeWord(memPtr, 0x20, v);
        Memory.writeWord(memPtr, 0x40, r);
        Memory.writeWord(memPtr, 0x60, s);

        Memory.writeWord(0x00, 0x00, 0x00);

        uint256 recovered;
        assembly ("memory-safe") {
            let success := staticcall(gas(), 0x01, memPtr, 0x80, 0x00, 0x20)
            if iszero(success) { revert(0x00, 0x00) }
            recovered := mload(0x00)
        }

        return recovered == Secp256k1.toAddress(signatureRX, signatureRY);
    }
}
