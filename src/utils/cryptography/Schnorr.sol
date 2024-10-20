// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "./ECDSA.sol";
import {Secp256k1} from "./Secp256k1.sol";

library Schnorr {
    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool) {
        return isValidMultiplier(publicKeyX) && Secp256k1.isOnCurve(publicKeyX, publicKeyY);
    }

    function isValidSignatureR(uint256 signatureRX, uint256 signatureRY) internal pure returns (bool) {
        return Secp256k1.isOnCurve(signatureRX, signatureRY);
    }

    function isValidMultiplier(uint256 multiplier) internal pure returns (bool) {
        return multiplier % Secp256k1.N != 0;
    }

    function verifySignature(
        uint256 memPtr,
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        uint256 signatureZ,
        uint256 challenge
    ) internal view returns (bool) {
        uint256 e;
        unchecked {
            e = Secp256k1.N - mulmod(signatureZ, publicKeyX, Secp256k1.N);
        }

        uint256 v = Secp256k1.yParityEthereum(publicKeyY);

        uint256 r = publicKeyX;

        uint256 s;
        unchecked {
            s = Secp256k1.N - mulmod(challenge, publicKeyX, Secp256k1.N);
        }

        return ECDSA.recover(memPtr, e, v, r, s) == Secp256k1.toAddress(signatureRX, signatureRY);
    }
}
