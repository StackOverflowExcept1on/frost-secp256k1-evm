// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ChaChaRngOffchain} from "./utils/cryptography/ChaChaRngOffchain.sol";
import {Secp256k1} from "./utils/cryptography/Secp256k1.sol";
import {FROST} from "./FROST.sol";

/**
 * @dev Signing key for Schnorr signature on `FROST-secp256k1-KECCAK256`.
 */
type SigningKey is uint256;

/**
 * @dev Library for creating `FROST-secp256k1-KECCAK256` signatures.
 */
library FROSTOffchain {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    using FROSTOffchain for SigningKey;

    /**
     * @dev Generates new signing key.
     * @return signingKey Signing key.
     */
    function newSigningKey() internal view returns (SigningKey) {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        return SigningKey.wrap(scalar);
    }

    /**
     * @dev Creates signing key from `scalar`.
     * @dev Reverts if `scalar` is not valid non-zero scalar.
     * @param scalar Valid non-zero scalar.
     * @return signingKey Signing key.
     */
    function signingKeyFromScalar(uint256 scalar) internal pure returns (SigningKey) {
        require(Secp256k1.isValidNonZeroScalar(scalar));
        return SigningKey.wrap(scalar);
    }

    /**
     * @dev Returns signing key `signingKey` as valid non-zero `scalar`.
     * @return scalar valid non-zero `scalar`.
     */
    function asScalar(SigningKey signingKey) internal pure returns (uint256) {
        return SigningKey.unwrap(signingKey);
    }

    /**
     * @dev Creates `FROST-secp256k1-KECCAK256` signature.
     * @param signingKey Signing key.
     * @param messageHash Message hash.
     * @return signatureRX Signature R x.
     * @return signatureRY Signature R y.
     * @return signatureZ Signature Z.
     */
    function createSignature(SigningKey signingKey, bytes32 messageHash)
        internal
        returns (uint256 signatureRX, uint256 signatureRY, uint256 signatureZ)
    {
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.1.0/frost-core/src/signing_key.rs#L50

        uint256 rawSigningKey = signingKey.asScalar();
        Vm.Wallet memory publicKey = vm.createWallet(rawSigningKey);

        uint256 k = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory R = vm.createWallet(k);

        (, uint256 challenge) =
            FROST.computeChallenge(publicKey.publicKeyX, publicKey.publicKeyY, R.publicKeyX, R.publicKeyY, messageHash);

        uint256 z = addmod(k, mulmod(challenge, rawSigningKey, Secp256k1.N), Secp256k1.N);

        return (R.publicKeyX, R.publicKeyY, z);
    }
}
