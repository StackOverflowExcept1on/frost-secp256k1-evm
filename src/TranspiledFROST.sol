// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @dev Transpiled library for verifying `FROST-secp256k1-KECCAK256` signatures.
 */
library TranspiledFROST {
    /**
     * @dev Checks if public key `(x, y)` is on curve and that `x < Secp256k1.N`.
     *      It also checks that `x % Secp256k1.N != 0`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @return _isValidPublicKey `true` if public key is valid, `false` otherwise.
     */
    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool _isValidPublicKey) {
        assembly ("memory-safe") {
            function fun_isValidPublicKey(var_publicKeyX, var_publicKeyY) -> var {
                let expr := lt(var_publicKeyX, not(0x014551231950b75fc4402da1732fc9bebe))
                if expr {
                    expr := eq(
                        mulmod(var_publicKeyY, var_publicKeyY, not(0x01000003d0)),
                        addmod(
                            mulmod(
                                var_publicKeyX,
                                mulmod(var_publicKeyX, var_publicKeyX, not(0x01000003d0)),
                                not(0x01000003d0)
                            ),
                            0x07,
                            not(0x01000003d0)
                        )
                    )
                }
                var := expr
            }
            _isValidPublicKey := fun_isValidPublicKey(publicKeyX, publicKeyY)
        }
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
    ) internal view returns (bool isValidSignature) {
        assembly ("memory-safe") {
            function fun_verifySignature(
                var_publicKeyX,
                var_publicKeyY,
                var_signatureCommitmentX,
                var_signatureCommitmentY,
                var_signatureZ,
                var_messageHash
            ) -> var {
                var := 0
                if iszero(
                    eq(
                        mulmod(var_signatureCommitmentY, var_signatureCommitmentY, not(0x01000003d0)),
                        addmod(
                            mulmod(
                                var_signatureCommitmentX,
                                mulmod(var_signatureCommitmentX, var_signatureCommitmentX, not(0x01000003d0)),
                                not(0x01000003d0)
                            ),
                            0x07,
                            not(0x01000003d0)
                        )
                    )
                ) {
                    var := 0
                    leave
                }
                if iszero(var_signatureZ) {
                    var := 0
                    leave
                }
                if iszero(lt(var_signatureZ, not(0x014551231950b75fc4402da1732fc9bebe))) {
                    var := 0
                    leave
                }
                let expr := and(var_publicKeyY, 0x01)
                let ret := 0
                ret := 270
                let var_memPtr := mload(0x40)
                let usr$newFreePtr := add(var_memPtr, 288)
                if or(gt(usr$newFreePtr, 0xFFFFFFFFFFFFFFFF), lt(usr$newFreePtr, var_memPtr)) {
                    revert(0, 0)
                }
                mstore(0x40, usr$newFreePtr)
                calldatacopy(var_memPtr, calldatasize(), 0x88)
                mstore8(add(var_memPtr, 0x88), add(and(var_signatureCommitmentY, 0x01), 0x02))
                mstore(add(var_memPtr, 137), var_signatureCommitmentX)
                mstore8(add(var_memPtr, 169), add(expr, 0x02))
                mstore(add(var_memPtr, 170), var_publicKeyX)
                mstore(add(var_memPtr, 202), var_messageHash)
                mstore(add(var_memPtr, 234), 0x300046524f53542d736563703235366b312d4b454343414b3235362d763163)
                mstore(add(var_memPtr, 266), shl(229, 0x03430b61))
                let var_value := keccak256(var_memPtr, ret)
                let _1 := add(var_memPtr, 204)
                mstore(_1, var_value)
                let _2 := add(var_memPtr, 236)
                mstore8(_2, 0x01)
                let ret_1 := 0
                ret_1 := 66
                let var_value_1 := keccak256(_1, 66)
                mstore(_1, xor(var_value, var_value_1))
                mstore8(_2, 0x02)
                let expr_1 :=
                    addmod(
                        mulmod(shr(0x40, var_value_1), shl(192, 1), not(0x014551231950b75fc4402da1732fc9bebe)),
                        or(and(shl(0x80, var_value_1), shl(128, 0xffffffffffffffff)), shr(0x80, keccak256(_1, 66))),
                        not(0x014551231950b75fc4402da1732fc9bebe)
                    )
                if iszero(expr_1) {
                    var := 0
                    leave
                }
                mstore(
                    var_memPtr,
                    sub(
                        not(0x014551231950b75fc4402da1732fc9bebe),
                        mulmod(var_signatureZ, var_publicKeyX, not(0x014551231950b75fc4402da1732fc9bebe))
                    )
                )
                mstore(add(var_memPtr, 0x20), add(expr, 0x1b))
                mstore(add(var_memPtr, 0x40), var_publicKeyX)
                mstore(
                    add(var_memPtr, 0x60),
                    sub(
                        not(0x014551231950b75fc4402da1732fc9bebe),
                        mulmod(expr_1, var_publicKeyX, not(0x014551231950b75fc4402da1732fc9bebe))
                    )
                )
                mstore(0, 0)
                pop(staticcall(gas(), 0x01, var_memPtr, 0x80, 0, 0x20))
                let var_recovered := mload(0)
                mstore(0, var_signatureCommitmentX)
                mstore(0x20, var_signatureCommitmentY)
                var := eq(var_recovered, and(keccak256(0, 0x40), sub(shl(160, 1), 1)))
            }
            isValidSignature := fun_verifySignature(
                publicKeyX,
                publicKeyY,
                signatureCommitmentX,
                signatureCommitmentY,
                signatureZ,
                messageHash
            )
        }
    }
}
