#!/usr/bin/env bash
cat <<EOF > src/Counter.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {FROST} from "./FROST.sol";

contract Counter {
    constructor() payable {}

    function method1(uint256 publicKeyX, uint256 publicKeyY) external payable {
        require(FROST.isValidPublicKey(publicKeyX, publicKeyY));
    }

    function method2(uint256 publicKeyX, uint256 publicKeyY) external payable {
        require(!FROST.isValidPublicKey(publicKeyX, publicKeyY));
    }
}
EOF
forge build --force
sed -i '/^[[:space:]]*\/\/\//d' out/Counter.sol/Counter.iropt
sed -i 's/\/\*\*[^*]*\*\/[[:space:]]*//g' out/Counter.sol/Counter.iropt
FUNC_IS_VALID_PUBLIC_KEY=$(grep -Pzo '.*function\s+fun_isValidPublicKey\([^\)]*\)\s*->\s*[^\n]*\s*{[^{}]*(?:{[^{}]*}[^{}]*)*}' out/Counter.sol/Counter.iropt | sed 's/\x00/\n/g')

cat <<EOF > src/Counter.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {FROST} from "./FROST.sol";

contract Counter {
    constructor() payable {}

    function method1(uint256 publicKeyX, uint256 publicKeyY, uint256 signatureRX, uint256 signatureRY, uint256 signatureZ, bytes32 messageHash) external payable {
        require(FROST.verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, messageHash));
    }

    function method2(uint256 publicKeyX, uint256 publicKeyY, uint256 signatureRX, uint256 signatureRY, uint256 signatureZ, bytes32 messageHash) external payable {
        require(!FROST.verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, messageHash));
    }
}
EOF
forge build --force
sed -i '/^[[:space:]]*\/\/\//d' out/Counter.sol/Counter.iropt
sed -i 's/\/\*\*[^*]*\*\/[[:space:]]*//g' out/Counter.sol/Counter.iropt
FUNC_VERIFY_SIGNATURE=$(grep -Pzo '.*function\s+fun_verifySignature\([^\)]*\)\s*->\s*[^\n]*\s*{[^{}]*(?:{[^{}]*}[^{}]*)*}' out/Counter.sol/Counter.iropt | sed 's/\x00/\n/g')

rm src/Counter.sol

cat <<EOF > src/TranspiledFROST.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @dev Transpiled library for verifying \`FROST-secp256k1-KECCAK256\` signatures.
 */
library TranspiledFROST {
    /**
     * @dev Checks if public key \`(x, y)\` is on curve and that \`x < Secp256k1.N\`.
     *      It also checks that \`x % Secp256k1.N != 0\`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @return _isValidPublicKey \`true\` if public key is valid, \`false\` otherwise.
     */
    function isValidPublicKey(uint256 publicKeyX, uint256 publicKeyY) internal pure returns (bool _isValidPublicKey) {
        assembly ("memory-safe") {
$FUNC_IS_VALID_PUBLIC_KEY
            _isValidPublicKey := fun_isValidPublicKey(publicKeyX, publicKeyY)
        }
    }

    /**
     * @dev Verifies \`FROST-secp256k1-KECCAK256\` signature by formula \$zG - cX = R$.
     *      - Public key (\$X$) must be checked with \`FROST.isValidPublicKey(publicKeyX, publicKeyY)\`.
     *      - Signature R (\$R$) must be on curve.
     *      - Signature Z (\$z$) must be in \`[1, Secp256k1.N)\`.
     *      - Challenge (\$c$) is computed via \`FROST.computeChallenge(...)\`,
     *        must be in \`[1, Secp256k1.N)\`.
     * @param publicKeyX Public key x.
     * @param publicKeyY Public key y.
     * @param signatureRX Signature R x.
     * @param signatureRY Signature R y.
     * @param signatureZ Signature Z.
     * @param messageHash Message hash.
     * @return isValidSignature \`true\` if signature is valid, \`false\` otherwise.
     */
    function verifySignature(
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 signatureRX,
        uint256 signatureRY,
        uint256 signatureZ,
        bytes32 messageHash
    ) internal view returns (bool isValidSignature) {
        assembly ("memory-safe") {
$FUNC_VERIFY_SIGNATURE
            isValidSignature :=
                fun_verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, messageHash)
        }
    }
}
EOF
forge fmt
