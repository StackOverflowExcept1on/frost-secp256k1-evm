// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import {Secp256k1Arithmetic} from "src/utils/cryptography/Secp256k1Arithmetic.sol";

contract Secp256k1ArithmeticWrapper {
    function decompressToAffinePoint(uint256 memPtr, uint256 x, uint256 yCompressed)
        external
        view
        returns (uint256, uint256)
    {
        return Secp256k1Arithmetic.decompressToAffinePoint(memPtr, x, yCompressed);
    }
}
