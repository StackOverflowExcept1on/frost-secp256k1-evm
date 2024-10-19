// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FROST} from "./FROST.sol";

contract Counter {
    uint256 publicKeyX;
    uint256 publicKeyY;

    constructor() payable {
        uint256 _publicKeyX = 0xbc5e83c1f1b03cbb9cc4bab889e6a970e1f4c5c65c5f89e8d9723d73b726cc3e;
        uint256 _publicKeyY = 0xdbed58a60a09b1bab5b9aa6601f6b0b71b3f7ad9172d110f4af1904fbdbc6a34;
        require(FROST.isValidPublicKey(_publicKeyX, _publicKeyY));
        publicKeyX = _publicKeyX;
        publicKeyY = _publicKeyY;
    }

    function verifySignature(uint256 signatureRX, uint256 signatureRY, uint256 signatureZ, bytes32 message)
        external
        payable
    {
        require(FROST.verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, message));
    }
}
