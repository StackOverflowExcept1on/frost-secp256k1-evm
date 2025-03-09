// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FROST} from "src/FROST.sol";

contract FROSTCounter {
    uint256 public publicKeyX;
    uint256 public publicKeyY;

    uint256 public nonce;

    uint256 public number;

    constructor(uint256 _publicKeyX, uint256 _publicKeyY) {
        require(FROST.isValidPublicKey(_publicKeyX, _publicKeyY));
        publicKeyX = _publicKeyX;
        publicKeyY = _publicKeyY;
    }

    function setNumber(uint256 newNumber, uint256 signatureRX, uint256 signatureRY, uint256 signatureZ) public {
        bytes32 messageHash =
            keccak256(abi.encodePacked(block.chainid, uint256(uint160(address(this))), nonce, newNumber));
        nonce++;
        // NOTE: `require(FROST.isValidPublicKey(...))` is checked in constructor
        require(FROST.verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, messageHash));
        number = newNumber;
    }

    function increment(uint256 signatureRX, uint256 signatureRY, uint256 signatureZ) public {
        uint256 newNumber = number + 1;
        setNumber(newNumber, signatureRX, signatureRY, signatureZ);
    }
}
