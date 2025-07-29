// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

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

    function setNumber(
        uint256 newNumber,
        uint256 signatureCommitmentX,
        uint256 signatureCommitmentY,
        uint256 signatureZ
    ) public {
        /// forge-lint: disable-start(asm-keccak256)
        bytes32 messageHash =
            keccak256(abi.encodePacked(block.chainid, uint256(uint160(address(this))), nonce, newNumber));
        /// forge-lint: disable-end(asm-keccak256)
        nonce++;
        // NOTE: `require(FROST.isValidPublicKey(...))` is checked in constructor
        require(
            FROST.verifySignature(
                publicKeyX, publicKeyY, signatureCommitmentX, signatureCommitmentY, signatureZ, messageHash
            )
        );
        number = newNumber;
    }

    function increment(uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) public {
        uint256 newNumber = number + 1;
        setNumber(newNumber, signatureCommitmentX, signatureCommitmentY, signatureZ);
    }
}
