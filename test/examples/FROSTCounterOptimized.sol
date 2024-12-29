// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Hashes} from "src/utils/cryptography/Hashes.sol";
import {Memory} from "src/utils/Memory.sol";
import {FROST} from "src/FROST.sol";

contract FROSTCounterOptimized {
    uint128 nonce;
    uint128 number;

    // cargo run --release --manifest-path offchain-signer/Cargo.toml
    uint256 internal constant PUBLIC_KEY_X = 0xBC5E83C1F1B03CBB9CC4BAB889E6A970E1F4C5C65C5F89E8D9723D73B726CC3E;
    uint256 internal constant PUBLIC_KEY_Y = 0xDBED58A60A09B1BAB5B9AA6601F6B0B71B3F7AD9172D110F4AF1904FBDBC6A34;

    constructor() payable {
        require(FROST.isValidPublicKey(PUBLIC_KEY_X, PUBLIC_KEY_Y));
    }

    function setNumber(uint128 newNumber, uint256 signatureRX, uint256 signatureRY, uint256 signatureZ) public {
        uint256 memPtr = Memory.allocate(96);
        Memory.writeWord(memPtr, 0, uint256(uint160(address(this))));
        Memory.writeWord(memPtr, 32, nonce);
        Memory.writeWord(memPtr, 64, newNumber);

        bytes32 messageHash = bytes32(Hashes.efficientKeccak256(memPtr, 12, 84));

        // NOTE: `FROST.isValidPublicKey(...)` is checked at compile time
        require(FROST.verifySignature(PUBLIC_KEY_X, PUBLIC_KEY_Y, signatureRX, signatureRY, signatureZ, messageHash));

        number = newNumber;
        unchecked {
            nonce++;
        }
    }
}
