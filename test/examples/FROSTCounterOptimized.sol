// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Hashes} from "src/utils/cryptography/Hashes.sol";
import {Memory} from "src/utils/Memory.sol";
import {FROST} from "src/FROST.sol";

contract FROSTCounterOptimized {
    uint128 nonce;
    uint128 number;

    // cargo run --release --manifest-path offchain-signer/Cargo.toml
    uint256 internal constant PUBLIC_KEY_X = 0x355EEDCBB159977FA7F08B97D32BA7E413345FF9F3BB6FF9D48A857BCD429D52;
    uint256 internal constant PUBLIC_KEY_Y = 0x3EC6F7DA9AE3EFCEC9F84EE894E840D672E9BF3E91C3025AFC4FDACE3DC0E0DC;

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
