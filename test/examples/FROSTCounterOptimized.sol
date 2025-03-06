// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Hashes} from "src/utils/cryptography/Hashes.sol";
import {Memory} from "src/utils/Memory.sol";
import {FROST} from "src/FROST.sol";

contract FROSTCounterOptimized {
    uint128 nonce;
    uint128 number;

    // cargo run --release --manifest-path offchain-signer/Cargo.toml
    uint256 internal constant PUBLIC_KEY_X = 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09;
    uint256 internal constant PUBLIC_KEY_Y = 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF;

    constructor() payable {
        require(FROST.isValidPublicKey(PUBLIC_KEY_X, PUBLIC_KEY_Y));
    }

    function setNumber(uint128 newNumber, uint256 signatureRX, uint256 signatureRY, uint256 signatureZ) public {
        uint256 memPtr = Memory.allocate(96);
        Memory.writeWord(memPtr, 0, uint256(uint160(address(this))));
        Memory.writeWord(memPtr, 32, uint256(nonce));
        unchecked {
            nonce++;
        }
        Memory.writeWord(memPtr, 64, newNumber);

        bytes32 messageHash = bytes32(Hashes.efficientKeccak256(memPtr, 12, 84));

        // NOTE: `FROST.isValidPublicKey(...)` is checked at compile time
        require(FROST.verifySignature(PUBLIC_KEY_X, PUBLIC_KEY_Y, signatureRX, signatureRY, signatureZ, messageHash));

        number = newNumber;
    }
}
