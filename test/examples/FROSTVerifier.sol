// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FROST} from "src/FROST.sol";

/**
 * @dev Contract for verifying FROST signatures.
 *
 *      It is written optimally to minimize bytecode size and gas overhead:
 *      - `uint256 publicKeyX` and `uint256 publicKeyY`
 *         are not marked as `public` to reduce bytecode size.
 *      - `payable` is used to reduce bytecode size.
 *      - `require(FROST.isValidPublicKey(...))`
 *         is checked at compile time.
 *
 *      All of these approaches allow profiling gas costs via `forge test --gas-report`
 *      including costs for loading from storage, calldata costs, etc.
 */
contract FROSTVerifier {
    uint256 publicKeyX;
    uint256 publicKeyY;

    constructor() payable {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        uint256 _publicKeyX = 0x355EEDCBB159977FA7F08B97D32BA7E413345FF9F3BB6FF9D48A857BCD429D52;
        uint256 _publicKeyY = 0x3EC6F7DA9AE3EFCEC9F84EE894E840D672E9BF3E91C3025AFC4FDACE3DC0E0DC;
        require(FROST.isValidPublicKey(_publicKeyX, _publicKeyY));
        publicKeyX = _publicKeyX;
        publicKeyY = _publicKeyY;
    }

    function verifySignature(uint256 signatureRX, uint256 signatureRY, uint256 signatureZ, bytes32 messageHash)
        external
        payable
    {
        // NOTE: `FROST.isValidPublicKey(...)` is checked at compile time
        require(FROST.verifySignature(publicKeyX, publicKeyY, signatureRX, signatureRY, signatureZ, messageHash));
    }
}
