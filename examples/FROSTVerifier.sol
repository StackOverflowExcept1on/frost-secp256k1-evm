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
        uint256 _publicKeyX = 0xBC5E83C1F1B03CBB9CC4BAB889E6A970E1F4C5C65C5F89E8D9723D73B726CC3E;
        uint256 _publicKeyY = 0xDBED58A60A09B1BAB5B9AA6601F6B0B71B3F7AD9172D110F4AF1904FBDBC6A34;
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
