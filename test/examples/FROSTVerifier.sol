// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

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
        uint256 _publicKeyX = 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09;
        uint256 _publicKeyY = 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF;
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
