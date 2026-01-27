// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {FROST} from "src/FROST.sol";
import {Memory} from "src/utils/Memory.sol";
import {Hashes} from "src/utils/cryptography/Hashes.sol";

contract FROSTWalletOptimized {
    uint256 nonce;

    // cargo run --release --manifest-path offchain-signer/Cargo.toml
    uint256 internal constant PUBLIC_KEY_X = 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09;
    uint256 internal constant PUBLIC_KEY_Y = 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF;

    constructor() payable {
        require(FROST.isValidPublicKey(PUBLIC_KEY_X, PUBLIC_KEY_Y));
    }

    function executeTransaction5112088248(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 signatureCommitmentX,
        uint256 signatureCommitmentY,
        uint256 signatureZ
    ) external payable {
        uint256 size;
        unchecked {
            size = 0xc0 + data.length;
        }
        uint256 memPtr = Memory.allocate(size);

        Memory.copyFromCalldata(memPtr, 0xc0, data);
        uint256 dataHash = Hashes.efficientKeccak256(memPtr, 0xc0, data.length);

        Memory.writeWord(memPtr, 0x00, block.chainid);
        Memory.writeWord(memPtr, 0x20, uint256(uint160(address(this))));
        Memory.writeWord(memPtr, 0x40, nonce);
        unchecked {
            nonce++;
        }
        Memory.writeWord(memPtr, 0x60, uint256(uint160(to)));
        Memory.writeWord(memPtr, 0x80, value);
        Memory.writeWord(memPtr, 0xa0, dataHash);

        bytes32 messageHash = bytes32(Hashes.efficientKeccak256(memPtr, 0x00, 0xc0));

        // NOTE: `require(FROST.isValidPublicKey(...))` is checked in constructor
        require(
            FROST.verifySignature(
                PUBLIC_KEY_X, PUBLIC_KEY_Y, signatureCommitmentX, signatureCommitmentY, signatureZ, messageHash
            )
        );

        bool success;
        assembly ("memory-safe") {
            success := call(gas(), to, value, add(memPtr, 0xc0), data.length, 0x00, 0x00)
        }
        require(success);
    }

    receive() external payable {}
}
