// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Memory} from "./Memory.sol";

library ECDSA {
    function recover(uint256 memPtr, uint256 e, uint256 v, uint256 r, uint256 s)
        internal
        view
        returns (uint256 recovered)
    {
        Memory.writeWord(memPtr, 0x00, e);
        Memory.writeWord(memPtr, 0x20, v);
        Memory.writeWord(memPtr, 0x40, r);
        Memory.writeWord(memPtr, 0x60, s);

        Memory.writeWord(0x00, 0x00, 0x00);

        assembly ("memory-safe") {
            let success := staticcall(gas(), 0x01, memPtr, 0x80, 0x00, 0x20)
            if iszero(success) { revert(0x00, 0x00) }
            recovered := mload(0x00)
        }
    }
}
