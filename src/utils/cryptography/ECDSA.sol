// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Memory} from "../Memory.sol";

/**
 * @dev Library for low-level ECDSA recovery.
 */
library ECDSA {
    /**
     * @dev Recovers Ethereum address from ECDSA signature.
     *      `ecrecover(e, v, r, s)` works according to formula $Q = r^{-1} \( sR - eG \)$
     *      from https://secg.org/sec1-v2.pdf#subsubsection.4.1.6.
     * @param memPtr Memory pointer for writing 128 bytes of input data.
     * @param e Message hash, can be any 256-bit number,
     *          will be reduced to valid scalar (can be zero scalar).
     * @param v Recovery ID, can be 27 or 28.
     *          Point `R(x, y)` has `yParity = v - 27`, `y` is calculated from `yParity`.
     * @param r Non-zero scalar r, must be in `[1, Secp256k1.N)` and `x = r` must be on curve.
     *          Point `R(x, y)` has coordinate `x = r`.
     * @param s Non-zero scalar s, must be in `[1, Secp256k1.N)`.
     * @return recovered 160-bit Ethereum address of `Q` point.
     * @dev If `v, r, s` do not satisfy above conditions, then `recovered = 0`
     */
    function recover(uint256 memPtr, uint256 e, uint256 v, uint256 r, uint256 s)
        internal
        view
        returns (uint256 recovered)
    {
        // https://github.com/argotorg/solidity/blob/v0.8.33/libsolidity/codegen/ir/IRGeneratorForStatements.cpp#L1653
        Memory.writeWord(memPtr, 0x00, e);
        Memory.writeWord(memPtr, 0x20, v);
        Memory.writeWord(memPtr, 0x40, r);
        Memory.writeWord(memPtr, 0x60, s);

        Memory.writeWord(0x00, 0x00, 0x00);

        // https://evm.codes/precompiled#0x01
        assembly ("memory-safe") {
            pop(staticcall(gas(), 0x01, memPtr, 0x80, 0x00, 0x20))
            recovered := mload(0x00)
        }
    }
}
