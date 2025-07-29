// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Memory} from "../Memory.sol";

/**
 * @dev Library for low-level modular exponentiation.
 */
library ModExp {
    /**
     * @dev Calculates modular exponentiation `(base ** exponent) % modulus`.
     *      The fifth contract performs arbitrary-precision exponentiation under modulo.
     *      Here, $0^0$ is taken to be one, and $x \mod 0$ is zero for all $x$
     *      (from Ethereum Yellow Paper).
     * @param memPtr Memory pointer for writing 192 bytes of input data.
     * @param base Base.
     * @param exponent Exponent.
     * @param modulus Modulus.
     * @return result Modular exponentiation result.
     */
    function modexp(uint256 memPtr, uint256 base, uint256 exponent, uint256 modulus)
        internal
        view
        returns (uint256 result)
    {
        Memory.writeWord(memPtr, 0x00, 0x20);
        Memory.writeWord(memPtr, 0x20, 0x20);
        Memory.writeWord(memPtr, 0x40, 0x20);
        Memory.writeWord(memPtr, 0x60, base);
        Memory.writeWord(memPtr, 0x80, exponent);
        Memory.writeWord(memPtr, 0xa0, modulus);

        Memory.writeWord(0x00, 0x00, 0x00);

        // https://evm.codes/precompiled#0x05
        assembly ("memory-safe") {
            pop(staticcall(gas(), 0x05, memPtr, 0xc0, 0x00, 0x20))
            result := mload(0x00)
        }
    }
}
