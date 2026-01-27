// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Secp256k1} from "./Secp256k1.sol";
import {Vm} from "forge-std/Vm.sol";

/**
 * @dev Library for interaction with pseudo-random number generator.
 * @dev Foundry uses `rand_chacha::ChaChaRng` under the hood:
 *      - https://docs.rs/rand_chacha/latest/rand_chacha/type.ChaChaRng.html
 */
library ChaChaRngOffchain {
    /// forge-lint: disable-next-item(screaming-snake-case-const)
    /**
     * @dev Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D:
     *      - https://github.com/foundry-rs/forge-std/blob/master/src/Base.sol
     */
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /**
     * @dev Generates valid `scalar` in `[0, Secp256k1.N)`.
     * @return scalar valid `scalar`.
     */
    function randomScalar() internal view returns (uint256) {
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/traits.rs#L55

        while (true) {
            uint256 scalar = uint256(bytes32(vm.randomBytes(32)));

            if (Secp256k1.isValidScalar(scalar)) {
                return scalar;
            }
        }

        revert();
    }

    /**
     * @dev Generates valid non-zero `scalar` in `[1, Secp256k1.N)`.
     * @return scalar valid non-zero `scalar`.
     */
    function randomNonZeroScalar() internal view returns (uint256) {
        // https://github.com/ZcashFoundation/frost/blob/frost-secp256k1/v2.2.0/frost-core/src/lib.rs#L140

        while (true) {
            uint256 scalar = randomScalar();

            if (Secp256k1.isValidNonZeroScalar(scalar)) {
                return scalar;
            }
        }

        revert();
    }
}
