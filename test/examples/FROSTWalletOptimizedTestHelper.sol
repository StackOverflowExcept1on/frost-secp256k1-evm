// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import {Vm} from "forge-std/Test.sol";
import {FROSTWalletOptimized} from "test/examples/FROSTWalletOptimized.sol";

library FROSTWalletOptimizedTestHelper {
    /// forge-lint: disable-next-item(screaming-snake-case-const)
    /**
     * @dev Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D:
     *      - https://github.com/foundry-rs/forge-std/blob/master/src/Base.sol
     */
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    using FROSTWalletOptimizedTestHelper for FROSTWalletOptimized;

    function getNonce(FROSTWalletOptimized frostWallet) internal view returns (uint256) {
        return uint256(vm.load(address(frostWallet), bytes32(uint256(0))));
    }

    function getMessageHash(FROSTWalletOptimized frostWallet, address to, uint256 value, bytes memory data)
        public
        view
        returns (bytes32)
    {
        uint256 nonce = frostWallet.getNonce();
        return getMessageHashWithNonce(frostWallet, to, value, data, nonce);
    }

    function getMessageHashWithNonce(
        FROSTWalletOptimized frostWallet,
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce
    ) public view returns (bytes32) {
        bytes32 dataHash = keccak256(data);
        return keccak256(
            abi.encodePacked(
                block.chainid, uint256(uint160(address(frostWallet))), nonce, uint256(uint160(to)), value, dataHash
            )
        );
    }

    function getTranscationData() public pure returns (address to, uint256 value, bytes memory data) {
        return (0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 1 ether, "");
    }
}
