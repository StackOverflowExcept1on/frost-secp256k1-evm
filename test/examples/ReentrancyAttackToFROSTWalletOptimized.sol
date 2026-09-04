// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import {FROSTOffchain, SigningKey} from "src/FROSTOffchain.sol";
import {FROSTWalletOptimized} from "test/examples/FROSTWalletOptimized.sol";
import {FROSTWalletOptimizedTestHelper} from "test/examples/FROSTWalletOptimizedTestHelper.sol";

/// forge-lint: disable-next-item(locked-ether)
contract ReentrancyAttackToFROSTWalletOptimized {
    using FROSTOffchain for SigningKey;
    using FROSTWalletOptimizedTestHelper for FROSTWalletOptimized;

    SigningKey signingKey;
    FROSTWalletOptimized frostWallet;

    uint256 nonce;

    constructor(SigningKey _signingKey, FROSTWalletOptimized _frostWallet) {
        signingKey = _signingKey;
        frostWallet = _frostWallet;

        nonce = frostWallet.getNonce();
    }

    function executeTransaction5112088248() public {
        (address to, uint256 value, bytes memory data) = (address(this), 1 ether, "");
        bytes32 messageHash = frostWallet.getMessageHashWithNonce(to, value, data, nonce);
        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);
        frostWallet.executeTransaction5112088248(
            to, value, data, signatureCommitmentX, signatureCommitmentY, signatureZ
        );
    }

    receive() external payable {
        if (address(frostWallet).balance > 0) {
            executeTransaction5112088248();
        }
    }
}
