// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {FROSTVerifier} from "./FROSTVerifier.sol";

contract FROSTVerifierTest is Test {
    FROSTVerifier frostVerifier;

    function setUp() public {
        frostVerifier = new FROSTVerifier();
    }

    function test_VerifySignature() public {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        frostVerifier.verifySignature(
            0xDF70C2D9D0BC0711BD338F95527A4545F8BB3530B3A90E07B34DF5B0F298DED1,
            0xA84975B1488E6EA60530A3BDB74B2E7C9F0217769CBF0F2565744A353B919554,
            0xB164EC237AF7EA1AF309EBDB6AA9588FCB821FB1E3AD32315A95D59A7F0A4600,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
    }
}
