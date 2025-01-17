// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

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
            0x920C53E3750C5D00AC46627E9B38BE025CC38C32651791AE231912CB2C078956,
            0x01477EC8424AD9DC3C2C528DF3D9CC929719C15AF3D4B75EF5955CE39FFE4C77,
            0x640D1DDE956D3DCE68499F102B87A2FEE6F18DA105916F003930A53F97786AEC,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
    }
}
