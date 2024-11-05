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
            0xFEAEDAC471D34A127CB52CAA1B01549E21EFAC0E30DFDE9173E6DC739C1982D0,
            0xA3E8E852ED62DFB12DA5C0C0A555CAF0DE99C4B568EF217ABBA765B7C7AFB2F8,
            0xBDD6B6C184BAE9468F68A56ECB54EB768E6A369E4E1162F46B992FCEBE3B3CA2,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
    }
}
