// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {FROST} from "src/FROST.sol";

contract FROSTTest is Test {
    function test_VerifySignature() public view {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        bool isValidSignature = FROST.verifySignature(
            0xBC5E83C1F1B03CBB9CC4BAB889E6A970E1F4C5C65C5F89E8D9723D73B726CC3E,
            0xDBED58A60A09B1BAB5B9AA6601F6B0B71B3F7AD9172D110F4AF1904FBDBC6A34,
            0xFEAEDAC471D34A127CB52CAA1B01549E21EFAC0E30DFDE9173E6DC739C1982D0,
            0xA3E8E852ED62DFB12DA5C0C0A555CAF0DE99C4B568EF217ABBA765B7C7AFB2F8,
            0xBDD6B6C184BAE9468F68A56ECB54EB768E6A369E4E1162F46B992FCEBE3B3CA2,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
        assertTrue(isValidSignature);
    }
}
