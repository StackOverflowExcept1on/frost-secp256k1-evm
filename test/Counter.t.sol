// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Counter} from "../src/Counter.sol";

contract CounterTest is Test {
    Counter public counter;

    function setUp() public {
        counter = new Counter();
    }

    function test_VerifySignature() public {
        counter.verifySignature(
            0xfeaedac471d34a127cb52caa1b01549e21efac0e30dfde9173e6dc739c1982d0,
            0xa3e8e852ed62dfb12da5c0c0a555caf0de99c4b568ef217abba765b7c7afb2f8,
            0xbdd6b6c184bae9468f68a56ecb54eb768e6a369e4e1162f46b992fcebe3b3ca2,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
    }
}
