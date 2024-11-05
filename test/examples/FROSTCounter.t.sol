// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {FROSTCounter} from "./FROSTCounter.sol";

contract FROSTCounterTest is Test {
    FROSTCounter frostCounter;

    function setUp() public {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        frostCounter = new FROSTCounter(
            0xBC5E83C1F1B03CBB9CC4BAB889E6A970E1F4C5C65C5F89E8D9723D73B726CC3E,
            0xDBED58A60A09B1BAB5B9AA6601F6B0B71B3F7AD9172D110F4AF1904FBDBC6A34
        );
        assertEq(address(frostCounter), DEFAULT_TEST_CONTRACT);
    }

    function test_SetNumber() public {
        uint256 newNumber = 42;
        frostCounter.setNumber(
            newNumber,
            0x8CECF8872AE9C2A20C40558D8D7ACBC763652969DDCAE24C1897EB8947F8B77A,
            0x519AA2359DD3D52B91890B8A7F591FCA08B5E7B1F2FF30F1826DB31BECDA9378,
            0xD899C3623F2223C1585B810D874D0E4FF62140FFD7663215929DBFF1D3995951
        );
        assertEq(frostCounter.number(), newNumber);
        assertEq(frostCounter.nonce(), 1);
    }
}
