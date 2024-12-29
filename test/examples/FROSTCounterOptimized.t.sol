// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {FROSTCounterOptimized} from "./FROSTCounterOptimized.sol";

contract FROSTCounterOptimizedTest is Test {
    FROSTCounterOptimized frostCounter;

    function setUp() public {
        frostCounter = new FROSTCounterOptimized();
        assertEq(address(frostCounter), DEFAULT_TEST_CONTRACT);
    }

    function test_SetNumber() public {
        uint128 newNumber = 42;
        frostCounter.setNumber(
            newNumber,
            0x8CECF8872AE9C2A20C40558D8D7ACBC763652969DDCAE24C1897EB8947F8B77A,
            0x519AA2359DD3D52B91890B8A7F591FCA08B5E7B1F2FF30F1826DB31BECDA9378,
            0xD899C3623F2223C1585B810D874D0E4FF62140FFD7663215929DBFF1D3995951
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(1))
        );

        newNumber = 43;
        frostCounter.setNumber(
            newNumber,
            0xCD731E9ACB757AB877B473C78FFF5387F1E136FB53415FED65A79120708AA85B,
            0x401392126E0BD61C90AE3EAD1C2B738B37AF34FD1F2B65580311CB1352AAD684,
            0xBE6B295689BABDFA4C08E267B77FAE1465137173F1B7DCF668A594BABB849AE5
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(2))
        );
    }
}
