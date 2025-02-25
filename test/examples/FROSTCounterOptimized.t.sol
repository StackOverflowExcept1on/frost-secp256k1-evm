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
            0x91785E23DEC1B7DEEF15CF2EC5BD973868728B35F0FC435792A35B6CD367723A,
            0x3C5455B649F8DC3532A6D7BC5280957C2299BF19C4E1BD1F23B7DC06455E855C,
            0x9CDBF89F79DEC56B38AD66D302EC1475F0A43F5F41BA205E3BC6F1A65151AE52
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(1))
        );

        newNumber = 43;
        frostCounter.setNumber(
            newNumber,
            0xE993054A9C58EF3009A326AD26A3DE42D6E1B8DC23590EF2695E9E5F59474C52,
            0xB9EB4EE5410AC35A8F0A6D27AD0A379036DD196A9D838314767B78475319E56C,
            0x24CAA718B2EA9CCFC1A1E18B56C90A591B0B2EF2D131D731A69613170915CE02
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(2))
        );
    }
}
