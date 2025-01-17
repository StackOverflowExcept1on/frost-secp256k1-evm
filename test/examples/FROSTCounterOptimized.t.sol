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
            0x29FFED4CADB8FF3C9CFCFCD5CE4F89C2467F1A450291468846C342937B4DBDA5,
            0x79081588876F648C9EB9B813F99DB278263443D95E42A04BA5D74347C66C62DA,
            0xA0DE90FFF2BBEF6D6EE55A7B010A871991936AF86882848C121BFDDF485FDE5F
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(1))
        );

        newNumber = 43;
        frostCounter.setNumber(
            newNumber,
            0x3AF5C69DB5AC3145AD483FDA5B88E730FCEE63BE82E0447B7E8430840CE863B3,
            0xC68CD93B2D5830F3EBDD770842407580F8BF8EC50D83850B5CD402D0ABB4F98C,
            0x7269D362F043FE33AFDC25A38BC6538BC668188D6518BB77268B40BD9F20AC50
        );
        assertEq(
            uint256(vm.load(address(frostCounter), bytes32(uint256(0)))),
            uint256((uint256(newNumber) << 128) | uint256(2))
        );
    }
}
