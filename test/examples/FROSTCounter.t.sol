// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {FROSTCounter} from "./FROSTCounter.sol";

contract FROSTCounterTest is Test {
    FROSTCounter frostCounter;

    function setUp() public {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        frostCounter = new FROSTCounter(
            0x355EEDCBB159977FA7F08B97D32BA7E413345FF9F3BB6FF9D48A857BCD429D52,
            0x3EC6F7DA9AE3EFCEC9F84EE894E840D672E9BF3E91C3025AFC4FDACE3DC0E0DC
        );
        assertEq(address(frostCounter), DEFAULT_TEST_CONTRACT);
    }

    function test_SetNumber() public {
        uint256 newNumber = 42;
        frostCounter.setNumber(
            newNumber,
            0x29FFED4CADB8FF3C9CFCFCD5CE4F89C2467F1A450291468846C342937B4DBDA5,
            0x79081588876F648C9EB9B813F99DB278263443D95E42A04BA5D74347C66C62DA,
            0xA0DE90FFF2BBEF6D6EE55A7B010A871991936AF86882848C121BFDDF485FDE5F
        );
        assertEq(frostCounter.number(), newNumber);
        assertEq(frostCounter.nonce(), 1);

        newNumber = 43;
        frostCounter.setNumber(
            newNumber,
            0x3AF5C69DB5AC3145AD483FDA5B88E730FCEE63BE82E0447B7E8430840CE863B3,
            0xC68CD93B2D5830F3EBDD770842407580F8BF8EC50D83850B5CD402D0ABB4F98C,
            0x7269D362F043FE33AFDC25A38BC6538BC668188D6518BB77268B40BD9F20AC50
        );
        assertEq(frostCounter.number(), newNumber);
        assertEq(frostCounter.nonce(), 2);
    }
}
