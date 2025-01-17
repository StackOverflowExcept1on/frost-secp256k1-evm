// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TranspiledFROST as FROST} from "src/TranspiledFROST.sol";

contract TranspiledFROSTTest is Test {
    function test_VerifySignature() public view {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        bool isValidSignature = FROST.verifySignature(
            0x355EEDCBB159977FA7F08B97D32BA7E413345FF9F3BB6FF9D48A857BCD429D52,
            0x3EC6F7DA9AE3EFCEC9F84EE894E840D672E9BF3E91C3025AFC4FDACE3DC0E0DC,
            0x920C53E3750C5D00AC46627E9B38BE025CC38C32651791AE231912CB2C078956,
            0x01477EC8424AD9DC3C2C528DF3D9CC929719C15AF3D4B75EF5955CE39FFE4C77,
            0x640D1DDE956D3DCE68499F102B87A2FEE6F18DA105916F003930A53F97786AEC,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
        assertTrue(isValidSignature);
    }
}
