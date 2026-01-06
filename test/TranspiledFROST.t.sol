// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std/Test.sol";
import {TranspiledFROST as FROST} from "src/TranspiledFROST.sol";

contract TranspiledFROSTTest is Test {
    function test_VerifySignature() public view {
        // cargo run --release --manifest-path offchain-signer/Cargo.toml
        bool isValidSignature = FROST.verifySignature(
            0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09,
            0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF,
            0xDF70C2D9D0BC0711BD338F95527A4545F8BB3530B3A90E07B34DF5B0F298DED1,
            0xA84975B1488E6EA60530A3BDB74B2E7C9F0217769CBF0F2565744A353B919554,
            0xB164EC237AF7EA1AF309EBDB6AA9588FCB821FB1E3AD32315A95D59A7F0A4600,
            0x4141414141414141414141414141414141414141414141414141414141414141
        );
        assertTrue(isValidSignature);
    }
}
