// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ChaChaRngOffchain} from "src/utils/cryptography/ChaChaRngOffchain.sol";

contract ChaChaRngOffchainTest is Test {
    // let mut rng = rand_chacha::ChaChaRng::from_seed([0x42; 32]);
    // let signing_key = frost_secp256k1_evm::SigningKey::new(&mut rng);
    // dbg!(signing_key.to_scalar());

    /// forge-config: default.fuzz.seed = "0x4242424242424242424242424242424242424242424242424242424242424242"
    function test_RandomScalar() public view {
        assertEq(ChaChaRngOffchain.randomScalar(), 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E);
        assertEq(ChaChaRngOffchain.randomScalar(), 0xE106B40D369F5C94F5DD2A13D9131585121002ED9E313D2DC9E49FF534C50BD1);
    }

    /// forge-config: default.fuzz.seed = "0x4242424242424242424242424242424242424242424242424242424242424242"
    function test_RandomNonZeroScalar() public view {
        assertEq(
            ChaChaRngOffchain.randomNonZeroScalar(), 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E
        );
        assertEq(
            ChaChaRngOffchain.randomNonZeroScalar(), 0xE106B40D369F5C94F5DD2A13D9131585121002ED9E313D2DC9E49FF534C50BD1
        );
    }
}
