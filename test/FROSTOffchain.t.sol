// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {FROST} from "src/FROST.sol";
import {SigningKey, FROSTOffchain} from "src/FROSTOffchain.sol";

contract FROSTOffchainTest is Test {
    // let mut rng = rand_chacha::ChaChaRng::from_seed([0x42; 32]);
    // let signing_key = frost_secp256k1_evm::SigningKey::new(&mut rng);
    // let verifying_key = frost_secp256k1_evm::VerifyingKey::from(signing_key);
    // let message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes();
    // let signature = signing_key.sign(&mut rng, message);
    // let verifying_key_compressed = verifying_key.serialize()?;
    // let verifying_key_uncompressed = convert_public_key(&verifying_key_compressed);
    // let (x, y) = verifying_key_uncompressed.split_at(32);
    // println!("signing_key:");
    // println!("  s: 0x{}", slice2hex(&signing_key.serialize()));
    // println!();
    // println!("verifying_key:");
    // println!("  X: 0x{}", slice2hex(x));
    // println!("  Y: 0x{}", slice2hex(y));
    // println!();
    // let commitment_compressed = signature.serialize()?;
    // let commitment_uncompressed = convert_public_key(&commitment_compressed);
    // let (x, y) = commitment_uncompressed.split_at(32);
    // println!("commitment (signature.R):");
    // println!("  X: 0x{}", slice2hex(x));
    // println!("  Y: 0x{}", slice2hex(y));
    // println!();
    // println!("signature (signature.z):");
    // println!("  z: 0x{}", slice2hex(&commitment_compressed[33..]));

    using FROSTOffchain for SigningKey;

    /// forge-config: default.fuzz.seed = "0x4242424242424242424242424242424242424242424242424242424242424242"
    function test_CreateSignature() public {
        SigningKey signingKey = FROSTOffchain.newSigningKey();

        Vm.Wallet memory wallet = vm.createWallet(signingKey.asScalar());

        uint256 privateKey = wallet.privateKey;
        assertEq(privateKey, 0xA4DDF31F7F32BA696F14CE50ECF3F21E3E100E83BDF47966E7B07468E9500B6E);

        uint256 publicKeyX = wallet.publicKeyX;
        uint256 publicKeyY = wallet.publicKeyY;

        assertEq(publicKeyX, 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09);
        assertEq(publicKeyY, 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF);

        bytes32 messageHash = 0x4141414141414141414141414141414141414141414141414141414141414141;

        (uint256 signatureCommitmentX, uint256 signatureCommitmentY, uint256 signatureZ) =
            signingKey.createSignature(messageHash);

        assertEq(signatureCommitmentX, 0x01B0906E61AD4FCB2B91129D75723A1C6CD03D56B52A6A78A155292F0CF558E7);
        assertEq(signatureCommitmentY, 0xB4AFD878B61315BC5288973744B9B569B9014B32FFC88F90AA511DE056D29D60);
        assertEq(signatureZ, 0x9C626F590D090702BE5396079D5A8644CC7099AC80B7A7F8CD4574E7E464CCA7);

        assertTrue(
            FROST.verifySignature(
                publicKeyX, publicKeyY, signatureCommitmentX, signatureCommitmentY, signatureZ, messageHash
            )
        );
    }
}
