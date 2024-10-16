use frost_secp256k1_evm as frost;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

fn convert_public_key(serialized: &[u8]) -> Vec<u8> {
    let serialized_element = &serialized[..33].try_into().unwrap();
    let deserialized_element =
        <<frost::Secp256K1Keccak256 as frost::Ciphersuite>::Group as frost::Group>::deserialize(
            serialized_element,
        )
        .unwrap();
    let encoded_point = deserialized_element.to_encoded_point(false);
    encoded_point.as_bytes()[1..].to_vec()
}

fn slice2hex(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn main() -> Result<(), frost::Error> {
    let mut rng = StdRng::seed_from_u64(123);
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // Verifies the secret shares from the dealer and store them in a BTreeMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..=min_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes();
    // In practice, the SigningPackage must be sent to all participants
    // involved in the current signing (at least min_signers participants),
    // using an authenticate channel (and confidential if the message is secret).
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);

    let verifying_key_compressed = pubkey_package.verifying_key().serialize()?;
    let verifying_key_uncompressed = convert_public_key(&verifying_key_compressed);
    let (x, y) = verifying_key_uncompressed.split_at(32);

    println!("verifying_key:");
    println!("  X: 0x{}", slice2hex(x));
    println!("  Y: 0x{}", slice2hex(y));

    println!();

    let group_commitment_compressed = group_signature.serialize()?;
    let group_commitment_uncompressed = convert_public_key(&group_commitment_compressed);
    let (x, y) = group_commitment_uncompressed.split_at(32);

    println!("group_commitment (group_signature.R):");
    println!("  X: 0x{}", slice2hex(x));
    println!("  Y: 0x{}", slice2hex(y));

    println!();

    println!("group_signature (group_signature.z):");
    println!("  z: 0x{}", slice2hex(&group_commitment_compressed[33..]));

    Ok(())
}
