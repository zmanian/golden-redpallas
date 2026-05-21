//! Print the checked-in Golden `RedPallas` eVRF test vector.

use std::fmt::Write;

use golden_pallas::{
    HelperSecretKey, VestaScalar, derive_mask, hash_to_vesta_h1, hash_to_vesta_h2,
};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write to string");
    }
    out
}

fn main() {
    let dealer_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
    let participant_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
    let transcript = b"golden-redpallas-evrf-test-vector-v0";
    let hash_message = b"golden-redpallas-hash-to-vesta-vector-v0";

    let dealer_public = dealer_secret.public_key();
    let participant_public = participant_secret.public_key();
    let shared = dealer_secret.diffie_hellman(participant_public);
    let mask = derive_mask(shared, transcript);
    let h1 = hash_to_vesta_h1(hash_message);
    let h2 = hash_to_vesta_h2(hash_message);

    println!("version=0");
    println!("dealer_secret={}", hex(&dealer_secret.scalar().to_bytes()));
    println!(
        "participant_secret={}",
        hex(&participant_secret.scalar().to_bytes())
    );
    println!("dealer_public={}", hex(&dealer_public.point().to_bytes()));
    println!(
        "participant_public={}",
        hex(&participant_public.point().to_bytes())
    );
    println!("shared_point={}", hex(&shared.point().to_bytes()));
    println!("transcript={}", String::from_utf8_lossy(transcript));
    println!("mask={}", hex(&mask.to_bytes()));
    println!("hash_message={}", String::from_utf8_lossy(hash_message));
    println!("h1={}", hex(&h1.to_bytes()));
    println!("h2={}", hex(&h2.to_bytes()));
}
