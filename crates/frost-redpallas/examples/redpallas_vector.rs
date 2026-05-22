//! Generate a deterministic `RedPallas` `SpendAuth` signature vector.

use rand_core::{CryptoRng, Error, RngCore};
use reddsa::{SigningKey, VerificationKey, orchard};

const MESSAGE: &[u8] = b"Golden RedPallas SpendAuth vector v0";

struct FixedRng {
    byte: u8,
}

impl FixedRng {
    const fn new() -> Self {
        Self { byte: 0x42 }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.byte;
            self.byte = self.byte.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

fn main() {
    let mut scalar = [0_u8; 32];
    scalar[0] = 7;
    let signing_key =
        SigningKey::<orchard::SpendAuth>::try_from(scalar).expect("valid signing key");
    let verification_key = VerificationKey::from(&signing_key);
    let signature = signing_key.sign(FixedRng::new(), MESSAGE);
    let public_key: [u8; 32] = verification_key.into();
    let signature: [u8; 64] = signature.into();

    println!("message = {}", String::from_utf8_lossy(MESSAGE));
    println!("public_key = {public_key:?}");
    println!("signature = {signature:?}");
}
