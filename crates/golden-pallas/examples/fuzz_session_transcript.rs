//! Executable fuzz harness for Golden DKG session transcript parsing.

use std::{env, fs, str};

use golden_pallas::DkgFixture;

fn main() {
    for path in env::args().skip(1) {
        let input = fs::read(&path).expect("read fuzz input");
        fuzz_one(&input);
    }
}

fn fuzz_one(input: &[u8]) {
    let Ok(text) = str::from_utf8(input) else {
        return;
    };

    if let Ok(fixture) = DkgFixture::parse(text) {
        let _ = fixture.run();
    }
}
