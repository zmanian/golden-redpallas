# Parser Fuzzing

Golden session transcript parsing is covered by:

- `transcript_parser_fuzz_corpus_does_not_panic`, a deterministic malformed
  corpus test in `golden-pallas`.
- `crates/golden-pallas/examples/fuzz_session_transcript.rs`, an executable
  harness that accepts arbitrary input files and feeds valid UTF-8 into
  `DkgFixture::parse` and `DkgFixture::run`.

Run the harness with:

```sh
cargo run -p golden-pallas --example fuzz_session_transcript -- test-vectors/golden-pallas/dkg-v0.txt
```

The harness intentionally treats parser errors as successful fuzz outcomes; the
property under test is that malformed transcript bytes do not panic and valid
transcripts continue into normal validation.

Proof public-input decoding is covered by:

- `ProofPublicInputs::from_bytes` unit tests in `golden-proofs`, including
  canonical round trips and malformed encodings.
- `crates/golden-proofs/examples/fuzz_proof_public_inputs.rs`, an executable
  harness that accepts arbitrary input files and feeds them into the strict
  public-input decoder.

Run the harness with:

```sh
cargo run -p golden-proofs --example fuzz_proof_public_inputs -- test-vectors/golden-pallas/dkg-v0.txt
```

The proof-input harness intentionally treats decoder errors as successful fuzz
outcomes; the property under test is that malformed proof-public-input bytes do
not panic and valid encodings continue into transcript binding logic.
