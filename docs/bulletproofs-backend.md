# Bulletproofs Backend Notes

The production-reviewed proof backend is not available yet. The current
`golden-proofs` crate defines the API that a backend must satisfy, includes a
non-zero-knowledge fixture backend for integration tests, and now carries an
unaudited Pallas Bulletproofs backend candidate under the `pallas-backend`
feature.

## Current Decision

Build a dedicated Pallas-field proof backend behind `ProofSystem`; see
[`adr/0001-pallas-bulletproofs-backend.md`](adr/0001-pallas-bulletproofs-backend.md).

Do not build the Golden eVRF circuit directly on the public Rust `bulletproofs`
crate. Current crate metadata for `bulletproofs 5.0.0` describes it as a
Ristretto-based Bulletproofs implementation. Golden for `RedPallas` needs a
proof system over the Pallas scalar field with generators and transcript binding
that match the Pasta-cycle implementation.

## Backend Requirements

- Pallas scalar field arithmetic.
- Commitment generators suitable for the DKG public inputs.
- R1CS or equivalent constraints for the Vesta eVRF relation.
- Fiat-Shamir transcript domain separation.
- Single proof verification.
- Batch proof verification.
- Deterministic test vectors for public inputs and proofs.
- Explicit rejection of tampered public inputs.

## Fixture Backend

`FixtureProofSystem` is intentionally not zero-knowledge and must never be used
for production. It validates witness/public-input consistency and emits a digest
of public inputs so the rest of the codebase can integrate against stable proof
types before the Bulletproofs backend exists. `ProofPublicInputs` intentionally
does not expose the DH shared point or derived mask; those values live in
`ProofWitness` and are hidden by the Pallas backend candidate's opaque circuit
proof envelope.

The fixture backend currently checks:

- dealer helper secret matches dealer helper public key;
- Vesta DH shared point matches dealer secret and participant public key;
- private mask witness matches the shared point and transcript binding;
- mask commitment equals `mask * Pallas::generator()`;
- proof digest changes when session, keys, mask commitment, or public polynomial
  change.

## Pallas Backend Candidate

`golden-proofs` now exposes a feature-gated `pallas-backend` candidate:

```sh
cargo test -p golden-proofs --features pallas-backend
```

The `PallasProofSkeleton` type name is historical, but the implementation now
emits linked opaque Pallas circuit proofs rather than serialized witness traces.
It exists to pin the Pallas-specific transcript domains, proof byte framing,
deterministic challenge derivation, hash-to-curve generator derivation,
public/private input split, and executable mask/DH circuit layer that must pass
performance hardening and independent cryptographic review before production
use.

Important caveat: the skeleton no longer serializes the shared point or reduced
mask, and it now synthesizes the Blake2b-512 mask hash relation inside the
Pallas circuit. The mask circuit constrains the private shared-point compressed
encoding, the public mask transcript, the Blake2b compression output, and the
field reduction from the 64-byte digest to the hidden mask scalar. It also binds
the private shared-point affine coordinates to hidden shared-coordinate
commitments, binds the compressed sign bit to y parity, and enforces the Vesta
curve equation for that affine point. A linked DH circuit proves that those same
coordinates satisfy `dealer_public = dealer_secret * Vesta::generator()` and
`shared_point = dealer_secret * participant_public`. The backend remains
unaudited and non-production until the proof system receives independent
cryptographic review and performance hardening.

The skeleton currently covers:

- public/witness consistency checks shared with the fixture backend;
- deterministic Fiat-Shamir challenge derivation over the Golden mask public
  inputs without publishing the DH shared point or mask as public inputs;
- proof framing with backend id, magic bytes, version, and embedded opaque
  Pallas circuit proof bytes;
- deterministic proof-byte reproduction under an injected test RNG, while the
  public prover continues to use OS randomness;
- deterministic Pallas generator derivation using Pasta hash-to-curve, avoiding
  generator vectors with known discrete logarithms relative to the Orchard
  basepoint;
- a feature-gated Pallas inner-product argument with logarithmic prover and
  verifier folding, transcript-bound setup and claims, compact proof encoding,
  and rejection tests for tampered products and vector lengths;
- digest-sized Fiat-Shamir setup/circuit transcript commitments for the Pallas
  circuit and IPA layers, avoiding repeated expansion of every generator and
  matrix entry into the interactive transcript prefix while preserving
  domain-separated binding;
- a Pallas-field circuit layout for `1 | committed values | left wires | right
  wires | output wires`, plus an R1CS-to-circuit adapter that preserves the
  constant column instead of routing it through a free witness wire;
- a Pallas circuit proof object that commits to witness wires with prover
  randomness, reduces circuit constraints with Fiat-Shamir challenges, checks
  the Bulletproofs polynomial identities, and discharges the final inner-product
  claim through the Pallas IPA proof;
- reusable circuit-family setup generators for same-shaped mask and Vesta-DH
  circuits, with cached IPA generator vectors to avoid repeated hash-to-curve
  derivation across proof batches;
- circuit proof byte encoding and parsing for the opaque proof object;
- active skeleton proof encoding that embeds linked mask and Vesta-DH circuit
  proofs instead of a serialized shared-point/mask trace;
- a privacy regression test that rejects proof bytes containing the private
  shared-point or mask encodings;
- an Arkworks-synthesized Blake2b-512 circuit for
  `H(MASK_TO_FIELD || compressed_shared_point || mask_transcript)`, converted
  into the Pallas circuit layout and tied to the hidden mask scalar by field
  reduction of the 64-byte digest;
- in-circuit boolean constraints for the private shared-point compressed
  encoding, sign-bit/y-parity binding, hidden affine coordinate commitments, and
  the Vesta curve equation for the private shared point;
- an Arkworks-synthesized Vesta scalar-multiplication R1CS, converted into the
  Pallas circuit layout and linked to the mask circuit through shared hidden
  x/y coordinate commitments;
- a deterministic mask hash-to-field trace containing the shared-point encoding,
  transcript digest, raw 64-byte hash output, and reduced Pallas mask;
- a constraint-oriented byte-limb view of the mask trace with length, range, and
  canonical mask encoding checks;
- a Pallas-field limb view of the mask hash trace and Vesta DH trace, with each
  byte witness represented as a Pallas scalar and range-checked before relation
  verification;
- a prover-side Vesta DH constraint trace and in-circuit proof for
  `dealer_public = dealer_secret * Vesta::generator()` and
  `shared_point = dealer_secret * participant_public`;
- trace validation for `mask = H(shared_point, transcript)`;
- public commitment checks for `mask_commitment = mask * Pallas::generator()`;
- a versioned canonical byte encoding for proof public inputs, with strict
  rejection of truncated data, trailing data, zero participant identifiers,
  empty public polynomials, and non-canonical point encodings;
- a circuit proof that the public `mask_commitment` opens to a hidden committed
  mask scalar without serializing the mask;
- end-to-end proofed DKG recovery using the Pallas backend candidate under the
  `pallas-backend` feature;
- single and batch verification behavior under the `ProofSystem` trait;
- malformed, tampered proof, and malformed constraint rejection tests.

## Batch Verification Contract

The current `PallasProofSkeleton::verify_batch` implementation is conservative:
it verifies each batch member with the same verifier used by
`ProofSystem::verify`. This is not an optimized aggregated Bulletproofs batch
algorithm. Its soundness is the conjunction of the single-proof checks for every
member, and its failure behavior is deterministic: the method returns the first
backend, framing, public-input, circuit-proof, or constraint failure encountered
while iterating over the supplied batch.

The production backend may replace this with an aggregated verifier, but it must
preserve the same external contract: every invalid member must make the whole
batch fail, and no caller may need to retry single verification to learn whether
the batch was accepted.

## Test Cost

The Arkworks-synthesized Blake2b mask circuit makes full
`PallasProofSkeleton::prove` tests expensive in debug builds. Default debug test
runs cover circuit synthesis, satisfaction, parser failures, malformed proofs,
and batch failure without generating a full Blake2b proof. Release-mode
`golden-proofs` tests additionally run the full proof happy path, proof-byte
determinism, privacy scan, core proof tamper matrix, and public-input tamper
checks, plus a two-proof batch verification success case and a one-proof
proofed-DKG recovery/tamper smoke test. The main end-to-end skeleton proof test
can be run directly with:

```sh
cargo test --release -p golden-proofs --features pallas-backend pallas::tests::skeleton_backend_proves_and_verifies_valid_inputs -- --exact --nocapture
```

The deterministic proof-vector check is also release-mode active:

```sh
cargo test --release -p golden-proofs --features pallas-backend pallas::tests::skeleton_deterministic_rng_reproduces_proof_vector_bytes -- --exact --nocapture
```

So is the proof-privacy regression that scans the opaque proof bytes for the
private shared-point and mask encodings:

```sh
cargo test --release -p golden-proofs --features pallas-backend pallas::tests::skeleton_proof_bytes_do_not_serialize_private_trace_material -- --exact --nocapture
```

CI also runs the full release-mode Pallas proof backend suite:

```sh
cargo test --release -p golden-proofs --features pallas-backend
```

The benchmark harness can also report verifier-side circuit dimensions without
creating a proof:

```sh
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench -- --circuit-profile
```

The current profile is archived in
`docs/benchmarks/pallas-proof-circuit-profile-2026-05-22.csv`. It reports
152,298 constraints for the mask hash/commitment circuit and 8,661 constraints
for the Vesta-DH circuit, making the Arkworks-synthesized Blake2b mask circuit
the main target for performance hardening.

The full-fixture proofed-DKG Pallas integration tests stay opt-in as ignored
heavy tests and can be run explicitly with
`cargo test -p golden-proofs --features pallas-backend -- --ignored`.

## Next Implementation Step

Harden the skeleton as an auditable backend: profile the Arkworks-synthesized
mask circuit, reduce avoidable prover/verifier overhead, and prepare the proof
system for independent cryptographic review. The benchmark harness now emits
machine-readable prover timing, prover RSS, verifier, proof-size, and direct
batch-verifier fields for `n = 4, 8, 16, 32`, plus a `--single-proof` smoke mode
and a `--circuit-profile` mode for quick current-backend measurements. A current
one-proof smoke snapshot lives in
`docs/benchmarks/pallas-proof-smoke-2026-05-22.csv`; a current circuit-size
profile lives in
`docs/benchmarks/pallas-proof-circuit-profile-2026-05-22.csv`; regenerate the
full DKG matrix from the current harness before audit closeout or performance
comparisons.
The current-harness `n = 4` row is archived as
`docs/benchmarks/pallas-proof-dkg-2026-05-22-n4.csv`; the current-harness
`n = 8` row is archived as
`docs/benchmarks/pallas-proof-dkg-2026-05-22-n8.csv`; the `n = 16` and `n = 32`
rows remain pending.
