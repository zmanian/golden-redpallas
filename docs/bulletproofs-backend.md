# Bulletproofs Backend Notes

The production proof backend is not implemented yet. The current
`golden-proofs` crate defines the API that a backend must satisfy and includes a
non-zero-knowledge fixture backend for integration tests.

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
types before the Bulletproofs backend exists.

The fixture backend currently checks:

- dealer helper secret matches dealer helper public key;
- Vesta DH shared point matches dealer secret and participant public key;
- mask matches the shared point and transcript binding;
- mask commitment equals `mask * Pallas::generator()`;
- proof digest changes when session, keys, mask commitment, or public polynomial
  change.

## Pallas Backend Skeleton

`golden-proofs` now exposes a feature-gated `pallas-backend` skeleton:

```sh
cargo test -p golden-proofs --features pallas-backend
```

The `PallasProofSkeleton` backend is still not zero-knowledge. It exists to pin
the Pallas-specific transcript domains, proof byte framing, deterministic
challenge derivation, generator-derivation boundary, and first executable
mask-relation constraint layer that the production backend will replace with
real Pallas-field Bulletproofs constraints.

The skeleton currently covers:

- public/witness consistency checks shared with the fixture backend;
- deterministic Fiat-Shamir challenge derivation over the Golden mask public
  inputs;
- proof framing with backend id, magic bytes, version, challenge, constraint
  commitment, opening nonce commitment, opening response, and digest;
- deterministic Pallas generator derivation for backend tests;
- a deterministic mask hash-to-field trace containing the shared-point encoding,
  transcript digest, raw 64-byte hash output, and reduced Pallas mask;
- trace validation for `mask = H(shared_point, transcript)`;
- public commitment checks for `mask_commitment = mask * Pallas::generator()`;
- a Schnorr-style proof that the mask-variable commitment opens to the public
  mask without serializing the blinding;
- single and batch verification behavior under the `ProofSystem` trait;
- malformed, tampered proof, and malformed constraint rejection tests.

## Next Implementation Step

Replace hash trace validation with arithmetic constraints for the hash-to-field
relation, then fold the Schnorr opening proof into the Pallas-field proof
transcript.
