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

## Next Implementation Step

Add a `golden-proofs::pallas` proof backend behind a feature flag. The
implementation should satisfy the same `ProofSystem` trait and reuse the fixture
tests as behavioral tests, then add real proof serialization and batch
verification tests.
