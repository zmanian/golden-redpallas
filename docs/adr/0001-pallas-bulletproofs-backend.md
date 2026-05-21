# ADR 0001: Build a Dedicated Pallas-Field Proof Backend

## Status

Accepted.

## Context

Golden for `RedPallas` needs a proof system that works over the Pallas scalar
field and can prove the helper-curve eVRF relation used to derive DKG masks.

The current public Rust `bulletproofs` crate is version `5.0.0`. Its crate
metadata describes it as "a pure-Rust implementation of Bulletproofs using
Ristretto". That is the wrong curve and scalar field for a native
`RedPallas`/Pallas-field Golden proof.

Using it directly would force one of two bad options:

- emulate Pallas/Vesta arithmetic inside a Ristretto/Curve25519 proof field;
- fork or heavily rewrite the backend while still carrying APIs designed around
  Ristretto assumptions.

Both options add avoidable complexity before the Golden eVRF circuit is even
specified.

## Decision

Implement a dedicated Pallas-field proof backend behind the existing
`golden_proofs::ProofSystem` trait.

The existing `FixtureProofSystem` remains only an integration-test backend. It
must not be exposed as production cryptography.

The production backend should live under `golden-proofs` and satisfy the same
public API:

- `ProofPublicInputs`
- `ProofWitness`
- `MaskProof`
- `ProofSystem::prove`
- `ProofSystem::verify`
- `ProofSystem::verify_batch`

## Consequences

- The DKG and proof plumbing can continue to develop against stable proof
  interfaces.
- The real backend can use Pallas scalar arithmetic directly.
- Batch verification can be designed for the Golden transcript shape from the
  start.
- More implementation work is required than reusing a crate wholesale.
- The custom backend will require a focused cryptographic audit.

## Implementation Notes

The first production backend milestone should not attempt the full Golden eVRF
circuit. It should implement a small Pallas-field inner-product proof skeleton
with deterministic tests, transcript domain separation, and batch-verification
shape. After that, add the R1CS layer and eVRF constraints incrementally.
