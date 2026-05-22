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

`ProofPublicInputs` must remain limited to the session binding, dealer and
participant identifiers, helper public keys, mask commitment, and public
polynomial. The DH shared point and derived mask are witness/proof-internal
values, not public inputs.

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
circuit. It now includes a small Pallas-field inner-product proof layer with
deterministic tests, transcript domain separation, hash-to-curve generator
derivation, compact proof encoding, and the basic verifier rejection shape. It
also includes the R1CS-facing circuit layout and constant-column preserving
R1CS adapter, plus a first circuit proof object that reduces constraints to IPA
and round-trips as opaque bytes. The active Pallas proof envelope now embeds
that circuit proof instead of serializing the shared-point/mask trace. The mask
circuit now uses Arkworks gadgets to prove Blake2b-512 mask digest generation,
digest reduction to the hidden mask scalar, compressed shared-point encoding,
Vesta curve membership, and y-parity sign binding. A linked Arkworks-derived
circuit proves the Vesta scalar-multiplication relation for the dealer public
key and shared point against the same hidden coordinate commitments. A private
test-only prover seam accepts an injected RNG so release tests can reproduce
opaque proof bytes exactly while the public prover remains randomized with
`OsRng`. The next step is profiling, hardening, and independent cryptographic
review.
