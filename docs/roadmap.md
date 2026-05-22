# Roadmap

See [`implementation-testing-plan.md`](implementation-testing-plan.md) for the
full staged implementation plan, test matrix, CI plan, and release gates.

## Milestone 0: Repository Baseline

- [x] Rust workspace.
- [x] Core field abstraction.
- [x] Shamir evaluation and interpolation tests.
- [x] Dealer transcript data model.
- [x] Placeholder crates for Pallas and FROST integration.

## Milestone 1: Pallas Core Types

- [x] Add validated protocol configuration for threshold and participants.
- [x] Add verified transcript wrapper for aggregation-safe APIs.
- [x] Add participant share aggregation across verified dealer transcripts.
- [x] Add generic public-key commitment aggregation.
- [x] Add `pasta_curves` dependency.
- [x] Bind `golden_core::FieldElement` to `pasta_curves::pallas::Scalar`.
- [x] Add serialization for Pallas scalars and points.
- [x] Add Pallas public polynomial commitments.
- [x] Define participant identifiers compatible with FROST identifiers.

## Milestone 2: Vesta eVRF

- [x] Select hash-to-Vesta construction and domain separators.
- [x] Add Vesta helper-curve point and scalar wrappers.
- [x] Implement dealer and participant helper-curve keys.
- [x] Implement DH-derived mask generation.
- [x] Add test vectors for deterministic transcripts.
- [x] Document all domain separators.

## Milestone 2.5: Golden DKG Simulation

- [x] Add deterministic `t = 2, n = 3` DKG fixture.
- [x] Generate dealer transcripts with Pallas commitments and Vesta-derived masks.
- [x] Recover aggregate participant shares from public transcripts.
- [x] Verify aggregate public key against reconstructed aggregate secret.
- [x] Reject corrupted mask commitments.
- [x] Reject fewer than threshold valid dealer transcripts.
- [x] Verify transcript ordering does not change recovered shares.

## Milestone 3: Golden Proofs

- [x] Add proof-facing API and fixture backend.
- [x] Wire fixture proof verification into DKG recovery.
- [x] Add proof batch-verification API and fixture DKG batch path.
- [x] Share DKG mask transcript binding across DKG and proof code.
- [x] Document Bulletproofs backend decision constraints.
- [x] Decide between existing Bulletproofs R1CS library and custom implementation.
- [x] Add feature-gated Pallas backend skeleton and transcript tests.
- [x] Add executable Pallas mask-relation constraint layer.
- [x] Replace opened mask commitment with a Schnorr-style opening proof.
- [x] Add Pallas inner-product proof primitive.
- [x] Add Pallas circuit layout and R1CS adapter.
- [x] Connect Pallas circuit proof to IPA.
- [x] Add deterministic hash-to-field trace for mask derivation.
- [x] Add byte-limb constraint trace for mask derivation.
- [x] Add prover-side Vesta DH constraint trace.
- [x] Replace serialized shared-point/mask trace with an opaque Pallas circuit
      proof envelope.
- [x] Add deterministic proof-byte reproduction test under an injected test RNG.
- [x] Lower mask digest bit/range checks and field reduction into the Pallas
      circuit proof verifier.
- [x] Lower shared-point x-coordinate encoding and Vesta curve-equation checks
      into the Pallas circuit proof verifier.
- [x] Lower compressed-point sign binding into the Pallas circuit proof
      verifier.
- [x] Lower Vesta scalar multiplication into the Pallas circuit proof verifier.
- [x] Lower Blake2b mask digest generation into the Pallas circuit proof
      verifier.
- [x] Wire Pallas proof backend into proofed DKG recovery.
- [x] Implement Pallas-field trace views for eVRF mask computation.
- [x] Implement batch verification.
- [x] Add malformed-transcript negative tests.
- [x] Add canonical proof public-input encoding with malformed decoder tests.
- [x] Add proof public-input decoder fuzz-smoke harness.
- [x] Add benchmark harness for prover, verifier, proof-size, and direct batch
      verifier cost for `n = 4`, `n = 8`, `n = 16`, and `n = 32`.

## Milestone 4: FROST RedPallas

- [x] Implement or upstream Pallas ciphersuite support.
- [x] Map Golden shares to FROST signing shares.
- [x] Enforce RedPallas even-y key normalization.
- [x] Implement ZIP-312 re-randomization support.
- [x] Verify signatures against Zcash RedPallas test vectors.

## Milestone 5: Infrastructure

- [x] Define Golden DKG session transcript format.
- [x] Add CLI commands for creating, posting, verifying, and recovering shares.
- [x] Prototype frostd session support.
- [x] Add wallet backup JSON format.

## Milestone 6: Audit Readiness

- [x] Threat model.
- [x] Constant-time review.
- [x] Dependency review.
- [x] Fuzzing for transcript parsing.
- [ ] Independent cryptographic audit.
  - Audit package and handoff materials are prepared in
    [`audit-package.md`](audit-package.md) and
    [`independent-audit-handoff.md`](independent-audit-handoff.md); completion
    requires external reviewer sign-off.
