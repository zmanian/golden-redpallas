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
- [ ] Define participant identifiers compatible with FROST identifiers.

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
- [x] Add deterministic hash-to-field trace for mask derivation.
- [ ] Implement Pallas-field constraints for eVRF mask computation.
- [ ] Implement batch verification.
- [ ] Add malformed-transcript negative tests.
- [ ] Benchmark prover and verifier cost for `n = 8`, `n = 16`, and `n = 32`.

## Milestone 4: FROST RedPallas

- [ ] Implement or upstream Pallas ciphersuite support.
- [ ] Map Golden shares to FROST signing shares.
- [ ] Enforce RedPallas even-y key normalization.
- [ ] Implement ZIP-312 re-randomization support.
- [ ] Verify signatures against Zcash RedPallas test vectors.

## Milestone 5: Infrastructure

- [ ] Define Golden DKG session transcript format.
- [ ] Add CLI commands for creating, posting, verifying, and recovering shares.
- [ ] Prototype frostd session support.
- [ ] Add wallet backup JSON format.

## Milestone 6: Audit Readiness

- [ ] Threat model.
- [ ] Constant-time review.
- [ ] Dependency review.
- [ ] Fuzzing for transcript parsing.
- [ ] Independent cryptographic audit.
