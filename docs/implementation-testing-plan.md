# Implementation and Testing Plan

This plan turns the Golden for `RedPallas` goal into staged engineering work with
explicit deliverables, test gates, and audit checkpoints. The project must not be
used with real Zcash keys or funds until every cryptographic milestone has passed
independent review.

## Principles

- Keep protocol-independent Golden logic separate from curve-specific code.
- Prefer audited Rust crypto crates over custom arithmetic and serialization.
- Treat every cryptographic equation as a testable contract with positive and
  negative cases.
- Add deterministic test vectors at each boundary before optimizing.
- Benchmark only after correctness tests and malformed-input tests are in place.
- Make unsafe or unaudited placeholders impossible to call accidentally from
  production-facing APIs.

## Workstreams

1. `golden-core`: Shamir sharing, transcript shape, participant indexing,
   aggregation, verification orchestration, serialization-neutral traits.
2. `golden-pallas`: `pasta_curves` bindings, Pallas scalar/group wrappers, Vesta
   helper-curve operations, eVRF mask derivation, domain separation.
3. `golden-proofs`: Bulletproofs/R1CS backend, Golden eVRF circuit,
   commitments, batched verification.
4. `frost-redpallas`: FROST ciphersuite integration, `RedPallas` even-y
   normalization, ZIP-312 re-randomized signing hooks.
5. `golden-cli`: local DKG transcript generation, verification, recovery,
   backup export, and interop test harnesses.
6. Integration: frostd or wallet-facing session transport, transcript storage,
   authenticated participant discovery, and backup workflows.

## Milestone 1: Core Protocol Completion

### Implementation

- Finalize `FieldElement` requirements or replace with ecosystem traits when
  concrete Pallas support lands.
- Add participant-set validation:
  - non-zero identifiers;
  - no duplicates;
  - threshold `1 <= t <= n`;
  - identifier conversion to field elements without ambiguity.
- Add dealer aggregation:
  - recover each dealer share by subtracting the locally derived mask;
  - sum valid dealer shares into the participant's final signing share;
  - sum public polynomial constant commitments into the group public key;
  - reject duplicate or insufficient dealer transcripts.
- Model commitment equations through traits:
  - scalar multiplication by the DKG generator;
  - public polynomial evaluation in the group;
  - mask commitment addition.
- Add serialization data types without committing to wire formats too early.

### Tests

- Unit tests for threshold validation and duplicate rejection.
- Property-style tests over the test field:
  - random polynomials reconstruct the same constant from any `t` shares;
  - fewer than `t` shares do not reconstruct in deterministic negative cases;
  - aggregated dealer shares reconstruct the sum of dealer secrets.
- Transcript tests:
  - missing participant;
  - duplicate participant;
  - rejected proof;
  - failed commitment equation;
  - insufficient valid dealers.

### Acceptance Criteria

- `golden-core` has no curve-specific dependencies.
- All core aggregation paths are covered by tests over the test field.
- Public APIs distinguish unverified transcripts from verified transcripts.

## Milestone 2: Pallas Scalar and Group Bindings

### Implementation

- Add `pasta_curves` and any required trait crates.
- Implement wrappers for:
  - Pallas scalar field;
  - Pallas group element;
  - Vesta group element;
  - canonical compressed encodings.
- Implement constant-time equality and conditional negation through existing
  primitives.
- Implement public polynomial commitments:
  - coefficient commitments `[f_k]G`;
  - group evaluation `F(x) = sum_k [x^k]F_k`;
  - commitment equation `c_ji G = F_j(x_i) + M_ij`.
- Define domain separators for every hash:
  - DKG session;
  - participant identifiers;
  - dealer transcript;
  - eVRF `H1`;
  - eVRF `H2`;
  - mask-to-field;
  - proof transcript.

### Tests

- Known scalar encoding round trips.
- Reject non-canonical scalar and point encodings.
- Pallas group law sanity checks against `pasta_curves`.
- Polynomial commitment tests:
  - committed evaluation matches scalar evaluation times generator;
  - malformed coefficient commitment fails verification;
  - participant identifier changes alter the evaluation point.
- Domain-separation tests:
  - all domains are unique;
  - changing session id changes transcript hashes and masks.

### Acceptance Criteria

- `golden-pallas` can verify unmasked Shamir commitments over Pallas.
- No custom field or curve arithmetic is introduced unless documented with an
  audit requirement.

## Milestone 3: Vesta eVRF Mask Derivation

### Implementation

- Define dealer and participant helper-curve key material.
- Implement hash-to-Vesta functions for `H1` and `H2`.
- Implement DH-derived shared point computation on Vesta.
- Implement mask derivation into the Pallas scalar field.
- Bind masks to:
  - session id;
  - dealer id;
  - participant id;
  - dealer public key;
  - participant public key;
  - public polynomial commitment digest.
- Add transcript types for public eVRF inputs and private witnesses.

### Tests

- Deterministic eVRF test vectors from fixed seeds.
- Dealer and participant independently derive the same mask.
- Different session ids, dealer ids, participant ids, or public keys produce
  different masks.
- Invalid helper-curve encodings are rejected.
- Mask derivation never accepts identity public keys.

### Acceptance Criteria

- Each participant can recover its own dealer shares locally.
- Observers can receive all public eVRF inputs needed for proof verification.
- Test vectors are checked into the repo.

## Milestone 4: Golden Proof System

### Implementation

- Decide proof backend:
  - reuse an existing Bulletproofs/R1CS implementation if it supports the
    Pallas scalar field and required generator configuration;
  - otherwise create a dedicated `golden-proofs` crate.
- Define the exact statement:
  - dealer public key consistency;
  - Vesta DH computation;
  - mask hash relation;
  - mask commitment relation;
  - binding to session and transcript digest.
- Implement gadgets:
  - field bit decomposition;
  - boolean/range constraints;
  - Vesta point arithmetic or the Golden arithmetization used to avoid proving
    final DKG-group multiplication;
  - hash-to-field constraints or public-input treatment for hash-to-curve where
    appropriate.
- Implement proof creation for one dealer transcript.
- Implement single and batch verification.
- Add transcript domain separation for Fiat-Shamir challenges.

### Tests

- Proof accepts valid witness/transcript pairs.
- Proof rejects:
  - wrong dealer secret;
  - wrong participant public key;
  - wrong mask commitment;
  - wrong masked share;
  - changed session id;
  - changed public polynomial;
  - reordered transcript inputs if ordering is part of the digest.
- Batch verification rejects if any included proof is invalid.
- Serialization round trips for proofs and public inputs.
- Fuzz proof-public-input decoders.

### Benchmarks

- Prover time and memory for `n = 4, 8, 16, 32`.
- Single verifier time for `n = 4, 8, 16, 32`.
- Batch verifier time for dealer counts `m = 4, 8, 16, 32`.
- Proof size as a function of participants and dealers.

### Acceptance Criteria

- The verifier is deterministic and rejects all malformed negative tests.
- Batch verification has a clear soundness rationale and documented failure
  behavior.
- Benchmarks produce reproducible machine-readable output.

## Milestone 5: Complete Golden DKG

### Implementation

- Add end-to-end dealer transcript generation:
  - sample dealer polynomial;
  - compute public polynomial;
  - derive per-participant masks;
  - publish masked shares and proofs.
- Add participant verification and recovery:
  - validate all dealer transcripts;
  - keep only valid contributions;
  - recover own shares;
  - aggregate final share;
  - compute aggregate public key and verification shares.
- Define threshold policy:
  - minimum valid dealer count;
  - whether dealers are also participants;
  - treatment of absent, invalid, or duplicated dealers.
- Add transcript manifests with stable ordering rules.

### Tests

- End-to-end DKG for `t = 1`, `t = 2`, `t = n`, and representative larger
  configurations.
- Every participant derives a final share that reconstructs the same group key.
- Invalid dealer transcripts are excluded without changing valid participants'
  recovered shares.
- Reordering public transcript files does not change final output.
- Golden output is deterministic when fed deterministic seeds.

### Acceptance Criteria

- `golden-cli` can run a local file-based DKG simulation.
- The simulation emits per-participant backups and a shared public key.
- All outputs are reproducible from deterministic test fixtures.

## Milestone 6: `RedPallas` FROST Integration

### Implementation

- Evaluate the cleanest integration path:
  - upstream or implement a `frost-core` ciphersuite for Pallas;
  - reuse Zcash `reddsa` `redpallas` types where possible;
  - avoid duplicating signature internals if existing crates expose safe hooks.
- Convert Golden shares into FROST key packages.
- Convert Golden public polynomial data into FROST verification shares.
- Implement even-y normalization:
  - inspect aggregate public key parity;
  - if odd, negate aggregate key and every secret/verification share;
  - test that normalized key matches Zcash `RedPallas` expectations.
- Implement ZIP-312 re-randomization support:
  - derive randomizer;
  - compute randomized public key;
  - bind randomizer into signing transcript;
  - produce signatures accepted by Zcash verification code.

### Tests

- FROST key package serialization round trips.
- Even-y tests for both even and odd aggregate keys.
- Threshold signing succeeds with any valid signing subset of size `t`.
- Signing fails with fewer than `t` shares.
- Re-randomized signatures verify under the randomized public key.
- Different randomizers produce unlinkable public keys/signatures for the same
  base key and message.
- Interop tests against Zcash `RedPallas` verification.

### Acceptance Criteria

- Golden-generated shares can produce valid threshold `RedPallas` signatures.
- Even-y normalization is applied exactly once and is visible in backups.
- ZIP-312 behavior is covered by test vectors.

## Milestone 7: Orchard Wallet and Transaction Integration

### Implementation

- Define what Golden generates directly:
  - spend-authorizing key `ask` shares;
  - aggregate spend-authorizing public key;
  - verification shares and participant metadata.
- Document how other Orchard keys are obtained:
  - generated independently;
  - imported from wallet context;
  - never silently derived from threshold `ask` unless a Zcash-compatible design
    is specified.
- Add transaction signing integration tests:
  - create Orchard spend authorization payload;
  - coordinate FROST signing;
  - verify final transaction authorization signature.
- Keep network/broadcasting outside this repo until signing correctness is
  proven.

### Tests

- Orchard spend authorization digest fixtures.
- Signature verification against Zcash libraries.
- Negative tests for wrong transaction digest and wrong randomized key.
- Backup restore test: export shares, import into fresh process, sign.

### Acceptance Criteria

- A local integration test signs and verifies an Orchard spend authorization
  payload without using real funds.
- Backup restore produces identical verification shares and signing behavior.

## Milestone 8: CLI, frostd, and Operations

### Implementation

- CLI commands:
  - `session create`;
  - `dealer contribute`;
  - `transcript verify`;
  - `share recover`;
  - `backup export`;
  - `backup inspect`;
  - `bench`.
- File formats:
  - session manifest;
  - participant registration;
  - dealer transcript;
  - proof bundle;
  - participant backup.
- frostd integration:
  - authenticated session creation;
  - transcript upload;
  - transcript fetch;
  - immutable transcript digest;
  - no acknowledgement round required by Golden.
- Operational docs:
  - participant setup;
  - backup handling;
  - recovery;
  - security assumptions.

### Tests

- CLI golden-path tests using temporary directories.
- CLI rejects malformed and mismatched files.
- frostd protocol tests with multiple simulated clients.
- Backward/forward compatibility tests for versioned file formats.

### Acceptance Criteria

- A complete local multi-participant DKG can be driven through the CLI.
- frostd integration is optional and does not change transcript semantics.

## Milestone 9: Hardening and Audit Readiness

### Implementation

- Threat model:
  - malicious dealer;
  - malicious participant;
  - transcript equivocation;
  - replay across sessions;
  - backup compromise;
  - denial of service.
- Constant-time review:
  - scalar handling;
  - secret polynomial coefficients;
  - masks;
  - FROST signing shares;
  - randomizers.
- Dependency review:
  - crypto crate maintenance;
  - audit history;
  - feature flags;
  - `no_std` feasibility if needed.
- Fuzzing:
  - transcript parser;
  - proof parser;
  - backup parser;
  - CLI file loading.
- Documentation:
  - security status;
  - protocol assumptions;
  - unsupported use cases;
  - audit checklist.

### Tests

- Continuous fuzz targets for all parsers.
- Differential tests where equivalent representations must verify identically.
- Fault-injection tests for corrupted transcript bytes.
- `cargo audit` and license checks in CI.
- Miri or sanitizer runs where practical.

### Acceptance Criteria

- Audit package contains protocol spec, implementation notes, test vectors,
  benchmarks, and threat model.
- All unsafe code is either absent or isolated with justification.
- CI blocks release artifacts unless tests, clippy, fuzz smoke tests, and audit
  checks pass.

## Test Matrix

| Layer | Positive Tests | Negative Tests | Interop Tests | Benchmarks |
| --- | --- | --- | --- | --- |
| Core Shamir | reconstruct, aggregate | duplicates, missing shares | none | optional |
| Pallas bindings | group/scalar equations | invalid encodings | `pasta_curves` | MSM, eval |
| Vesta eVRF | matching masks | wrong keys/session | test vectors | mask derivation |
| Proofs | valid witness | tampered public inputs | proof vectors | prover/verifier |
| Golden DKG | all participants recover | invalid dealers | transcript files | end-to-end |
| FROST | threshold signs | fewer than threshold | Zcash `RedPallas` | signing |
| ZIP-312 | rerandomized verify | wrong randomizer | Zcash ZIP fixtures | signing |
| CLI/frostd | local session | malformed files | network harness | session scale |

## Continuous Integration Plan

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test --workspace --release`
- feature-gated slow tests for proof and FROST interop fixtures
- benchmark workflow on demand, not on every pull request
- fuzz smoke tests on pull requests and longer fuzzing on scheduled runs
- dependency and license review on pull requests

## Release Gates

### Developer Preview

- Core DKG simulation works over Pallas.
- eVRF mask derivation works with deterministic vectors.
- Proof system may still be experimental.
- Clearly marked unusable for real keys.

### Cryptography Preview

- Proof system complete.
- Golden end-to-end DKG works over Pallas/Vesta.
- Benchmarks published.
- External review requested.

### FROST Preview

- Golden shares sign through `RedPallas` FROST.
- Even-y and ZIP-312 behavior covered by vectors.
- Orchard spend authorization payload verifies locally.

### Audit Candidate

- Threat model complete.
- Fuzzing and CI complete.
- No placeholder cryptography in reachable APIs.
- Independent audit materials prepared.

### Production Consideration

- Independent audit complete.
- Audit findings resolved.
- Wallet integration reviewed separately.
- Operational backup and recovery docs complete.
