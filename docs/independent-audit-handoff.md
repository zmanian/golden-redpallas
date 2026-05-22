# Independent Cryptographic Audit Handoff

An independent cryptographic audit has not been performed in this repository. The
roadmap item remains open until an external cryptographic reviewer completes the
review, publishes findings, and the repository resolves or explicitly accepts
those findings.

This handoff lists the materials that should be given to the reviewer and the
minimum questions the review must answer.

## Scope To Audit

- Golden DKG share masking and recovery in `golden-core` and `golden-pallas`.
- eVRF mask derivation transcript binding.
- Proof public inputs, witness handling, and Pallas backend candidate
  limitations.
- RedPallas FROST share mapping, even-y normalization, and ZIP-312 randomization.
- Wallet backup JSON contents and operational handling.

## Known Non-Production Limitations

- `golden-proofs` contains an unaudited Pallas zero-knowledge backend
  candidate, not a production-reviewed proof backend; the active proof bytes no
  longer serialize the shared point or mask, and the verifier checks
  digest-bit reduction to the mask plus Blake2b digest generation, shared-point
  encoding, curve constraints, and the Vesta scalar-multiplication relation.
- CLI session and wallet backup files are plaintext local artifacts.
- `frostd` support is a key-package prototype, not an authenticated network
  session implementation.
- Wallet transaction construction and broadcast are out of scope for this repo.

## Required Reviewer Outcomes

- Confirm the Golden protocol statement and proof relation.
- Confirm no participant can recover another participant's share from public
  transcripts.
- Confirm transcript replay protection is sufficient.
- Confirm RedPallas normalization matches Orchard SpendAuth requirements.
- Confirm ZIP-312 signing compatibility with Zcash verification semantics.
- Identify whether the current proof backend candidate can be hardened into the
  production proof backend.
- Review all secret-share, mask, randomizer, and backup handling for
  side-channel and operational leakage risks.
- Review dependency choices and version posture for the curve, FROST, and RedDSA
  crates used by the implementation.

## Evidence Bundle

- `docs/audit-package.md`
- `README.md`
- `docs/roadmap.md`
- `docs/implementation-testing-plan.md`
- `docs/threat-model.md`
- `docs/constant-time-review.md`
- `docs/dependency-review.md`
- `docs/fuzzing.md`
- `docs/bulletproofs-backend.md`
- `docs/session-transcript-format.md`
- `docs/wallet-backup-json.md`
- `docs/frostd-session-prototype.md`
- `test-vectors/`
- `docs/benchmarks/`

## Reproduction Commands

The reviewer should run these commands from a clean checkout:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo test -p golden-proofs --features pallas-backend
cargo test --release -p golden-proofs --features pallas-backend
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench -- --circuit-profile
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo run -p golden-cli -- verify test-vectors/golden-pallas/dkg-v0.txt
cargo run -p golden-pallas --example fuzz_session_transcript -- test-vectors/golden-pallas/dkg-v0.txt
cargo run -p golden-proofs --example fuzz_proof_public_inputs -- test-vectors/golden-pallas/dkg-v0.txt
```

## Completion Criteria

The `Independent cryptographic audit` roadmap item can be checked only after:

- an external reviewer has delivered a written report;
- every high or critical finding has a code or documentation resolution;
- every accepted lower-severity finding is tracked with rationale;
- the final reviewer sign-off references the exact repository revision reviewed;
- fresh test, clippy, audit, CLI, and fuzz-smoke outputs are attached to the
  audit closeout.
