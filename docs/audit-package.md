# Audit Package

Golden RedPallas is ready for independent cryptographic review, not production
deployment. This package indexes the materials an external reviewer should use
and the current evidence that the in-repository audit-readiness gates have been
run.

## Status

- Roadmap state: the Pallas proof backend now lowers Vesta scalar
  multiplication and Blake2b mask digest generation into the circuit verifier;
  independent cryptographic audit remains open.
- Production state: not production ready; the Pallas proof backend is an
  unaudited zero-knowledge candidate, not a production-reviewed proof system.
- Audit state: no independent cryptographic audit report has been received.

## Protocol And Design Materials

- `docs/architecture.md`: crate boundaries and high-level protocol flow.
- `docs/implementation-testing-plan.md`: staged implementation plan, test matrix,
  CI plan, and release gates.
- `docs/adr/0001-pallas-bulletproofs-backend.md`: proof-backend decision record.
- `docs/bulletproofs-backend.md`: current proof-backend contract and limitations.
- `docs/session-transcript-format.md`: versioned local session transcript format.
- `docs/wallet-backup-json.md`: recovered wallet backup JSON shape.
- `docs/frostd-session-prototype.md`: local `frostd` key-package handoff flow.

## Security Review Materials

- `docs/threat-model.md`: assets, adversaries, mitigations, and open risks.
- `docs/constant-time-review.md`: unsafe-code and secret-handling review.
- `docs/dependency-review.md`: dependency posture and RustSec advisory result.
- `docs/fuzzing.md`: transcript parser and proof-public-input decoder
  fuzz-smoke harnesses.
- `docs/independent-audit-handoff.md`: reviewer scope, required outcomes, and
  closeout criteria.

## Evidence Artifacts

- `test-vectors/golden-pallas/dkg-v0.txt`: deterministic Golden DKG fixture.
- `test-vectors/golden-pallas/evrf-v0.txt`: deterministic Vesta eVRF fixture.
- `test-vectors/frost-redpallas/redpallas-spendauth-v0.txt`: RedPallas SpendAuth
  verification vector.
- `docs/benchmarks/`: proof-backend benchmark harness notes and archived
  benchmark output. The current `pallas-proof-smoke-2026-05-22.csv` covers one
  full Pallas proof with proof size, prover RSS, prover timing, and verifier
  timing. The current `pallas-proof-circuit-profile-2026-05-22.csv` profiles
  the linked mask and Vesta-DH circuit dimensions without creating a proof; it
  identifies the mask hash circuit as the dominant cost with 152,298 of 160,959
  total constraints. The current `pallas-proof-dkg-2026-05-22-n4.csv`,
  `pallas-proof-dkg-2026-05-22-n8.csv`, and
  `pallas-proof-dkg-2026-05-22-n16.csv` files cover the `n = 4`, `n = 8`, and
  `n = 16` DKG rows with the current harness fields. The archived
  `pallas-proof-skeleton-2026-05-21.csv` covers `n = 8`, `n = 16`, and `n = 32`
  but predates the current harness fields; regenerate the remaining `n = 32`
  current-harness row before audit closeout.

## Current Verification Commands

Run these commands from a clean checkout before handing the package to a
reviewer:

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
git diff --check
```

The CI workflow in `.github/workflows/ci.yml` mirrors these gates for pull
requests and pushes to `main`, and includes a release-gate job that depends on
the test and audit jobs.

## Reviewer Closeout Inputs

The independent audit can be closed only when the reviewer returns:

- a written report naming the exact commit reviewed;
- severity-rated findings for every issue or an explicit no-findings statement;
- confirmation that roadmap cryptographic claims were reviewed against code and
  tests;
- final sign-off after high and critical findings are resolved;
- a list of accepted residual risks for lower-severity findings.
