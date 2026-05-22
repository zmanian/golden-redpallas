# Benchmarks

The Pallas proof backend benchmark harness lives in
`crates/golden-proofs/examples/pallas_bench.rs` and is gated behind the
`pallas-backend` feature:

```sh
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench
```

To run only selected sizes, pass a comma-separated subset:

```sh
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench -- --sizes 4
```

For an interactive smoke measurement of the current full proof path, run one
proof instead of the full proofed-DKG matrix:

```sh
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench -- --single-proof
```

To profile the verifier-side circuit dimensions without producing a proof, run:

```sh
cargo run --release -p golden-proofs --features pallas-backend --example pallas_bench -- --circuit-profile
```

The current harness emits machine-readable CSV for `n = 4, 8, 16, 32` with
these columns:

- `n`
- `threshold`
- `dealers`
- `proofs`
- `proof_bytes`
- `prove_micros`
- `prove_rss_bytes`
- `verify_one_micros`
- `verify_batch_micros`
- `verify_all_micros`

`prove_rss_bytes` reports process RSS after proof generation. On Linux this is
read from `/proc/self/status` `VmHWM`; on macOS this is sampled from
`ps -o rss=`. Other platforms emit `0` so the CSV schema remains stable without
using unsafe platform APIs.

`verify_batch_micros` measures direct `ProofSystem::verify_batch` time for the
first participant's dealer proofs. `verify_one_micros` measures full proofed
share recovery for the first participant, including transcript checks and share
recovery. `verify_all_micros` repeats recovery for every participant.

`pallas-proof-smoke-2026-05-22.csv` is a current one-proof smoke snapshot from
the `--single-proof` mode. It covers proof size, prover time, prover RSS, and
verifier time for one valid Pallas backend proof, and is intended for quick
regression checks while the full DKG matrix remains too expensive for an
interactive run. The latest row was collected after moving Pallas circuit setup
to a reusable circuit-family domain, adding in-process IPA generator-vector
caching, and switching circuit/IPA Fiat-Shamir setup prefixes to compact
domain-separated digests.

`pallas-proof-dkg-2026-05-22-n4.csv`,
`pallas-proof-dkg-2026-05-22-n8.csv`, and
`pallas-proof-dkg-2026-05-22-n16.csv` are current-harness DKG benchmark rows
collected after the same setup-cache and transcript-digest hardening. The
`n = 8` and `n = 16` rows were collected outside the sandbox so the macOS RSS
probe could populate `prove_rss_bytes`. The remaining `n = 32` row is still
pending because the current prover path is too expensive for a comfortable
interactive full-matrix run.

`pallas-proof-circuit-profile-2026-05-22.csv` is a current circuit-size profile
from `--circuit-profile`. It reports the linked mask and Vesta-DH circuit
dimensions without generating a proof. The current profile shows that the mask
hash circuit is the dominant prover/verifier cost, with 152,298 of the 160,959
total constraints.

`pallas-proof-skeleton-2026-05-21.csv` is an archived snapshot from an earlier
proof-backend harness. It covers `n = 8, 16, 32` and predates the
`proof_bytes`, `prove_rss_bytes`, `verify_batch_micros`, and `n = 4`
benchmark fields. Generate a fresh CSV from the current harness for audit
closeout or performance comparisons.
