# Golden RedPallas

Research implementation scaffold for a one-round Golden DKG targeting Zcash Orchard
RedPallas keys and re-randomized FROST signing.

This repository intentionally starts with protocol boundaries and testable core data
flow instead of unaudited cryptographic shortcuts. The current code implements:

- finite-field abstractions used by the DKG logic;
- Shamir polynomial evaluation and Lagrange interpolation;
- dealer contribution creation and participant share recovery;
- Pallas/Vesta mask derivation and deterministic DKG fixtures;
- proof verification hooks, fixture proofs, and a feature-gated Pallas proof
  skeleton;
- RedPallas FROST share/key-package helpers with even-y normalization and
  ZIP-312 randomization support;
- CLI commands for local session creation, posting, verification, and share
  recovery.

Open work is tracked in [`docs/roadmap.md`](docs/roadmap.md).

## Workspace

- `golden-core`: Golden protocol data flow, Shamir sharing, transcript model.
- `golden-pallas`: Pallas/Vesta adapter boundary.
- `frost-redpallas`: RedPallas/FROST adapter boundary.
- `golden-cli`: CLI entry point for future DKG session operations.

## Build

```sh
cargo test --workspace
```

## Security Status

This repository is not production ready. It contains an executable Pallas proof
skeleton, not a production zero-knowledge proof backend, and the implementation
has not completed an independent cryptographic audit. Do not use it with real
keys or funds.
