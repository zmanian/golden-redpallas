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
- `golden-pallas`: Pallas/Vesta adapter boundary and DKG simulation.
- `golden-proofs`: proof verification hooks and the feature-gated Pallas proof backend.
- `frost-redpallas`: RedPallas/FROST adapter boundary with ZIP-312 randomization.
- `golden-cli`: `golden` binary for local DKG session operations.

## Build

```sh
cargo test --workspace
```

## CLI

The `golden` binary drives local DKG sessions against fixtures:

```sh
cargo run -p golden-cli -- status                       # report build/security status
cargo run -p golden-cli -- create <fixture> <session>   # create a session from a fixture
cargo run -p golden-cli -- post <session>               # post participant contributions
cargo run -p golden-cli -- verify <session>             # verify the aggregate transcript
cargo run -p golden-cli -- recover <session> <id>       # recover a participant's wallet backup
```

## Documentation

Design notes, threat model, and audit material live under [`docs/`](docs/);
open work is tracked in [`docs/roadmap.md`](docs/roadmap.md).

## Security Status

This repository is not production ready. It contains an unaudited candidate
Pallas proof backend (an IPA-based prover/verifier with circuit traces for the
mask hash, mask opening, and Vesta DH relations) that still self-identifies as
a skeleton and has not completed an independent cryptographic audit. Do not
use it with real keys or funds.
