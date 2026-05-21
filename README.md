# Golden RedPallas

Research implementation scaffold for a one-round Golden DKG targeting Zcash Orchard
RedPallas keys and re-randomized FROST signing.

This repository intentionally starts with protocol boundaries and testable core data
flow instead of unaudited cryptographic shortcuts. The current code implements:

- finite-field abstractions used by the DKG logic;
- Shamir polynomial evaluation and Lagrange interpolation;
- dealer contribution creation and participant share recovery;
- transcript verification hooks for mask proofs;
- crate boundaries for Pallas/Vesta, Bulletproofs, FROST, and CLI integration.

The Pallas/Vesta eVRF, Bulletproofs circuit, and RedPallas FROST ciphersuite are
tracked as explicit work items in [`docs/roadmap.md`](docs/roadmap.md).

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

This repository is not production ready. The cryptographic proof system and
RedPallas/FROST integration are not implemented yet and must be audited before use
with real keys or funds.
