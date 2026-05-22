# Dependency Review

Review date: 2026-05-22.

The review command was:

```sh
cargo tree --workspace -e normal,build
cargo audit
```

## Direct Dependencies

- `golden-pallas`: `blake2b_simd 1.0.4`, `pasta_curves 0.5.1`.
- `golden-proofs`: `ark-ec 0.5`, `ark-ff 0.5`, `ark-r1cs-std 0.5`,
  `ark-relations 0.5`, `ark-vesta 0.5`, `blake2b_simd 1.0.4`, `golden-core`,
  `golden-pallas`.
- `frost-redpallas`: `frost-rerandomized 0.6.0`, `reddsa 0.5.1`,
  `golden-core`, `golden-pallas`.
- `golden-cli`: `golden-core`, `golden-pallas`, `frost-redpallas`.

## Security-Relevant Transitive Dependencies

- `subtle 2.6.1` for constant-time primitives.
- `zeroize 1.8.2` via FROST/RedDSA key types.
- `ff 0.13.1`, `group 0.13.0`, and `pasta_curves 0.5.1` for curve and scalar
  arithmetic.
- `frost-core 0.6.0` and `frost-rerandomized 0.6.0` for threshold signing.
- `reddsa 0.5.1` for Zcash RedDSA/RedPallas compatibility.
- `arkworks 0.5` crates for the Pallas proof backend's Vesta R1CS synthesis.

## Review Notes

- No networking, database, or filesystem-watching dependencies are present.
- Proc-macro dependencies are limited to derive helpers pulled by upstream
  FROST/serde stacks.
- `rand_core` is used only in the deterministic RedPallas vector generator
  example.
- The `golden-proofs` arkworks dependencies disable default features to avoid
  pulling `ark-relations`' optional `tracing-subscriber 0.2` dependency, which
  is covered by `RUSTSEC-2025-0055`.
- `cargo audit` loaded 1098 RustSec security advisories and reported no
  vulnerabilities for the current `Cargo.lock` dependency set. It reports one
  allowed warning for `paste 1.0.15` (`RUSTSEC-2024-0436`) through arkworks.
- CI should continue running `cargo audit` or an equivalent advisory check so
  future dependency changes keep this review current.
