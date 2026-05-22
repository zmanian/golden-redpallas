# Constant-Time Review

Review date: 2026-05-21.

## Result

The workspace has `unsafe_code = "forbid"` in `Cargo.toml`. A direct source scan
found no Rust `unsafe` blocks in `crates/`. The implementation relies on
`pasta_curves`, `reddsa`, `frost-rerandomized`, `subtle`, and `zeroize` for
secret scalar arithmetic, RedPallas signing semantics, and key material hygiene.

## Secret-Dependent Areas

- `golden-core` test field arithmetic is not constant-time and is only used in
  tests.
- `PallasScalar::invert` and scalar equality route through `pasta_curves`.
- Transcript parsing and CLI JSON formatting operate on public session data.
- Even-y normalization branches on public verification-share bytes, not secret
  scalar bytes.
- Golden proof backend proving code is executable and tested, but not audited
  for constant-time behavior.

## Follow-Up Before Production

- Harden the proof backend candidate into an audited constant-time backend.
- Run a tool-assisted side-channel review on final secret-share handling.
- Add encrypted backup storage before using wallet backup JSON outside tests.
- Confirm upstream `reddsa` and `frost-rerandomized` versions remain within
  their audited support windows.
