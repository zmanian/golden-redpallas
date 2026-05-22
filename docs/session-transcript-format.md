# Golden DKG Session Transcript Format

Version 0 is a line-oriented UTF-8 format. It is intentionally small enough to
review by eye and is the canonical interchange format accepted by `golden-cli`
for local DKG experiments.

## File Shape

```text
version=0
threshold=<usize>
session=<opaque session id>
participants=<participant-id>:<helper-secret>;...
dealers=<dealer-id>/<helper-secret>:<coefficient>,...
```

Blank lines and lines beginning with `#` are ignored.

## Fields

- `version`: must be `0`.
- `threshold`: minimum number of valid dealer transcripts required for recovery.
- `session`: opaque bytes encoded as UTF-8 text and bound into all eVRF mask transcripts.
- `participants`: semicolon-separated participant records. Participant IDs must be
  non-zero `u16` values so they map directly into FROST identifiers.
- `dealers`: semicolon-separated dealer records. Dealer coefficients are listed in
  ascending polynomial order, with the constant term first.

## Validation

A session transcript is accepted only if:

- the protocol threshold and participants pass `golden-core` validation;
- every dealer transcript verifies against its public polynomial commitment;
- enough dealer transcripts are present to meet the threshold;
- the aggregate public key equals the generator multiplied by the aggregate
  dealer secret in the deterministic simulation.

## CLI Mapping

- `golden create <fixture> <session-out>` validates and writes a v0 session file.
- `golden post <session>` prints the public posting summary.
- `golden verify <session>` verifies all deterministic transcript invariants.
- `golden recover <session> <participant-id>` emits the wallet backup JSON for
  one recovered aggregate share.
