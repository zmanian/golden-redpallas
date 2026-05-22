# Threat Model

Golden RedPallas targets a one-round DKG that outputs Zcash Orchard
SpendAuth-compatible RedPallas shares for later FROST signing.

## Assets

- Participant Golden/FROST signing shares.
- Helper-curve secrets used to derive eVRF masks.
- Dealer polynomial coefficients.
- Session transcript integrity and ordering.
- Aggregate RedPallas public key and recovered wallet backup JSON.

## Trusted Computing Base

- `golden-core` Shamir, transcript, verification, and aggregation logic.
- `golden-pallas` Pallas/Vesta adapters and deterministic mask derivation.
- `golden-proofs` proof-facing APIs and the feature-gated Pallas skeleton.
- `frost-redpallas` mapping into `reddsa` and `frost-rerandomized`.
- Upstream `pasta_curves`, `reddsa`, `frost-rerandomized`, `blake2b_simd`,
  `subtle`, and `zeroize` implementations.

## Adversaries

- Malicious dealers publishing malformed masked shares or public commitments.
- Malicious participants attempting to recover other participants' shares.
- Coordinators replaying transcripts into a different session.
- Storage attackers reading unencrypted local backups.
- Network attackers modifying transcript or `frostd` transport messages.

## Current Mitigations

- Participant IDs are non-zero `u16` values compatible with FROST identifiers.
- Transcript verification rejects missing participants, duplicate shares,
  unverified proofs, and failed commitment equations.
- Mask derivation binds the session ID, dealer ID, participant ID, helper keys,
  and public polynomial.
- RedPallas FROST adapter enforces even-y normalization before key-package use.
- ZIP-312 randomization uses `frost-rerandomized` parameters over the Orchard
  SpendAuth generator.
- Wallet backup JSON includes only recovered local share material and the
  aggregate public key.

## Out Of Scope

- Production network transport, authentication, and peer discovery.
- Encrypted backup storage.
- Wallet spend-policy UX.
- Production deployment of the unaudited zero-knowledge proof backend.
- Independent cryptographic audit.

## Open Risks

- The Pallas proof backend remains unaudited and is not production-approved.
- CLI session files and backup JSON are plaintext.
- The `frostd` integration is a local key-package prototype, not a transport
  implementation.
- Constant-time behavior depends heavily on upstream curve and RedDSA crates.
