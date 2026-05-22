# Wallet Backup JSON Format

The v0 wallet backup format is emitted by:

```sh
golden recover <session> <participant-id>
```

It captures only the local participant material needed by downstream wallet
experiments. It is not encrypted and must not be used with real funds.

## Shape

```json
{
  "version": 0,
  "scheme": "golden-redpallas-wallet-backup",
  "session_format": "golden-dkg-session-v0",
  "session_id": "golden-dkg-v0",
  "participant_id": 1,
  "dealer_count": 3,
  "share_hex": "<32-byte Pallas scalar hex>",
  "group_public_key_hex": "<32-byte RedPallas public key hex>"
}
```

## Invariants

- `participant_id` is the FROST-compatible participant identifier.
- `dealer_count` is the number of verified dealer transcripts aggregated into
  `share_hex`.
- `share_hex` is the little-endian canonical Pallas scalar encoding.
- `group_public_key_hex` is the compressed Pallas encoding of the aggregate
  Orchard SpendAuth public key.
- The file intentionally does not contain helper-curve secrets, dealer
  polynomials, or proof witnesses.
