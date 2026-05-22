# `frostd` Session Prototype

Golden replaces FROST DKG, not FROST signing. The current prototype boundary is:

1. Run Golden DKG and recover each participant backup with `golden recover`.
2. Normalize the recovered Pallas scalar through `frost-redpallas`.
3. Convert the participant ID with `frost_identifier`.
4. Build `reddsa::frost::redpallas` key packages using the normalized signing
   share, verification share, and aggregate group public key.
5. Use the existing `frost-rerandomized` round-one, round-two, and aggregate
   functions for ZIP-312 signing sessions.

## Prototype Message Fields

```json
{
  "protocol": "golden-redpallas-frostd-v0",
  "participant_id": 1,
  "frost_identifier": 1,
  "share_hex": "<normalized FROST signing share>",
  "verification_share_hex": "<even-y verification share>",
  "group_public_key_hex": "<aggregate RedPallas key>",
  "session_format": "golden-dkg-session-v0"
}
```

This document is the integration contract for a future `frostd` transport shim.
The in-repo implementation currently stops at deterministic local key-package
construction and ZIP-312-compatible randomized signing parameters.
