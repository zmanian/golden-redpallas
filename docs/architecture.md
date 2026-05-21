# Architecture

Golden for RedPallas has four layers.

## 1. Core DKG

`golden-core` owns protocol-independent data flow:

- participant identifiers;
- Shamir polynomial evaluation over a scalar field;
- masked dealer contributions;
- public verification equations;
- share recovery and aggregation.

The core crate receives masks and proof verification results through traits. It
does not know how the eVRF, Bulletproofs, or Pallas curve are implemented.

## 2. Pallas/Vesta Cryptography

`golden-pallas` will bind the core protocol to the Pasta cycle:

- DKG group: Pallas;
- scalar field: Pallas scalar field;
- helper curve: Vesta, defined over the Pallas scalar field;
- hash-to-Vesta functions for Golden eVRF inputs;
- hash-to-field output for masks.

This crate must use constant-time implementations from audited dependencies where
available.

## 3. Proof System

The Golden proof system must show that the published mask commitment and masked
share are consistent with the dealer key, participant key, helper-curve DH output,
and public polynomial. The intended target is a Bulletproofs-style R1CS over the
Pallas scalar field.

The core crate models proof verification as an external result because the proof
system should be independently benchmarked and audited.

## 4. RedPallas FROST

`frost-redpallas` will adapt Golden output shares into FROST signing keys:

- implement or wrap a Pallas ciphersuite;
- enforce Zcash RedPallas even-y public keys;
- support ZIP-312 re-randomized signing;
- provide serialization suitable for wallet backups.

Golden replaces FROST DKG only. FROST signing remains a separate two-round
threshold signing protocol.
