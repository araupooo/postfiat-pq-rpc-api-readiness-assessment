# Migration matrix

Per-method recommendation and dependency order. Recommendations are
MODELLED judgements, not measured outcomes. "Hybrid" means: accept
both the classical scheme and the PQ scheme during transition
(dual signatures / hybrid KEM), with classical-only acceptance
removed only after a coordinated cutover. "No-change" means: no
migration action is required on quantum grounds for this method.

## By exposure

| Exposure | Methods | Recommendation | Dependency order |
|----------|---------|----------------|------------------|
| signing (create) | sign, sign_for, submit, channel_authorize | hybrid (ML-DSA dual signatures, FIPS 204) | 3 — after key types (1) and transport (2) |
| signing (verify only) | channel_verify, submit_multisigned | hybrid (verify ML-DSA alongside Ed25519/secp256k1) | 3 — with the create methods; verification must accept both during transition |
| key-exchange (key generation) | validation_create, wallet_propose | hybrid (generate/accept PQ key types alongside KeyType secp256k1/ed25519) | 1 — first: KeyType enum + key generation are the choke point for everything else |
| hashing | server_definitions | no-change (SHA-512-Half retained) | — (monitor only) |
| none (hash data) | ledger, ledger_closed, ledger_data, ledger_entry, ledger_header, tx, transaction_entry, account_tx | no-change | — (monitor only) |
| none (other) | 57 methods incl. connect, manifest, simulate, random | no-change | — (transport only; see order 2) |

## Dependency order (modelled)

1. **Key types and key generation.** `KeyType` has exactly two
   enumerators (`include/xrpl/protocol/KeyType.h:29-30`). A PQ key
   type is a new enumerator plus new branches in `generateSecretKey`,
   `derivePublicKey`, `generateKeyPair`, `sign`, `verify`, and the
   `keyTypeFromString` parser — and new serialised key prefixes
   (today 0xED for Ed25519, compressed secp256k1). Until this exists,
   no method can emit or accept a PQ key. Methods: `validation_create`,
   `wallet_propose`.
2. **Transport.** TLS key exchange is delegated to OpenSSL; a hybrid
   ML-KEM TLS configuration (FIPS 203) is an OpenSSL/deployment
   change, not an RPC code change. It protects recorded sessions
   (harvest-now-decrypt-later) and is independent of the signing
   migration. Peer-handshake session signatures (secp256k1-only,
   `Handshake.cpp:203,318`) ride on the same layer.
3. **Signatures.** Dual-signature acceptance in `sign`, `sign_for`,
   `submit`, `submit_multisigned`, `channel_authorize`,
   `channel_verify`. Size impact (FIPS 204 Table 2): ML-DSA-44 public
   key 1,312 bytes, signature 2,420 bytes — roughly 40x a 33-byte
   compressed secp256k1 key and ~38x a 64-byte Ed25519 signature.
   `TxnSignature` / `SigningPubKey` are variable-length fields, but
   ledger formats and `checkSign` canonicality rules assume ~64–72
   byte signatures and 33-byte keys; the assessment must price in
   serialised-transaction bloat before any cutover.
4. **Hashing (monitor only).** SHA-512-Half stays. No action unless a
   hash weakness is found; note there is no hash agility — a future
   hash replacement is a coordinated change, not a drop-in.

## Per-method table (HIGH and MEDIUM urgency only; all 66 LOW methods are no-change)

| Method | Exposure | Urgency | Recommendation | Blocks on |
|--------|----------|---------|----------------|-----------|
| sign | signing (create+verify) | HIGH | hybrid | KeyType + dual-signature acceptance |
| sign_for | signing (create) | HIGH | hybrid | KeyType + dual-signature acceptance |
| submit | signing (create+verify) | HIGH | hybrid | KeyType + dual-signature acceptance |
| channel_authorize | signing (create) | HIGH | hybrid | KeyType + dual-signature acceptance |
| validation_create | key-exchange | HIGH | hybrid | KeyType enumerator + generateSecretKey branch |
| wallet_propose | key-exchange | HIGH | hybrid | KeyType enumerator + generateKeyPair branch |
| channel_verify | signing (verify) | MEDIUM | hybrid | dual-signature verification |
| submit_multisigned | signing (verify) | MEDIUM | hybrid | dual-signature verification |

## Notes

- `submit_multisigned` and `channel_verify` are MEDIUM, not HIGH:
  they verify supplied signatures but accept no secret key, so a
  quantum break forges signatures but does not expose key material
  through them.
- `simulate` is LOW / no-change: it rejects signed input and dry-runs
  via `TxQ::apply`; its PQ exposure is the same signature
  verification as `submit`, already covered at order 3.
- SLH-DSA (FIPS 205) is a backup option only: signatures 7,856–49,856
  bytes make it impractical as a transaction-signature replacement
  without a field-size redesign; its small public keys (32–64 bytes)
  are the closest PQ match to today's 33-byte keys.
- ML-KEM (FIPS 203) has no RPC method target: there is no KEM-shaped
  operation in the method inventory. Its relevance is transport/
  overlay key establishment only.
