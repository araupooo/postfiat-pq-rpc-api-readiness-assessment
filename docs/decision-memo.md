# Decision memo

Prioritised recommendations. Every recommendation below is a MODELLED
judgement based on source-derived facts in this pack; none is a
measured outcome. Facts are cited; judgements are labelled.

## 1. Do not ship a PQ signature change before the KeyType choke point is solved (HIGH, modelled)

[FACT] `KeyType` has exactly two enumerators, secp256k1 = 0 and
ed25519 = 1 (`include/xrpl/protocol/KeyType.h:29-30`), and
`keypairForSignature` rejects anything else
(`src/xrpld/rpc/detail/RPCHelpers.cpp:927-930`). [FACT] All 6 signing
methods and both key-generation methods funnel through
`generateSecretKey` / `derivePublicKey` / `generateKeyPair` /
`sign` / `verify`. [ANALYSIS] Any PQ signature work that does not
start with a new `KeyType` enumerator plus new branches in those
functions — and new serialised key prefixes — cannot be accepted by
any method. [RECOMMENDATION] Treat the KeyType extension as the
first migration work item; do not start with per-method changes.

## 2. Migrate the 4 signature-creation methods to hybrid dual signatures (HIGH, modelled)

[FACT] `sign`, `sign_for`, the signing path of `submit`, and
`channel_authorize` create signatures with server-held secret keys
(`src/xrpld/rpc/detail/TransactionSign.cpp:676-682`,
`src/xrpld/rpc/handlers/PayChanClaim.cpp:92`). [FACT] The signing
path is gated on `canSign()` (`src/xrpld/core/Config.h:365-367`,
default off) and carries a deprecation notice, but is live in this
commit. [ANALYSIS] These four are the only methods where a quantum
break yields forged signatures from a live service, and the
deprecation notice does not remove the exposure. [RECOMMENDATION]
Accept ML-DSA (FIPS 204) signatures alongside Ed25519/secp256k1
during transition; remove classical-only acceptance only after a
coordinated cutover. Price in the size impact first: ML-DSA-44
signatures are 2,420 bytes and public keys 1,312 bytes (FIPS 204
Table 2).

## 3. Treat validation_create output as the most sensitive response in the surface (HIGH, modelled)

[FACT] `validation_create` returns a secp256k1 private key, seed, and
1751 key in the response (`src/xrpld/rpc/handlers/
ValidationCreate.cpp:54-64`) and is ADMIN-only. [RECOMMENDATION] Any
harness or operator tooling that calls it must never log or persist
the response; a PQ-era replacement must not return PQ private-key
material over RPC in the same way.

## 4. Configure hybrid ML-KEM TLS at the deployment layer (MEDIUM, modelled)

[FACT] The default cipher list is TLSv1.2-only
(`src/libxrpl/basics/make_SSLContext.cpp:104`) and key exchange is
delegated to OpenSSL. [FACT] No PQ or hybrid key exchange is
configured in-tree. [ANALYSIS] Recorded TLS sessions are exposed to
harvest-now-decrypt-later; this is the only retrospective-decryption
exposure in the pack. [RECOMMENDATION] Enable a hybrid ML-KEM TLS
key exchange via the OpenSSL/deployment configuration when the
linked OpenSSL supports it; no RPC code change is required for this
step.

## 5. Keep SHA-512-Half; do not spend migration effort on hashing (LOW, modelled)

[FACT] SHA-512-Half is the only hash in the signing path and the
ledger/tx identity hash. [ANALYSIS] Grover's algorithm only halves
its effective strength (256-bit output, ~128-bit post-quantum), and
no hash replacement exists in the FIPS PQ standards for this role.
[RECOMMENDATION] No-change for `server_definitions` and the 8
hash-data methods. Record the absence of hash agility as a gap: a
future hash replacement would be a coordinated change.

## 6. Do not claim an ML-KEM migration surface inside RPC (LOW, modelled)

[FACT] There is no KEM-shaped operation in the 74-method inventory
and no ECDH/KEM code path reachable from any RPC method.
[RECOMMENDATION] State the ML-KEM relevance as transport/overlay
key establishment only; do not assign ML-KEM work to any RPC method.

## 7. Keep the dead declarations dead (LOW, modelled)

[FACT] `doPause`/`doResume` are declared but unregistered and
undefined. [RECOMMENDATION] Do not re-register them without a
review; they are not methods in this commit and must not be counted
in any future inventory without a table entry.
