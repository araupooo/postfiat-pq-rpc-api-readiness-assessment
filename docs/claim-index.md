# Claim-to-evidence index

Every claim in this pack, its status, its primary source, and the
evidence file that supports it. Status meanings: **VERIFIED** —
checked against the pinned source by the classifier and re-verified
by the probe (source-derived); **SPECIFIED** — defined by the pinned
code but not exercised by the classifier in this pack; **MODELLED** —
a judgement (urgency, priority, recommendation), labelled as such;
**UNTESTABLE** — the claim cannot be tested with the tooling in this
pack (no live node was run). No claim in this pack is a measured
runtime result.

| ID | Status | Claim | Primary source | Evidence |
|----|--------|-------|----------------|----------|
| C-01 | VERIFIED | 74 JSON-RPC methods are dispatchable: 72 handlerArray entries plus 2 new-style handlers (ledger, version). | `src/xrpld/rpc/detail/Handler.cpp:83-199,246-249` | `outputs/derived/method-inventory.json` lines 1-3 (`method_count` 74), `outputs/derived/readiness-matrix.json` line 134, probe A-01 |
| C-02 | VERIFIED | Exposure breakdown: signing 6, key-exchange 2, hashing 1, none 65. | `src/rpc_inventory.py` rules + probe B-01 | `outputs/derived/readiness-matrix.json` lines 80-85, probe B-01 |
| C-03 | MODELLED | Urgency breakdown: HIGH 6, MEDIUM 2, LOW 66 (modelled judgements). | `src/rpc_inventory.py` rules | `outputs/derived/readiness-matrix.json` lines 205-209, probe B-01 |
| C-04 | MODELLED | Recommendations: hybrid 8, no-change 66, pq-only 0 (modelled judgements). | `src/rpc_inventory.py` rules | `outputs/derived/readiness-matrix.json` lines 164-168, probe B-01 |
| C-05 | VERIFIED | No ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, or SPHINCS+ occurs anywhere in src/ + include/ (0 file hits, 9 terms). | classifier PQ grep | `outputs/derived/readiness-matrix.json` lines 137-154, probe D-01 |
| C-06 | VERIFIED | Only two signature schemes exist in the tree: secp256k1 and Ed25519; KeyType has exactly two enumerators. | `include/xrpl/protocol/KeyType.h:29-30` | `fixtures/source-excerpts/E23.txt`, `configs/readiness-table.json` (ed25519, secp256k1 families) |
| C-07 | VERIFIED | SHA-512-Half is the ledger/transaction hash: sha512Half defined in digest.h, entry indexes are sha512Half values. | `include/xrpl/protocol/digest.h:224`, `src/libxrpl/protocol/Indexes.cpp:113` | `fixtures/source-excerpts/E22.txt`, `E32.txt` |
| C-08 | VERIFIED | sign and sign_for sign with a supplied secret key via transactionSign (ripple::sign / stTx->sign). | `src/xrpld/rpc/detail/TransactionSign.cpp:676-682` | `fixtures/source-excerpts/E10.txt`, `outputs/derived/method-inventory.json` lines 1829-1865 (sign), 1866-1902 (sign_for) |
| C-09 | VERIFIED | submit has two paths: tx_blob path verifies signatures (STTx::checkSign); signing path is deprecated and gated on canSign(). | `src/libxrpl/protocol/STTx.cpp:259`, `src/xrpld/rpc/handlers/Submit.cpp:67-71` | `fixtures/source-excerpts/E14.txt`, `E35.txt`, `outputs/derived/method-inventory.json` lines 1971-2007 |
| C-10 | VERIFIED | validation_create generates a secp256k1 validator key pair and returns the private key, seed, and public key. | `src/xrpld/rpc/handlers/ValidationCreate.cpp:54-64` | `fixtures/source-excerpts/E17.txt`, `outputs/derived/method-inventory.json` lines 2287-2322 |
| C-11 | VERIFIED | wallet_propose generates an account key pair from seed material (default secp256k1) and returns seed material. | `src/xrpld/rpc/handlers/WalletPropose.cpp:122-136` | `fixtures/source-excerpts/E18.txt`, `outputs/derived/method-inventory.json` lines 2529-2565 |
| C-12 | VERIFIED | The peer-handshake session signature is secp256k1-only: signDigest over a shared value, verified with verifyDigest. | `src/xrpld/overlay/detail/Handshake.cpp:203,318` | `fixtures/source-excerpts/E20.txt`, `E21.txt` |
| C-13 | VERIFIED | The default TLS cipher list is TLSv1.2-only and key exchange is delegated to OpenSSL. | `src/libxrpl/basics/make_SSLContext.cpp:104,365` | `fixtures/source-excerpts/E26.txt`, `E27.txt` |
| C-14 | VERIFIED | manifest is a read-only lookup of a stored validator manifest by node public key; it signs or verifies nothing in the handler. | `src/xrpld/rpc/handlers/DoManifest.cpp:42,60-61` | `fixtures/source-excerpts/E19.txt`, `outputs/derived/method-inventory.json` lines 1249-1282 |
| C-15 | VERIFIED | channel_authorize signs a payment-channel claim; channel_verify verifies one against a supplied public key. | `src/xrpld/rpc/handlers/PayChanClaim.cpp:92,160` | `fixtures/source-excerpts/E15.txt`, `E16.txt`, `outputs/derived/method-inventory.json` lines 449-485, 486-522 |
| C-16 | VERIFIED | simulate rejects signed input (rpcTX_SIGNED) and dry-runs via TxQ::apply. | `src/xrpld/rpc/handlers/Simulate.cpp:124-139,229` | `fixtures/source-excerpts/E41.txt`, `E36.txt`, `outputs/derived/method-inventory.json` lines 1903-1936 |
| C-17 | VERIFIED | The gRPC surface is 4 read-only ledger methods, registered in GRPCServer.cpp. | `src/xrpld/rpc/GRPCHandlers.h:40-55`, `src/xrpld/app/main/GRPCServer.cpp:488-498` | `fixtures/source-excerpts/E31.txt`, `E40.txt`, `outputs/derived/readiness-matrix.json` lines 87-108 |
| C-18 | VERIFIED | doPause and doResume are declared but unregistered and undefined. | `src/xrpld/rpc/handlers/Handlers.h:110,120` | `fixtures/source-excerpts/E34.txt`, `outputs/derived/readiness-matrix.json` lines 193-204 |
| C-19 | SPECIFIED | No in-tree code sets a TLS minimum version or selects a PQ/hybrid group; negotiated TLS parameters come from OpenSSL defaults plus the cipher list. | `src/libxrpl/basics/make_SSLContext.cpp` (no set_min_proto / TLS1_3_VERSION gate found) | `fixtures/source-excerpts/E26.txt`, `E27.txt` — the absence is stated, not exercised by any probe |
| C-20 | MODELLED | HIGH urgency for 6 methods: the 4 signature-creation methods plus the 2 key-generation methods (secret-key handling). | `src/rpc_inventory.py` rules | `outputs/derived/readiness-matrix.json` lines 122-129 |
| C-21 | MODELLED | Hybrid recommendation for 8 methods (6 signing + 2 key-exchange); pq-only for none. | `src/rpc_inventory.py` rules | `outputs/derived/readiness-matrix.json` lines 164-168 |
| C-22 | MODELLED | Hashing recommendation is no-change on Grover grounds: a 256-bit sha512Half output retains about 128 bits of post-quantum strength. | `configs/readiness-table.json` (sha512-half family) | `outputs/derived/readiness-matrix.json` lines 80-85 (hashing 1), `docs/decision-memo.md` |
| C-23 | UNTESTABLE | Live TLS handshake negotiation (versions, groups, certificates) on a running node. | — | No live node was run in this pack; the boundary is stated in `README.md` and `docs/methodology.md` |
| C-24 | UNTESTABLE | FIPS test-vector execution for ML-KEM / ML-DSA / SLH-DSA. | — | No implementation exists in the tree to test against (`outputs/derived/readiness-matrix.json` lines 137-154, 0 hits) |

## Counts

- VERIFIED: 16
- SPECIFIED: 1
- MODELLED: 5
- UNTESTABLE: 2
- Total: 24
