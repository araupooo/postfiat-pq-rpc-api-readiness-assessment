# Risk register

| ID | Severity | Risk | Primary source | Evidence |
|----|----------|------|----------------|----------|
| R-01 | HIGH | Shor's algorithm breaks Ed25519/secp256k1 signatures: any signature recorded on the ledger becomes forgeable after the fact, and long-lived validator keys are compromisable. | `include/xrpl/protocol/KeyType.h:29-30` | `configs/readiness-table.json` (ed25519, secp256k1 families) |
| R-02 | HIGH | validation_create and wallet_propose return key material over RPC; a compromised admin channel yields long-lived keys. | `src/xrpld/rpc/handlers/ValidationCreate.cpp:54-64` | `fixtures/source-excerpts/E17.txt`, `E18.txt` |
| R-03 | HIGH | Harvest-now-decrypt-later on TLS sessions: classical key exchange under the TLSv1.2 default cipher list can be decrypted retrospectively. | `src/libxrpl/basics/make_SSLContext.cpp:104` | `fixtures/source-excerpts/E26.txt` |
| R-04 | MEDIUM | Validator manifest keys are long-lived Ed25519/secp256k1; rotation requires new manifests and re-publication. | `src/xrpld/rpc/handlers/DoManifest.cpp:30-65` | `fixtures/source-excerpts/E19.txt` |
| R-05 | MEDIUM | Hybrid migration doubles signature sizes (ML-DSA-44: 2,420-byte signatures, 1,312-byte public keys); serialised-transaction size assumptions in ledger formats are untested at those sizes. | FIPS 204 Table 2 | `docs/citations.md` |
| R-06 | MEDIUM | submit accepts classically-signed transactions indefinitely; no migration deadline or classical-rejection switch exists in code. | `src/xrpld/rpc/handlers/Submit.cpp:45-112` | `fixtures/source-excerpts/E35.txt` |
| R-07 | MEDIUM | No hash agility: sha512Half is the only hash; a hash break needs a coordinated change across ledger, transaction, and index code. | `include/xrpl/protocol/digest.h:224` | `fixtures/source-excerpts/E22.txt` |
| R-08 | MEDIUM | PQ hybrid TLS depends on the linked OpenSSL build, not in-tree code; an older OpenSSL silently leaves the classical default in place. | `src/libxrpl/basics/make_SSLContext.cpp:347-376` | `fixtures/source-excerpts/E27.txt` |
| R-09 | LOW | gRPC ledger reads expose ledger hashes; low sensitivity, read-only. | `src/xrpld/rpc/GRPCHandlers.h:40-55` | `fixtures/source-excerpts/E31.txt` |
| R-10 | LOW | doPause/doResume dead declarations could be re-registered without review and counted as methods. | `src/xrpld/rpc/handlers/Handlers.h:110,120` | `fixtures/source-excerpts/E34.txt` |
| R-11 | LOW | random returns CSPRNG output; no PQ concern, but seed entropy depends on the host RNG (crypto_prng). | `src/xrpld/rpc/handlers/Random.cpp:46` | `fixtures/source-excerpts/E33.txt` |
| R-12 | LOW | 65 methods with no direct crypto exposure still transit TLS; their exposure is transport-only (see R-03). | `src/xrpld/rpc/detail/Handler.cpp:83-199` | `outputs/derived/method-inventory.json` |

## Counts

- HIGH: 3
- MEDIUM: 5
- LOW: 4
- Total: 12
