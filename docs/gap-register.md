# Gap register

| ID | Status | Gap | Evidence |
|----|--------|-----|----------|
| G-01 | OPEN | No ML-KEM / ML-DSA / SLH-DSA implementation or test vectors anywhere in the tree (0 hits over src/ + include/). | `outputs/derived/readiness-matrix.json` lines 137-154 |
| G-02 | OPEN | No hybrid signature format defined for transactions or validations (no dual-signature field or acceptance rule). | `docs/migration-matrix.md` |
| G-03 | OPEN | No ledger rule for PQ key types: KeyType has exactly two enumerators (secp256k1, ed25519) and keypairForSignature rejects anything else. | `fixtures/source-excerpts/E23.txt` |
| G-04 | OPEN | No TLS hybrid group configured; PQ transport depends on the linked OpenSSL build, not in-tree code. | `fixtures/source-excerpts/E26.txt`, `E27.txt` |
| G-05 | OPEN | No live-node verification in this pack: no RPC response was observed, no TLS handshake negotiated, no role enforcement tested on a running node. | `docs/methodology.md` |
| G-06 | OPEN | FIPS 206 (FN-DSA) is not tracked in the readiness table; it is a draft standard, not final. | `docs/citations.md` |

## Counts

- OPEN: 6
- Total: 6
