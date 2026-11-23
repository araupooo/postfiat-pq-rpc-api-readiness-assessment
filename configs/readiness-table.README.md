# readiness-table.json

`configs/readiness-table.json` (schema version 1) lists the 7
primitive families relevant to the RPC/API surface at the pinned
commit, with a status for each:

| Family | Status | Meaning |
|--------|--------|---------|
| ed25519 | not-quantum-resistant | In the tree; broken by Shor's algorithm |
| secp256k1 | not-quantum-resistant | In the tree; broken by Shor's algorithm |
| sha512-half | quantum-resistant-grover-limited | In the tree; Grover only, ~128-bit post-quantum strength |
| ml-kem | not-present | FIPS 203; 0 hits in src/ + include/ |
| ml-dsa | not-present | FIPS 204; 0 hits in src/ + include/ |
| slh-dsa | not-present | FIPS 205; 0 hits in src/ + include/ |
| tls-transport | classical-only | In the tree via OpenSSL; no PQ/hybrid KEM configured |

Each in-tree family carries `sources`: repo-relative file, line range,
and an anchor string. `src/rpc_inventory.py` re-verifies every anchor
inside its cited range on every run. The three not-present families
carry `absence_evidence` instead: the classifier's case-insensitive
grep over `src/` + `include/` (9 terms, 0 file hits), re-run by
`scripts/probe.py` check D-01.

`migration` on each family is a modelled judgement, not a measured
outcome. `references` are external standards (FIPS 203/204/205,
FIPS 180-4); see `docs/citations.md` for full citations and the
size-value caveats.
