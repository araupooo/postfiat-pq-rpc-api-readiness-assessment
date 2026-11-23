# Citations

## Standards (primary)

- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism
  Standard, final 13 August 2024, effective 14 August 2024.
  https://doi.org/10.6028/NIST.FIPS.203 —
  https://csrc.nist.gov/pubs/fips/203/final
  Parameter sets (Table 3): ML-KEM-512 (pk 800, sk 1,632, ct 768),
  ML-KEM-768 (pk 1,184, sk 2,400, ct 1,088), ML-KEM-1024 (pk 1,568,
  sk 3,168, ct 1,568); shared secret 32 bytes. ML-KEM-768 is the NIST
  recommended default. Caveat: NIST CSRC carries a planning note
  (17 Nov 2025) that an issue in FIPS 203 will be corrected in a
  future update/revision; table values are cited as final-standard
  values with that caveat.
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard,
  final 13 August 2024, effective 14 August 2024.
  https://doi.org/10.6028/NIST.FIPS.204
  Parameter sets (Table 2, public-key and signature sizes only):
  ML-DSA-44 (pk 1,312, sig 2,420), ML-DSA-65 (pk 1,952, sig 3,309),
  ML-DSA-87 (pk 2,592, sig 4,627). No default parameter set is
  designated. ML-DSA private-key sizes are NOT cited in this pack:
  secondary sources disagree (2,560/4,032/4,896 vs 2,528/4,000/4,864)
  and the primary Table 2 value was not re-verified for this pack.
- NIST FIPS 205, Stateless Hash-Based Digital Signature Standard,
  final 13 August 2024, effective 14 August 2024.
  https://doi.org/10.6028/NIST.FIPS.205
  Parameter sets (Table 2, verified in the primary text): public
  keys 32/48/64 bytes, signatures 7,856–49,856 bytes across the
  twelve parameter sets (128s 7,856; 128f 17,088; 192s 16,224; 192f
  35,664; 256s 29,792; 256f 49,856). Private-key size is 4n bytes by
  construction (64/96/128) — derived from the key-generation
  description, not tabulated in Table 2.
- NIST FIPS 180-4, Secure Hash Standard (SHA-512), the hash function
  underlying sha512Half.
- FIPS 206 (FN-DSA, from FALCON) is a draft standard, not final; it
  is tracked as a gap (G-06), not a readiness family.

Federal Register notice of approval for FIPS 203/204/205: Vol. 89
No. 157 (14 August 2024), effective 14 August 2024.
https://www.govinfo.gov/content/pkg/FR-2024-08-14/html/2024-17956.htm

## Pinned tree (primary)

- `postfiatorg/postfiatd` @
  `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, PR #50
  merge). Per-file blob SHA + SHA-256 in
  `fixtures/source-hashes.json`; all 27 files cross-checked against
  the GitHub API.
- XRPL cryptographic-keys documentation, linked from in-tree code
  (`src/libxrpl/protocol/SecretKey.cpp:136`):
  https://xrpl.org/cryptographic-keys.html#secp256k1-key-derivation
- XRPL Public API Methods reference (external corroboration only;
  the tree is authoritative):
  https://xrpl.org/docs/references/http-websocket-apis/public-api-methods

## Reading note

FIPS 203/204/205 sizes above are the values used in
`docs/migration-matrix.md` and `docs/decision-memo.md`. The ML-KEM
and SLH-DSA sizes were cross-checked between the primary FIPS texts
and secondary size tables; the ML-DSA private-key sizes were not
cross-checked to a single primary value and are therefore omitted
rather than cited.
