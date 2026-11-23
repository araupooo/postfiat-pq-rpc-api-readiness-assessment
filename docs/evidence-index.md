# Evidence index

Every evidence artefact in this pack, what it contains, and how it
was produced. Pinned commit throughout:
`0085a1ff885d6a446369cf73a4430f75af22be55`.

## Classifier outputs (tested)

- `outputs/derived/method-inventory.json` (2,570 lines) — one row per
  method (74 rows, sorted by method name): registration site,
  implementation file:line, role, condition, API range, exposure,
  urgency (modelled), recommendation (modelled), evidence token,
  rationale, primitives, signature operation, hash-data flag.
  Produced by `src/rpc_inventory.py`.
  SHA-256: `dc58e7d292360f9c3cc1c5384655e80253d349dc0b55dfe8a306d4d9a0745fe7`
- `outputs/derived/readiness-matrix.json` (210 lines) — counts by
  exposure (lines 80-85), urgency (205-209), recommendation
  (164-168), roles (169-172), method lists per exposure, gRPC methods
  (87-108), unregistered handlers (193-201), PQ absence record
  (137-154). Produced by `src/rpc_inventory.py`.
  SHA-256: `7df4d889a99da50c42bee5f7c1ccb96018477d3245af5e6f3d5e070f5deae06c`
- `outputs/derived/probe-results.json` (65 lines) — 9/9 probe checks
  PASS, with the inventory/matrix digests. Produced by
  `scripts/probe.py`.
- `outputs/derived/run-summary.json` — step statuses for the full
  suite. Produced by `scripts/run_all.sh`.
- `outputs/probe-run.log` — unedited probe stdout (9 PASS lines plus
  full SHA-256 digests). No timestamps, no absolute paths.
- `outputs/run.log` — full SHA-256 listing of every deterministic
  output file. No timestamps, no absolute paths.

## Configs (source-derived)

- `configs/readiness-table.json` — 7 primitive families (Ed25519,
  secp256k1, SHA-512-Half, ML-KEM, ML-DSA, SLH-DSA, TLS transport)
  with status, role, quantum threat, migration (modelled), in-tree
  source citations (anchor-verified by the classifier), and external
  FIPS references. Schema version 1.
- `configs/readiness-table.README.md` — how to read the table.

## Fixtures (source-derived)

- `fixtures/excerpts-manifest.json` — 41 excerpts (E01–E41) with
  file, line range, anchor, purpose. Every range and anchor was
  verified against the pinned checkout before extraction.
- `fixtures/source-excerpts/E01.txt`–`E41.txt` — verbatim excerpts
  with header (repo, commit, file, lines, file SHA-256, git blob
  SHA). Produced by `scripts/extract_excerpts.py`.
- `fixtures/source-hashes.json` — SHA-256 digests and git blob SHAs
  for all 27 cited source files and all 41 excerpts. Every file's
  blob SHA + size cross-checked against the GitHub API (27/27 match).

## Docs

- `docs/methodology.md` — pinned source, classifier model, exposure
  boundary, source-derived/tested/modelled split, API versions,
  signing gate, determinism.
- `docs/claim-index.md` — 24 claims (VERIFIED 16, SPECIFIED 1,
  MODELLED 5, UNTESTABLE 2), each mapped to script + output file +
  exact line range.
- `docs/excerpts.md` — short verbatim excerpts with commit + path,
  plus the full 41-excerpt index.
- `docs/citations.md` — FIPS 203/204/205 (+180-4, 206 draft) and
  pinned-tree references, with the size-value caveats.
- `docs/migration-matrix.md` — per-method recommendation and
  dependency order (modelled).
- `docs/risk-register.md` — 12 risks (HIGH 3, MEDIUM 5, LOW 4).
- `docs/decision-memo.md` — 7 prioritised recommendations
  (modelled).
- `docs/gap-register.md` — 6 gaps, all OPEN.
- `docs/evidence-index.md` — this file.

## Top level

- `README.md` — verdict, key numbers, counts, reproduce steps, file
  map.
- `findings.json` — 10 findings (HIGH 3, MEDIUM 4, LOW 3), all
  VERIFIED.
- `run-manifest.json` — pinned commit, counts recomputed from the
  tables, probe results, inventory/matrix digests.
- `SHA256SUMS` — digests of every pack file except itself and the
  internal-only `PACK-READY.md`.
- `PACK-READY.md` — internal-only checklist (not in the upload set).
