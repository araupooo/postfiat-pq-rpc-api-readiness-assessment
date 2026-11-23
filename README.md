# Post-Quantum RPC and API Readiness Assessment

## Verdict

**No post-quantum algorithm exists anywhere in the pinned tree. The
whole RPC signing surface is Ed25519 + secp256k1 (6 methods), key
generation is secp256k1 by default (2 methods), the only hash is
SHA-512-Half (1 method computes one, 8 return hash data), and TLS is
classical-only by default. 65 of 74 methods perform no cryptographic
operation in the handler at all. Migration is a KeyType-first hybrid
programme: 8 methods need hybrid (ML-DSA / ML-KEM) treatment, 66 need
no change.**

## Key numbers (SOURCE-DERIVED from the pinned tree — no live node was run)

- Pinned source: postfiatd `0085a1ff885d6a446369cf73a4430f75af22be55`
  (2026-10-10, PR #50 merge).
- 74 JSON-RPC methods inventoried by a runnable classifier parsing
  the handler table: 72 `handlerArray` entries + 2 new-style handlers
  (`ledger`, `version`). Roles: 51 USER, 23 ADMIN. Default API range
  1–3; only `ledger_header` and `tx_history` are restricted to v1.
- Exposure: signing 6, key-exchange 2, hashing 1, none 65.
  Signature operations: 4 create (sign, sign_for, submit, channel_authorize),
  2 verify-only (channel_verify, submit_multisigned). Key generation:
  validation_create, wallet_propose. Hash computed in-handler:
  server_definitions only. 8 methods return sha512Half-derived hash
  data; 1 returns CSPRNG output (random).
- Urgency (modelled): HIGH 6, MEDIUM 2, LOW 66.
  Recommendation (modelled): hybrid 8, no-change 66, pq-only 0.
- Readiness families (7): Ed25519 and secp256k1 not-quantum-resistant;
  SHA-512-Half quantum-resistant (Grover-limited); ML-KEM / ML-DSA /
  SLH-DSA not present (0 hits across src/ + include/ for 9 terms);
  TLS transport classical-only.
- gRPC surface: 4 methods (GetLedger, GetLedgerEntry, GetLedgerData,
  GetLedgerDiff), all read-only ledger queries, no crypto exposure.
- Declared but unregistered: doPause, doResume (dead declarations).
- Probe: 9/9 checks PASS (inventory completeness, arithmetic,
  rule evidence, readiness cross-check, gRPC/unregistered, count
  reconciliation, determinism, excerpt integrity, timing sanity).
- Excerpts: 41 verbatim pinned-source excerpts, 27 source files,
  blob SHAs + sizes cross-checked against the GitHub API (27/27 match).

## Counts

- Findings: 10 (HIGH 3, MEDIUM 4, LOW 3), all VERIFIED.
- Claims: 24 (VERIFIED 16, SPECIFIED 1, MODELLED 5, UNTESTABLE 2).
- Risks: 12 (HIGH 3, MEDIUM 5, LOW 4).
- Gaps: 6.

## Boundary

No live node was run and no RPC call was made. The classifier parses
source and classifies; every number above is source-derived or a
labelled modelled judgement. Source-derived facts (inventory,
readiness table, PQ absence) are re-verified by `scripts/probe.py`
against the pinned checkout. Tested results are the classifier run
and the 9 probe checks. Modelled judgements are urgency, priority,
and recommendations. Live-node claims (TLS negotiation, RPC
responses, FIPS test vectors) are UNTESTABLE in this pack and are
stated as such in `docs/claim-index.md`.

## Reproduce

```bash
python3 src/rpc_inventory.py               # classifier -> outputs/derived/method-inventory.json + readiness-matrix.json
python3 scripts/probe.py                   # 9 probe checks, exit 0 only if all pass
python3 scripts/extract_excerpts.py        # verbatim pinned-source excerpts + hashes
bash scripts/run_all.sh                    # full suite end to end
bash scripts/clean_reproduce.sh            # full fresh-environment check
bash scripts/verify_digests.sh             # sha256sum -c SHA256SUMS
```

Only deterministic source parsing runs. No live node, no RPC calls,
no transactions, no votes, no live key material, no credentials
anywhere in the pack.

## File map

- `README.md` — this file.
- `findings.json` — 10 findings with severity, status, evidence.
- `run-manifest.json` — pinned commit, counts recomputed from the tables.
- `docs/` — decision memo, migration matrix, methodology,
  claim-to-evidence index, excerpts, citations, evidence index, risk
  register, gap register.
- `src/rpc_inventory.py` — stdlib-only deterministic classifier
  (handler-table parser + exposure rules + readiness cross-check).
- `scripts/` — classifier runner, probe, excerpts, reproduce, compare,
  digests.
- `configs/readiness-table.json` — the 7 primitive families with
  status, sources, and FIPS references.
- `fixtures/source-excerpts/` — 41 verbatim pinned-source excerpts
  with file paths and grep-verified line numbers.
- `fixtures/source-hashes.json` — SHA-256 digests and git blob SHAs
  for every cited source file.
- `outputs/` — unedited classifier/probe logs, derived JSONs,
  fresh-clone reproduction evidence.
- `SHA256SUMS` — digests of every pack file except itself and the
  internal-only `PACK-READY.md`.
