# Methodology

## Pinned source

postfiatd commit `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, PR #50 merge; repo `postfiatorg/postfiatd`). A local
checkout at `~/workspace/postfiatd-pin-0085a1f` was verified with
`git rev-parse HEAD` before any excerpt was taken. Every line number
in this pack was verified with `grep -n` on that checkout; no line
number was taken from a web fetch. `scripts/extract_excerpts.py`
re-derives all 41 excerpts from the checkout and records SHA-256
digests plus git blob SHAs in `fixtures/source-hashes.json` (27 source
files). Every cited file's blob SHA + size was cross-checked against
the GitHub API (repo `postfiatorg/postfiatd`, ref = pinned commit);
all 27 files matched (API size == local byte count, API blob SHA ==
local `git hash-object`).

Real paths are used throughout. Header files live under `include/`
(`include/xrpl/...`), not under `src/libxrpl/`; implementation files
live under `src/`. There is no `src/xrpld/rpc/handlers/Version.cpp` —
`VersionHandler` is header-only. There is no `src/libxrpl/protocol/
KeyType.h` — it is `include/xrpl/protocol/KeyType.h`.

## Classifier model

`src/rpc_inventory.py` (stdlib only, deterministic) parses the pinned
tree — no live node was run and no RPC call was made:

1. **Handler table.** It parses `src/xrpld/rpc/detail/Handler.cpp`
   `handlerArray` (72 entries) with a regex over the
   `{"name", byRef(&doX), Role::Y, CONDITION[, minVer, maxVer]}`
   shape, recording each entry's start/end line, and the two
   `addHandler<T>()` registrations (`LedgerHandler`, `VersionHandler`),
   reading their `name` / `role` / `condition` / API-version constants
   from the class headers. The commented-out `profile` entry
   (Handler.cpp:148-150) does not match the entry regex (it is
   commented out and has a space in `byRef (`) and is correctly
   excluded.
2. **Implementation mapping.** Each `doX` function is mapped to its
   definition in `src/xrpld/rpc/handlers/*.cpp` (declarations in
   `Handlers.h` are not scanned, so they cannot collide). The
   function-name line is recorded, not the `Json::Value` return-type
   line above it.
3. **Classification rules.** Each method carries an explicit rule or
   the `default-none` rule. Every explicit rule carries an evidence
   token; the classifier verifies the token exists in the cited file
   at the recorded line and FAILS if any rule's evidence is missing.
   A `default-none` method whose implementation file contains a crypto
   token (word-boundary `sign(` / `verify(`, `sha512Half`, key
   generation / signature verification helpers, `getTransactionID()`,
   `info().hash`, `getHashBySeq`) FAILS the run, forcing an explicit
   rule. `insert_or_assign` does not match the `sign(` token
   (word-boundary lookbehind).
4. **Readiness cross-check.** Every inventory row's primitives are
   checked against `configs/readiness-table.json`; every readiness
   source anchor is re-verified inside its cited line range; and the
   PQ absence claim is re-grepped (9 terms over `src/` + `include/`,
   0 file hits).
5. **gRPC + unregistered.** gRPC declarations are read from
   `src/xrpld/rpc/GRPCHandlers.h` (4 methods); handlers declared in
   `Handlers.h` but not registered (`doPause`, `doResume`) are
   recorded in the matrix.

## Exposure boundary (the definition that decides every row)

Exposure is defined by **direct handler operation only** — what the
handler function or its direct helpers do:

- **signing** — the handler creates a signature with a server-held
  secret key (`signature_operation: create`) or verifies a supplied
  signature (`verify`); `sign` and `submit` do both
  (`create+verify`).
- **key-exchange** — the handler creates or derives key material.
  There is no KEM/ECDH code path reachable from any RPC method, so
  this category is key generation in practice
  (`validation_create`, `wallet_propose`).
- **hashing** — the handler computes a hash. Only
  `server_definitions` does (`sha512Half` over the definitions JSON).
- **none** — no signing, key-generation, or hashing operation in the
  handler. This includes methods that merely **return hash data**
  (a ledger hash, a transaction ID — 8 methods, flagged
  `hash_data: true`) and methods whose cryptography lives in another
  layer: `connect` (peer-handshake session signature, overlay layer),
  `manifest` (manifest signature verification, validator-manifest
  layer), `simulate` (any signature verification is indirect, inside
  the apply pipeline), `server_info` (the definitions hash is computed
  for `server_definitions`, not for `server_info`).

This boundary was cross-checked against an independent parallel
research pass over the same pinned tree, which used the same direct-
operation definition and reached the same 74-method inventory, the
same 4-method gRPC surface, the same 0-hit PQ result, and the same
two-scheme (`KeyType` has exactly two enumerators) finding. Two
differences were found and resolved in favour of the verified parse:
the research notes' "52 USER / 22 ADMIN" role split is a miscount —
the classifier parse gives 51 USER / 23 ADMIN (23 `Role::ADMIN`
occurrences in `Handler.cpp`, plus the two new-style handlers, both
`Role::USER`); and the research notes' ML-DSA private-key sizes
(2,560/4,032/4,896) carry a secondary-source discrepancy, so this
pack cites only ML-DSA public-key and signature sizes from FIPS 204
Table 2 and does not cite ML-DSA private-key sizes at all.

## What is source-derived, tested, or modelled

- **SOURCE-DERIVED** — the 74-method inventory, registration sites,
  roles, conditions, API ranges, implementation files, evidence
  tokens, the 7-family readiness table, the 0-hit PQ grep, the 4
  gRPC methods, the unregistered declarations. Each is re-verified by
  `scripts/probe.py` against the checkout.
- **TESTED** — the classifier run and the 9 probe checks
  (`scripts/probe.py`), including the byte-identical determinism
  re-run (full SHA-256 compare). These test the pack's own outputs,
  not postfiatd behaviour.
- **MODELLED** — urgency (HIGH/MEDIUM/LOW) and recommendation
  (hybrid/no-change/pq-only), labelled `modelled` in every inventory
  row. No live node was run, so no claim in this pack is a measured
  runtime result. In particular: no TLS handshake was negotiated, no
  RPC response was observed, and no FIPS test vector was executed.

## API versions

Default handler API range is 1–3
(`apiMinimumSupportedVersion` = 1, `apiMaximumSupportedVersion` = 3
via `apiBetaVersion`, `include/xrpl/protocol/ApiVersion.h:56-62`).
Only `ledger_header` and `tx_history` are restricted to API v1
(`Handler.cpp:135,181`). The classifier records explicit ranges
where present and `1-3 (default)` otherwise.

## Signing gate

`sign`, `sign_for`, `channel_authorize`, and the signing path of
`submit` are registered `Role::USER` and refuse non-ADMIN callers
unless `signingEnabled_` is true (`canSign()`,
`src/xrpld/core/Config.h:365-367`; default `signingEnabled_ = false`,
`Config.h:132`). `wallet_propose` and `validation_create` are
registered `Role::ADMIN` outright. Responses for `sign`, `sign_for`,
and signing-`submit` carry a deprecation notice; the methods are
live in this commit.

## Determinism

Re-runs produce byte-identical outputs: sorted keys and rows, no
timestamps, no absolute paths, no elapsed times in any deterministic
output. Timing is sanity-checked (non-negative) in `probe.py` and
never recorded. `scripts/compare_reproduce.py` deep-compares a fresh
run against the shipped outputs ignoring only volatile fields.
