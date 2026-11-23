#!/bin/bash
# run_all.sh — run the full Post-Quantum RPC and API Readiness
# Assessment suite end to end: excerpt extraction (when a manifest
# and a pinned checkout are available), readiness-table schema
# validation, classifier run, probe checks, run manifest, and a full
# SHA-256 listing (all 64 hex chars) of every deterministic output file.
#
# Idempotent: outputs are deterministic (no timestamps, no absolute
# paths, no measured timings in any derived JSON), so a second run
# produces byte-identical outputs and digests.
#
# Exit codes:
#   0 — every step passed.
#   1 — a step failed.
#   2 — src/rpc_inventory.py is missing.
#
# Excerpt extraction is skipped (recorded, not fatal) when no manifest
# exists yet, or when the pinned checkout is not available in this
# environment (e.g. CI): the shipped excerpts stay covered by
# SHA256SUMS verification instead.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_ROOT" || exit 1
PINNED_COMMIT="0085a1ff885d6a446369cf73a4430f75af22be55"
PINNED_CHECKOUT="${PINNED_CHECKOUT:-$HOME/workspace/postfiatd-pin-0085a1f}"
mkdir -p outputs/derived fixtures/source-excerpts
export PINNED_CHECKOUT

OVERALL=0
EXTRACT_STATUS="skipped: no excerpts manifest"
READINESS_STATUS="pass"
CLASSIFY_STATUS="not_run"
PROBE_STATUS="skipped: no probe script"

echo "=== run_all.sh ==="
echo "pack: $PACK_ROOT"
echo "pinned commit: $PINNED_COMMIT"

# --- step 1: extract excerpts -------------------------------------------
echo "--- step 1: extract excerpts ---"
if [ -f fixtures/excerpts-manifest.json ]; then
  if [ -d "$PINNED_CHECKOUT" ]; then
    if python3 scripts/extract_excerpts.py; then
      EXTRACT_STATUS="pass"
    else
      echo "extract_excerpts.py FAILED"
      EXTRACT_STATUS="failed"
      OVERALL=1
    fi
  else
    EXTRACT_STATUS="skipped: no pinned checkout at PINNED_CHECKOUT"
    echo "extract skipped: no pinned checkout ($PINNED_CHECKOUT)"
  fi
else
  echo "extract skipped: no fixtures/excerpts-manifest.json yet"
fi

# --- step 2: validate readiness table -----------------------------------
echo "--- step 2: validate readiness table ---"
if python3 - <<'EOF'
import json
cfg = json.load(open("configs/readiness-table.json"))
assert cfg.get("schema_version") == 1, "schema_version != 1"
assert cfg.get("pinned_commit") == "0085a1ff885d6a446369cf73a4430f75af22be55", "pinned_commit mismatch"
fams = cfg["families"]
assert isinstance(fams, list) and len(fams) == 7, f"need 7 families, got {len(fams)}"
ids = sorted(f["id"] for f in fams)
assert ids == ["ed25519", "ml-dsa", "ml-kem", "secp256k1", "sha512-half", "slh-dsa", "tls-transport"], f"family ids wrong: {ids}"
allowed = {"not-quantum-resistant", "quantum-resistant-grover-limited", "not-present", "classical-only"}
for f in fams:
    assert f["status"] in allowed, f"{f['id']}: bad status {f['status']}"
    for s in f.get("sources", []):
        for k in ("file", "start_line", "end_line", "anchor"):
            assert k in s, f"{f['id']}: source missing {k}"
        assert s["start_line"] <= s["end_line"], f"{f['id']}: bad source range"
    assert f.get("migration"), f"{f['id']}: missing migration"
print("readiness table: 7 families, ids + statuses OK")
EOF
then
  READINESS_STATUS="pass"
else
  echo "readiness-table validation FAILED"
  READINESS_STATUS="failed"
  OVERALL=1
fi

# --- step 3: classifier ---------------------------------------------------
echo "--- step 3: classifier ---"
if [ ! -f src/rpc_inventory.py ]; then
  echo "ERROR: src/rpc_inventory.py is missing — the harness builder must provide it."
  exit 2
fi
python3 src/rpc_inventory.py
CLASSIFY_RC=$?
if [ "$CLASSIFY_RC" -eq 0 ]; then
  CLASSIFY_STATUS="pass"
  echo "classifier: PASS"
else
  CLASSIFY_STATUS="failed"
  echo "classifier FAILED (exit $CLASSIFY_RC)"
  OVERALL=1
fi

# --- step 4: probe checks -------------------------------------------------
echo "--- step 4: probe checks ---"
if [ -f scripts/probe.py ]; then
  if python3 scripts/probe.py; then
    PROBE_STATUS="pass"
  else
    echo "probe.py FAILED"
    PROBE_STATUS="failed"
    OVERALL=1
  fi
else
  echo "probe skipped: no scripts/probe.py yet"
fi

# --- step 5: run summary + run manifest (deterministic) ------------------
echo "--- step 5: run summary + run manifest ---"
EXTRACT_STATUS="$EXTRACT_STATUS" READINESS_STATUS="$READINESS_STATUS" \
CLASSIFY_STATUS="$CLASSIFY_STATUS" PROBE_STATUS="$PROBE_STATUS" python3 - <<'EOF'
import hashlib
import json
import os
import re
from collections import Counter

summary = {
    "pack": "Post-Quantum RPC and API Readiness Assessment",
    "pinned_commit": "0085a1ff885d6a446369cf73a4430f75af22be55",
    "method_count": 74,
    "steps": {
        "extract_excerpts": os.environ["EXTRACT_STATUS"],
        "readiness_table": os.environ["READINESS_STATUS"],
        "classifier": os.environ["CLASSIFY_STATUS"],
        "probe": os.environ["PROBE_STATUS"],
    },
}
with open("outputs/derived/run-summary.json", "w") as fh:
    json.dump(summary, fh, indent=1)
    fh.write("\n")

inv = json.load(open("outputs/derived/method-inventory.json"))
mat = json.load(open("outputs/derived/readiness-matrix.json"))
probe = json.load(open("outputs/derived/probe-results.json"))
findings = json.load(open("findings.json"))["findings"]
hashes = json.load(open("fixtures/source-hashes.json"))

def table_rows(path, prefix, status_col=1):
    rows = []
    for ln in open(path, encoding="utf-8"):
        m = re.match(rf"\| ({prefix}-\d+) \| ([A-Z]+) \|", ln)
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows

claims = table_rows("docs/claim-index.md", "C")
risks = table_rows("docs/risk-register.md", "R")
gaps = table_rows("docs/gap-register.md", "G")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

manifest = {
    "pack": "Post-Quantum RPC and API Readiness Assessment",
    "pinned_commit": "0085a1ff885d6a446369cf73a4430f75af22be55",
    "counts": {
        "methods": {
            "total": inv["method_count"],
            "by_exposure": mat["exposure_counts"],
            "by_urgency": mat["urgency_counts"],
            "by_recommendation": mat["recommendation_counts"],
        },
        "findings": {
            "total": len(findings),
            "by_severity": dict(sorted(Counter(f["severity"] for f in findings).items())),
            "by_status": dict(sorted(Counter(f["status"] for f in findings).items())),
        },
        "claims": {
            "total": len(claims),
            "by_status": dict(sorted(Counter(s for _, s in claims).items())),
        },
        "risks": {
            "total": len(risks),
            "by_severity": dict(sorted(Counter(s for _, s in risks).items())),
        },
        "gaps": len(gaps),
    },
    "probes": {"passed": probe["passed"], "total": probe["total"]},
    "inventory_sha256": sha256_file("outputs/derived/method-inventory.json"),
    "matrix_sha256": sha256_file("outputs/derived/readiness-matrix.json"),
    "verification": {
        "excerpts": len(hashes["excerpts"]),
        "source_files": len(hashes["files"]),
    },
    "status": "SOURCE-DERIVED",
}
with open("run-manifest.json", "w") as fh:
    json.dump(manifest, fh, indent=1)
    fh.write("\n")
print("wrote outputs/derived/run-summary.json")
print("wrote run-manifest.json")
print("counts: methods=%d findings=%d claims=%d risks=%d gaps=%d" % (
    inv["method_count"], len(findings), len(claims), len(risks), len(gaps)))
EOF
if [ "$?" -ne 0 ]; then
  echo "run summary / manifest FAILED"
  OVERALL=1
fi

# --- step 6: full SHA-256 listing of deterministic outputs --------------
echo "--- step 6: SHA-256 of deterministic outputs (full 64 hex chars) ---"
{
  echo "# run.log — deterministic output digests (no timestamps, no absolute paths)"
  echo "# step extract_excerpts: $EXTRACT_STATUS"
  echo "# step readiness_table: $READINESS_STATUS"
  echo "# step classifier: $CLASSIFY_STATUS"
  echo "# step probe: $PROBE_STATUS"
  find outputs -type f ! -name 'run.log' ! -name 'compare-results.json' \
    ! -name 'fresh-clone-*' | sort | xargs sha256sum
} > outputs/run.log
cat outputs/run.log

# --- step 7: digests -------------------------------------------------------
echo "--- step 7: digests ---"
bash scripts/make_sha256sums.sh || { echo "make_sha256sums.sh FAILED"; OVERALL=1; }
bash scripts/verify_digests.sh || { echo "verify_digests.sh FAILED"; OVERALL=1; }

echo "=== run_all.sh done ==="
echo "extract_excerpts: $EXTRACT_STATUS"
echo "readiness_table: $READINESS_STATUS"
echo "classifier: $CLASSIFY_STATUS"
echo "probe: $PROBE_STATUS"
if [ "$OVERALL" -ne 0 ]; then
  echo "run_all.sh: FAILED (see steps above)"
  exit 1
fi
echo "run_all.sh: ALL STEPS PASSED"
exit 0
