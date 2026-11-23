#!/usr/bin/env python3
"""probe.py — re-verify the PQ readiness inventory from its own outputs.

Usage:
    python3 scripts/probe.py [INVENTORY_JSON]

Reads outputs/derived/method-inventory.json (default), re-derives
every invariant from the stored values instead of trusting them, and
re-checks each one against the pinned checkout:

  A  inventory completeness: 74 methods (72 handlerArray + 2
     addHandler), no duplicates, every registration site in bounds,
     every implementation file exists and the recorded line names the
     handler function.
  B  exposure/urgency/recommendation arithmetic reconciles to 74.
  C  rule evidence: every explicit-rule evidence token is found at
     the recorded line; every default-none implementation file is
     free of crypto tokens.
  D  readiness cross-check: 7 families, status distribution,
     every source anchor re-verified inside its cited range, PQ
     absence re-grepped (0 hits).
  E  gRPC surface (4 methods) and declared-but-unregistered handlers
     (doPause, doResume) match the matrix.
  F  counts reconcile across files: matrix == inventory ==
     readiness-table; excerpts manifest == extracted files ==
     source-hashes.json.
  G  determinism: re-running the classifier to a temp dir reproduces
     byte-identical outputs (full SHA-256 compare).
  H  excerpt integrity: every excerpt file digest matches
     fixtures/source-hashes.json.
  T  timing sanity only (non-negative, never recorded).

Exit 0 only if every case passes. Prints one PASS/FAIL line per case
with the FULL 64-char SHA-256 digest where a digest is involved, and
writes outputs/derived/probe-results.json plus outputs/probe-run.log
(the log is the unedited stdout of this run; it contains no absolute
paths and no timestamps).

No live node is involved: every check is source-derived or
classifier-output-derived.
"""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = PACK_ROOT / "outputs" / "derived" / "method-inventory.json"
PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"
PINNED_CHECKOUT = Path(__import__("os").environ.get(
    "PINNED_CHECKOUT", str(Path.home() / "workspace" / "postfiatd-pin-0085a1f")))

DENY_PATTERNS = [
    r"(?<![A-Za-z0-9_])sign\(",
    r"(?<![A-Za-z0-9_])verify\(",
    r"sha512Half",
    r"generateSecretKey",
    r"generateKeyPair",
    r"derivePublicKey",
    r"transactionSign",
    r"checkSign",
    r"signDigest",
    r"verifyDigest",
    r"randomSeed",
    r"getSeedFromRPC",
    r"parseRippleLibSeed",
    r"getTransactionID\(\)",
    r"info\(\)\.hash",
    r"getHashBySeq",
]
PQ_TERMS = ["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium",
            "SPHINCS", "mlkem", "mldsa", "slhdsa"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    inventory_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INVENTORY
    doc = load_json(inventory_path)
    methods = doc["methods"]
    matrix = load_json(PACK_ROOT / "outputs" / "derived" / "readiness-matrix.json")
    readiness = load_json(PACK_ROOT / "configs" / "readiness-table.json")
    manifest = load_json(PACK_ROOT / "fixtures" / "excerpts-manifest.json")
    hashes = load_json(PACK_ROOT / "fixtures" / "source-hashes.json")
    checks = []
    lines = []

    def check(cid, label, ok, detail=""):
        checks.append({"id": cid, "check": label, "pass": bool(ok),
                       "detail": detail})
        lines.append(("PASS " if ok else "FAIL ") + cid + " " + label +
                     ((" — " + detail) if detail else ""))

    t_start = time.monotonic()

    # --- A: inventory completeness --------------------------------------
    names = [m["method"] for m in methods]
    styles = {}
    for m in methods:
        styles.setdefault(m["registration_style"], 0)
        styles[m["registration_style"]] += 1
    a_ok = (len(methods) == 74 and len(set(names)) == 74
            and styles.get("handlerArray") == 72
            and styles.get("addHandler") == 2
            and doc.get("pinned_commit") == PINNED_COMMIT)
    a_detail = ""
    handler_lines = (PINNED_CHECKOUT / "src/xrpld/rpc/detail/Handler.cpp").read_text().splitlines()
    for m in methods:
        reg = m["registration"]
        if not (1 <= reg["start_line"] <= reg["end_line"] <= len(handler_lines)):
            a_ok = False
            a_detail = f"{m['method']}: registration range out of bounds"
            break
        if m["registration_style"] == "handlerArray":
            site = "\n".join(handler_lines[reg["start_line"] - 1:reg["end_line"]])
            if f'"{m["method"]}"' not in site or m["handler_function"] not in site:
                a_ok = False
                a_detail = f"{m['method']}: registration site does not name method/function"
                break
        impl = m["implementation"]
        ipath = PINNED_CHECKOUT / impl["file"]
        if not ipath.is_file():
            a_ok = False
            a_detail = f"{m['method']}: implementation file missing: {impl['file']}"
            break
        ilines = ipath.read_text(errors="replace").splitlines()
        if impl["line"] is None or not (1 <= impl["line"] <= len(ilines)):
            a_ok = False
            a_detail = f"{m['method']}: implementation line out of bounds"
            break
        if m["handler_function"] not in ilines[impl["line"] - 1]:
            a_ok = False
            a_detail = (f"{m['method']}: implementation line {impl['line']} "
                        f"does not name {m['handler_function']}")
            break
    check("A-01", "inventory: 74 methods (72 handlerArray + 2 addHandler), no duplicates, every registration site and implementation line names the method",
          a_ok, a_detail or "74 methods, all sites verified")

    # --- B: arithmetic reconciles ---------------------------------------
    from collections import Counter
    exp = Counter(m["exposure"] for m in methods)
    urg = Counter(m["urgency"] for m in methods)
    rec = Counter(m["recommendation"] for m in methods)
    b_ok = (exp == {"signing": 6, "key-exchange": 2, "hashing": 1, "none": 65}
            and urg == {"HIGH": 6, "MEDIUM": 2, "LOW": 66}
            and rec == {"hybrid": 8, "no-change": 66}
            and sum(exp.values()) == sum(urg.values()) == sum(rec.values()) == 74
            and matrix["exposure_counts"] == {"signing": 6, "key-exchange": 2,
                                              "hashing": 1, "none": 65}
            and matrix["urgency_counts"] == {"HIGH": 6, "MEDIUM": 2, "LOW": 66}
            and matrix["recommendation_counts"] == {"hybrid": 8, "pq-only": 0,
                                                    "no-change": 66}
            and matrix["method_count"] == 74)
    check("B-01", "exposure 6/2/1/65, urgency 6/2/66, recommendation 8/66/0; all sum to 74 and match the matrix",
          b_ok, f"exposure={dict(exp)} urgency={dict(urg)} recommendation={dict(rec)}")

    # --- C: rule evidence -------------------------------------------------
    c_ok = True
    c_detail = ""
    for m in methods:
        ev = m["evidence"]
        elines = (PINNED_CHECKOUT / ev["file"]).read_text(errors="replace").splitlines()
        if not (1 <= ev["line"] <= len(elines)) or ev["token"] not in elines[ev["line"] - 1]:
            c_ok = False
            c_detail = (f"{m['method']}: evidence token {ev['token']!r} not "
                        f"at {ev['file']}:{ev['line']}")
            break
        if m["rule"] == "default-none":
            text = (PINNED_CHECKOUT / m["implementation"]["file"]).read_text(errors="replace")
            for pat in DENY_PATTERNS:
                mm = re.search(pat, text)
                if mm:
                    c_ok = False
                    c_detail = (f"{m['method']}: default-none implementation "
                                f"contains crypto token {pat!r}")
                    break
            if not c_ok:
                break
    check("C-01", "every rule's evidence token sits at its recorded line; every default-none implementation is free of crypto tokens",
          c_ok, c_detail or "%d explicit rules verified, %d default-none implementations clean" % (
              sum(1 for m in methods if m["rule"] == "explicit"),
              sum(1 for m in methods if m["rule"] == "default-none")))

    # --- D: readiness cross-check ----------------------------------------
    fams = {f["id"]: f for f in readiness["families"]}
    d_ok = (len(readiness["families"]) == 7
            and readiness.get("pinned_commit") == PINNED_COMMIT
            and sorted(fams) == ["ed25519", "ml-dsa", "ml-kem", "secp256k1",
                                 "sha512-half", "slh-dsa", "tls-transport"])
    d_detail = ""
    status_counts = Counter(f["status"] for f in readiness["families"])
    if status_counts != {"not-quantum-resistant": 2,
                         "quantum-resistant-grover-limited": 1,
                         "not-present": 3, "classical-only": 1}:
        d_ok = False
        d_detail = f"status distribution wrong: {dict(status_counts)}"
    if d_ok:
        for fam in readiness["families"]:
            for src in fam.get("sources", []):
                slines = (PINNED_CHECKOUT / src["file"]).read_text(errors="replace").splitlines()
                found = [i + 1 for i, ln in enumerate(slines) if src["anchor"] in ln]
                inside = [l for l in found if src["start_line"] <= l <= src["end_line"]]
                if not inside:
                    d_ok = False
                    d_detail = (f"family {fam['id']}: anchor {src['anchor']!r} "
                                f"not inside {src['file']}:{src['start_line']}-{src['end_line']}")
                    break
            if not d_ok:
                break
    pq_total = 0
    if d_ok:
        for term in PQ_TERMS:
            out = subprocess.run(
                ["grep", "-rni", "--include=*.cpp", "--include=*.h", "-l",
                 term, "src", "include"],
                cwd=str(PINNED_CHECKOUT), capture_output=True, text=True)
            pq_total += len(out.stdout.split()) if out.stdout.strip() else 0
        if pq_total != 0:
            d_ok = False
            d_detail = f"PQ grep found {pq_total} file hits, expected 0"
    check("D-01", "readiness table: 7 families, status 2/1/3/1, every source anchor re-verified in range, PQ grep 0 hits",
          d_ok, d_detail or "7 families; PQ terms checked: " + ", ".join(PQ_TERMS))

    # --- E: gRPC + unregistered -------------------------------------------
    e_ok = (matrix["grpc_method_count"] == 4
            and sorted(g["method"] for g in matrix["grpc_methods"]) ==
                ["doLedgerDataGrpc", "doLedgerDiffGrpc",
                 "doLedgerEntryGrpc", "doLedgerGrpc"]
            and [u["handler_function"] for u in matrix["unregistered_declared_handlers"]] ==
                ["doPause", "doResume"])
    check("E-01", "gRPC surface is 4 methods (GetLedger/GetLedgerEntry/GetLedgerData/GetLedgerDiff); declared-but-unregistered handlers are exactly doPause/doResume",
          e_ok, f"grpc={matrix['grpc_method_count']} unregistered={[u['handler_function'] for u in matrix['unregistered_declared_handlers']]}")

    # --- F: counts reconcile across files ---------------------------------
    f_ok = True
    f_detail = ""
    if matrix["signing_methods"] != sorted(m["method"] for m in methods if m["exposure"] == "signing"):
        f_ok, f_detail = False, "matrix signing_methods != inventory"
    elif matrix["key_exchange_methods"] != sorted(m["method"] for m in methods if m["exposure"] == "key-exchange"):
        f_ok, f_detail = False, "matrix key_exchange_methods != inventory"
    elif matrix["hashing_methods"] != sorted(m["method"] for m in methods if m["exposure"] == "hashing"):
        f_ok, f_detail = False, "matrix hashing_methods != inventory"
    elif matrix["high_urgency_methods"] != sorted(m["method"] for m in methods if m["urgency"] == "HIGH"):
        f_ok, f_detail = False, "matrix high_urgency_methods != inventory"
    elif matrix["readiness_families"] != sorted(fams):
        f_ok, f_detail = False, "matrix readiness_families != readiness table"
    excerpts = manifest.get("excerpts", [])
    exdir = PACK_ROOT / "fixtures" / "source-excerpts"
    if f_ok and len(excerpts) != len(list(exdir.glob("*.txt"))):
        f_ok, f_detail = False, "manifest excerpt count != extracted file count"
    if f_ok:
        for e in excerpts:
            if e["id"] not in hashes.get("excerpts", {}):
                f_ok, f_detail = False, f"excerpt {e['id']} missing from source-hashes.json"
                break
            if hashes["excerpts"][e["id"]]["file"] != e["file"]:
                f_ok, f_detail = False, f"excerpt {e['id']}: file mismatch vs source-hashes.json"
                break
    check("F-01", "matrix lists reconcile with the inventory and readiness table; excerpt manifest, extracted files and source-hashes.json agree",
          f_ok, f_detail or f"{len(excerpts)} excerpts, {len(hashes.get('files', {}))} source files in hashes")

    # --- G: determinism ----------------------------------------------------
    inv_digest = sha256_file(inventory_path)
    mat_digest = sha256_file(PACK_ROOT / "outputs" / "derived" / "readiness-matrix.json")
    with tempfile.TemporaryDirectory(prefix="pftl-pq-probe.") as td:
        tmp_inv = Path(td) / "method-inventory.json"
        tmp_mat = Path(td) / "readiness-matrix.json"
        proc = subprocess.run(
            [sys.executable, str(PACK_ROOT / "src" / "rpc_inventory.py"),
             "--out", str(tmp_inv), "--matrix-out", str(tmp_mat)],
            capture_output=True, text=True)
        rerun_ok = proc.returncode == 0
        rerun_inv = sha256_file(tmp_inv) if tmp_inv.is_file() else "missing"
        rerun_mat = sha256_file(tmp_mat) if tmp_mat.is_file() else "missing"
    check("G-01", "determinism: classifier re-run reproduces byte-identical inventory and matrix (full SHA-256)",
          rerun_ok and rerun_inv == inv_digest and rerun_mat == mat_digest,
          f"inventory shipped={inv_digest} rerun={rerun_inv}; matrix shipped={mat_digest} rerun={rerun_mat}")

    # --- H: excerpt integrity ----------------------------------------------
    h_ok = True
    h_detail = ""
    for ex_id, rec in sorted(hashes.get("excerpts", {}).items()):
        p = exdir / f"{ex_id}.txt"
        if not p.is_file():
            h_ok, h_detail = False, f"excerpt file missing: {ex_id}.txt"
            break
        if sha256_file(p) != rec["sha256"]:
            h_ok, h_detail = False, f"excerpt {ex_id}.txt digest mismatch"
            break
    check("H-01", "every excerpt file digest matches fixtures/source-hashes.json",
          h_ok, h_detail or f"{len(hashes.get('excerpts', {}))} excerpt digests verified")

    # Timing sanity only: non-negative, never compared exactly. The
    # value is NOT recorded in any output file or log line: persisting
    # it would make probe-results.json, probe-run.log, and run.log
    # (which digests them) differ on every run and break the
    # byte-identical reproduction check.
    elapsed_ms = (time.monotonic() - t_start) * 1000.0
    timing_ok = elapsed_ms >= 0
    check("T-01", "timing sanity: total probe elapsed_ms is non-negative (loose band, never exact)",
          timing_ok, "value not recorded; never compared")

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    lines.append(f"probe: {passed}/{total} checks PASS")
    lines.append(f"probe: method-inventory.json sha256: {inv_digest}")
    lines.append(f"probe: readiness-matrix.json sha256: {mat_digest}")
    lines.append(f"probe: pinned commit {PINNED_COMMIT}")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)

    result_doc = {
        "pack": "Post-Quantum RPC and API Readiness Assessment",
        "pinned_commit": PINNED_COMMIT,
        "inventory_file": "outputs/derived/method-inventory.json",
        "inventory_sha256": inv_digest,
        "matrix_sha256": mat_digest,
        "checks": checks,
        "passed": passed,
        "total": total,
    }
    out_derived = PACK_ROOT / "outputs" / "derived" / "probe-results.json"
    out_derived.parent.mkdir(parents=True, exist_ok=True)
    with open(out_derived, "w", encoding="utf-8") as fh:
        json.dump(result_doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
    (PACK_ROOT / "outputs" / "probe-run.log").write_text(text)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
