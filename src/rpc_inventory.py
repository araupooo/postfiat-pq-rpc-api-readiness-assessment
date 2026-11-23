#!/usr/bin/env python3
"""rpc_inventory.py — deterministic JSON-RPC method inventory + PQ classifier.

Usage:
    python3 src/rpc_inventory.py [--checkout PATH] [--readiness PATH]
        [--out PATH] [--matrix-out PATH]

Parses the pinned postfiatd source tree (no live node, no RPC calls):

1.  Reads the JSON-RPC handler table in
    src/xrpld/rpc/detail/Handler.cpp (``handlerArray``) — every
    ``{"name", byRef(&doX), Role::Y, CONDITION[, minVer, maxVer]}``
    entry, with its registration-site line numbers.
2.  Reads the new-style handlers registered via ``addHandler<T>()``
    (``LedgerHandler``, ``VersionHandler``) and their ``name`` /
    ``role`` / ``condition`` / API-version constants from the class
    headers.
3.  Maps each ``doX`` function to its implementation file under
    src/xrpld/rpc/handlers/ by searching for the definition.
4.  Classifies each method by crypto exposure (signing /
    key-exchange / hashing / none) and migration urgency (HIGH /
    MEDIUM / LOW, a modelled judgement) using the RULES table below.
    Every rule carries an evidence token; the classifier verifies the
    token exists in the cited file (first matching line recorded) and
    FAILS if any rule's evidence is missing — a rule is never taken
    on trust.
5.  Guards the ``none`` default: any method with no explicit rule
    whose implementation file contains a crypto token (word-boundary
    ``sign(`` / ``verify(`` / ``sha512Half`` / key generation /
    signature verification helpers) FAILS the run, forcing an
    explicit rule.
6.  Cross-checks every inventory row's primitives against
    configs/readiness-table.json and re-verifies every readiness-table
    source citation (anchor inside the cited line range) and the
    zero-hit PQ absence claim (case-insensitive grep for
    ML-KEM/ML-DSA/SLH-DSA/Kyber/Dilithium/SPHINCS over src/ and
    include/).
7.  Records the gRPC surface (src/xrpld/rpc/GRPCHandlers.h) and
    handlers declared in Handlers.h but NOT registered in the table
    (doPause, doResume) in the readiness matrix.

Outputs (deterministic: sorted keys, sorted rows, repo-relative paths
only, no timestamps, no absolute paths, no elapsed times):
    outputs/derived/method-inventory.json
    outputs/derived/readiness-matrix.json

Exit 0 only if every parse, rule-evidence, guard, and cross-check
passes.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parent.parent
COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"
DEFAULT_CHECKOUT = Path(os.environ.get(
    "PINNED_CHECKOUT", "~/workspace/postfiatd-pin-0085a1f")).expanduser()

HANDLER_CPP = "src/xrpld/rpc/detail/Handler.cpp"
HANDLERS_H = "src/xrpld/rpc/handlers/Handlers.h"
HANDLERS_DIR = "src/xrpld/rpc/handlers"
GRPC_H = "src/xrpld/rpc/GRPCHandlers.h"

# Evidence tokens that force an explicit rule. Word-boundary regexes
# (``assign(`` must not match ``sign(``).
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

# method -> (exposure, urgency, recommendation, evidence_file,
#            evidence_token, rationale, primitives, signature_operation,
#            hash_data)
# Exposure is defined by DIRECT handler operation only (the handler
# function or its direct helpers): "signing" covers both creating a
# signature with a server-held secret key and verifying a supplied
# signature (distinguished by signature_operation); "key-exchange"
# covers creating, deriving, or publishing key material (there is no
# KEM/ECDH code path reachable from any RPC method — see the readiness
# table); "hashing" covers computing a hash in the handler. A method
# that merely RETURNS hash data (a ledger hash, a transaction ID) or
# triggers cryptography deeper in the stack (overlay handshake,
# apply-pipeline verification) is "none" with hash_data=true or an
# explicit rationale — the boundary is documented per row and in
# docs/methodology.md. Urgency and recommendation are MODELLED
# judgements (labelled as such in every output row); exposure and
# evidence are source-derived and verified here.
RULES = {
    # --- signing: a signature is created or verified ----------------
    "sign": ("signing", "HIGH", "hybrid",
             "src/xrpld/rpc/detail/TransactionSign.cpp",
             "stTx->sign(pk, sk, signatureTarget)",
             "sign calls transactionSign, which signs the transaction "
             "with the supplied secret key (and re-verifies the "
             "signature at construct time via checkValidity). Gated "
             "on canSign() (Config.h:365-367) for non-ADMIN callers.",
             ["ed25519", "secp256k1"], "create+verify", False),
    "sign_for": ("signing", "HIGH", "hybrid",
                 "src/xrpld/rpc/detail/TransactionSign.cpp",
                 "stTx->sign(pk, sk, signatureTarget)",
                 "sign_for calls transactionSignFor, which signs for a "
                 "multi-signing account with the supplied secret key. "
                 "Gated on canSign() for non-ADMIN callers.",
                 ["ed25519", "secp256k1"], "create", False),
    "submit": ("signing", "HIGH", "hybrid",
               "src/libxrpl/protocol/STTx.cpp",
               "STTx::checkSign(",
               "submit has two paths: with tx_blob it verifies the "
               "submitted signatures (STTx::checkSign); without it, "
               "it signs like sign — inline signing deprecated "
               "(Submit.cpp:67-71) and gated on canSign().",
               ["ed25519", "secp256k1"], "create+verify", False),
    "submit_multisigned": ("signing", "MEDIUM", "hybrid",
                           "src/xrpld/rpc/detail/TransactionSign.cpp",
                           "transactionSubmitMultiSigned(",
                           "submit_multisigned accepts no secret key; "
                           "it assembles a pre-signed multi-signed blob "
                           "and verifies the signatures via "
                           "transactionConstructImpl/checkValidity.",
                           ["ed25519", "secp256k1"], "verify", False),
    "channel_authorize": ("signing", "HIGH", "hybrid",
                          "src/xrpld/rpc/handlers/PayChanClaim.cpp",
                          "sign(pk, sk, msg.slice())",
                          "channel_authorize signs a payment-channel "
                          "claim with the supplied secret key. Gated on "
                          "canSign() for non-ADMIN callers.",
                          ["ed25519", "secp256k1"], "create", False),
    "channel_verify": ("signing", "MEDIUM", "hybrid",
                       "src/xrpld/rpc/handlers/PayChanClaim.cpp",
                       "verify(*pk, msg.slice()",
                       "channel_verify verifies a payment-channel "
                       "claim signature against a supplied public key; "
                       "no secret key is involved.",
                       ["ed25519", "secp256k1"], "verify", False),
    # --- key-exchange: key material is created or derived ------------
    # (No KEM/ECDH exists in the tree; this is key generation.)
    "validation_create": ("key-exchange", "HIGH", "hybrid",
                          "src/xrpld/rpc/handlers/ValidationCreate.cpp",
                          "generateSecretKey(KeyType::secp256k1, *seed)",
                          "validation_create generates a secp256k1 "
                          "validator key pair from a seed and returns "
                          "the private key, seed and public key.",
                          ["secp256k1"], None, False),
    "wallet_propose": ("key-exchange", "HIGH", "hybrid",
                       "src/xrpld/rpc/handlers/WalletPropose.cpp",
                       "generateKeyPair(*keyType, *seed)",
                       "wallet_propose generates an Ed25519 (default "
                       "secp256k1) account key pair from a seed or a "
                       "fresh random seed and returns seed material.",
                       ["ed25519", "secp256k1"], None, False),
    # --- hashing: a hash is computed in the handler -------------------
    "server_definitions": ("hashing", "LOW", "no-change",
                           "src/xrpld/rpc/handlers/ServerInfo.cpp",
                           "sha512Half(ripple::Slice",
                           "server_definitions is the only handler that "
                           "computes a hash: sha512Half over the "
                           "serialised definitions JSON.",
                           ["sha512-half"], None, False),
    # --- none, explicit: hash data returned, no hash computed --------
    "ledger": ("none", "LOW", "no-change",
               "src/xrpld/rpc/handlers/LedgerHandler.cpp",
               "getTransactionID()",
               "ledger returns ledger data including transaction IDs "
               "(sha512Half values) but computes no hash in the "
               "handler.",
               ["sha512-half"], None, True),
    "ledger_closed": ("none", "LOW", "no-change",
                      "src/xrpld/rpc/handlers/LedgerClosed.cpp",
                      "ledger->info().hash",
                      "ledger_closed returns the closed ledger's hash "
                      "but computes no hash in the handler.",
                      ["sha512-half"], None, True),
    "ledger_data": ("none", "LOW", "no-change",
                    "src/xrpld/rpc/handlers/LedgerData.cpp",
                    "lpLedger->info().hash",
                    "ledger_data returns the selected ledger's hash "
                    "but computes no hash in the handler.",
                    ["sha512-half"], None, True),
    "ledger_entry": ("none", "LOW", "no-change",
                     "src/libxrpl/protocol/Indexes.cpp",
                     "return sha512Half(safe_cast",
                     "ledger_entry looks up entries by index; entry "
                     "indexes are sha512Half values, but the handler "
                     "computes no hash.",
                     ["sha512-half"], None, True),
    "ledger_header": ("none", "LOW", "no-change",
                      "src/xrpld/rpc/handlers/LedgerHeader.cpp",
                      "addJson(jvResult, {*lpLedger, &context, 0});",
                      "ledger_header serialises the ledger header, "
                      "including its hash, but computes no hash in "
                      "the handler.",
                      ["sha512-half"], None, True),
    "tx": ("none", "LOW", "no-change",
           "src/xrpld/rpc/handlers/Tx.cpp",
           "getHashBySeq(seq) == hash",
           "tx compares a requested transaction hash against the "
           "ledger's hash-by-sequence record but computes no hash "
           "in the handler.",
           ["sha512-half"], None, True),
    "transaction_entry": ("none", "LOW", "no-change",
                          "src/xrpld/rpc/handlers/TransactionEntry.cpp",
                          "sttx->getTransactionID()",
                          "transaction_entry returns the transaction's "
                          "ID (a sha512Half value) but computes no "
                          "hash in the handler.",
                          ["sha512-half"], None, True),
    "account_tx": ("none", "LOW", "no-change",
                   "src/xrpld/rpc/handlers/AccountTx.cpp",
                   "getHashBySeq(",
                   "account_tx returns transactions with their hashes "
                   "and per-ledger hashes but computes no hash in "
                   "the handler.",
                   ["sha512-half"], None, True),
    # --- none, explicit: crypto lives in another layer ---------------
    "server_info": ("none", "LOW", "no-change",
                    "src/xrpld/rpc/handlers/ServerInfo.cpp",
                    "sha512Half(ripple::Slice",
                    "The sha512Half call in ServerInfo.cpp computes "
                    "the definitions hash served by "
                    "server_definitions; server_info itself returns "
                    "server state and emits no hash.",
                    [], None, False),
    "connect": ("none", "LOW", "no-change",
                "src/xrpld/overlay/detail/Handshake.cpp",
                "signDigest(",
                "connect only initiates an overlay connection; the "
                "peer-handshake session signature is created in the "
                "overlay layer, not in the handler.",
                [], None, False),
    "manifest": ("none", "LOW", "no-change",
                 "src/xrpld/rpc/handlers/DoManifest.cpp",
                 "parseBase58<PublicKey>(TokenType::NodePublic, requested)",
                 "manifest is a read-only lookup of a stored validator "
                 "manifest by public key; manifest signature "
                 "verification lives in the validator-manifest layer.",
                 [], None, False),
    "simulate": ("none", "LOW", "no-change",
                 "src/xrpld/rpc/handlers/Simulate.cpp",
                 "getTxQ().apply(",
                 "simulate rejects signed input and dry-runs via "
                 "TxQ::apply; any signature verification is indirect, "
                 "inside the apply pipeline, not in the handler.",
                 [], None, False),
    "random": ("none", "LOW", "no-change",
               "src/xrpld/rpc/handlers/Random.cpp",
               "crypto_prng()",
               "random returns one CSPRNG output (beast::rngfill with "
               "crypto_prng()); it creates no key, signature, or hash.",
               [], None, False),
}

PQ_TERMS = ["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium",
            "SPHINCS", "mlkem", "mldsa", "slhdsa"]

ENTRY_RE = re.compile(
    r'\{\s*"([a-z_0-9]+)",\s*byRef\(&(\w+)\),\s*Role::(\w+),\s*'
    r'(\w+)(?:,\s*(\d+),\s*(\d+))?\s*\}')


def fail(msg):
    print(f"rpc_inventory: ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def find_token(checkout, relpath, token):
    """Return the first line number containing token, or None."""
    path = checkout / relpath
    if not path.is_file():
        return None
    lines = path.read_text(errors="replace").splitlines()
    for i, ln in enumerate(lines, 1):
        if token in ln:
            return i
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkout", default=str(DEFAULT_CHECKOUT))
    ap.add_argument("--readiness",
                    default=str(PACK_ROOT / "configs" / "readiness-table.json"))
    ap.add_argument("--out", default=str(
        PACK_ROOT / "outputs" / "derived" / "method-inventory.json"))
    ap.add_argument("--matrix-out", default=str(
        PACK_ROOT / "outputs" / "derived" / "readiness-matrix.json"))
    args = ap.parse_args()
    checkout = Path(args.checkout).expanduser()
    if not checkout.is_dir():
        fail(f"pinned checkout not found: {checkout}")
    try:
        head = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        fail(f"git rev-parse HEAD failed in {checkout}: {exc.stderr.strip()}")
    if head != COMMIT:
        fail(f"pinned checkout HEAD {head} != {COMMIT} ({checkout})")
    print(f"pinned checkout verified: {head}")

    handler_text = (checkout / HANDLER_CPP).read_text()
    handler_lines = handler_text.splitlines()

    # --- 1. handlerArray entries --------------------------------------
    methods = {}
    for m in ENTRY_RE.finditer(handler_text):
        name, func, role, cond, minv, maxv = m.groups()
        if name in methods:
            fail(f"duplicate handlerArray entry: {name}")
        start = line_of(handler_text, m.start())
        end = line_of(handler_text, m.end())
        methods[name] = {
            "method": name,
            "handler_function": func,
            "registration": {
                "file": HANDLER_CPP,
                "start_line": start,
                "end_line": end,
            },
            "role": role,
            "condition": cond,
            "min_api_version": int(minv) if minv else None,
            "max_api_version": int(maxv) if maxv else None,
            "registration_style": "handlerArray",
        }
    print(f"handlerArray entries parsed: {len(methods)}")

    # --- 2. new-style handlers ----------------------------------------
    new_style = {}
    for m in re.finditer(r"addHandler<(\w+)>\(\);", handler_text):
        cls = m.group(1)
        line = line_of(handler_text, m.start())
        new_style[cls] = line
    print(f"addHandler<> registrations: {sorted(new_style)}")
    class_files = {"LedgerHandler": "src/xrpld/rpc/handlers/LedgerHandler.h",
                   "VersionHandler": "src/xrpld/rpc/handlers/Version.h"}
    for cls, reg_line in sorted(new_style.items()):
        cfile = class_files.get(cls)
        if not cfile:
            fail(f"no known class file for {cls}")
        ctext = (checkout / cfile).read_text()
        nm = re.search(r'name\s*(?:\[\])?\s*=\s*"(\w+)"', ctext)
        rm = re.search(r"static constexpr Role role = Role::(\w+);", ctext)
        cm = re.search(r"static constexpr Condition condition = (\w+);", ctext)
        mn = re.search(r"minApiVer = ([A-Za-z0-9_:]+);", ctext)
        mx = re.search(r"maxApiVer = ([A-Za-z0-9_:]+);", ctext)
        if not (nm and rm and cm and mn and mx):
            fail(f"could not parse class constants for {cls} in {cfile}")
        name = nm.group(1)
        if name in methods:
            fail(f"duplicate method (new-style vs table): {name}")
        methods[name] = {
            "method": name,
            "handler_function": cls,
            "registration": {
                "file": HANDLER_CPP,
                "start_line": reg_line,
                "end_line": reg_line,
            },
            "role": rm.group(1),
            "condition": cm.group(1),
            "min_api_version": mn.group(1),
            "max_api_version": mx.group(1),
            "registration_style": "addHandler",
            "class_file": cfile,
            "class_name_line": line_of(ctext, nm.start()),
        }

    # --- 3. implementation files --------------------------------------
    handlers_dir = checkout / HANDLERS_DIR
    impl_index = {}  # doFunction -> (file, line)
    # Definitions live in .cpp files only; Handlers.h carries declarations
    # with the same signature shape and must not be scanned.
    for path in sorted(handlers_dir.glob("*.cpp")):
        text = path.read_text(errors="replace")
        rel = str(path.relative_to(checkout))
        for m in re.finditer(
                r"^(?:Json::Value\s+)?(do\w+)\s*\(RPC::JsonContext&",
                text, re.MULTILINE):
            func = m.group(1)
            if func in impl_index and impl_index[func][0] != rel:
                fail(f"duplicate definition of {func}: "
                     f"{impl_index[func][0]} vs {rel}")
            # Line of the function name, not the return-type line above it.
            impl_index[func] = (rel, line_of(text, m.start(1)))
    print(f"do* definitions found in {HANDLERS_DIR}: {len(impl_index)}")

    deny_res = [re.compile(p) for p in DENY_PATTERNS]
    rows = []
    for name in sorted(methods):
        row = dict(methods[name])
        func = row["handler_function"]
        if row["registration_style"] == "addHandler":
            impl_file = row["class_file"]
            impl_line = None
            ctext = (checkout / impl_file).read_text()
            cm = re.search(rf"class {func}\b", ctext)
            impl_line = line_of(ctext, cm.start()) if cm else None
        else:
            if func not in impl_index:
                fail(f"no implementation found for handler function {func} "
                     f"(method {name})")
            impl_file, impl_line = impl_index[func]
        row["implementation"] = {"file": impl_file, "line": impl_line}
        # API version range: explicit (min, max) ints, else the default
        # 1-3 (apiMinimumSupportedVersion=1 .. apiMaximumValidVersion=3,
        # ApiVersion.h:56-62).
        if isinstance(row["min_api_version"], int) and isinstance(
                row["max_api_version"], int):
            row["api_version_range"] = (
                f"{row['min_api_version']}-{row['max_api_version']}")
        else:
            row["api_version_range"] = "1-3 (default)"
        if name in RULES:
            (exposure, urgency, rec, ev_file, ev_token, why, prims,
             sig_op, hash_data) = RULES[name]
            ev_line = find_token(checkout, ev_file, ev_token)
            if ev_line is None:
                fail(f"rule evidence missing for {name}: token "
                     f"{ev_token!r} not found in {ev_file}")
            row["exposure"] = exposure
            row["urgency"] = urgency
            row["recommendation"] = rec
            row["evidence"] = {"file": ev_file, "line": ev_line,
                               "token": ev_token}
            row["rationale"] = why
            row["primitives"] = prims
            row["signature_operation"] = sig_op
            row["hash_data"] = hash_data
            row["rule"] = "explicit"
        else:
            # Guard: a default-none method must not touch crypto.
            text = (checkout / impl_file).read_text(errors="replace")
            for pat in deny_res:
                mm = pat.search(text)
                if mm:
                    fail(f"method {name} has no explicit rule but its "
                         f"implementation {impl_file} contains crypto "
                         f"token {pat.pattern!r} at line "
                         f"{line_of(text, mm.start())}")
            row["exposure"] = "none"
            row["urgency"] = "LOW"
            row["recommendation"] = "no-change"
            if row["registration_style"] == "addHandler":
                # Evidence is the name constant in the class header, not
                # the addHandler<> line (which never spells the name).
                ctext = (checkout / row["class_file"]).read_text()
                nm2 = re.search(r'name\s*(?:\[\])?\s*=\s*"(\w+)"', ctext)
                ev_file = row["class_file"]
                ev_line = line_of(ctext, nm2.start())
                ev_token = nm2.group(0)
            else:
                ev_file = row["registration"]["file"]
                ev_line = row["registration"]["start_line"]
                ev_token = f'"{name}"'
            row["evidence"] = {
                "file": ev_file,
                "line": ev_line,
                "token": ev_token,
            }
            row["rationale"] = ("No signing, key-exchange or hashing "
                                "operation in the handler implementation; "
                                "registration site only.")
            row["primitives"] = []
            row["signature_operation"] = None
            row["hash_data"] = False
            row["rule"] = "default-none"
        row["urgency_basis"] = "modelled"
        row["recommendation_basis"] = "modelled"
        rows.append(row)

    # --- 4. readiness-table cross-check -------------------------------
    readiness = json.loads(Path(args.readiness).read_text())
    if readiness.get("pinned_commit") != COMMIT:
        fail("readiness-table pinned_commit mismatch")
    families = {f["id"]: f for f in readiness["families"]}
    for row in rows:
        for prim in row["primitives"]:
            if prim not in families:
                fail(f"method {row['method']}: unknown primitive {prim!r} "
                     f"(not in readiness-table families)")
    for fam in readiness["families"]:
        for src in fam.get("sources", []):
            ln = find_token(checkout, src["file"], src["anchor"])
            if ln is None:
                fail(f"readiness family {fam['id']}: source anchor "
                     f"{src['anchor']!r} not found in {src['file']}")
            if not (src["start_line"] <= ln <= src["end_line"]):
                fail(f"readiness family {fam['id']}: anchor "
                     f"{src['anchor']!r} at line {ln} outside cited "
                     f"range {src['start_line']}-{src['end_line']} "
                     f"in {src['file']}")
            src["verified_line"] = ln
    # PQ absence: zero hits over src/ + include/.
    pq_hits = {}
    for term in PQ_TERMS:
        out = subprocess.run(
            ["grep", "-rni", "--include=*.cpp", "--include=*.h", "-l",
             term, "src", "include"],
            cwd=str(checkout), capture_output=True, text=True)
        hits = sorted(out.stdout.split()) if out.stdout.strip() else []
        pq_hits[term] = hits
    total_pq_hits = sum(len(v) for v in pq_hits.values())
    print(f"PQ term hits in src/+include/: {total_pq_hits}")
    for fam_id in ("ml-kem", "ml-dsa", "slh-dsa"):
        fam = families[fam_id]
        if fam["status"] != "not-present":
            fail(f"readiness family {fam_id}: status must be not-present")
        if total_pq_hits != 0:
            fail(f"PQ absence claim contradicted: {total_pq_hits} hits: "
                 f"{pq_hits}")

    # --- 5. gRPC surface + unregistered declarations ------------------
    grpc_text = (checkout / GRPC_H).read_text()
    grpc = []
    for m in re.finditer(r"^(do\w+Grpc)\(", grpc_text, re.MULTILINE):
        grpc.append({"method": m.group(1),
                     "file": GRPC_H,
                     "line": line_of(grpc_text, m.start())})
    grpc = sorted(grpc, key=lambda g: g["method"])
    print(f"gRPC handler declarations: {len(grpc)}")

    decl_text = (checkout / HANDLERS_H).read_text()
    declared = set(re.findall(r"^(do\w+)\(RPC::JsonContext&", decl_text,
                              re.MULTILINE))
    registered_funcs = {r["handler_function"] for r in rows
                        if r["registration_style"] == "handlerArray"}
    unregistered = []
    for func in sorted(declared - registered_funcs):
        mm = re.search(rf"^{re.escape(func)}\(RPC::JsonContext&",
                       decl_text, re.MULTILINE)
        unregistered.append({"handler_function": func,
                             "file": HANDLERS_H,
                             "line": line_of(decl_text, mm.start()) if mm else None})
    print(f"declared-but-unregistered handlers: "
          f"{[u['handler_function'] for u in unregistered]}")

    # --- 6. outputs ----------------------------------------------------
    from collections import Counter
    exp_counts = Counter(r["exposure"] for r in rows)
    urg_counts = Counter(r["urgency"] for r in rows)
    rec_counts = Counter(r["recommendation"] for r in rows)
    role_counts = Counter(r["role"] for r in rows)

    inventory = {
        "pack": "Post-Quantum RPC and API Readiness Assessment",
        "pinned_commit": COMMIT,
        "source": "parsed from the pinned postfiatd source tree; no live "
                  "node was run and no RPC call was made",
        "handler_table": HANDLER_CPP,
        "method_count": len(rows),
        "methods": rows,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=1, sort_keys=True)
        fh.write("\n")

    matrix = {
        "pack": "Post-Quantum RPC and API Readiness Assessment",
        "pinned_commit": COMMIT,
        "method_count": len(rows),
        "exposure_counts": {k: exp_counts.get(k, 0)
                            for k in ("signing", "key-exchange",
                                      "hashing", "none")},
        "urgency_counts": {k: urg_counts.get(k, 0)
                           for k in ("HIGH", "MEDIUM", "LOW")},
        "recommendation_counts": {k: rec_counts.get(k, 0)
                                  for k in ("hybrid", "pq-only",
                                            "no-change")},
        "role_counts": dict(sorted(role_counts.items())),
        "explicit_rule_methods": sorted(RULES),
        "default_none_methods": sorted(
            r["method"] for r in rows if r["rule"] == "default-none"),
        "signing_methods": sorted(
            r["method"] for r in rows if r["exposure"] == "signing"),
        "key_exchange_methods": sorted(
            r["method"] for r in rows if r["exposure"] == "key-exchange"),
        "hashing_methods": sorted(
            r["method"] for r in rows if r["exposure"] == "hashing"),
        "high_urgency_methods": sorted(
            r["method"] for r in rows if r["urgency"] == "HIGH"),
        "hash_data_methods": sorted(
            r["method"] for r in rows if r.get("hash_data")),
        "signature_create_methods": sorted(
            r["method"] for r in rows
            if r.get("signature_operation") in ("create", "create+verify")),
        "signature_verify_methods": sorted(
            r["method"] for r in rows
            if r.get("signature_operation") in ("verify", "create+verify")),
        "grpc_methods": grpc,
        "grpc_method_count": len(grpc),
        "unregistered_declared_handlers": unregistered,
        "pq_absence": {"terms_checked": PQ_TERMS,
                       "total_file_hits": total_pq_hits,
                       "scope": ["src", "include"]},
        "readiness_families": sorted(families),
    }
    matrix_path = Path(args.matrix_out)
    matrix_path.parent.mkdir(parents=True, exist_ok=True)
    with open(matrix_path, "w", encoding="utf-8") as fh:
        json.dump(matrix, fh, indent=1, sort_keys=True)
        fh.write("\n")
    def _disp(p):
        try:
            return str(p.relative_to(PACK_ROOT))
        except ValueError:
            return str(p)

    print(f"wrote {_disp(out_path)} ({len(rows)} methods)")
    print(f"wrote {_disp(matrix_path)}")
    print(f"exposure: {dict(exp_counts)} urgency: {dict(urg_counts)} "
          f"recommendation: {dict(rec_counts)}")


if __name__ == "__main__":
    main()
