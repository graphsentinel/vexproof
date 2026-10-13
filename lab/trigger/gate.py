#!/usr/bin/env python3
"""Exercise-layer gate file: the pre-registered "all N runs give affected_evidence" decision for one OSV and one
shipped artifact, recomputed from the counted runs (private plan "exercise layer" §4 row 1, §6; review l5-r17).

The gate file binds the decision to: the OSV, the shipped binary's sha256 (from the spec and from every run), the
frozen spec / runner / attribution sha256 recorded at pre-registration, and the sha256 of every evidence file of every
counted run. lab/autochain.py --exercise reads it, re-checks the binding and never promotes on a gate that is missing,
malformed, mismatched or failed.

usage: gate.py --spec SPEC.yaml --frozen spec=HEX,runner=HEX,attribution=HEX --n 5 --out GATE.json [--root DIR] RUN_DIR...
       gate.py --check GATE.json [--binary SHIPPED_BINARY] [--osv OSV] [--root DIR]   (exit 0 = valid and passed)
The frozen runner/attribution hashes are recorded from the pre-registration; runs made before resolved.json carried
them cannot be re-verified against those files (recorded, not checked).
"""
import argparse
import hashlib
import json
import os
import sys

import yaml

EVIDENCE = ("status.json", "results.tsv", "resolved.json", "e2a-perf.data")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def failing(status):
    """the named conditions that did not hold in one run"""
    out = []
    for r in status.get("oracle") or []:
        out += [f"{','.join(r['arms'])}: {c['check']}" for c in r["checks"] if not c["ok"]]
    e = status.get("e2a") or {}
    out += [f"e2a: {k}" for k, v in (e.get("checks") or {}).items() if not v]
    out += [f"harness: {h.get('error')} ({h.get('arm')})" for h in status.get("harness_errors") or []]
    out += [f"arm unavailable: {a}" for a in status.get("arms_unavailable") or []]
    return out


def build(spec_path, frozen, n, runs, root="."):
    doc = yaml.safe_load(open(spec_path))
    spec = doc["spec"]
    want = spec["target"]["binary"]["sha256"]
    rec, digests, seen = [], set(), set()
    for d in runs:
        missing = [f for f in EVIDENCE if not os.path.exists(os.path.join(d, f))]
        if missing:
            raise SystemExit(f"{d}: incomplete run, missing {missing}")
        files = {f: sha256(os.path.join(d, f)) for f in EVIDENCE}
        if files["status.json"] in seen:
            raise SystemExit(f"{d}: the same run counted twice")
        seen.add(files["status.json"])
        st = json.load(open(os.path.join(d, "status.json")))["status"]
        if "row1" not in st or "e2a" not in st:
            raise SystemExit(f"{d}: not an exercise-layer run (no row1/e2a)")
        digests.add(st["resolved"]["shipped_sha256"])
        for k in ("spec", "runner", "attribution"):  # runs that record their provenance must match the frozen hashes
            got = st["resolved"].get(f"{k}_sha256")
            if got and frozen.get(k) and not got.startswith(frozen[k]):
                raise SystemExit(f"{d}: {k} {got[:8]} is not the frozen {frozen[k]}")
        rec.append({"run": os.path.basename(os.path.normpath(d)), "path": os.path.relpath(d, root),
                    "row1": st["row1"]["result"],
                    "failing": failing(st), "files": files})
    if digests != {want}:
        raise SystemExit(f"shipped binary differs from the spec in the runs: {sorted(digests)} vs {want}")
    actual = {"spec": sha256(spec_path)}
    if frozen.get("spec") and not actual["spec"].startswith(frozen["spec"]):
        raise SystemExit(f"spec {spec_path} is not the frozen one ({frozen['spec']})")
    if n < 1:
        raise SystemExit("--n must be a positive, pre-registered number of runs")
    passed = len(rec) == n and all(r["row1"] == "affected_evidence" for r in rec)
    return {"osv": spec["vulnerability"]["osv"], "n": n, "spec_sha256": actual["spec"],
            "spec_path": os.path.relpath(spec_path, root), "target": spec["target"]["source"]["mainPackage"].rstrip("/").rsplit("/", 1)[-1],
            "release": spec["target"]["source"]["ref"], "shipped_sha256": want,
            "spec": spec_path, "frozen_sha256": frozen, "gate": f"all {n} counted runs give affected_evidence",
            "counted_runs": len(rec), "result": "passed" if passed else "failed",
            "affected_evidence_runs": sum(r["row1"] == "affected_evidence" for r in rec), "runs": rec}


def check(gate, binary=None, osv=None, root="."):
    """re-validate a gate file against the evidence itself; returns (ok, reason). Checks: the gate is for this OSV and
    this binary; N is positive and the counters agree; the spec file still has the frozen hash; every counted run's
    evidence files exist and still have their recorded sha256; each run's row-1 result is re-read from its status.json;
    no run is counted twice; the recorded result equals the result recomputed from the runs."""
    try:
        g = json.load(open(gate))
        n, runs = int(g["n"]), g["runs"]
        if osv is not None and g["osv"] != osv:
            return False, f"gate is for another OSV ({g['osv']})"
        if binary is not None and sha256(binary) != g["shipped_sha256"]:
            return False, "gate is for another binary"
        if n < 1 or g["counted_runs"] != len(runs):
            return False, "inconsistent counters"
        if sha256(os.path.join(root, g["spec_path"])) != g["spec_sha256"]:
            return False, "spec changed since the gate was built"
        if len({r["files"]["status.json"] for r in runs}) != len(runs):
            return False, "a run is counted twice"
        rows = []
        for r in runs:
            if set(r["files"]) != set(EVIDENCE):  # the complete manifest: no file can be left out of the checks
                return False, f"incomplete evidence manifest: {r['path']}"
            for f, h in r["files"].items():
                fp = os.path.join(root, r["path"], f)
                if not os.path.exists(fp):
                    return False, f"evidence missing: {r['path']}/{f}"
                if sha256(fp) != h:
                    return False, f"evidence changed: {r['path']}/{f}"
            st = json.load(open(os.path.join(root, r["path"], "status.json")))["status"]
            if st["row1"]["result"] != r["row1"] or st["resolved"]["shipped_sha256"] != g["shipped_sha256"]:
                return False, f"recorded run does not match its evidence: {r['path']}"
            rows.append(st["row1"]["result"])
        recomputed = len(rows) == n and all(x == "affected_evidence" for x in rows)
        if g["affected_evidence_runs"] != sum(x == "affected_evidence" for x in rows):
            return False, "inconsistent counters"
        if ("passed" if recomputed else "failed") != g["result"]:
            return False, "recorded result does not match the runs"
        if g["result"] != "passed":
            return False, "gate failed: " + "; ".join(sorted({f for r in runs for f in r["failing"]}))
        return True, f"gate passed ({len(rows)}/{n})"
    except (OSError, ValueError, KeyError, TypeError, IndexError) as ex:
        return False, f"malformed gate file: {type(ex).__name__}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec")
    ap.add_argument("--frozen", default="")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--out")
    ap.add_argument("--check")
    ap.add_argument("--binary")
    ap.add_argument("--osv")
    ap.add_argument("--root", default=".", help="directory the run and spec paths are relative to")
    ap.add_argument("runs", nargs="*")
    A = ap.parse_args()
    if A.check:
        ok, why = check(A.check, A.binary, A.osv, A.root)
        print(why)
        return 0 if ok else 1
    frozen = dict(kv.split("=", 1) for kv in A.frozen.split(",") if kv)
    g = build(A.spec, frozen, A.n, A.runs, A.root)
    os.makedirs(os.path.dirname(os.path.abspath(A.out)), exist_ok=True)
    json.dump(g, open(A.out, "w"), indent=1)
    print(f"{g['osv']} {g['target']} {g['release']}: {g['result']} ({g['affected_evidence_runs']}/{g['counted_runs']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
