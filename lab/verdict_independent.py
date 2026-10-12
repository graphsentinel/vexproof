#!/usr/bin/env python3
"""V4: independent L4 verdict from `go tool cover -func` output (Go's own parser), without symcov.py's regex ranges.

Input: the per-function report produced inside the target's module, `go tool cover -func=cov.txt > func.txt`,
plus the govulncheck JSON (for the OSV symbols). A symbol is executed if its function has coverage > 0%.
`go tool cover -func` drops method receivers, so with --src the declaration line of each OSV symbol (receiver included)
is located in the source and matched by file:line; without --src the match is by bare name (client and server methods
of the same name merge: the V4 61/62 miss).

usage: verdict_independent.py --func func.txt --govulncheck G.json --osv ID[,ID] [--measurements M.tsv --target T]
       prints one row per (OSV, package): executed / not-observed / not-instrumented, and, if --measurements is
       given, compares with symcov's L4 column for the same rows.
"""
import argparse
import csv
import json
import os
import re


def stream(path):
    raw, dec, i = open(path).read(), json.JSONDecoder(), 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return
        o, i = dec.raw_decode(raw, i)
        yield o


LINE = re.compile(r"^(?P<file>\S+?):(?P<line>\d+):\s+(?P<func>\S+)\s+(?P<pct>[\d.]+)%$")


def decl_lines(src, pkg, sym):
    """{(file, line)} where symbol "Recv.Name" or "Name" is declared in the package source (non-test files)"""
    recv, _, name = sym.rpartition(".")
    pat = re.compile(r"^func \([^)]*?\*?" + re.escape(recv) + r"(\[[^\]]*\])?\) " + re.escape(name) + r"[\[(]" if recv
                     else r"^func " + re.escape(name) + r"[\[(]")
    d, out = os.path.join(src, pkg), set()
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if f.endswith(".go") and not f.endswith("_test.go"):
            for i, line in enumerate(open(os.path.join(d, f)), 1):
                if pat.match(line):
                    out.add((f"{pkg}/{f}", i))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--func", required=True)
    ap.add_argument("--govulncheck", required=True)
    ap.add_argument("--osv", required=True)
    ap.add_argument("--measurements")
    ap.add_argument("--target")
    ap.add_argument("--src", help="vendor root: match symbols by declaration file:line (receiver-aware)")
    A = ap.parse_args()
    # go tool cover -func names methods without receivers ("ServeConn"), so key by (package dir, func name)
    cov: dict[tuple[str, str], float] = {}
    at: dict[tuple[str, int], float] = {}
    pkgs = set()
    for line in open(A.func):
        m = LINE.match(line.strip())
        if not m:
            continue
        pkg = m.group("file").rsplit("/", 1)[0]
        pkgs.add(pkg)
        key = (pkg, m.group("func"))
        cov[key] = max(cov.get(key, 0.0), float(m.group("pct")))
        at[(m.group("file"), int(m.group("line")))] = float(m.group("pct"))
    osv = {o["osv"]["id"]: o["osv"] for o in stream(A.govulncheck) if "osv" in o}
    mine = {}
    unresolved = []
    for oid in A.osv.split(","):
        for a in osv[oid]["affected"]:
            if a["package"]["name"] == "stdlib":
                continue
            for imp in a.get("ecosystem_specific", {}).get("imports", []):
                pkg = imp["path"]
                if pkg not in pkgs:
                    v = "not-instrumented"
                else:
                    if A.src:
                        locs = set()
                        for s in imp.get("symbols", []):
                            found = decl_lines(A.src, pkg, s)
                            if not found:
                                unresolved.append(f"{pkg}.{s}")
                            locs |= found
                        hit = any(at.get(loc, 0.0) > 0 for loc in locs)
                    else:
                        hit = any(cov.get((pkg, s.split(".")[-1]), 0.0) > 0 for s in imp.get("symbols", []))
                    v = "executed" if hit else "not-observed"
                mine[(oid, pkg)] = v
                print(f"{oid}\t{pkg}\t{v}")
    if A.src:
        print(f"unresolved symbols (no declaration found): {len(unresolved)} {' '.join(unresolved)}".rstrip())
    if A.measurements:
        agree = disagree = 0
        for r in csv.DictReader(open(A.measurements), delimiter="\t"):
            if A.target and r["target"] != A.target:
                continue
            k = (r["osv"], r["package"])
            if k not in mine:
                continue
            theirs = r["L4"] if r["L4"] in ("executed", "not-observed") else "not-instrumented"
            if theirs == "not-linked":
                theirs = "not-instrumented"
            if theirs == mine[k]:
                agree += 1
            else:
                disagree += 1
                print(f"DISAGREE {k}: symcov={r['L4']} independent={mine[k]}")
        print(f"agreement: {agree}/{agree + disagree}")


if __name__ == "__main__":
    main()
