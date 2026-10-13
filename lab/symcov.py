#!/usr/bin/env python3
"""Map OSV vulnerable symbols to Go coverage blocks and emit one verdict row per (target, OSV).

Layers per the measurement contract:
  L1  Trivy on the binary (module present)
  L3  govulncheck source mode: deepest level reached (module / package / symbol)
  L4  coverage of the vulnerable symbols' function bodies in the running target (positive evidence only)

usage: symcov.py --target NAME --govulncheck G.json --trivy T.json --trivy-target BIN --cov COV.txt --goos GOOS
                 --src VENDOR_ROOT --osv GO-2023-2102,... [--linked PKG,...] > rows.tsv
"""
import argparse
import json
import os
import re
import sys


def read_stream(path):
    raw, dec, i, out = open(path).read(), json.JSONDecoder(), 0, []
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            break
        obj, i = dec.raw_decode(raw, i)
        out.append(obj)
    return out


def govulncheck(path):
    objs = read_stream(path)
    osv = {o["osv"]["id"]: o["osv"] for o in objs if "osv" in o}
    level: dict[str, str] = {}
    rank = {"module": 1, "package": 2, "symbol": 3}
    for o in objs:
        f = o.get("finding")
        if not f:
            continue
        top = (f.get("trace") or [{}])[0]
        lv = "symbol" if top.get("function") else "package" if top.get("package") else "module"
        if rank[lv] > rank.get(level.get(f["osv"], ""), 0):
            level[f["osv"]] = lv
    return osv, level


def trivy_ids(path, target):
    d = json.load(open(path))
    for r in d.get("Results", []):
        if os.path.basename(r.get("Target", "")) == target:
            return {v["VulnerabilityID"] for v in r.get("Vulnerabilities") or []}
    return set()


def coverage(path):
    """file -> list of (startline, endline, hits)"""
    blocks: dict[str, list[tuple[int, int, int]]] = {}
    for line in open(path):
        if line.startswith("mode:"):
            continue
        f, rest = line.rsplit(":", 1)
        rng, _, cnt = rest.split()
        a, b = rng.split(",")
        blocks.setdefault(f, []).append((int(a.split(".")[0]), int(b.split(".")[0]), int(cnt)))
    return blocks


FUNC = re.compile(r"^func (?:\((?:\w+ )?\*?(\w+)(?:\[[^\]]*\])?\) )?(\w+)\(")


def func_ranges(pkg_dir):
    """symbol ('Recv.Name' or 'Name') -> (file basename, start, end) for every func in the package dir"""
    out: dict[str, tuple[str, int, int]] = {}
    if not os.path.isdir(pkg_dir):
        return out
    for fn in sorted(os.listdir(pkg_dir)):
        if not fn.endswith(".go") or fn.endswith("_test.go"):
            continue
        lines = open(os.path.join(pkg_dir, fn)).read().split("\n")
        for i, ln in enumerate(lines):
            m = FUNC.match(ln)
            if not m:
                continue
            end = next((j for j in range(i, len(lines)) if lines[j] == "}"), i)
            out[f"{m.group(1)}.{m.group(2)}" if m.group(1) else m.group(2)] = (fn, i + 1, end + 1)
    return out


def main():
    ap = argparse.ArgumentParser()
    for a in ("--target", "--govulncheck", "--trivy", "--trivy-target", "--cov", "--src", "--osv"):
        ap.add_argument(a, required=True)
    ap.add_argument("--linked", default="", help="comma list of instrumented packages (to tell 'not linked' apart)")
    ap.add_argument("--goroot", help="GOROOT/src of the build's Go version: measure stdlib entries too (skipped without)")
    ap.add_argument("--goos", required=True,
                    help="the build's GOOS (required): an OSV import restricted to other GOOS values gives no row (its "
                         "code is not compiled for this build; a same-named function of another file is not it)")
    A = ap.parse_args()
    osv, level = govulncheck(A.govulncheck)
    tids = trivy_ids(A.trivy, A.trivy_target)
    cov = coverage(A.cov)
    linked = set(filter(None, A.linked.split(",")))
    print("target\tosv\taliases\tL1_trivy\tL3_level\tpackage\tsymbols\tsym_found\tblocks\tblocks_hit\tL4\tverdict")
    for oid in A.osv.split(","):
        o = osv.get(oid)
        if not o:
            # govulncheck reported nothing for this OSV: the module is not in the build at a vulnerable version
            print(f"{A.target}\t{oid}\t-\t{'yes' if oid in tids else 'no'}\tnone\t-\t-\t-\t-\t-\tabsent\tABSENT")
            continue
        aliases = ",".join(o.get("aliases", []))
        l1 = "yes" if (tids & set(o.get("aliases", [])) or oid in tids) else "no"
        l3 = level.get(oid, "none")
        for aff in o.get("affected", []):
            if aff["package"]["name"] == "stdlib" and not A.goroot:
                continue  # stdlib judged by the scanner's own Go version in source mode; handled separately
            root = A.goroot if aff["package"]["name"] == "stdlib" else A.src
            for imp in aff.get("ecosystem_specific", {}).get("imports", []):
                if imp.get("goos") and A.goos not in imp["goos"]:
                    continue
                pkg, syms = imp["path"], imp.get("symbols", [])
                ranges = func_ranges(os.path.join(root, pkg))
                total = hit = found = 0
                for s in syms:
                    r = ranges.get(s)
                    if not r:
                        continue
                    found += 1
                    fn, a, b = r
                    for blk in cov.get(f"{pkg}/{fn}", []):
                        if a <= blk[0] <= b:
                            total += 1
                            hit += blk[2] > 0
                in_cov = any(k.startswith(pkg + "/") for k in cov)
                if not in_cov:
                    l4 = "not-linked" if pkg in linked else "not-instrumented"
                else:
                    l4 = "executed" if hit else "not-observed"
                if l4 == "executed":
                    verdict = "CONTRADICTION" if l3 in ("module", "package", "none") else "EXECUTED"
                elif l3 == "symbol":
                    verdict = "REACHABLE-NOT-OBSERVED"
                elif l4 in ("not-observed", "not-linked"):
                    verdict = "NOT-REACHABLE-STATIC"
                else:
                    verdict = "UNKNOWN"
                print(f"{A.target}\t{oid}\t{aliases}\t{l1}\t{l3}\t{pkg}\t{len(syms)}\t{found}\t{total}\t{hit}\t{l4}\t{verdict}")


if __name__ == "__main__":
    sys.exit(main())
