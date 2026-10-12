#!/usr/bin/env python3
"""Write lab/expected.tsv from one results directory (a run of scripts/lab.sh test, or the measured results).

  make_expected.py RESULTS_DIR > lab/expected.tsv

Rows: kind, key, expected value.
  chain     <chains dir>/<target>/<OSV>       status|justification   hand-configured evidence chains
  auto      <release>/<target>/<OSV>          status|justification   automatic static chains
  report    <release>/<target>                group counts           lab/report.py
  decisions ground-truth                      matched/total          lab/decisions.py
  trigger   GO-2026-6609/shipped              verdict                lab/trigger/runner.py (smoke spec)
"""
import csv
import glob
import json
import os
import sys


def rows(res):
    out = []
    for f in sorted(glob.glob(os.path.join(res, "chains-*", "index.json"))):
        d = os.path.basename(os.path.dirname(f))
        for x in json.load(open(f)):
            out.append(("chain", f"{d}/{x['target']}/{x['osv']}", f"{x['status']}|{x['justification'] or ''}"))
    for f in sorted(glob.glob(os.path.join(res, "chains-auto", "*", "*", "index.json"))):
        rel = os.path.relpath(os.path.dirname(f), os.path.join(res, "chains-auto"))
        for x in json.load(open(f)):
            out.append(("auto", f"{rel}/{x['osv']}", f"{x['status']}|{x['justification'] or ''}"))
    f = os.path.join(res, "report", "index.json")
    if os.path.exists(f):
        for x in json.load(open(f)):
            out.append(("report", f"{x['release'].replace(' ', '-')}/{x['target']}",
                        " ".join(f"{k}={v}" for k, v in x["counts"].items())))
    f = os.path.join(res, "decisions.tsv")
    if os.path.exists(f):
        gt = [r for r in csv.DictReader(open(f), delimiter="\t") if r.get("gt_status")]
        out.append(("decisions", "ground-truth", f"{sum(r['match'] == 'yes' for r in gt)}/{len(gt)}"))
    f = os.path.join(res, "trigger-smoke", "status.json")
    if os.path.exists(f):
        out.append(("trigger", "GO-2026-6609/shipped", json.load(open(f))["status"]["verdict"]))
    return out


def main():
    print("kind\tkey\texpected")
    for r in sorted(rows(sys.argv[1])):
        print("\t".join(r))


if __name__ == "__main__":
    main()
