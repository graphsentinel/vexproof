#!/usr/bin/env python3
"""Collect every evidence chain into results/decisions.tsv, next to the maintainers' ground truth (where one exists).

The ground-truth table below is the only hand-entered data; each row cites the issue it comes from. A chain matches
when its status equals the ground-truth status (justification is reported, not compared: maintainers rarely state one).

usage: decisions.py  (run from the project root)
"""
import csv
import glob
import json
import os

# (release, target, osv) -> (status, justification the maintainers gave or implied, or "", source)
# Only explicit maintainer decisions count. GO-2025-3595 on kube-apiserver was dropped after the V7 review: an x/net bump
# with no not_affected claim is not a decision that the component is affected (see NO_DECISION).
GROUND_TRUTH = {
    ("v1.28.2", "kube-apiserver", "GO-2023-2102"): ("affected", "", "k/k #121120, #121201 (rapid reset fix in the API server)"),
    ("v1.28.2", "kube-apiserver", "GO-2024-3333"): ("not_affected", "vulnerable_code_not_in_execute_path",
                                                    "k/k #129347 (dims: govulncheck shows not affected)"),
    ("v1.28.2", "kube-apiserver", "GO-2024-3321"): ("not_affected", "vulnerable_code_not_present",
                                                    "k/k #129164 (only a test suite uses x/crypto/ssh)"),
    ("v1.28.2", "kubectl", "GO-2024-3333"): ("not_affected", "vulnerable_code_not_in_execute_path", "k/k #129347"),
    ("v1.36.5", "kubelet", "GO-2026-5426"): ("not_affected", "vulnerable_code_not_present",
                                             "k/k #138329 (dims: BSD/Solaris only, not shipped)"),
    ("v1.36.5", "kube-apiserver", "GO-2026-5426"): ("not_affected", "vulnerable_code_not_present", "k/k #138329"),
}
NO_DECISION = {
    ("v1.28.2", "kube-apiserver", "GO-2025-3595"): "k/k #131128 / #131103: x/net bumped; no statement either way",
}

SOURCES = [  # (chains dir, release, run label)
    ("results/chains-v1.28.2", "v1.28.2", "lab"),
    ("results/chains-v1.36.5", "v1.36.5", "shipped"),
] + [(d, "metrics-server-v0.9.0", os.path.basename(d).replace("chains-ci-", "c6-ci-")) for d in sorted(glob.glob("results/chains-ci-metrics-server-v0.9.0-r*"))]


def main():
    out = open("results/decisions.tsv", "w")
    cols = ["release", "run", "target", "osv", "aliases", "L1", "L3", "L4_hit", "P_present", "taint", "status",
            "justification", "gt_status", "gt_justification", "gt_source", "match", "match_justification"]
    w = csv.DictWriter(out, fieldnames=cols, delimiter="\t")
    w.writeheader()
    for d, rel, run in SOURCES:
        for f in sorted(glob.glob(f"{d}/*--*.json")):
            c = json.load(open(f))
            gt = GROUND_TRUTH.get((rel, c["target"], c["osv"]))
            pres = c.get("shipped_binary_symbols_present")
            taint = c.get("taint_paths")
            w.writerow({
                "release": rel, "run": run, "target": c["target"], "osv": c["osv"], "aliases": c.get("aliases", ""),
                "L1": c.get("L1_scanner"), "L3": c.get("L3_level"),
                "L4_hit": (c.get("L4a_coverage") or {}).get("hit"),
                "P_present": len(pres) if isinstance(pres, list) else "n/a",
                "taint": (len(taint) if isinstance(taint, list) else ("rule" if c.get("taint_by_rule") else "n/a")),
                "status": c["vex_status"], "justification": c.get("vex_justification") or "",
                "gt_status": gt[0] if gt else "", "gt_justification": gt[1] if gt else "",
                "gt_source": gt[2] if gt else NO_DECISION.get((rel, c["target"], c["osv"]), ""),
                "match": ("yes" if gt[0] == c["vex_status"] else "no") if gt else "",
                "match_justification": ("yes" if gt[1] == (c.get("vex_justification") or "") else "no")
                if gt and gt[1] else "",
            })
    out.close()
    rows = list(csv.DictReader(open("results/decisions.tsv"), delimiter="\t"))
    g = [r for r in rows if r["gt_status"]]
    j = [r for r in g if r["gt_justification"]]
    print(f"{len(rows)} decisions, {len(g)} with ground truth, {sum(r['match'] == 'yes' for r in g)} status match, "
          f"{sum(r['match_justification'] == 'yes' for r in j)}/{len(j)} justification match")


if __name__ == "__main__":
    main()
