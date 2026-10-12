#!/usr/bin/env python3
"""Compare the runs of scripts/lab.sh test with lab/expected.tsv.

Fails (exit 1) when the plan is not complete, a planned step is missing or exited non-zero, an expected row is missing
or different in any run, or a run produced a row the table does not expect. Writes a Markdown summary.

usage: summary.py --plan lab/.runtime/plan.json --results results --expected lab/expected.tsv --out lab/.runtime/summary.md
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make_expected as me  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--out", required=True)
    A = ap.parse_args()
    plan = json.load(open(A.plan))
    expected = {(r["kind"], r["key"]): r["expected"] for r in csv.DictReader(open(A.expected), delimiter="\t")}
    problems, lines = [], []
    if plan.get("complete") != 1:
        problems.append("the test plan is not complete (interrupted run)")
    lines.append(f"# vexproof lab: {plan['runs']} fast-path run(s){' + FULL' if plan.get('full') else ''}\n")
    lines.append("| run | steps ok | rows as expected | different | missing | unexpected |")
    lines.append("|---|---|---|---|---|---|")
    for i in range(1, plan["runs"] + 1):
        d = os.path.join(A.results, f"run-{i}")
        steps = {}
        f = os.path.join(d, "steps.tsv")
        if os.path.exists(f):
            for ln in open(f):
                s, rc, _ = ln.rstrip("\n").split("\t")
                steps[s] = int(rc)
        bad_steps = [s for s in plan["steps"] if steps.get(s) != 0]
        for s in bad_steps:
            problems.append(f"run {i}: step {s} " + ("missing" if s not in steps else f"exit {steps[s]}"))
        got = {(k, key): v for k, key, v in me.rows(d)} if os.path.isdir(d) else {}
        same = [k for k in expected if got.get(k) == expected[k]]
        diff = [k for k in expected if k in got and got[k] != expected[k]]
        miss = [k for k in expected if k not in got]
        extra = [k for k in got if k not in expected]
        for k in diff[:20]:
            problems.append(f"run {i}: {k[0]} {k[1]}: expected {expected[k]}, got {got[k]}")
        for k in miss[:20]:
            problems.append(f"run {i}: {k[0]} {k[1]}: missing")
        for k in extra[:20]:
            problems.append(f"run {i}: {k[0]} {k[1]}: not in the expected table ({got[k]})")
        lines.append(f"| {i} | {len(plan['steps']) - len(bad_steps)}/{len(plan['steps'])} | {len(same)}/{len(expected)} "
                     f"| {len(diff)} | {len(miss)} | {len(extra)} |")
    if plan.get("full"):
        f = os.path.join(A.results, "full", "steps.tsv")
        rc = open(f).read().split("\t")[1] if os.path.exists(f) else None
        lines.append(f"\nFULL=1: {'exit ' + rc if rc is not None else 'missing'} (results/full/)")
        if rc != "0":
            problems.append("FULL=1: " + (f"exit {rc}" if rc is not None else "missing"))
        fs = os.path.join(A.results, "full", "summary.json")
        if os.path.exists(fs):
            for c in json.load(open(fs)).get("checks", []):
                lines.append(f"- {'ok' if c['ok'] else 'FAIL'} {c['check']}: {c['observed']}")
                if not c["ok"]:
                    problems.append(f"FULL=1: {c['check']}")
    lines.append("\n" + ("**Result: OK**" if not problems else f"**Result: FAIL** ({len(problems)} problem(s))"))
    lines += [f"- {p}" for p in problems[:60]]
    text = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(os.path.abspath(A.out)), exist_ok=True)
    open(A.out, "w").write(text)
    print(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
