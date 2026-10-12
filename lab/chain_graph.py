#!/usr/bin/env python3
"""Render one evidence chain (results/chains/<target>--<osv>.json) as Graphviz DOT.

Lanes, left to right: entry point -> project code -> dependency -> vulnerable symbol -> VEX status.
Evidence boxes hang under the edge they support: taint path (CodeQL), coverage (rebuild), uprobe hits (shipped binary),
presence in the shipped binary. Missing evidence is drawn dashed, so the reader sees what was *not* shown.

usage: chain_graph.py <chain.json> > out.dot
"""
import json
import sys

STATUS_COLOR = {"affected": "#b91c1c", "not_affected": "#15803d", "under_investigation": "#b45309"}


def short(f):
    f = f.replace("golang.org/x/net/", "x/net/").replace("k8s.io/apimachinery/pkg/util/", "apimachinery/")
    return f.replace("k8s.io/", "")


def esc(s):
    return s.replace('"', '\\"')


def main():
    c = json.load(open(sys.argv[1]))
    path = c.get("L3_call_path") or []
    # keep the entry, the frames of the project and its direct dependency, and the symbol
    keep = []
    if path:
        keep.append(path[0])
        keep += [fr for fr in path[1:-1] if any(k in (fr["func"] or "") for k in ("proxy", "apiserver", "kubectl/pkg/cmd", "http2.(*Server)"))][-3:]
        keep.append(path[-1])
    out = ['digraph chain {', ' rankdir=LR; node [shape=box, style="rounded,filled", fillcolor="#f8fafc", fontname="Helvetica", fontsize=10];',
           ' edge [fontname="Helvetica", fontsize=9];',
           f' labelloc=t; label="{esc(c["target"])} · {esc(c["osv"])} ({esc(c["aliases"].split(",")[0])})";']
    prev = None
    for i, fr in enumerate(keep):
        nid = f"n{i}"
        color = "#fee2e2" if i == len(keep) - 1 else ("#e0f2fe" if i == 0 else "#f8fafc")
        out.append(f' {nid} [label="{esc(short(fr["func"] or (fr.get("package") or "?") + " (package)"))}\\n{esc(fr["pos"])}", fillcolor="{color}"];')
        if prev and i > 1:  # the n0 -> n1 edge is drawn below with its label
            out.append(f' {prev} -> {nid} [color="#64748b"];')
        prev = nid
    if keep:
        out.append(' n0 -> n1 [label="govulncheck example path\\n(one of possibly many)", fontcolor="#64748b", color="#64748b"];' if len(keep) > 1 else "")
    if c.get("runtime_entry") and keep:
        out.append(f' rt [label="{esc(c["runtime_entry"])}", fillcolor="#dcfce7"];')
        out.append(f' rt -> n{len(keep) - 1} [style=bold, color="#15803d", label="observed at runtime"];')
    if not keep:
        out.append(f' n0 [label="no symbol-level path\\n(govulncheck: {esc(c["L3_level"])})", style="rounded,dashed"];')
        prev = "n0"
    st = c["vex_status"] + (f"\\n{c['vex_justification']}" if c.get("vex_justification") else "")
    out.append(f' vex [label="OpenVEX: {esc(st)}", shape=box, style="filled", fontcolor="white", fillcolor="{STATUS_COLOR.get(c["vex_status"], "#475569")}"];')
    out.append(f" {prev} -> vex [style=bold];")
    ev = []
    t = c.get("taint_paths")
    if isinstance(t, list) and t:
        ev.append(("taint", f"CodeQL taint: {len(t)} path(s)\\n{esc(t[0][0]['pos'])} → {esc(t[0][-1]['pos'])}", "solid"))
    elif c.get("taint_by_rule"):
        ev.append(("taint", "untrusted input by rule:\\nnetwork listener entry", "solid"))
    else:
        ev.append(("taint", "taint: " + ("no path" if t == [] else "not run"), "dashed"))
    cov = c.get("L4a_coverage") or {}
    if str(cov.get("blocks", "-")) in ("-", "", "None"):
        ev.append(("cov", "coverage (rebuild): not run", "dashed"))
    else:
        ev.append(("cov", f"coverage (rebuild): {cov.get('hit')}/{cov.get('blocks')} blocks", "solid" if str(cov.get("hit", "0")) not in ("0", "", "-", "None") else "dashed"))
    up = c.get("L4b_uprobes")
    if isinstance(up, dict) and up:
        ev.append(("up", "uprobes (shipped binary):\\n" + "\\n".join(f"{k.replace('vxb_', '')}: {v}" for k, v in up.items()), "solid" if any(up.values()) else "dashed"))
    pres = c.get("shipped_binary_symbols_present")
    if isinstance(pres, list):
        ev.append(("pres", f"vulnerable code in shipped binary: {len(pres)} of {c.get('symbols_checked', '?')} checked" + ("" if pres else "\\n(dead-code eliminated)"), "solid"))
    ev.append(("l1", f"scanner (Trivy) flags it: {c.get('L1_scanner')}", "solid"))
    out.append(" subgraph cluster_ev { label=\"evidence\"; style=dashed; color=\"#94a3b8\";")
    for k, label, style in ev:
        out.append(f'  ev_{k} [label="{label}", shape=note, style="filled,{style}", fillcolor="#fffbeb"];')
    out.append(" }")
    for k, _, _ in ev:
        out.append(f" ev_{k} -> vex [style=dotted, arrowhead=none];")
    if c.get("ground_truth"):
        out.append(f' gt [label="ground truth:\\n{esc(c["ground_truth"])}", shape=plaintext];')
        out.append(" vex -> gt [style=invis];")
    out.append("}")
    print("\n".join(out))


if __name__ == "__main__":
    sys.exit(main())
