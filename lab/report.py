#!/usr/bin/env python3
"""Per-target triage report: every vulnerability the tools report, grouped by how strong the evidence is.

For each (release, target) it joins govulncheck (all findings, not only the chained ones), Trivy and the evidence
chains, and puts each vulnerability in exactly one group:

  affected            evidence chain: executed + untrusted input (CodeQL path or entry-point rule)
  not_affected        evidence chain: vulnerable code absent from the shipped binary, or every package measured and
                      unreachable
  under_investigation evidence chain: not enough evidence either way (reason in the note)
  static_reachable    no chain yet; govulncheck finds a call path to a vulnerable symbol
  static_not_reached  no chain yet; govulncheck: module or package present, vulnerable symbol not reached
  scanner_only        Trivy lists it, govulncheck reports nothing (other database, or a symbol-less entry)

Only the first three are VEX decisions. The last three are what the tools say before any evidence chain was built.

Writes results/report/index.json, one small JSON file per target, and results/report/vex-report.html.
usage: report.py   (run from the project root)
"""
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain import stream  # noqa: E402

# Every source scan runs with the shipped binary's own Go version and build tags (from its buildinfo); Trivy and the
# automatic chains look at the official binary. The earlier scans with another Go version or without the tags are kept
# as evidence of that trap (evidence/c0-*, c4-*, c6-*).
C9 = "evidence/c9-autochain-"
TARGETS = [  # release, target, govulncheck, (trivy file, trivy target) or None, chains dirs, note
    ("v1.28.2", "kube-apiserver", f"{C9}v1.28.2/govulncheck-source-matched-kube-apiserver.json",
     (f"{C9}v1.28.2/trivy-official.json", "kube-apiserver"), ["results/chains-v1.28.2", "results/chains-auto/v1.28.2/kube-apiserver"],
     "official binary (go1.20.8, tags selinux,notest); hand-built chains: coverage rebuild, uprobes, CodeQL"),
    ("v1.28.2", "kubectl", f"{C9}v1.28.2/govulncheck-source-matched-kubectl.json",
     (f"{C9}v1.28.2/trivy-official.json", "kubectl"), ["results/chains-v1.28.2", "results/chains-auto/v1.28.2/kubectl"],
     "official binary (go1.20.8, tags selinux,notest); hand-built chains: coverage rebuild"),
    ("v1.36.5", "kube-apiserver", f"{C9}v1.36.5/govulncheck-source-matched-kube-apiserver.json",
     (f"{C9}v1.36.5/trivy-official.json", "kube-apiserver"), ["results/chains-v1.36.5", "results/chains-auto/v1.36.5/kube-apiserver"],
     "official binary (go1.26.8, tags selinux,notest,grpcnotrace); static layers only"),
    ("v1.36.5", "kubelet", f"{C9}v1.36.5/govulncheck-source-matched-kubelet.json",
     (f"{C9}v1.36.5/trivy-official.json", "kubelet"), ["results/chains-v1.36.5", "results/chains-auto/v1.36.5/kubelet"],
     "official binary (go1.26.8, tags selinux,notest,grpcnotrace); static layers only"),
    ("v1.36.5", "kubectl", f"{C9}v1.36.5/govulncheck-source-matched-kubectl.json",
     (f"{C9}v1.36.5/trivy-official.json", "kubectl"), ["results/chains-auto/v1.36.5/kubectl"],
     "official binary (go1.26.8, tags selinux,notest,grpcnotrace); static layers only"),
    ("metrics-server v0.9.0", "metrics-server", f"{C9}metrics-server-v0.9.0/govulncheck-source-matched-metrics-server.json",
     (f"{C9}metrics-server-v0.9.0/trivy-official.json", "metrics-server"),
     ["results/chains-ci-metrics-server-v0.9.0-r1", "results/chains-auto/metrics-server-v0.9.0/metrics-server"],
     "official image binary (go1.26.4); hand-built chains: CI recipe in k3d, run r1 of 5 (same statuses in all 5)"),
]

GROUPS = [
    ("affected", "Affected", "Evidence chain: the vulnerable code ran and takes untrusted input."),
    ("not_affected", "Not affected", "Evidence chain: the vulnerable code is absent from the shipped binary, or "
                                     "every vulnerable package was measured and the code is unreachable."),
    ("candidate", "Affected candidate", "Vulnerable code executed under the workload and a CodeQL path from received "
                                        "input reaches it; awaiting or needing a human review (still under_investigation "
                                        "in OpenVEX)."),
    ("under_investigation", "Under investigation", "Evidence chain built, evidence not sufficient either way."),
    ("static_reachable", "Reachable, not chained", "govulncheck finds a call path to a vulnerable symbol. "
                                                   "No evidence chain yet: needs investigation."),
    ("static_not_reached", "Not reached, not chained", "govulncheck: the module or package is in the build, the "
                                                       "vulnerable symbol is not reached. A static hint, not a VEX decision."),
    ("scanner_only", "Scanner only", "Trivy lists it, govulncheck reports nothing for it."),
]
RANK = {"module": 1, "package": 2, "symbol": 3}
SEV_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEV_FILE = "evidence/c10-severity/index.json"  # lab/severity_fetch.py (GitHub Advisory Database)
SEV = json.load(open(SEV_FILE)) if os.path.exists(SEV_FILE) else {}
CQ_DIR = "evidence/c11-codeql-batch"  # lab/codeql/sinkgen/batch.py output, one dir per <release>--<target>


COARSE = 10  # more reached symbols than this: a sink on "any argument" is trivially reached (HTTP entry points)


def codeql_results(release, target):
    """{osv: {"llm": index row, "all": index row, "symbols": n}} from the two batch runs, if present"""
    base = os.path.join(CQ_DIR, f"{release.replace(' ', '-')}--{target}")
    out = {}
    for key, d in (("llm", base), ("all", base + "-all-args")):
        f = os.path.join(d, "index.json")
        if not os.path.exists(f):
            continue
        for x in json.load(open(f))["results"]:
            out.setdefault(x["osv"], {})[key] = x
            rf = os.path.join(d, x["osv"], "result.json")
            if os.path.exists(rf):
                n = sum(len(p.get("symbols", [])) for p in json.load(open(rf)).get("packages", {}).values())
                out[x["osv"]]["symbols"] = n
    return out


def one(x):
    if not x:
        return None
    if not x.get("compiled"):
        return "no query"
    if x.get("taint_results"):
        return f"path ({x['taint_results']})"
    if x.get("sink_sites_outside_pkg"):
        return f"no path, {x['sink_sites_outside_pkg']} sink sites"
    return "no sink sites"


def codeql_label(c):
    """CodeQL outcome for the table: LLM-proposed sinks and the all-arguments baseline. A path is a lead for
    review, never a VEX decision by itself; with coarse OSV symbols the baseline is not informative."""
    if not c:
        return "not run"
    parts = []
    if one(c.get("llm")):
        parts.append(f"LLM sinks: {one(c['llm'])}")
    if one(c.get("all")):
        parts.append(f"all args: {one(c['all'])}")
    if c.get("symbols", 0) > COARSE:
        parts.append(f"coarse: {c['symbols']} reached symbols, not informative")
    return "; ".join(parts) or "not run"


def severity(oid, trivy_sev):
    """(level, cvss, source): GitHub advisory first, Trivy second"""
    g = SEV.get(oid) or {}
    if g.get("severity") and g["severity"] != "unknown":
        return g["severity"], g.get("cvss_v3"), "GitHub"
    if trivy_sev and trivy_sev.upper() != "UNKNOWN":
        return trivy_sev.lower(), None, "Trivy"
    return "unknown", None, ""


def fixed(osv):
    out = set()
    for a in osv.get("affected", []):
        for r in a.get("ranges", []):
            out |= {e["fixed"] for e in r.get("events", []) if "fixed" in e}
    return sorted(out)


def collect(release, target, gv, trivy, chains_dir, note):
    osvs, level, gv_go = {}, {}, None
    for o in stream(gv):
        if "config" in o:
            gv_go = o["config"].get("go_version")
        if "osv" in o:
            osvs[o["osv"]["id"]] = o["osv"]
        f = o.get("finding")
        if f:
            top = (f.get("trace") or [{}])[0]
            lv = "symbol" if top.get("function") else ("package" if top.get("package") else "module")
            if RANK[lv] > RANK.get(level.get(f["osv"], ""), 0):
                level[f["osv"]] = lv
    tv = {}
    if trivy:
        for r in json.load(open(trivy[0])).get("Results", []):
            if r["Target"] == trivy[1]:
                for v in r.get("Vulnerabilities") or []:
                    tv.setdefault(v["VulnerabilityID"], v)
    chains = {}
    dirs = [chains_dir] if isinstance(chains_dir, str) else list(chains_dir or [])
    for d in dirs:
        if not os.path.exists(os.path.join(d, "index.json")):
            continue
        for e in json.load(open(os.path.join(d, "index.json"))):
            if e["target"] == target and e["osv"] in chains:
                continue  # a hand-built chain wins over an automatic one
            if e["target"] == target:
                chains[e["osv"]] = json.load(open(os.path.join(d, e["file"])))
                chains[e["osv"]]["_file"] = os.path.join(d, e["file"])
    cq = codeql_results(release, target)
    rows, seen_trivy = [], set()
    for oid in sorted(level):
        o = osvs.get(oid, {})
        ids = {oid, *o.get("aliases", [])}
        in_trivy = sorted(ids & set(tv))
        seen_trivy |= set(in_trivy)
        mod = (o.get("affected") or [{}])[0].get("package", {}).get("name", "")
        c = chains.get(oid)
        if c:
            group = c["vex_status"]
            if group == "under_investigation" and (c.get("runtime") or {}).get("affected_candidate"):
                group = "candidate"
        else:
            group = "static_reachable" if level[oid] == "symbol" else "static_not_reached"
        rows.append({
            "osv": oid, "cve": [a for a in o.get("aliases", []) if a.startswith("CVE-")],
            "summary": o.get("summary", ""), "module": mod, "fixed": fixed(o),
            "trivy": ("yes" if in_trivy else "no") if trivy else "not run",
            "severity": tv[in_trivy[0]].get("Severity", "") if in_trivy else "",
            **dict(zip(("sev", "cvss", "sev_source"), severity(oid, tv[in_trivy[0]].get("Severity", "") if in_trivy else ""))),
            "govulncheck": level[oid], "group": group,
            "justification": (c or {}).get("vex_justification") or "", "auto": bool((c or {}).get("auto")),
            "note": (c or {}).get("status_note") or "",
            "substate": ((c.get("substate") or "hand_built_chain") if c and c["vex_status"] == "under_investigation" else ""),
            "chain": (c or {}).get("_file", ""),
            "codeql": codeql_label(cq.get(oid)),
        })
    for vid, v in sorted(tv.items()):
        if vid in seen_trivy or any(vid in r["cve"] for r in rows):
            continue
        rows.append({"osv": "", "cve": [vid], "summary": v.get("Title", ""), "module": v.get("PkgName", ""),
                     "fixed": [v.get("FixedVersion", "")] if v.get("FixedVersion") else [], "trivy": "yes",
                     "severity": v.get("Severity", ""), "govulncheck": "none", "group": "scanner_only",
                     **dict(zip(("sev", "cvss", "sev_source"), severity("", v.get("Severity", "")))),
                     "justification": "", "note": "", "substate": "", "chain": "", "codeql": "not run"})
    counts = {g: sum(r["group"] == g for r in rows) for g, _, _ in GROUPS}
    subs = {}
    for x in rows:
        if x["group"] == "under_investigation":
            subs[x["substate"]] = subs.get(x["substate"], 0) + 1
    by_sev = {g: {v: sum(r["group"] == g and r["sev"] == v for r in rows) for v in SEV_ORDER} for g, _, _ in GROUPS}
    built_go = next((v.get("InstalledVersion") for v in tv.values() if v.get("PkgName") == "stdlib"), None)
    warning = None
    if built_go and gv_go and built_go.lstrip("v") != gv_go.lstrip("go"):
        warning = (f"govulncheck ran in source mode with {gv_go}; the binary was built with Go {built_go.lstrip('v')}. "
                   f"Source mode checks the scanner's own standard library, so standard-library entries for the shipped "
                   f"Go version show up only in Trivy (\"scanner only\").")
    return {"release": release, "target": target, "note": note, "govulncheck_file": gv,
            "trivy_file": trivy[0] if trivy else None,
            "chains_dir": ", ".join(dirs) or None, "govulncheck_go": gv_go,
            "binary_go": built_go, "warning": warning, "counts": counts, "by_severity": by_sev,
            "substates": subs, "rows": rows}


PAGE_CSS = """
/* layout: one column; a summary matrix (target x group), then one section per target with its table */
:root {
  --bg: #f6f7f9; --panel: #ffffff; --fg: #1b2330; --muted: #5b6676; --line: #dfe3ea; --accent: #2f5bd3;
  --red: #b42318; --red-bg: #fde8e6; --green: #157a3c; --green-bg: #e3f4ea; --amber: #a15c00; --amber-bg: #fdf0d9;
  --grey: #5b6676; --grey-bg: #eceff3; --violet: #6b3fb8; --violet-bg: #efe8fb;
  --sans: "IBM Plex Sans", system-ui, sans-serif; --mono: "IBM Plex Mono", ui-monospace, monospace;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg: #11151c; --panel: #171c25; --fg: #e4e8ef; --muted: #9aa5b5; --line: #2a3240; --accent: #7d9cff;
  --red: #ff8a7a; --red-bg: #3a1d1a; --green: #6fd394; --green-bg: #15301f; --amber: #f2b45a; --amber-bg: #352711;
  --grey: #a3adbb; --grey-bg: #222936; --violet: #b99bf0; --violet-bg: #2a2140; color-scheme: dark } }
:root[data-theme="dark"] {
  --bg: #11151c; --panel: #171c25; --fg: #e4e8ef; --muted: #9aa5b5; --line: #2a3240; --accent: #7d9cff;
  --red: #ff8a7a; --red-bg: #3a1d1a; --green: #6fd394; --green-bg: #15301f; --amber: #f2b45a; --amber-bg: #352711;
  --grey: #a3adbb; --grey-bg: #222936; --violet: #b99bf0; --violet-bg: #2a2140; color-scheme: dark }
body { background: var(--bg); color: var(--fg); font: 14px/1.5 var(--sans); }
main { max-width: 1180px; margin: 0 auto; padding-inline: 16px; padding-block: 28px 56px; display: grid; gap: 28px; }
h1 { font-size: 24px; margin: 0; text-wrap: balance; }
h2 { font-size: 18px; margin: 0; text-wrap: balance; }
p { margin: 0; max-width: 72ch; }
.muted { color: var(--muted); }
.mono { font-family: var(--mono); font-size: 12.5px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; display: grid; gap: 12px; min-width: 0; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
td.n { text-align: right; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.g-affected { color: var(--red); background: var(--red-bg); }
.g-not_affected { color: var(--green); background: var(--green-bg); }
.g-under_investigation { color: var(--amber); background: var(--amber-bg); }
.g-candidate { color: var(--red); background: var(--amber-bg); }
.g-static_reachable { color: var(--violet); background: var(--violet-bg); }
.g-static_not_reached, .g-scanner_only { color: var(--grey); background: var(--grey-bg); }
.zero { color: var(--muted); opacity: .5; }
td.cq-path { color: var(--violet); font-weight: 600; }
.s-critical { color: var(--panel); background: var(--red); }
.s-high { color: var(--red); background: var(--red-bg); }
.s-medium { color: var(--amber); background: var(--amber-bg); }
.s-low, .s-unknown { color: var(--grey); background: var(--grey-bg); }
.legend { display: grid; gap: 6px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
.legend div { display: grid; gap: 2px; }
.filters { display: flex; flex-wrap: wrap; gap: 6px; }
.filters button { font: inherit; font-size: 12px; border: 1px solid var(--line); background: var(--panel); color: var(--fg);
  border-radius: 999px; padding: 2px 10px; cursor: pointer; }
.filters button[aria-pressed="true"] { border-color: var(--accent); color: var(--accent); }
.filters button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.sum { color: var(--muted); font-size: 12.5px; }
a { color: var(--accent); }
.warn { border-left: 3px solid var(--amber); background: var(--amber-bg); padding: 6px 10px; border-radius: 4px; }
"""


def render(reports, generated):
    e = html.escape
    out = ["<title>vexproof Triage</title><link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?"
           "family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap\">",
           f"<style>{PAGE_CSS}</style><main>",
           "<header style=\"display:grid;gap:6px\"><h1>vexproof triage report</h1>",
           f"<p class=\"muted\">Every vulnerability govulncheck or Trivy reports per binary, grouped by the strength of the "
           f"evidence. Only the first three groups are VEX decisions (evidence chain built). Generated {e(generated)} "
           f"by <span class=\"mono\">lab/report.py</span>.</p></header>"]
    out.append("<section class=\"panel\"><h2>Summary</h2><div class=\"scroll\"><table><tr><th>Release</th><th>Binary</th>")
    out += [f"<th><span class=\"pill g-{g}\">{e(t)}</span></th>" for g, t, _ in GROUPS]
    out.append("<th>Total</th></tr>")
    for r in reports:
        anchor = f"{r['release']}-{r['target']}".replace(" ", "-").replace(".", "-")
        out.append(f"<tr><td>{e(r['release'])}</td><td><a href=\"#{anchor}\">{e(r['target'])}</a></td>")
        out += [f"<td class=\"n{' zero' if not r['counts'][g] else ''}\">{r['counts'][g]}</td>" for g, _, _ in GROUPS]
        out.append(f"<td class=\"n\">{len(r['rows'])}</td></tr>")
    out.append("</table></div>")
    out.append("<h2>Open findings by severity</h2><p class=\"sum\">Affected and under investigation, by GitHub advisory "
               "severity (Trivy where GitHub has none). Highest first: this is the work queue.</p>"
               "<div class=\"scroll\"><table><tr><th>Release</th><th>Binary</th><th>Group</th>")
    out += [f"<th><span class=\"pill s-{v}\">{v}</span></th>" for v in SEV_ORDER]
    out.append("</tr>")
    for r in reports:
        for g in ("affected", "candidate", "under_investigation"):
            if not r["counts"][g]:
                continue
            title = dict((a, t) for a, t, _ in GROUPS)[g]
            out.append(f"<tr><td>{e(r['release'])}</td><td>{e(r['target'])}</td><td><span class=\"pill g-{g}\">{e(title)}</span></td>")
            out += [f"<td class=\"n{' zero' if not r['by_severity'][g][v] else ''}\">{r['by_severity'][g][v]}</td>" for v in SEV_ORDER]
            out.append("</tr>")
    out.append("</table></div>")
    names = sorted({k for r in reports for k in r["substates"]})
    if names:
        out.append("<h2>Under investigation by sub-state</h2><p class=\"sum\">What is missing, per chain (the first "
                   "that holds: not measured, not observed under the workload, observed without a demonstrated input "
                   "path, ...). The label is the first part of each reason below.</p><div class=\"scroll\"><table>"
                   "<tr><th>Release</th><th>Binary</th>" + "".join(f"<th class=\"mono\">{e(k)}</th>" for k in names)
                   + "</tr>")
        for r in reports:
            if r["substates"]:
                out.append(f"<tr><td>{e(r['release'])}</td><td>{e(r['target'])}</td>" + "".join(
                    f"<td class=\"n{' zero' if not r['substates'].get(k) else ''}\">{r['substates'].get(k, 0)}</td>"
                    for k in names) + "</tr>")
        out.append("</table></div>")
    out.append("<div class=\"legend\">")
    out += [f"<div><span><span class=\"pill g-{g}\">{e(t)}</span></span><span class=\"sum\">{e(d)}</span></div>"
            for g, t, d in GROUPS]
    out.append("</div></section>")
    for r in reports:
        anchor = f"{r['release']}-{r['target']}".replace(" ", "-").replace(".", "-")
        out.append(f"<section class=\"panel\" id=\"{anchor}\"><h2>{e(r['target'])} <span class=\"muted\">{e(r['release'])}</span></h2>"
                   f"<p class=\"sum\">{e(r['note'])}. Sources: <span class=\"mono\">{e(r['govulncheck_file'])}</span>"
                   f"{', <span class=mono>' + e(r['trivy_file']) + '</span>' if r['trivy_file'] else ''}"
                   f"{', <span class=mono>' + e(r['chains_dir']) + '</span>' if r['chains_dir'] else ''}.</p>")
        if r["warning"]:
            out.append(f"<p class=\"warn\">{e(r['warning'])}</p>")
        out.append("<div class=\"filters\" role=\"group\" aria-label=\"Filter by group\">"
                   "<button type=\"button\" data-g=\"all\" aria-pressed=\"true\">All</button>")
        out += [f"<button type=\"button\" data-g=\"{g}\" aria-pressed=\"false\">{e(t)} ({r['counts'][g]})</button>"
                for g, t, _ in GROUPS if r["counts"][g]]
        out.append("</div><div class=\"scroll\"><table><tr><th>Group</th><th>OSV / CVE</th><th>Module</th>"
                   "<th>Severity</th><th>Summary</th><th>Fixed in</th><th>Trivy</th><th>govulncheck</th><th>CodeQL</th><th>Reason</th></tr>")
        order = {g: i for i, (g, _, _) in enumerate(GROUPS)}
        for x in sorted(r["rows"], key=lambda x: (order[x["group"]], SEV_ORDER.index(x["sev"]), -(x["cvss"] or 0),
                                                  x["osv"] or x["cve"][0])):
            title = dict((g, t) for g, t, _ in GROUPS)[x["group"]]
            ident = (f"<a class=\"mono\" href=\"https://pkg.go.dev/vuln/{e(x['osv'])}\">{e(x['osv'])}</a><br>" if x["osv"] else "")
            ident += f"<span class=\"mono muted\">{e(', '.join(x['cve']))}</span>"
            reason = x["justification"] or ""
            if x["note"]:
                reason = (reason + "; " if reason else "") + x["note"]
            if x["chain"]:
                kind = "automatic static chain" if x.get("auto") else "evidence chain"
                reason += f"<br><span class=\"mono muted\">{kind}: {e(x['chain'])}</span>"
            out.append(f"<tr data-g=\"{x['group']}\"><td><span class=\"pill g-{x['group']}\">{e(title)}</span></td>"
                       f"<td>{ident}</td><td class=\"mono\">{e(x['module'])}</td>"
                       f"<td><span class=\"pill s-{x['sev']}\">{e(x['sev'])}</span>"
                       f"{'<br><span class=\"mono muted\">CVSS ' + str(x['cvss']) + '</span>' if x['cvss'] else ''}"
                       f"{'<br><span class=\"muted sum\">' + e(x['sev_source']) + '</span>' if x['sev_source'] else ''}</td>"
                       f"<td>{e(x['summary'])}</td>"
                       f"<td class=\"mono\">{e(', '.join(x['fixed']))}</td><td>{e(x['trivy'])}</td><td>{e(x['govulncheck'])}</td>"
                       f"<td{' class=\"cq-path\"' if 'path (' in x['codeql'] and 'coarse' not in x['codeql'] else ''}>{e(x['codeql'])}</td>"
                       f"<td>{reason}</td></tr>")
        out.append("</table></div></section>")
    out.append("""</main><script>
document.querySelectorAll('.filters').forEach(function (bar) {
  var rows = bar.parentElement.querySelectorAll('tr[data-g]');
  bar.addEventListener('click', function (ev) {
    var b = ev.target.closest('button'); if (!b) return;
    bar.querySelectorAll('button').forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
    rows.forEach(function (tr) { tr.hidden = b.dataset.g !== 'all' && tr.dataset.g !== b.dataset.g; });
  });
});
</script>""")
    return "".join(out)


def main():
    import datetime
    os.makedirs("results/report", exist_ok=True)
    reports, index = [], []
    for t in TARGETS:
        r = collect(*t)
        reports.append(r)
        name = f"{r['release'].replace(' ', '-')}--{r['target']}.json"
        json.dump(r, open(os.path.join("results/report", name), "w"), indent=1)
        index.append({"file": name, "release": r["release"], "target": r["target"], "counts": r["counts"],
                      "under_investigation_substates": r["substates"]})
        print(f"{r['release']:22} {r['target']:15} " + " ".join(f"{g}={n}" for g, n in r["counts"].items()))
    json.dump(index, open("results/report/index.json", "w"), indent=1)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    open("results/report/vex-report.html", "w").write(render(reports, now))


if __name__ == "__main__":
    main()
