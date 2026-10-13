#!/usr/bin/env python3
"""Automatic static chains for findings that have none yet: no rebuild, no runtime, shipped binary only.

For every OSV that govulncheck (source mode) reaches at symbol level and that has no hand-built chain, it checks:
  P    are the OSV's vulnerable symbols in the shipped binary? (full .gopclntab listing from lab/pclnsym "~")
  L3b  does govulncheck in binary mode (the shipped binary's own symbols, Go version and build tags) still report it
       at symbol level?
  R    raw-name check: does the qualified name of any OSV symbol occur anywhere in the binary? Go keeps the names of
       inlined functions in .gopclntab's name table for tracebacks, so a name that occurs nowhere was neither linked
       nor inlined. Positive control: names of listed functions of the same package are found the same way.
  GOOS the OSV entry's goos restriction vs. the binary's GOOS from buildinfo.
Status (fails closed, DEC-12):
  not_affected / vulnerable_code_not_present  only if every OSV import lists its symbols, every OSV symbol is
                                              missing from the full listing (names compared with pclntab's "%2e"
                                              escape read as "."), another function of the same package or module
                                              is present (positive control), none of the symbol names occurs
                                              anywhere in the binary in either spelling (R), and the raw-name check
                                              finds the control's own name (positive control for R). If binary mode
                                              reports the OSV at symbol level, the note records it as a scanner
                                              false positive (the name is not in the binary).
  not_affected / vulnerable_code_not_present  if every OSV import is restricted to GOOS values the binary was not
                                              built for (the "build GOOS=" line of go version -m), no affected
                                              module lacks an import list, and binary mode does not report the OSV
  under_investigation                          otherwise, with the reason. Static layers alone never give affected.
With --cov (symcov rows from a coverage run) and --codeql (lab/codeql/sinkgen/batch.py output), after the rules above:
  Coverage rows count only in a package the OSV names; a contradictory or unknown row (L4 label vs. hit count)
  gives under_investigation, and so does execution in the rebuild of code the shipped-binary check calls absent.
  candidate            the OSV's vulnerable code executed under the workload AND a CodeQL path from input the program
                       receives (source kind "request") reaches a sink of a reached symbol, in a package of the shipped
                       binary, with specific (not coarse) symbols. Status stays under_investigation with
                       "affected_candidate": true. CodeQL's source model is too coarse to decide alone (client-side
                       request objects, response buffers and trigger mismatches all looked like hits on kube-apiserver).
  affected             a candidate that a review file (--reviews DIR/<OSV>.json, verdict "confirmed") confirms;
                       "rejected" keeps under_investigation with the reason; "plausible" stays a candidate.
  under_investigation  executed but the path comes only from an HTTP response the program requested (trust
                       boundary), or the symbols are coarse, or there is no path; or not executed (the note says which)

usage: autochain.py --report results/report/<rel>--<target>.json --pclnsym ALL.txt --govulncheck-binary G.json
                    --out DIR --purl PURL
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain import count, govulncheck_paths, inventory_names, row_state, stream, strip_generics  # noqa: E402


def norm(fn):
    """golang.org/x/net/http2.(*Server).ServeConn -> golang.org/x/net/http2.Server.ServeConn (generics dropped)"""
    return strip_generics(fn).replace("(*", "").replace(")", "")


def binary_levels(path):
    """strongest govulncheck level per OSV (symbol > package > module), independent of stream order"""
    rank = {"module": 0, "package": 1, "symbol": 2}
    lv = {}
    for o in stream(path):
        f = o.get("finding")
        if f:
            tr = f.get("trace") or [{}]
            x = ("symbol" if any(fr.get("function") for fr in tr)
                 else "package" if any(fr.get("package") for fr in tr) else "module")
            if rank[x] > rank.get(lv.get(f["osv"]), -1):
                lv[f["osv"]] = x
    return lv


# under_investigation sub-states (private plan "exercise layer" §5): orthogonal dimensions, one headline label.
# Values within one dimension are mutually exclusive. Phase 0 derives them from the existing layers; the exercise layer
# (entry attribution, differential triggers) fills instrumentation, execution attribution and trigger later.
HEADLINE_ORDER = ("contradictory_rows", "layers_disagree", "instrumentation_failed", "not_measured", "inconclusive",
                  "trigger_not_validated", "arm_unavailable", "mitigated_by_configuration",
                  "shipped_not_triggered_cause_unknown", "candidate_awaiting_review", "rejected",
                  "observed_upstream_input_only", "attribution_incomplete", "observed_no_input_path_demonstrated",
                  "observed_input_path_not_analysed",
                  "not_observed", "osv_without_symbols", "symbols_too_coarse", "symbols_missing_possibly_inlined",
                  "no_positive_control", "trigger_class_unsupported")


def headline(d):
    """the first predicate of HEADLINE_ORDER that holds for the dimensions d"""
    holds = {
        "contradictory_rows": d["consistency"] == "contradictory_rows",
        "layers_disagree": d["consistency"] == "layers_disagree",
        "instrumentation_failed": d["instrumentation"] == "instrumentation_failed",
        "not_measured": d["measurement"] == "not_measured",
        "candidate_awaiting_review": d["review"] == "candidate_awaiting_review",
        "rejected": d["review"] == "rejected",
        "observed_upstream_input_only": d["execution"] == "observed" and d["input_path"] == "upstream_only",
        "attribution_incomplete": d["execution"] == "attribution_incomplete",
        "observed_no_input_path_demonstrated": d["execution"] == "observed" and d["input_path"] == "no_input_path_demonstrated",
        "observed_input_path_not_analysed": d["execution"] == "observed" and d["input_path"] == "not_run",
        "not_observed": d["execution"].startswith("not_observed"),
        **{k: d["trigger"] == k for k in ("inconclusive", "trigger_not_validated", "arm_unavailable",
                                          "mitigated_by_configuration", "shipped_not_triggered_cause_unknown",
                                          "trigger_class_unsupported")},
        **{k: k in d["data"] for k in ("osv_without_symbols", "symbols_too_coarse", "symbols_missing_possibly_inlined",
                                       "no_positive_control")},
    }
    return next((k for k in HEADLINE_ORDER if holds[k]), "unclassified")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--pclnsym", required=True)
    ap.add_argument("--govulncheck-binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--purl", required=True)
    ap.add_argument("--binary", required=True, help="the shipped binary (raw-name check)")
    ap.add_argument("--buildinfo", required=True, help="go version -m output (GOOS)")
    ap.add_argument("--cov", help="symcov rows (measurements TSV) from a coverage run of this target")
    ap.add_argument("--codeql", help="batch.py output dir (all-args mode) for this target")
    ap.add_argument("--coarse", type=int, default=10, help="more reached symbols than this: CodeQL sinks too coarse")
    ap.add_argument("--reviews", help="dir of <OSV>.json review files (verdict confirmed / plausible / rejected)")
    ap.add_argument("--profile", default="lab-workload", help="name of the workload profile behind --cov")
    A = ap.parse_args()
    rep = json.load(open(A.report))
    if not (isinstance(rep, dict) and isinstance(rep.get("rows"), list) and rep.get("target") and rep.get("govulncheck_file")):
        raise SystemExit(f"{A.report}: not a lab/report.py report (target, govulncheck_file, rows)")
    listed = sorted(n.removeprefix("vendor/") for n in inventory_names([A.pclnsym]))  # pclntab spelling
    funcs = {norm(n.replace("%2e", ".")) for n in listed}
    osvs = {}  # every record of an OSV counts: affected entries are merged, never overwritten
    for o in stream(rep["govulncheck_file"]):
        if "osv" in o:
            x = osvs.setdefault(o["osv"]["id"], {**o["osv"], "affected": []})
            x["affected"] = x["affected"] + list(o["osv"].get("affected", []))
    blv = binary_levels(A.govulncheck_binary)
    raw = open(A.binary, "rb").read()
    goos_lines = [m.group(1) for ln in open(A.buildinfo) if (m := re.fullmatch(r"\s*build\s+GOOS=(\S+)\s*", ln))]
    goos = goos_lines[0] if len(set(goos_lines)) == 1 else None

    def escaped(pkg):
        """pclntab spelling of an import path: dots in the last element become %2e (gopkg.in/yaml.v3 -> yaml%2ev3)"""
        head, sep, tail = pkg.rpartition("/")
        return head + sep + tail.replace(".", "%2e")

    tails = {}

    def after(prefix):
        """the bytes that follow every occurrence of prefix in the binary, each up to the next NUL (cached): a name
        "<prefix><rest>" occurs in the binary iff one of them starts with rest (names contain no NUL)"""
        if prefix not in tails:
            pre, out, i = prefix.encode(), [], raw.find(prefix.encode())
            while i != -1:
                j = i + len(pre)
                k = raw.find(b"\x00", j)
                out.append(raw[j:k if k != -1 else len(raw)])
                i = raw.find(pre, i + 1)
            tails[prefix] = out
        return tails[prefix]

    def in_binary(pkg, sym):
        """does any pclntab spelling of an OSV symbol occur in the binary bytes? T.M -> pkg.(*T).M, pkg.T.M and the
        generic instantiations pkg.(*T[...]).M, pkg.T[...].M; F -> pkg.F; path plain and with %2e"""
        recv, _, name = sym.rpartition(".")
        for p in {pkg, escaped(pkg)}:
            for t in after(p + "."):
                if not recv:
                    if t.startswith(sym.encode()):
                        return True
                    continue
                if t.startswith(f"(*{recv}).{name}".encode()) or t.startswith(f"{recv}.{name}".encode()):
                    return True
                for pre in (f"(*{recv}[", f"{recv}["):
                    if t.startswith(pre.encode()) and re.match(re.escape(pre.encode()) + rb"[^\x00]*?\]\)?\."
                                                              + re.escape(name.encode()) + rb"(?![A-Za-z0-9_])", t):
                        return True
        return False
    os.makedirs(A.out, exist_ok=True)
    cov_rows = {}
    if A.cov:
        import csv
        for row in csv.DictReader(open(A.cov), delimiter="\t"):
            if row.get("target") == rep["target"]:
                cov_rows.setdefault(row["osv"], []).append(row)
    cq = {}
    if A.codeql and os.path.exists(os.path.join(A.codeql, "index.json")):
        for x in json.load(open(os.path.join(A.codeql, "index.json")))["results"]:
            rf = os.path.join(A.codeql, x["osv"], "result.json")
            r = json.load(open(rf)) if os.path.exists(rf) else {}
            x["symbols"] = sum(len(p.get("symbols", [])) for p in r.get("packages", {}).values()) if r else None
            x["main_sinks"] = r.get("sinks_main_module", 0)
            cq[x["osv"]] = x
    index, statements = [], []
    for r in rep["rows"]:
        if r["group"] != "static_reachable" and not r.get("auto"):
            continue
        o = osvs[r["osv"]]
        checked, present, in_raw, goos_lists, no_symbols, no_imports = [], [], [], [], [], []
        modules = set()
        for a in o.get("affected", []):
            mod = a["package"]["name"]
            modules.add(mod)
            if not a.get("ecosystem_specific", {}).get("imports"):
                no_imports.append(mod)  # an affected module without imports: the whole module, any GOOS
                no_symbols.append(mod)
            for imp in a.get("ecosystem_specific", {}).get("imports", []):
                goos_lists.append(imp.get("goos"))
                if not imp.get("symbols"):
                    no_symbols.append(imp["path"])
                for s in imp.get("symbols", []):
                    if in_binary(imp["path"], s):
                        in_raw.append(f"{imp['path']}.{s}")
                    full = norm(f"{imp['path']}.{s}")
                    checked.append(full)
                    if full in funcs:
                        present.append(full)
        # positive control: functions of the same import packages (stdlib) or the same module, found in the listing
        pkgs = {imp["path"] for a in o.get("affected", []) for imp in a.get("ecosystem_specific", {}).get("imports", [])}
        # matched in pclntab spelling, so "m/p.evil.G" (package m/p%2eevil) is not a function of package m/p
        control = [n for n in listed if any(n.startswith(escaped(p) + ".") for p in pkgs)][:3]
        if not control and "stdlib" not in modules:
            control = [n for n in listed if any(n.startswith(m + "/") or n.startswith(escaped(m) + ".") for m in modules)][:3]
        # positive control for the raw-name check: the control's own pclntab name occurs in the binary bytes
        raw_control = any(n.encode() in raw for n in control)
        b = blv.get(r["osv"], "not reported")
        other_os = bool(goos_lists) and goos is not None and all(g and goos not in g for g in goos_lists)
        if other_os and b == "not reported" and not no_imports:
            status, just = "not_affected", "vulnerable_code_not_present"
            note = (f"OSV applies only to GOOS {sorted({x for g in goos_lists for x in g})}; the binary is GOOS={goos} "
                    f"(buildinfo); binary-mode govulncheck: {b}")
        elif checked and not present and control and not in_raw and raw_control and not no_symbols:
            status, just = "not_affected", "vulnerable_code_not_present"
            note = (f"none of {len(checked)} OSV symbols in the shipped binary, and none of their names occurs anywhere "
                    f"in it (so not inlined either); binary-mode govulncheck: {b}"
                    + (" (a false positive: it reports a symbol whose name is not in the binary)" if b == "symbol" else ""))
        elif not checked:
            status, just, note = "under_investigation", None, "OSV entry lists no symbols"
        elif no_symbols and not present:
            status, just = "under_investigation", None
            note = f"OSV imports without a symbol list ({', '.join(sorted(no_symbols))}): absence of the listed symbols does not cover them"
        elif control and not present and not in_raw and not raw_control:
            status, just = "under_investigation", None
            note = "raw-name check has no positive control (the control's name is not found in the binary bytes)"
        elif not present:
            status, just = "under_investigation", None
            note = (f"OSV symbols missing from the listing, but binary-mode govulncheck reports {b}: possibly inlined"
                    if b == "symbol" else "OSV symbols missing, no same-module function found as control")
        else:
            status, just = "under_investigation", None
            note = (f"{len(present)} of {len(checked)} OSV symbols are in the shipped binary; static path exists; "
                    f"binary-mode govulncheck: {b}; no runtime or taint evidence (static layers only)")
        data = []
        if not checked or no_symbols:
            data.append("osv_without_symbols")
        if checked and not present and b == "symbol" and status == "under_investigation":
            data.append("symbols_missing_possibly_inlined")
        if checked and not present and status == "under_investigation" and (not control or (not in_raw and not raw_control)):
            data.append("no_positive_control")
        dims = {"consistency": "ok", "instrumentation": "not_run", "measurement": "not_measured", "execution": "n/a",
                "input_path": "not_run", "trigger": "none", "review": "none", "data": data}
        runtime = None
        if A.cov or A.codeql:
            rows = cov_rows.get(r["osv"], [])
            exe = [x for x in rows if row_state(x) == "executed" and x["package"].replace("%2e", ".") in pkgs]
            exe_other = [x["package"] for x in rows
                         if row_state(x) == "executed" and x["package"].replace("%2e", ".") not in pkgs]
            bad = [x["package"] for x in rows if row_state(x) in ("contradictory", "unknown-count", "unknown-label")]
            runtime = {"coverage_rows": len(rows), "executed_packages": [x["package"] for x in exe],
                       "contradictory_packages": bad,
                       "blocks": f"{sum(count(x['blocks_hit']) for x in exe)} of {sum(count(x['blocks']) or 0 for x in exe)}"
                       if exe else None}
            c = cq.get(r["osv"], {})
            by_src = c.get("taint_sinks_by_source") or {}
            # no result file or no reached symbol: specificity unknown, so no candidate
            coarse = not c.get("symbols") or c["symbols"] > A.coarse
            in_bin = (c.get("sinks_in_binary") or 0) + (c.get("main_sinks") or 0) > 0
            req, resp = by_src.get("request", 0) > 0 and in_bin, by_src.get("response", 0) > 0 and in_bin
            cqtxt = ("not run" if not c else f"path from request ({by_src.get('request', 0)} sinks)" if req
                     else f"path only from upstream responses ({by_src.get('response', 0)} sinks)" if resp
                     else f"no path, {c.get('sink_sites_outside_pkg') or 0} sink sites" if c.get("compiled") else "no query")
            runtime["codeql"] = cqtxt
            runtime["coarse_symbols"] = coarse
            if rows:
                dims["measurement"] = f"measured({A.profile})"
                dims["execution"] = "observed" if exe else f"not_observed({A.profile})"
            if c:
                dims["input_path"] = ("not_decidable" if coarse else "client" if req else "upstream_only" if resp
                                      else "no_input_path_demonstrated" if c.get("compiled") else "not_run")
            if coarse and exe:
                data.append("symbols_too_coarse")
            if bad:
                dims["consistency"] = "contradictory_rows"
            if bad:
                status, just = "under_investigation", None
                note = f"contradictory coverage row (L4 label vs. hit count) for {', '.join(bad)}; " + note
            elif status == "not_affected" and exe_other:
                status, just = "under_investigation", None
                dims["consistency"] = "layers_disagree"
                note = (f"layers disagree: {note}; but coverage rows of packages the OSV does not name executed "
                        f"({', '.join(exe_other)}): the row/package mapping needs checking")
            elif status == "not_affected" and exe:
                # the rebuild executed code the shipped-binary check calls absent: the two layers disagree
                status, just = "under_investigation", None
                dims["consistency"] = "layers_disagree"
                note = (f"layers disagree: {note}; but the coverage rebuild executed it ({runtime['blocks']} blocks in "
                        f"{', '.join(runtime['executed_packages'])})")
            elif status == "not_affected":
                pass  # code absent or other GOOS, and nothing executed
            elif exe and req and not coarse:
                rv = os.path.join(A.reviews, f"{r['osv']}.json") if A.reviews else ""
                review = json.load(open(rv)) if rv and os.path.exists(rv) else None
                if review is not None and (not isinstance(review, dict) or review.get("verdict") not in ("confirmed", "plausible", "rejected")
                                           or not review.get("reason") or review.get("osv") != r["osv"]):
                    raise SystemExit(f"{rv}: review needs osv={r['osv']}, verdict confirmed|plausible|rejected and a reason")
                runtime["affected_candidate"] = True
                runtime["review"] = review
                base = (f"executed under the lab workload ({runtime['blocks']} blocks in {', '.join(runtime['executed_packages'])}) "
                        f"and a CodeQL path from received input reaches a sink of a reached symbol")
                if review and review["verdict"] == "confirmed":
                    status, just = "affected", None
                    note = f"{base}; review confirmed: {review['reason']}"
                elif review and review["verdict"] == "rejected":
                    status, just = "under_investigation", None
                    dims["review"] = "rejected"
                    runtime["affected_candidate"] = False
                    note = f"{base}; candidate rejected in review: {review['reason']}"
                else:
                    status, just = "under_investigation", None
                    dims["review"] = "candidate_awaiting_review"
                    note = (f"affected candidate: {base}; " + (f"review: plausible, {review['reason']}" if review
                                                               else "awaiting review"))
            elif exe:
                why = ("CodeQL path only from upstream HTTP responses (trust boundary)" if resp and not coarse
                       else f"OSV symbols too coarse for CodeQL ({c.get('symbols')} reached)" if coarse
                       else f"CodeQL: {cqtxt}" + ("; candidate: vulnerable_code_cannot_be_controlled_by_adversary"
                                                  if c.get("compiled") and not req and not resp else ""))
                status, just = "under_investigation", None
                note = f"executed under the lab workload ({runtime['blocks']} blocks); {why}"
            elif rows:
                status, just = "under_investigation", None
                note = (f"not observed under the lab workload ({len(rows)} package rows measured); CodeQL: {cqtxt}"
                        + ("; symbols coarse" if coarse else "") + "; " + note)
        sub = headline(dims) if status == "under_investigation" else None
        if sub == "unclassified":
            raise SystemExit(f"{r['osv']}: under_investigation without a sub-state: {dims}")
        if sub:
            note = f"[{sub}] {note}"
        chain = {"target": rep["target"], "osv": r["osv"], "aliases": ",".join(o.get("aliases", [])),
                 "auto": True, "L1_scanner": r["trivy"], "L3_level": "symbol",
                 "L3_call_path": govulncheck_paths(rep["govulncheck_file"], r["osv"]),
                 "L3b_binary_mode": b, "symbols_checked": checked, "shipped_binary_symbols_present": present,
                 "inventory_control": control, "names_in_binary": in_raw, "osv_goos": goos_lists, "binary_goos": goos, "L4a_coverage": "not run", "L4b_uprobes": "not run",
                 "taint_paths": "not run", "runtime": runtime, "vex_status": status, "vex_justification": just, "status_note": note,
                 "substate": sub, "substate_dimensions": dims if sub else None}
        name = f"{rep['target']}--{r['osv']}.json"
        json.dump(chain, open(os.path.join(A.out, name), "w"), indent=1)
        index.append({"file": name, "target": rep["target"], "osv": r["osv"], "status": status, "justification": just,
                      "substate": sub})
        st = {"vulnerability": {"name": r["osv"], "aliases": o.get("aliases", [])}, "products": [{"@id": A.purl}],
              "status": status, "status_notes": note, "impact_statement": f"automatic static chain: {name}"}
        if just:
            st["justification"] = just
        statements.append(st)
        print(f"{r['osv']:14} {status:20} {note}")
    json.dump(index, open(os.path.join(A.out, "index.json"), "w"), indent=1)
    json.dump({"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://example.invalid/vexproof/auto/{rep['target']}",
               "author": "vexproof autochain (lab run, static layers only)", "version": 1, "statements": statements},
              open(os.path.join(A.out, "openvex.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
