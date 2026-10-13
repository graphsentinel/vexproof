#!/usr/bin/env python3
"""Bulk CodeQL taint queries for every open finding of one binary (after govulncheck).

For each OSV in the report's affected / under_investigation groups:
  1. symbols: the vulnerable symbols govulncheck actually reached in this program (finding traces), grouped by
     package; the OSV's full symbol list only if no trace names one. Standard-library symbols included.
  2. the LLM (any model on an Ollama endpoint, thinking off) proposes where untrusted data enters each symbol (sinkgen PROMPT);
     the query text comes from sinkgen's fixed TEMPLATE, never from the model.
  3. every query is compile-checked; the valid ones run in one `codeql database analyze` (taint paths) and one
     `codeql database run-queries` (sink call sites outside the vulnerable package).
Per OSV: out/<OSV>/{prompt-*.txt, response-*.json, sink.ql, sites.ql, result.json}; out/index.json; out/summary.tsv.

Speed: one compile call for all files, then ONE combined taint query (one global data-flow pass, each sink labelled
with its OSV) and one combined sink-site query. One query per OSV meant one data-flow pass per OSV (~10 min for 23
OSVs on metrics-server; combined ~2.5 min). Results are read from raw #select rows, not SARIF (SARIF merges alerts at
one location, which hid OSVs with identical sinks).

A path is evidence that untrusted data can reach the sink in this code base. "No path" counts only if the same DB
sees sink call sites (DEC-08). The LLM proposal itself is never evidence.

usage: batch.py --report results/report/<rel>--<target>.json --vendor SRC/vendor --goroot GOROOT/src --db DB --out DIR
                [--pclnsym LISTING]          (marks sinks in packages the shipped binary contains)
       batch.py --rescore DIR --pclnsym LISTING   (re-derive those fields for an existing batch, no CodeQL run)
                [--model MODEL] [--ollama URL] [--workers 6] [--samples 3] [--only GO-..,GO-..]
       --mode all-args needs no LLM; --mode llm needs a model on an Ollama endpoint (local by default, see sinkgen.py)
"""
import argparse
import concurrent.futures
import shutil
import csv
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sinkgen  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OPEN = ("affected", "under_investigation")
MAX_SYMBOLS = 40  # prompt size guard; reached symbols are usually far fewer


def is_stdlib(pkg):
    return "." not in pkg.split("/")[0]


def reached_symbols(govulncheck, osv_id):
    """{package: [symbol]} from the finding traces (trace[0] is the vulnerable symbol)"""
    out = {}
    for o in sinkgen.stream(govulncheck):
        f = o.get("finding")
        if not f or f["osv"] != osv_id:
            continue
        top = (f.get("trace") or [{}])[0]
        if top.get("function"):
            sym = f"{top['receiver'].lstrip('*')}.{top['function']}" if top.get("receiver") else top["function"]
            out.setdefault(top["package"], set()).add(sym)
    return {p: sorted(s) for p, s in out.items()}


def propose(job, model, url, samples):
    """`samples` LLM calls for (osv, package, symbols); the sink set is the union of the valid proposals.

    The same prompt at temperature 0 does not always return the same sinks (metrics-server, GO-2026-6348: one run
    dropped mem.NewBuffer and lost a real path), so one call is not enough. Returns (job, result)."""
    sigs, ctors = sinkgen.signatures(job["root"], job["pkg"], job["symbols"])
    prompt = sinkgen.PROMPT.format(id=job["osv"], aliases=", ".join(job["aliases"]), details=job["details"][:600],
                                   pkg=job["pkg"], symbols=", ".join(job["symbols"]),
                                   sigs="\n".join(sigs) or "(none found)", ctors="\n".join(ctors[:20]) or "(none)")
    tag = job["pkg"].replace("/", "_")
    open(os.path.join(job["dir"], f"prompt-{tag}.txt"), "w").write(prompt)
    clauses, sinks, per_sample, errors, secs = {}, [], [], [], 0.0
    for k in range(samples):
        try:
            resp, t = sinkgen.ask(model, url, prompt)
            secs += t
        except Exception as e:  # network or model error is a result
            errors.append(f"llm: {e}")
            continue
        json.dump(resp, open(os.path.join(job["dir"], f"response-{tag}-{k}.json"), "w"), indent=1)
        try:
            txt = resp["message"]["content"].strip()
            if txt.startswith("```"):
                txt = txt.split("\n", 1)[1].rsplit("```", 1)[0]
            prop = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
            got = []
            for sk in prop["sinks"]:
                try:
                    c = sinkgen.sink_clause(sk, job["pkg"])
                except ValueError as e:
                    errors.append(str(e))
                    continue
                key = (sk["kind"], sk["function"], sk.get("index"))
                got.append(list(key))
                if c not in clauses:
                    clauses[c] = key
                    sinks.append(sk)
            per_sample.append(sorted(got))
        except Exception as e:
            errors.append(f"proposal: {e}")
    distinct = len({json.dumps(x) for x in per_sample})
    res = {"seconds": round(secs, 1), "samples": samples, "valid_samples": len(per_sample),
           "distinct_proposals": distinct, "per_sample": per_sample, "proposal": {"sinks": sinks},
           "clauses": list(clauses)}
    if errors:
        res["errors"] = errors[:5]
    if not clauses:
        res["error"] = errors[0] if errors else "no sink proposed"
    return job, res


def taint_rows(tc):
    """the combined taint query's decoded #select rows -> {osv: [sink location]}, {osv: {source kind: {location}}}"""
    rows = list(csv.reader(open(tc)))
    h = rows[0]
    mcol, ucol = h.index("col3"), h.index("URL for col0")
    by, kinds = {}, {}
    for row in rows[1:]:
        oid, kind = (row[mcol].split(":", 2) + ["", ""])[:2]
        loc = row[ucol].split("/vendor/")[-1].split("/src/")[-1].rsplit(":", 3)[0]
        by.setdefault(oid, []).append(loc)
        kinds.setdefault(oid, {}).setdefault(kind, set()).add(loc)
    return by, kinds


def linked_packages(pclnsym):
    """the packages of the shipped binary, from its full .gopclntab listing"""
    linked = set()
    for ln in open(pclnsym):
        t = ln.split("\t")
        if len(t) > 1:
            fn = t[1].removeprefix("vendor/")
            head, _, tail = fn.rpartition("/")
            linked.add((head + "/" if head else "") + tail.split(".", 1)[0])
    return linked


def binary_fields(sink_locations, linked):
    """sinks in packages the shipped binary contains (module code), own-module sinks, packages it lacks"""
    locs = set(sink_locations)
    dep = [x for x in locs if "." in x.split("/", 1)[0]]  # module path: domain first
    pk = {x.rsplit("/", 1)[0] for x in dep}
    return {"sinks_in_binary": sum(1 for x in dep if x.rsplit("/", 1)[0] in linked),
            "sinks_main_module": len(locs) - len(dep),  # own code: not checked here
            "sink_packages_not_in_binary": sorted(p for p in pk if p not in linked)[:10]}


def rescore(out, pclnsym):
    """re-derive the shipped-binary fields of an existing batch from its archived combined/taint.csv (no CodeQL run):
    the same computation a run with --pclnsym does"""
    by, _ = taint_rows(os.path.join(out, "combined", "taint.csv"))
    linked = linked_packages(pclnsym)
    idx = json.load(open(os.path.join(out, "index.json")))
    for x in idx["results"]:
        if x.get("taint_results"):
            f = binary_fields(by.get(x["osv"], []), linked)
            x["sinks_in_binary"] = f["sinks_in_binary"]
            rf = os.path.join(out, x["osv"], "result.json")
            r = json.load(open(rf))
            r.update(f)
            json.dump(r, open(rf, "w"), indent=1)
    idx["rescored_with_pclnsym"] = os.path.basename(pclnsym)
    json.dump(idx, open(os.path.join(out, "index.json"), "w"), indent=1)
    print(f"rescored {sum(1 for x in idx['results'] if x.get('taint_results'))} OSVs with a path")


def main():
    ap = argparse.ArgumentParser()
    for a in ("--report", "--vendor", "--goroot", "--db", "--out"):
        ap.add_argument(a)  # required unless --rescore (checked below)
    ap.add_argument("--model", default=os.environ.get("VEXPROOF_LLM_MODEL"),
                    help="model name on the Ollama endpoint (or VEXPROOF_LLM_MODEL); needed for --mode llm")
    ap.add_argument("--ollama", default=os.environ.get("VEXPROOF_OLLAMA_URL", "http://localhost:11434"),
                    help="Ollama endpoint (default: local Ollama)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--samples", type=int, default=3, help="LLM calls per (OSV, package); sinks are unioned")
    ap.add_argument("--mode", choices=("llm", "all-args"), default="llm",
                    help="all-args: no LLM; every argument and the receiver of each reached symbol is a sink "
                         "(deterministic over-approximation: the baseline that a 'no path' needs)")
    ap.add_argument("--only", default="")
    ap.add_argument("--pclnsym", help="full .gopclntab listing of the shipped binary: marks sinks in packages it lacks")
    ap.add_argument("--rescore", help="an existing batch output dir: re-derive the shipped-binary fields with --pclnsym")
    A = ap.parse_args()
    if A.rescore:
        if not A.pclnsym:
            raise SystemExit("--rescore needs --pclnsym")
        return rescore(A.rescore, A.pclnsym)
    missing = [x for x in ("report", "vendor", "goroot", "db", "out", "pclnsym") if not getattr(A, x)]  # --pclnsym too:
    # without the shipped binary's listing every path would look as if it had no sink in the binary
    if missing:
        raise SystemExit(f"missing: {', '.join('--' + x for x in missing)}")
    if A.mode == "llm" and not A.model:
        raise SystemExit("--mode llm needs --model (or VEXPROOF_LLM_MODEL)")
    rep = json.load(open(A.report))
    gv = rep["govulncheck_file"]
    osvs = {o["osv"]["id"]: o["osv"] for o in sinkgen.stream(gv) if "osv" in o}
    only = set(filter(None, A.only.split(",")))
    rows = [r for r in rep["rows"] if r["group"] in OPEN and r["osv"] and (not only or r["osv"] in only)]
    qdir, sdir = os.path.join(A.out, "queries"), os.path.join(A.out, "sites")
    for d in (qdir, sdir):
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "qlpack.yml"), "w").write(
            f"name: vexproof/sinkgen-{os.path.basename(d)}\nversion: 0.0.1\ndependencies:\n  codeql/go-all: \"7.0.5\"\n")
    jobs, recs = [], {}
    for r in rows:
        o = osvs[r["osv"]]
        d = os.path.join(A.out, r["osv"])
        os.makedirs(d, exist_ok=True)
        rec = {"osv": r["osv"], "group": r["group"], "severity": r.get("sev"), "model": A.model, "packages": {}}
        reached = reached_symbols(gv, r["osv"])
        if not reached:  # fall back to the OSV's own list
            for a in o.get("affected", []):
                for imp in a.get("ecosystem_specific", {}).get("imports", []):
                    if imp.get("symbols"):
                        reached.setdefault(imp["path"], []).extend(imp["symbols"])
            rec["symbols_from"] = "osv"
        else:
            rec["symbols_from"] = "govulncheck traces"
        if not reached:
            rec["error"] = "no symbols: nothing to generate"
        for pkg, syms in reached.items():
            root = A.goroot if is_stdlib(pkg) else A.vendor
            if not os.path.isdir(os.path.join(root, pkg)):
                rec["packages"][pkg] = {"error": f"package source not found under {root}"}
                continue
            jobs.append({"osv": r["osv"], "pkg": pkg, "symbols": syms[:MAX_SYMBOLS], "root": root, "dir": d,
                         "aliases": o.get("aliases", []), "details": o.get("details", "")})
            rec["packages"][pkg] = {"symbols": syms[:MAX_SYMBOLS], "truncated": len(syms) > MAX_SYMBOLS}
        recs[r["osv"]] = rec
    t0 = time.time()
    timing = {}
    if A.mode == "all-args":
        for j in jobs:
            cl = []
            for sym in j["symbols"]:
                recv, _, name = sym.rpartition(".")
                tgt = (f'exists(Method m | m.hasQualifiedName("{j["pkg"]}", "{recv}", "{name}") |' if recv
                       else f'exists(Function m | m.hasQualifiedName("{j["pkg"]}", "{name}") |')
                cl.append(f"    {tgt} exists(DataFlow::CallNode c | c.getTarget() = m | "
                          f"n = c.getAnArgument() or n = c.getReceiver()))")
            recs[j["osv"]]["packages"][j["pkg"]].update({"mode": "all-args", "clauses": cl})
        jobs = []
    with concurrent.futures.ThreadPoolExecutor(A.workers) as ex:
        for job, res in ex.map(lambda j: propose(j, A.model, A.ollama, A.samples), jobs):
            recs[job["osv"]]["packages"][job["pkg"]].update(res)
    print(f"{len(jobs)} proposals for {len(recs)} OSVs in {time.time() - t0:.0f}s")
    # one query per OSV over all its packages; compile-check each
    valid = []
    for oid, rec in recs.items():
        clauses = [c for p in rec["packages"].values() for c in p.get("clauses", [])]
        if not clauses:
            rec["compiled"] = False
            rec.setdefault("error", "no valid sink proposal")
            continue
        body = "\n    or\n".join(clauses)
        rec["_body"] = body
        name = oid.lower().replace("-", "_")
        q = os.path.join(qdir, f"{name}.ql")
        s = os.path.join(sdir, f"{name}.ql")
        open(q, "w").write(sinkgen.TEMPLATE.format(osv=oid, osvid=oid.lower(), sinks=body))
        pkgs = list(rec["packages"])
        excl = " and ".join(f'not n.getFile().getAbsolutePath().matches("%/{p}/%")' for p in pkgs)
        open(s, "w").write(sinkgen.SITES.format(sinks=body, pkgpath=pkgs[0]).replace(
            f'not n.getFile().getAbsolutePath().matches("%/{pkgs[0]}/%")', excl))
        for f in (q, s):
            open(os.path.join(A.out, oid, os.path.basename(f).replace(name, "sink" if f == q else "sites")), "w").write(open(f).read())
        valid.append((oid, name))
    lock = os.path.join(HERE, "..", "codeql-pack.lock.yml")  # resolves codeql/go-all from the local cache, no network
    for d in (qdir, sdir):
        if os.path.exists(lock):
            shutil.copy(lock, os.path.join(d, "codeql-pack.lock.yml"))
        else:
            sinkgen.codeql("pack", "install", d)
    # compile only what runs (the combined queries, below); per-OSV files are compile-checked only if that fails,
    # to find the OSV with the bad clause (76 per-OSV compiles took 306 s on kube-apiserver)
    t1 = time.time()
    ok = list(valid)
    for oid, _ in ok:
        recs[oid]["compiled"] = True
    if ok:
        # one taint query for all OSVs: a single global data-flow pass, sinks labelled by OSV. One query per OSV
        # meant one full data-flow computation per OSV.
        sink_of = "\n  or\n".join(f'  (\n{recs[oid]["_body"]}\n  ) and osv = "{oid}"' for oid, _ in ok)
        outside = "\n  or\n".join(
            f'  osv = "{oid}" and ' + " and ".join(f'not n.getFile().getAbsolutePath().matches("%/{p}/%")'
                                                    for p in recs[oid]["packages"]) for oid, _ in ok)
        q = sinkgen.TEMPLATE.format(osv="combined", osvid="combined", sinks="    sinkOf(n, _)")
        q = q.replace("import go\n", f"import go\n\npredicate sinkOf(DataFlow::Node n, string osv) {{\n{sink_of}\n}}\n", 1)
        q = q[:q.index("from Flow::PathNode")] + (
            "from Flow::PathNode src, Flow::PathNode sink, string osv, string kind\n"
            "where Flow::flowPath(src, sink) and sinkOf(sink.getNode(), osv) and\n"
            "  (if exists(Field f | f.hasQualifiedName(\"net/http\", \"Response\", \"Body\") | src.getNode() = f.getARead())\n"
            "   then kind = \"response\" else kind = \"request\")\n"
            'select sink.getNode(), src, sink, osv + ":" + kind + ": untrusted data reaches a sink", src.getNode(), "source"\n')
        cdir = os.path.join(A.out, "combined")
        os.makedirs(cdir, exist_ok=True)
        open(os.path.join(cdir, "qlpack.yml"), "w").write(open(os.path.join(qdir, "qlpack.yml")).read().replace("sinkgen-queries", "sinkgen-combined"))
        shutil.copy(os.path.join(qdir, "codeql-pack.lock.yml"), cdir)
        open(os.path.join(cdir, "taint.ql"), "w").write(q)
        open(os.path.join(cdir, "sites.ql"), "w").write(
            f"import go\n\npredicate sinkOf(DataFlow::Node n, string osv) {{\n{sink_of}\n}}\n\n"
            f"predicate outside(DataFlow::Node n, string osv) {{\n{outside}\n}}\n\n"
            "from DataFlow::Node n, string osv\nwhere sinkOf(n, osv) and outside(n, osv)\nselect n, osv\n")
        rc, log = sinkgen.codeql("query", "compile", "--check-only", "--threads=16",
                                 os.path.join(cdir, "taint.ql"), os.path.join(cdir, "sites.ql"))
        if rc:  # isolate the failing OSVs, then rebuild without them
            files = [os.path.join(d, f"{name}.ql") for _, name in valid for d in (qdir, sdir)]
            _, log = sinkgen.codeql("query", "compile", "--check-only", "--threads=16", *files)
            failed = {ln.split("Failed [", 1)[1].split("] ", 1)[1].strip().rstrip(".")
                      for ln in log.splitlines() if "Failed [" in ln}
            for oid, name in valid:
                if {os.path.join(qdir, f"{name}.ql"), os.path.join(sdir, f"{name}.ql")} & failed:
                    recs[oid]["compiled"] = False
                    recs[oid]["error"] = "compile failed"
            print(f"combined query failed to compile; {sum(1 for o, _ in valid if not recs[o]['compiled'])} OSVs "
                  f"excluded; rerun to analyse the rest")
            ok = []
        timing["compile_s"] = round(time.time() - t1)
        print(f"{len(ok)} of {len(valid)} OSVs in the combined query ({timing['compile_s']}s compile)")
    if ok:
        t2 = time.time()
        # `query run` + raw #select rows: `database analyze` merges alerts at the same location, so OSVs that share
        # sink nodes (the HTTP/2 advisories) collapsed into one in SARIF
        tb, tc = os.path.join(cdir, "taint.bqrs"), os.path.join(cdir, "taint.csv")
        rc, log = sinkgen.codeql("query", "run", os.path.join(cdir, "taint.ql"), "-d", A.db, "--output", tb, "--threads=16")
        timing["taint_s"] = round(time.time() - t2)
        if rc or sinkgen.codeql("bqrs", "decode", "--format=csv", "--entities=url,string", "--result-set=#select",
                                "--output", tc, tb)[0]:
            print("taint failed:", log)
        else:
            by, kinds = taint_rows(tc)
            linked = linked_packages(A.pclnsym) if A.pclnsym else None
            for oid, _ in ok:
                if linked is not None:
                    recs[oid].update(binary_fields(by.get(oid, []), linked))
                recs[oid]["taint_results"] = len(set(by.get(oid, [])))  # distinct sink locations reached
                # source kind: "request" = input the program receives (remote), "response" = body of an HTTP response
                # the program asked for (an upstream server: a trust-boundary judgement, not attacker input by default)
                recs[oid]["taint_sinks_by_source"] = {k: len(v) for k, v in kinds.get(oid, {}).items()}
                recs[oid]["taint_path_rows"] = len(by.get(oid, []))  # (source, sink) pairs
                recs[oid]["taint_sinks"] = sorted(set(by.get(oid, [])))[:20]
        t3 = time.time()
        bq = os.path.join(cdir, "sites.bqrs")
        rc, log = sinkgen.codeql("query", "run", os.path.join(cdir, "sites.ql"), "-d", A.db, "--output", bq, "--threads=16")
        timing["sites_s"] = round(time.time() - t3)
        csvf = os.path.join(cdir, "sites.csv")
        if rc == 0 and sinkgen.codeql("bqrs", "decode", "--format=csv", "--output", csvf, bq)[0] == 0:
            counts = {}
            for row in list(csv.reader(open(csvf)))[1:]:
                counts[row[-1]] = counts.get(row[-1], 0) + 1
            for oid, _ in ok:
                recs[oid]["sink_sites_outside_pkg"] = counts.get(oid, 0)
        else:
            print("sites failed:", log)
    print("timing:", json.dumps(timing))
    index = []
    for oid, rec in recs.items():
        rec.pop("_body", None)
        for p in rec["packages"].values():
            p.pop("clauses", None)
        json.dump(rec, open(os.path.join(A.out, oid, "result.json"), "w"), indent=1)
        index.append({"osv": oid, "severity": rec.get("severity"), "compiled": rec.get("compiled"),
                      "sink_sites_outside_pkg": rec.get("sink_sites_outside_pkg"),
                      "taint_results": rec.get("taint_results"), "sinks_in_binary": rec.get("sinks_in_binary"),
                      "taint_sinks_by_source": rec.get("taint_sinks_by_source"),
                      "unstable_proposals": sum(1 for p in rec["packages"].values() if p.get("distinct_proposals", 1) > 1),
                      "error": (rec.get("error") or "")[:120]})
    json.dump({"report": A.report, "db": A.db, "timing": timing, "mode": A.mode, "model": A.model if A.mode == "llm" else None,
               "results": index},
              open(os.path.join(A.out, "index.json"), "w"), indent=1)
    with open(os.path.join(A.out, "summary.tsv"), "w") as fh:
        w = csv.DictWriter(fh, fieldnames=list(index[0]) if index else ["osv"], delimiter="\t")
        w.writeheader()
        w.writerows(index)
    n = len(index)
    comp = sum(1 for x in index if x["compiled"])
    paths = sum(1 for x in index if x["taint_results"])
    print(f"proposals differed between samples for {sum(1 for x in index if x['unstable_proposals'])} of {n} OSVs")
    print(f"{n} OSVs: {comp} queries compiled, {paths} with a taint path, "
          f"{sum(1 for x in index if x['compiled'] and not x['taint_results'] and x['sink_sites_outside_pkg'])} "
          f"no path with sink sites, {sum(1 for x in index if x['compiled'] and not x['sink_sites_outside_pkg'])} no sink sites")


if __name__ == "__main__":
    main()
