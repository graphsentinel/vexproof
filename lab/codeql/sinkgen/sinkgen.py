#!/usr/bin/env python3
"""OSV entry -> LLM-proposed sink model (JSON) -> CodeQL query from a fixed template -> compile -> run -> validate.

The LLM only chooses *where untrusted data enters the vulnerable symbol*: an argument, the receiver, or an argument
of a constructor that returns the receiver type. The query text comes from TEMPLATE, never from the model.

usage: sinkgen.py --osv GO-2025-3595 --govulncheck G.json --src VENDOR_ROOT --db CODEQL_DB --out DIR
                  --model MODEL [--ollama URL]
The LLM is any model served by an Ollama endpoint: --model or VEXPROOF_LLM_MODEL names it, --ollama or
VEXPROOF_OLLAMA_URL gives the endpoint (default: a local Ollama, http://localhost:11434). No API key is used.
"""
import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

CODEQL = os.environ.get("CODEQL", "codeql")  # the CodeQL CLI on PATH (scripts/platform.sh with FULL=1) or $CODEQL

TEMPLATE = """/**
 * @name sinkgen {osv}: untrusted data reaches the vulnerable symbol's input
 * @kind path-problem
 * @problem.severity warning
 * @id vexproof/sinkgen-{osvid}
 */

import go

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    // template v3: a *http.Request read inside an HTTP client's round trip is the program's own outgoing request,
    // not remote input (batch run on metrics-server: 3 of 4 paths came from there)
    // heuristic, by function name and by HTTP client implementation file
    n instanceof RemoteFlowSource and
    not n.getRoot().(FuncDef).getName().regexpMatch("(?i).*(roundtrip|dial).*") and
    not n.getFile().getAbsolutePath()
        .regexpMatch(".*/(x/net/http2/transport[^/]*|net/http/(transport|client)[^/]*|grpc/internal/transport/http2_client)[.]go")
    or
    exists(Field f | f.hasQualifiedName("net/http", "Response", "Body") | n = f.getARead())
  }}

  predicate isSink(DataFlow::Node n) {{
{sinks}
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "untrusted data reaches a {osv} sink", src.getNode(), "source"
"""

SITES = """import go
from DataFlow::Node n
where
  (
{sinks}
  ) and not n.getFile().getAbsolutePath().matches("%/{pkgpath}/%")
select n, "sink site"
"""


def sink_clause(s, pkg):
    """one disjunct of isSink for a proposed sink; accepts pkg.F, pkg.(*T).M, pkg.T.M, (*T).M, T.M, F"""
    fn = s["function"].strip()
    short = pkg.rsplit("/", 1)[-1]
    for prefix in (pkg + ".", short + "."):
        if fn.startswith(prefix):
            fn = fn[len(prefix):]
            break
    m = re.match(r"^(?:\(\*?(?P<r1>\w+)\)|(?P<r2>\w+))\.(?P<name>\w+)$", fn) or re.match(r"^(?P<name>\w+)$", fn)
    if not m:
        raise ValueError(f"bad function name: {s['function']}")
    recv = m.groupdict().get("r1") or m.groupdict().get("r2")
    name = m.group("name")
    if recv:
        target = f'exists(Method m | m.hasQualifiedName("{pkg}", "{recv}", "{name}") |'
    else:
        target = f'exists(Function m | m.hasQualifiedName("{pkg}", "{name}") |'
    # template v2: only calls whose static target is this function/method. Method.getACall() also matches calls
    # dispatched through an interface (e.g. every io.Reader.Read), which made every reader a sink (E2).
    call = "exists(DataFlow::CallNode c | c.getTarget() = m |"
    if s["kind"] == "receiver":
        return f"    {target} {call} n = c.getReceiver()))"
    return f"    {target} {call} n = c.getArgument({int(s.get('index', 0))})))"


def stream(path):
    raw, dec, i = open(path).read(), json.JSONDecoder(), 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return
        o, i = dec.raw_decode(raw, i)
        yield o


FUNC = re.compile(r"^func (?:\((?:\w+ )?\*?(\w+)\) )?(\w+)\((.*)$")


def signatures(src, pkgpath, symbols):
    """Go signatures (+ doc line) for the symbols, plus constructors returning a receiver type"""
    d = os.path.join(src, pkgpath)
    want = set(symbols)
    recvs = {s.split(".")[0] for s in symbols if "." in s}
    out, ctors = [], []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".go") or fn.endswith("_test.go"):
            continue
        lines = open(os.path.join(d, fn)).read().split("\n")
        for i, ln in enumerate(lines):
            m = FUNC.match(ln)
            if not m:
                continue
            key = f"{m.group(1)}.{m.group(2)}" if m.group(1) else m.group(2)
            doc = lines[i - 1].strip() if i and lines[i - 1].startswith("//") else ""
            if key in want:
                out.append(f"{ln.rstrip(' {')}    {doc}")
            elif not m.group(1) and any(re.search(rf"\*?{r}\b", m.group(3).split(")")[-1]) for r in recvs):
                ctors.append(f"{ln.rstrip(' {')}    {doc}")
    return out, ctors


def ask(model, url, prompt):
    req = {"model": model, "stream": False, "options": {"temperature": 0}, "format": "json",
           "messages": [{"role": "user", "content": prompt}]}
    req["think"] = False
    t = time.time()
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{url}/api/chat", json.dumps(req).encode(),
                                                          {"Content-Type": "application/json"}), timeout=1800)
    except urllib.error.HTTPError:  # models without a thinking switch reject the field
        req.pop("think")
        r = urllib.request.urlopen(urllib.request.Request(f"{url}/api/chat", json.dumps(req).encode(),
                                                          {"Content-Type": "application/json"}), timeout=1800)
    d = json.load(r)
    return d, round(time.time() - t, 1)


PROMPT = """You map a Go vulnerability entry to CodeQL sinks. A sink is where attacker-controlled data enters the
vulnerable code. Choose, for each vulnerable symbol, the program point whose value is that input:
- "arg" with "index": an argument of the vulnerable function or method;
- "receiver": the receiver of a vulnerable method, when the method processes data held by the receiver;
- "ctor-arg" with "index": an argument of a constructor that creates the receiver from the input (for example a
  reader passed to NewX), when the vulnerable method reads data given at construction time.
Prefer the point where the untrusted bytes first enter. Do not invent functions: use only names listed below.

Vulnerability: {id} ({aliases})
Details: {details}
Package: {pkg}
Vulnerable symbols: {symbols}

Signatures of the vulnerable symbols:
{sigs}

Constructors in the same package that return one of the receiver types:
{ctors}

Return ONLY JSON: {{"sinks":[{{"kind":"arg|receiver|ctor-arg","function":"<pkg>.<Func> or <pkg>.(*<T>).<M>","index":0}}],"rationale":"<2 sentences>"}}
"""


def codeql(*args):
    env = dict(os.environ, CODEQL_ALLOW_INSTALLATION_ANYWHERE="true")
    p = subprocess.run([CODEQL, *args], capture_output=True, text=True, env=env, check=False)
    return p.returncode, (p.stdout + p.stderr)[-1500:]


def main():
    ap = argparse.ArgumentParser()
    for a in ("--osv", "--govulncheck", "--src", "--db", "--out"):
        ap.add_argument(a, required=True)
    ap.add_argument("--model", default=os.environ.get("VEXPROOF_LLM_MODEL"),
                    help="model name on the Ollama endpoint (or VEXPROOF_LLM_MODEL)")
    ap.add_argument("--ollama", default=os.environ.get("VEXPROOF_OLLAMA_URL", "http://localhost:11434"),
                    help="Ollama endpoint (default: local Ollama)")
    A = ap.parse_args()
    if not A.model:
        raise SystemExit("--model (or VEXPROOF_LLM_MODEL) is required")
    osv = next(o["osv"] for o in stream(A.govulncheck) if "osv" in o and o["osv"]["id"] == A.osv)
    imps = [i for a in osv["affected"] if a["package"]["name"] != "stdlib"
            for i in a.get("ecosystem_specific", {}).get("imports", []) if i.get("symbols")]
    out0 = os.path.join(A.out, A.model.replace(":", "_").replace("/", "_"), A.osv)
    if not imps:  # stdlib-only entries need GOROOT sources; entries without symbols cannot yield sinks
        os.makedirs(out0, exist_ok=True)
        rec = {"osv": A.osv, "model": A.model, "compiled": False, "error": "no non-stdlib import with symbols in the OSV entry"}
        json.dump(rec, open(os.path.join(out0, "result.json"), "w"), indent=1)
        print(json.dumps(rec))
        return
    # the module that govulncheck flagged first; one import path per run
    imp = imps[0]
    pkg, syms = imp["path"], imp.get("symbols", [])
    sigs, ctors = signatures(A.src, pkg, syms)
    out = os.path.join(A.out, A.model.replace(":", "_").replace("/", "_"), A.osv)
    os.makedirs(out, exist_ok=True)
    prompt = PROMPT.format(id=osv["id"], aliases=", ".join(osv.get("aliases", [])), details=osv.get("details", "")[:600],
                           pkg=pkg, symbols=", ".join(syms), sigs="\n".join(sigs) or "(none found)",
                           ctors="\n".join(ctors) or "(none)")
    open(os.path.join(out, "prompt.txt"), "w").write(prompt)
    resp, secs = ask(A.model, A.ollama, prompt)
    json.dump(resp, open(os.path.join(out, "response.json"), "w"), indent=1)
    rec = {"osv": A.osv, "model": A.model, "seconds": secs}
    try:
        txt = resp["message"]["content"].strip()
        if txt.startswith("```"):  # some models fence the JSON despite format=json; recorded as-is in response.json
            txt = txt.split("\n", 1)[1].rsplit("```", 1)[0]
        prop = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
        clauses = [sink_clause(s, pkg) for s in prop["sinks"]]
        rec["proposal"] = prop
    except Exception as e:  # malformed proposal is a result, not a crash
        rec.update(compiled=False, error=f"proposal: {e}")
        json.dump(rec, open(os.path.join(out, "result.json"), "w"), indent=1)
        print(json.dumps(rec))
        return
    body = "\n    or\n".join(clauses)
    q = os.path.join(out, "sink.ql")
    open(q, "w").write(TEMPLATE.format(osv=A.osv, osvid=A.osv.lower(), sinks=body))
    open(os.path.join(out, "qlpack.yml"), "w").write("name: vexproof/sinkgen-run\nversion: 0.0.1\ndependencies:\n  codeql/go-all: \"7.0.5\"\n")
    sites = os.path.join(out, "sites.ql")
    open(sites, "w").write(SITES.format(sinks=body, pkgpath=pkg))
    codeql("pack", "install", out)
    rc, log = codeql("query", "compile", "--check-only", q, sites)
    rec["compiled"] = rc == 0
    if rc:
        rec["error"] = log
    else:
        rc2, log2 = codeql("query", "run", sites, "-d", A.db, "--output", os.path.join(out, "sites.bqrs"))
        rc3, _ = codeql("bqrs", "decode", "--format=csv", "--output", os.path.join(out, "sites.csv"), os.path.join(out, "sites.bqrs"))
        rec["sink_sites_outside_pkg"] = max(0, sum(1 for _ in open(os.path.join(out, "sites.csv"))) - 1) if rc3 == 0 else None
        rc4, log4 = codeql("database", "analyze", A.db, q, "--format=sarif-latest", "--output", os.path.join(out, "taint.sarif"), "--rerun", "--threads=16")
        if rc4 == 0:
            res = json.load(open(os.path.join(out, "taint.sarif")))["runs"][0]["results"]
            rec["taint_results"] = len(res)
            rec["taint_sinks"] = sorted({f"{r['locations'][0]['physicalLocation']['artifactLocation']['uri'].split('vendor/')[-1]}:{r['locations'][0]['physicalLocation']['region']['startLine']}" for r in res})
        else:
            rec["error"] = log4
    json.dump(rec, open(os.path.join(out, "result.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in rec.items() if k != "proposal"}))
    print("proposal:", json.dumps(rec.get("proposal", {}).get("sinks")))


if __name__ == "__main__":
    main()
