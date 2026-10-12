#!/usr/bin/env python3
"""Assemble one evidence chain per (target, OSV) and derive an OpenVEX statement from it.

A chain joins what each layer can prove:
  L1  scanner (Trivy)                   -> the module is listed in the binary's build info
  P   presence in the shipped binary    -> the vulnerable symbols exist after linking (pclnsym on .gopclntab)
  L3  govulncheck                       -> module / package / symbol, plus the call path entry -> symbol
  T   CodeQL taint                      -> untrusted data reaches the symbol's input (SARIF path)
  L4a coverage on the rebuild           -> blocks of the symbol executed under a named workload
  L4b uprobes on the shipped binary     -> entry hits of the symbol under a named workload

The OpenVEX status follows the strongest evidence, never the weakest:
  executed (L4) and tainted (T)         -> affected
  executed, no taint path found         -> under_investigation (candidate: vulnerable_code_cannot_be_controlled_by_adversary)
  symbols absent from shipped binary    -> not_affected / vulnerable_code_not_present
  no symbol-level path (L3) and not executed -> not_affected / vulnerable_code_not_in_execute_path
  symbol-level path but never executed  -> under_investigation ("not observed" is not "unreachable")
Fail closed (V7 review): a negative justification needs affirmative evidence.
  - Any contradictory measurement row (executed with no positive count, not-observed with a positive or unknown count)
    blocks every decision: under_investigation, and so does an L4 label outside the symcov vocabulary. Execution counts only for rows of a package the OSV entry names;
    an executed row of any other package blocks every negative decision (the row/package mapping is in doubt), and
    execution together with symbols absent from the shipped binary is a layer disagreement: under_investigation.
  - Symbols and controls are written in pclntab spelling (dots in the last import-path element as "%2e"; "m/p.T.M"
    is method M of type T in package m/p).
  - vulnerable_code_not_present needs the symbols missing from the target's own inventory (presence is matched
    liberally: a substring hit in the name as listed, with "%2e" read as ".", or with generic type arguments
    removed counts as present) AND a positive control found there (strictly: the exact pclntab name,
    or a "~" prefix ending at a package boundary). The control's package must be the shipped symbols' package or a
    parent at a "/" boundary. Inventory lines must be pclnsym output (0xADDR TAB name TAB file:line, ":-1" for functions
    without a source file) or the run stops.
  - vulnerable_code_not_in_execute_path needs a row for every package the OSV entry names (stdlib included), each
    not-observed with a count of exactly 0, a govulncheck level below symbol in the rows, and no symbol-level finding
    for the OSV in the govulncheck stream itself.
  - affected needs execution (a coverage row with a positive count, or a hit on a vulnerable-symbol uprobe of this
    target) and either a CodeQL code flow from a result whose rule id names the OSV (as a whole token: GO-1 does not
    match go-10), or a declared entry-point rule {"entry": <function>, "reason": <text>} whose entry function is a
    function frame of any of this OSV's symbol-level govulncheck call paths (that path is recorded; a rule off every
    path is recorded and not used). The query is OSV-specific (its sink is derived from the OSV symbols
    and recorded in the query); SARIF flows carry no callee identity, so a flow is bound to the OSV by rule id only. Results without a code flow, flows with fewer than two located
    steps, and results of other rules are not taint paths.
Anything else is under_investigation with a note. Scanner omission is never component_not_present. Uprobe profiles
are per target ({target: [files]}); a probe's hits are the maximum over its files; helper probes go under
"uprobes_context" and are reported only.

usage: chain.py <config.json>   (see results/chains/config.json)
"""
import csv
import datetime
import json
import os
import re
import sys


def stream(path):
    raw, dec, i = open(path).read(), json.JSONDecoder(), 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return
        obj, i = dec.raw_decode(raw, i)
        yield obj


def govulncheck_paths(path, osv_id):
    """shortest symbol-level call path (entry first) for this OSV, or None"""
    paths = govulncheck_all_paths(path, osv_id)
    return min(paths, key=len) if paths else None


def govulncheck_all_paths(path, osv_id):
    """every symbol-level call path (entry first) for this OSV; a frame without a function keeps "func": None"""
    out = []
    for o in stream(path):
        f = o.get("finding")
        if not f or f["osv"] != osv_id or not any(fr.get("function") for fr in f.get("trace") or []):
            continue
        frames = []
        for fr in reversed(f["trace"]):
            name = fr.get("function")
            if name and fr.get("receiver"):
                name = f"{fr['receiver']}.{name}"
            if name and fr.get("package"):
                name = f"{fr['package']}.{name}"
            pos = fr.get("position", {})
            frames.append({"func": name or None, "package": fr.get("package"),
                           "pos": f"{pos.get('filename', '').split('/vendor/')[-1].split('/src/')[-1]}:{pos.get('line', '')}"})
        out.append(frames)
    return out


def _pos(loc, artifacts=()):
    """"file:line" of a SARIF location (inline uri, or an index into the run's artifacts), or None if it has no file"""
    pl = (loc or {}).get("physicalLocation") or {}
    al = pl.get("artifactLocation") or {}
    uri = al.get("uri")
    idx = al.get("index")
    if uri is None and isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < len(artifacts):
        uri = ((artifacts[idx] or {}).get("location") or {}).get("uri")
    return f"{uri.split('vendor/')[-1]}:{(pl.get('region') or {}).get('startLine', '?')}" if isinstance(uri, str) and uri else None


def names_osv(rule_id, osv_id):
    """the rule id names this OSV as a whole token ("vexproof/go-2025-3595-taint" names GO-2025-3595, not GO-2025-359)"""
    return re.search(rf"(?<![0-9a-z]){re.escape(osv_id.lower())}(?![0-9a-z])", (rule_id or "").lower()) is not None


def symbol_level(path, osv_id):
    """does any finding for this OSV carry a function in any trace frame? (conservative symbol-level test)"""
    return any((o.get("finding") or {}).get("osv") == osv_id
               and any(fr.get("function") for fr in o["finding"].get("trace") or []) for o in stream(path))


def sarif_paths(path, osv_id):
    """code flows ([step...]) of results whose rule id names this OSV, or None if there is no SARIF file.
    A result without a code flow (a sink site), a flow without steps, or a result of another rule is not a path."""
    if not path or not os.path.exists(path):
        return None
    flows = []
    for run in json.load(open(path)).get("runs", []):
        artifacts = run.get("artifacts") or []
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        cached = run.get("threadFlowLocations") or []

        def ref(seq, i):  # SARIF index reference, or {} if it does not resolve
            return seq[i] if isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(seq) else {}
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or (ref(rules, res.get("ruleIndex")) or {}).get("id")
            if not names_osv(rule_id, osv_id):
                continue
            for cf in res.get("codeFlows") or []:
                for tf in cf.get("threadFlows") or []:
                    locs = [loc if "location" in loc else ref(cached, loc.get("index")) or {}
                            for loc in tf.get("locations") or []]
                    steps = [{"pos": _pos(loc.get("location"), artifacts),
                              "msg": ((loc.get("location") or {}).get("message") or {}).get("text", "")}
                             for loc in locs]
                    if len(steps) >= 2 and all(st["pos"] for st in steps):
                        flows.append(steps)
    return flows


def osv_packages(path, osv_id):
    """import paths that the OSV entry names (stdlib included, from the govulncheck stream; the union over every
    record of this OSV), or None if absent"""
    out = None
    for o in stream(path):
        if o.get("osv", {}).get("id") == osv_id:
            out = (out or set()) | {i["path"] for a in o["osv"].get("affected", [])
                                    for i in a.get("ecosystem_specific", {}).get("imports", [])}
    return out


def pkg_of(sym):
    """import path part of a symbol: "~golang.org/x/net/html.(*T).M" -> "golang.org/x/net/html".
    pclntab escapes dots in the last path element ("gopkg.in/yaml%2ev3.F"), so the first dot ends the package."""
    s = sym.lstrip("~")
    head, _, tail = s.rpartition("/")
    return ((head + "/" if head else "") + tail.split(".", 1)[0]).rstrip("/")


def within(pkg, parent):
    """pkg is parent or below it at a "/" boundary (m/p is within m and m/p, not within m/pq)"""
    return pkg == parent or pkg.startswith(parent + "/")


def count(v):
    """a block or hit count: non-negative int, or None if missing or not a number"""
    v = (v or "").strip()
    return int(v) if re.fullmatch(r"[0-9]+", v, re.ASCII) else None


L4_LABELS = {"executed", "not-observed", "not-linked", "not-instrumented", "absent", "not-run"}


def row_state(r):
    """executed / not-observed / contradictory / unknown-count / unknown-label / the row's own L4 label"""
    l4, n = (r.get("L4") or "").strip(), count(r.get("blocks_hit"))
    if l4 not in L4_LABELS:
        return "unknown-label"
    if l4 == "executed":
        return "executed" if n else "contradictory"
    if l4 == "not-observed":
        return "not-observed" if n == 0 else "contradictory" if n else "unknown-count"
    if n is None and (r.get("blocks_hit") or "").strip() not in ("", "-"):
        return "unknown-count"
    return "contradictory" if n else (l4 or "missing")


PCLNSYM_LINE = re.compile(r"0x[0-9a-f]+\t([^\t]+)\t(?:[^\t]+:[1-9][0-9]*|:-1)", re.ASCII)  # no source file: ":-1"


def inventory_names(files):
    """function names from pclnsym listings (names may contain spaces); any other line format stops the run"""
    names = set()
    for p in files:
        for i, line in enumerate(open(p), 1):
            m = PCLNSYM_LINE.fullmatch(line.rstrip("\n"))
            if not m or not m.group(1).strip():
                raise SystemExit(f"{p}:{i}: not a pclnsym line (0xADDR<TAB>name<TAB>file:line)")
            names.add(m.group(1))
    return names


def uprobe_hits(paths):
    """{probe_name: hits} from uprobe_profile files ("name hits" per line)"""
    out = {}
    for p in paths:
        for i, line in enumerate(open(p), 1):
            t = line.split()
            if not t:
                continue
            if len(t) != 2 or count(t[1]) is None:
                raise SystemExit(f"{p}:{i}: not a uprobe_profile line (name hits)")
            out[t[0]] = max(out.get(t[0], 0), int(t[1]))
    return out


def strip_generics(name):
    """m/p.(*T[go.shape.int]).F -> m/p.(*T).F (nested brackets too)"""
    prev = None
    while prev != name:
        prev, name = name, re.sub(r"\[[^\[\]]*\]", "", name)
    return name


def spellings(name):
    """a name as listed, with %2e read as ".", and both of those without generic type arguments"""
    dot = name.replace("%2e", ".")
    return {name, dot, strip_generics(name), strip_generics(dot)}


def per_target(cfg, key, targets):
    """{target: [files]}; a plain list is accepted only for a single-target config"""
    v = cfg.get(key, [])
    if isinstance(v, dict):
        if not all(isinstance(f, list) for f in v.values()):
            raise SystemExit(f"{key}: every target needs a list of files")
        return v
    if v and len(targets) > 1:
        raise SystemExit(f"{key} must be {{target: [files]}} when the config has several targets")
    return {t: v for t in targets}


def main():
    cfg = json.load(open(sys.argv[1]))
    base = os.path.dirname(os.path.abspath(sys.argv[1]))
    rows = list(csv.DictReader(open(cfg["measurements"]), delimiter="\t"))
    targets = {c["target"] for c in cfg["chains"]}
    inventory = per_target(cfg, "pclnsym", targets)
    hits_by_target = {t: uprobe_hits(f) for t, f in per_target(cfg, "uprobe_profiles", targets).items()}
    statements, index = [], []
    rank = {"none": 0, "module": 1, "package": 2, "symbol": 3}
    for c in cfg["chains"]:
        target, osv = c["target"], c["osv"]
        mine = [r for r in rows if r["target"] == target and r["osv"] == osv]
        best = max(mine, key=lambda r: -1 if count(r["blocks_hit"]) is None else count(r["blocks_hit"])) if mine else {}
        gv = cfg.get("govulncheck", {}).get(target)
        gv_ok = bool(gv) and os.path.exists(gv)
        expected = osv_packages(gv, osv) if gv_ok else None

        def state(r):  # execution counts only in a package the OSV names
            st = row_state(r)
            pkg = r["package"].replace("%2e", ".")
            return "executed-other-package" if st == "executed" and pkg not in (expected or ()) else st
        states = {state(r) for r in mine}
        missing_pkgs = sorted(expected - {r["package"].replace("%2e", ".") for r in mine}) if expected else []
        names = inventory_names(inventory.get(target, []))
        listed = set().union(*(spellings(n) for n in names))

        def present(s):  # liberal: a false "present" can only block vulnerable_code_not_present
            qs = spellings(s[1:] if s.startswith("~") else s)
            return any(q in n for q in qs for n in listed)

        def control_found(s):  # strict: exact pclntab name, or a "~" prefix ending at a package boundary
            if s.startswith("~"):
                if not s.endswith(("/", ".")):
                    raise SystemExit(f"{target} {osv}: inventory_control {s!r} must end with '/' or '.'")
                return any(n.startswith(s[1:]) for n in names)
            return s in names
        sym_present = [s for s in c.get("symbols_shipped", []) if present(s)]
        # absence counts only if a positive control of the same package (or a parent at a "/" boundary) is found
        shipped_pkgs = {pkg_of(s) for s in c.get("symbols_shipped", [])}
        control = [s for s in c.get("inventory_control", []) if control_found(s)
                   and all(within(p, pkg_of(s)) for p in shipped_pkgs)]
        shipped_absent = bool(c.get("symbols_shipped")) and not sym_present and bool(control)
        hits = hits_by_target.get(target, {})
        up = {k: v for k, v in hits.items() if k in c.get("uprobes", [])}
        up_ctx = {k: v for k, v in hits.items() if k in c.get("uprobes_context", [])}
        executed_up = any(v > 0 for v in up.values())
        if c.get("taint_sarif") and not os.path.exists(c["taint_sarif"]):
            raise SystemExit(f"{target} {osv}: taint_sarif {c['taint_sarif']} does not exist")
        taint = sarif_paths(c.get("taint_sarif"), osv)
        if taint == [] and int(c.get("taint_sink_sites", 0)) == 0:
            # "no path" is evidence only if the same database sees the sink call sites (vendored code trap)
            taint = None
        l3s = {r.get("L3_level") for r in mine}
        l3 = max(l3s, key=lambda x: rank.get(x or "", -1), default="none")
        path = govulncheck_paths(gv, osv) if gv_ok else None
        taint_rule, rule_unused, rule_path = None, None, None
        rule = c.get("untrusted_by_rule")
        if rule is not None and not (isinstance(rule, dict) and isinstance(rule.get("entry"), str) and rule["entry"]
                                     and isinstance(rule.get("reason"), str) and rule["reason"]):
            raise SystemExit(f"{target} {osv}: untrusted_by_rule must be {{\"entry\": <function>, \"reason\": <text>}}")
        if not taint and rule:
            # e.g. the call path passes the server's connection handler: the input is the peer's bytes. Recorded as a
            # rule, never mixed with CodeQL evidence, and used only if its entry is on this OSV's call path.
            rule_path = next((pth for pth in (govulncheck_all_paths(gv, osv) if gv_ok else [])
                              if any(fr["func"] and fr["func"] == rule["entry"] for fr in pth)), None)
            if rule_path:
                taint_rule = rule
            else:
                rule_unused = f"entry {rule['entry']} is not a frame of the symbol-level call path"
        if path or (gv_ok and symbol_level(gv, osv)):  # the stream reports a symbol-level finding, whatever the rows say
            l3 = "symbol"
        executed = "executed" in states or executed_up
        note = None
        if states & {"contradictory", "unknown-count", "unknown-label"}:
            status, just = "under_investigation", None
            note = "contradictory or unknown measurement row (L4 label vs. hit count)"
        elif executed and shipped_absent:
            status, just = "under_investigation", None
            note = "layers disagree: executed, but the symbols are absent from the shipped binary"
        elif "executed-other-package" in states:
            status, just = "under_investigation", None
            note = "executed row of a package the OSV does not name: the row/package mapping needs checking"
        elif executed and (taint or taint_rule):
            status, just = "affected", None
            if not taint:
                note = "affected by rule (untrusted entry point), not by a CodeQL path"
        elif executed:
            status, just = "under_investigation", None
            note = "executed; no taint path or untrusted-entry rule (candidate: vulnerable_code_cannot_be_controlled_by_adversary)"
        elif not mine:
            status, just, note = "under_investigation", None, "no measurement rows for this target and OSV"
        elif shipped_absent:
            status, just = "not_affected", "vulnerable_code_not_present"
        elif l3 == "symbol":
            status, just = "under_investigation", None
            note = "symbol-level path, not observed under the workload (not observed is not unreachable)"
        elif not l3s <= {"none", "module", "package"}:
            status, just, note = "under_investigation", None, "govulncheck level missing for a package"
        elif states == {"absent"}:
            status, just = "under_investigation", None
            note = "govulncheck reports nothing for this OSV; scanner omission is not treated as absence"
        elif states == {"not-observed"} and expected and not missing_pkgs:
            status, just = "not_affected", "vulnerable_code_not_in_execute_path"
        else:
            status, just = "under_investigation", None
            gaps = sorted(states - {"not-observed"}) + [f"no row for {p}" for p in missing_pkgs]
            if not expected:
                gaps.append("OSV package list unavailable" if gv_ok else "govulncheck stream missing")
            note = f"incomplete coverage evidence ({', '.join(gaps)}) and no shipped-binary check"
        chain = {
            "target": target, "osv": osv, "aliases": best.get("aliases", ""),
            "L1_scanner": best.get("L1_trivy"),
            "shipped_binary_symbols_present": sym_present if c.get("symbols_shipped") else "not checked",
            "symbols_checked": len(c.get("symbols_shipped", [])),
            "L3_level": l3, "L3_call_path": path,
            "taint_paths": taint if taint is not None else "not run",
            "taint_by_rule": taint_rule,
            "taint_rule_unused": rule_unused,
            "taint_rule_call_path": rule_path,
            "L4a_coverage": {"run": best.get("run"), "blocks": best.get("blocks"), "hit": best.get("blocks_hit")},
            "L4a_rows": [{"run": r.get("run"), "package": r.get("package"), "blocks": r.get("blocks"),
                          "hit": r.get("blocks_hit"), "state": state(r)} for r in mine],
            "L4b_uprobes": up or "not run",
            "L4b_uprobes_context": up_ctx or None,
            "runtime_entry": c.get("runtime_entry"),
            "ground_truth": c.get("ground_truth"),
            "vex_status": status, "vex_justification": just, "status_note": note,
        }
        name = f"{target}--{osv}.json"
        json.dump(chain, open(os.path.join(base, name), "w"), indent=1)
        index.append({"file": name, "target": target, "osv": osv, "status": status, "justification": just})
        st = {"vulnerability": {"name": osv, "aliases": [a for a in chain["aliases"].split(",") if a]},
              "products": [{"@id": cfg["products"][target]}], "status": status,
              "impact_statement": f"evidence chain: {cfg['evidence_base']}/{name}"}
        if just:
            st["justification"] = just
        if note:
            st["status_notes"] = note
        if status == "affected":
            st["action_statement"] = c.get("action", "Upgrade the dependency to a fixed version.")
        statements.append(st)
    json.dump(index, open(os.path.join(base, "index.json"), "w"), indent=1)
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": cfg["vex_id"], "author": cfg["author"],
           "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "version": 1, "statements": statements}
    json.dump(vex, open(cfg["openvex_out"], "w"), indent=1)
    for i in index:
        print(f"{i['target']:15} {i['osv']:13} {i['status']:20} {i['justification'] or ''}")


if __name__ == "__main__":
    sys.exit(main())
