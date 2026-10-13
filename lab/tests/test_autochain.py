"""autochain: the raw-name and GOOS rules, and the inlining guard (synthetic inputs)."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def run(tmp_path, imports, funcs, raw, binary_level, goos="linux", extra=(), buildinfo=None, extra_gb=(), module="m",
        more_affected=(), report=None):
    osv = {"id": "GO-1", "aliases": [], "affected": [{"package": {"name": module}, "ecosystem_specific": {"imports": imports}},
                                                     *more_affected]}
    gv = tmp_path / "gv.json"
    gv.write_text(json.dumps({"osv": osv}))
    gb = tmp_path / "gb.json"
    gb.write_text(json.dumps({"osv": osv}) + (json.dumps({"finding": {"osv": "GO-1", "trace": [
        {"module": "m", "package": "m/p", "function": "F"}]}}) if binary_level == "symbol" else "")
        + "".join(json.dumps(o) for o in extra_gb))
    rep = tmp_path / "rep.json"
    rep.write_text(json.dumps(report if report is not None else {"target": "t", "govulncheck_file": str(gv), "rows": [
        {"osv": "GO-1", "group": "static_reachable", "trivy": "yes"}]}))
    inv = tmp_path / "inv.txt"
    inv.write_text("".join(f"0x1\t{f}\tf.go:1\n" for f in funcs))
    b = tmp_path / "bin"
    b.write_bytes(raw)
    bi = tmp_path / "bi.txt"
    bi.write_text(buildinfo if buildinfo is not None else f"\tbuild\tGOOS={goos}\n")
    out = tmp_path / "out"
    subprocess.run([sys.executable, f"{ROOT}/lab/autochain.py", "--report", str(rep), "--pclnsym", str(inv),
                    "--govulncheck-binary", str(gb), "--binary", str(b), "--buildinfo", str(bi), "--out", str(out),
                    "--purl", "pkg:golang/x", *extra], check=True, capture_output=True)
    return json.load(open(out / "t--GO-1.json"))


IMP = [{"path": "m/p", "symbols": ["T.F"]}]


def test_symbol_present_stays_investigation(tmp_path):
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol")
    assert c["vex_status"] == "under_investigation"


def test_absent_everywhere_is_not_present(tmp_path):
    c = run(tmp_path, IMP, ["m/p.G"], b"m/p.G", "symbol")
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_present")


def test_name_in_binary_but_not_listed_is_inlined(tmp_path):
    c = run(tmp_path, IMP, ["m/p.G"], b"xx m/p.(*T).F xx", "symbol")
    assert c["vex_status"] == "under_investigation"


def test_absent_without_control(tmp_path):
    c = run(tmp_path, IMP, ["other.G"], b"", "not reported")
    assert c["vex_status"] == "under_investigation"


def test_other_goos(tmp_path):
    c = run(tmp_path, [{"path": "m/p", "symbols": ["T.F"], "goos": ["windows"]}], ["m/p.(*T).F", "m/p.G"],
            b"m/p.(*T).F", "not reported")
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_present")


def test_other_goos_but_binary_mode_reports(tmp_path):
    c = run(tmp_path, [{"path": "m/p", "symbols": ["T.F"], "goos": ["windows"]}], ["m/p.(*T).F", "m/p.G"],
            b"m/p.(*T).F", "symbol")
    assert c["vex_status"] == "under_investigation"


def runtime_inputs(tmp_path, executed, request_sinks, verdict=None, symbols=1):
    cov = tmp_path / "cov.tsv"
    cov.write_text("target\tosv\tpackage\tblocks\tblocks_hit\tL4\n"
                   f"t\tGO-1\tm/p\t10\t{3 if executed else 0}\t{'executed' if executed else 'not-observed'}\n")
    cq = tmp_path / "cq"
    (cq / "GO-1").mkdir(parents=True)
    (cq / "index.json").write_text(json.dumps({"results": [{"osv": "GO-1", "compiled": True, "taint_results": request_sinks,
        "sink_sites_outside_pkg": 3, "sinks_in_binary": request_sinks,
        "taint_sinks_by_source": {"request": request_sinks} if request_sinks else {}}]}))
    (cq / "GO-1" / "result.json").write_text(json.dumps({"packages": {"m/p": {"symbols": ["S"] * symbols}}}))
    args = ["--cov", str(cov), "--codeql", str(cq)]
    if verdict:
        rv = tmp_path / "rv"
        rv.mkdir()
        (rv / "GO-1.json").write_text(json.dumps({"osv": "GO-1", "verdict": verdict, "reason": "r"}))
        args += ["--reviews", str(rv)]
    return args


def chain_with(tmp_path, **kw):
    return run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=runtime_inputs(tmp_path, **kw))


def test_candidate_without_review_stays_investigation(tmp_path):
    c = chain_with(tmp_path, executed=True, request_sinks=2)
    assert c["vex_status"] == "under_investigation" and c["runtime"]["affected_candidate"]


def test_confirmed_candidate_is_affected(tmp_path):
    assert chain_with(tmp_path, executed=True, request_sinks=2, verdict="confirmed")["vex_status"] == "affected"


def test_rejected_candidate(tmp_path):
    c = chain_with(tmp_path, executed=True, request_sinks=2, verdict="rejected")
    assert c["vex_status"] == "under_investigation" and not c["runtime"]["affected_candidate"]


def test_not_executed_is_no_candidate(tmp_path):
    c = chain_with(tmp_path, executed=False, request_sinks=2, verdict="confirmed")
    assert c["vex_status"] == "under_investigation" and not c["runtime"].get("affected_candidate")


def test_coarse_symbols_no_candidate(tmp_path):
    c = chain_with(tmp_path, executed=True, request_sinks=2, verdict="confirmed", symbols=50)
    assert c["vex_status"] == "under_investigation" and not c["runtime"].get("affected_candidate")


# --- round 5 ---

def test_escaped_import_path_is_found_present(tmp_path):
    imp = [{"path": "m/p.v3", "symbols": ["F"]}]
    c = run(tmp_path, imp, ["m/p%2ev3.F", "m/p%2ev3.G"], b"m/p%2ev3.F m/p%2ev3.G", "not reported")
    assert c["vex_status"] == "under_investigation" and c["shipped_binary_symbols_present"]


def test_escaped_name_only_in_raw_bytes_blocks_absence(tmp_path):
    imp = [{"path": "m/p.v3", "symbols": ["F"]}]
    c = run(tmp_path, imp, ["m/p%2ev3.G"], b"m/p%2ev3.F m/p%2ev3.G", "symbol")
    assert c["vex_status"] == "under_investigation"


def test_import_without_symbol_list_blocks_absence(tmp_path):
    imp = [{"path": "m/p", "symbols": ["F"]}, {"path": "m/q"}]
    c = run(tmp_path, imp, ["m/p.G", "m/q.H"], b"m/p.G m/q.H", "not reported")
    assert c["vex_status"] == "under_investigation"


def test_raw_check_needs_its_own_positive_control(tmp_path):
    c = run(tmp_path, [{"path": "m/p", "symbols": ["F"]}], ["m/p.G"], b"", "symbol")
    assert c["vex_status"] == "under_investigation"


def test_malformed_inventory_line_stops(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, IMP, ["m/p.G\tjunk"], b"m/p.G", "not reported")


def test_goos_branch_needs_binary_mode_silent(tmp_path):
    gb_pkg = {"finding": {"osv": "GO-1", "trace": [{"module": "m", "package": "m/p"}]}}
    imp = [{"path": "m/p", "symbols": ["T.F"], "goos": ["windows"]}]
    c = run(tmp_path, imp, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "package-finding", extra_gb=[gb_pkg])
    assert c["vex_status"] == "under_investigation"


def test_goos_only_from_the_build_line(tmp_path):
    imp = [{"path": "m/p", "symbols": ["T.F"], "goos": ["linux"]}]
    c = run(tmp_path, imp, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "not reported", goos="plan9",
            buildinfo="\tbuild\tGOOS=linux\nnote GOOS=plan9\n")
    assert c["vex_status"] == "under_investigation"


def test_execution_in_another_package_is_not_execution(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="confirmed")
    cov = tmp_path / "cov.tsv"
    cov.write_text(cov.read_text().replace("\tm/p\t", "\tm/unrelated\t"))
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)
    assert c["vex_status"] == "under_investigation" and not c["runtime"]["executed_packages"]


@pytest.mark.parametrize("hit", ["-", "unknown"])
def test_unknown_coverage_count_blocks_absence(tmp_path, hit):
    args = runtime_inputs(tmp_path, executed=False, request_sinks=0)
    cov = tmp_path / "cov.tsv"
    cov.write_text(cov.read_text().replace("\t0\tnot-observed", f"\t{hit}\tnot-observed"))
    c = run(tmp_path, IMP, ["m/p.G"], b"m/p.G", "not reported", extra=args)
    assert c["vex_status"] == "under_investigation"


def test_missing_codeql_result_is_not_specific(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="confirmed")
    os.remove(tmp_path / "cq" / "GO-1" / "result.json")
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)
    assert c["vex_status"] == "under_investigation"


def test_review_without_verdict_stops(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="confirmed")
    (tmp_path / "rv" / "GO-1.json").write_text(json.dumps({"osv": "GO-1", "reason": "r"}))
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)


# --- round 6 ---

def test_generic_receiver_name_in_binary_blocks_absence(tmp_path):
    c = run(tmp_path, IMP, ["m/p.G"], b"m/p.G\x00m/p.(*T[go.shape.int]).F\x00", "symbol")
    assert c["vex_status"] == "under_investigation"


def test_unescaped_raw_spelling_blocks_absence(tmp_path):
    imp = [{"path": "gopkg.in/yaml.v3", "symbols": ["T.F"]}]
    c = run(tmp_path, imp, ["gopkg.in/yaml%2ev3.G"], b"gopkg.in/yaml%2ev3.G gopkg.in/yaml.v3.(*T).F", "not reported")
    assert c["vex_status"] == "under_investigation"


def test_dotted_sibling_package_is_no_control(tmp_path):
    osv_imp = [{"path": "m/p/sub", "symbols": ["F"]}]
    c = run(tmp_path, osv_imp, ["m/p%2eevil.G"], b"m/p%2eevil.G", "not reported", module="m/p")
    assert c["vex_status"] == "under_investigation"


def test_affected_entry_without_imports_blocks_absence(tmp_path):
    c = run(tmp_path, [{"path": "m/p", "symbols": ["F"]}], ["m/p.G"], b"m/p.G", "not reported",
            more_affected=[{"package": {"name": "n", "ecosystem": "Go"}}])
    assert c["vex_status"] == "under_investigation"


def test_review_that_is_not_an_object_stops(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="confirmed")
    (tmp_path / "rv" / "GO-1.json").write_text("[]")
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)


def test_report_with_another_schema_stops(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, IMP, ["m/p.G"], b"m/p.G", "not reported", report={})


def test_execution_in_unnamed_package_blocks_absence(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=0)
    cov = tmp_path / "cov.tsv"
    cov.write_text(cov.read_text().replace("\tm/p\t", "\tvendor/m/p\t"))
    c = run(tmp_path, IMP, ["m/p.G"], b"m/p.G", "not reported", extra=args)
    assert c["vex_status"] == "under_investigation"


# --- round 7 ---

def test_module_without_imports_blocks_goos_rule(tmp_path):
    c = run(tmp_path, [{"path": "m/p", "symbols": ["F"], "goos": ["windows"]}], ["m/p.G"], b"m/p.G", "not reported",
            more_affected=[{"package": {"name": "n", "ecosystem": "Go"}}])
    assert c["vex_status"] == "under_investigation"


def test_binary_level_is_the_strongest_in_any_order(tmp_path):
    mod = {"finding": {"osv": "GO-1", "trace": [{"module": "m"}]}}
    pkg = {"finding": {"osv": "GO-1", "trace": [{"module": "m", "package": "m/p"}]}}
    for order in ([mod, pkg], [pkg, mod]):
        c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "x", extra_gb=order)
        assert c["L3b_binary_mode"] == "package"


# --- round 8 ---

def test_escaped_execution_matches_import(tmp_path):
    args = runtime_inputs(tmp_path, True, 2, "confirmed")
    cov = tmp_path / "cov.tsv"
    cov.write_text(cov.read_text().replace("\tm/p\t", "\tm/p%2ev3\t"))
    c = run(tmp_path, [{"path": "m/p.v3", "symbols": ["F"]}], ["m/p%2ev3.F"], b"m/p%2ev3.F", "symbol", extra=args)
    assert c["runtime"]["executed_packages"]


def test_empty_specificity_evidence(tmp_path):
    args = runtime_inputs(tmp_path, True, 2, "confirmed")
    (tmp_path / "cq" / "GO-1" / "result.json").write_text(json.dumps({"packages": {}}))
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)
    assert c["vex_status"] == "under_investigation"


# --- round 9 ---

def test_nested_generic_is_listed_present(tmp_path):
    fn = "m/p.(*T[go.shape.[2]int]).F"
    c = run(tmp_path, IMP, [fn, "m/p.G"], (fn + "\x00m/p.G").encode(), "symbol")
    assert c["shipped_binary_symbols_present"] == ["m/p.T.F"]


# --- round 10 ---

def test_duplicate_osv_preserves_present_symbol(tmp_path):
    imports = [{"path": "m/p", "symbols": ["F"]}]

    def record(imps):
        return {"osv": {"id": "GO-1", "aliases": [], "affected": [{"package": {"name": "m"},
                                                                   "ecosystem_specific": {"imports": imps}}]}}
    source = tmp_path / "source.json"
    source.write_text("\n".join(map(json.dumps, [record(imports + [{"path": "m/q", "symbols": ["H"]}]), record(imports)])))
    report = {"target": "t", "govulncheck_file": str(source),
              "rows": [{"osv": "GO-1", "group": "static_reachable", "trivy": "yes"}]}
    c = run(tmp_path, imports, ["m/p.G", "m/q.H"], b"m/p.G\x00m/q.H\x00", "not reported", report=report)
    assert c["vex_status"] == "under_investigation"


# --- under_investigation sub-states (one headline label per chain) ---
def test_static_only_is_not_measured(tmp_path):
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol")
    assert c["substate"] == "not_measured" and c["status_note"].startswith("[not_measured] ")


def test_candidate_sub_states(tmp_path):
    assert chain_with(tmp_path, executed=True, request_sinks=2)["substate"] == "candidate_awaiting_review"


def test_rejected_sub_state(tmp_path):
    assert chain_with(tmp_path, executed=True, request_sinks=2, verdict="rejected")["substate"] == "rejected"


def test_executed_without_path_sub_state(tmp_path):
    c = chain_with(tmp_path, executed=True, request_sinks=0)
    assert c["substate"] == "observed_no_input_path_demonstrated"
    assert c["substate_dimensions"]["measurement"] == "measured(lab-workload)"


def test_not_observed_sub_state(tmp_path):
    c = chain_with(tmp_path, executed=False, request_sinks=2)
    assert c["substate"] == "not_observed" and c["substate_dimensions"]["execution"] == "not_observed(lab-workload)"


def test_coarse_sub_state(tmp_path):
    c = chain_with(tmp_path, executed=True, request_sinks=2, symbols=50)
    assert c["substate"] == "symbols_too_coarse" and c["substate_dimensions"]["input_path"] == "not_decidable"


def test_decided_chains_have_no_sub_state(tmp_path):
    assert chain_with(tmp_path, executed=True, request_sinks=2, verdict="confirmed")["substate"] is None


def test_headline_order_is_total():
    import importlib.util
    spec = importlib.util.spec_from_file_location("autochain", f"{ROOT}/lab/autochain.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    base = {"consistency": "ok", "instrumentation": "not_run", "measurement": "measured(p)", "execution": "observed",
            "input_path": "client", "trigger": "none", "review": "none", "data": []}
    assert m.headline({**base, "consistency": "contradictory_rows", "measurement": "not_measured"}) == "contradictory_rows"
    assert m.headline({**base, "measurement": "not_measured", "data": ["osv_without_symbols"]}) == "not_measured"
    assert m.headline({**base, "input_path": "upstream_only"}) == "observed_upstream_input_only"
    assert m.headline(base) == "unclassified"  # observed + client input without a review flag never happens in autochain


def test_failed_codeql_query_is_classified(tmp_path):
    args = runtime_inputs(tmp_path, executed=True, request_sinks=0)
    idx = tmp_path / "cq" / "index.json"
    idx.write_text(json.dumps({"results": [{"osv": "GO-1", "compiled": False}]}))
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], b"m/p.(*T).F", "symbol", extra=args)
    assert c["substate"] == "observed_input_path_not_analysed"


def test_raw_control_failure_is_no_positive_control(tmp_path):
    c = run(tmp_path, IMP, ["m/p.G"], b"nothing", "not reported")
    assert "raw-name check has no positive control" in c["status_note"]
    assert "no_positive_control" in c["substate_dimensions"]["data"]


def test_every_reachable_dimension_combination_has_a_headline():
    import importlib.util
    import itertools
    spec = importlib.util.spec_from_file_location("autochain", f"{ROOT}/lab/autochain.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    for cons, meas, exe, inp, rev in itertools.product(
            ("ok", "contradictory_rows", "layers_disagree"), ("not_measured", "measured(p)"),
            ("n/a", "observed", "not_observed(p)"), ("not_run", "client", "upstream_only", "not_decidable",
                                                      "no_input_path_demonstrated"),
            ("none", "candidate_awaiting_review", "rejected")):
        if (meas == "not_measured") != (exe == "n/a"):
            continue  # execution is set exactly when coverage rows exist
        if inp == "not_decidable":
            data = [["symbols_too_coarse"]] if exe == "observed" else [[]]
        else:
            data = [[]]
        for dt in data + [["osv_without_symbols"]]:
            for trg in ("none", "unevaluated", "inconclusive", "gate_invalid"):
                if trg != "none" and not (exe == "observed" and inp == "client"):
                    continue  # gate states only exist for affected candidates
                if exe == "observed" and inp == "client" and rev == "none" and trg == "none":
                    continue  # a candidate always has a review state or (with --exercise) a gate state
                d = {"consistency": cons, "instrumentation": "not_run", "measurement": meas, "execution": exe,
                     "input_path": inp, "trigger": trg, "review": rev, "data": dt}
                assert m.headline(d) != "unclassified", d


# --- exercise-layer gate policy (--exercise) ---
def make_gate(tmp_path, binary_bytes, rows=("affected_evidence",), osv="GO-1"):
    """real evidence files + a gate built by lab/trigger/gate.py"""
    import hashlib
    sys.path.insert(0, f"{ROOT}/lab/trigger")
    import gate as G
    spec = tmp_path / "spec.yaml"
    spec.write_text(json.dumps({"spec": {"vulnerability": {"osv": osv}, "target": {
        "binary": {"sha256": hashlib.sha256(binary_bytes).hexdigest()},
        "source": {"ref": "v1", "mainPackage": "./cmd/t"}}}}))
    runs = []
    for i, x in enumerate(rows):
        d = tmp_path / f"run{i}"
        d.mkdir()
        (d / "status.json").write_text(json.dumps({"status": {
            "row1": {"result": x}, "e2a": {"checks": {"trigger_counts": x == "affected_evidence"}},
            "oracle": [], "resolved": {"shipped_sha256": hashlib.sha256(binary_bytes).hexdigest()}}}))
        for f in ("results.tsv", "resolved.json", "e2a-perf.data"):
            (d / f).write_text(f"{f}{i}")
        runs.append(str(d))
    g = G.build(str(spec), {}, len(rows), runs, str(tmp_path))
    gd = tmp_path / "gates"
    gd.mkdir()
    (gd / f"{osv}.json").write_text(json.dumps(g))
    return gd, G


def exercised(tmp_path, verdict="confirmed", cite=True, binary_bytes=b"m/p.(*T).F", rows=("affected_evidence",),
              tamper=None, osv="GO-1"):
    raw = b"m/p.(*T).F"
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict=verdict)
    gd, G = make_gate(tmp_path, binary_bytes, rows, osv)
    if tamper:
        tamper(tmp_path, gd)
    if verdict and cite:
        rv = tmp_path / "rv" / "GO-1.json"
        r = json.loads(rv.read_text())
        r["exercise_gate_sha256"] = G.sha256(str(gd / f"{osv}.json")) if (gd / f"{osv}.json").exists() else ""
        rv.write_text(json.dumps(r))
    return run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], raw, "symbol",
               extra=args + ["--exercise", str(gd), "--exercise-root", str(tmp_path)])


def test_passed_gate_and_citing_review_is_affected(tmp_path):
    assert exercised(tmp_path)["vex_status"] == "affected"


def test_passed_gate_without_citing_review_waits(tmp_path):
    c = exercised(tmp_path, cite=False)
    assert c["vex_status"] == "under_investigation" and c["substate"] == "candidate_awaiting_review"


def test_failed_gate_is_inconclusive_even_with_review(tmp_path):
    c = exercised(tmp_path, rows=("affected_evidence", "inconclusive"))
    assert c["vex_status"] == "under_investigation" and c["substate"] == "inconclusive"
    assert "e2a: trigger_counts" in c["status_note"]


def test_gate_for_another_binary_is_invalid(tmp_path):
    c = exercised(tmp_path, binary_bytes=b"another binary")
    assert c["vex_status"] == "under_investigation" and c["substate"] == "gate_invalid"


def test_gate_for_another_osv_is_invalid(tmp_path):
    def rename(tp, gd):
        (gd / "GO-2.json").rename(gd / "GO-1.json")
    c = exercised(tmp_path, osv="GO-2", tamper=rename, cite=False)
    assert c["vex_status"] == "under_investigation" and c["substate"] == "gate_invalid"


def test_changed_evidence_invalidates_the_gate(tmp_path):
    def edit(tp, gd):
        (tp / "run0" / "results.tsv").write_text("edited")
    c = exercised(tmp_path, tamper=edit)
    assert c["vex_status"] == "under_investigation" and c["substate"] == "gate_invalid"
    assert "evidence changed" in c["status_note"]


def test_gate_whose_result_does_not_match_its_runs_is_invalid(tmp_path):
    def lie(tp, gd):
        g = json.loads((gd / "GO-1.json").read_text())
        g["result"] = "passed"
        (gd / "GO-1.json").write_text(json.dumps(g))
    c = exercised(tmp_path, rows=("affected_evidence", "inconclusive"), tamper=lie)
    assert c["vex_status"] == "under_investigation" and c["substate"] == "gate_invalid"


def test_malformed_gate_is_invalid(tmp_path):
    def garble(tp, gd):
        (gd / "GO-1.json").write_text("{not json")
    c = exercised(tmp_path, tamper=garble, cite=False)
    assert c["vex_status"] == "under_investigation" and c["substate"] == "gate_invalid"


def test_zero_runs_cannot_pass(tmp_path):
    with pytest.raises(SystemExit):
        make_gate(tmp_path, b"x", rows=())


def test_rejected_candidate_with_failed_gate_keeps_both_dimensions(tmp_path):
    c = exercised(tmp_path, verdict="rejected", rows=("affected_evidence", "inconclusive"))
    assert c["substate_dimensions"]["review"] == "rejected" and c["substate_dimensions"]["trigger"] == "inconclusive"


def test_headline_order_of_gate_states():
    import importlib.util
    spec = importlib.util.spec_from_file_location("autochain", f"{ROOT}/lab/autochain.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    o = m.HEADLINE_ORDER
    assert o.index("instrumentation_failed") < o.index("gate_invalid") < o.index("not_measured") < o.index("inconclusive") \
        < o.index("unevaluated") < o.index("candidate_awaiting_review") < o.index("rejected")


def test_no_gate_file_is_unevaluated(tmp_path):
    raw = b"m/p.(*T).F"
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="confirmed")
    d = tmp_path / "gates"
    d.mkdir()
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], raw, "symbol", extra=args + ["--exercise", str(d)])
    assert c["vex_status"] == "under_investigation" and c["substate"] == "unevaluated"


def test_rejected_candidate_stays_rejected_under_the_gate_policy(tmp_path):
    raw = b"m/p.(*T).F"
    args = runtime_inputs(tmp_path, executed=True, request_sinks=2, verdict="rejected")
    d = tmp_path / "gates"
    d.mkdir()
    c = run(tmp_path, IMP, ["m/p.(*T).F", "m/p.G"], raw, "symbol", extra=args + ["--exercise", str(d)])
    assert c["vex_status"] == "under_investigation" and c["substate"] == "rejected"


def test_incomplete_manifest_invalidates_the_gate(tmp_path):
    def drop(tp, gd):
        g = json.loads((gd / "GO-1.json").read_text())
        g["runs"][0]["files"] = {"status.json": g["runs"][0]["files"]["status.json"]}
        (gd / "GO-1.json").write_text(json.dumps(g))
        for f in ("results.tsv", "resolved.json", "e2a-perf.data"):
            (tp / "run0" / f).unlink()
    c = exercised(tmp_path, tamper=drop)
    assert c["substate"] == "gate_invalid" and "incomplete evidence manifest" in c["status_note"]


def test_inflated_counter_invalidates_the_gate(tmp_path):
    def inflate(tp, gd):
        g = json.loads((gd / "GO-1.json").read_text())
        g["affected_evidence_runs"] = 99
        (gd / "GO-1.json").write_text(json.dumps(g))
    c = exercised(tmp_path, tamper=inflate)
    assert c["substate"] == "gate_invalid" and "inconsistent counters" in c["status_note"]
