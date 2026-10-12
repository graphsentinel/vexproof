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
