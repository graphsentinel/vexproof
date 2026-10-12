"""V7 review: missing or contradictory evidence must never become not_affected (synthetic inputs)."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
COLS = "run target osv aliases L1_trivy L3_level package symbols sym_found blocks blocks_hit L4 verdict".split()


def run(tmp_path, rows, chain, pclnsym=None, pkgs=("p", "q"), affected=None, gv_extra=(), extra=None, target="t"):
    m = tmp_path / "m.tsv"
    m.write_text("\t".join(COLS) + "\n" + "".join("\t".join(r.get(c, "-") for c in COLS) + "\n" for r in rows))
    affected = affected if affected is not None else [{"package": {"name": "m"}, "ecosystem_specific": {
        "imports": [{"path": p} for p in pkgs]}}]
    osv = {"osv": {"id": "GO-1", "affected": affected}}
    objs = ([osv] if pkgs or affected else []) + list(gv_extra)
    (tmp_path / "gv.json").write_text("\n".join(json.dumps(o) for o in objs))
    cfg = {"measurements": str(m), "govulncheck": {"t": str(tmp_path / "gv.json"), "u": str(tmp_path / "gv.json")},
           "pclnsym": pclnsym or [], "products": {"t": "pkg:golang/x", "u": "pkg:golang/y"}, "evidence_base": "x",
           "vex_id": "x", "author": "x", "openvex_out": str(tmp_path / "vex.json"),
           "chains": [dict(target="t", osv="GO-1", **chain)]}
    cfg.update(extra or {})
    (tmp_path / "c.json").write_text(json.dumps(cfg))
    subprocess.run([sys.executable, f"{ROOT}/lab/chain.py", str(tmp_path / "c.json")], check=True, capture_output=True)
    return json.load(open(tmp_path / f"{target}--GO-1.json"))


RULE = {"entry": "e.Serve", "reason": "the call path passes the connection handler"}
ON_PATH = {"finding": {"osv": "GO-1", "trace": [{"package": "p", "function": "F"}, {"package": "e", "function": "Serve"}]}}


def inv(tmp_path, *names, name="inv.txt"):
    f = tmp_path / name
    f.write_text("".join(f"0x{i + 1}\t{n}\tf.go:1\n" for i, n in enumerate(names)))
    return [str(f)]



def row(**kw):
    r = {"run": "x", "target": "t", "osv": "GO-1", "L1_trivy": "yes", "L3_level": "package", "package": "p",
         "blocks_hit": "0", "L4": "not-observed"}
    r.update(kw)
    return r


def test_no_rows(tmp_path):
    assert run(tmp_path, [], {})["vex_status"] == "under_investigation"


def test_not_linked_without_shipped_check(tmp_path):
    assert run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {})["vex_status"] == "under_investigation"


def test_symbols_checked_against_empty_inventory(tmp_path):
    inv = tmp_path / "inv.txt"
    inv.write_text("")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {"symbols_shipped": ["m/p.F"]}, [str(inv)])
    assert c["vex_status"] == "under_investigation"


def test_shipped_absent_with_nonempty_inventory(tmp_path):
    inv = tmp_path / "inv.txt"
    inv.write_text("0x1\tm/p.G\tf.go:1\n")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]},
            [str(inv)])
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_present")


def test_shipped_absent_without_positive_control(tmp_path):
    inv = tmp_path / "inv.txt"
    inv.write_text("0x1\tm/p.G\tf.go:1\n")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.H"]},
            [str(inv)])
    assert c["vex_status"] == "under_investigation"


def test_absent_and_trivy_silent(tmp_path):
    assert run(tmp_path, [row(L4="absent", L3_level="none", L1_trivy="no")], {})["vex_status"] == "under_investigation"


def test_missing_l3(tmp_path):
    assert run(tmp_path, [row(L3_level="-")], {})["vex_status"] == "under_investigation"


def test_mixed_not_linked_and_not_observed(tmp_path):
    rows = [row(L4="not-observed"), row(package="q", L4="not-linked", blocks_hit="-")]
    assert run(tmp_path, rows, {})["vex_status"] == "under_investigation"


def test_only_measured_unreachable_is_not_in_execute_path(tmp_path):
    c = run(tmp_path, [row(), row(package="q")], {})
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_in_execute_path")


def test_inventory_scoped_to_target(tmp_path):
    inv = tmp_path / "inv.txt"
    inv.write_text("0x1\tm/p.G\tf.go:1\n")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]},
            {"other-target": [str(inv)]})
    assert c["vex_status"] == "under_investigation"


def test_absent_but_trivy_lists_it(tmp_path):
    assert run(tmp_path, [row(L4="absent", L3_level="none")], {})["vex_status"] == "under_investigation"


def test_one_package_uninstrumented(tmp_path):
    rows = [row(L4="not-observed"), row(package="q", L4="not-instrumented", blocks_hit="-")]
    assert run(tmp_path, rows, {})["vex_status"] == "under_investigation"


def test_symbol_level_not_observed(tmp_path):
    assert run(tmp_path, [row(L3_level="symbol")], {})["vex_status"] == "under_investigation"


def test_executed_without_taint_is_not_affected_never(tmp_path):
    c = run(tmp_path, [row(L3_level="symbol", L4="executed", blocks_hit="5")], {})
    assert c["vex_status"] == "under_investigation" and c["status_note"].startswith("executed")


def test_control_from_another_package(tmp_path):
    inv = tmp_path / "inv.txt"
    inv.write_text("0x1\tother/x.G\tf.go:1\n")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")], {"symbols_shipped": ["m/p.F"], "inventory_control": ["other/x.G"]},
            [str(inv)])
    assert c["vex_status"] == "under_investigation"


def test_missing_package_row(tmp_path):
    assert run(tmp_path, [row()], {})["vex_status"] == "under_investigation"


def test_osv_package_list_unavailable(tmp_path):
    assert run(tmp_path, [row(), row(package="q")], {}, pkgs=())["vex_status"] == "under_investigation"


def test_contradictory_row(tmp_path):
    rows = [row(blocks_hit="5"), row(package="q")]
    assert run(tmp_path, rows, {})["vex_status"] == "under_investigation"


# --- round 4 (re-review of the round-3 fixes) ---

def test_control_prefix_must_stop_at_package_boundary(tmp_path):
    for shipped, ctl in (("m/p.F", "m/pq.G"), ("m/payroll.F", "m/p.G")):
        c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
                {"symbols_shipped": [shipped], "inventory_control": [ctl]}, inv(tmp_path, ctl))
        assert c["vex_status"] == "under_investigation", (shipped, ctl)


def test_control_from_parent_package_at_boundary_is_accepted(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["~m/p/ssh."], "inventory_control": ["~m/p/"]}, inv(tmp_path, "m/p/cipher.G"))
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_present")


def test_unqualified_control_does_not_match_unrelated_package(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["resource.F"], "inventory_control": ["resource.G"]}, inv(tmp_path, "unrelated/resource.G"))
    assert c["vex_status"] == "under_investigation"


def test_control_must_match_exactly_not_as_suffix(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, inv(tmp_path, "x/m/p.G"))
    assert c["vex_status"] == "under_investigation"


def test_tilde_control_must_end_at_a_boundary(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["~m/p."], "inventory_control": ["~m/p"]}, inv(tmp_path, "m/p.G"))


def test_contradictory_row_blocks_not_present_too(tmp_path):
    c = run(tmp_path, [row(blocks_hit="5"), row(package="q")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, inv(tmp_path, "m/p.G"))
    assert c["vex_status"] == "under_investigation"


@pytest.mark.parametrize("hit", ["-", "unknown", "-1", " 5"])
def test_not_observed_needs_a_zero_count(tmp_path, hit):
    assert run(tmp_path, [row(blocks_hit=hit), row(package="q")], {})["vex_status"] == "under_investigation"


@pytest.mark.parametrize("hit", ["0", "-"])
def test_executed_label_without_positive_count_is_not_execution(tmp_path, hit):
    c = run(tmp_path, [row(L4="executed", blocks_hit=hit)], {"untrusted_by_rule": RULE}, gv_extra=[ON_PATH])
    assert c["vex_status"] == "under_investigation"


def sarif(tmp_path, results):
    f = tmp_path / "t.sarif"
    f.write_text(json.dumps({"runs": [{"results": results}]}))
    return str(f)


def flow(*uris):
    return {"threadFlows": [{"locations": [{"location": {"physicalLocation": {
        "artifactLocation": {"uri": u}, "region": {"startLine": 1}}}} for u in uris]}]}


def test_empty_sarif_flow_is_not_taint(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-1-taint", "codeFlows": [flow()]}]), "taint_sink_sites": 1})
    assert c["vex_status"] == "under_investigation"


def test_sarif_of_another_rule_is_not_taint(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-2-taint", "codeFlows": [flow("a.go", "b.go")]}])})
    assert c["vex_status"] == "under_investigation"


def test_location_only_sarif_result_is_not_taint(tmp_path):
    res = {"ruleId": "x/go-1-taint", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.go"},
                                                                          "region": {"startLine": 1}}}]}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [res])})
    assert c["vex_status"] == "under_investigation"


def test_sarif_result_without_flow_or_location_does_not_crash(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-1"}])})
    assert c["vex_status"] == "under_investigation"


def test_matching_sarif_flow_gives_affected(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-1-taint", "codeFlows": [flow("a.go", "b.go")]}])})
    assert c["vex_status"] == "affected"


def test_uprobe_profile_list_rejected_for_several_targets(tmp_path):
    prof = tmp_path / "up.txt"
    prof.write_text("p_F 5\n")
    two = [dict(target=t, osv="GO-1", uprobes=["p_F"], untrusted_by_rule=RULE) for t in ("t", "u")]
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [], {}, extra={"chains": two, "uprobe_profiles": [str(prof)]})


def test_uprobe_hits_count_only_for_their_target(tmp_path):
    prof = tmp_path / "up.txt"
    prof.write_text("p_F 5\n")
    two = [dict(target=t, osv="GO-1", uprobes=["p_F"], untrusted_by_rule=RULE) for t in ("t", "u")]
    extra = {"chains": two, "uprobe_profiles": {"t": [str(prof)]}}
    assert run(tmp_path, [], {}, extra=extra, gv_extra=[ON_PATH])["vex_status"] == "affected"
    assert run(tmp_path, [], {}, extra=extra, gv_extra=[ON_PATH], target="u")["vex_status"] == "under_investigation"


def test_malformed_uprobe_profile_stops(tmp_path):
    prof = tmp_path / "up.txt"
    prof.write_text("p_F garbage\n")
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row()], {"uprobes": ["p_F"]}, extra={"uprobe_profiles": [str(prof)]})


def test_symbol_level_finding_in_stream_blocks_not_in_execute_path(tmp_path):
    finding = {"finding": {"osv": "GO-1", "trace": [{"package": "p", "function": "F"}]}}
    assert run(tmp_path, [row(), row(package="q")], {}, gv_extra=[finding])["vex_status"] == "under_investigation"


def test_stdlib_package_named_by_the_osv_needs_a_row(tmp_path):
    aff = [{"package": {"name": "m"}, "ecosystem_specific": {"imports": [{"path": "p"}]}},
           {"package": {"name": "stdlib"}, "ecosystem_specific": {"imports": [{"path": "net/http"}]}}]
    assert run(tmp_path, [row()], {}, affected=aff)["vex_status"] == "under_investigation"


def test_two_column_inventory_stops(tmp_path):
    f = tmp_path / "inv.txt"
    f.write_text("0x1\tm/p.F\n0x2\tm/p.G\tf.go:1\n")
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, [str(f)])


def test_escaped_last_path_element(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["gopkg.in/yaml%2ev3.F"], "inventory_control": ["gopkg.in/yaml%2ev3.G"]},
            inv(tmp_path, "gopkg.in/yaml%2ev3.G"))
    assert (c["vex_status"], c["vex_justification"]) == ("not_affected", "vulnerable_code_not_present")


def test_missing_govulncheck_target_does_not_crash(tmp_path):
    c = run(tmp_path, [row(), row(package="q")], {}, extra={"govulncheck": {}})
    assert c["vex_status"] == "under_investigation"


# --- round 5 ---

@pytest.mark.parametrize("hit", ["unknown", "-", "-1", "\u00b2"])
def test_unknown_count_blocks_not_present_too(tmp_path, hit):
    c = run(tmp_path, [row(blocks_hit=hit)], {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]},
            inv(tmp_path, "m/p.G"))
    assert c["vex_status"] == "under_investigation"


def test_rule_id_must_name_the_osv_as_a_token(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-10-taint", "codeFlows": [flow("a.go", "b.go")]}])})
    assert c["vex_status"] == "under_investigation"


def test_flow_steps_without_location_are_not_a_path(tmp_path):
    res = {"ruleId": "GO-1", "codeFlows": [{"threadFlows": [{"locations": [{}, {}]}]}]}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [res])})
    assert c["vex_status"] == "under_investigation"


@pytest.mark.parametrize("line", ["0xZ\tm/p.G\t\n", "junk\tm/p.G\tf.go:1\n", "0x1\tm/p.G\tf.go\n"])
def test_invalid_inventory_lines_stop(tmp_path, line):
    f = tmp_path / "inv.txt"
    f.write_text(line)
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, [str(f)])


def test_inventory_names_may_contain_spaces(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]},
            inv(tmp_path, "m/p.G", "type:.eq.struct { A int }"))
    assert c["vex_status"] == "not_affected"


def test_unescaped_config_name_finds_escaped_listing(tmp_path):
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["gopkg.in/yaml.v3.F"], "inventory_control": ["~gopkg.in/"]},
            inv(tmp_path, "gopkg.in/yaml%2ev3.F"))
    assert c["vex_status"] == "under_investigation" and c["shipped_binary_symbols_present"]


def test_execution_in_another_package_does_not_count(tmp_path):
    c = run(tmp_path, [row(package="m/unrelated", L4="executed", blocks_hit="1")], {"untrusted_by_rule": RULE},
            gv_extra=[ON_PATH])
    assert c["vex_status"] == "under_investigation"


def test_uprobe_hits_take_the_maximum_over_profiles(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("p_F 5\n")
    b.write_text("p_F 0\n")
    c = run(tmp_path, [row(), row(package="q")], {"uprobes": ["p_F"]}, extra={"uprobe_profiles": [str(a), str(b)]})
    assert c["vex_status"] == "under_investigation" and c["L4b_uprobes"] == {"p_F": 5}


def test_functions_without_source_file_are_valid_lines(tmp_path):
    f = tmp_path / "inv.txt"
    f.write_text("0x401420\tcrosscall1\t:-1\n0x2\tm/p.G\tf.go:1\n")
    c = run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, [str(f)])
    assert c["vex_status"] == "not_affected"


# --- round 6 ---

def test_unknown_count_on_any_label_blocks(tmp_path):
    c = run(tmp_path, [row(L4="not-instrumented", blocks_hit="unknown")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, inv(tmp_path, "m/p.G"))
    assert c["vex_status"] == "under_investigation"


def test_rule_id_token_ends_before_a_letter(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": sarif(tmp_path, [{"ruleId": "x/go-1abc", "codeFlows": [flow("a.go", "b.go")]}])})
    assert c["vex_status"] == "under_investigation"


@pytest.mark.parametrize("pos", [":0", "f.go:-2", "f.go:0"])
def test_inventory_positions_are_file_line_or_minus_one(tmp_path, pos):
    f = tmp_path / "inv.txt"
    f.write_text(f"0x1\tm/p.G\t{pos}\n")
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, [str(f)])


def test_configured_sarif_must_exist(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"taint_sarif": str(tmp_path / "missing.sarif"), "untrusted_by_rule": RULE}, gv_extra=[ON_PATH])


# --- round 7 ---

def test_generic_instantiation_in_listing_counts_as_present(tmp_path):
    c = run(tmp_path, [row(package="m/p", L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p.(*T).F"], "inventory_control": ["m/p.G"]},
            inv(tmp_path, "m/p.G", "m/p.(*T[go.shape.int]).F"), pkgs=("m/p",))
    assert c["vex_status"] == "under_investigation" and c["shipped_binary_symbols_present"]


def test_execution_in_another_package_blocks_absence(tmp_path):
    c = run(tmp_path, [row(package="vendor/m/p", L4="executed", blocks_hit="1")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, inv(tmp_path, "m/p.G"), pkgs=("m/p",))
    assert c["vex_status"] == "under_investigation"


def test_execution_with_symbols_absent_is_disagreement(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"], "untrusted_by_rule": RULE},
            inv(tmp_path, "m/p.G"), gv_extra=[ON_PATH])
    assert c["vex_status"] == "under_investigation" and "disagree" in c["status_note"]


def test_escaped_package_in_row_matches_osv_import(tmp_path):
    finding = {"finding": {"osv": "GO-1", "trace": [{"package": "m/p.v3", "function": "F"},
                                                    {"package": "e", "function": "Serve"}]}}
    c = run(tmp_path, [row(package="m/p%2ev3", L4="executed", blocks_hit="5")], {"untrusted_by_rule": RULE},
            pkgs=("m/p.v3",), gv_extra=[finding])
    assert c["vex_status"] == "affected"


# --- round 8 ---

def test_escaped_generic_presence(tmp_path):
    c = run(tmp_path, [row(package="m/p.v3", L4="not-linked", blocks_hit="-")],
            {"symbols_shipped": ["m/p%2ev3.(*T).F"], "inventory_control": ["m/p%2ev3.G"]},
            inv(tmp_path, "m/p%2ev3.G", "m/p%2ev3.(*T[go.shape.int]).F"), pkgs=("m/p.v3",))
    assert c["vex_status"] == "under_investigation"


def test_escaped_zero_row_covers_import(tmp_path):
    c = run(tmp_path, [row(package="m/p%2ev3")], {}, pkgs=("m/p.v3",))
    assert c["vex_status"] == "not_affected"


def test_non_string_sarif_uri_is_no_step(tmp_path):
    res = {"ruleId": "GO-1", "codeFlows": [{"threadFlows": [{"locations": [
        {"location": {"physicalLocation": {"artifactLocation": {"uri": 7}}}}] * 2}]}]}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [res])})
    assert c["vex_status"] == "under_investigation"


def test_per_target_files_must_be_lists(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row()], {}, extra={"uprobe_profiles": {"t": "a.txt"}})


# --- round 9 ---

def test_duplicate_osv_cannot_hide_package(tmp_path):
    later = {"osv": {"id": "GO-1", "affected": [{"package": {"name": "m"},
                                                 "ecosystem_specific": {"imports": [{"path": "p"}, {"path": "q"}]}}]}}
    c = run(tmp_path, [row()], {}, pkgs=("p",), gv_extra=[later])
    assert c["vex_status"] == "under_investigation"


def test_function_in_an_inner_trace_frame_is_symbol_level(tmp_path):
    finding = {"finding": {"osv": "GO-1", "trace": [{"package": "p"}, {"package": "p", "function": "F"}]}}
    assert run(tmp_path, [row(), row(package="q")], {}, gv_extra=[finding])["vex_status"] == "under_investigation"


# --- round 10 ---

def test_rule_must_be_entry_and_reason(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        run(tmp_path, [row(L4="executed", blocks_hit="5")], {"untrusted_by_rule": "TODO"}, gv_extra=[ON_PATH])


def test_rule_off_the_call_path_is_not_used(tmp_path):
    rule = {"entry": "x.Elsewhere", "reason": "r"}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"untrusted_by_rule": rule}, gv_extra=[ON_PATH])
    assert c["vex_status"] == "under_investigation" and c["taint_rule_unused"]


def test_rule_without_a_symbol_level_path_is_not_used(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"untrusted_by_rule": RULE})
    assert c["vex_status"] == "under_investigation"


def test_rule_on_the_path_with_execution_is_affected(tmp_path):
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"untrusted_by_rule": RULE}, gv_extra=[ON_PATH])
    assert c["vex_status"] == "affected" and c["taint_by_rule"] == RULE


def test_inner_function_retains_call_path(tmp_path):
    finding = {"finding": {"osv": "GO-1", "trace": [{"package": "p"}, {"package": "p", "function": "F"}]}}
    c = run(tmp_path, [row(), row(package="q")], {}, gv_extra=[finding])
    assert c["L3_level"] == "symbol" and c["L3_call_path"] is not None


# --- round 11 ---

def test_functionless_frame_cannot_authorize_rule(tmp_path):
    finding = {"finding": {"osv": "GO-1", "trace": [{"package": "p"}, {"package": "e", "function": "Serve"}]}}
    for entry in ("p.", "p", ""):
        rule = {"entry": entry or "x", "reason": "r"}
        c = run(tmp_path, [row(L4="executed", blocks_hit="1")], {"untrusted_by_rule": rule}, gv_extra=[finding])
        assert c["vex_status"] == "under_investigation", entry


def test_rule_on_a_longer_path_still_counts(tmp_path):
    shorter = {"finding": {"osv": "GO-1", "trace": [{"package": "p", "function": "F"}]}}
    c = run(tmp_path, [row(L4="executed", blocks_hit="1")], {"untrusted_by_rule": RULE}, gv_extra=[ON_PATH, shorter])
    assert c["vex_status"] == "affected" and any(fr["func"] == "e.Serve" for fr in c["taint_rule_call_path"])


# --- round 12 ---

def test_indexed_sarif_locations(tmp_path):
    f = sarif(tmp_path, [{"ruleId": "x/go-1-taint", "codeFlows": [flow("a.go", "b.go")]}])
    data = json.loads(open(f).read())
    r0 = data["runs"][0]
    r0["artifacts"] = [{"location": {"uri": "a.go"}}, {"location": {"uri": "b.go"}}]
    for i, loc in enumerate(r0["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]):
        loc["location"]["physicalLocation"]["artifactLocation"] = {"index": i}
    open(f, "w").write(json.dumps(data))
    assert run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": f})["vex_status"] == "affected"


def test_unresolved_sarif_index_is_no_step(tmp_path):
    loc = {"location": {"physicalLocation": {"artifactLocation": {"index": 9}}}}
    res = {"ruleId": "GO-1", "codeFlows": [{"threadFlows": [{"locations": [loc, loc]}]}]}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [res])})
    assert c["vex_status"] == "under_investigation"


@pytest.mark.parametrize("label", ["garbage", "", "not-linkd"])
def test_unknown_l4_label_blocks(tmp_path, label):
    c = run(tmp_path, [row(L4=label, blocks_hit="")],
            {"symbols_shipped": ["m/p.F"], "inventory_control": ["m/p.G"]}, inv(tmp_path, "m/p.G"))
    assert c["vex_status"] == "under_investigation"


def test_row_of_an_unnamed_package_cannot_stand_in_for_a_named_one(tmp_path):
    assert run(tmp_path, [row(package="p"), row(package="P")], {})["vex_status"] == "under_investigation"


# --- round 13 ---

@pytest.mark.parametrize("reference", ["rule", "steps"])
def test_indirect_sarif_evidence(tmp_path, reference):
    f = sarif(tmp_path, [{"ruleId": "GO-1", "codeFlows": [flow("a.go", "b.go")]}])
    data = json.loads(open(f).read())
    r = data["runs"][0]
    result = r["results"][0]
    if reference == "rule":
        r["tool"] = {"driver": {"name": "CodeQL", "rules": [{"id": "GO-1"}]}}
        del result["ruleId"]
        result["ruleIndex"] = 0
    else:
        tf = result["codeFlows"][0]["threadFlows"][0]
        r["threadFlowLocations"] = tf["locations"]
        tf["locations"] = [{"index": 0}, {"index": 1}]
    open(f, "w").write(json.dumps(data))
    assert run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": f})["vex_status"] == "affected"


def test_unresolved_rule_index_is_not_the_osv(tmp_path):
    res = {"ruleIndex": 5, "codeFlows": [flow("a.go", "b.go")]}
    c = run(tmp_path, [row(L4="executed", blocks_hit="5")], {"taint_sarif": sarif(tmp_path, [res])})
    assert c["vex_status"] == "under_investigation"
