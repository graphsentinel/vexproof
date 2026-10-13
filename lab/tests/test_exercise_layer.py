"""exercise layer (P1): argument provenance (E2a), the new oracle checks and the row-1 decision, on synthetic inputs."""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "lab", "trigger"))
import attribution as A  # noqa: E402
import runner as R  # noqa: E402

REQ = {"path": "/x", "payload": {"generator": "http-range", "header": "Range", "count": "{{n}}", "marker": True}}


def arg(n, mk):
    return R.payload(REQ, {"n": n}, mk)[1]["Range"].encode()


def hit(b, length=None):
    return {"length": len(b) if length is None else length, "prefix": b[:64], "stack": []}


def window(calib_n=(2, 4, 12), trig_n=(50000,), other_n=(1,)):
    mk = iter(range(10001, 99999, 2))
    calib = {m: arg(n, m) for n in calib_n for m in [next(mk)]}
    trig = {m: arg(n, m) for n in trig_n for m in [next(mk)]}
    other = {m: arg(n, m) for n in other_n for m in [next(mk)]}
    return calib, trig, other


def test_marker_keeps_the_range_count():
    h = R.payload(REQ, {"n": 5}, 12345)[1]["Range"]
    assert h.startswith("bytes=12345-12345,") and h.count(",") == 4
    assert R.payload({**REQ, "payload": {**REQ["payload"], "marker": False}}, {"n": 3})[1]["Range"] == "bytes=0-0,2-2,4-4"


def test_all_marked_hits_attribute():
    c, t, o = window()
    hits = [hit(v) for v in [*c.values(), *t.values(), *o.values()]] + [hit(b"", 0)] * 8  # internal calls
    r = A.evaluate(hits, 0, 0, c, t, o)
    assert r["state"] == "attributed_client" and r["unmatched_hits"] == 8


def test_missing_trigger_hit_is_incomplete():
    c, t, o = window()
    r = A.evaluate([hit(v) for v in [*c.values(), *o.values()]], 0, 0, c, t, o)
    assert r["state"] == "attribution_incomplete"


def test_duplicate_cannot_hide_a_missing_hit():
    c, t, o = window(trig_n=(50000, 50000))
    k1, k2 = list(t)
    hits = [hit(v) for v in [*c.values(), *o.values()]] + [hit(t[k1]), hit(t[k1])]
    assert A.evaluate(hits, 0, 0, c, t, o)["state"] == "attribution_incomplete"


def test_lost_events_or_failed_reads_fail_instrumentation():
    c, t, o = window()
    hits = [hit(v) for v in [*c.values(), *t.values(), *o.values()]]
    assert A.evaluate(hits, 1, 0, c, t, o)["state"] == "instrumentation_failed"
    assert A.evaluate(hits, 0, 1, c, t, o)["state"] == "instrumentation_failed"


def test_calibration_needs_three_distinct_lengths_one_over_64():
    c, t, o = window(calib_n=(2, 4, 4))
    hits = [hit(v) for v in [*c.values(), *t.values(), *o.values()]]
    assert A.evaluate(hits, 0, 0, c, t, o)["state"] == "instrumentation_failed"
    c, t, o = window(calib_n=(2, 3, 4))  # all shorter than 64 bytes
    hits = [hit(v) for v in [*c.values(), *t.values(), *o.values()]]
    assert A.evaluate(hits, 0, 0, c, t, o)["state"] == "instrumentation_failed"


def test_wrong_register_fails_calibration():
    c, t, o = window()
    # a wrong register map reads e.g. the size argument as length: no hit matches any calibration request
    hits = [hit(v, length=3_000_000) for v in [*c.values(), *t.values(), *o.values()]]
    assert A.evaluate(hits, 0, 0, c, t, o)["state"] == "instrumentation_failed"


def test_same_length_other_prefix_is_not_a_match():
    c, t, o = window()
    k = next(iter(t))
    forged = b"bytes=99999-99999" + t[k][17:]
    hits = [hit(v) for v in [*c.values(), *o.values()]] + [hit(forged)]
    assert A.evaluate(hits, 0, 0, c, t, o)["state"] == "attribution_incomplete"


def test_prologue_pinning(tmp_path):
    b = tmp_path / "b"
    b.write_bytes(b"\x4c\x8d\x64\x24\xd8\x4d\x3b\x66\x10\x0f\x86" + b"\x90" * 16)
    assert A.pin_decoding(str(b), 0, "amd64", "1.20.8")["abi"] == "amd64 ABIInternal"
    with pytest.raises(SystemExit):
        A.pin_decoding(str(b), 1, "amd64", "1.20.8")
    with pytest.raises(SystemExit):
        A.pin_decoding(str(b), 0, "arm64", "1.20.8")
    with pytest.raises(SystemExit):
        A.pin_decoding(str(b), 0, "amd64", "1.16.15")


def test_parse_perf_script(tmp_path):
    lst = tmp_path / "l.txt"
    lst.write_text("0x1000\tnet/http.parseRange\tfs.go:1\n0x2000\tmain.handler\tm.go:1\n")
    words = (b"bytes=1" + b"\x00" * 57)
    w = " ".join(f"w{i}={int.from_bytes(words[8 * i:8 * i + 8], 'little'):#x}" for i in range(8))
    script = (f"vxl5_r:arg: (1000) len=7 {w}\n\t    1000\n\t    2010\n\n"
              f"vxl5_r:arg: (1000) len=(fault) w0=0\n\t    1000\n")
    hits, lost, failed = A.parse(script, "", A.Listing(str(lst)))
    assert hits == [{"length": 7, "prefix": b"bytes=1", "stack": ["net/http.parseRange", "main.handler"]}]
    assert (lost, failed) == (0, 1)
    assert A.parse("LOST 3 events!\n", "LOST events: 2\n", A.Listing(str(lst)))[1] == 5


ORACLE = [{"arms": ["shipped"], "when": "n > 200", "expect": {"status": 206, "separation": {"benign": "n == 1", "factor": 5}}},
          {"arms": ["baseline"], "when": "n > 200", "expect": {"status": 206, "separation": {"benign": "n == 1", "factor": 5},
                                                              "statusSameAs": "shipped"}}]


def rows(arm, benign, trig, st=206):
    return ([{"arm": arm, "n": 1, "status": 206, "server_cpu_s": x} for x in benign]
            + [{"arm": arm, "n": 50000, "status": st, "server_cpu_s": x} for x in trig])


def test_separation_needs_every_trigger_above_every_benign():
    ok = R.evaluate(ORACLE[:1], rows("shipped", [0.01] * 5, [0.6, 0.7, 0.65, 0.8, 0.9]), "n")
    assert ok[0]["ok"]
    bad = R.evaluate(ORACLE[:1], rows("shipped", [0.01, 0.01, 0.2, 0.01, 0.01], [0.6, 0.7, 0.65, 0.8, 0.9]), "n")
    assert not bad[0]["ok"]


def test_baseline_must_answer_like_shipped():
    rs = rows("shipped", [0.01] * 5, [0.7] * 5) + rows("baseline", [0.01] * 5, [0.7] * 5, st=200)
    ev = R.evaluate(ORACLE, rs, "n")
    assert ev[0]["ok"] and not ev[1]["ok"]


SPEC = {"attribution": {"rule": {"shippedRules": [["shipped"]], "baselineRules": [["baseline"]],
                                 "vulnerableRules": [["vulnerable-rebuild"]], "fixedRules": [["fixed-rebuild"]]}}}


def ev(**ok):
    return [{"arms": [a], "ok": ok.get(a.replace("-", "_"), True)} for a in ("shipped", "baseline", "vulnerable-rebuild", "fixed-rebuild")]


def test_row1_affected_only_with_every_condition():
    good = {"state": "attributed_client"}
    assert R.row1(SPEC, ev(), [{"ok": True}], "triggered", good)["result"] == "affected_evidence"
    assert R.row1(SPEC, ev(), [{"ok": True}], "triggered", {"state": "attribution_incomplete"})["result"] == "attribution_incomplete"
    assert R.row1(SPEC, ev(), [{"ok": True}], "triggered", {"state": "instrumentation_failed"})["result"] == "instrumentation_failed"
    assert R.row1(SPEC, ev(), [{"ok": True}], "triggered", None)["result"] != "affected_evidence"
    assert R.row1(SPEC, ev(fixed_rebuild=False), [{"ok": True}], "inconclusive", good)["result"] == "inconclusive"
    assert R.row1(SPEC, ev(vulnerable_rebuild=False), [{"ok": True}], "not-triggered", good)["result"] == "trigger_not_validated"
    assert R.row1(SPEC, ev(baseline=False), [{"ok": True}], "not-triggered", good)["result"] == "arm_unavailable"
    assert R.row1(SPEC, ev(shipped=False), [{"ok": True}], "not-triggered", good)["result"] == "shipped_not_triggered_cause_unknown"
    assert R.row1(SPEC, ev(), [{"ok": False}], "inconclusive", good)["result"] == "inconclusive"


def test_row1_needs_every_rule_of_an_arm():
    e = ev() + [{"arms": ["fixed-rebuild"], "ok": False}]
    assert R.row1(SPEC, e, [{"ok": True}], "triggered", {"state": "attributed_client"})["result"] != "affected_evidence"


def test_fixed_arm_cap_is_relative_to_the_shipped_whole_document():
    rule = [{"arms": ["fixed-rebuild"], "when": "n > 200",
             "expect": {"status": 200, "maxCPUBelow": {"arm": "shipped", "when": "n == 0", "factor": 5}}}]
    whole = [{"arm": "shipped", "n": 0, "status": 200, "server_cpu_s": x} for x in (0.04, 0.05, 0.05, 0.06, 0.05)]
    fixed = [{"arm": "fixed-rebuild", "n": 50000, "status": 200, "server_cpu_s": x} for x in (0.04, 0.1, 0.06, 0.05, 0.05)]
    assert R.evaluate(rule, whole + fixed, "n")[0]["ok"]
    slow = fixed[:4] + [{"arm": "fixed-rebuild", "n": 50000, "status": 200, "server_cpu_s": 0.3}]
    assert not R.evaluate(rule, whole + slow, "n")[0]["ok"]


def test_whole_document_request_has_no_range():
    assert "Range" not in R.payload(REQ, {"n": 0}, None)[1]
