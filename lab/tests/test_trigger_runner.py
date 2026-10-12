"""TriggerTest runner: arm resolution from OSV ranges, payload generators, oracle evaluation (no podman needed)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "trigger"))
import runner  # noqa: E402

OSV = {"affected": [{"package": {"name": "stdlib"}, "ranges": [{"events": [
    {"introduced": "0"}, {"fixed": "1.26.9"}, {"introduced": "1.27.0-0"}, {"fixed": "1.27.2"}]}]}]}


def test_arm_resolution():
    fixes = runner.stdlib_fixes(OSV)
    assert runner.arm_go({"go": "firstFixed"}, fixes) == "1.26.9"
    assert runner.arm_go({"go": "lastVulnerable"}, fixes) == "1.26.8"
    assert runner.arm_go({"go": "1.25.3"}, fixes) == "1.25.3"


def test_payload_generators():
    _, h = runner.payload({"path": "/x", "payload": {"generator": "http-range", "header": "Range", "count": "{{n}}"}}, {"n": 3})
    assert h["Range"] == "bytes=0-0,2-2,4-4"
    p, _ = runner.payload({"path": "/x?a=1", "payload": {"generator": "query-params", "count": "2"}}, {})
    assert p == "/x?a=1&p0=1&p1=1"


def rows(arm, status, cpus):
    return [{"arm": arm, "n": n, "status": status, "server_cpu_s": c} for n, c in cpus.items()]


ORACLE = [{"arms": ["vuln"], "when": "n > 200", "expect": {"status": 206, "serverCPU": "growsWith(n)"}},
          {"arms": ["fixed"], "when": "n > 200", "expect": {"status": 200, "serverCPUMax": "0.05s"}}]


def test_oracle_holds():
    r = rows("vuln", 206, {1: 0.01, 250: 0.02, 50000: 0.7}) + rows("fixed", 200, {250: 0.02, 50000: 0.02})
    assert all(x["ok"] for x in runner.evaluate(ORACLE, r, "n"))


def test_oracle_fails_without_growth():
    r = rows("vuln", 206, {250: 0.02, 50000: 0.03}) + rows("fixed", 200, {250: 0.02, 50000: 0.02})
    ev = runner.evaluate(ORACLE, r, "n")
    assert not ev[0]["ok"] and ev[1]["ok"]


def test_when_filter():
    assert runner.when_ok("n > 200", {"n": 250}) and not runner.when_ok("n > 200", {"n": 150})


# --- lab-only safety: the spec cannot name a target, a token, or oversize requests ---

import copy  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

SMOKE = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "trigger", "smoke-go-2026-6609.yaml")))["spec"]


def test_smoke_spec_passes():
    runner.check_spec(copy.deepcopy(SMOKE))


@pytest.mark.parametrize("mutate", [
    lambda s: s["safety"].update(environment="staging"),
    lambda s: s["runtime"]["auth"].update(tokenSource="file"),
    lambda s: s["runtime"]["auth"].update(value="a-fixed-credential"),
    lambda s: s["runtime"].update(host="10.0.0.1"),
    lambda s: s["runtime"].update(kubeconfig="~/.kube/config"),
    lambda s: s["trigger"]["request"].update(url="https://example.com/openapi/v2"),
    lambda s: s["trigger"]["parameters"].update(n=[500000]),
])
def test_unsafe_specs_are_refused(mutate):
    s = copy.deepcopy(SMOKE)
    mutate(s)
    with pytest.raises(SystemExit):
        runner.check_spec(s)
