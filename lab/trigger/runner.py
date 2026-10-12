#!/usr/bin/env python3
"""Local runner for a TriggerTest (deploy/crds/vexproof.graphsentinel.github.io_triggertests.yaml), with docker or podman.

Resolves the "auto" fields itself:
  - shipped binary: copied out of spec.target.binary.image (or downloaded from url), sha256-checked
  - build: Go version, tags, GOOS and the gitVersion/gitCommit stamped by ldflags, from `go version -m`
  - arms: lastVulnerable / firstFixed from the OSV entry's standard-library ranges (vuln.go.dev, cached)
Then builds the rebuilt arms (same source, go.mod untouched), records each arm's DefaultGODEBUG, runs every arm in its
own set of containers with the sidecars, sends the controls and the trigger requests, evaluates the oracle written in
the spec and writes the evidence. A failed trigger is "not-triggered", never not_affected.

Lab only (validation of a known, fixed vulnerability against the lab's own instance, never an attack tool):
  - The runner starts the target itself; a spec cannot name a host, URL or existing cluster to send requests to.
  - Each run creates its own CA, server certificate (name vexproof-lab-target), service-account keys and bearer token
    under lab/.runtime/trigger/<run>/pki (never written to the evidence). The spec's auth.tokenSource must be "lab-generated".
  - Before every request the runner checks that the container carrying the run's label is running and publishes the
    port it connects to, on 127.0.0.1 only; TLS trusts only the run's CA, checks the server name and the server
    certificate's fingerprint; any redirect is refused. Any mismatch stops the run.

usage: runner.py SPEC.yaml [--arms a,b] [--out DIR] [--status-to KUBE_CONTEXT]   (run from the project root)
       --status-to patches the TriggerTest's status in that cluster after the run
environment: ENGINE (docker | podman; default: docker if usable, else podman), VEXPROOF_RUNTIME (lab/.runtime),
             VEXPROOF_BASE_IMAGE (image the target binary runs in), GO_IMAGE (golang image template for builds)
"""
import argparse
import csv
import hashlib
import http.client
import itertools
import json
import os
import re
import secrets
import shutil
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNTIME = os.path.abspath(os.environ.get("VEXPROOF_RUNTIME", os.path.join(ROOT, "lab", ".runtime")))
GO_IMAGE = os.environ.get("GO_IMAGE", "docker.io/library/golang:{}")
BASE_IMAGE = os.environ.get("VEXPROOF_BASE_IMAGE", "docker.io/library/alpine:3.20")
LAB_NAME = "vexproof-lab-target"
LABEL = "vexproof.lab"


def engine():
    e = os.environ.get("ENGINE")
    if e:
        return e
    for cand in ("docker", "podman"):
        if shutil.which(cand) and subprocess.run([cand, "info"], capture_output=True).returncode == 0:
            return cand
    raise SystemExit("no usable container engine (docker or podman)")


ENGINE = None


def sh(*a, check=True, env=None, inp=None):
    p = subprocess.run(a, capture_output=True, text=True, env=env, input=inp)
    if check and p.returncode:
        raise SystemExit(f"command failed: {' '.join(a[:6])}...\n{p.stderr[-1500:]}")
    return p.stdout


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------- resolution ----------

def shipped_binary(spec, cache):
    b = spec["target"]["binary"]
    if not b.get("sha256"):
        raise SystemExit("spec.target.binary.sha256 is required")
    os.makedirs(cache, exist_ok=True)
    dst = os.path.join(cache, f"shipped-{b['sha256'][:16]}")
    if not os.path.exists(dst):
        tmp = dst + ".part"
        if b.get("image"):
            sh(ENGINE, "pull", "-q", b["image"])
            cid = sh(ENGINE, "create", b["image"]).strip()
            try:
                sh(ENGINE, "cp", f"{cid}:{b['path']}", tmp)
            finally:
                sh(ENGINE, "rm", cid, check=False)
        else:
            urllib.request.urlretrieve(b["url"], tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dst)
    digest = hashlib.sha256(open(dst, "rb").read()).hexdigest()
    if b["sha256"] != digest:
        os.remove(dst)
        raise SystemExit(f"sha256 mismatch for the shipped binary: {digest}")
    return dst, digest


def buildinfo(path, go="1.26.9"):
    if shutil.which("go"):
        txt = sh("go", "version", "-m", path)
    else:
        d = os.path.dirname(os.path.abspath(path))
        txt = sh(ENGINE, "run", "--rm", "-v", f"{d}:/b:ro", GO_IMAGE.format(go), "go", "version", "-m",
                 f"/b/{os.path.basename(path)}")
    info = {"go": re.search(r":\s+go(\S+)", txt).group(1), "raw": txt}
    for key, rx in (("tags", r"-tags=(\S+)"), ("goos", r"GOOS=(\S+)"), ("default_godebug", r"DefaultGODEBUG=(\S+)"),
                    ("git_version", r"gitVersion=([^' ]+)"), ("git_commit", r"gitCommit=([0-9a-f]{40})"),
                    ("vcs_revision", r"vcs.revision=([0-9a-f]+)"), ("path", r"\tpath\t(\S+)")):
        m = re.search(rx, txt)
        info[key] = m.group(1) if m else None
    return info


def osv_entry(osv_id, out):
    f = os.path.join(out, f"{osv_id}.json")
    if not os.path.exists(f):
        urllib.request.urlretrieve(f"https://vuln.go.dev/ID/{osv_id}.json", f)
    return json.load(open(f))


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def stdlib_fixes(osv):
    fixed = [e["fixed"] for a in osv["affected"] if a["package"]["name"] == "stdlib"
             for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
    if not fixed:
        raise SystemExit("this runner resolves Go toolchain arms only for standard-library entries")
    return sorted(fixed, key=vtuple)


def arm_go(arm, fixes):
    g = arm.get("go")
    if g == "firstFixed":
        return fixes[0]
    if g == "lastVulnerable":
        ma, mi, pa = vtuple(fixes[0])
        if pa == 0:
            raise SystemExit(f"{fixes[0]} is a .0 release: give lastVulnerable explicitly")
        return f"{ma}.{mi}.{pa - 1}"
    return g


def source_tree(src):
    """a checkout of spec.target.source: localPath (inside the project) or a shallow clone of repo@ref"""
    if src.get("localPath"):
        p = os.path.abspath(os.path.join(ROOT, src["localPath"]))
        if not os.path.isdir(p):
            raise SystemExit(f"source.localPath {src['localPath']} not found")
        return p
    d = os.path.join(RUNTIME, "src", re.sub(r"[^A-Za-z0-9.-]", "_", f"{src['repo']}@{src['ref']}"))
    if not os.path.isdir(d):
        sh("git", "clone", "-q", "--depth", "1", "--branch", src["ref"], src["repo"], d)
    return d


def build(spec, src, go, tags, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    name = f"{os.path.basename(spec['target']['source']['mainPackage'].rstrip('/'))}-go{go}"
    dst = os.path.join(out_dir, name)
    if not os.path.exists(dst):
        ld = spec.get("build", {}).get("extraLdflags", "")
        cache = os.path.join(RUNTIME, "gocache")
        os.makedirs(cache, exist_ok=True)
        cmd = [ENGINE, "run", "--rm", "-v", f"{src}:/src", "-v", f"{cache}:/root/.cache", "-v", f"{out_dir}:/out",
               "-w", "/src", "-e", "GOFLAGS=-mod=vendor", "-e", "CGO_ENABLED=0", "-e", "GOTOOLCHAIN=local",
               GO_IMAGE.format(go), "go", "build"]
        if tags:
            cmd += ["-tags", tags]
        if ld:
            cmd += [f"-ldflags={ld}"]
        cmd += ["-o", f"/out/{name}", spec["target"]["source"]["mainPackage"]]
        sh(*cmd)
    return dst


# ---------- the lab's own identity ----------

class LabIdentity:
    """per-run CA, server certificate for LAB_NAME, service-account key pair and bearer token (lab-only)"""

    def __init__(self, run_dir):
        self.dir = os.path.join(run_dir, "pki")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        d = self.dir

        def ossl(*a):
            sh("openssl", *a)
        ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
             "-subj", "/CN=vexproof lab CA (this run only)", "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.pem",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash")
        ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={LAB_NAME}",
             "-keyout", f"{d}/server.key", "-out", f"{d}/server.csr")
        with open(f"{d}/server.ext", "w") as fh:
            fh.write(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                     f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{LAB_NAME}\n"
                     "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        ossl("x509", "-req", "-in", f"{d}/server.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
             "-CAcreateserial", "-days", "2", "-extfile", f"{d}/server.ext", "-out", f"{d}/server.pem")
        ossl("genrsa", "-out", f"{d}/sa.key", "2048")
        ossl("rsa", "-in", f"{d}/sa.key", "-pubout", "-out", f"{d}/sa.pub")
        self.token = secrets.token_hex(24)
        with open(f"{d}/tokens.csv", "w") as fh:
            fh.write(f'{self.token},vexproof-lab,vexproof-lab,"system:masters"\n')
        for f in os.listdir(d):  # the target runs as root in its container, but nobody else on the host reads them
            os.chmod(os.path.join(d, f), 0o644 if f.endswith((".pem", ".pub", ".csv")) else 0o600)
        os.chmod(f"{d}/server.key", 0o644)  # read by the target process inside the container
        os.chmod(f"{d}/sa.key", 0o644)
        der = ssl.PEM_cert_to_DER_cert(open(f"{d}/server.pem").read())
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.ctx = ssl.create_default_context(cafile=f"{d}/ca.pem")
        self.ctx.check_hostname = True
        self.ctx.verify_mode = ssl.CERT_REQUIRED


# ---------- runtime ----------

class Target:
    """the arm's containers: a holder that owns the network namespace and publishes the port on 127.0.0.1,
    the sidecars and the target binary joined to it"""

    def __init__(self, spec, run, arm_name, binary, ident, godebug=None):
        self.spec, self.rt, self.ident, self.run = spec, spec["runtime"], ident, run
        self.name = f"vexproof-tt-{run}-{arm_name}".lower()
        lbl = ["--label", f"{LABEL}=trigger", "--label", f"{LABEL}.run={run}"]
        self.close()
        port = int(self.rt.get("port", 6443))
        sh(ENGINE, "run", "-d", "--name", f"{self.name}-net", *lbl, "-p", f"127.0.0.1::{port}", BASE_IMAGE,
           "sleep", "86400")
        net = ["--network", f"container:{self.name}-net"]
        for sc in self.rt.get("sidecars", []):
            sh(ENGINE, "run", "-d", "--name", f"{self.name}-{sc['name']}", *lbl, *net, sc["image"], *sc.get("args", []))
        time.sleep(3)
        cmd = [ENGINE, "run", "-d", "--name", f"{self.name}-target", *lbl, *net,
               "-v", f"{os.path.dirname(os.path.abspath(binary))}:/b:ro", "-v", f"{ident.dir}:/pki:ro"]
        for f in self.rt.get("files", []):
            p = os.path.abspath(os.path.join(ROOT, f["hostPath"]))
            if os.path.commonpath([p, ROOT]) != ROOT:
                raise SystemExit(f"runtime.files: {f['hostPath']} is outside the project")
            cmd += ["-v", f"{p}:{f['mountPath']}:ro"]
        if godebug:
            cmd += ["-e", f"GODEBUG={godebug}"]
        cmd += [BASE_IMAGE, f"/b/{os.path.basename(binary)}", *self.rt.get("args", [])]
        sh(*cmd)
        self.port = self._published_port(port)
        rd = self.rt["readiness"]
        for _ in range(90):
            try:
                if self.request("GET", rd["path"], {}, auth=True)[0] == rd.get("expectStatus", 200):
                    return
            except (OSError, ssl.SSLError):
                pass
            time.sleep(2)
        raise SystemExit(f"{arm_name}: not ready")

    def _published_port(self, port):
        out = sh(ENGINE, "port", f"{self.name}-net", f"{port}/tcp").split()
        hp = [x for x in out if x.startswith("127.0.0.1:")]
        if len(hp) != 1:
            raise SystemExit(f"{self.name}: port {port} must be published on 127.0.0.1 only, got {out}")
        return int(hp[0].rsplit(":", 1)[1])

    def verify_target(self):
        """the container we started is still the one behind the port (label, state, port mapping)"""
        for c in ("net", "target"):
            st = json.loads(sh(ENGINE, "inspect", f"{self.name}-{c}"))[0]
            labels = (st.get("Config") or {}).get("Labels") or {}
            if labels.get(f"{LABEL}.run") != self.run or not (st.get("State") or {}).get("Running"):
                raise SystemExit(f"refusing: {self.name}-{c} is not this run's running lab container")
        if self._published_port(int(self.rt.get("port", 6443))) != self.port:
            raise SystemExit("refusing: the published port changed")

    def request(self, method, path, headers, auth=True, timeout=600):
        self.verify_target()
        h = dict(headers)
        if auth:
            h["Authorization"] = f"Bearer {self.ident.token}"
        # plain HTTP object over our own TLS socket: direct to 127.0.0.1, server name LAB_NAME, pinned certificate
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        c.connect = _connect_pinned(c, self.port, self.ident)
        t = time.time()
        c.request(method, path, headers=h)
        r = c.getresponse()
        body = r.read()
        c.close()
        if 300 <= r.status < 400:
            raise SystemExit(f"refusing: redirect {r.status} from the lab target")
        return r.status, len(body), time.time() - t

    def cpu(self):
        f = sh(ENGINE, "exec", f"{self.name}-target", "cat", "/proc/1/stat").split(")")[1].split()
        return (int(f[11]) + int(f[12])) / 100

    def close(self):
        ids = sh(ENGINE, "ps", "-aq", "--filter", f"name=^{self.name}-", check=False).split()
        if ids:
            sh(ENGINE, "rm", "-f", *ids, check=False)


def _connect_pinned(conn, port, ident):
    """connect to 127.0.0.1:port, TLS with server_hostname=LAB_NAME, then compare the certificate fingerprint"""
    import socket

    def connect():
        raw = socket.create_connection(("127.0.0.1", port), conn.timeout)
        s = ident.ctx.wrap_socket(raw, server_hostname=LAB_NAME)
        if hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest() != ident.fingerprint:
            s.close()
            raise SystemExit("refusing: the server certificate is not this run's lab certificate")
        conn.sock = s
    return connect


def payload(req, params):
    """(path, headers) for one request, from the payload generator"""
    path, headers = req["path"], dict(req.get("headers", {}))
    p = req.get("payload")
    if not p:
        return path, headers
    n = int(re.sub(r"\{\{(\w+)\}\}", lambda m: str(params[m.group(1)]), str(p.get("count", "1"))))
    if p["generator"] == "http-range":
        headers[p.get("header", "Range")] = "bytes=" + ",".join(f"{2 * i}-{2 * i}" for i in range(n))
    elif p["generator"] == "query-params":
        path += ("&" if "?" in path else "?") + "&".join(f"p{i}=1" for i in range(n))
    return path, headers


# ---------- oracle ----------

def when_ok(expr, params):
    if not expr:
        return True
    m = re.fullmatch(r"\s*(\w+)\s*(>=|<=|>|<|==)\s*(\d+)\s*", expr)
    v, op, x = params[m.group(1)], m.group(2), int(m.group(3))
    return {">": v > x, "<": v < x, ">=": v >= x, "<=": v <= x, "==": v == x}[op]


def evaluate(oracle, rows, pname):
    out = []
    for rule in oracle:
        arms_run = {r["arm"] for r in rows}
        if not set(rule["arms"]) & arms_run:
            continue  # arm not run (--arms)
        sel = [r for r in rows if r["arm"] in rule["arms"] and when_ok(rule.get("when"), {pname: r[pname]})]
        res = {"arms": rule["arms"], "when": rule.get("when"), "expect": rule["expect"], "rows": len(sel), "checks": []}
        e = rule["expect"]
        if "status" in e:
            got = sorted({r["status"] for r in sel})
            res["checks"].append({"check": f"status == {e['status']}", "observed": got, "ok": got == [e["status"]]})
        for arm in rule["arms"]:
            a = [r for r in rows if r["arm"] == arm]
            if not a:
                continue
            by = {}
            for r in a:
                by.setdefault(r[pname], []).append(r["server_cpu_s"])
            med = {k: statistics.median(v) for k, v in sorted(by.items())}
            if "serverCPU" in e:  # growsWith(p): median CPU at the largest value >= 5x the smallest value's
                lo, hi = med[min(med)], med[max(med)]
                res["checks"].append({"check": f"{arm}: {e['serverCPU']}", "observed": med,
                                      "ok": hi >= 5 * max(lo, 0.01)})
            if "serverCPUMax" in e:
                cap = float(e["serverCPUMax"].rstrip("s"))
                res["checks"].append({"check": f"{arm}: median CPU <= {cap}s", "observed": med,
                                      "ok": all(v <= cap for v in med.values())})
        res["ok"] = bool(res["checks"]) and all(c["ok"] for c in res["checks"])
        out.append(res)
    return out


def check_spec(spec):
    if spec["safety"]["environment"] != "lab-only":
        raise SystemExit("refusing: safety.environment must be lab-only")
    auth = spec["runtime"].get("auth", {})
    if auth.get("type") not in (None, "bearer") or set(auth) - {"type", "tokenSource"} or \
            auth.get("tokenSource", "lab-generated") != "lab-generated":
        raise SystemExit("refusing: runtime.auth may only be {type: bearer, tokenSource: lab-generated} "
                         "(the runner creates the credential for each run)")
    for k in ("host", "url", "address", "kubeconfig"):
        if k in spec["runtime"] or k in spec["trigger"]["request"]:
            raise SystemExit(f"refusing: a TriggerTest cannot name a target {k}; the runner starts the target itself")
    lim = spec["safety"].get("maxRequestBytes")
    if lim:
        cap = int(str(lim).rstrip("Mi")) * 1048576 if str(lim).endswith("Mi") else int(lim)
        trig = spec["trigger"]
        pname = next(iter(trig.get("parameters", {"n": [1]})))
        for v in trig.get("parameters", {pname: [1]})[pname]:
            pth, hdr = payload(trig["request"], {pname: v})
            if len(pth) + sum(len(k) + len(x) for k, x in hdr.items()) > cap:
                raise SystemExit(f"refusing: request for {pname}={v} exceeds safety.maxRequestBytes")


def main():
    global ENGINE
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("--arms", help="comma-separated arm names (default: all)")
    ap.add_argument("--out", help="evidence directory (default: spec.output.evidenceDir)")
    ap.add_argument("--status-to")
    A = ap.parse_args()
    doc = yaml.safe_load(open(A.spec))
    spec = doc["spec"]
    check_spec(spec)
    ENGINE = engine()
    out = os.path.abspath(A.out or spec.get("output", {}).get("evidenceDir", f"results/triggertest-{doc['metadata']['name']}"))
    os.makedirs(out, exist_ok=True)
    run = time.strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)
    run_dir = os.path.join(RUNTIME, "trigger", run)
    cache = os.path.join(RUNTIME, "cache", "trigger")
    t0 = time.time()

    log(f"resolve: shipped binary, buildinfo, OSV (engine {ENGINE})")
    binary, digest = shipped_binary(spec, cache)
    bi = buildinfo(binary)
    src = spec["target"]["source"]
    ref_check = "match" if bi["git_version"] == src["ref"] else (
        f"mismatch: binary says {bi['git_version']}" if bi["git_version"] else "not stamped in the binary")
    osv = osv_entry(spec["vulnerability"]["osv"], cache)
    fixes = stdlib_fixes(osv)
    b = spec.get("build", {})
    tags = bi["tags"] if b.get("tags", "auto") == "auto" else b["tags"]
    resolved = {"shipped_sha256": digest, "shipped_go": bi["go"], "tags": tags, "goos": bi["goos"],
                "git_version": bi["git_version"], "git_commit": bi["git_commit"], "ref_check": ref_check,
                "osv_fixed_go": fixes, "engine": ENGINE, "arms": {}}
    if ref_check.startswith("mismatch"):
        raise SystemExit(f"source ref does not match the binary: {ref_check}")

    wanted = set(A.arms.split(",")) if A.arms else None
    arms = []
    for arm in spec["arms"]:
        if wanted and arm["name"] not in wanted:
            continue
        if arm.get("from") == "target":
            path, go = binary, bi["go"]
        else:
            go = arm_go(arm, fixes)
            log(f"build {arm['name']} with go{go}")
            path = build(spec, source_tree(src), go, tags, os.path.join(cache, doc["metadata"]["name"]))
        info = buildinfo(path) if spec.get("recordDefaultGODEBUG", True) else {}
        resolved["arms"][arm["name"]] = {"go": go, "default_godebug": info.get("default_godebug"),
                                         "godebug_env": arm.get("godebug")}
        arms.append((arm, path))
    if not arms:
        raise SystemExit("no arm selected")
    json.dump(resolved, open(os.path.join(out, "resolved.json"), "w"), indent=1)

    ident = LabIdentity(run_dir)
    trig = spec["trigger"]
    pname = next(iter(trig.get("parameters", {"n": [1]})))
    values = trig.get("parameters", {pname: [1]})[pname]
    rows, controls = [], []
    try:
        for arm, path in arms:
            log(f"run {arm['name']}")
            t = Target(spec, run, arm["name"], path, ident, arm.get("godebug"))
            try:
                t.request(trig["request"]["method"], trig["request"]["path"], trig["request"].get("headers", {}))  # warm-up
                for c in trig.get("controls", []):
                    st = t.request(trig["request"]["method"], trig["request"]["path"], {}, auth=c.get("auth") != "none")[0]
                    controls.append({"arm": arm["name"], "control": c["name"], "expect": c["expectStatus"], "status": st,
                                     "ok": st == c["expectStatus"]})
                for v, k in itertools.product(values, range(trig["repeats"])):
                    pth, hdr = payload(trig["request"], {pname: v})
                    c0 = t.cpu()
                    st, size, dt = t.request(trig["request"]["method"], pth, hdr,
                                             timeout=spec["safety"].get("timeoutSeconds", 600))
                    time.sleep(0.5)
                    rows.append({"arm": arm["name"], pname: v, "repeat": k + 1, "status": st, "body_bytes": size,
                                 "seconds": round(dt, 3), "server_cpu_s": round(t.cpu() - c0, 2)})
            finally:
                t.close()
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)  # the run's keys and token are not kept

    with open(os.path.join(out, "results.tsv"), "w") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), delimiter="\t")
        w.writeheader()
        w.writerows(rows)
    ev = evaluate(spec["oracle"], rows, pname)
    vulnerable_rules = [r for r in ev if "fixed" not in " ".join(r["arms"])]
    if ev and all(r["ok"] for r in ev) and all(c["ok"] for c in controls):
        verdict = "triggered"
    elif not any(r["ok"] for r in vulnerable_rules):
        verdict = "not-triggered"
    else:
        verdict = "inconclusive"
    summary = (f"{verdict}: " + "; ".join(f"{'ok' if r['ok'] else 'FAIL'} {','.join(r['arms'])} when {r['when']}"
                                          for r in ev) + f"; controls {sum(c['ok'] for c in controls)}/{len(controls)} ok")
    status = {"phase": "Succeeded", "verdict": verdict, "resolved": resolved, "oracle": ev, "summary": summary,
              "evidence": os.path.relpath(out, ROOT)}
    json.dump({"status": status, "controls": controls, "seconds": round(time.time() - t0)},
              open(os.path.join(out, "status.json"), "w"), indent=1)
    log(summary)
    rv = spec.get("output", {}).get("review")
    if rv and verdict == "triggered":
        r = json.load(open(rv)) if os.path.exists(rv) else {"osv": spec["vulnerability"]["osv"]}
        r.update(verdict="confirmed", trigger_test=os.path.relpath(os.path.join(out, "status.json"), ROOT),
                 trigger_spec=A.spec)
        json.dump(r, open(rv, "w"), indent=1)
        log(f"review updated: {rv}")
    if A.status_to:
        body = json.dumps({"status": status})
        sh("kubectl", "--context", A.status_to, "-n", doc["metadata"]["namespace"], "patch", "triggertest",
           doc["metadata"]["name"], "--subresource=status", "--type=merge", "-p", body)
        log(f"status patched in {A.status_to}")
    return 0 if verdict == "triggered" else 1


if __name__ == "__main__":
    sys.exit(main())
