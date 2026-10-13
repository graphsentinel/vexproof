#!/usr/bin/env python3
"""Exercise layer P3 (plan §10): execution of the automatic chains' packages in a coverage rebuild, under a versioned
workload profile. Lab only; runs in the lab VM (docker, k3d, go).

  cov.py build  --target T --release R --out DIR
        coverage rebuild of the official binary's source: the shipped Go version, GOARCH, CGO setting and build tags,
        -cover -coverpkg=<main>,<every package named by an automatic chain of T> (stdlib included); refuses a
        dependency graph that differs from the shipped binary's; writes DIR/<T>-cover and DIR/provenance.json
  cov.py kubectl --release R --bin COVER_BIN --profile lab/workloads/kubectl.yaml --run N --out RUN_DIR
        a fresh k3d cluster (k3s image of the same version, pinned by digest, API on 127.0.0.1), the profile's fixtures
        and commands with GOCOVERDIR=RUN_DIR/cov; every invocation that should flush counters must leave a counter file
  cov.py rows   --target T --release R --build DIR --out ROWS.tsv RUN_DIR...
        per run: covdata textfmt + pkglist, lab/symcov.py per OSV, the instrumentation manifest; then the cross-run rule:
        executed if any valid run has a positive count (k/3 reported), not-observed only if every run is valid,
        complete, instrumented and mapped with zero, otherwise no row (incomplete)
"""
import argparse
import csv
import glob
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "lab", "trigger"))
import runner  # noqa: E402  (source_tree, buildinfo, sh)
import yaml  # noqa: E402

RT = os.path.join(ROOT, "lab", ".runtime")
BIN = os.path.join(RT, "cache", "bin")
MAIN = {"kubectl": "./cmd/kubectl", "kube-apiserver": "./cmd/kube-apiserver"}
K8S = "https://github.com/kubernetes/kubernetes"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def stream(path):
    raw, dec, i = open(path).read(), json.JSONDecoder(), 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            break
        o, i = dec.raw_decode(raw, i)
        yield o


def chain_osvs(target, release):
    """the OSV ids of this target's automatic chains (lab.sh results, run 1) and their affected packages"""
    idx = os.path.join(ROOT, "results", "run-1", "chains-auto", release, target, "index.json")
    osvs = [e["osv"] for e in json.load(open(idx))]
    gv = os.path.join(RT, "in", "evidence", f"c9-autochain-{release}", f"govulncheck-source-matched-{target}.json")
    pk = {}
    for o in stream(gv):
        if "osv" in o and o["osv"]["id"] in osvs:
            for a in o["osv"].get("affected", []):
                for imp in a.get("ecosystem_specific", {}).get("imports", []):
                    pk.setdefault(o["osv"]["id"], set()).add(imp["path"])
    return osvs, pk, gv


# ---------------------------------------------------------------- build
def version_ldflags(shipped, target):
    """the version stamps of the shipped binary as -X flags, when its buildinfo does not record -ldflags (newer Go
    omits them): read from the binary's own version output"""
    if target != "kubectl":
        return ""
    v = json.loads(subprocess.run([shipped, "version", "--client", "-o", "json"], capture_output=True, text=True,
                                  check=True).stdout)["clientVersion"]
    keys = ("gitVersion", "gitCommit", "gitTreeState", "buildDate", "gitMajor", "gitMinor")
    return " ".join(f"-X '{pkg}.{k}={v[k]}'" for pkg in ("k8s.io/client-go/pkg/version", "k8s.io/component-base/version")
                    for k in keys if v.get(k))


# ---------------------------------------------------------------- build
def build(A):
    runner.ENGINE = runner.engine()
    shipped = os.path.join(BIN, A.release, A.target)
    bi = runner.buildinfo(shipped)
    osvs, pk, _ = chain_osvs(A.target, A.release)
    src = runner.source_tree({"repo": K8S, "ref": A.release})
    mod = "k8s.io/kubernetes"
    main_pkg = mod + MAIN[A.target][1:]
    pkgs = sorted({p for s in pk.values() for p in s})
    coverpkg = ",".join([main_pkg] + pkgs)
    os.makedirs(A.out, exist_ok=True)
    out = os.path.abspath(A.out)
    name = f"{A.target}-cover"
    cgo = "1" if re.search(r"CGO_ENABLED=1", bi["raw"]) else "0"
    cache = os.path.join(RT, "gocache")
    os.makedirs(cache, exist_ok=True)
    cmd = [runner.ENGINE, "run", "--rm", "-v", f"{src}:/src", "-v", f"{cache}:/root/.cache", "-v", f"{out}:/out",
           "-w", "/src", "-e", "GOFLAGS=-mod=vendor", "-e", f"CGO_ENABLED={cgo}", "-e", "GOTOOLCHAIN=local",
           runner.GO_IMAGE.format(bi["go"]), "go", "build", "-buildvcs=false", "-trimpath"]
    if bi["tags"]:
        cmd += ["-tags", bi["tags"]]
    m = re.search(r'(?m)^\s*build\s+-ldflags="(.*)"\s*$', bi["raw"])
    ldflags = m.group(1) if m else version_ldflags(shipped, A.target)
    if ldflags:  # the shipped binary's own -ldflags (version stamps), so the rebuild reports the same version
        cmd += [f"-ldflags={ldflags}"]
    cmd += ["-cover", f"-coverpkg={coverpkg}", "-o", f"/out/{name}", MAIN[A.target]]
    log(f"build {A.target} {A.release} with go{bi['go']} ({len(pkgs)} packages + main)")
    runner.sh(*cmd)
    cb = runner.buildinfo(os.path.join(out, name))
    same = cb["deps"] == bi["deps"]
    tree = subprocess.run(["git", "-C", src, "rev-parse", "HEAD^{tree}"], capture_output=True, text=True).stdout.strip()
    prov = {"target": A.target, "release": A.release, "source": {"repo": K8S, "ref": A.release, "tree": tree,
                                                                "patches": "none"},
            "go": bi["go"], "goarch": bi.get("goarch"), "cgo": cgo, "tags": bi["tags"],
            "flags": "-buildvcs=false -trimpath -cover", "ldflags_from_shipped": ldflags, "coverpkg": [main_pkg] + pkgs, "osvs": osvs,
            "shipped_sha256": sha256(shipped), "cover_sha256": sha256(os.path.join(out, name)),
            "deps_equal_shipped": same}
    json.dump(prov, open(os.path.join(out, "provenance.json"), "w"), indent=1)
    if not same:
        raise SystemExit("dependency graph differs from the shipped binary: refusing this rebuild")
    log(f"ok: {name} {prov['cover_sha256'][:12]}, deps = shipped")


# ---------------------------------------------------------------- kubectl workload
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def csr_b64(d):
    key, csr = os.path.join(d, "lab.key"), os.path.join(d, "lab.csr")
    subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-subj", "/CN=vexproof-lab-user", "-keyout", key, "-out", csr], check=True, capture_output=True)
    import base64
    return base64.b64encode(open(csr, "rb").read()).decode()


def kubectl(A):
    prof = yaml.safe_load(open(A.profile))
    k3s = A.k3s_image or prof["k3s"][A.release]
    img = prof["images"]["busybox"]
    if "@sha256:" not in k3s or "@sha256:" not in img:
        raise SystemExit("images must be pinned by digest")
    run_dir = os.path.abspath(A.out)
    if os.path.exists(run_dir):
        raise SystemExit(f"{run_dir} exists: a run is never overwritten")
    cov, d = os.path.join(run_dir, "cov"), os.path.join(run_dir, "scratch")
    os.makedirs(cov)
    os.makedirs(d)
    cluster = f"vxp3-kc-{A.release.replace('.', '')}-r{A.run}"
    kcfg = os.path.join(run_dir, "kubeconfig")
    rec = {"run": A.run, "cluster": cluster, "k3s_image": k3s, "busybox": img, "profile_sha256": sha256(A.profile),
           "cover_sha256": sha256(A.bin), "driver_sha256": sha256(os.path.abspath(__file__)), "commands": [],
           "aborted": None}
    try:
        port = free_port()
        log(f"cluster {cluster} ({k3s}), API 127.0.0.1:{port}")
        subprocess.run(["k3d", "cluster", "delete", cluster], capture_output=True)
        subprocess.run(["k3d", "cluster", "create", cluster, "--image", k3s, "--api-port", f"127.0.0.1:{port}",
                        "--servers", "1", "--agents", "0", "--no-lb", "--wait", "--timeout", "300s",
                        "--kubeconfig-update-default=false", "--kubeconfig-switch-context=false"],
                       check=True, capture_output=True)
        open(kcfg, "w").write(subprocess.run(["k3d", "kubeconfig", "get", cluster], capture_output=True, text=True,
                                             check=True).stdout)
        os.chmod(kcfg, 0o600)
        sv = json.loads(subprocess.run(["kubectl", "--kubeconfig", kcfg, "version", "-o", "json"], capture_output=True,
                                       text=True).stdout or "{}").get("serverVersion", {})
        rec["server_version"] = sv.get("gitVersion")
        if not (rec["server_version"] or "").startswith(A.release + "+") and rec["server_version"] != A.release:
            raise RuntimeError(f"server {rec['server_version']} is not {A.release}: version precondition fails")
        values = {"k": f"{shlex.quote(os.path.abspath(A.bin))} --kubeconfig={kcfg}", "ns": "vxp3", "d": d, "img": img,
                  "csr_b64": csr_b64(d)}
        for fn, body in prof.get("files", {}).items():
            open(os.path.join(d, fn), "w").write(body.replace("{csr_b64}", values["csr_b64"]))
        env = {**os.environ, "GOCOVERDIR": cov}

        def fill(x):
            return re.sub(r"\{(k|ns|d|img)\}", lambda m: values[m.group(1)], x)

        def one(item_id, cmd, kind, expect, flush=True, inputs=(), background=None):
            """every invocation: exec'd (its PID names its counter file), exit code checked against the frozen list,
            a background command's probe checked against its frozen status"""
            t0 = time.time()
            probe = None
            p = subprocess.Popen(["bash", "-c", "exec " + fill(cmd)], env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
            if background:
                time.sleep(2)
                probe = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5",
                                        fill(background["probe"])], capture_output=True, text=True).stdout
                time.sleep(max(0, background["seconds"] - 2))
                p.send_signal(2)  # SIGINT: the command's own shutdown path
            try:
                o, _ = p.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                p.kill()
                o, _ = p.communicate()
            allowed = expect if isinstance(expect, list) else [expect]
            ok = p.returncode in allowed and (not background or probe == str(background.get("expect_probe", 200)))
            rec["commands"].append({"kind": kind, "id": item_id, "rc": p.returncode, "allowed": allowed, "probe": probe,
                                    "ok": ok, "seconds": round(time.time() - t0, 2), "inputs": list(inputs),
                                    "tail": (o or "")[-300:], "pid": p.pid, "flush": flush})
            log(f"{kind:8} {item_id:16} rc={p.returncode}{' probe=' + probe if probe else ''} {'ok' if ok else 'UNEXPECTED'}")

        for f in prof["fixtures"]:
            one(f["id"], f["cmd"], "fixture", f.get("expect", 0))
            if f.get("wait"):
                one(f["id"] + "-wait", f["wait"], "fixture", 0)
        for c in prof["commands"]:
            one(c["id"], c["cmd"], "command", c["expect"], c.get("flush", True), c.get("inputs", []), c.get("background"))
    except BaseException as ex:  # an aborted attempt is kept, with its reason, and is not a valid run
        rec["aborted"] = f"{type(ex).__name__}: {str(ex)[-300:]}"
        log(f"ABORTED: {rec['aborted']}")
    finally:
        subprocess.run(["k3d", "cluster", "delete", cluster], capture_output=True)
        for f in ("lab.key", "lab.csr"):
            fp = os.path.join(d, f)
            if os.path.exists(fp):
                os.remove(fp)
        if os.path.exists(kcfg):
            os.remove(kcfg)  # the run's credentials are not kept
        pids = {int(os.path.basename(f).split(".")[2]) for f in glob.glob(os.path.join(cov, "covcounters.*"))}
        for c in rec["commands"]:
            c["counter_file"] = c["pid"] in pids
        must = [c for c in rec["commands"] if c["flush"]]
        rec["invocations"] = len(must)
        rec["missing_counters"] = [c["id"] for c in must if not c["counter_file"]]
        rec["not_flushed_by_design"] = [c["id"] for c in rec["commands"] if not c["flush"]]
        rec["unexpected"] = [c["id"] for c in rec["commands"] if not c["ok"]]
        expected_n = len(prof["fixtures"]) + sum(1 for f in prof["fixtures"] if f.get("wait")) + len(prof["commands"])
        rec["complete"] = (rec["aborted"] is None and len(rec["commands"]) == expected_n and not rec["missing_counters"]
                           and not rec["unexpected"])
        json.dump(rec, open(os.path.join(run_dir, "run.json"), "w"), indent=1)
        log(f"invocations {len(must)}, missing counters {rec['missing_counters']}, not flushed by design "
            f"{rec['not_flushed_by_design']}, unexpected {rec['unexpected']}, aborted {rec['aborted']}, "
            f"complete={rec['complete']}")


APISERVER_ARGS = ["--etcd-servers=http://127.0.0.1:2379", "--service-account-issuer=https://kubernetes.default.svc",
                  "--service-account-key-file=/pki/sa.pub", "--service-account-signing-key-file=/pki/sa.key",
                  "--service-cluster-ip-range=10.96.0.0/16", "--tls-cert-file=/pki/server.pem",
                  "--tls-private-key-file=/pki/server.key", "--token-auth-file=/pki/tokens.csv",
                  "--authorization-mode=RBAC", "--secure-port=6443"]


def apiserver(A):
    """the coverage rebuild of kube-apiserver in the trigger runner's lab pod, driven by the official kubectl and by
    direct requests (profile lab/workloads/kube-apiserver.yaml), stopped with SIGTERM so it flushes its counters"""
    prof = yaml.safe_load(open(A.profile))
    etcd, backend = prof["etcd"][A.release], prof["backend"]
    if "@sha256:" not in etcd or "@sha256:" not in backend:
        raise SystemExit("images must be pinned by digest")
    run_dir = os.path.abspath(A.out)
    if os.path.exists(run_dir):
        raise SystemExit(f"{run_dir} exists: a run is never overwritten")
    cov, d = os.path.join(run_dir, "cov"), os.path.join(run_dir, "scratch")
    os.makedirs(cov)
    os.makedirs(d)
    os.chmod(cov, 0o777)  # the target runs as root in its container and writes its counters here
    runner.ENGINE = runner.engine()
    spec = {"runtime": {"port": 6443, "args": APISERVER_ARGS, "readiness": {"path": "/readyz", "expectStatus": 200},
                        "sidecars": [{"name": "etcd", "image": etcd, "args": ["etcd", "--data-dir=/tmp/etcd",
                                      "--listen-client-urls=http://127.0.0.1:2379",
                                      "--advertise-client-urls=http://127.0.0.1:2379"]},
                                     {"name": "backend", "image": backend, "args": ["httpd", "-f", "-p", "8080", "-h", "/etc"]}]}}
    kubectl_bin = os.path.join(BIN, A.release, "kubectl")
    kcfg = os.path.join(run_dir, "kubeconfig")
    run = f"p3api{A.run}" + time.strftime("%H%M%S")
    rec = {"run": A.run, "etcd": etcd, "backend": backend, "profile_sha256": sha256(A.profile),
           "cover_sha256": sha256(A.bin), "driver_sha256": sha256(os.path.abspath(__file__)),
           "kubectl_sha256": sha256(kubectl_bin), "steps": [], "aborted": None}
    ident, t = None, None
    try:
        ident = runner.LabIdentity(os.path.join(run_dir, "pki-run"))
        t = runner.Target(spec, run, "apiserver", os.path.abspath(A.bin), ident, cover_dir=cov)
        open(kcfg, "w").write(yaml.safe_dump({
            "apiVersion": "v1", "kind": "Config", "current-context": "lab",
            "clusters": [{"name": "lab", "cluster": {"server": f"https://127.0.0.1:{t.port}",
                                                     "certificate-authority": os.path.join(ident.dir, "ca.pem"),
                                                     "tls-server-name": runner.LAB_NAME}}],
            "users": [{"name": "lab", "user": {"token": ident.token}}],
            "contexts": [{"name": "lab", "context": {"cluster": "lab", "user": "lab"}}]}))
        os.chmod(kcfg, 0o600)
        ver = t.request("GET", "/version", {})
        rec["server_version_status"] = ver[0]
        ip = subprocess.run([runner.ENGINE, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", f"{t.name}-net"],
                            capture_output=True, text=True, check=True).stdout.strip()
        values = {"k": f"{shlex.quote(kubectl_bin)} --kubeconfig={kcfg}", "d": d, "img": backend,
                  "csr_b64": csr_b64(d), "backend_ip": ip}
        for fn, body in prof.get("files", {}).items():
            open(os.path.join(d, fn), "w").write(body.replace("{csr_b64}", values["csr_b64"]).replace("{backend_ip}", ip)
                                                 .replace("{img}", backend))

        def step(kind, sid, ok, detail):
            rec["steps"].append({"kind": kind, "id": sid, "ok": ok, **detail})
            log(f"{kind:8} {sid:22} {'ok' if ok else 'UNEXPECTED'} {detail.get('rc', detail.get('status', ''))}")

        for kind, items in (("fixture", prof["backend_fixture"]), ("kubectl", prof["kubectl"])):
            for c in items:
                cmd = re.sub(r"\{(k|d|img|backend_ip)\}", lambda m: values[m.group(1)], c["cmd"])
                r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=300)
                allowed = c["expect"] if isinstance(c["expect"], list) else [c["expect"]]
                step(kind, c["id"], r.returncode in allowed, {"rc": r.returncode, "tail": (r.stdout + r.stderr)[-200:]})
        for q in prof["requests"]:
            path, hdr = q["path"], dict(q.get("headers", {}))
            if q.get("range_count"):
                hdr["Range"] = "bytes=" + ",".join(f"{2 * i}-{2 * i}" for i in range(q["range_count"]))
            if q.get("query_count"):
                path += "?" + "&".join(f"p{i}=1" for i in range(q["query_count"]))
            st = t.request(q["method"], path, hdr, auth=q.get("auth") != "none")[0]
            allowed = q["status"] if isinstance(q["status"], list) else [q["status"]]
            step("request", q["id"], st in allowed, {"status": st})
        t.stop(60)  # SIGTERM: the coverage build writes its counters on a graceful exit
    except BaseException as ex:
        rec["aborted"] = f"{type(ex).__name__}: {str(ex)[-300:]}"
        log(f"ABORTED: {rec['aborted']}")
    finally:
        if t:
            t.close()
        for p in (kcfg, os.path.join(d, "lab.key"), os.path.join(d, "lab.csr")):
            if os.path.exists(p):
                os.remove(p)
        shutil.rmtree(os.path.join(run_dir, "pki-run"), ignore_errors=True)  # the run's keys and token are not kept
        counters = glob.glob(os.path.join(cov, "covcounters.*"))
        rec["counter_files"] = len(counters)
        rec["meta_files"] = len(glob.glob(os.path.join(cov, "covmeta.*")))
        rec["unexpected"] = [x["id"] for x in rec["steps"] if not x["ok"]]
        n_expected = len(prof["backend_fixture"]) + len(prof["kubectl"]) + len(prof["requests"])
        rec["complete"] = (rec["aborted"] is None and len(rec["steps"]) == n_expected and not rec["unexpected"]
                           and rec["counter_files"] >= 1 and rec["meta_files"] >= 1)
        json.dump(rec, open(os.path.join(run_dir, "run.json"), "w"), indent=1)
        log(f"steps {len(rec['steps'])}/{n_expected}, unexpected {rec['unexpected']}, counters {rec['counter_files']}, "
            f"aborted {rec['aborted']}, complete={rec['complete']}")


def metrics(A):
    """metrics-server: the CI recipe with coverpkg extended to the stdlib packages of the automatic chains, a fresh
    cluster per run, the profile's commands (exit codes checked), counters flushed by scaling to 0"""
    sys.path.insert(0, os.path.join(ROOT, "lab"))
    import full
    prof = yaml.safe_load(open(A.profile))
    run_dir = os.path.abspath(A.out)
    if os.path.exists(run_dir):
        raise SystemExit(f"{run_dir} exists: a run is never overwritten")
    os.makedirs(run_dir)
    runner.ENGINE = runner.engine()
    target, release = "metrics-server", "metrics-server-v0.9.0"
    _, pk, _ = chain_osvs(target, release)
    extra = sorted({p for s in pk.values() for p in s if "." not in p.split("/")[0]})  # stdlib import paths
    cluster = f"vxp3-ms-r{A.run}"
    rec = {"run": A.run, "profile_sha256": sha256(A.profile), "driver_sha256": sha256(os.path.abspath(__file__)),
           "recipe_sha256": sha256(os.path.join(ROOT, "ci", "vexproof.py")), "coverpkg_extra": extra,
           "cluster": cluster, "aborted": None}
    try:
        os.makedirs(full.RT, exist_ok=True)
        full.log = open(os.path.join(run_dir, "prepare.log"), "w")
        full.source()  # clone + vendor the release source, fetch the release manifest and check its sha256
        bad = [c for c in full.checks if not c["ok"]]
        if bad:
            raise RuntimeError(f"preparation failed: {bad}")
        gobin = os.path.join(full.RT, "gobin")
        os.makedirs(gobin, exist_ok=True)
        shutil.copy(shutil.which("govulncheck"), os.path.join(gobin, "govulncheck"))
        cfg = json.load(open(os.path.join(ROOT, "ci", "metrics-server.json")))
        out = os.path.join(run_dir, "ci")
        cfg.update(src=full.SRC, out=out, manifest=os.path.join(full.RT, "components.yaml"), engine=runner.ENGINE,
                   cluster=cluster, gocache=os.path.join(full.RT, "gocache"), gomod=os.path.join(full.RT, "gomod"),
                   gobin=gobin, trivycache=os.path.join(full.RT, "trivycache"), covdir=os.path.join(run_dir, "covhost"),
                   delete_cluster=True, coverpkg_extra=extra,
                   exercise=[e["cmd"].replace("CLUSTER", cluster) for e in prof["exercise"]])
        for d in ("gocache", "gomod", "trivycache"):
            os.makedirs(cfg[d], exist_ok=True)
        os.makedirs(cfg["covdir"], exist_ok=True)
        cf = os.path.join(run_dir, "ci-config.json")
        json.dump(cfg, open(cf, "w"), indent=1)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "ci", "vexproof.py"), cf], capture_output=True, text=True)
        rec["recipe_rc"] = r.returncode  # the recipe's own gate (fail_on affected) may be non-zero: recorded, not used
        ex = json.load(open(os.path.join(out, "exercise.json")))
        rec["exercise"] = [{"cmd": e["cmd"], "rc": e["rc"], "expect": p["expect"], "ok": e["rc"] == p["expect"]}
                           for e, p in zip(ex, prof["exercise"])]
        cov = os.path.join(run_dir, "cov")
        shutil.copytree(os.path.join(out, "covdata"), cov)
        shipped = os.path.join(BIN, release, target)
        built = runner.buildinfo(os.path.join(out, target))
        rec["deps_equal_shipped"] = built["deps"] == runner.buildinfo(shipped)["deps"]
        rec["cover_sha256"] = sha256(os.path.join(out, target))
        rec["go"] = built["go"]
    except BaseException as ex:
        rec["aborted"] = f"{type(ex).__name__}: {str(ex)[-300:]}"
        log(f"ABORTED: {rec['aborted']}")
    finally:
        subprocess.run(["k3d", "cluster", "delete", cluster], capture_output=True)
        cov = os.path.join(run_dir, "cov")
        rec["counter_files"] = len(glob.glob(os.path.join(cov, "covcounters.*"))) if os.path.isdir(cov) else 0
        rec["unexpected"] = [e["cmd"] for e in rec.get("exercise", []) if not e["ok"]]
        rec["complete"] = (rec["aborted"] is None and len(rec.get("exercise", [])) == len(prof["exercise"])
                           and not rec["unexpected"] and rec["counter_files"] >= 1 and rec.get("deps_equal_shipped") is True)
        json.dump(rec, open(os.path.join(run_dir, "run.json"), "w"), indent=1)
        log(f"exercise {len(rec.get('exercise', []))}/{len(prof['exercise'])}, unexpected {rec['unexpected']}, counters "
            f"{rec['counter_files']}, deps = shipped {rec.get('deps_equal_shipped')}, aborted {rec['aborted']}, "
            f"complete={rec['complete']}")


# ---------------------------------------------------------------- rows
def goroot(go, dst):
    if not os.path.isdir(os.path.join(dst, "net")):
        os.makedirs(dst, exist_ok=True)
        p = subprocess.run(f"{runner.ENGINE} run --rm {runner.GO_IMAGE.format(go)} tar -C /usr/local/go/src -c . | tar -C {shlex.quote(dst)} -x",
                           shell=True)
        if p.returncode:
            raise SystemExit("cannot extract GOROOT/src")
    return dst


def rows(A):
    runner.ENGINE = runner.engine()
    pf = os.path.join(A.build, "provenance.json")
    if os.path.exists(pf):
        prov = json.load(open(pf))
    else:  # metrics-server: the recipe builds in every run; the Go version comes from the first valid run
        prov = next(json.load(open(os.path.join(rd, "run.json"))) for rd in A.runs
                    if json.load(open(os.path.join(rd, "run.json"))).get("go"))
    osvs, pk, gv = chain_osvs(A.target, A.release)
    gr = goroot(prov["go"], os.path.join(RT, "goroot", prov["go"]))
    if A.target == "metrics-server":
        sys.path.insert(0, os.path.join(ROOT, "lab"))
        import full
        src = full.SRC
    else:
        src = runner.source_tree({"repo": K8S, "ref": A.release})
    trivy = os.path.join(RT, "in", "evidence", f"c9-autochain-{A.release}", "trivy-official.json")
    goos = runner.buildinfo(os.path.join(BIN, A.release, A.target)).get("goos")
    if not goos:
        raise SystemExit("the shipped binary's buildinfo has no GOOS: the GOOS mapping policy cannot be applied")
    per_run = []
    expected_pairs = [(o, pkg) for o in osvs for pkg in sorted(pk.get(o, ()))]
    for rd in A.runs:
        run = json.load(open(os.path.join(rd, "run.json")))
        if not run.get("complete"):  # decided before any coverage tool runs: the slot counts, nothing else does
            per_run.append({"dir": rd, "valid": False, "rows": {k: ("invalid-run", None) for k in expected_pairs}})
            json.dump({"invalid": run.get("aborted") or "incomplete run", "manifest": {}},
                      open(os.path.join(rd, "manifest.json"), "w"), indent=1)
            continue
        cov = os.path.join(rd, "cov")
        go = runner.GO_IMAGE.format(prov["go"])
        vol = ["-v", f"{os.path.abspath(rd)}:/r"]
        runner.sh(runner.ENGINE, "run", "--rm", *vol, go, "go", "tool", "covdata", "textfmt", "-i=/r/cov", "-o=/r/cov.txt")
        pl = runner.sh(runner.ENGINE, "run", "--rm", *vol, go, "go", "tool", "covdata", "pkglist", "-i=/r/cov")
        pkglist = sorted(set(pl.split()))
        open(os.path.join(rd, "pkglist.txt"), "w").write("\n".join(pkglist) + "\n")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "lab", "symcov.py"), "--target", A.target,
                              "--govulncheck", gv, "--trivy", trivy, "--trivy-target", A.target,
                              "--cov", os.path.join(rd, "cov.txt"), "--src", os.path.join(src, "vendor"),
                              "--goroot", gr, "--goos", goos, "--osv", ",".join(osvs)],
                             capture_output=True, text=True, check=True).stdout
        open(os.path.join(rd, "symcov.tsv"), "w").write(out)
        rr = {}
        for r in csv.DictReader(io.StringIO(out), delimiter="\t"):
            key = (r["osv"], r["package"])
            instrumented = r["package"] in pkglist
            mapped = r["symbols"] not in ("-", "0") and r["symbols"] == r["sym_found"]
            if r["L4"] == "executed" and int(r["blocks_hit"]) > 0:
                state = "executed"
            elif run["complete"] and instrumented and mapped and r["L4"] == "not-observed":
                state = "zero"  # gate on zeros: instrumented per the run's own counter metadata, every symbol mapped
            else:
                state = "incomplete"
            rr[key] = (state, r)
        per_run.append({"dir": rd, "valid": bool(run.get("complete")), "rows": rr})
        json.dump({"pkglist": pkglist, "goos": goos, "symcov_sha256": sha256(os.path.join(ROOT, "lab", "symcov.py")),
                   "manifest": {f"{k[0]} {k[1]}": v[0] for k, v in rr.items()}},
                  open(os.path.join(rd, "manifest.json"), "w"), indent=1)
    if len(per_run) != A.n:
        raise SystemExit(f"{len(per_run)} run directories given, {A.n} pre-registered: every counted slot is reported")
    valid = sum(p["valid"] for p in per_run)
    keys = sorted({k for p in per_run for k in p["rows"]})
    with open(A.out, "w") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["target", "osv", "aliases", "L1_trivy", "L3_level", "package", "symbols", "sym_found", "blocks",
                    "blocks_hit", "L4", "verdict", "runs_executed", "runs_valid", "measurement"])
        for k in keys:
            st = [p["rows"].get(k, ("incomplete", None)) for p in per_run]
            ex = [s for s, _ in st if s == "executed"]
            ref = next((r for _, r in st if r is not None), None)
            if ref is None:
                continue  # no valid run produced this pair
            if ex:
                hit = max(int(r["blocks_hit"]) for s, r in st if s == "executed")
                lab = "executed in the rebuild" + (" (k=1, not reproduced)" if len(ex) == 1 else "")
                w.writerow([A.target, k[0], ref["aliases"], ref["L1_trivy"], ref["L3_level"], k[1], ref["symbols"],
                            ref["sym_found"], ref["blocks"], hit, "executed", "EXECUTED", f"{len(ex)}/{A.n}",
                            valid, lab])
            elif valid == A.n and all(s == "zero" for s, _ in st):
                w.writerow([A.target, k[0], ref["aliases"], ref["L1_trivy"], ref["L3_level"], k[1], ref["symbols"],
                            ref["sym_found"], ref["blocks"], 0, "not-observed", "REACHABLE-NOT-OBSERVED",
                            f"0/{A.n}", valid, "not observed in this rebuild under these workloads"])
    log(f"rows -> {A.out}")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("build")
    b.add_argument("--target", required=True)
    b.add_argument("--release", required=True)
    b.add_argument("--out", required=True)
    k = sp.add_parser("kubectl")
    for a in ("--release", "--bin", "--profile", "--run", "--out"):
        k.add_argument(a, required=True)
    k.add_argument("--k3s-image")
    ms = sp.add_parser("metrics")
    for x in ("--profile", "--run", "--out"):
        ms.add_argument(x, required=True)
    ap2 = sp.add_parser("apiserver")
    for x in ("--release", "--bin", "--profile", "--run", "--out"):
        ap2.add_argument(x, required=True)
    r = sp.add_parser("rows")
    for a in ("--target", "--release", "--build", "--out"):
        r.add_argument(a, required=True)
    r.add_argument("--n", type=int, default=3, help="pre-registered number of runs")
    r.add_argument("runs", nargs="+")
    A = ap.parse_args()
    {"build": build, "kubectl": kubectl, "apiserver": apiserver, "metrics": metrics, "rows": rows}[A.cmd](A)


if __name__ == "__main__":
    main()
