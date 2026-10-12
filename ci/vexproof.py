#!/usr/bin/env python3
"""CI recipe (Mode A): evidence chain + OpenVEX for one Go workload, in a throwaway k3d cluster.

Steps, each logged to <out>/ci.log:
  1. govulncheck (source)  -> which non-stdlib OSV entries are symbol-level, and their packages
  2. coverage build         -> go build -cover -coverpkg=<main>,<vulnerable packages>   (main is required, P0 lesson)
  3. image + import         -> <engine> build, tarball, k3d image import (checked on the node with crictl)
  4. cluster                -> k3d cluster with a hostPath for GOCOVERDIR
  5. deploy                 -> the project's own manifest, image/env/volume patched
  6. exercise               -> the workload's commands from the config
  7. collect                -> scale to 0 (SIGTERM flushes counters), go tool covdata textfmt
  8. L1                     -> Trivy on the built binary
  9. chain                  -> lab/symcov.py per OSV, lab/chain.py -> OpenVEX; gate on config.fail_on
                              optional config.untrusted_by_rule: {OSV: {"entry": <function on the
                              govulncheck call path>, "reason": <text>}} (an author decision)

usage: vexproof.py CONFIG.json   (ci/metrics-server.json lists the fields; lab/full.py fills the paths)
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..", "lab")


def sh(cmd, log, check=True, capture=False):
    log.write(f"$ {cmd}\n")
    log.flush()
    p = subprocess.run(cmd, shell=True, text=True, capture_output=True, check=False)
    log.write(p.stdout[-4000:] + p.stderr[-4000:] + f"[rc={p.returncode}]\n")
    log.flush()
    if check and p.returncode:
        raise SystemExit(f"step failed: {cmd}\n{p.stderr[-2000:]}")
    return p.stdout if capture else p.returncode


def stream(path):
    raw, dec, i = open(path).read(), json.JSONDecoder(), 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return
        obj, i = dec.raw_decode(raw, i)
        yield obj


def symbol_level(govulncheck_json):
    """{osv_id: [import paths]} for non-stdlib entries that govulncheck reached at symbol level"""
    osv, sym = {}, set()
    for o in stream(govulncheck_json):
        if "osv" in o:
            osv[o["osv"]["id"]] = o["osv"]
        f = o.get("finding")
        if f and (f.get("trace") or [{}])[0].get("function"):
            sym.add(f["osv"])
    out = {}
    for oid in sorted(sym):
        paths = [i["path"] for a in osv[oid]["affected"] if a["package"]["name"] != "stdlib"
                 for i in a.get("ecosystem_specific", {}).get("imports", []) if i.get("symbols")]
        if paths:
            out[oid] = paths
    return out


def main():
    cfg = json.load(open(sys.argv[1]))
    out = os.path.abspath(cfg["out"])
    os.makedirs(out, exist_ok=True)
    src = os.path.abspath(cfg["src"])
    # the cluster mounts one fixed host dir for counters; reruns reuse it, so it is emptied here and copied per run
    cov = os.path.abspath(cfg.get("covdir", os.path.join(out, "covdata")))
    if os.path.isdir(cov):
        for f in os.listdir(cov):
            os.remove(os.path.join(cov, f))
    else:
        os.makedirs(cov)
    os.chmod(cov, 0o777)
    log = open(os.path.join(out, "ci.log"), "w")
    eng = cfg.get("engine") or os.environ.get("ENGINE", "docker")
    go = f"{eng} run --rm -v {src}:/src:Z -v {cfg['gocache']}:/root/.cache:Z -v {cfg['gomod']}:/go/pkg/mod:Z " \
         f"-v {cfg['gobin']}:/gobin:Z -v {out}:/out:Z -w /src -e GOTOOLCHAIN=local -e GOFLAGS=-mod=vendor -e CGO_ENABLED=0 {cfg['go_image']}"
    t0 = time.time()

    # 1. govulncheck
    gv = os.path.join(out, "govulncheck.json")
    sh(f"{go} sh -c '/gobin/govulncheck -format json {cfg['main_dir']} > /out/govulncheck.json'", log)
    targets = symbol_level(gv)
    pkgs = sorted({p for v in targets.values() for p in v})
    log.write(f"symbol-level OSV: {json.dumps(targets)}\n")

    # 2. coverage build (main package must be listed, or no counters are written)
    coverpkg = ",".join([cfg["main_pkg"]] + pkgs)
    # -buildvcs=false: like the measured build (no VCS stamp); git in the container cannot read a host-owned checkout
    sh(f"{go} go build -trimpath -buildvcs=false -cover -coverpkg={coverpkg} -o /out/{cfg['binary']} {cfg['main_dir']}", log)

    # 3. image + import
    open(os.path.join(out, "Containerfile"), "w").write(
        f"FROM docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\nCOPY {cfg['binary']} /{cfg['binary']}\nENTRYPOINT [\"/{cfg['binary']}\"]\n")
    img = cfg["image"]
    sh(f"{eng} build -q -t {img} -f {out}/Containerfile {out}", log)
    # Docker 29 (containerd store): save one platform, or k3s imports an image with missing blobs
    if sh(f"{eng} save --platform linux/amd64 -o {out}/image.tar {img}", log, check=False):
        sh(f"{eng} save -o {out}/image.tar {img}", log)

    # 4. cluster
    c = cfg["cluster"]
    if sh(f"k3d cluster get {c}", log, check=False):
        sh(f"k3d cluster create {c} --image {cfg['k3s_image']} --agents 0 -v {cov}:/cov@server:0 "
           f"{cfg.get('k3d_args', '')} --wait", log)
    sh(f"k3d image import -c {c} {out}/image.tar", log)
    # k3d reports success even when containerd dropped the image: check it on the node
    if img.split(":")[0] not in sh(f"{eng} exec k3d-{c}-server-0 crictl images", log, capture=True):
        raise SystemExit(f"image {img} not on the k3d node after import")
    kc = f"kubectl --context k3d-{c}"

    # 5. deploy: project manifest, patched
    sh(f"{kc} apply -f {cfg['manifest']}", log)
    ns, dep, ctr = cfg["namespace"], cfg["deployment"], cfg["container"]
    patch = {"spec": {"template": {"spec": {
        "securityContext": {"runAsUser": 0},
        "volumes": [{"name": "cov", "hostPath": {"path": "/cov", "type": "Directory"}}],
        "containers": [{"name": ctr, "image": img, "imagePullPolicy": "Never",
                        "args": cfg["args"], "env": [{"name": "GOCOVERDIR", "value": "/cov"}],
                        "securityContext": {"runAsNonRoot": False, "runAsUser": 0},
                        "volumeMounts": [{"name": "cov", "mountPath": "/cov"}]}]}}}}
    sh(f"{kc} -n {ns} patch deployment {dep} --type strategic -p '{json.dumps(patch)}'", log)
    sh(f"{kc} -n {ns} scale deployment/{dep} --replicas=1", log)  # a previous run left it at 0
    sh(f"{kc} -n {ns} rollout status deployment/{dep} --timeout=180s", log)

    # 6. exercise
    for cmd in cfg["exercise"]:
        sh(cmd.replace("KC", kc), log, check=False)

    # 7. collect: graceful stop flushes the counters
    sh(f"{kc} -n {ns} scale deployment/{dep} --replicas=0", log)
    sh(f"{kc} -n {ns} wait --for=delete pod -l {cfg['selector']} --timeout=120s", log, check=False)
    sh(f"{eng} run --rm -v {out}:/out:Z -v {cov}:/cov:Z {cfg['go_image']} sh -c 'go tool covdata textfmt -i=/cov -o /out/cov.txt && mkdir -p /out/covdata && cp /cov/* /out/covdata/'", log)

    # 8. L1
    sh(f"{eng} run --rm -v {out}:/scan:Z -v {cfg['trivycache']}:/root/.cache:Z docker.io/aquasec/trivy:0.58.2 "
       f"rootfs --scanners vuln --format json --output /scan/trivy.json /scan/{cfg['binary']}", log)

    # 9. chain
    rows = os.path.join(out, "measurements.tsv")
    first = True
    with open(rows, "w") as fh:
        for oid in targets:
            r = sh(f"python3 {LAB}/symcov.py --target {cfg['binary']} --govulncheck {gv} --trivy {out}/trivy.json "
                   f"--trivy-target {cfg['binary']} --cov {out}/cov.txt --src {src}/vendor --osv {oid}", log, capture=True)
            lines = r.strip().split("\n")
            for i, line in enumerate(lines):
                if i == 0 and not first:
                    continue
                fh.write(("run\t" if i == 0 else "ci\t") + line + "\n")
            first = False
    chains = os.path.join(out, "chains")
    os.makedirs(chains, exist_ok=True)
    conf = {"measurements": rows, "govulncheck": {cfg["binary"]: gv}, "pclnsym": [], "uprobe_profiles": [],
            "products": {cfg["binary"]: cfg["purl"]}, "evidence_base": os.path.relpath(chains, HERE + "/.."),
            "vex_id": cfg["vex_id"], "author": "vexproof CI recipe (lab run)",
            "openvex_out": os.path.join(out, "openvex.json"),
            "chains": [{"target": cfg["binary"], "osv": oid,
                        "untrusted_by_rule": cfg.get("untrusted_by_rule", {}).get(oid)} for oid in targets]}
    json.dump(conf, open(os.path.join(chains, "config.json"), "w"), indent=1)
    res = sh(f"python3 {LAB}/chain.py {chains}/config.json", log, capture=True)
    log.write(res)
    statuses = [ln.split()[2] for ln in res.strip().split("\n") if ln.strip()]
    failed = [s for s in statuses if s in cfg.get("fail_on", ["affected"])]
    summary = {"seconds": round(time.time() - t0), "symbol_level_osv": len(targets), "statuses": res.strip().split("\n"),
               "gate": "FAIL" if failed else "PASS"}
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1))
    if cfg.get("delete_cluster"):
        sh(f"k3d cluster delete {c}", log, check=False)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
