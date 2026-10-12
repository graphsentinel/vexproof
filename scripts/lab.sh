#!/usr/bin/env bash
# Layer 2, the lab: on top of scripts/platform.sh (tools; the k3d cluster is optional).
#
#   scripts/lab.sh build       build lab/pclnsym (the .gopclntab lister) into lab/.runtime/bin
#   scripts/lab.sh install     check and unpack the reference inputs (lab/fixtures.tsv), download the official binaries
#                              (sha256-checked), regenerate their full .gopclntab listings and check them against the
#                              measured ones, pull the trigger images; with a k3d cluster: apply the custom resources
#   scripts/lab.sh test        RUNS (default 5) runs of the fast path, then 'summary'; FULL=1 adds the full path once
#   scripts/lab.sh summary     compare the runs with lab/expected.tsv (exit 1 on any difference or missing result)
#   scripts/lab.sh uninstall   remove what install created (keeps the download cache; PURGE=1 removes it too)
#   scripts/lab.sh reinstall   uninstall + install
#   scripts/lab.sh status      what is installed, last summary
#   scripts/lab.sh all         build + install + test
#
# Fast path, per run (each in a fresh work directory under lab/.runtime/work/):
#   unit       pytest lab/tests (fail-closed decision rules, autochain, trigger runner)
#   chains     evidence chains + OpenVEX from the reference inputs: v1.28.2, v1.36.5, CI runs r1..r5 (lab/chain.py)
#   triage     report + automatic static chains for the six official binaries (lab/run_triage.sh)
#   decisions  the chains next to the maintainers' published decisions (lab/decisions.py)
#   trigger    GO-2026-6609 on the official kube-apiserver v1.28.2 + etcd, started by the runner itself (lab only)
#   crd        with the k3d cluster: a valid TriggerTest is accepted, invalid ones are rejected by the API server
# FULL=1 (once, after the fast-path runs): lab/full.py (metrics-server from source: CI recipe, Mode B, CodeQL).
#
# Options (environment): RUNS (5), FULL (0), ENGINE (docker | podman, detected), KUBE_CONTEXT (k3d-vexproof).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
source "$ROOT/scripts/versions.env"
RT=$ROOT/lab/.runtime; IN=$RT/in; CACHE=$RT/cache; BIN=$CACHE/bin
KCTX=${KUBE_CONTEXT:-k3d-$CLUSTER}
MANAGED=app.kubernetes.io/managed-by=vexproof-lab
export PATH="/usr/local/go/bin:$PATH"
log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
ME=$(id -un)

engine() {
  if [ -n "${ENGINE:-}" ]; then echo "$ENGINE"; return; fi
  if command -v docker >/dev/null && docker info >/dev/null 2>&1; then echo docker; return; fi
  if command -v podman >/dev/null && podman info >/dev/null 2>&1; then echo podman; return; fi
  echo none
}
need_engine() {  # right after 'platform.sh install' the docker group is not active in this shell yet: run again under it
  local e; e=$(engine)
  [ "$e" != none ] && { export ENGINE=$e; return 0; }
  if [ -z "${LAB_SG:-}" ] && getent group docker | grep -qw "$ME" && command -v sg >/dev/null; then
    export LAB_SG=1; exec sg docker -c "$(printf '%q ' "$0" "$@")"
  fi
  die "no usable container engine (docker or podman): scripts/platform.sh install"
}
cluster_up() { kubectl --context "$KCTX" get --raw /readyz >/dev/null 2>&1; }

# release dir / target / sha256 of each official binary
OFFICIAL="v1.28.2 kube-apiserver $BIN_v1_28_2_kube_apiserver
v1.28.2 kubectl $BIN_v1_28_2_kubectl
v1.36.5 kube-apiserver $BIN_v1_36_5_kube_apiserver
v1.36.5 kubelet $BIN_v1_36_5_kubelet
v1.36.5 kubectl $BIN_v1_36_5_kubectl
metrics-server-v0.9.0 metrics-server $BIN_metrics_server_v0_9_0_metrics_server"

# ---------------------------------------------------------------- build / install
cmd_build() {
  command -v go >/dev/null || die "go not found: scripts/platform.sh install"
  log "lab/pclnsym -> lab/.runtime/bin/pclnsym ($(go env GOVERSION))"
  mkdir -p "$RT/bin"
  (cd "$ROOT/lab/pclnsym" && GOFLAGS=-mod=mod CGO_ENABLED=0 go build -trimpath -o "$RT/bin/pclnsym" .)
}

fetch_official() {  # <release dir> <target> <sha256>
  local rel=$1 t=$2 want=$3 dst="$BIN/$1/$2" tmp
  mkdir -p "$BIN/$rel"
  if [ -f "$dst" ] && [ "$(sha256sum "$dst" | cut -d' ' -f1)" = "$want" ]; then echo "  $rel/$t (cached)"; return; fi
  tmp="$dst.part"; rm -f "$tmp"
  if [ "$t" = metrics-server ]; then
    "$ENGINE" pull -q "$METRICS_SERVER_IMAGE" >/dev/null
    local cid; cid=$("$ENGINE" create "$METRICS_SERVER_IMAGE")
    "$ENGINE" cp "$cid:/metrics-server" "$tmp"; "$ENGINE" rm "$cid" >/dev/null
  else
    curl -fsSLo "$tmp" "$K8S_DL/$rel/bin/linux/amd64/$t"
  fi
  echo "$want  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; die "sha256 mismatch: $rel/$t"; }
  chmod 0755 "$tmp"; mv "$tmp" "$dst"; echo "  $rel/$t (downloaded, sha256 ok)"
}

cmd_install() {
  need_engine install
  [ -x "$RT/bin/pclnsym" ] || cmd_build
  log "reference inputs (lab/fixtures.tsv: sha256 of every published file, unpacked into lab/.runtime/in)"
  rm -rf "$IN"; mkdir -p "$IN"
  (cd "$ROOT" && python3 lab/fixtures.py unpack "$IN/evidence")
  log "official binaries (linux/amd64, sha256 from scripts/versions.env)"
  while read -r rel t sha; do fetch_official "$rel" "$t" "$sha"; done <<< "$OFFICIAL"
  log "full .gopclntab listings regenerated from the official binaries (not published; checked against the measured ones)"
  while read -r rel t sha; do
    "$RT/bin/pclnsym" "$BIN/$rel/$t" "~" > "$IN/evidence/c9-autochain-$rel/pclnsym-all-$t.txt"
  done <<< "$OFFICIAL"
  (cd "$ROOT" && python3 lab/fixtures.py check "$IN/evidence")
  log "trigger images ($ENGINE)"
  "$ENGINE" pull -q "$ETCD_IMAGE" >/dev/null && "$ENGINE" pull -q "$BASE_IMAGE" >/dev/null && echo "  etcd, base image pulled"
  if cluster_up; then
    log "custom resources in $KCTX (labelled $MANAGED)"
    local crd
    for crd in "$ROOT"/deploy/crds/*.yaml; do
      local name; name=$(python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["metadata"]["name"])' "$crd")
      if kubectl --context "$KCTX" get crd "$name" >/dev/null 2>&1 && \
         [ "$(kubectl --context "$KCTX" get crd "$name" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')" != vexproof-lab ]; then
        die "CRD $name exists and was not created by this lab: not touched"
      fi
      kubectl --context "$KCTX" apply -f "$crd" >/dev/null
      kubectl --context "$KCTX" label crd "$name" "$MANAGED" --overwrite >/dev/null
      kubectl --context "$KCTX" wait --for=condition=Established "crd/$name" --timeout=60s >/dev/null
      echo "  $name"
    done
    if ! kubectl --context "$KCTX" get ns vexproof >/dev/null 2>&1; then
      kubectl --context "$KCTX" create namespace vexproof >/dev/null
      kubectl --context "$KCTX" label ns vexproof "$MANAGED" >/dev/null
    elif [ "$(kubectl --context "$KCTX" get ns vexproof -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')" != vexproof-lab ]; then
      die "namespace vexproof exists and was not created by this lab: not touched"
    fi
  else
    log "no cluster at $KCTX: custom resources skipped (scripts/platform.sh cluster-up to include them)"
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ > "$RT/installed"
  echo "installed"
}

cmd_uninstall() {
  local e; e=$(engine)
  if [ "$e" != none ]; then
    local ids; ids=$("$e" ps -aq --filter label=vexproof.lab || true)
    [ -n "$ids" ] && { log "lab containers"; "$e" rm -f $ids >/dev/null; }
  fi
  if cluster_up; then
    local crd
    for crd in "$ROOT"/deploy/crds/*.yaml; do
      local name; name=$(python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["metadata"]["name"])' "$crd")
      if [ "$(kubectl --context "$KCTX" get crd "$name" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null)" = vexproof-lab ]; then
        kubectl --context "$KCTX" delete crd "$name" --wait=true >/dev/null && echo "  CRD $name deleted"
      fi
    done
    if [ "$(kubectl --context "$KCTX" get ns vexproof -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null)" = vexproof-lab ]; then
      local left; left=$(kubectl --context "$KCTX" get all,configmaps,secrets -n vexproof --no-headers 2>/dev/null \
        | { grep -v -e '^configmap/kube-root-ca.crt' -e '^serviceaccount/' || true; } | wc -l)
      [ "$left" = 0 ] || die "namespace vexproof has $left objects that are not the lab's: not deleted"
      kubectl --context "$KCTX" delete ns vexproof --wait=true >/dev/null && echo "  namespace vexproof deleted"
    fi
  fi
  rm -rf "$IN" "$RT/work" "$RT/trigger" "$RT/installed" "$RT/plan.json" "$RT/test-started" "$RT/summary.md"
  [ "${PURGE:-0}" = 1 ] && rm -rf "$RT"
  # nothing of the lab may be left (download cache and results/ are kept on purpose)
  if [ "$e" != none ] && [ -n "$("$e" ps -aq --filter label=vexproof.lab)" ]; then die "lab containers left"; fi
  if cluster_up && kubectl --context "$KCTX" get crd -l "$MANAGED" --no-headers 2>/dev/null | grep -q .; then die "lab CRDs left"; fi
  echo "uninstalled (kept: lab/.runtime/cache and bin, results/)"
}

# ---------------------------------------------------------------- test
run_step() {  # <run dir> <step> <command...>: exit code and log per step; never stops the run
  local d=$1 s=$2; shift 2
  local start=$SECONDS rc=0
  ( cd "$d" && "$@" ) > "$d/results/logs/$s.log" 2>&1 || rc=$?
  printf '%s\t%s\t%s\n' "$s" "$rc" "$((SECONDS - start))" >> "$d/results/steps.tsv"
  printf '  %-10s exit %s, %s s\n' "$s" "$rc" "$((SECONDS - start))"
}

# step functions run under 'cmd || rc=$?', where bash ignores set -e: every command is checked explicitly
step_chains() {  # in the work dir
  local c r d
  for c in chains-v1.28.2 chains-v1.36.5; do
    mkdir -p "results/$c" && cp "lab/configs/$c.json" "results/$c/config.json" || return 1
    python3 lab/chain.py "results/$c/config.json" || return 1
  done
  for r in r1 r2 r3 r4 r5; do
    d="results/chains-ci-metrics-server-v0.9.0-$r"
    mkdir -p "$d" && sed "s/{run}/$r/g" lab/configs/chains-ci-metrics-server.json > "$d/config.json" || return 1
    python3 lab/chain.py "$d/config.json" || return 1
  done
}

step_crd() {  # a valid spec is accepted (server-side dry run); invalid ones are rejected by the schema
  kubectl --context "$KCTX" apply --dry-run=server -f examples/triggertest-go-2026-6609.yaml || return 1
  python3 - "$KCTX" <<'PY'
import copy, subprocess, sys, yaml
ctx = sys.argv[1]
base = yaml.safe_load(open("examples/triggertest-go-2026-6609.yaml"))
bad = {"osv-id": lambda d: d["spec"]["vulnerability"].update(osv="CVE-x"),
       "no-safety": lambda d: d["spec"].pop("safety"),
       "fixed-credential": lambda d: d["spec"]["runtime"]["auth"].update(tokenSource="file"),
       "not-lab-only": lambda d: d["spec"]["safety"].update(environment="production"),
       "one-arm": lambda d: d["spec"].update(arms=d["spec"]["arms"][:1])}
fails = 0
for name, mutate in bad.items():
    d = copy.deepcopy(base); mutate(d)
    p = subprocess.run(["kubectl", "--context", ctx, "apply", "--dry-run=server", "-f", "-"], input=yaml.safe_dump(d),
                       text=True, capture_output=True)
    print(f"{name}: {'rejected' if p.returncode else 'ACCEPTED'}")
    fails += p.returncode == 0
sys.exit(1 if fails else 0)
PY
}

cmd_test() {
  need_engine test
  [ -f "$RT/installed" ] || die "not installed: scripts/lab.sh install"
  local runs=${RUNS:-5} full=${FULL:-0} crd=0
  cluster_up && crd=1
  # the plan is written before the runs (complete=0), so an interrupted test cannot look complete
  date -u +%Y-%m-%dT%H:%M:%SZ > "$RT/test-started"
  python3 - "$RT/plan.json" "$runs" "$full" "$crd" <<'PY'
import json, sys
out, runs, full, crd = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4] == "1"
steps = ["unit", "chains", "triage", "decisions", "trigger"] + (["crd"] if crd else [])
json.dump({"runs": runs, "steps": steps, "full": full, "complete": 0}, open(out, "w"), indent=1)
PY
  rm -rf "$RT/work"; mkdir -p "$RT/work" "$ROOT/results"
  local i
  for i in $(seq 1 "$runs"); do
    local d="$RT/work/run-$i"
    mkdir -p "$d/results/logs"; : > "$d/results/steps.tsv"
    ln -s "$ROOT/lab" "$d/lab"; ln -s "$ROOT/examples" "$d/examples"; ln -s "$IN/evidence" "$d/evidence"
    log "run $i/$runs ($d)"
    run_step "$d" unit python3 -m pytest -q -p no:cacheprovider lab/tests
    run_step "$d" chains step_chains
    run_step "$d" triage env BIN="$BIN" sh lab/run_triage.sh
    run_step "$d" decisions python3 lab/decisions.py
    run_step "$d" trigger env ENGINE="$ENGINE" VEXPROOF_RUNTIME="$RT" VEXPROOF_BASE_IMAGE="$BASE_IMAGE" \
      python3 lab/trigger/runner.py lab/trigger/smoke-go-2026-6609.yaml --out "$d/results/trigger-smoke"
    [ "$crd" = 1 ] && run_step "$d" crd step_crd
    rm -rf "$ROOT/results/run-$i"; cp -r "$d/results" "$ROOT/results/run-$i"
  done
  if [ "$full" = 1 ]; then
    log "FULL=1: lab/full.py"
    local start=$SECONDS rc=0
    mkdir -p "$ROOT/results/full"
    (cd "$ROOT" && ENGINE=$ENGINE python3 lab/full.py) > "$ROOT/results/full/full.log" 2>&1 || rc=$?
    printf 'full\t%s\t%s\n' "$rc" "$((SECONDS - start))" > "$ROOT/results/full/steps.tsv"
    echo "  full: exit $rc, $((SECONDS - start)) s"
  fi
  python3 -c 'import json,sys;p=json.load(open(sys.argv[1]));p["complete"]=1;json.dump(p,open(sys.argv[1],"w"),indent=1)' "$RT/plan.json"
  cmd_summary
}

cmd_summary() {
  [ -f "$RT/plan.json" ] || die "no test plan: scripts/lab.sh test"
  python3 "$ROOT/scripts/summary.py" --plan "$RT/plan.json" --results "$ROOT/results" --expected "$ROOT/lab/expected.tsv" \
    --out "$RT/summary.md"
}

cmd_status() {
  log "lab"
  [ -f "$RT/installed" ] && echo "  installed $(cat "$RT/installed")" || echo "  not installed"
  [ -x "$RT/bin/pclnsym" ] && echo "  pclnsym built" || echo "  pclnsym not built"
  echo "  cached official binaries: $(find "$BIN" -type f 2>/dev/null | wc -l) of 6"
  local e; e=$(engine)
  [ "$e" != none ] && echo "  lab containers running: $("$e" ps -q --filter label=vexproof.lab | wc -l)"
  if cluster_up; then echo "  custom resources: $(kubectl --context "$KCTX" get crd -l "$MANAGED" --no-headers 2>/dev/null | wc -l)"
  else echo "  cluster $KCTX: not reachable"; fi
  [ -f "$RT/summary.md" ] && { log "last summary"; head -20 "$RT/summary.md"; }
}

case "${1:-}" in
  build) cmd_build ;;
  install) cmd_install ;;
  uninstall) cmd_uninstall ;;
  reinstall) cmd_uninstall; cmd_install ;;
  test) cmd_test ;;
  summary) cmd_summary ;;
  status) cmd_status ;;
  all) cmd_build; cmd_install; cmd_test ;;
  *) sed -n '2,26p' "$0"; exit 2 ;;
esac
