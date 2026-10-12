#!/usr/bin/env bash
# End-to-end check of the README quickstart in a fresh Ubuntu VM (multipass), from zero:
#   copy what a clone contains -> platform.sh install -> platform.sh cluster-up -> lab.sh all
#   -> lab.sh reinstall + one more test run (the lab can be removed and installed again) -> lab.sh uninstall
#   -> fetch results.
#
#   scripts/multipass-e2e.sh                         Ubuntu 26.04, RUNS=5, VM vexproof-e2e (deleted at the end on success)
#   UBUNTU=24.04 RUNS=1 scripts/multipass-e2e.sh
#   FULL=1 RUNS=1 scripts/multipass-e2e.sh           also the full path (metrics-server from source: CI recipe, Mode B,
#                                                    CodeQL); needs more disk and time
#
# Options (environment): UBUNTU (26.04), VM (vexproof-e2e), CPUS (8), MEM (16G), DISK (60G), RUNS (5), FULL (0),
#   REINSTALL_CHECK (1), KEEP (0: delete the VM afterwards; a failed run always keeps it), OUT (results/e2e-multipass).
# Output: $OUT/<UTC>-ubuntu<ver>[-full]/ (logs per step, summary.md, raw results archive, environment).
# Nothing from the host is passed into the VM except the source archive: no token, SSH agent or credential helper.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
UBUNTU=${UBUNTU:-26.04}; VM=${VM:-vexproof-e2e}; CPUS=${CPUS:-8}; MEM=${MEM:-16G}; DISK=${DISK:-60G}
RUNS=${RUNS:-5}; FULL=${FULL:-0}; KEEP=${KEEP:-0}; REINSTALL_CHECK=${REINSTALL_CHECK:-1}
# the source state is read before this run writes anything (its output directory)
CLEAN=0; [ -z "$(cd "$ROOT" && git status --porcelain 2>/dev/null)" ] && CLEAN=1
OUT=${OUT:-$ROOT/results/e2e-multipass}/$(date -u +%Y%m%dT%H%M%SZ)-ubuntu$UBUNTU$([ "$FULL" = 1 ] && echo -full || true)
mkdir -p "$OUT"
log() { printf '\n==> %s\n' "$*" | tee -a "$OUT/host.log"; }

command -v multipass >/dev/null || { echo "multipass not installed (sudo snap install multipass)" >&2; exit 1; }
if multipass info "$VM" >/dev/null 2>&1; then echo "VM $VM exists; delete it first: multipass delete --purge $VM" >&2; exit 1; fi

log "launch $VM: Ubuntu $UBUNTU, $CPUS CPU, $MEM, $DISK"
multipass launch "$UBUNTU" --name "$VM" --cpus "$CPUS" --memory "$MEM" --disk "$DISK" --timeout 900
# the VM is kept when the run failed, so it can be inspected (multipass delete --purge $VM);
# it is deleted only when the script exits 0 AND every step passed
cleanup() { local s=$?; [ "$KEEP" = 1 ] || [ "$s" != 0 ] || [ "${rc:-1}" != 0 ] || { multipass delete --purge "$VM" 2>/dev/null || true; }; }
trap cleanup EXIT

# Source: the committed tree (git archive HEAD) when the working tree is clean, which is exactly what a clone gets.
# With uncommitted changes the working tree is copied instead (tracked + untracked, not ignored) and recorded as such.
# Streamed over stdin: the multipass snap cannot read the host's /tmp.
if [ "$CLEAN" = 1 ]; then
  SRC="committed tree $(cd "$ROOT" && git rev-parse HEAD)"
  pack() { (cd "$ROOT" && git archive --format=tar.gz HEAD); }
else
  SRC="working tree with uncommitted changes (base $(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo none)); NOT what a clone gets"
  pack() { (cd "$ROOT" && git ls-files -co --exclude-standard | tar -czf - -T -); }
fi
log "copy source: $SRC"
echo "$SRC" > "$OUT/source.txt"
[ "$CLEAN" = 1 ] || (cd "$ROOT" && git status --short) >> "$OUT/source.txt"
pack | multipass exec "$VM" -- bash -c 'mkdir -p ~/lab && tar -xzf - -C ~/lab && find ~/lab -type f | wc -l'

run() { # <log name> <command>: runs in a fresh login shell, so group changes from the install apply
  local name=$1; shift
  log "$*"
  local start=$SECONDS r=0
  multipass exec "$VM" -- sudo -iu ubuntu bash -lc "cd ~/lab && $*" > "$OUT/$name.log" 2>&1 || r=$?
  tail -25 "$OUT/$name.log"
  echo "$name: exit $r, $((SECONDS - start)) s" | tee -a "$OUT/host.log"
  return $r
}

rc=0
step() { [ $rc = 0 ] || return 0; run "$@" || rc=$?; }
# install and cluster-up in one shell, as a reader pastes them: cluster-up must pick up the new docker group itself
step 01-platform-install-cluster-up "FULL=$FULL scripts/platform.sh install && scripts/platform.sh cluster-up"
step 02-lab-all "RUNS=$RUNS FULL=$FULL scripts/lab.sh all"
# raw results of every run, before anything is removed; a failed export fails the run
capture() {
  [ $rc = 0 ] || return 0
  multipass exec "$VM" -- bash -c 'cd ~/lab && tar -czf - results lab/.runtime/summary.md lab/.runtime/plan.json' \
    > "$OUT/raw-results-$1.tar.gz" && tar -tzf "$OUT/raw-results-$1.tar.gz" >/dev/null \
    && echo "raw results: raw-results-$1.tar.gz" | tee -a "$OUT/host.log" \
    || { echo "raw results export failed ($1)" | tee -a "$OUT/host.log"; rc=1; }
}
capture main
multipass exec "$VM" -- bash -c 'cp ~/lab/lab/.runtime/summary.md ~/summary-main.md' || true
if [ "$REINSTALL_CHECK" = 1 ]; then
  step 03-lab-reinstall "scripts/lab.sh reinstall && scripts/lab.sh status"
  step 04-lab-test-after-reinstall "RUNS=1 scripts/lab.sh test"
  capture after-reinstall
  step 05-lab-uninstall "scripts/lab.sh uninstall"
  # 'uninstall' checks that nothing of the lab is left; the platform must still work
  step 06-platform-after-uninstall "scripts/platform.sh status && kubectl --context k3d-vexproof wait --for=condition=Ready node --all --timeout=60s"
fi

log "fetch results"
# the summary is required: a failed or empty fetch fails the run
multipass exec "$VM" -- bash -c 'cat ~/summary-main.md' > "$OUT/summary.md" && [ -s "$OUT/summary.md" ] \
  && grep -q '^\*\*Result: OK\*\*' "$OUT/summary.md" || { echo "summary missing or not OK" | tee -a "$OUT/host.log"; rc=1; }
multipass exec "$VM" -- bash -c 'lsb_release -ds; uname -r; nproc; free -h | head -2; df -h / | tail -1; cd ~/lab && scripts/platform.sh status' \
  > "$OUT/environment.txt" 2>&1 || true
echo "result: exit $rc" | tee -a "$OUT/host.log"
echo "output: $OUT"
exit $rc
