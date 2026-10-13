#!/bin/sh
# Triage for every target in lab/report.py: report -> automatic static chains -> report again.
# Inputs per release live in evidence/c9-autochain-<release>/ (buildinfo, full .gopclntab listing, binary-mode
# govulncheck, matched source-mode govulncheck, Trivy). The official binaries are read from $BIN (scripts/lab.sh
# install downloads them, sha256-checked): <release>/<target>. Run from the work directory (scripts/lab.sh test).
set -eu
BIN=${BIN:?BIN: directory with the official binaries}
python3 lab/report.py > /dev/null
auto() {  # release-dir target purl [extra autochain args]
  r=$1 t=$2 p=$3; shift 3
  python3 lab/autochain.py --report "results/report/$r--$t.json" \
    --pclnsym "evidence/c9-autochain-$r/pclnsym-all-$t.txt" \
    --govulncheck-binary "evidence/c9-autochain-$r/govulncheck-binary-$t.json" \
    --binary "$BIN/$r/$t" --buildinfo "evidence/c9-autochain-$r/buildinfo-$t.txt" \
    --out "results/chains-auto/$r/$t" --purl "$p" "$@" > /dev/null
}
# runtime layer: coverage run c12 (FULL=1 rebuilds it) + CodeQL batch (all-args, source kinds) + review files;
# exercise layer P3b: CodeQL all-args batches per target (evidence/c18-p3b);
# exercise layer P3: execution rows of coverage rebuilds under versioned workload profiles (evidence/c17-p3);
# exercise layer: affected needs a passed gate (evidence/gates, lab/trigger/gate.py) cited by a confirmed review
auto v1.28.2 kube-apiserver "pkg:golang/k8s.io/kubernetes@v1.28.2#cmd/kube-apiserver" \
  --cov evidence/c12-cov-v1.28.2/measurements.tsv --codeql evidence/c11-codeql-batch/v1.28.2--kube-apiserver-all-args \
  --reviews evidence/reviews/v1.28.2/kube-apiserver \
  --exercise evidence/gates/v1.28.2/kube-apiserver --exercise-root .
auto v1.28.2 kubectl "pkg:golang/k8s.io/kubernetes@v1.28.2#cmd/kubectl" \
  --cov evidence/c17-p3/rows/kubectl-v1.28.2.tsv --profile kubectl-workload-v1 \
  --codeql evidence/c18-p3b/kubectl-v1.28.2/batch \
  --exercise evidence/gates/v1.28.2/kubectl --exercise-root .
auto v1.36.5 kube-apiserver "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kube-apiserver" \
  --cov evidence/c17-p3/rows/kube-apiserver-v1.36.5.tsv --profile kube-apiserver-workload-v1 \
  --codeql evidence/c18-p3b/kube-apiserver-v1.36.5/batch \
  --exercise evidence/gates/v1.36.5/kube-apiserver --exercise-root .
auto v1.36.5 kubelet "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kubelet" \
  --exercise evidence/gates/v1.36.5/kubelet --exercise-root .
auto v1.36.5 kubectl "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kubectl" \
  --cov evidence/c17-p3/rows/kubectl-v1.36.5.tsv --profile kubectl-workload-v1 \
  --codeql evidence/c18-p3b/kubectl-v1.36.5/batch \
  --exercise evidence/gates/v1.36.5/kubectl --exercise-root .
auto metrics-server-v0.9.0 metrics-server "pkg:golang/sigs.k8s.io/metrics-server@v0.9.0" \
  --cov evidence/c17-p3/rows/metrics-server-v0.9.0.tsv --profile metrics-server-workload-v1 \
  --codeql evidence/c18-p3b/metrics-server-v0.9.0-c11-rescored \
  --exercise evidence/gates/metrics-server-v0.9.0/metrics-server --exercise-root .
python3 lab/report.py
