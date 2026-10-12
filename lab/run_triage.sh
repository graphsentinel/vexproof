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
# runtime layer: coverage run c12 (FULL=1 rebuilds it) + CodeQL batch (all-args, source kinds) + review files
auto v1.28.2 kube-apiserver "pkg:golang/k8s.io/kubernetes@v1.28.2#cmd/kube-apiserver" \
  --cov evidence/c12-cov-v1.28.2/measurements.tsv --codeql evidence/c11-codeql-batch/v1.28.2--kube-apiserver-all-args \
  --reviews evidence/reviews/v1.28.2/kube-apiserver
auto v1.28.2 kubectl "pkg:golang/k8s.io/kubernetes@v1.28.2#cmd/kubectl"
auto v1.36.5 kube-apiserver "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kube-apiserver"
auto v1.36.5 kubelet "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kubelet"
auto v1.36.5 kubectl "pkg:golang/k8s.io/kubernetes@v1.36.5#cmd/kubectl"
auto metrics-server-v0.9.0 metrics-server "pkg:golang/sigs.k8s.io/metrics-server@v0.9.0"
python3 lab/report.py
