# c18 — exercise layer P3b: input-path analysis of the chains executed in P3

One CodeQL database per target (never shared), built with the shipped binary's Go version (official go.dev tarball,
sha256-checked), its build tags, GOOS/GOARCH and CGO setting, `go.extract_vendor_dirs=true`; then
`lab/codeql/sinkgen/batch.py --mode all-args` (no LLM; template v3). Databases are not published (several GB each;
`identity.json` records how to rebuild them).

- `kubectl-v1.28.2/`, `kubectl-v1.36.5/`, `kube-apiserver-v1.36.5/`: identity.json (CodeQL and Go versions, go env,
  tags, source tree hash, vendor/modules.txt sha256), db-create.log, batch.log, `batch/` (index.json, summary.tsv,
  combined/taint.csv and sites.csv, per OSV result.json and the queries; binary .bqrs files omitted).
  The first P3b run did not pass the shipped binary's listing to batch.py; these batches were re-scored with
  `batch.py --rescore … --pclnsym` from their archived taint.csv (no CodeQL re-run).
- `metrics-server-v0.9.0-c11-rescored/`: c11's metrics-server all-args batch (run before source kinds and without the
  listing), re-scored the same way; c11 itself is unchanged. As in c11, the unused `model` field is neutralised.
