# c17 — exercise layer P3: coverage rebuilds under versioned workload profiles

Counted runs of plan §10 (protocols in the private review record l5-r25 … r30): kubectl v1.28.2 and v1.36.5 (3 runs
each), kube-apiserver v1.36.5 and v1.28.2 (3 runs each; plus one D-set separation run for v1.28.2), metrics-server
v0.9.0 (3 runs). Driver `lab/p3/cov.py`, profiles `lab/workloads/`.

- `builds/*-provenance.json`: source, Go, GOOS/GOARCH, CGO, tags, coverpkg, sha256 of the shipped and the rebuilt binary,
  dependency graph equal to the shipped binary's (metrics-server builds in each run: see its run.json).
- `runs/<run>/`: run.json (every invocation or step with exit code / status, PID-matched counter files, validity),
  manifest.json (per (OSV, package): executed / zero / incomplete; GOOS; symcov sha256), pkglist.txt (packages in the
  counter metadata), symcov.tsv, cov.txt.gz (go tool covdata textfmt). Raw counter files, images and binaries are not
  published.
- `rows/`: the cross-run rows fed to autochain `--cov` (kubectl ×2, kube-apiserver v1.36.5, metrics-server); the
  kube-apiserver v1.28.2 P3 cohort (reported next to c12, not fed); the kubectl v1.28.2 rows before the GOOS correction
  and the D-set single run (descriptive only), kept for disclosure.

Published copy: in the kubectl runs' run.json, the recorded output of `kubectl config view --minify` is replaced by a
note (kubectl had masked the client certificate and key as DATA+OMITTED); nothing else is changed.
