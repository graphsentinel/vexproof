# Custom resources (API group `vexproof.graphsentinel.github.io`, v1alpha1)

The group is under `graphsentinel.github.io`, the GitHub Pages domain of github.com/graphsentinel.

| Kind | What | Status |
|---|---|---|
| `TriggerTest` (`tt`) | runs a known vulnerability's trigger against the shipped binary and against rebuilds that differ only in the fix; compares the result with an oracle written in the spec | schema; **local runner** `lab/trigger/runner.py` (docker or podman) runs it and can patch the CR status; no in-cluster controller |
| `VexScan` (`vs`) | evidence chain for every finding of one image (scanner, shipped symbols, govulncheck, CodeQL, runtime) → OpenVEX | schema only; the pieces exist as scripts (`lab/run_triage.sh`, `lab/codeql/sinkgen/batch.py`, `ci/vexproof.py`) |

`scripts/lab.sh install` applies the CRDs to the lab's k3d cluster (labelled `app.kubernetes.io/managed-by=vexproof-lab`);
`scripts/lab.sh test` checks that a valid `TriggerTest` is accepted and invalid ones are rejected. By hand:

```sh
kubectl apply -f deploy/crds/
kubectl create namespace vexproof
kubectl apply -f examples/triggertest-go-2026-6609.yaml
python3 lab/trigger/runner.py examples/triggertest-go-2026-6609.yaml --status-to <kube-context>
kubectl -n vexproof get tt     # PHASE Succeeded, VERDICT triggered
```

The full example builds two kube-apiserver v1.28.2 arms from source (last vulnerable and first fixed Go), which takes
a while; `lab/trigger/smoke-go-2026-6609.yaml` runs the official binary only.

**What "auto" resolves.**
- `build.go` and `build.tags` come from the shipped binary's buildinfo, and the source ref is checked against the
  `gitVersion` stamped into it.
- `arms[].go: firstFixed | lastVulnerable` comes from the OSV entry's standard-library ranges on vuln.go.dev.
- Every arm's `DefaultGODEBUG` is recorded: `go.mod` is never edited, and its `go` line decides which security
  defaults a rebuilt binary gets.

**Safety.**
- `safety.environment` must be `lab-only` and `runtime.auth.token` must be `lab-generated`; the schema and the runner
  both enforce it.
- The runner starts the target itself and connects only to it (see "Lab-only trigger tests" in the main README).
- A verdict of `not-triggered` is not `not_affected`.
- `onUnexpectedTrigger: stop-and-report`: a trigger on a supported release means a private report
  (security@kubernetes.io), not a publication.

**Verdicts.** `triggered`, `not-triggered` and `inconclusive`. Only `triggered` updates the review file named in
`output.review` (`confirmed`), which turns an affected candidate into `affected` in the automatic chain.
