# vexproof

Evidence chains for VEX statements. For every vulnerability a scanner reports in a Go binary, vexproof collects what
each tool can actually show (the module is listed, the vulnerable symbols survived linking, a static call path
reaches them, untrusted input reaches them, they executed under a workload) and derives one OpenVEX status from the
chain. Missing or contradictory evidence never becomes `not_affected`.

Measured on Kubernetes components (kube-apiserver, kubectl, kubelet at v1.28.2 and v1.36.5) and metrics-server
v0.9.0. This is a lab: it reproduces the measurements and the decision rules, it is not a production scanner.

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Results](#results)
- [Quickstart](#quickstart)
- [How-to](#how-to)
- [Lab-only trigger tests](#lab-only-trigger-tests)
- [Troubleshooting](#troubleshooting)
- [Versions](#versions)
- [Layout](#layout)

## The problem

A scanner lists dozens of CVEs for an image. The developer answers "we never call that code". The claim needs
evidence. A VEX statement records an assessment, it does not prove it, and the five OpenVEX `not_affected`
justifications each need a different kind of proof:

| Justification | Proof it needs |
|---|---|
| `component_not_present` | the component is not in the build |
| `vulnerable_code_not_present` | the vulnerable code is not in the shipped binary |
| `vulnerable_code_not_in_execute_path` | no execution path reaches it |
| `vulnerable_code_cannot_be_controlled_by_adversary` | untrusted input cannot reach it |
| `inline_mitigations_already_exist` | a mitigation stops it |

Today's tools each answer one of these questions, with defaults that can silently give the wrong answer. vexproof
joins them per finding and records which layer said what.

## How it works

One chain per (binary, OSV entry):

| Layer | Question | Tool |
|---|---|---|
| L1 | is the module listed? | Trivy on the binary |
| P | are the vulnerable symbols in the **shipped** binary? | `.gopclntab` listing of the official binary (`lab/pclnsym`), positive control from the same package or a parent at a `/` boundary |
| L3 | does a static call path reach them? | govulncheck (source mode with the shipped Go version and build tags, and binary mode) |
| T | does untrusted data reach their input? | CodeQL taint query with sinks derived from the OSV symbols, or a declared entry-point rule bound to the call path |
| L4a | did they execute under a workload? | coverage build of the same source (`go build -cover`) |
| L4b | did they execute in the shipped binary? | kernel uprobes on the official binary (Mode B) |
| L6 | does the documented trigger reproduce? | `TriggerTest`: the shipped binary vs. rebuilds that differ only in the fix |
| L5 | does the client's input reach the vulnerable function **in the shipped binary**, and does the trigger separate the vulnerable from the fixed build? | exercise layer: `TriggerTest` with four arms (shipped, same-Go rebuild, last vulnerable, first fixed), argument provenance (uprobes at `.gopclntab` offsets read the function's argument and match a per-request marker, `lab/trigger/attribution.py`), and a pre-registered all-N gate (`lab/trigger/gate.py`) |

Decision rules (`lab/chain.py`, `lab/autochain.py`; every rule has a regression test in `lab/tests/`):

- `affected`: executed (a coverage row with a positive count, or a hit on a vulnerable-symbol uprobe of this target)
  **and** a CodeQL flow whose rule names the OSV, or an entry-point rule whose entry function is a frame of the OSV's
  symbol-level call path. In the automatic chains, `affected` additionally needs a passed exercise-layer gate for that
  binary and OSV (all pre-registered runs meet the row-1 rule: shipped and vulnerable arms trigger, the fixed arm does
  not, and the marked client input reaches the OSV symbol as its argument) and a review file marked `confirmed` that
  names the gate by its sha256. Otherwise the chain stays `under_investigation` with the sub-state `unevaluated`,
  `inconclusive` (failed gate, with the failing conditions) or `gate_invalid`.
- `not_affected / vulnerable_code_not_present`: the symbols are absent from the shipped binary's full listing, a
  positive control from the same package (or a parent at a `/` boundary) is present, and (automatic chains) none of the names occurs anywhere in the
  binary's bytes, in any spelling (plain, `%2e`-escaped, generic instantiations).
- `not_affected / vulnerable_code_not_in_execute_path`: a coverage row for every package the OSV names, each with a
  count of exactly 0, and no symbol-level finding for the OSV anywhere in the govulncheck output.
- Anything else is `under_investigation` with a note that says which evidence is missing or contradictory.
  "Not observed" is never "unreachable"; a scanner that reports nothing is never `component_not_present`.

The rules were reviewed in several rounds until no reviewer could construct an input that yields `not_affected` or
`affected` without the evidence above (contradictory rows, unknown counts, foreign packages, look-alike package
names, escaped and generic symbol names, duplicate OSV records, SARIF results of other rules, and more; see
`lab/tests/test_chain_failclosed.py` and `lab/tests/test_autochain.py`).

## Results

Each number below is regenerated by `scripts/lab.sh test` from the reference inputs in `evidence/reference/` (the
**fast** column), re-measured from source by `FULL=1` (the **full** column), or kept as reference evidence of a run
that the lab does not repeat.

| Result | Evidence | Reproduced by |
|---|---|---|
| Status matched the maintainers' published decision in **6 of 6** cases (4 CVEs, 2 releases); justification matched in 4 of the 5 cases where one was given or implied | `lab/decisions.py` (ground truth with issue links) | fast |
| v1.28.2 kube-apiserver, HTTP/2 rapid reset (GO-2023-2102): **executed**, 60 of 109 blocks; `affected` via an entry-point rule on its call path | coverage rebuild c0, `evidence/reference/measurements/` | fast (chain), reference (coverage run) |
| v1.28.2 kube-apiserver, x/net/html tokenizer (GO-2025-3595): executed 36 of 88 blocks via the service proxy to an HTML backend, CodeQL taint path from the upstream response body; `affected` | c1 coverage, c3 CodeQL | fast (chain), reference (runs) |
| v1.28.2 kubectl, same advisory: symbol-reachable, **never executed**: stays `under_investigation` | c0/c1 | fast |
| v1.28.2 kube-apiserver, GO-2024-3333 and GO-2024-3321: vulnerable code absent from the official binary (positive controls: other `x/net/html` and 115 other `x/crypto` functions present): `not_affected / vulnerable_code_not_present` | c2 `.gopclntab` listings | fast |
| v1.36.5 kubelet and kube-apiserver, CVE-2026-39883 (GO-2026-5426): flagged by Trivy and by govulncheck at symbol level; the BSD/Solaris host-ID code is not compiled for Linux: each shipped binary contains all 49 functions of `otel/sdk/resource` and none of them is BSD or exec code: `not_affected / vulnerable_code_not_present` | c4 | fast |
| metrics-server v0.9.0 CI recipe, 5 runs: five x/net HTTP/2 advisories **executed** in 5 of 5 runs; gRPC and x/text advisories symbol-reachable but not executed in any run; all 8 stay `under_investigation` (executed, but no taint path or rule was declared) | c6 r1–r5 | fast (chains), full (one new run from source) |
| Mode B on the official metrics-server image in k3d: HTTP/2 server-side probes fire (`processHeaders`, `closeStream`, `readMetaFrame`). Two client-side probes showed 0 although the coverage build executed the code: `RoundTripOpt`, and `(*transportResponseBody).Read`, which is the compiler-generated pointer wrapper (`<autogenerated>:1`) of the method that runs; so 0 hits is not "not executed", and a probe must sit on the function that is called. The full path re-ran it on 2026-10-13 from a clean VM: server-side 60/56/56, wrapper 0, `RoundTripOpt` 0, and the value method `transportResponseBody.Read` behind the wrapper 27. | c7 | full |
| Six official binaries, 193 automatic chains: 5 `not_affected` (OSV entries restricted to Windows), 2 `affected` (GO-2026-6609 and GO-2025-4009 in kube-apiserver v1.28.2: exercise gate passed, review cites it), 186 `under_investigation`, each with one sub-state: 117 not measured (no runtime layer for that binary yet), 22 not observed under the workload, 18 executed without a demonstrated input path, 10 rejected in review, 8 executed with input only from upstream responses, 8 with OSV symbols too coarse for CodeQL, 2 candidates not yet exercised, 1 failed exercise gate (GO-2026-4341); static layers alone never give `affected` | c9, c11, c12, gates | fast |
| CodeQL over-approximation on metrics-server (every argument of every reached symbol is a sink, no LLM): taint paths for 6 of 23 open findings | c11 | fast (inputs), full (new run) |
| GO-2026-6609 trigger on kube-apiserver v1.28.2: with 50,000 ranges the official binary and a go1.26.8 rebuild answer 206 and use 0.66–0.78 s CPU per request; the go1.26.9 rebuild answers 200 with 0.02 s; anonymous requests are refused (403) | c13, c14 | fast (official binary only), reference (rebuilt arms) |
| Exercise layer, GO-2026-6609 (Range): the marked Range header of every request reaches `net/http.parseRange` in the official binary as its argument (13/13 markers per run; the server also calls it internally with an empty argument); four arms, gate **passed 5/5**. A first cohort failed 3/5 (the CPU window included a pause after each response); the measurement was corrected and re-registered before the second cohort | c15 (all 13 runs), `evidence/reference/gates/` | fast (gate check), reference (runs; need sudo and perf) |
| Exercise layer, GO-2025-4009 (encoding/pem): CSR create with 20,000 BEGIN lines in a 480 KB body: 12–18 s container CPU per request on the official binary vs. 0.05–0.41 s for the same number of bytes without BEGIN lines; first fixed Go 0.04–0.30 s; the marked PEM bytes reach `pem.Decode` as its argument on every observed request; gate **passed 5/5** | c16 | fast (gate check), reference (runs) |
| Exercise layer, GO-2026-4341 (net/url query parameters): 4 of 5 runs met every condition; one run failed suppression (one fixed-arm request of 52 ms) and argument multiplicity (one request parsed 7 times instead of 6): gate **failed**, the chain is `under_investigation / inconclusive` | c16 | fast (gate check), reference (runs) |

Traps that the cross-checking layers exposed (each with its evidence in `evidence/reference/`):

1. **CodeQL skips `vendor/` by default.** Without `--extractor-option=go.extract_vendor_dirs=true` the kube-apiserver
   database has 0 `html.NewTokenizer` call sites; with it, 3. A "no taint path" from the default database is
   meaningless (`c3-codeql/db-sanity.csv`).
2. **govulncheck's example path is one of many.** For rapid reset it went through `DebugSocket`, not the listener the
   workload used.
3. **Coverage with go1.20 and `-coverpkg` without the main package writes no counters at all**, which reads like
   "nothing executed"; the CI recipe always lists the main package.
4. **Source-mode govulncheck with another Go version or without the shipped build tags** hides the standard-library
   CVEs of the shipped Go (39 for v1.28.2) or reports packages the build drops (`grpcnotrace`).
5. **A rebuild with a fixed Go is not necessarily fixed:** a `go.mod` with an old `go` line embeds
   `DefaultGODEBUG=urlmaxqueryparams=0`, so the query-parameter limit stays off (recorded per arm by the trigger
   runner).
6. **Scanner freshness:** five x/net advisories published at 22:31 UTC were missed by a Trivy database updated at
   15:33 UTC the same day.

Not claimed:

- No new vulnerability. Every CVE here is known and fixed; the measured v1.28.2 release is end-of-life.
- "Not observed" is not "unreachable", and "executed" is not "exploitable".
- Matching six maintainer decisions is status agreement on six cases, not a proof that the engine is correct.
- The LLM sink proposals (below) are inputs to a query template, never evidence.
- Exercise-layer results hold for the tested authenticated request path and lab configuration; they measure the
  container's CPU during the request, not an advisory's full impact (GO-2026-4341 is about memory exhaustion), and
  argument provenance shows that the marked bytes reach the function's entry, not every intermediate call.
- Go only.

## Quickstart

On a fresh Ubuntu 24.04 or 26.04 (amd64) host or VM with sudo:

```sh
git clone https://github.com/graphsentinel/vexproof.git
cd vexproof
scripts/platform.sh install && scripts/platform.sh cluster-up
scripts/lab.sh all
```

`lab.sh all` builds the `.gopclntab` lister, checks and unpacks the reference inputs, downloads the six official
binaries (sha256-checked), regenerates their full symbol listings and checks them against the measured ones, then
runs the fast path 5 times and compares every result with `lab/expected.tsv`. It ends with `Result: OK` (exit 0) or a
list of differences (exit 1). The summary is in `lab/.runtime/summary.md`, each run's outputs in `results/run-<n>/`.

Measured in multipass VMs with 8 vCPUs, 16 GB RAM and a 60 GB disk: `platform.sh install && cluster-up` 1.5–2 min,
`lab.sh all` with 5 runs 9.3 min on Ubuntu 26.04 (about 75–90 s per run after the first install) and 3.4 min with
1 run on Ubuntu 24.04. `FULL=1` adds 29 min (CodeQL database 20 min of it); after it the VM used 14 GB of disk
(4.9 GB under `lab/.runtime/`).

## How-to

Two layers, each with its own script.

**Layer 1, `scripts/platform.sh`: tools and the k3d cluster.**

| Command | What |
|---|---|
| `install` | Ubuntu packages that are missing (Docker from `docker.io` + `docker-buildx`, python3 with yaml and pytest, git, openssl, curl, unzip); Go, kubectl and k3d at the pinned versions, sha256-checked, only if missing. An existing Docker engine is left as it is. `UPGRADE_TOOLS=1` replaces existing tools. |
| `FULL=1 … install` | also govulncheck and the CodeQL CLI (needed by `FULL=1` tests) |
| `cluster-up` / `cluster-down` | k3d cluster `vexproof`, used for the custom resources; the fast path runs without it (the `crd` step is then skipped) |
| `status` | tool versions and the cluster |

**Layer 2, `scripts/lab.sh`: the lab.**

| Command | What |
|---|---|
| `build` | `lab/pclnsym` into `lab/.runtime/bin/` |
| `install` | reference inputs (`lab/fixtures.tsv`: sha256 of every file), official binaries, regenerated listings, trigger images; with a cluster: the CRDs and the `vexproof` namespace, labelled `app.kubernetes.io/managed-by=vexproof-lab` |
| `test` | `RUNS` fast-path runs (default 5), then `summary`; `FULL=1` adds the full path once |
| `summary` | compare all runs with `lab/expected.tsv` |
| `uninstall` / `reinstall` | remove what `install` created (an existing CRD or namespace it did not create is never touched); the download cache is kept unless `PURGE=1` |
| `status` / `all` | state / `build` + `install` + `test` |

Fast-path steps per run: `unit` (pytest), `chains` (hand-configured chains + OpenVEX for v1.28.2, v1.36.5 and CI
runs r1–r5), `triage` (report + automatic chains for six binaries), `decisions` (ground truth), `trigger` (lab-only
GO-2026-6609 check on the official kube-apiserver v1.28.2), `crd` (with a cluster: a valid `TriggerTest` is accepted
and invalid ones are rejected by the API server).

Options: `RUNS`, `FULL`, `ENGINE` (`docker` or `podman`; detected), `KUBE_CONTEXT` (default `k3d-vexproof`).

**Full path (`FULL=1`, `lab/full.py`)**, once after the fast path, on metrics-server v0.9.0 from source:
the CI recipe (`ci/vexproof.py`: govulncheck, coverage rebuild, k3d cluster `vexproof-ci`, the project's release
manifest, workload, Trivy, chains), Mode B uprobes on the official image's binary, and a CodeQL database + the
all-arguments taint batch. A newer vulnerability database may add OSV entries; they are listed, the measured ones are
compared. Results in `results/full/`.

**OpenVEX output.** Each chains directory has `openvex.json` and one JSON per chain with every layer's evidence;
`results/run-<n>/report/vex-report.html` groups every finding of every binary by evidence strength.

**CI recipe for your own Go service.** `ci/vexproof.py CONFIG.json` with the fields of `ci/metrics-server.json`
(source, manifest, workload commands, gate); `ci/github-actions.yaml` is a draft workflow. It needs no secrets.

**LLM sink proposals (optional).** `lab/codeql/sinkgen/` can ask an LLM where untrusted data enters a vulnerable
symbol; the query text always comes from a fixed template. It uses any model on an Ollama endpoint:
`VEXPROOF_LLM_MODEL=<model>` and `VEXPROOF_OLLAMA_URL` (default: a local Ollama at `http://localhost:11434`); no API
key. Proposals are unstable between samples and were validated only against a small reference set; the
`--mode all-args` baseline needs no LLM. In one feasibility step (c1) a human completed the last step of an input the
LLM proposed.

**Custom resources.** `deploy/crds/`: `TriggerTest` (runs a known vulnerability's trigger against the shipped binary
and fix-only rebuilds; the local runner `lab/trigger/runner.py` patches its status) and `VexScan` (schema only).
There is no in-cluster controller.

## Lab-only trigger tests

The trigger runner validates a **known, fixed** vulnerability against **the lab's own** instance; it is not an attack
tool and cannot be pointed at anything else:

- The runner starts the target itself (a container with the run's label, etcd as a sidecar). A spec cannot name a
  host, URL, kubeconfig or cluster; such specs are refused, as are fixed credentials and requests over
  `safety.maxRequestBytes`.
- Each run creates its own CA, a server certificate for `vexproof-lab-target`, service-account keys and a bearer
  token under `lab/.runtime/trigger/<run>/` and deletes them after the run; none of them is written to the results.
- Before every request the runner checks that the labelled container is running and publishes the port on
  `127.0.0.1` only; TLS trusts only the run's CA, checks the server name and the certificate fingerprint; redirects
  are refused. Any mismatch stops the run.
- Exercise-layer specs (`lab/trigger/l5-*.yaml`) add argument provenance: they need `sudo` for tracefs uprobes and
  `perf`, record one process of the run's own container, and pin the decoding (GOARCH, Go version, register ABI,
  the prologue bytes at the probe offset). Run one with `python3 lab/trigger/runner.py lab/trigger/l5-go-2025-4009.yaml
  --out results/l5-4009-1`, then `python3 lab/trigger/gate.py --spec … --n 5 --out GATE.json RUN_DIR...` and
  `gate.py --check GATE.json --osv OSV --binary BIN`. Thresholds live in the spec and are fixed before the counted runs.
- A trigger that fires on a supported release is a private report to the project's security contact
  (security@kubernetes.io for Kubernetes, security@golang.org for Go), not a publication.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker not usable` right after `platform.sh install` | the new docker group applies to new shells; the scripts re-run themselves under `sg docker`, otherwise log out and in |
| `sha256 mismatch` for an official binary | a partial download; run `lab.sh install` again (the file is removed) |
| `regenerated file differs from the measured one` | the official binary or `lab/pclnsym` differs; check `scripts/versions.env` |
| `trigger` step fails with `not ready` | the etcd or base image could not be pulled; `docker pull` them manually (digests in `scripts/versions.env`) |
| `crd` step missing | no cluster at `KUBE_CONTEXT`; `scripts/platform.sh cluster-up` then `lab.sh reinstall` |
| `FULL=1`: `codeql not found` | `FULL=1 scripts/platform.sh install` |
| k3d image import reports success but the pod cannot start | Docker 29 containerd store; the CI recipe saves one platform and checks the node with `crictl images` |

## Versions

`scripts/versions.env` pins everything; `scripts/check-versions.sh` lists newer releases. Host tools are the latest
stable on 2026-10-13 (Go 1.27.2, kubectl v1.37.1, k3d v5.9.0, k3s v1.37.1-k3s1). The measured releases (Kubernetes
v1.28.2 and v1.36.5, metrics-server v0.9.0) and the measurement tools (govulncheck v1.8.0, CodeQL 2.25.2) stay at the
versions the results were measured with; a newer one is a separate run. v1.37.1 ships the fixed OpenTelemetry SDK, so
the v1.36.5 finding does not apply there.

End-to-end runs from the committed tree in fresh multipass VMs (`scripts/multipass-e2e.sh`: install, cluster, all
runs, reinstall + one more run, uninstall, platform check), outputs in `evidence/e2e-multipass/`:

| Run | Ubuntu | Commit | Result |
|---|---|---|---|
| [20261012T235455Z-ubuntu26.04](evidence/e2e-multipass/20261012T235455Z-ubuntu26.04/summary.md) | 26.04.1 | `055d17f` | 5 runs, 6/6 steps and 249/249 expected rows each; reinstall, uninstall OK |
| [20261012T235620Z-ubuntu24.04](evidence/e2e-multipass/20261012T235620Z-ubuntu24.04/summary.md) | 24.04 | `055d17f` | 1 run, 6/6 steps, 249/249; reinstall, uninstall OK |
| [20261012T231041Z-ubuntu26.04-full](evidence/e2e-multipass/20261012T231041Z-ubuntu26.04-full/main/results/full/summary.json) | 26.04.1 | `ad973b7` | 5 runs 249/249 + `FULL=1` 25/25 checks; its reinstall step stopped on a `lab.sh status` exit code, fixed in `055d17f` (no lab code change) |

## Layout

| Path | What |
|---|---|
| `scripts/` | `platform.sh`, `lab.sh`, `versions.env`, `summary.py`, `make_expected.py`, `multipass-e2e.sh`, `check-versions.sh` |
| `lab/chain.py`, `lab/autochain.py` | decision rules (hand-configured and automatic chains) |
| `lab/report.py`, `lab/decisions.py`, `lab/run_triage.sh` | triage report, ground truth, the automatic run |
| `lab/symcov.py`, `lab/verdict_independent.py` | OSV symbols to coverage blocks; independent check with `go tool cover` |
| `lab/pclnsym/` | function listing from `.gopclntab` (survives stripping) |
| `lab/codeql/` | taint queries, sink generation and the batch runner |
| `lab/trigger/` | `TriggerTest` runner, the fast-path spec, the exercise-layer specs (`l5-*.yaml`), argument provenance (`attribution.py`) and gates (`gate.py`) |
| `lab/full.py` | the full path |
| `lab/configs/`, `lab/fixtures.tsv`, `lab/expected.tsv` | chain configs, input manifest, expected results |
| `lab/tests/` | unit tests of the decision rules, autochain and the runner |
| `ci/` | CI recipe, its metrics-server config, Mode B DaemonSet, draft GitHub workflow |
| `deploy/crds/`, `examples/` | custom resources and example objects |
| `evidence/reference/` | reference inputs and run outputs, one per run type (c0–c16), and the exercise-layer gates (`gates/`) |

## Licence

Apache-2.0. See `NOTICE`.
