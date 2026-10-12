#!/usr/bin/env bash
# Compares the pins in scripts/versions.env with the latest upstream stable releases.
# Read-only: it changes nothing. Host tools may be raised by hand; the measured releases (Kubernetes v1.28.2 / v1.36.5,
# metrics-server v0.9.0) and the measurement tools (govulncheck, CodeQL) stay pinned: a newer one is a separate run.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
source "$ROOT/scripts/versions.env"

gh_latest() { curl -fsSL "https://api.github.com/repos/$1/releases/latest" | python3 -c 'import sys,json;print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || echo "?"; }
go_latest() { curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["version"][2:])' 2>/dev/null || echo "?"; }
vuln_latest() { curl -fsSL "https://api.github.com/repos/golang/vuln/tags?per_page=20" | python3 -c '
import sys,json,re
v=[t["name"] for t in json.load(sys.stdin) if re.fullmatch(r"v\d+\.\d+\.\d+",t["name"])]
print(max(v,key=lambda s:tuple(map(int,s[1:].split("."))))) if v else print("?")' 2>/dev/null || echo "?"; }

row() { local s="same"; [ "$2" != "$3" ] && s="NEWER AVAILABLE ($4)"; [ "$3" = "?" ] && s="unknown"; printf '%-12s %-24s %-24s %s\n' "$1" "$2" "$3" "$s"; }
printf '%-12s %-24s %-24s %s\n' COMPONENT PINNED LATEST STATUS
row go          "$GO_VERSION"           "$(go_latest)"                         "host tool: update the pin"
row kubectl     "$KUBECTL_VERSION"      "$(curl -fsSL https://dl.k8s.io/release/stable.txt)" "host tool: update the pin"
row k3d         "$K3D_VERSION"          "$(gh_latest k3d-io/k3d)"              "host tool: update the pin"
row k3s         "${K3S_IMAGE##*:}"      "$(gh_latest k3s-io/k3s | tr + -)"     "cluster image: update the pin"
row govulncheck "$GOVULNCHECK_VERSION"  "$(vuln_latest)"                       "measurement tool: re-measure as a separate run"
row codeql      "v$CODEQL_VERSION"      "$(gh_latest github/codeql-cli-binaries)" "measurement tool: re-measure as a separate run"
printf '%-12s %-24s %-24s %s\n' kubernetes "v1.28.2, v1.36.5" "$(curl -fsSL https://dl.k8s.io/release/stable.txt)" "measured releases: a newer one is a separate run"
