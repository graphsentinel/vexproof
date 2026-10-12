#!/usr/bin/env bash
# Layer 1, the platform: tools on the host and the lab's k3d cluster. The lab (scripts/lab.sh) is installed on top.
#
#   scripts/platform.sh install       install what is missing on an Ubuntu host (24.04 / 26.04, amd64)
#   FULL=1 scripts/platform.sh install   also govulncheck and the CodeQL CLI (for scripts/lab.sh test with FULL=1)
#   scripts/platform.sh cluster-up    k3d cluster for the custom resources (TriggerTest, VexScan)
#   scripts/platform.sh cluster-down  delete the k3d cluster
#   scripts/platform.sh status        tool versions, kube context, nodes
#
# 'install' never replaces what is already there:
#   - Ubuntu's own packages, at the version Ubuntu ships: Docker (docker.io, docker-buildx), python3 (+ yaml, pytest),
#     git, openssl, curl, unzip. An existing Docker engine of any source is left unchanged.
#   - not packaged by Ubuntu: Go, kubectl and k3d (and with FULL=1 govulncheck and CodeQL), at the versions in
#     scripts/versions.env, sha256-checked, only when missing. Existing ones are kept and a version difference is
#     reported. UPGRADE_TOOLS=1 replaces them.
# The measured binaries are linux/amd64, so the lab needs an amd64 host.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
source "$ROOT/scripts/versions.env"
log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
K="kubectl --context k3d-$CLUSTER"
ME=$(id -un)
export PATH="/usr/local/go/bin:$PATH"

# ---------------------------------------------------------------- install
# keep <tool> <pinned> <installed version>: true (skip install) when the tool exists and no upgrade was asked for
keep() {
  command -v "$1" >/dev/null 2>&1 || return 1
  [ "${UPGRADE_TOOLS:-0}" = 1 ] && return 1
  if [ "$3" = "$2" ]; then log "$1 $3 already installed"
  else log "$1 $3 already installed, kept (lab pins $2; UPGRADE_TOOLS=1 replaces it)"; fi
}

cmd_install() {
  command -v apt-get >/dev/null || die "install supports Ubuntu (apt); elsewhere install docker, python3 (yaml, pytest), openssl, go, kubectl and k3d yourself"
  local arch; arch=$(dpkg --print-architecture)
  [ "$arch" = amd64 ] || die "the measured binaries are linux/amd64; this host is $arch"
  export DEBIAN_FRONTEND=noninteractive

  # only packages that are missing: 'apt-get install' of an installed package would also upgrade it
  missing_pkgs() { local p; for p in "$@"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || echo "$p"; done; }
  local need; need=$(missing_pkgs git openssl python3 python3-yaml python3-pytest curl ca-certificates unzip)
  if [ -n "$need" ]; then
    log "apt packages (Ubuntu's versions): $(echo $need)"
    sudo apt-get update -y
    # shellcheck disable=SC2086
    sudo -E apt-get install -y --no-install-recommends $need
  else
    log "apt packages: git, openssl, python3 (yaml, pytest), curl, ca-certificates, unzip already installed, left unchanged"
  fi

  local new_group=0
  if command -v docker >/dev/null 2>&1; then
    # any existing engine (docker-ce, docker.io, rootless, snap, Desktop) is left as it is: no service or group change
    log "Docker already installed, left unchanged: $(docker --version 2>/dev/null || echo unknown)"
    docker info >/dev/null 2>&1 || echo "note: 'docker info' fails for $ME; the lab needs a Docker engine this user can use"
  else
    log "Docker from Ubuntu's docker.io and docker-buildx packages, service enabled, $ME added to group docker"
    sudo apt-get update -y
    sudo -E apt-get install -y docker.io docker-buildx
    sudo systemctl enable --now docker
    if ! id -nG "$ME" | grep -qw docker; then sudo usermod -aG docker "$ME"; new_group=1; fi
  fi

  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN

  if ! keep go "go$GO_VERSION" "$(go env GOVERSION 2>/dev/null)"; then
    log "Go $GO_VERSION (go.dev/dl) into /usr/local/go"
    curl -fsSLo "$tmp/go.tgz" "https://go.dev/dl/go$GO_VERSION.linux-$arch.tar.gz"
    echo "$GO_SHA256_AMD64  $tmp/go.tgz" | sha256sum -c -
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$tmp/go.tgz"
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
    sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  fi

  if ! keep kubectl "$KUBECTL_VERSION" "$(kubectl version --client -o json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])' 2>/dev/null)"; then
    log "kubectl $KUBECTL_VERSION (dl.k8s.io)"
    curl -fsSLo "$tmp/kubectl" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl"
    curl -fsSLo "$tmp/kubectl.sha256" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl.sha256"
    echo "$(cat "$tmp/kubectl.sha256")  $tmp/kubectl" | sha256sum -c -
    sudo install -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl
  fi

  if ! keep k3d "$K3D_VERSION" "$(k3d version 2>/dev/null | sed -n 's/^k3d version //p')"; then
    log "k3d $K3D_VERSION (github.com/k3d-io/k3d)"
    curl -fsSLo "$tmp/k3d" "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/k3d-linux-$arch"
    curl -fsSLo "$tmp/k3d.sums" "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/checksums.txt"
    local sum; sum=$(grep "/k3d-linux-$arch\$" "$tmp/k3d.sums" | cut -d' ' -f1 || true)
    [ -n "$sum" ] || die "no checksum for k3d-linux-$arch in checksums.txt"
    echo "$sum  $tmp/k3d" | sha256sum -c -
    sudo install -m 0755 "$tmp/k3d" /usr/local/bin/k3d
  fi

  if [ "${FULL:-0}" = 1 ]; then
    # govulncheck from its module, verified by the Go checksum database (sum.golang.org)
    if ! keep govulncheck "$GOVULNCHECK_VERSION" "$(govulncheck -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p')"; then
      log "govulncheck $GOVULNCHECK_VERSION (go install, checksum database)"
      GOBIN="$tmp" GOFLAGS=-mod=mod go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
      sudo install -m 0755 "$tmp/govulncheck" /usr/local/bin/govulncheck
    fi
    if ! keep codeql "$CODEQL_VERSION" "$(codeql version --format=terse 2>/dev/null)"; then
      log "CodeQL CLI $CODEQL_VERSION (github.com/github/codeql-cli-binaries) into /opt/codeql-$CODEQL_VERSION"
      curl -fsSLo "$tmp/codeql.zip" "https://github.com/github/codeql-cli-binaries/releases/download/v$CODEQL_VERSION/codeql-linux64.zip"
      echo "$CODEQL_SHA256  $tmp/codeql.zip" | sha256sum -c -
      sudo rm -rf "/opt/codeql-$CODEQL_VERSION" && sudo mkdir -p "/opt/codeql-$CODEQL_VERSION"
      sudo unzip -q "$tmp/codeql.zip" -d "/opt/codeql-$CODEQL_VERSION"
      sudo ln -sf "/opt/codeql-$CODEQL_VERSION/codeql/codeql" /usr/local/bin/codeql
    fi
  fi

  # k3s inside Docker needs enough inotify watches; only raised, never lowered
  log "inotify limits for k3s-in-docker"
  local conf="" key want cur
  for kv in fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=1048576; do
    key=${kv%=*}; want=${kv#*=}; cur=$(sysctl -n "$key")
    if [ "$cur" -lt "$want" ]; then conf+="$key=$want"$'\n'; echo "  $key $cur -> $want"; else echo "  $key $cur (kept)"; fi
  done
  if [ -n "$conf" ]; then printf '%s' "$conf" | sudo tee /etc/sysctl.d/99-vexproof.conf >/dev/null; sudo sysctl --system >/dev/null; fi

  cmd_status_tools
  echo
  [ "$new_group" = 1 ] && echo "You were added to the docker group; the next commands pick it up by themselves (sg docker). Next:"
  echo "  scripts/platform.sh cluster-up"
  echo "  scripts/lab.sh all"
}

# ---------------------------------------------------------------- cluster
docker_or_sg() {  # right after 'install' the docker group is not active in this shell yet: run again under it
  docker info >/dev/null 2>&1 && return 0
  if [ -z "${LAB_SG:-}" ] && getent group docker | grep -qw "$ME" && command -v sg >/dev/null; then
    export LAB_SG=1; exec sg docker -c "$(printf '%q ' "$0" "$@")"
  fi
  die "docker not usable by $ME (log out and in again so the docker group applies)"
}

cmd_cluster_up() {
  command -v k3d >/dev/null || die "k3d not found: scripts/platform.sh install"
  docker_or_sg cluster-up
  if k3d cluster list -o json | python3 -c 'import sys,json;sys.exit(0 if any(c["name"]=="'"$CLUSTER"'" for c in json.load(sys.stdin)) else 1)'; then
    log "k3d cluster $CLUSTER exists (scripts/platform.sh cluster-down to start over)"
  else
    log "k3d cluster $CLUSTER ($K3S_IMAGE): 1 server"
    k3d cluster create "$CLUSTER" --image "$K3S_IMAGE" --servers 1 --agents 0 \
      --k3s-arg '--disable=traefik,metrics-server@server:0' --wait
  fi
  $K wait --for=condition=Ready node --all --timeout=180s
  echo "kube context: k3d-$CLUSTER"
}

cmd_cluster_down() {
  command -v k3d >/dev/null || die "k3d not found"
  docker_or_sg cluster-down
  k3d cluster delete "$CLUSTER"
}

# ---------------------------------------------------------------- status
cmd_status_tools() {
  log "tools"
  printf '  %-12s %s\n' docker "$(docker version --format '{{.Server.Version}}' 2>/dev/null || docker --version 2>/dev/null || echo missing)"
  printf '  %-12s %s\n' python3 "$(python3 --version 2>/dev/null | cut -d' ' -f2 || echo missing)"
  printf '  %-12s %s\n' openssl "$(openssl version 2>/dev/null | cut -d' ' -f2 || echo missing)"
  printf '  %-12s %s\n' go "$(go env GOVERSION 2>/dev/null || echo missing)"
  printf '  %-12s %s\n' kubectl "$(kubectl version --client -o json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])' 2>/dev/null || echo missing)"
  printf '  %-12s %s\n' k3d "$(k3d version 2>/dev/null | sed -n 's/^k3d version //p' || echo missing)"
  printf '  %-12s %s\n' govulncheck "$(govulncheck -version 2>/dev/null | sed -n 's/^Scanner: //p' || true)"
  printf '  %-12s %s\n' codeql "$(codeql version --format=terse 2>/dev/null || true)"
}

cmd_status() {
  cmd_status_tools
  log "cluster (context k3d-$CLUSTER)"
  $K get nodes 2>/dev/null || echo "  not running (scripts/platform.sh cluster-up; the lab works without it, the custom-resource check is skipped)"
}

case "${1:-}" in
  install) cmd_install ;;
  cluster-up) cmd_cluster_up ;;
  cluster-down) cmd_cluster_down ;;
  status) cmd_status ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
