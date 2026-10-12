#!/bin/sh
# deterministic kubectl input set (D-set): every subcommand's --help + real operations
K="/b/kubectl-cover --kubeconfig=/r/in/kubeconfig"
log(){ echo "{\"cmd\":\"$*\"}" >> /r/in/det-invocations.jsonl; }
: > /r/in/det-invocations.jsonl
for sc in $($K --help 2>/dev/null | awk '/^  [a-z]/{print $1}'); do log "$sc --help"; $K $sc --help >/dev/null 2>&1; done
for c in "version" "api-resources" "get ns" "create ns team-a" "apply -f /r/in/cm.yaml" "get cm demo -n team-a -o yaml" "get cm demo -n team-a -o json" "describe cm demo -n team-a" "explain pods" "explain deployment.spec" "auth can-i get pods" "config view" "get --raw /openapi/v2" "get --raw /healthz" "delete cm demo -n team-a" "get pods -A" "top pods" "cluster-info" "diff -f /r/in/cm.yaml"; do log "$c"; $K $c >/dev/null 2>&1; done
echo done
