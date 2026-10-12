#!/bin/sh
# five runs of the CI recipe on the same cluster; each run gets its own evidence dir (r1..r5)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
CFG=$1
for k in 1 2 3 4 5; do
  python3 - "$CFG" "$k" > /tmp/vexproof-run.json <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["out"] = c["out"] + f"-r{sys.argv[2]}"; print(json.dumps(c))
PY
  echo "== run $k"
  python3 "$HERE/vexproof.py" /tmp/vexproof-run.json | tail -3
done
