#!/usr/bin/env python3
"""Reference evidence and fast-path inputs (lab/fixtures.tsv).

  fixtures.py unpack OUT       check the sha256 of every published file (inputs and reference evidence), unpack the
                               inputs into OUT/<unpacked_path> (gunzip *.gz) and check the sha256 of the result
  fixtures.py regenerated OUT  list the files that are rebuilt from the official binaries (unpacked_path, sha256)
  fixtures.py check OUT        check the sha256 of the regenerated files in OUT
Run from the project root. Any mismatch or missing file exits non-zero.
"""
import csv
import gzip
import hashlib
import os
import sys

MANIFEST = "lab/fixtures.tsv"


def rows():
    with open(MANIFEST) as fh:
        return list(csv.DictReader((ln for ln in fh if not ln.startswith("#")), delimiter="\t"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    cmd, out = sys.argv[1], os.path.abspath(sys.argv[2])
    bad = []
    if cmd == "unpack":
        n = 0
        for r in rows():
            if r["role"] == "regenerated":
                continue
            if not os.path.isfile(r["repo_path"]):
                bad.append(f"missing {r['repo_path']}")
                continue
            data = open(r["repo_path"], "rb").read()
            if sha(data) != r["repo_sha256"]:
                bad.append(f"sha256 mismatch {r['repo_path']}")
                continue
            if r["role"] != "input":
                continue
            if r["repo_path"].endswith(".gz"):
                data = gzip.decompress(data)
            if sha(data) != r["unpacked_sha256"]:
                bad.append(f"sha256 mismatch after unpacking {r['repo_path']}")
                continue
            dst = os.path.join(out, r["unpacked_path"])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, "wb").write(data)
            n += 1
        print(f"{n} inputs unpacked into {out}")
    elif cmd == "regenerated":
        for r in rows():
            if r["role"] == "regenerated":
                print(f"{r['unpacked_path']}\t{r['unpacked_sha256']}")
    elif cmd == "check":
        for r in rows():
            if r["role"] != "regenerated":
                continue
            p = os.path.join(out, r["unpacked_path"])
            if not os.path.isfile(p):
                bad.append(f"missing {r['unpacked_path']}")
            elif sha(open(p, "rb").read()) != r["unpacked_sha256"]:
                bad.append(f"regenerated file differs from the measured one: {r['unpacked_path']}")
        print("regenerated files match" if not bad else "")
    else:
        raise SystemExit(__doc__)
    for b in bad:
        print(f"error: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
