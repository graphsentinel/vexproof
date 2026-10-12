#!/usr/bin/env python3
"""Fetch severity (GitHub Advisory Database: severity + CVSS) for every OSV in the report's govulncheck files.

One small JSON per OSV in evidence/c10-severity/<OSV>.json (source URL, fetch time, raw fields), plus index.json.
Read-only queries of public data via `gh api`; existing files are kept, except those without a severity yet (new
advisories are often unrated for days), which a rerun asks again.
usage: severity_fetch.py   (run from the project root)
"""
import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain import stream  # noqa: E402
from report import TARGETS  # noqa: E402

OUT = "evidence/c10-severity"


def gh(path):
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None


def main():
    os.makedirs(OUT, exist_ok=True)
    osvs = {}
    for t in TARGETS:
        for o in stream(t[2]):
            if "osv" in o:
                osvs[o["osv"]["id"]] = o["osv"].get("aliases", [])
    index = {}
    for oid, aliases in sorted(osvs.items()):
        f = os.path.join(OUT, f"{oid}.json")
        if not os.path.exists(f) or json.load(open(f)).get("severity") in (None, "unknown"):
            ghsa = next((a for a in aliases if a.startswith("GHSA-")), None)
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            adv, src = None, None
            if ghsa:
                src = f"/advisories/{ghsa}"
                adv = gh(src)
            if not adv and cve:
                src = f"/advisories?cve_id={cve}"
                r = gh(src)
                adv = r[0] if r else None
            cv = ((adv or {}).get("cvss_severities") or {})
            rec = {"osv": oid, "aliases": aliases, "source": f"https://api.github.com{src}" if src else None,
                   "fetched": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "ghsa_id": (adv or {}).get("ghsa_id"), "severity": (adv or {}).get("severity"),
                   "cvss_v3": (cv.get("cvss_v3") or {}).get("score"), "cvss_v4": (cv.get("cvss_v4") or {}).get("score"),
                   "cvss_vector": (cv.get("cvss_v3") or {}).get("vector_string")}
            json.dump(rec, open(f, "w"), indent=1)
        rec = json.load(open(f))
        index[oid] = {"severity": rec["severity"], "cvss_v3": rec["cvss_v3"], "file": f"{oid}.json"}
    json.dump(index, open(os.path.join(OUT, "index.json"), "w"), indent=1)
    known = sum(1 for v in index.values() if v["severity"] and v["severity"] != "unknown")
    print(f"{len(index)} OSVs, {known} with a GitHub severity")


if __name__ == "__main__":
    main()
