#!/usr/bin/env python3
"""Argument provenance on the shipped binary (exercise layer E2a): do the bytes a request carried reach the OSV
symbol as its argument?

The official binaries are stripped, so the probe is a kernel uprobe defined through tracefs at the symbol's file
offset (entry address from the .gopclntab listing, lab/pclnsym, as in Mode B). The uprobe fetches the argument's
length and its first 64 bytes from the registers the spec names (Go amd64 ABIInternal: a string argument is pointer +
length in consecutive integer registers); perf records the hits with frame-pointer stacks for context.

Fails closed (private plan "exercise layer" §3 E2a):
  - decoding is pinned: amd64, Go >= 1.17, and the probe site starts with the ABIInternal stack-check prologue
    (CMPQ SP or a LEAQ'd register against 16(R14)); otherwise the run stops
  - every request carries a fresh marker in its first 64 bytes; a hit is attributed to a request only on the exact
    length and the exact captured prefix (bytes beyond 64 are not compared)
  - calibration: >= 3 benign requests with distinct markers and lengths, one longer than 64 bytes; each must be seen
    the expected number of times; lost events and failed reads make the window instrumentation_failed

Lab only: needs root (sudo -n) for tracefs and perf, and records one process of the run's own container.
"""
import bisect
import os
import re
import secrets
import struct
import subprocess
import time

TRACEFS = "/sys/kernel/tracing"
WORDS = 8  # 8 x u64 = the first 64 bytes of the argument


class Listing:
    """address <-> function name from a pclnsym listing (0xADDR TAB name TAB file:line)"""

    def __init__(self, path):
        rows = []
        for ln in open(path):
            p = ln.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].startswith("0x"):
                rows.append((int(p[0], 16), p[1]))
        if not rows:
            raise SystemExit(f"{path}: no pclnsym rows")
        rows.sort()
        self.addrs = [a for a, _ in rows]
        self.names = [n for _, n in rows]
        self.by_name = {}
        for a, n in rows:
            self.by_name.setdefault(n, a)
        self.end = self.addrs[-1] + (1 << 20)  # the last function's end is unknown

    def name(self, addr):
        if addr < self.addrs[0] or addr >= self.end:
            return None
        return self.names[bisect.bisect_right(self.addrs, addr) - 1]

    def addr(self, name):
        if name not in self.by_name:
            raise SystemExit(f"{name}: not in the listing (pclntab spelling, e.g. net/http.parseRange)")
        return self.by_name[name]


def file_offset(binary, addr):
    """virtual address -> file offset through the ELF64 PT_LOAD segments"""
    with open(binary, "rb") as fh:
        b = fh.read(4096)
    phoff, = struct.unpack_from("<Q", b, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", b, 0x36)
    with open(binary, "rb") as fh:
        fh.seek(phoff)
        ph = fh.read(phentsize * phnum)
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", ph, i * phentsize)
        if p_type == 1 and p_vaddr <= addr < p_vaddr + p_filesz:
            return addr - p_vaddr + p_offset
    raise SystemExit(f"address {addr:#x} in no PT_LOAD segment")


# ABIInternal stack-check prologues on amd64 (R14 holds the goroutine): CMPQ SP, 16(R14) or
# LEAQ -n(SP), R12 / CMPQ R12, 16(R14)
PROLOGUE = re.compile(rb"^(\x49\x3b\x66\x10|\x4c\x8d\x64\x24.\x4d\x3b\x66\x10|\x4c\x8d\xa4\x24....\x4d\x3b\x66\x10)", re.S)


def pin_decoding(binary, offset, goarch, go):
    """the checks that make the register map meaningful; returns the facts, raises on a mismatch"""
    with open(binary, "rb") as fh:
        fh.seek(offset)
        head = fh.read(16)
    facts = {"goarch": goarch, "go": go, "prologue": head.hex(), "abi": "amd64 ABIInternal"}
    if goarch != "amd64":
        raise SystemExit(f"E2a: GOARCH {goarch} not supported (register map is amd64 ABIInternal)")
    if tuple(int(x) for x in re.findall(r"\d+", go)[:2]) < (1, 17):
        raise SystemExit(f"E2a: go{go} predates the register ABI")
    if not PROLOGUE.match(head):
        raise SystemExit(f"E2a: probe site does not start with an ABIInternal stack-check prologue: {head.hex()}")
    return facts


def marker():
    """a fresh per-request marker: an odd number, so it never equals an even range offset of the generator"""
    return 2 * secrets.randbelow(40000) + 10001


class ArgWindow:
    """one bounded recording window on one process: tracefs uprobe with argument fetch + perf record"""

    def __init__(self, run, pid, binary, offset, regs):
        self.group = "vxl5_" + re.sub(r"[^a-z0-9]", "", run.lower())[:20]
        self.pid, self.binary, self.offset = pid, binary, offset
        lr, pr = regs["length"], regs["pointer"]
        if not (re.fullmatch(r"[a-z0-9]+", lr) and re.fullmatch(r"[a-z0-9]+", pr)):
            raise SystemExit(f"E2a: bad register names {regs}")
        self.fetch = f"len=%{lr}:s64 " + " ".join(f"w{i}=+{8 * i}(%{pr}):u64" for i in range(WORDS))
        self.data = None
        self.proc = None

    def _events(self, line):
        subprocess.run(["sudo", "-n", "tee", "-a", f"{TRACEFS}/uprobe_events"], input=line + "\n", text=True,
                       capture_output=True, check=True)

    def start(self, out_dir):
        self.data = os.path.join(out_dir, "e2a-perf.data")
        self._events(f"p:{self.group}/arg {self.binary}:{self.offset:#x} {self.fetch}")
        self.proc = subprocess.Popen(["sudo", "-n", "perf", "record", "-q", "-e", f"{self.group}:arg",
                                      "--call-graph", "fp", "-p", str(self.pid), "-o", self.data],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        if self.proc.poll() is not None:
            self.close()
            raise SystemExit("E2a: perf record did not start")

    def stop(self):
        subprocess.run(["sudo", "-n", "kill", "-INT", str(self.proc.pid)], check=False)
        try:
            self.proc.wait(60)
        finally:
            self.close()
        subprocess.run(["sudo", "-n", "chmod", "644", self.data], check=True)
        script = subprocess.run(["sudo", "-n", "perf", "script", "-i", self.data, "-F", "event,trace,ip",
                                 "--show-lost-events"], capture_output=True, text=True, check=True).stdout
        stats = subprocess.run(["sudo", "-n", "perf", "report", "-i", self.data, "--stats"],
                               capture_output=True, text=True, check=False).stdout
        return script, stats

    def close(self):
        subprocess.run(["sudo", "-n", "tee", "-a", f"{TRACEFS}/uprobe_events"], input=f"-:{self.group}/arg\n",
                       text=True, capture_output=True)


def parse(script, stats, listing):
    """perf script output -> hits with length, captured prefix, symbolized stack; lost and failed-read counts"""
    hits, failed = [], 0
    lost = sum(int(x) for x in re.findall(r"(?m)^\s*LOST (\d+) events", script))
    m = re.search(r"(?m)^\s*LOST events:\s*(\d+)", stats or "")
    lost += int(m.group(1)) if m else 0
    for block in script.strip().split("\n\n"):
        lines = block.strip().splitlines()
        if not lines or ":arg:" not in lines[0]:
            continue
        f = dict(re.findall(r"\b(len|w\d)=(\S+)", lines[0]))
        try:
            n = int(f["len"], 0)
            words = [int(f[f"w{i}"], 0) for i in range(WORDS)]
        except (KeyError, ValueError):
            failed += 1
            continue
        raw = b"".join(w.to_bytes(8, "little") for w in words)
        addrs = [int(x, 16) for x in re.findall(r"(?m)^\s*([0-9a-f]+)\b", "\n".join(lines[1:]))]
        hits.append({"length": n, "prefix": raw[:min(max(n, 0), 64)],
                     "stack": [listing.name(a) for a in addrs]})
    return hits, lost, failed


def match(hits, expected):
    """expected: marker -> argument bytes (as sent). Per-marker counts, plus unmatched hits (internal calls)."""
    counts = {mk: 0 for mk in expected}
    unmatched = []
    for h in hits:
        mk = next((k for k, v in expected.items() if h["length"] == len(v) and h["prefix"] == v[:64]), None)
        if mk is None:
            unmatched.append(h)
        else:
            counts[mk] += 1
    return counts, unmatched


def evaluate(hits, lost, failed, calib, trigger, others=None, per_request=None):
    """calib, trigger, others (the other marked requests of the window, e.g. benign baselines): marker -> argument
    bytes. Returns the E2a result of one window (plan §3 E2a, §4 row 1)."""
    others = others or {}
    expected = {**calib, **trigger, **others}
    counts, unmatched = match(hits, expected)
    # hits per request on this path: given by the spec, or learned from the calibration requests (all must agree)
    seen = {counts[k] for k in calib}
    learned = next(iter(seen)) if len(seen) == 1 and min(seen) >= 1 else None
    if per_request is None:
        per_request = learned
    lens = [len(v) for v in calib.values()]
    checks = {
        "calibration_inputs": len(calib) >= 3 and len(set(lens)) == len(lens) and max(lens) > 64,
        "calibration_distinct_from_trigger": not ({len(v) for v in calib.values()} & {len(v) for v in trigger.values()}),
        "markers_unique": len({v[:64] for v in expected.values()}) == len(expected),
        "no_lost_events": lost == 0,
        "no_failed_reads": failed == 0,
        "calibration_counts": per_request is not None and all(counts[k] == per_request for k in calib),
        "other_request_counts": all(counts[k] == per_request for k in others),
        "trigger_counts": bool(trigger) and all(counts[k] == per_request for k in trigger),
    }
    instrumentation = all(checks[k] for k in ("calibration_inputs", "calibration_distinct_from_trigger",
                                              "markers_unique", "no_lost_events", "no_failed_reads",
                                              "calibration_counts", "other_request_counts"))
    state = ("attributed_client" if instrumentation and checks["trigger_counts"]
             else "instrumentation_failed" if not instrumentation else "attribution_incomplete")
    return {"state": state, "checks": checks, "hits_per_request": per_request,
            "per_marker": {str(k): v for k, v in counts.items()},
            "unmatched_hits": len(unmatched),
            "unmatched_lengths": sorted({h["length"] for h in unmatched}),
            "example_stack": next((h["stack"][:30] for h in hits if h["length"] in {len(v) for v in trigger.values()}), None)}
