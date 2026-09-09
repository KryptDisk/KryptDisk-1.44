#!/usr/bin/env python3
"""
KryptDisk passive mesh monitor
- Auto-discovers Bootstrap* nodes under ~/kryptdisk/app/nodes
- Reads process stats, UDP queues, /proc VM stats, and existing KDK logs
- Does not connect to or modify KryptDisk
- Refreshes terminal dashboard and appends CSV samples

Usage:
    python3 kdk_monitor.py
    python3 kdk_monitor.py --interval 5
    python3 kdk_monitor.py --csv ~/kryptdisk/monitor.csv
"""

import argparse
import csv
import glob
import os
import re
import shutil
import subprocess
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

DEFAULT_NODES = Path.home() / "kryptdisk" / "app" / "nodes"
DEFAULT_CSV = Path.home() / "kryptdisk" / "kdk_monitor.csv"

EVENTS = ("ROAM", "TURN", "INJECT", "QUEUE", "RELIABLE", "PLUCK")
RETRY_RE = re.compile(r"(?:RETRY|RECEIPT-RETRY|MESSAGE-RETRY)")
TAG_RE = re.compile(r"\[([A-Z0-9_-]+)\]")
PORT_RE = re.compile(r"--port\s+(\d+)")
NAME_RE = re.compile(r"--name\s+(.+?)\s+--port\s+")
SS_RE = re.compile(r"UNCONN\s+(\d+)\s+(\d+)\s+\S+:(\d+)\s+")


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True, check=False).stdout


def discover_processes():
    out = run(["ps", "-eo", "pid=,%cpu=,rss=,etime=,args="])
    found = {}
    for line in out.splitlines():
        if "kdk_core.py" not in line or "--kdk-node-child" not in line:
            continue
        parts = line.strip().split(None, 4)
        if len(parts) < 5:
            continue
        pid, cpu, rss, etime, args = parts
        nm = NAME_RE.search(args)
        pm = PORT_RE.search(args)
        if not nm or not pm:
            continue
        found[int(pm.group(1))] = {
            "pid": int(pid), "cpu": float(cpu), "rss_kb": int(rss),
            "etime": etime, "name": nm.group(1).strip()
        }
    return found


def udp_queues():
    out = run(["ss", "-lunp"])
    q = {}
    for line in out.splitlines():
        m = SS_RE.search(line)
        if m:
            recvq, sendq, port = map(int, m.groups())
            q[port] = (recvq, sendq)
    return q


def meminfo():
    vals = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            vals[k] = int(v.strip().split()[0])
    return vals


def vmstat():
    vals = {}
    with open("/proc/vmstat") as f:
        for line in f:
            k, v = line.split()
            if k in ("pswpin", "pswpout"):
                vals[k] = int(v)
    return vals


def cpu_ticks():
    with open("/proc/stat") as f:
        p = f.readline().split()
    nums = list(map(int, p[1:]))
    idle = nums[3] + nums[4]
    total = sum(nums)
    return total, idle


def log_for_node(nodes_dir, name, port):
    node_dir = nodes_dir / name / "logs"
    exact = node_dir / f"node_{port}.log"
    if exact.exists():
        return exact
    candidates = sorted(node_dir.glob("node_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


class LogRate:
    def __init__(self, window=60):
        self.window = window
        self.files = {}
        self.events = {}

    def sample(self, path):
        now = time.time()
        key = str(path) if path else None
        if not path or not path.exists():
            return Counter()

        st = path.stat()
        state = self.files.get(key)

        # First observation establishes a baseline at EOF. Historical log lines
        # must not be counted as events that occurred during the current minute.
        if state is None:
            self.files[key] = {"pos": st.st_size}
            self.events.setdefault(key, deque())
            return Counter()

        # A smaller file means rotation/truncation. Start at the beginning of the
        # new active log; those lines genuinely appeared since our last sample.
        if st.st_size < state["pos"]:
            self.files[key]["pos"] = 0

        pos = self.files[key]["pos"]

        with path.open("r", errors="replace") as f:
            f.seek(pos)
            text = f.read()
            self.files[key]["pos"] = f.tell()

        dq = self.events.setdefault(key, deque())
        for line in text.splitlines():
            tags = TAG_RE.findall(line)
            for tag in tags:
                if tag in EVENTS:
                    dq.append((now, tag))
            if RETRY_RE.search(line):
                dq.append((now, "RETRY"))

        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return Counter(tag for _, tag in dq)


def fmt_mb(kb):
    return f"{kb/1024:.1f}"


def clear():
    print("\033[2J\033[H", end="")


def main():
    ap = argparse.ArgumentParser(description="Passive KryptDisk mesh monitor")
    ap.add_argument("--nodes", type=Path, default=DEFAULT_NODES)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--no-csv", action="store_true")
    args = ap.parse_args()

    args.csv = args.csv.expanduser()
    args.nodes = args.nodes.expanduser()
    if not args.no_csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)

    rates = LogRate(60)
    last_cpu = cpu_ticks()
    last_vm = vmstat()
    last_t = time.time()

    fields = [
        "timestamp", "load1", "load5", "load15", "cpu_busy_pct",
        "mem_available_mb", "swap_used_mb", "swapin_per_s", "swapout_per_s",
        "node", "port", "pid", "node_cpu_pct", "rss_mb", "recvq_bytes",
        "sendq_bytes", "roam_per_min", "turn_per_min", "inject_per_min",
        "queue_per_min", "retry_per_min"
    ]
    need_header = not args.no_csv and (not args.csv.exists() or args.csv.stat().st_size == 0)

    try:
        while True:
            start = time.time()
            procs = discover_processes()
            queues = udp_queues()
            mem = meminfo()
            cur_vm = vmstat()
            cur_cpu = cpu_ticks()
            loads = os.getloadavg()

            dt = max(start - last_t, 0.001)
            dtotal = cur_cpu[0] - last_cpu[0]
            didle = cur_cpu[1] - last_cpu[1]
            busy = 100.0 * (1.0 - didle / dtotal) if dtotal > 0 else 0.0
            swapin = (cur_vm.get("pswpin", 0) - last_vm.get("pswpin", 0)) / dt
            swapout = (cur_vm.get("pswpout", 0) - last_vm.get("pswpout", 0)) / dt
            swap_used_kb = mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)

            rows = []
            for port in sorted(procs):
                p = procs[port]
                log = log_for_node(args.nodes, p["name"], port)
                c = rates.sample(log)
                recvq, sendq = queues.get(port, (0, 0))
                rows.append({
                    "name": p["name"], "port": port, "pid": p["pid"],
                    "cpu": p["cpu"], "rss": p["rss_kb"], "recvq": recvq,
                    "sendq": sendq, "counts": c
                })

            clear()
            stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            print(f"KryptDisk Mesh Monitor  |  {stamp}  |  refresh {args.interval:g}s")
            print("=" * 98)
            print(
                f"VM CPU busy {busy:5.1f}%   load {loads[0]:.2f} {loads[1]:.2f} {loads[2]:.2f}   "
                f"RAM avail {mem.get('MemAvailable',0)/1024:.0f} MB   "
                f"swap used {swap_used_kb/1024:.0f} MB   "
                f"swap I/O {swapin:.1f}/{swapout:.1f} pages/s"
            )
            print("-" * 98)
            print(f"{'NODE':<16} {'PORT':>5} {'CPU%':>6} {'RSS MB':>7} {'RECV-Q':>9} "
                  f"{'ROAM/m':>7} {'TURN/m':>7} {'INJ/m':>6} {'QUEUE/m':>7} {'RETRY/m':>8}")
            print("-" * 98)
            for r in rows:
                c = r["counts"]
                recv_mark = "!" if r["recvq"] >= 200_000 else " "
                cpu_mark = "!" if r["cpu"] >= 25 else " "
                print(
                    f"{r['name']:<16} {r['port']:>5} {r['cpu']:>5.1f}{cpu_mark} "
                    f"{fmt_mb(r['rss']):>7} {r['recvq']:>8}{recv_mark} "
                    f"{c['ROAM']:>7} {c['TURN']:>7} {c['INJECT']:>6} "
                    f"{c['QUEUE']:>7} {c['RETRY']:>8}"
                )
            print("-" * 98)
            print("! = node CPU >=25% or UDP Recv-Q >=200000 bytes")
            if not args.no_csv:
                print(f"CSV: {args.csv}")

                with args.csv.open("a", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fields)
                    if need_header:
                        w.writeheader()
                        need_header = False
                    for r in rows:
                        c = r["counts"]
                        w.writerow({
                            "timestamp": stamp,
                            "load1": f"{loads[0]:.3f}", "load5": f"{loads[1]:.3f}",
                            "load15": f"{loads[2]:.3f}", "cpu_busy_pct": f"{busy:.2f}",
                            "mem_available_mb": f"{mem.get('MemAvailable',0)/1024:.2f}",
                            "swap_used_mb": f"{swap_used_kb/1024:.2f}",
                            "swapin_per_s": f"{swapin:.3f}", "swapout_per_s": f"{swapout:.3f}",
                            "node": r["name"], "port": r["port"], "pid": r["pid"],
                            "node_cpu_pct": f"{r['cpu']:.2f}", "rss_mb": fmt_mb(r["rss"]),
                            "recvq_bytes": r["recvq"], "sendq_bytes": r["sendq"],
                            "roam_per_min": c["ROAM"], "turn_per_min": c["TURN"],
                            "inject_per_min": c["INJECT"], "queue_per_min": c["QUEUE"],
                            "retry_per_min": c["RETRY"]
                        })

            last_cpu, last_vm, last_t = cur_cpu, cur_vm, start
            elapsed = time.time() - start
            time.sleep(max(0.2, args.interval - elapsed))
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
