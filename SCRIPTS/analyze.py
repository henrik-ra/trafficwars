#!/usr/bin/env python3
"""
TrafficWars fast analyzer + risk scorer for team 3.

- Reads last N lines of NGINX access log (default 50k).
- Aggregates per-IP counts, status distribution, time window.
- Fetches ipinfo metadata for top IPs (cached, bounded concurrency).
- Prints overall stats, top endpoints, risk-scored IP table, and
  ready-to-paste ipset commands for high-risk IPs.

Usage:
    sudo python3 SCRIPTS/analyze.py           # top 30, 50k lines
    sudo python3 SCRIPTS/analyze.py --top 50  # top 50
    sudo python3 SCRIPTS/analyze.py --lines 200000
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import urllib.error
import urllib.request

TEAM = os.environ.get("TEAM", "team3")
LOG = os.environ.get("ACCESS_LOG", "/var/log/nginx/access.log")
IPINFO_URL = f"http://ipinfo.{TEAM}/ips/{{ip}}"
IPINFO_TIMEOUT = 2.0
IPINFO_WORKERS = 8

LOG_RE = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>[^\s"]*)(?:\s+\S+)?"\s+'
    r'(?P<status>\d{3})\s+'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S"


# ---------- data types ----------

@dataclass
class IpStats:
    count: int = 0
    statuses: Counter = None
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    paths: Counter = None

    def __post_init__(self):
        if self.statuses is None:
            self.statuses = Counter()
        if self.paths is None:
            self.paths = Counter()

    @property
    def duration(self) -> float:
        if self.first_ts and self.last_ts:
            return max(1.0, self.last_ts - self.first_ts)
        return 1.0

    @property
    def rps(self) -> float:
        return self.count / self.duration

    @property
    def bad_ratio(self) -> float:
        if not self.statuses:
            return 0.0
        bad = sum(c for s, c in self.statuses.items() if s >= 400)
        total = sum(self.statuses.values())
        return bad / total if total else 0.0


# ---------- log reading ----------

def read_log(path: str, n_lines: int) -> list[str]:
    """Read last N lines efficiently using tail."""
    try:
        out = subprocess.run(
            ["tail", "-n", str(n_lines), path],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
        return out.stdout.splitlines()
    except FileNotFoundError:
        print(f"ERROR: tail not found", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR reading {path}: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_log(lines: list[str]) -> tuple[dict[str, IpStats], Counter, Counter]:
    ip_stats: dict[str, IpStats] = defaultdict(IpStats)
    all_statuses: Counter = Counter()
    all_paths: Counter = Counter()

    for line in lines:
        m = LOG_RE.match(line)
        if not m:
            continue
        ip = m.group("ip")
        try:
            status = int(m.group("status"))
        except ValueError:
            continue
        path = (m.group("path") or "").split("?", 1)[0]
        ts_str = m.group("time").split(" ")[0]
        try:
            ts = datetime.strptime(ts_str, TIME_FMT).timestamp()
        except ValueError:
            ts = None

        s = ip_stats[ip]
        s.count += 1
        s.statuses[status] += 1
        s.paths[path] += 1
        if ts is not None:
            if s.first_ts is None or ts < s.first_ts:
                s.first_ts = ts
            if s.last_ts is None or ts > s.last_ts:
                s.last_ts = ts

        all_statuses[status] += 1
        all_paths[path] += 1

    return ip_stats, all_statuses, all_paths


# ---------- ipinfo ----------

_cache: dict[str, Optional[dict]] = {}

def ipinfo(ip: str) -> Optional[dict]:
    if ip in _cache:
        return _cache[ip]
    url = IPINFO_URL.format(ip=ip)
    try:
        with urllib.request.urlopen(url, timeout=IPINFO_TIMEOUT) as r:
            if r.status == 200:
                data = json.loads(r.read().decode("utf-8"))
                _cache[ip] = data
                return data
    except (urllib.error.URLError, TimeoutError,
            json.JSONDecodeError, ConnectionError):
        pass
    _cache[ip] = None
    return None


def lookup_all(ips: list[str]) -> dict[str, Optional[dict]]:
    results: dict[str, Optional[dict]] = {}
    with ThreadPoolExecutor(max_workers=IPINFO_WORKERS) as ex:
        futures = {ex.submit(ipinfo, ip): ip for ip in ips}
        for f in as_completed(futures):
            ip = futures[f]
            try:
                results[ip] = f.result()
            except Exception:
                results[ip] = None
    return results


# ---------- scoring ----------

def score(stats: IpStats, info: Optional[dict]) -> tuple[int, list[str]]:
    s = 0
    reasons: list[str] = []

    # rate signals
    if stats.rps >= 5.0:
        s += 60; reasons.append(f"rps={stats.rps:.1f}")
    elif stats.rps >= 2.0:
        s += 40; reasons.append(f"rps={stats.rps:.1f}")
    elif stats.rps >= 1.0:
        s += 20; reasons.append(f"rps={stats.rps:.1f}")

    # absolute volume
    if stats.count >= 500:
        s += 30; reasons.append(f"count={stats.count}")
    elif stats.count >= 200:
        s += 15; reasons.append(f"count={stats.count}")

    # error ratio
    if stats.bad_ratio > 0.5 and stats.count > 20:
        s += 20; reasons.append(f"err={stats.bad_ratio:.0%}")

    # ipinfo signals
    if info:
        priv = info.get("privacy") or {}
        if priv.get("tor"):
            s += 60; reasons.append("tor")
        if priv.get("vpn"):
            s += 35; reasons.append("vpn")
        if priv.get("relay"):
            s += 10; reasons.append("relay")
        asn_type = (info.get("asn") or {}).get("type")
        if asn_type == "hosting":
            s += 30; reasons.append("hosting")
        elif asn_type == "business":
            s += 5

    return s, reasons


def verdict(score_val: int) -> str:
    if score_val >= 80:
        return "HARD BLOCK"
    if score_val >= 50:
        return "SOFT"
    if score_val >= 30:
        return "WATCH"
    return "ok"


# ---------- main ----------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--top", type=int, default=30, help="how many top IPs to score")
    p.add_argument("--lines", type=int, default=50000, help="log lines to analyze")
    p.add_argument("--min-score", type=int, default=80,
                   help="min score for block suggestions")
    p.add_argument("--no-ipinfo", action="store_true",
                   help="skip ipinfo lookups (faster, volume-only scoring)")
    args = p.parse_args()

    t0 = time.time()
    print(f"=== TrafficWars Analyzer (team={TEAM}) ===")
    print(f"Reading last {args.lines} lines from {LOG} ...", flush=True)

    lines = read_log(LOG, args.lines)
    ip_stats, all_statuses, all_paths = parse_log(lines)

    total = sum(all_statuses.values())
    if total == 0:
        print("No parseable log lines found.")
        return

    # --- overall ---
    # estimate overall timespan + rps using earliest/latest ts across all IPs
    first_ts = min((s.first_ts for s in ip_stats.values() if s.first_ts), default=None)
    last_ts  = max((s.last_ts  for s in ip_stats.values() if s.last_ts),  default=None)
    if first_ts and last_ts:
        span = max(1.0, last_ts - first_ts)
        overall_rps = total / span
        print(f"\nParsed: {total} requests across {span:.0f}s "
              f"(~{overall_rps:.1f} req/s)   unique IPs: {len(ip_stats)}")
    else:
        print(f"\nParsed: {total} requests   unique IPs: {len(ip_stats)}")

    print("\nStatus codes:")
    for st, c in all_statuses.most_common():
        print(f"  {st}: {c}  ({c/total:.1%})")

    print("\nTop endpoints:")
    for path, c in all_paths.most_common(10):
        print(f"  {c:6d}  {path}")

    # --- top IPs ---
    top = sorted(ip_stats.items(), key=lambda kv: kv[1].count, reverse=True)[:args.top]

    # --- ipinfo ---
    infos: dict[str, Optional[dict]] = {}
    if not args.no_ipinfo:
        print(f"\nFetching ipinfo for top {len(top)} IPs ...", flush=True)
        infos = lookup_all([ip for ip, _ in top])
        n_ok = sum(1 for v in infos.values() if v)
        print(f"  got {n_ok}/{len(top)} successful lookups")

    # --- score table ---
    print("\n" + "=" * 110)
    print(f"{'SCORE':>5}  {'IP':<16}  {'COUNT':>6}  {'RPS':>5}  "
          f"{'ERR%':>5}  {'ASN':<10}  {'CC':<3}  {'PRIVACY':<20}  VERDICT / REASONS")
    print("-" * 110)

    scored: list[tuple[int, str, IpStats, Optional[dict], list[str]]] = []
    for ip, st in top:
        info = infos.get(ip)
        sc, reasons = score(st, info)
        scored.append((sc, ip, st, info, reasons))

    scored.sort(key=lambda x: x[0], reverse=True)

    for sc, ip, st, info, reasons in scored:
        if info:
            asn_type = ((info.get("asn") or {}).get("type") or "-")[:10]
            cc = info.get("countryCode") or "-"
            priv = info.get("privacy") or {}
            flags = []
            if priv.get("tor"):   flags.append("TOR")
            if priv.get("vpn"):   flags.append("VPN")
            if priv.get("relay"): flags.append("RELAY")
            privacy = ",".join(flags) or "-"
            svc = priv.get("service") or ""
            if svc:
                privacy = f"{privacy}({svc[:12]})"
        else:
            asn_type, cc, privacy = "?", "?", "?"

        v = verdict(sc)
        print(f"{sc:>5}  {ip:<16}  {st.count:>6}  {st.rps:>5.1f}  "
              f"{st.bad_ratio*100:>4.0f}%  {asn_type:<10}  {cc:<3}  "
              f"{privacy:<20}  {v} [{','.join(reasons)}]")

    # --- block suggestions ---
    to_block = [(sc, ip) for sc, ip, *_ in scored if sc >= args.min_score]
    print("\n" + "=" * 110)
    print(f"Suggested ipset blocks (score >= {args.min_score}): {len(to_block)}")
    if to_block:
        print("\n# Copy-paste to block (ensure 'threat' ipset + iptables rule exist):")
        print("sudo iptables -C INPUT -m set --match-set threat src -j DROP 2>/dev/null || \\")
        print("  sudo iptables -I INPUT 2 -m set --match-set threat src -j DROP")
        for sc, ip in to_block:
            print(f"sudo ipset add threat {ip} -exist   # score={sc}")

    print(f"\nDone in {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
