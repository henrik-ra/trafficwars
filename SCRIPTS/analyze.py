#!/usr/bin/env python3
"""
TrafficWars strong analyzer for Team 3 (Check24 specific).
Aggregates by IP, Subnet (/24), ASN, and Company.
Adds heavy penalty for Non-DACH countries since Check24 is DACH-focused.

Usage:
  sudo python3 SCRIPTS/analyze.py --lines 50000
  sudo python3 SCRIPTS/analyze.py --lines 50000 --mode suggest
  sudo python3 SCRIPTS/analyze.py --lines 50000 --mode apply
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import urllib.error
import urllib.request

TEAM = os.environ.get("TEAM", "team3")
LOG = os.environ.get("ACCESS_LOG", "/var/log/nginx/access.log")
IPINFO_URL = f"http://ipinfo.{TEAM}/ips/{{ip}}"
IPINFO_TIMEOUT = 2.0
IPINFO_WORKERS = 16

DACH_COUNTRIES = {"DE", "AT", "CH"}

LOG_RE = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>[^\s"]*)(?:\s+\S+)?"\s+'
    r'(?P<status>\d{3})\s+'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S"

@dataclass
class Stats:
    count: int = 0
    statuses: Counter = field(default_factory=Counter)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    ips: set = field(default_factory=set)

    def add(self, ts, status, ip):
        self.count += 1
        self.statuses[status] += 1
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        self.ips.add(ip)

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

def read_log(path: str, n_lines: int) -> list[str]:
    out = subprocess.run(
        ["tail", "-n", str(n_lines), path],
        check=True, capture_output=True, text=True, errors="replace",
    )
    return out.stdout.splitlines()

def parse_log(lines):
    by_ip = defaultdict(Stats)
    by_subnet = defaultdict(Stats)
    all_statuses = Counter()
    all_paths = Counter()

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

        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        by_ip[ip].add(ts, status, ip)
        by_subnet[subnet].add(ts, status, ip)
        all_statuses[status] += 1
        all_paths[path] += 1

    return by_ip, by_subnet, all_statuses, all_paths

def ipinfo_one(ip: str) -> Optional[dict]:
    url = IPINFO_URL.format(ip=ip)
    try:
        with urllib.request.urlopen(url, timeout=IPINFO_TIMEOUT) as r:
            if r.status == 200:
                return json.loads(r.read().decode("utf-8"))
    except:
        pass
    return None

def fetch_ipinfo_batch(ips: list[str]) -> dict:
    results = {}
    print(f"  ipinfo: fetching {len(ips)} IPs...", flush=True)
    with ThreadPoolExecutor(max_workers=IPINFO_WORKERS) as ex:
        futures = {ex.submit(ipinfo_one, ip): ip for ip in ips}
        for f in as_completed(futures):
            ip = futures[f]
            try:
                results[ip] = f.result()
            except Exception:
                results[ip] = None
    return results

def score_ip(st: Stats, info: Optional[dict]) -> tuple[int, list[str]]:
    s = 0
    reasons = []

    # RPS
    if st.rps >= 10: s += 80; reasons.append(f"rps={st.rps:.1f}")
    elif st.rps >= 5: s += 60; reasons.append(f"rps={st.rps:.1f}")
    elif st.rps >= 2: s += 40; reasons.append(f"rps={st.rps:.1f}")
    elif st.rps >= 1: s += 20; reasons.append(f"rps={st.rps:.1f}")

    # Total Count
    if st.count >= 500: s += 30; reasons.append(f"cnt={st.count}")
    elif st.count >= 200: s += 15

    # Errors
    if st.bad_ratio > 0.5 and st.count > 20:
        s += 20; reasons.append(f"err={st.bad_ratio:.0%}")

    if info:
        priv = info.get("privacy") or {}
        if priv.get("tor"): s += 60; reasons.append("tor")
        if priv.get("vpn"): s += 35; reasons.append("vpn")
        # Check24 DACH check
        cc = info.get("countryCode")
        if cc and cc not in DACH_COUNTRIES:
            s += 50
            reasons.append(f"non-DACH({cc})")
        
        asn_type = (info.get("asn") or {}).get("type")
        if asn_type == "hosting":
            s += 30; reasons.append("hosting")
    else:
        # If no info, we can't tell, rely on volume
        pass

    return s, reasons

def score_group(st: Stats, n_ips: int, is_non_dach: bool = False) -> tuple[int, list[str]]:
    s = 0
    reasons = []
    if st.rps >= 50: s += 80; reasons.append(f"grp_rps={st.rps:.1f}")
    elif st.rps >= 20: s += 60; reasons.append(f"grp_rps={st.rps:.1f}")
    elif st.rps >= 10: s += 40; reasons.append(f"grp_rps={st.rps:.1f}")
    
    if is_non_dach:
        s += 50; reasons.append("non-DACH")

    # Distributed attack from group
    if n_ips >= 20 and st.rps >= 10: s += 40; reasons.append(f"ips={n_ips}")
    elif n_ips >= 10 and st.rps >= 5: s += 20; reasons.append(f"ips={n_ips}")
    
    if st.bad_ratio > 0.5 and st.count > 100: s += 20; reasons.append(f"err={st.bad_ratio:.0%}")
    return s, reasons

def verdict(s: int) -> str:
    if s >= 80: return "HARD"
    if s >= 50: return "SOFT"
    if s >= 30: return "WATCH"
    return "ok"

def ensure_ipset():
    subprocess.run(["ipset", "create", "threat", "hash:ip", "timeout", "7200", "-exist"], stderr=subprocess.DEVNULL)
    subprocess.run(["ipset", "create", "threat_net", "hash:net", "timeout", "7200", "-exist"], stderr=subprocess.DEVNULL)
    for s in ("threat", "threat_net"):
        if subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", s, "src", "-j", "DROP"], stderr=subprocess.DEVNULL).returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "2", "-m", "set", "--match-set", s, "src", "-j", "DROP"])

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lines", type=int, default=50000)
    p.add_argument("--top", type=int, default=50)
    p.add_argument("--mode", choices=["observe", "suggest", "apply"], default="observe")
    args = p.parse_args()

    print(f"=== TrafficWars Strong Analyzer (team={TEAM}, mode={args.mode}) ===")
    lines = read_log(LOG, args.lines)
    by_ip, by_subnet, all_statuses, all_paths = parse_log(lines)
    
    if not by_ip:
        print("No log lines parsed.")
        return

    top_ips = sorted(by_ip.keys(), key=lambda ip: by_ip[ip].count, reverse=True)[:args.top * 2]
    infos = fetch_ipinfo_batch(top_ips)

    # ASN & Company Aggregation
    by_asn = defaultdict(Stats)
    by_comp = defaultdict(Stats)
    asn_meta = {}
    comp_meta = {}

    for ip in top_ips:
        info = infos.get(ip)
        if not info: continue
        st = by_ip[ip]
        asn = (info.get("asn") or {}).get("asn") or "unknown"
        comp = (info.get("company") or {}).get("name") or "unknown"
        cc = info.get("countryCode") or "-"
        
        g_asn = by_asn[asn]
        g_asn.count += st.count; g_asn.statuses.update(st.statuses); g_asn.ips.add(ip)
        g_asn.first_ts = min(filter(None, [g_asn.first_ts, st.first_ts]), default=None)
        g_asn.last_ts = max(filter(None, [g_asn.last_ts, st.last_ts]), default=None)
        asn_meta[asn] = {"cc": cc, "type": (info.get("asn") or {}).get("type") or ""}

        g_comp = by_comp[comp]
        g_comp.count += st.count; g_comp.statuses.update(st.statuses); g_comp.ips.add(ip)
        g_comp.first_ts = min(filter(None, [g_comp.first_ts, st.first_ts]), default=None)
        g_comp.last_ts = max(filter(None, [g_comp.last_ts, st.last_ts]), default=None)
        comp_meta[comp] = {"cc": cc}

    # IP Table
    print("\n" + "="*115 + f"\nPER-IP (top {args.top})\n" + "-"*115)
    print(f"{'SCORE':>5}  {'IP':<16}  {'COUNT':>6}  {'RPS':>5}  {'ERR%':>4}  {'CC':<3}  {'PRIVACY':<18}  REASONS")
    
    scored_ips = []
    for ip in top_ips[:args.top]:
        st = by_ip[ip]
        info = infos.get(ip)
        s, reasons = score_ip(st, info)
        scored_ips.append((s, ip, st, info, reasons))
    
    scored_ips.sort(key=lambda x: x[0], reverse=True)
    
    for s, ip, st, info, reasons in scored_ips:
        cc = (info.get("countryCode") or "-") if info else "?"
        priv = info.get("privacy") or {} if info else {}
        privacy = ",".join([k for k in ["tor", "vpn", "relay"] if priv.get(k)]) or "-"
        print(f"{s:>5}  {ip:<16}  {st.count:>6}  {st.rps:>5.1f}  {st.bad_ratio*100:>3.0f}%  {cc:<3}  {privacy:<18}  {verdict(s)} [{','.join(reasons)}]")

    # Subnet Table
    print("\n" + "="*115 + f"\nPER-/24-SUBNET (top 15 by volume)\n" + "-"*115)
    scored_subs = []
    for subnet, st in sorted(by_subnet.items(), key=lambda kv: kv[1].count, reverse=True)[:15]:
        # heuristic: if we don't have country code for the subnet directly, just volume score
        s, reasons = score_group(st, len(st.ips))
        scored_subs.append((s, subnet, st, reasons))
    
    for s, subnet, st, reasons in sorted(scored_subs, key=lambda x: x[0], reverse=True):
        print(f"{s:>5}  {subnet:<18}  {st.count:>6}  {st.rps:>6.1f}  {st.bad_ratio*100:>3.0f}%  {len(st.ips):>4}  {verdict(s)} [{','.join(reasons)}]")

    # ASN Table
    if by_asn:
        print("\n" + "="*115 + f"\nPER-ASN (top 15 by volume)\n" + "-"*115)
        scored_asns = []
        for asn, st in sorted(by_asn.items(), key=lambda kv: kv[1].count, reverse=True)[:15]:
            cc = asn_meta[asn]["cc"]
            s, reasons = score_group(st, len(st.ips), is_non_dach=(cc not in DACH_COUNTRIES and cc != "-"))
            scored_asns.append((s, asn, cc, st, reasons))
        for s, asn, cc, st, reasons in sorted(scored_asns, key=lambda x: x[0], reverse=True):
            print(f"{s:>5}  {asn:<10}  {cc:<3}  {st.count:>6}  {st.rps:>6.1f}  {len(st.ips):>4} IP  [{','.join(reasons)}]")

    # Actions
    to_block_ips = [ip for s, ip, *_ in scored_ips if s >= 80]
    to_block_subs = [sub for s, sub, *_ in scored_subs if s >= 80]

    print("\n" + "="*115)
    if args.mode == "observe":
        print(f"Would block {len(to_block_ips)} IPs and {len(to_block_subs)} Subnets. Run with --mode suggest or --mode apply to action them.")
    elif args.mode == "suggest":
        print("# Commands to block (Score >= 80):")
        for ip in to_block_ips: print(f"sudo ipset add threat {ip} -exist")
        for sub in to_block_subs: print(f"sudo ipset add threat_net {sub} -exist")
    elif args.mode == "apply":
        ensure_ipset()
        for ip in to_block_ips: subprocess.run(["ipset", "add", "threat", ip, "-exist"])
        for sub in to_block_subs: subprocess.run(["ipset", "add", "threat_net", sub, "-exist"])
        print(f"Applied blocks for {len(to_block_ips)} IPs and {len(to_block_subs)} /24 Subnets.")

if __name__ == "__main__":
    main()
