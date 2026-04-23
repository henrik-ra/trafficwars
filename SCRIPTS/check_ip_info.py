#!/usr/bin/env python3
"""
Read last 50 NGINX access log lines, extract unique IPs, query IP info API.
Output:
  - DATA/<N>_queried_ips.json       — list of IPs that were queried
  - DATA/<N>_ip_info_results.json   — IP → API response mapping
  - DATA/<N>_query_log.txt          — log with rate limit encounters, timing, errors

Uses exponential backoff on 429 responses. Rate limit unknown — this script
discovers it adaptively.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

NGINX_LOG = "/var/log/nginx/access.log"
DATA_DIR = Path("/root/DATA")
IPINFO_BASE = "http://ipinfo.team3/ips"
LINES = 50
MAX_RETRIES = 5
BASE_DELAY = 1.0  # seconds


def get_next_number() -> int:
    existing = [int(f.stem.split("_")[0]) for f in DATA_DIR.glob("*_*.json")]
    return max(existing, default=0) + 1


def read_last_ips(path: str, n: int) -> list[str]:
    result = subprocess.run(
        ["tail", "-n", str(n), path],
        capture_output=True, text=True, check=True,
    )
    ips: list[str] = []
    for line in result.stdout.strip().splitlines():
        ip = line.split()[0] if line.strip() else ""
        if ip:
            ips.append(ip)
    return sorted(set(ips))


def query_ipinfo(ip: str, log_lines: list[str]) -> dict | None:
    url = f"{IPINFO_BASE}/{ip}"
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = Request(url)
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            return data
        except HTTPError as e:
            if e.code == 429:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                msg = (
                    f"[{datetime.now(timezone.utc).isoformat()}] "
                    f"429 for {ip}, attempt {attempt}/{MAX_RETRIES}, "
                    f"backoff {delay:.1f}s"
                )
                log_lines.append(msg)
                print(f"  {msg}")
                if attempt < MAX_RETRIES:
                    time.sleep(delay)
                else:
                    msg = (
                        f"[{datetime.now(timezone.utc).isoformat()}] "
                        f"Gave up on {ip} after {MAX_RETRIES} retries"
                    )
                    log_lines.append(msg)
                    return None
            else:
                msg = (
                    f"[{datetime.now(timezone.utc).isoformat()}] "
                    f"HTTP {e.code} for {ip}: {e.reason}"
                )
                log_lines.append(msg)
                return None
        except Exception as e:
            msg = (
                f"[{datetime.now(timezone.utc).isoformat()}] "
                f"Error for {ip}: {e}"
            )
            log_lines.append(msg)
            return None
    return None


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Reading last {LINES} lines from {NGINX_LOG} ...")
    unique_ips = read_last_ips(NGINX_LOG, LINES)
    print(f"Found {len(unique_ips)} unique IPs: {unique_ips}")

    number = get_next_number()
    log_lines: list[str] = []
    rate_limits_encountered = 0
    results: dict[str, dict | None] = {}

    log_lines.append(
        f"=== IP Info Query Run #{number} ==="
    )
    log_lines.append(
        f"Started: {datetime.now(timezone.utc).isoformat()}"
    )
    log_lines.append(f"Source: last {LINES} lines of {NGINX_LOG}")
    log_lines.append(f"Unique IPs: {len(unique_ips)}")
    log_lines.append("")

    for ip in unique_ips:
        print(f"Querying {ip} ...")
        data = query_ipinfo(ip, log_lines)
        results[ip] = data
        if data is None:
            rate_limits_encountered += 1

    # Write queried IPs list
    ips_file = DATA_DIR / f"{number:03d}_queried_ips.json"
    with open(ips_file, "w") as f:
        json.dump(unique_ips, f, indent=2)
    print(f"Wrote {ips_file}")

    # Write IP info results
    info_file = DATA_DIR / f"{number:03d}_ip_info_results.json"
    with open(info_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Wrote {info_file}")

    # Write log
    log_lines.append("")
    log_lines.append(
        f"Finished: {datetime.now(timezone.utc).isoformat()}"
    )
    log_lines.append(f"Rate limits encountered: {rate_limits_encountered}")
    log_file = DATA_DIR / f"{number:03d}_query_log.txt"
    with open(log_file, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"Wrote {log_file}")
    print(f"Done. Rate limits hit: {rate_limits_encountered}/{len(unique_ips)}")


if __name__ == "__main__":
    main()
