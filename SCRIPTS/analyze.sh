#!/usr/bin/env bash
# Wrapper around analyze.py (the robust Python version).
# Kept so the old command still works; forwards all args.
set -u
exec python3 "$(dirname "$0")/analyze.py" "$@"

# --- old bash implementation below is ignored after exec ---

TEAM="${TEAM:-team3}"
LOG="/var/log/nginx/access.log"
N="${1:-30}"
LINES="${LINES:-20000}"

echo "=== TrafficWars Analyzer (team: $TEAM, last $LINES log lines) ==="
echo

# --- 1. Overall traffic stats ---
echo "--- Overall traffic ---"
TOTAL=$(tail -n "$LINES" "$LOG" | wc -l)
echo "Total requests analyzed: $TOTAL"

echo
echo "Requests per second (top 10 busiest seconds):"
tail -n "$LINES" "$LOG" | awk '{print $4}' | cut -d: -f2-4 | uniq -c | sort -rn | head -10

echo
echo "Status code distribution:"
tail -n "$LINES" "$LOG" | awk '{print $9}' | sort | uniq -c | sort -rn

echo
echo "Top endpoints:"
tail -n "$LINES" "$LOG" | awk -F'"' '{print $2}' | awk '{print $2}' | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -10

# --- 2. Top IPs by volume ---
echo
echo "--- Top $N IPs by request count ---"
TOP_IPS=$(tail -n "$LINES" "$LOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n "$N")
echo "$TOP_IPS"

# --- 3. Risk scoring per top IP ---
echo
echo "--- Risk assessment (hitting ipinfo.$TEAM) ---"
printf "%-8s  %-16s  %-20s  %-8s  %-6s  %-6s  %-6s  %s\n" \
  "SCORE" "IP" "ASN_TYPE/COMPANY" "COUNTRY" "VPN" "TOR" "RELAY" "VERDICT"
echo "--------------------------------------------------------------------------------"

echo "$TOP_IPS" | awk '{print $2, $1}' | while read ip count; do
  # skip empty
  [ -z "$ip" ] && continue

  # fetch ipinfo (with short timeout)
  json=$(curl -s --max-time 2 "http://ipinfo.$TEAM/ips/$ip")
  if [ -z "$json" ]; then
    asn_type="?"; country="?"; vpn="?"; tor="?"; relay="?"; company="?"
  else
    asn_type=$(echo "$json" | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("asn") or {}).get("type") or "-")' 2>/dev/null)
    country=$(echo "$json"  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("countryCode") or "-")' 2>/dev/null)
    vpn=$(echo "$json"      | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("privacy") or {}).get("vpn"))' 2>/dev/null)
    tor=$(echo "$json"      | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("privacy") or {}).get("tor"))' 2>/dev/null)
    relay=$(echo "$json"    | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("privacy") or {}).get("relay"))' 2>/dev/null)
    company=$(echo "$json"  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(((d.get("company") or {}).get("name") or "-")[:18])' 2>/dev/null)
  fi

  # --- scoring ---
  score=0
  [ "$count" -ge 300 ] && score=$((score + 60))
  [ "$count" -ge 150 ] && [ "$count" -lt 300 ] && score=$((score + 40))
  [ "$count" -ge 80 ]  && [ "$count" -lt 150 ] && score=$((score + 20))
  [ "$tor" = "True" ]   && score=$((score + 60))
  [ "$vpn" = "True" ]   && score=$((score + 35))
  [ "$relay" = "True" ] && score=$((score + 10))
  [ "$asn_type" = "hosting" ] && score=$((score + 30))

  # verdict
  if   [ "$score" -ge 80 ]; then verdict="HARD BLOCK (ipset)"
  elif [ "$score" -ge 50 ]; then verdict="SOFT (rate-limit hard)"
  elif [ "$score" -ge 30 ]; then verdict="watch"
  else                           verdict="ok"
  fi

  printf "%-8s  %-16s  %-20s  %-8s  %-6s  %-6s  %-6s  %s (count=%s)\n" \
    "$score" "$ip" "$asn_type/$company" "$country" "$vpn" "$tor" "$relay" "$verdict" "$count"
done | sort -rn

# --- 4. Ready-to-run block commands ---
echo
echo "--- Suggested ipset commands (score >= 80) ---"
echo "Run manually after reviewing above:"
echo
echo "$TOP_IPS" | awk '{print $2, $1}' | while read ip count; do
  [ -z "$ip" ] && continue
  json=$(curl -s --max-time 2 "http://ipinfo.$TEAM/ips/$ip")
  asn_type=$(echo "$json" | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("asn") or {}).get("type") or "-")' 2>/dev/null)
  vpn=$(echo "$json"      | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("privacy") or {}).get("vpn"))' 2>/dev/null)
  tor=$(echo "$json"      | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("privacy") or {}).get("tor"))' 2>/dev/null)

  score=0
  [ "$count" -ge 300 ] && score=$((score + 60))
  [ "$count" -ge 150 ] && [ "$count" -lt 300 ] && score=$((score + 40))
  [ "$tor" = "True" ]   && score=$((score + 60))
  [ "$vpn" = "True" ]   && score=$((score + 35))
  [ "$asn_type" = "hosting" ] && score=$((score + 30))

  [ "$score" -ge 80 ] && echo "sudo ipset add threat $ip   # count=$count score=$score"
done
