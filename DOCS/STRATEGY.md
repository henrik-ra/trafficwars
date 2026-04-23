# Strategy

## Setup
Single VM running as reverse proxy / load balancer (NGINX). Incoming traffic: legitimate users + bots / DDoS. Backend application is not publicly reachable — all traffic passes through NGINX.

## Goal
Keep the webshop available for legitimate users by filtering out malicious/spam traffic using rate limiting, IP blocking, and risk-based access control.

## Loop
1. **Analyze** — Read NGINX access logs (`/var/log/nginx/access.log`). Identify suspicious patterns (bursts, known bad IPs, scraping, etc.).
2. **Enrich** — Query the IP info API (`http://ipinfo.team<N>/ips/<IP>`) for metadata (ASN, VPN/TOR flags, company type). Cache results to avoid hitting API rate limits.
3. **Score** — Assign each IP a risk score based on traffic patterns + IP metadata.
4. **Act** — Enforce controls:
   - **NGINX rate limiting** — Per-IP request caps in `loadbalancer.conf`.
   - **iptables + ipset** — Drop traffic from high-risk IPs at the firewall level.
   - **Dynamic tarpit / block** — Python app (uvicorn + pm2) that monitors logs, scores IPs, and writes iptables rules or updates ipsets.
5. **Monitor** — Check Grafana dashboard for revenue impact and traffic changes. Adjust thresholds accordingly.
6. **Repeat** — Continuous cycle: log → analyze → score → block → monitor → tune.

## Feature ownership

| Feature | Tool | Why |
|---------|------|-----|
| Static per-IP rate limit (e.g. 30 req/s) | **NGINX** (`limit_req_zone`) | Built-in, zero-latency, configure once |
| Drop all traffic from known bad IPs | **iptables + ipset** | Kernel-level, no overhead from userspace processing |
| Parse access logs to extract IPs + paths + rates | **Python app** | NGINX has no built-in log analysis — need custom pattern matching |
| Query IP info API + cache results | **Python app** | API returns JSON, needs rate-limit-aware client + cache |
| Compute risk score per IP (rate × metadata × path) | **Python app** | Custom logic combining multiple signals — not expressible in NGINX config alone |
| Add/remove IPs from ipset dynamically | **Python app** (calls `ipset` via subprocess) | iptables/ipset has no built-in scoring engine — decisions must come from analysis |
| Route traffic to different backends or tarpit based on score | **NGINX** (if using `map` + variables) or **Python** (if using iptables reroute) | Possible in NGINX with `$limit_rate` but complex — simpler to handle in Python + iptables |
| Serve health/metrics endpoint for monitoring | **Python app** (uvicorn ASGI endpoint) | Need a lightweight HTTP server for internal status checks |

**Summary:** NGINX and iptables handle the _enforcement_ (fast path). Python handles the _intelligence_ (slow path: analysis, enrichment, scoring, decision-making).

### Data flow
```
Traffic → NGINX (logs + rate limit) → Backend app
                                    ↑
                              iptables drops here
                                    ↑
                            Python app edits ipset
                                    ↑
         Python app reads logs → scores IPs → decides block/limit/pass
```

The Python app **never touches traffic**. It only:
1. Reads `/var/log/nginx/access.log` (passive).
2. Calls IP info API for enrichment.
3. Computes risk scores.
4. Executes `sudo ipset add threat <IP>` or writes NGINX config + reloads.

## Components
- **NGINX** — Entry point. Rate limiting via `limit_req_zone`. Access logs for analysis.
- **iptables + ipset** — Kernel-level IP blocking. Efficient for large blocklists.
- **Python app** (uvicorn + pm2) — Custom analysis logic. Reads NGINX logs, calls IP info API, computes risk scores, manages ipset rules.
- **IP info API** — Returns ASN, geolocation, privacy flags (VPN/TOR/hosting) per IP. Rate-limited — cache aggressively.
