# TrafficWars — Load Balancer Defense

## What is this?
We are defending a simulated webshop from bad traffic (bots, DDoS, scrapers) during a competition. Our VM acts as a reverse proxy / load balancer in front of the application. All traffic passes through us — we decide what reaches the backend.

## Stack
| Component | Role |
|-----------|------|
| **NGINX** | Reverse proxy, static rate limiting, access logs |
| **iptables + ipset** | Kernel-level IP blocking |
| **Python app** (uvicorn + pm2) | Dynamic analysis, risk scoring, ban management |
| **IP info API** | Metadata per IP (ASN, VPN/TOR flags, geolocation) |
| **Grafana** | Monitoring dashboard (revenue, traffic, API usage) |

## Strategy (high-level)
1. **Read** NGINX access logs → identify suspicious IPs.
2. **Query** IP info API → enrich with metadata.
3. **Score** each IP (rate, VPN/datacenter flags, path patterns).
4. **Block** high-risk IPs via ipset/iptables. Rate-limit medium-risk via NGINX.
5. **Monitor** Grafana → tune thresholds. Repeat.

## File layout
```
DOCS/
├── README.md                          ← You are here
├── STRATEGY.md                        ← Full strategy with loop details
├── Links.md                           ← Reference links
├── SCRIPTS.md                         ← Helper script reference
├── AppParts/                          ← Component designs
│   ├── IPRiskScorer.md
│   ├── RateLimiter.md
│   └── PythonAppServer.md
└── GivenSetupDocs/                    ← Platform setup docs
    ├── How to use Nginx on this setuo.md
    ├── How to use the Firewall.md
    └── How to use the IP info service.md

SCRIPTS/                               ← Shell helpers
├── install.sh                         ← Install opencode CLI
├── install_deps.sh                    ← Install Python deps + pm2 + start app
├── openNginxAccessLogs.sh
└── openNginxConfig.sh

DATA/                                  ← Cached IP info JSON files (numbered: 001.json, 002.json...)

LOAD_BALANCER_APP/                     ← Python app root (uvicorn + pm2)
├── main.py                            ← ASGI entry point, /health endpoint
├── ipRiskScorer.py                    ← IP risk scoring logic
├── requirements.txt                   ← Python dependencies
└── ecosystem.config.js                ← pm2 config (auto-watch + reload)
```

## Quick start
```bash
# Watch live traffic
tail -f /var/log/nginx/access.log

# Check current iptables rules
sudo iptables -S

# Query IP metadata
curl http://ipinfo.team3/ips/10.10.12.34

# Edit NGINX config
nano /etc/nginx/conf.d/loadbalancer.conf

# Reload NGINX after config changes
sudo nginx -s reload

# Install app dependencies + start with pm2
sudo bash /root/SCRIPTS/install_deps.sh

# View pm2 app logs
pm2 logs

# List pm2 processes
pm2 list
```

## Key files
- `/etc/nginx/conf.d/loadbalancer.conf` — NGINX upstream + rate limits
- `/var/log/nginx/access.log` — All HTTP traffic
- `/root/LOAD_BALANCER_APP/` — Python scoring + ban logic (auto-reloaded by pm2)
- `/root/DATA/` — Cached IP info JSON files
- `/root/DOCS/STRATEGY.md` — Full operational loop
