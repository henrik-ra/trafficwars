# Python App Server

- **Runtime:** uvicorn (ASGI) managed by pm2.
- **Auto-reload:** pm2 watches `.py` files; changes trigger automatic restart.
- **Project root:** `/root/LOAD_BALANCER_APP/`

## Files

| File | Purpose |
|------|---------|
| `main.py` | ASGI entry point (uvicorn), exposes `/health` endpoint |
| `ipRiskScorer.py` | IP risk scoring logic |
| `(future) logWatcher.py` | Tails NGINX access log, feeds IPs to scorer |
| `(future) banManager.py` | Takes high-score IPs, adds to ipset + iptables |
| `requirements.txt` | Python dependencies (uvicorn, httpx) |
| `ecosystem.config.js` | pm2 config — watches all `.py` files, auto-restarts |

## pm2 Commands

```bash
pm2 list                          # List all processes
pm2 logs                          # View logs
pm2 restart all                   # Restart everything
pm2 start ecosystem.config.js     # Start from config file
```

## Notes

- pm2 watches all `.py` files in `LOAD_BALANCER_APP/`. Save a file → pm2 auto-restarts.
- Each team member can work on one feature file (risk scorer, log watcher, ban manager).
- Scripts that batch-process logs (e.g. parse access log → query IP info → save JSON) live in `/root/SCRIPTS/`, not in the app.
- Cached IP info data is stored in `/root/DATA/` as numbered JSON files (`001.json`, `002.json`, ...).
