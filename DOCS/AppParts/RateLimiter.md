# Rate Limiter

## NGINX-native rate limiting (Layer 7)

Configured in `/etc/nginx/conf.d/loadbalancer.conf` (see `LOAD_BALANCER_APP/loadbalancer.conf`).

### What was added to the original config

**3 zone definitions** (before the `upstream` block):
```nginx
limit_req_zone  $binary_remote_addr zone=perip:10m    rate=20r/s;
limit_req_zone  $binary_remote_addr zone=checkout:10m  rate=10r/s;
limit_conn_zone $binary_remote_addr zone=connperip:10m;
```

**Server-level** connection cap:
```nginx
limit_conn connperip 20;    # max 20 simultaneous connections per IP
```

**`location /`** — general rate limit:
```nginx
limit_req zone=perip burst=40 nodelay;   # max 20 req/s per IP, burst of 40
```

**`location /checkout`** — stricter limit on the money endpoint:
```nginx
limit_req  zone=checkout burst=20 nodelay;  # max 10 req/s per IP
limit_conn connperip 10;                     # max 10 connections per IP
```

### Deploy
```bash
sudo cp /root/LOAD_BALANCER_APP/loadbalancer.conf /etc/nginx/conf.d/loadbalancer.conf
sudo nginx -t && sudo systemctl reload nginx
```

### Tuning
- If still too many 503s from backend → lower `rate=` values (e.g. `1r/s` on checkout).
- If revenue drops → raise `rate=` or increase `burst=`.
- Always check Grafana after each change.

Current baseline (team 3 traffic analysis): normal users ~1 req/s,
bots were caught at 5-6 req/s — so `2r/s` on checkout should pass real
customers while blocking volume bots.

## Dynamic rate limiting (Python app)

For IPs with medium risk scores (not yet block-worthy), the Python app can:

1. Monitor access log for per-IP request rates.
2. For IPs exceeding thresholds, add to an ipset that `iptables` uses to **limit** (via `hashlimit` module) or **drop**.
3. Lower scores → just log + monitor. High scores → instant ipset ban.

## Decision
Use **NGINX `limit_req`** for baseline rate limiting (all traffic). Use **Python + iptables/ipset** for risk-adaptive blocking (above NGINX's static config).

