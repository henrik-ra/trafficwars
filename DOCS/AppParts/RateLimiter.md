# Rate Limiter

## NGINX-native rate limiting (Layer 7)

Configure in `/etc/nginx/conf.d/loadbalancer.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=webapp:10m rate=30r/s;

server {
    listen 80;
    location / {
        limit_req zone=webapp burst=20 nodelay;
        proxy_pass http://application;
    }
}
```

Tiered limits based on risk score (requires dynamic NGINX module or Lua — if unavailable, handle via Python + iptables instead).

## Dynamic rate limiting (Python app)

For IPs with medium risk scores (not yet block-worthy), the Python app can:

1. Monitor access log for per-IP request rates.
2. For IPs exceeding thresholds, add to an ipset that `iptables` uses to **limit** (via `hashlimit` module) or **drop**.
3. Lower scores → just log + monitor. High scores → instant ipset ban.

## Decision
Use **NGINX `limit_req`** for baseline rate limiting (all traffic). Use **Python + iptables/ipset** for risk-adaptive blocking (above NGINX's static config).
