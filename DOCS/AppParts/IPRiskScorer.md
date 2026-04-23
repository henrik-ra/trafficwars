# IPRiskScorer

**File:** `LOAD_BALANCER_APP/ipRiskScorer.py`

Takes an IP address, returns a risk score (e.g. 0–100). Logic:

- **Rate-based** — Requests/sec from NGINX logs. High burst = higher score.
- **Metadata-based** — IP info API fields:
  - `privacy.vpn` / `privacy.tor` → +high score
  - `asn.type` / `company.type` = `hosting` → +medium score (datacenter IPs)
  - Known bad ASNs or countries (configurable list) → +score
- **Path-based** — Repeated hits to login, checkout, or API endpoints without browsing → +score.
- **Cache** — Store scores per IP with TTL. Avoid redundant API calls.

Output: `{"ip": "x.x.x.x", "score": 85, "reason": "vpn+high_rate"}`

Called by the rate limiter / ban manager on a polling or event-driven basis.
