# IP Info Service

## Endpoint
```bash
curl http://ipinfo.team<N>/ips/<IP>
```
Only accessible from the load balancer VM.

## Response (JSON)
```json
{
  "ip": "10.10.255.239",
  "continentCode": "EU",
  "countryCode": "DE",
  "country": "Germany",
  "city": "Munich",
  "latitude": 48.13743,
  "longitude": 11.57549,
  "asn": { "asn": "AS3320", "name": "Deutsche Telekom AG", "type": "isp" },
  "company": { "name": "Telekom Deutschland GmbH", "type": "isp" },
  "privacy": { "vpn": false, "relay": false, "tor": false, "service": "" }
}
```

## Key fields for risk scoring
| Field | Meaning |
|-------|---------|
| `asn.type` / `company.type` | `isp`, `hosting`, `business`, `edu` |
| `privacy.vpn` | True if IP is a known VPN exit node |
| `privacy.tor` | True if IP is a TOR exit node |
| `countryCode` | Origin country |

Example VPN IP:
```json
{
  "ip": "10.10.74.227",
  "asn": { "type": "hosting" },
  "company": { "type": "hosting" },
  "privacy": { "vpn": true, "service": "NordVPN" }
}
```

## Rate limit
The API has a request cap. If exceeded, returns `429 Too Many Requests`. Monitor usage on the Grafana dashboard.

**Must cache IP info results** (in-memory dict with TTL, or SQLite) to avoid repeated lookups for the same IP.
