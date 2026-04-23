Use the following command to query information for an IP, such as 10.10.12.34. Since the IP Information Service is only accessibly from your load balancer, you need to run the command on your load balancer.

curl http://ipinfo.team3/ips/10.10.12.34


JSON Response

The service responds with JSON data, which look like this:

{
  "ip": "10.10.255.239",
  "continentCode": "EU",
  "countryCode": "DE",
  "country": "Germany",
  "city": "Munich",
  "latitude": 48.13743,
  "longitude": 11.57549,
  "asn": {
    "asn": "AS3320",
    "name": "Deutsche Telekom AG",
    "type": "isp"
  },
  "company": {
    "name": "Telekom Deutschland GmbH",
    "type": "isp"
  },
  "privacy": {
    "vpn": false,
    "relay": false,
    "tor": false,
    "service": ""
  }
}

Another example of an IP that is likely to be a VPN exit node looks like this:

{
  "ip": "10.10.74.227",
  "continentCode": "AS",
  "countryCode": "JP",
  "country": "Japan",
  "city": "Tokyo",
  "latitude": 35.6895,
  "longitude": 139.69171,
  "asn": {
    "asn": "AS136787",
    "name": "TEFINCOM S.A.",
    "type": "hosting"
  },
  "company": {
    "name": "Packethub S.A.",
    "type": "hosting"
  },
  "privacy": {
    "vpn": true,
    "relay": false,
    "tor": false,
    "service": "NordVPN"
  }
}

The type fields for autonomous systems and companies are either isp, hosting, business, or edu.

The IP Information Service provides this functionality as an HTTP endpoint and can therefore be used by any HTTP client. In particular, every major programming language has some sort of HTTP client and JSON parser in its standard library, so you can code some logic to automatically query and evaluates the IP metadata of IPs from the NGINX access log.

Rate Limit
API Rate Limit

The maximum number of requests to the API in a given timeframe is limited to a certain amount, so keep that in mind when automating your requests. Therefore, it may be a good solution to cache the collected data in some way to avoid requesting the information for the same IP address over and over again.

If a request gets rate limited, the API responds with the status 429 Too Many Requests. You can monitor your "ipinfo" API requests (including status codes) next to your team's other monitoring data on the Grafana dashboard. Monitoring is discussed in more detail in the Monitoring section.