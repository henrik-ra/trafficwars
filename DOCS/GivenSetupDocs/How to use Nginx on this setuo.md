# NGINX

## Role
Reverse proxy / load balancer. Forwards HTTP traffic from the internet to the backend application (not publicly reachable). Single upstream in this competition.

## Config file
`/etc/nginx/conf.d/loadbalancer.conf`

Default config:
```nginx
upstream application {
    server application.team1;
}

server {
    listen 80;
    location / {
        proxy_pass http://application;
    }
}
```

## Access logs
`/var/log/nginx/access.log`

Log format:
```
10.10.12.34 - - [31/May/2023:09:10:11 +0000] "GET /checkout?shopping_cart_id=92837465029182738291 HTTP/1.1" 200 0 "-" "Mozilla/5.0 ..."
```

Key fields: client IP, timestamp, HTTP method + path, status code, user-agent.

Useful commands:
```bash
tail /var/log/nginx/access.log              # Last 10 lines
tail -f /var/log/nginx/access.log           # Follow new lines
```

## Rate limiting (built-in)
Add to `loadbalancer.conf`:
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

See: https://www.nginx.com/blog/rate-limiting-nginx/
