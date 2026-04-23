NGINX

Your load balancer is running NGINX with a simple HTTP load balancing configuration. It is set up to proxy the customers' HTTP requests coming from the internet to your application, which itself is not publicly reachable from the internet. This process is called load balancing, because it allows you to precisely control the distribution of incoming requests across a group of backend servers.
NGINX Configuration

In the setup for this competition, this process is simplified in the sense, that you only have a single backend, which is your application, and all incoming traffic is simply forwarded to that application.
NGINX configuration

If you want to take a look how your NGINX server is configured or even want to modify it, you can find the configuration file at /etc/nginx/conf.d/loadbalancer.conf.

The default configuration (for team 1) looks like this:

upstream application {
    server application.team1;
}

server {
    listen 80;

    location / {
        proxy_pass http://application;
    }
}

This configuration file is important if you want to modify NGINX's behavior or take advantage of NGINX's built-in features such as rate limiting.
NGINX Access Log

To start with, you don't have to change anything in the NGINX configuration. Instead, since NGINX is already running and handling incoming requests, take a look at the NGINX access log located at /var/log/nginx/access.log.
tail nginx access log

It is not recommended to cat the while log file, as it will contain a line for each past request. A better option is to use the tail command, which only prints the last few lines.

tail /var/log/nginx/access.log

If you also want to print all new log lines as new requests are processed, you can add the -f flag:

tail -f /var/log/nginx/access.log

A log line from the access log might look like this:

10.10.12.34 - - [31/May/2023:09:10:11 +0000] "GET /checkout?shopping_cart_id=92837465029182738291 HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Android 9; Mobile; rv:109.0) Gecko/113.0 Firefox/113.0"

The important parts for you are the customer's IP address (10.10.12.34), the timestamp (31/May/2023:09:10:11) and the HTTP status code (200).

You can already use this information to analyze basic traffic patterns and make decisions based on them. But just relying on this data alone is probably not enough to build any more sophisticated logic. Therefore, you have access to an IP information service that provides metadata for a given IP address. This service and how to can use it is described in detail in the next section.
NGINX Rate Limit

A very useful feature of NGINX is its rate limiting capability. By configuring a rate limit in the NGINX configuration, you can limit the number of HTTP requests a client is allowed to make in a given period of time. This is very useful to protect against attacks that consist of huge floods of requests, such as DDoS attacks.

As this is an incredible powerful feature, it is highly recommended to read this blog post and use it in your NGINX config.