# Setup
On a VM. This should act as a loadbalancer.
Getting simulated user traffic and bot requests/DDOS.
Using NGINX.
Have a firewall

# Goal

Write logic to filter out spam traffic, to protect the web app from fraufulant traffic, to make it stay available for legitimate users.

# Logical Steps

Use ngingx access logs and the ip info lookup service to get ip info.
Worlking in a loop. Analyse traffic with nginx access logs and ip info service. Understand waht is likely spam/bot behavior that needs to be banned.
use wirewall rules to block bad traffic. use nginx or similar too?
analyse further traffic and impact on revenue (not accessible in this vm, our team has a dashboard setup on a separte screen)

Repeat loop of analyse logs, write logic to combat bad traffic, monitor, and so on.