# Firewall (iptables + ipset)

## iptables
Linux kernel firewall. Rules match packets on source IP, port, protocol, etc., then ACCEPT or DROP.

**List rules:**
```bash
sudo iptables -S
```

**Add rule (drop HTTP from specific IP):**
```bash
sudo iptables -A INPUT -p tcp --dport 80 -s 10.10.12.34 -j DROP
```

**Flags:**
- `-A` = append (lowest priority), `-I` = insert (highest priority), `-D` = delete
- `-p tcp --dport 80` = match TCP port 80
- `-s <IP>` = source IP
- `-j DROP` = drop packet

**Delete rule:**
```bash
sudo iptables -D INPUT -p tcp --dport 80 -s 10.10.12.34 -j DROP
```

⚠️ New rules are active immediately. Be careful not to drop your own SSH session.

## ipset
Efficient set data structure for managing many IPs in a single rule.

**Create an ipset:**
```bash
sudo ipset create threat hash:ip
```

**Add IP to set:**
```bash
sudo ipset add threat 10.10.12.34
```

**Link to iptables (single rule drops all IPs in set):**
```bash
sudo iptables -A INPUT -m set --match-set threat src -j DROP
```

## Strategy
- Add high-risk IPs to `threat` ipset.
- iptables rule drops all traffic from that set at the kernel level (before NGINX even sees it).
- Use timeouts or periodic cleanup to expire bans after a configurable period.
