Firewall
Motivation

If you've built some logic that tries to identify which requests are coming from real customers and which are likely coming from malicious actors, you want to drop those undesirable requests while your application is overloaded. However, you then find yourself in a dilemma, because on the one hand you want to keep your application alive and serving as many customer requests as possible, while on the other hand you don't want to just drop any requests that you're not sure about, because it could very well be a paying customer that you don't want to upset. The initial situation you find yourself in during this contest, where your application is clearly overloaded, forces you to make a trade-off between allowing as many customers as possible to use the application while accepting that you may inadvertently block a handful of customers.
iptables

The way to "drop" a request, that is, to reject the packet as early as possible, is to use a firewall. The most direct and efficient method is to use iptables, which is a firewall that is installed by default on most Linux distributions, including Ubuntu.

As iptables is fairly complex, this section will provide you the most important commands you need to know for a basic firewall setup.
Rules

Iptables maintains a list of rules that specify filters such as source IP, destination port, or protocol, and then specify an action, which is either accept or reject. For each incoming and outgoing packet, iptables checks if the packet matches any of the configured rules and then either accepts or drops the packet.

Use the following command to display the current list of configured rules:

sudo iptables -S

If you have not yet configured any rules, the output should look like this:

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

You can see that there are multiple different "chains", which in short, correspond to different stages where you can inspect and filter traffic in the system. The most important one for this event is the INPUT chain, because all packets arriving at the network interface of the load balancer are matched against the rules in the INPUT chain.
Managing Rules

To add a rule to iptables, you have to at least specify the chain and the action and can optionally provide filters for things like the protocol or port.

The following command adds an iptables rule that drops all incoming HTTP traffic from the IP address 10.10.12.34:

sudo iptables -A INPUT -p tcp --dport 80 -s 10.10.12.34 -j DROP

The -A flag means that the rule should be appended to the end of the list of rules and therefore also has the lowest priority. If you want to insert the rule at the top of the list with the highest priority, use -I instead. If you want to delete a rule, just use the same command but replace the -A / -I with -D.

For example, the following command removes the rule from the previous example:

sudo iptables -D INPUT -p tcp --dport 80 -s 10.10.12.34 -j DROP

You can read more about the different flags in the iptables man pages.
Don't lock yourself out

When experimenting with iptables rules, keep in mind that new rules become active as soon as you run the command. This also means that it is very easy to lock yourself out if you accidentally add a new rule with a broad filter that will drop your current and all future SSH connections, meaning there is no way to connect to server!
Tip: ipset

Adding a single rule for each individual IP address from which you want to block requests becomes quite messy and inefficient as the number of IPs grows. Iptables has a solution to this problem called an ipsets, which is essentially an efficient data structure for managing and matching IPs. You can add many IPs to an ipset and only need to add a single iptables rule that will drop all the IP addresses contained in the ipset.

For starters, use the following command to create an ipset (which is called threat in this example):

sudo ipset create threat hash:ip

You can also configure the ipset to have a timeout, which will cause the ipset to delete entries after a certain amount of time. For more information on this topic, see the ipset man pages.

To add an IP to the ipset, run the following command:

sudo ipset add threat 10.10.12.34

The only thing left to do is to add an iptables rule that will drop all the IPs in the ipset:

sudo iptables -A INPUT -m set --match-set threat src -j DROP