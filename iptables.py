#!/usr/bin/env python3

"""Manages the local system's iptables configuration.

The necessary iptables rules depends on what services are being used and 
will have to be modified by other methods several times during execution. 
These rules should be as restrictive as possible."""

import logging
import socket
import subprocess

"""
Private Functions
"""

def __iptables(rule, output=False):
    """Helper function that executes an iptables rule on the local system."""
    rule_split = rule.split(" ")
    if output:
        r = subprocess.run(["iptables", *rule_split], capture_output=True)
        print(r.stdout.decode("utf8"))
    else:
        subprocess.run(["iptables", *rule_split])

"""
Public Functions
"""

def setup_iptables_for_hostname_https(config, hostname):
    """Configures the local system to communicate to a remote host on HTTPS.

    This function uses the configuration to determine the correct interfaces,
    networks, and services to allow.

    First the IP address of the remote hostname must be determined via DNS, and
    there may be multiple IP addresses that need to be allowed. Then, iptables 
    can be configured to allow HTTPS only to that IP address, dropping all other
    traffic (besides the allowed services already mentioned)."""

    # Allow DNS lookups
    custom_rules = []
    custom_rules.append("-A OUTPUT -o {} -p udp -d {} --dport 53 -j ACCEPT".format(
        config["net"]["interface"],
        config["net"]["dns"]
    ))
    custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport 53 -j ACCEPT".format(
        config["net"]["interface"],
        config["net"]["dns"]
    ))
    setup_iptables_rules(config, custom_rules)

    # Perform DNS lookups for remote host IP
    # If hostname has several IPs, try to get them all!
    ips = []
    attempts_left = 4
    while attempts_left > 0:
        logging.debug("DNS lookup attempts left: {:5d}, Number of IPs: {:5d}".format(attempts_left, len(ips)))
        ip = socket.gethostbyname(hostname)
        if ip not in ips:
            ips.append(ip)
            attempts_left += len(ips)
        attempts_left -= 1

    # Allow HTTPS traffic to remote target IPs
    for ip in ips:
        custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport 443 -j ACCEPT".format(
            config["net"]["interface"],
            ip
        ))
    setup_iptables_rules(config, custom_rules)  

def setup_iptables_for_vpn(config, droplet_ip):
    """Configures the local system to communicate to the VPN droplet.

    This function uses the configuration to determine the correct interfaces,
    networks, and services to allow.

    SSH/HTTPS/OpenVPN communications need to be allowed to the droplet, and then
    all traffic going out the new OpenVPN tun0 interface needs to be allowed."""

    custom_rules = []
    custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport 443 -j ACCEPT".format(
        config["net"]["interface"],
        droplet_ip
    ))
    custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport 22 -j ACCEPT".format(
        config["net"]["interface"],
        droplet_ip
    ))
    custom_rules.append("-A OUTPUT -o {} -p udp -d {} --dport 1194 -j ACCEPT".format(
        config["net"]["interface"],
        droplet_ip
    ))
    custom_rules.append("-A OUTPUT -o tun0 -j ACCEPT")
    setup_iptables_rules(config, custom_rules)
    
def setup_iptables_rules(config, custom_rules):
    """Configures the local system iptables with default plus custom rules.

    All traffic that is not explicitly allowed by the configuration or custom rule 
    should be dropped. The order of firewall commands is done such that no packets 
    can sneak in or out while the rules are being configured."""

    # Default policy is to drop all traffic
    __iptables("-P INPUT DROP")
    __iptables("-P FORWARD DROP")
    __iptables("-P OUTPUT DROP")

    # Get rid of all rules (so only the default policy applies)
    __iptables("-F")

    # Allow localhost and established communcations
    __iptables("-A INPUT -i lo -j ACCEPT")
    __iptables("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    __iptables("-A OUTPUT -o lo -j ACCEPT")
    __iptables("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

    # Allow some UDP ports on specified interface to specified gateway
    # (this allows things like DHCP to still work)
    for port in config["net"]["allowedudpports"]:
        __iptables("-A OUTPUT -o {} -p udp -d {} --dport {} -j ACCEPT".format(
            config["net"]["interface"],
            config["net"]["gateway"],
            port
        ))

    # Explicitly block any specified networks
    for net in config["net"]["dropnets"]:
        __iptables("-A OUTPUT -o {} -d {} -j DROP".format(
            config["net"]["interface"],
            net
        ))

    # Add custom rules
    for custom_rule in custom_rules:
        __iptables(custom_rule)

    # Print out iptables state if at proper log level
    logger = logging.getLogger()
    output = (logger.level in [logging.DEBUG, logging.INFO])
    __iptables("-nvL", output=output)
