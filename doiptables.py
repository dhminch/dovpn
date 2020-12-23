#!/usr/bin/python3

import logging
import socket
import subprocess

DO_API_DOMAIN = """api.digitalocean.com"""

"""
Private Functions
"""

def __iptables(rule, output=False):
    rule_split = rule.split(" ")
    if output:
        r = subprocess.run(["iptables", *rule_split], capture_output=True)
        print(r.stdout.decode("utf8"))
    else:
        subprocess.run(["iptables", *rule_split])

"""
Public Functions
"""

def setup_iptables_for_do_api(config):
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

    # DO API has several IPs, try to get them all!
    do_ips = []
    for i in range(10):
        do_ip = socket.gethostbyname(DO_API_DOMAIN)
        if do_ip not in do_ips:
            do_ips.append(do_ip)

    for do_ip in do_ips:
        custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport 443 -j ACCEPT".format(
            config["net"]["interface"],
            do_ip
        ))
    setup_iptables_rules(config, custom_rules)  

def setup_iptables_for_vpn(config, droplet_ip):
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
    __iptables("-P INPUT DROP")
    __iptables("-P FORWARD DROP")
    __iptables("-P OUTPUT DROP")
    __iptables("-F")
    __iptables("-A INPUT -i lo -j ACCEPT")
    __iptables("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    __iptables("-A OUTPUT -o lo -j ACCEPT")
    __iptables("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    for port in config["net"]["allowedudpports"]:
        __iptables("-A OUTPUT -o {} -p udp -d {} --dport {} -j ACCEPT".format(
            config["net"]["interface"],
            config["net"]["gateway"],
            port
        ))
    for net in config["net"]["dropnets"]:
        __iptables("-A OUTPUT -o {} -d {} -j DROP".format(
            config["net"]["interface"],
            net
        ))
    for custom_rule in custom_rules:
        __iptables(custom_rule)
    logger = logging.getLogger()
    output = (logger.level in [logging.DEBUG, logging.INFO])
    __iptables("-nvL", output=output)
