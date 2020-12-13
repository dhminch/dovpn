#!/usr/bin/python3
 
import argparse
import ipaddress
import os
import random
import socket
import subprocess
import yaml

from DigitalOceanAPIv2 import DigitalOceanAPIv2


import logging
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


DO_API_DOMAIN = """api.digitalocean.com"""

def iptables(rule, output=False):
    rule_split = rule.split(" ")
    if output:
        r = subprocess.run(["iptables", *rule_split], capture_output=True)
        print(r.stdout.decode("utf8"))
    else:
        subprocess.run(["iptables", *rule_split])

def setup_iptables_rules(config, custom_rules):
    iptables("-P INPUT DROP")
    iptables("-P FORWARD DROP")
    iptables("-P OUTPUT DROP")
    iptables("-F")
    iptables("-A INPUT -i lo -j ACCEPT")
    iptables("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    iptables("-A OUTPUT -o lo -j ACCEPT")
    iptables("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    iptables("-A OUTPUT -o {} -p udp -d {} --dport 53 -j ACCEPT".format(
        config["net"]["interface"],
        config["net"]["dns"]
    ))
    iptables("-A OUTPUT -o {} -p tcp -d {} --dport 53 -j ACCEPT".format(
        config["net"]["interface"],
        config["net"]["dns"]
    ))
    for port in config["net"]["allowedudpports"]:
        iptables("-A OUTPUT -o {} -p udp -d {} --dport {} -j ACCEPT".format(
            config["net"]["interface"],
            config["net"]["gateway"],
            port
        ))
    for net in config["net"]["dropnets"]:
        iptables("-A OUTPUT -o {} -d {} -j DROP".format(
            config["net"]["interface"],
            net
        ))
    for custom_rule in custom_rules:
        iptables(custom_rule)
    iptables("-nvL", output=True)

def setup_iptables_for_do_api(config):
    # DO API has several IPs, try to get them all!
    do_ips = []
    for i in range(10):
        do_ip = socket.gethostbyname(DO_API_DOMAIN)
        if do_ip not in do_ips:
            do_ips.append(do_ip)

    custom_rules = []
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
    custom_rules.append("-A OUTPUT -o {} -p tcp -d {} --dport {} -j ACCEPT".format(
        config["net"]["interface"],
        droplet_ip,
        config["ssh"]["port"]
    ))
    custom_rules.append("-A OUTPUT -o {} -p udp -d {} --dport 1194 -j ACCEPT".format(
        config["net"]["interface"],
        droplet_ip
    ))
    custom_rules.append("-A OUTPUT -o tun0 -j ACCEPT")
    setup_iptables_rules(config, custom_rules)

def get_vpn_droplet(config, do_api):
    r= do_api.create_droplet(
        name = config["do"]["droplet"]["prefix"] + str(random.randint(0, 100000)),
        image = config["do"]["droplet"]["image"],
        region = config["do"]["droplet"]["region"],
        size = config["do"]["droplet"]["size"],
        tag = config["do"]["droplet"]["tag"],
        sshkeyid = config["do"]["sshkeyid"]
    )
    print(r)

def main():
    parser = argparse.ArgumentParser(description='Manage a DigitalOcean VPN.')
    parser.add_argument('-c', '--config', default="config.yaml",
                        help='configuration file location')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("You are not root!")
        exit(1)

    if not os.path.isfile(args.config):
        print("Config file {} does not exist.".format(args.config))
        exit(1)

    with open(args.config, "r") as config_file:
        config_yaml = yaml.load(config_file, Loader=yaml.FullLoader)

    setup_iptables_for_do_api(config_yaml)

    do_api = DigitalOceanAPIv2(config_yaml["do"]["apikey"])
    get_vpn_droplet(config_yaml, do_api)
    
    setup_iptables_for_vpn(config_yaml, "1.2.3.4")
    

if __name__ == "__main__":
    main()