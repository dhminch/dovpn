#!/usr/bin/python3
 
import argparse
from Crypto.PublicKey import RSA
from datetime import datetime
import ipaddress
import os
import random
import socket
import stat
import string
import subprocess
import time
import yaml

from DigitalOceanAPIv2 import DigitalOceanAPIv2


"""import logging
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
requests_log.propagate = True"""

DO_API_DOMAIN = """api.digitalocean.com"""

def generate_password(length):
    return ''.join([random.choice(string.ascii_letters) for x in range(length)])

def create_ssh_keypair():
    key = RSA.generate(2048, os.urandom)
    public_key = key.exportKey('OpenSSH')
    private_key = key.exportKey('PEM')
    return {"public": public_key, "private": private_key}

def ssh_configure_droplet(droplet_ip, ssh_keypair, ssh_tmp_dir, openvpn_password):
    ssh_key_filename = "{}{}".format("dovpn-", random.randint(0,100000))
    ssh_key_file = os.path.join(ssh_tmp_dir, ssh_key_filename)
    with open(ssh_key_file, "w") as ssh_key_handle:
        ssh_key_handle.write(ssh_keypair["private"].decode("utf8"))
    os.chmod(ssh_key_file, stat.S_IRUSR | stat.S_IWUSR)


    ssh_openvpn_script = subprocess.Popen(
        [ "ssh", 
            "root@{}".format(droplet_ip),
            "-i", ssh_key_file, 
            "-o", "StrictHostKeyChecking=no", 
            "-o", "UserKnownHostsFile=/dev/null",
            "/usr/bin/ovpn-init", "--batch" ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        encoding='utf-8'
    )
    time.sleep(5)
    out, err = ssh_openvpn_script.communicate("yes")
    print(out)

    ssh_set_passwd = subprocess.Popen(
        [ "ssh", 
            "root@{}".format(droplet_ip),
            "-i", ssh_key_file, 
            "-o", "StrictHostKeyChecking=no", 
            "-o", "UserKnownHostsFile=/dev/null",
            "/usr/bin/passwd", "openvpn" ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        encoding='utf-8'
    )
    time.sleep(1)
    out, err = ssh_set_passwd.communicate("{}\n{}".format(openvpn_password, openvpn_password))
    print(out)

    os.remove(ssh_key_file)

def log_print(msg):
    print("[{}] {}".format(
        datetime.now(),
        msg
    ))

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

def get_vpn_droplet(config, do_api, do_keypair_id):
    r = do_api.create_droplet(
        name = config["do"]["droplet"]["prefix"] + str(random.randint(0, 100000)),
        image = config["do"]["droplet"]["image"],
        region = config["do"]["droplet"]["region"],
        size = config["do"]["droplet"]["size"],
        tag = config["do"]["droplet"]["tag"],
        sshkeyid = do_keypair_id
    )
    droplet_id = r["droplet"]["id"]
    droplet_name = r["droplet"]["name"]
    log_print("Droplet {} was created and named {}".format(droplet_id, droplet_name))

    log_print("Waiting 30 seconds for droplet to start and get networking information")
    time.sleep(30)

    for attempt in range(10):
        r = do_api.list_droplets_by_tag(config["do"]["droplet"]["tag"])
        for droplet in r["droplets"]:
            if droplet["id"] == droplet_id:
                ipv4_networks = r["droplets"][0]["networks"]["v4"]
                for ipv4_network in ipv4_networks:
                    if ipv4_network["type"] == "public":
                        log_print("Found public IPv4 address at {}".format(ipv4_network["ip_address"]))
                        return {"id": droplet_id, "ip": ipv4_network["ip_address"]}
        
        log_print("No IPv4 address yet, trying again in 10 seconds")
        time.sleep(10)

    return {"id": droplet_id, "ip": None}

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

    log_print("Loading configuration file {}".format(args.config))
    with open(args.config, "r") as config_file:
        config_yaml = yaml.load(config_file, Loader=yaml.FullLoader)

    do_api = DigitalOceanAPIv2(config_yaml["do"]["apikey"])

    log_print("Configuring iptables for communications with Digital Ocean API")
    setup_iptables_for_do_api(config_yaml)

    log_print("Generating SSH keypair")
    ssh_keypair = create_ssh_keypair()
    do_keypair_name = config_yaml["do"]["droplet"]["tag"] + "_key_" + str(random.randint(0,100000))
    do_keypair_id = do_api.add_ssh_keypair(
        do_keypair_name,
        ssh_keypair["public"]
    )
    log_print("Created DO SSH Key of ID {} and name {}".format(do_keypair_id, do_keypair_name))

    log_print("Creating VPN droplet")
    r = get_vpn_droplet(config_yaml, do_api, do_keypair_id)
    droplet_ip = r["ip"]
    
    log_print("Configuring iptables for communications with VPN droplet")
    setup_iptables_for_vpn(config_yaml, droplet_ip)

    log_print("SSHing into droplet to configure OpenVPN")
    openvpn_password = generate_password(24)
    log_print("Generated OpenVPN password of {}".format(openvpn_password))
    ssh_configure_droplet(droplet_ip, ssh_keypair, config_yaml["ssh"]["tmpdir"], openvpn_password)
 






    exit()
    time.sleep(60)

    log_print("Configuring iptables for communications with Digital Ocean API")
    setup_iptables_for_do_api(config_yaml)

    log_print("Delete all droplets with tag \"{}\"".format(config_yaml["do"]["droplet"]["tag"]))
    do_api.delete_droplets_by_tag(config_yaml["do"]["droplet"]["tag"])

    log_print("Delete SSH key with id {}".format(do_keypair_id))
    do_api.delete_ssh_keypair(do_keypair_id)

if __name__ == "__main__":
    main()