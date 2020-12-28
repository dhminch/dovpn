#!/usr/bin/env python3

"""Class that oversees the entire VPN operation.

Manages the droplet deployment and configuration and oversees the OpenVPN 
Access Server deployment and configuration."""

import logging
import random
import time

from DigitalOceanAPIv2 import DigitalOceanAPIv2
import crypto
import iptables
import networking
import openvpnas

DO_API_DOMAIN = """api.digitalocean.com"""
IP_API_DOMAIN = """ifconfig.co"""

class NoDropletIpAddressError(Exception):
    pass

class VpnOrchestrator():
    """Oversees the entire VPN operation and ensures clean state."""

    """
    Class Init
    """

    def __init__(self, config):
        self.config = config
        self.droplet = {
            "id": None,
            "name": None,
            "ip": None
        }
        self.do_keypair = {
            "public": None,
            "private": None,
            "id": None,
            "name": None
        }
        self.local_ip = None
        self.do_api = DigitalOceanAPIv2(self.config["do"]["apikey"])
        self.openvpn = None

    """
    Private Methods
    """

    def __add_droplet_firewall(self):
        """Adds a Digital Ocean firewall that restricts incoming traffic.

        Only incoming SSH/HTTPS/OpenVPN traffic from the local public IP
        address is allowed through this firewall. This firewall is applied 
        to all droplets with the tag. All outgoing traffic is allowed."""

        logging.info("Adding firewall for tag {}".format(
            self.config["do"]["droplet"]["tag"]))
        
        inbound_rules = [
            { # Allow SSH in from local IP
                "protocol": "tcp",
                "ports": "22",
                "sources": {
                    "addresses": [
                        self.local_ip
                    ]
                }
            }, { # Allow HTTPS in from local IP
                "protocol": "tcp",
                "ports": "443",
                "sources": {
                    "addresses": [
                        self.local_ip
                    ]
                }
            }, { # Allow OpenVPN in from local IP
                "protocol": "udp",
                "ports": "1194",
                "sources": {
                    "addresses": [
                        self.local_ip
                    ]
                }
            }
        ]

        outbound_rules = [
            { # Allow ICMP any
                "protocol": "icmp",
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                }
            }, { # Allow TCP any
                "protocol": "tcp",
                "ports": "all",
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                }
            }, { # Allow UDP any
                "protocol": "udp",
                "ports": "all",
                "destinations": {
                    "addresses": [
                        "0.0.0.0/0",
                        "::/0"
                    ]
                }
            }
        ]

        firewall_name = crypto.make_name(self.config["do"]["droplet"]["prefix"])
        self.do_api.add_firewall(
            firewall_name, 
            self.config["do"]["droplet"]["tag"],
            inbound_rules,
            outbound_rules
        )

    def __clean(self):
        """Cleans up any droplets, keys, or firewalls."""
        logging.info("Deleting all droplets with tag \"{}\"".format(self.config["do"]["droplet"]["tag"]))
        self.do_api.delete_droplets_by_tag(self.config["do"]["droplet"]["tag"])

        logging.info("Deleting all SSH keys with tag \"{}\"".format(self.config["do"]["droplet"]["tag"]))
        self.do_api.delete_ssh_keypairs_by_tag(self.config["do"]["droplet"]["tag"])

        logging.info("Delete firewalls with prefix \"{}\"".format(self.config["do"]["droplet"]["prefix"]))
        self.do_api.delete_firewalls_with_prefix(self.config["do"]["droplet"]["prefix"])

    def __get_vpn_droplet(self):
        """Creates droplet and then provides IP address of the new droplet."""

        # Request droplet
        r = self.do_api.create_droplet(
            name = crypto.make_name(self.config["do"]["droplet"]["prefix"]),
            image = self.config["do"]["droplet"]["image"],
            region = self.config["do"]["droplet"]["region"],
            size = self.config["do"]["droplet"]["size"],
            tag = self.config["do"]["droplet"]["tag"],
            sshkeyid = self.do_keypair["id"]
        )
        self.droplet["id"] = r["droplet"]["id"]
        self.droplet["name"] = r["droplet"]["name"]
        logging.info("Droplet {} was created and named {}".format(
            self.droplet["id"], self.droplet["name"]))

        logging.info("Waiting 60 seconds for droplet to start and get networking information")
        time.sleep(60)

        # Get droplet IP
        for _ in range(6):
            r = self.do_api.list_droplets_by_tag(self.config["do"]["droplet"]["tag"])
            for droplet in r["droplets"]:
                if droplet["id"] == self.droplet["id"]:
                    ipv4_networks = r["droplets"][0]["networks"]["v4"]
                    for ipv4_network in ipv4_networks:
                        if ipv4_network["type"] == "public":
                            logging.info("Found public IPv4 address at {}".format(ipv4_network["ip_address"]))
                            self.droplet["ip"] = ipv4_network["ip_address"]
                            return
            
            logging.info("No IPv4 address yet, trying again in 10 seconds")
            time.sleep(10)

        raise NoDropletIpAddressError()

    def __setup_ssh_keypair(self):
        """Creates SSH key pair and adds it to Digital Ocean."""
        logging.info("Generating SSH keypair")
        ssh_keypair = crypto.create_ssh_keypair()
        self.do_keypair["public"] = ssh_keypair["public"]
        self.do_keypair["private"] = ssh_keypair["private"]
        self.do_keypair["name"] = crypto.make_name(self.config["do"]["droplet"]["tag"])
        self.do_keypair["id"] = self.do_api.add_ssh_keypair(
            self.do_keypair["name"],
            self.do_keypair["public"]
        )
        logging.info("Created DO SSH Key of ID {} and name {}".format(
            self.do_keypair["id"], 
            self.do_keypair["name"]
        ))

    """
    Public Methods
    """

    def clean(self):
        """Allows traffic to Digital Ocean and cleans up any artifacts."""
        logging.info("Configuring iptables for communications with Digital Ocean API")
        iptables.setup_iptables_for_hostname_https(self.config, DO_API_DOMAIN)

        self.__clean()

    def start(self):
        """Starts the Digital Ocean VPN."""

        # Get local public IP address
        logging.info("Configuring iptables for communications with IP address lookup API")
        iptables.setup_iptables_for_hostname_https(self.config, IP_API_DOMAIN)
        try:
            self.local_ip = networking.get_my_ip()
        except networking.LocalIpAddressLookupError:
            logging.critical("Unable to get local IP address")
            self.teardown()
            exit(1)

        logging.info("Configuring iptables for communications with Digital Ocean API")
        iptables.setup_iptables_for_hostname_https(self.config, DO_API_DOMAIN)

        self.__clean() # Double-check that there are no previous artifacts
        self.__setup_ssh_keypair()
        self.__add_droplet_firewall()

        logging.info("Creating VPN droplet")
        try:
            self.__get_vpn_droplet()
        except NoDropletIpAddressError:
            logging.critical("Unable to get an IP address for droplet")
            self.teardown()
            exit(1)
        except:
            logging.critical("Unknown error starting droplet")
            self.teardown()
            exit(1)

        # Start up OpenVPN
        self.openvpn = openvpnas.OpenVpnAs(
            self.config, 
            self.droplet["ip"],
            self.do_keypair["private"]
        )
        self.openvpn.start()

    def teardown(self):
        """Tears down the VPN and ensures a clean state remains.

        This method may be called when an error condition occurs and everything
        needs to be cleaned up. The biggest concern is cleaning up Digital Ocean well,
        because otherwise usage charges will be incurred. However, this can be problematic
        if networking issues are the source of the error in the first place."""

        if self.openvpn:
            self.openvpn.teardown()
            self.openvpn = None

        logging.info("Configuring iptables for communications with Digital Ocean API")
        iptables.setup_iptables_for_hostname_https(self.config, DO_API_DOMAIN)

        self.__clean()

        # Is not strictly necessary, but seems better to leave system more
        # secure than we found it
        logging.info("Locking down iptables")
        iptables.setup_iptables_rules(self.config, [])

    def wait(self):
        """Waits for OpenVPN process to be finished running."""
        logging.info("OpenVPN running....Ctrl+C to tear things down")
        try:
            self.openvpn.wait()
        except KeyboardInterrupt:
            logging.info("All done, stopping OpenVPN and cleaning up")