#!/usr/bin/python3

import logging
import random
import time

from DigitalOceanAPIv2 import DigitalOceanAPIv2
import crypto
import doiptables
import openvpnas

class NoDropletIpAddressError(Exception):
    pass

class VpnOrchestrator():
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
        self.do_api = DigitalOceanAPIv2(self.config["do"]["apikey"])
        self.openvpn = None

    """
    Private Methods
    """

    def __clean(self):
        logging.info("Deleting all droplets with tag \"{}\"".format(self.config["do"]["droplet"]["tag"]))
        self.do_api.delete_droplets_by_tag(self.config["do"]["droplet"]["tag"])

        logging.info("Deleting all SSH keys with tag \"{}\"".format(self.config["do"]["droplet"]["tag"]))
        self.do_api.delete_ssh_keypairs_by_tag(self.config["do"]["droplet"]["tag"])

    def __get_vpn_droplet(self):
        r = self.do_api.create_droplet(
            name = self.config["do"]["droplet"]["prefix"] + str(random.randint(0, 100000)),
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
        logging.info("Generating SSH keypair")
        ssh_keypair = crypto.create_ssh_keypair()
        self.do_keypair["public"] = ssh_keypair["public"]
        self.do_keypair["private"] = ssh_keypair["private"]
        self.do_keypair["name"] = self.config["do"]["droplet"]["tag"] + "_key_" + str(random.randint(0,100000))
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
        logging.info("Configuring iptables for communications with Digital Ocean API")
        doiptables.setup_iptables_for_do_api(self.config)

        self.__clean()

    def start(self):
        logging.info("Configuring iptables for communications with Digital Ocean API")
        doiptables.setup_iptables_for_do_api(self.config)

        self.__clean()

        self.__setup_ssh_keypair()

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

        self.openvpn = openvpnas.OpenVpnAs(
            self.config, 
            self.droplet["ip"],
            self.do_keypair["private"]
        )
        self.openvpn.start()

    def teardown(self):
        self.openvpn.teardown()

        logging.info("Configuring iptables for communications with Digital Ocean API")
        doiptables.setup_iptables_for_do_api(self.config)

        logging.info("Delete all droplets with tag \"{}\"".format(self.config["do"]["droplet"]["tag"]))
        self.do_api.delete_droplets_by_tag(self.config["do"]["droplet"]["tag"])

        logging.info("Delete SSH key with id {}".format(self.do_keypair["id"]))
        self.do_api.delete_ssh_keypair(self.do_keypair["id"])

        logging.info("Locking down iptables")
        doiptables.setup_iptables_rules(self.config, [])

    def wait(self):
        logging.info("OpenVPN running....Ctrl+C to tear things down")
        try:
            self.openvpn.wait()
        except KeyboardInterrupt:
            logging.info("All done, stopping OpenVPN and cleaning up")