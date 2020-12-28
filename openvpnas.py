#!/usr/bin/python3

import json
import logging
import os
import random
import requests
import signal
import subprocess
import stat
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import crypto
import doiptables

class OpenVpnAs():
    """
    Class Initialization
    """

    def __init__(self, config, ip, private_key):
        self.auth_file = None
        self.config = config
        self.config_file = None
        self.ip = ip
        self.password = None
        self.private_key = private_key
        self.process = None
        self.ssh_keyfile = None

    """ 
    Private Methods
    """

    def __openvpn_web_get_config(self):
        s = requests.Session()

        r = s.get("https://{}/".format(self.ip),
                verify=False
        )

        r = s.get("https://{}/".format(self.ip),
                verify=False
        )

        r = s.get("https://{}/__session_start__/".format(self.ip),
                verify=False
        )   

        r = s.post("https://{}/__auth__".format(self.ip),
                data = {"username": "openvpn", "password": self.password},
                verify=False
        )

        r = s.post("https://{}/downloads.json".format(self.ip),
                headers= {
                    "X-OpenVPN": "1",
                    "X-CWS-Proto-Ver": "2"
                },
                verify=False
        )
        config_url = json.loads(r.text[5:])["settings"]["userlocked"]
        
        r = s.get("https://{}/{}".format(self.ip, config_url),
                verify=False
        )
        config_file_contents = r.text

        auth_filename = crypto.make_name("openvpn-auth")
        self.auth_file = os.path.join(self.config["local"]["tmpdir"], auth_filename)
        with open(self.auth_file, "w") as auth_handle:
            auth_handle.write("{}\n{}".format("openvpn", self.password))
        os.chmod(self.auth_file, stat.S_IRUSR | stat.S_IWUSR)

        config_file_contents = config_file_contents.replace(
            "auth-user-pass", 
            "auth-user-pass {}".format(self.auth_file)
        )

        config_filename = crypto.make_name("openvpn")
        self.config_file = os.path.join(self.config["local"]["tmpdir"], config_filename)
        with open(self.config_file, "w") as config_handle:
            config_handle.write(config_file_contents)
        os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)

    def __ssh_configure_droplet(self):
        ssh_key_filename = crypto.make_name("droplet-ssh")
        self.ssh_keyfile = os.path.join(self.config["local"]["tmpdir"], ssh_key_filename)
        with open(self.ssh_keyfile, "w") as ssh_key_handle:
            ssh_key_handle.write(self.private_key.decode("utf8"))
        os.chmod(self.ssh_keyfile, stat.S_IRUSR | stat.S_IWUSR)

        ssh_openvpn_script = subprocess.Popen(
            [ "ssh", 
                "root@{}".format(self.ip),
                "-i", self.ssh_keyfile, 
                "-o", "StrictHostKeyChecking=no", 
                "-o", "UserKnownHostsFile=/dev/null",
                "/usr/bin/ovpn-init", "--batch" ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding='utf-8'
        )
        time.sleep(5)
        out, _ = ssh_openvpn_script.communicate("yes")
        if logging.getLogger().level == logging.DEBUG:
            print(out)
        ssh_openvpn_script.wait()

        ssh_set_passwd = subprocess.Popen(
            [ "ssh", 
                "root@{}".format(self.ip),
                "-i", self.ssh_keyfile, 
                "-o", "StrictHostKeyChecking=no", 
                "-o", "UserKnownHostsFile=/dev/null",
                "/usr/bin/passwd", "openvpn" ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding='utf-8'
        )
        time.sleep(1)
        out, _ = ssh_set_passwd.communicate(
            "{}\n{}".format(self.password, self.password))
        if logging.getLogger().level == logging.DEBUG:
            print(out)
        ssh_set_passwd.wait()

        ssh_get_ip = subprocess.Popen(
            [ "ssh", 
                "root@{}".format(self.ip),
                "-i", self.ssh_keyfile, 
                "-o", "StrictHostKeyChecking=no", 
                "-o", "UserKnownHostsFile=/dev/null",
                "echo", "$SSH_CLIENT"],
            stdout=subprocess.PIPE,
            encoding='utf-8'
        )
        time.sleep(1)
        out, _ = ssh_get_ip.communicate()
        if logging.getLogger().level == logging.DEBUG:
            print(out)
        ssh_get_ip.wait()
        self.localip = out.split()[0]

        if self.ssh_keyfile and os.path.isfile(self.ssh_keyfile):
            os.remove(self.ssh_keyfile)
            self.ssh_keyfile = None    

    """
    Public Methods
    """

    def start(self):
        logging.info("Configuring iptables for communications with VPN droplet")
        doiptables.setup_iptables_for_vpn(self.config, self.ip)

        logging.info("SSHing into droplet to configure OpenVPN")
        self.password = crypto.generate_password(24)
        logging.debug("Generated OpenVPN password of {}".format(self.password))
        self.__ssh_configure_droplet()

        logging.info("Waiting 60s for web portal to start")
        time.sleep(60)

        logging.info("Getting OpenVPN configuration from web portal")
        self.__openvpn_web_get_config()

        logging.info("Starting OpenVPN")
        self.process = subprocess.Popen(["openvpn", "--config", self.config_file])
        
    def teardown(self):
        logging.info("Killing OpenVPN process")
        if self.process:
            os.kill(self.process.pid, signal.SIGINT)

        logging.info("Removing related files")
        if self.config_file and os.path.isfile(self.config_file):
            os.remove(self.config_file)
            self.config_file = None

        if self.auth_file and os.path.isfile(self.auth_file):
            os.remove(self.auth_file)
            self.auth_file = None

        if self.ssh_keyfile and os.path.isfile(self.ssh_keyfile):
            os.remove(self.ssh_keyfile)
            self.ssh_keyfile = None

    def wait(self):
        self.process.wait()