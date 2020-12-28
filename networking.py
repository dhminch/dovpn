#!/usr/bin/python3

import logging
import requests

IP_API_DOMAIN = """ifconfig.co"""

class LocalIpAddressLookupError(Exception):
    pass

def get_my_ip():
    try:
        r = requests.get("https://{}/ip".format(IP_API_DOMAIN))
        ip = r.content.strip().decode("utf8")
        logging.info("Local IP is {}".format(ip))
        return ip
    except:
        raise LocalIpAddressLookupError
