#!/usr/bin/env python3

"""Main function for the DOVPN project."""
 
import argparse
import logging
import os
import yaml

import vpnorchestrator

def main():
    """Main function that sets up script to run.

    Handles arguments, logging, and configuration before passing of control
    to the orchestrator object."""
    
    parser = argparse.ArgumentParser(description='Manage a DigitalOcean VPN.')
    parser.add_argument('-c', '--config', default="config.yaml",
                        help='configuration file location')
    parser.add_argument('-r', '--remove', action='store_true',
                        help='remove all related DigitalOcean droplets and keys, and quit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="enable verbose output")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="enable verbose output with HTTP requests (implies -v)")
    args = parser.parse_args()

    log_format = "%(asctime)s %(levelname)8s: %(message)s"
    if args.debug:
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig(format=log_format, level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(format=log_format, level=logging.DEBUG)
    else:
        logging.basicConfig(format=log_format, level=logging.INFO)

    if os.geteuid() != 0:
        logging.critical("You are not root!")
        exit(1)

    if not os.path.isfile(args.config):
        logging.critical("Config file {} does not exist.".format(args.config))
        exit(1)

    logging.info("Loading configuration file {}".format(args.config))
    with open(args.config, "r") as config_file:
        config_yaml = yaml.load(config_file, Loader=yaml.FullLoader)

    if args.remove:
        logging.info("Removing all DigitalOcean droplets and keys")
        orch = vpnorchestrator.VpnOrchestrator(config_yaml)
        orch.clean()
        exit(0)

    try:
        orch = vpnorchestrator.VpnOrchestrator(config_yaml)
        orch.start()
        orch.wait()
        orch.teardown()
    except Exception as ex:
        orch.teardown()
        raise ex

if __name__ == "__main__":
    main()