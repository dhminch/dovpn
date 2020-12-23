#!/usr/bin/python3
 
import argparse
import logging
import os
import yaml

import vpnorchestrator

def main():
    logging.basicConfig(format='%(asctime)s %(levelname)8s: %(message)s', level=logging.DEBUG)

    parser = argparse.ArgumentParser(description='Manage a DigitalOcean VPN.')
    parser.add_argument('-c', '--config', default="config.yaml",
                        help='configuration file location')
    parser.add_argument('-r', '--remove', action='store_true',
                        help='remove all related DigitalOcean droplets and keys, and quit')
    args = parser.parse_args()

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