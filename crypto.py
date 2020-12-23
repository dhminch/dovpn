#!/usr/bin/python3

from Crypto.PublicKey import RSA
import os
import random
import string

"""
Public Functions
"""

def generate_password(length):
    return ''.join([random.choice(string.ascii_letters) for x in range(length)])

def create_ssh_keypair():
    key = RSA.generate(2048, os.urandom)
    public_key = key.exportKey('OpenSSH')
    private_key = key.exportKey('PEM')
    return {"public": public_key, "private": private_key}
