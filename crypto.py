#!/usr/bin/env python3

"""Manages the cryptography and other name generation functionality needed."""

from Crypto.PublicKey import RSA
import os
import random
import string

"""
Public Functions
"""

def generate_password(length):
    """Generates a random password of mixed-case letters."""
    return ''.join([random.choice(string.ascii_letters) for x in range(length)])

def create_ssh_keypair():
    """Generates a 2048-bit RSA SSH key pair."""
    key = RSA.generate(2048, os.urandom)
    public_key = key.exportKey('OpenSSH')
    private_key = key.exportKey('PEM')
    return {"public": public_key, "private": private_key}

def make_name(prefix):
    """Generates a string using the given prefix and randomly generated number."""
    suffix = str(random.randint(0, 1000000))
    return "{}-{}".format(prefix, suffix)