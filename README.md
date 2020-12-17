# dovpn
Project to use Digital Ocean OpenVPN Access Servers to protect a Kali VM

## Dependencies

python3
pycryptodome

## Setup

Make a copy of `config.sample.yaml` and name it `config.yaml` for the script to find it by default, or give it a name of your choosing and pass it to the script in the `-c/--config` parameter.

## Future Improvements

- Have SSH use EC instead of RSA
- Have SSH key protected by password when it's on disk