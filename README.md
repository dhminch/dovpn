# dovpn
Project to use Digital Ocean OpenVPN Access Servers to protect a Kali VM

## Setup

Create a file in the same directory as your script and name it "DO_API_KEY". Put your Digital Ocean API key in this file. Do not share this key or file with anyone!

```
echo <YOUR_DO_API_KEY> > DO_API_KEY
chmod 0600 DO_API_KEY
```