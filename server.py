import argparse, setproctitle
from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.inet import IP, UDP






def main():
    setproctitle.setproctitle("monitor")
    sniff(filter)