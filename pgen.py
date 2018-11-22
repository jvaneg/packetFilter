#---------------------------------------
# Author: Joel van Egmond
# ID: 10102094
#
# Purpose: Generates a packet with an IP header and a Transport layer header (TCP/UDP/Other),
#          and writes it to a file
#
# Usage: python pgen.py [tcp/udp/other] [source ip] [source port] [dest ip] [dest port] [out file name]
#---------------------------------------

import sys

from scapy.all import ICMP, IP, TCP, UDP, raw


def main(argv):
    if(len(argv) != 7):
        print("Invalid args!\npgen.py [tcp/udp/other] [source ip] [source port] [dest ip] [dest port] [out file name]")
        exit(-1)
        
    protocol = argv[1].lower()
    sourceAddr = argv[2]
    sourcePort = int(argv[3])
    destAddr = argv[4]
    destPort = int(argv[5])
    outFileName = argv[6]

    if(protocol == "tcp"):
        pkt = IP(dst=destAddr, src=sourceAddr)/TCP(dport=destPort, sport=sourcePort)
    elif(protocol == "udp"):
        pkt = IP(dst=destAddr, src=sourceAddr)/UDP(dport=destPort, sport=sourcePort)
    else:
        pkt = IP(dst=destAddr, src=sourceAddr)/ICMP() # this just exists to create failing test cases, ICMP is arbitrary

    outFile = open(outFileName,"wb")
    outFile.write(raw(pkt))
    outFile.close()

    print("Packet created!")
        
    
# Constants
TCP_PROTOCOL = 6    # TCP protocol number
UDP_PROTOCOL = 17   # UDP protocol number

if __name__ == "__main__":
    main(sys.argv)
