#---------------------------------------
# Author: Joel van Egmond
# ID: 10102094
#
# Purpose: Takes 2 args: rule file and binary packet file.
#          The packet file is processed by the rule file (the filter).
#          The rules file lists the rules of the packet filter in the form:
#               [allow/deny] [udp/tcp] [source ip]:[source port] -> [dest ip]:[dest port]
#
#          The packet file is the raw packet data that is being processed by the filter. The packet 
#          file is a binary file that consists of the IP header, the TCP or UDP header 
#          (depending on the type of packet) and the payload of the packet.
#
#          The pfilter program reads the rule file and the packet data, compares the packet's headers
#          to the rules and outputs:
#               allow       ->  if the rules specify that the packet should be allowed
#               deny        ->  if the rules specify that the packet should be denied
#               unspecified ->  if there is no rule that applies to the packet
#
# Usage:   python pfilter.py [rules] [packet]
#
# Note: - requires scapy library from https://scapy.net/
#       - assumes that rule file is well-formed and of form:
#           [allow/deny] [udp/tcp] [source ip]:[source port] -> [dest ip]:[dest port]
#       - assumes that the packet file is well-formed, and contains IP header, TCP/UDP header, and payload (no link layer header)
#---------------------------------------

import re
import sys

from scapy.all import IP,UDP,TCP

#---------------------------------------
# Purpose: Represents a single rule from the rule file
# 
# Constructor inputs:
#   decision    - whether to allow or deny a matching packet
#   protocol    - the transport layer protocol of matching packets (tcp/udp)
#   sourceAddr  - the source ip address of matching packets
#   sourcePort  - the source port of matching packets
#   destAddr    - the destination ip address of matching packets
#   destPort    - the destination port of matching packets
#---------------------------------------
class Rule:
    #---------------------------------------
    # Default constructor
    #---------------------------------------
    def __init__(self, decision, protocol, sourceAddr, sourcePort, destAddr, destPort):
        self.decision = decision.lower()

        if(protocol.lower() == "tcp"):
            self.protocol = TCP_PROTOCOL
        elif(protocol.lower() == "udp"):
            self.protocol = UDP_PROTOCOL
        else:
            self.protocol = 0

        self.sourceAddr = sourceAddr
        self.sourcePort = sourcePort
        self.destAddr = destAddr
        self.destPort = destPort

    #---------------------------------------
    # To string specification
    #---------------------------------------
    def __str__(self):
        if(self.protocol == TCP_PROTOCOL):
            protocol = "tcp" 
        elif(self.protocol == UDP_PROTOCOL):
            protocol = "udp"
        else:
            protocol = "other"

        return self.decision + " " + protocol + " " + self.sourceAddr + ":" + self.sourcePort + " -> " + self.destAddr + ":" + self.destPort

    #---------------------------------------
    # Representation specification
    #---------------------------------------
    def __repr__(self):
        return str(self)

    #---------------------------------------
    # Purpose: Determines if a packet matches this rule
    #          and if so, also returns the the decision the rule specifies,
    # Inputs:
    #   protocol    - the transport layer protocol of the incoming packet (tcp/udp)
    #   sourceAddr  - the source ip address of the incoming packet
    #   sourcePort  - the source port of the incoming packet
    #   destAddr    - the destination ip address of the incoming packet
    #   destPort    - the destination port of the incoming packet
    # Output:
    #   - whether or not the packet matches the rule (true/false)
    #   - if the packet matches, what decision the rule specifies
    #---------------------------------------
    def match(self, protocol, sourceAddr, sourcePort, destAddr, destPort):
        if( self._matchProtocol_(protocol) and \
            Rule._matchAddr_(self.sourceAddr, sourceAddr) and Rule._matchPort_(self.sourcePort,sourcePort) and \
            Rule._matchAddr_(self.sourceAddr, sourceAddr) and Rule._matchPort_(self.destPort,destPort) ):
            return (True, self.decision)
        else:
            return (False, UNSPECIFIED)

    #---------------------------------------
    # Purpose: Determines if the protocols match between the rule and a packet
    # Inputs:
    #   protocol    - the transport layer protocol of the incoming packet (tcp/udp)
    # Output:
    #   - whether or not the protocols match (true/false)
    #---------------------------------------
    def _matchProtocol_(self, protocol):
        return (self.protocol == protocol)

    #---------------------------------------
    # Purpose: Determines if a rule address and a packet address match
    #          Treats wildcard chars (*) in the rule address as matching anything
    # Inputs:
    #   ruleAddr     - the ip address specified in the rule
    #   pktAddr      - the ip address from the packet
    # Output:
    #   - whether or not the addresses match (true/false)
    #---------------------------------------
    @staticmethod
    def _matchAddr_(ruleAddr, pktAddr):
        splitRuleAddr = ruleAddr.split('.')
        splitPktAddr = pktAddr.split('.')

        for ruleElem,pktElem in zip(splitRuleAddr,splitPktAddr):
            if(ruleElem == WILDCHAR):
                return True
            elif(ruleElem != pktElem):
                return False
        
        return True

    #---------------------------------------
    # Purpose: Determines if a rule port and a packet port match
    #          Treats wildcard chars (*) in the rule port as matching anything
    # Inputs:
    #   rulePort     - the port specified in the rule
    #   pktPort      - the port from the packet
    # Output:
    #   - whether or not the ports match (true/false)
    #---------------------------------------
    @staticmethod
    def _matchPort_(rulePort, pktPort):
        if(rulePort == WILDCHAR):
            return True
        else:
            return (int(rulePort) == pktPort)

    
#---------------------------------------
# The main program, see top program documentation
#---------------------------------------
def main(argv):
    if(len(argv) != 3):
        print("Invalid args!\npfilter.py [rules] [packet]")
        exit(-1)

    rulesFile = argv[1]
    packetFile = argv[2]

    pktProtocol,sourceAddr,sourcePort,destAddr,destPort = getPacketData(packetFile)

    if(not((pktProtocol == TCP_PROTOCOL) or (pktProtocol == UDP_PROTOCOL))):
        print(UNSPECIFIED)
        exit(-1)

    rulesList = getRulesList(rulesFile)

    print(rulesList)

    print("Protocol: " + str(pktProtocol))
    print("Source: " + sourceAddr + ":" + str(sourcePort))
    print("Destination: " + destAddr + ":" + str(destPort))

    for rule in rulesList:
        match, decision = rule.match(pktProtocol, sourceAddr, sourcePort, destAddr, destPort)
        if(match):
            print(decision)
            exit(0)
    
    print(UNSPECIFIED) # no matching rule
    exit(-1)


#---------------------------------------
# Purpose: Gets the data needed from the binary packet file to compare it to rules
#          This comprises of the Transport Protocol, source IP and port,
#          and destination IP and port
# Inputs:
#   packetFile  - the name of the binary packet file
# Output:
#   pktProtocol - the transport level protocol, as an integer
#   sourceAddr  - the source IP address, as a string
#   sourcePort  - the source port (TCP or UDP), as an integer
#   destAddr    - the destination IP address, as a string
#   destPort    - the destination port (TCP or UDP), as an integer
#---------------------------------------
def getPacketData(packetFile):
    packetContent = open(packetFile,"rb").read()

    packet = IP(packetContent)

    pktProtocol = packet[IP].proto
    sourceAddr = packet[IP].src
    destAddr = packet[IP].dst

    if(pktProtocol == TCP_PROTOCOL):
        sourcePort = packet[TCP].sport
        destPort = packet[TCP].dport
    elif(pktProtocol == UDP_PROTOCOL):
        sourcePort = packet[UDP].sport
        destPort = packet[UDP].dport
    else:
        sourcePort = 0
        destPort = 0

    return (pktProtocol, sourceAddr, sourcePort, destAddr, destPort)

#---------------------------------------
# Purpose: Parses the rule file and puts them into an easy to compare data structure
#          for matching with port data
# Inputs:
#   ruleFile    - the name of the rules file
# Output:
#   rulesList   - a list of Rule objects
#---------------------------------------
def getRulesList(rulesFile):
    rulesStringList = open(rulesFile,"r").read().strip().split('\n')
    rulesList = []

    for ruleString in rulesStringList:
        splitRule = re.split('[ :]', ruleString)
        rule = Rule(splitRule[0], splitRule[1], splitRule[2], splitRule[3], splitRule[5], splitRule[6])
        rulesList.append(rule)

    return rulesList
    
    
# Constants
TCP_PROTOCOL = 6    # TCP protocol number
UDP_PROTOCOL = 17   # UDP protocol number

UNSPECIFIED = "unspecified"      # other/unspecified string

WILDCHAR = '*'      # match any wildcard char


if __name__ == "__main__":
    main(sys.argv)
