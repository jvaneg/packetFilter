#---------------------------------------
# Author: Joel van Egmond
# ID: 10102094
#
# Purpose: Adds the user to the password file if they have a valid (not already used) username,
#          and a valid password.
#          A password is invalid if it follows the format [word], [number], [wordnumber], or [numberword]
#          Where [word] comes from the words.txt file
#
# Usage: python pfilter.py [rules] [packet]
#
# Note: - requires scapy library from https://scapy.net/
#       - assumes that rule file is of form:
#           [allow/deny] [udp/tcp] [source ip]:[source port] -> [dest ip]:[dest port]
#       - assumes that the packet file is well-formed, and contains IP header, TCP/UDP header, and payload (no link layer header)
#---------------------------------------

import re
import sys

from scapy.all import IP,UDP,TCP


class Rule:
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

    def __str__(self):
        if(self.protocol == TCP_PROTOCOL):
            protocol = "tcp" 
        elif(self.protocol == UDP_PROTOCOL):
            protocol = "udp"
        else:
            protocol = "other"

        return self.decision + " " + protocol + " " + self.sourceAddr + ":" + self.sourcePort + " -> " + self.destAddr + ":" + self.destPort

    def __repr__(self):
        return str(self)

    def match(self, protocol, sourceAddr, sourcePort, destAddr, destPort):
        if( self._matchProtocol_(protocol) and \
            self._matchAddr_(self.sourceAddr, sourceAddr) and self._matchPort_(self.sourcePort,sourcePort) and \
            self._matchAddr_(self.sourceAddr, sourceAddr) and self._matchPort_(self.destPort,destPort) ):
            return (True, self.decision)
        else:
            return (False, UNSPECIFIED)

    def _matchProtocol_(self, protocol):
        return (self.protocol == protocol)

    def _matchAddr_(self, ruleAddr, pktAddr):
        splitRuleAddr = ruleAddr.split('.')
        splitPktAddr = pktAddr.split('.')

        for ruleElem,pktElem in zip(splitRuleAddr,splitPktAddr):
            if(ruleElem == WILDCHAR):
                return True
            elif(ruleElem != pktElem):
                return False
        
        return True

    def _matchPort_(self, rulePort, pktPort):
        if(rulePort == WILDCHAR):
            return True
        else:
            return (int(rulePort) == pktPort)

    
            
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
