-pfilter.py is the main packet filtering program
-Usage: 
    python pfilter.py [rules] [packet]

    -pfilter.py does NOT require scapy

-pgen.py is a program that generates binary packet files to test with
-Usage:
    python pgen.py [tcp/udp/other] [source ip] [source port] [dest ip] [dest port] [out file name]

    -pgen.py requires scapy library from https://scapy.net/
        - install with:
        pip install scapy
        OR
        pip install --user scapy

-Assumptions:
     -assumes that rule file is well-formed and of form:
        [allow/deny] [udp/tcp] [source ip]:[source port] -> [dest ip]:[dest port]
     -assumes that the packet file is well-formed, and contains IP header, TCP/UDP header, and payload (no link layer header)

Note: If you want to run my test cases without using pgen.py, all test packets are in the /testPkts/ folder, and all test rules are in the /testRules/ folder.


pfilter.py documentation:
#---------------------------------------
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
# Note: - assumes that rule file is well-formed and of form:
#           [allow/deny] [udp/tcp] [source ip]:[source port] -> [dest ip]:[dest port]
#       - assumes that the packet file is well-formed, and contains IP header, TCP/UDP header, and payload (no link layer header)
#---------------------------------------


pgen.py documentation:
#---------------------------------------
# Purpose: Generates a packet with an IP header and a Transport layer header (TCP/UDP/Other),
#          and writes it to a file
#          Intended to generate test files for pfilter.py
#          You should probably make output files of type .dat but it doesn't really matter.
#
# Usage: python pgen.py [tcp/udp/other] [source ip] [source port] [dest ip] [dest port] [out file name]
#
# Note: - requires scapy library from https://scapy.net/
#---------------------------------------

