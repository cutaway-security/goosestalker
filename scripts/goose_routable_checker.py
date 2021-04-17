###############################
# Import Python modules
###############################
import os, sys

###############################
# Import Scapy and Goose Modules
###############################
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.compat import raw
from scapy.all import rdpcap

###############################
# Global Variables
###############################
DEBUG = 0   # 0: off 1: Show Goose Payload 2: Full Debug

###############################
# Import packets into SCAPY
###############################
inf = sys.argv[1]
packets = rdpcap(inf)

###############################
# Process packets and search for GOOSE
###############################
# datasets = {src_mac:{'gocbref':GoCBRef, 'dataset':DataSet, 'goid':GoID}}
routable_goose   = b'\x01\x40'
tunneled_goose   = b'\xa0'
non_tunnel_goose = b'\xa1'
non_tunnel_sv    = b'\xa2'
non_tunnel_man   = b'\xa3'

cnt_routable_goose   = 0
cnt_tunneled_goose   = 0
cnt_non_tunnel_goose = 0
cnt_non_tunnel_sv    = 0
cnt_non_tunnel_man   = 0

for p in packets:
    # Only process UDP Packets
    if p.haslayer('UDP'):
        if p.load[0:2] == routable_goose:
            cnt_routable_goose = cnt_routable_goose + 1
            gsi = p.load[2:3]
            if gsi == tunneled_goose:
                cnt_tunneled_goose = cnt_tunneled_goose + 1
            if gsi == non_tunnel_goose:
                cnt_non_tunnel_goose = cnt_non_tunnel_goose + 1
            if gsi == non_tunnel_sv:
                cnt_non_tunnel_sv = cnt_non_tunnel_sv + 1
            if gsi == non_tunnel_man:
                cnt_non_tunnel_man = cnt_non_tunnel_man + 1


###############################
# Print Statements and Functions
###############################
## Normal Print Statement
print('Routable Goose and Sampled Values')
indent = '    '
if cnt_routable_goose:
    print('%sTotal Routable Goose Packets: %d'%(cnt_routable_goose))
    print('%sTotal Tunneled Goose: %d'%(cnt_tunneled_goose))
    print('%sTotal Non-tunneled Goose: %d'%(cnt_non_tunnel_goose))
    print('%sTotal Non-tunneled Sampled Values: %d'%(cnt_non_tunnel_sv))
    print('%sTotal Non-tunneled Management: %d'%(cnt_non_tunnel_man))
else:
    print('%sNo routable Goose or Sampled Values detected.'%(indent))
