###############################
# Import Python modules
###############################
import os, sys, datetime, inspect

###############################
# Import Scapy and Goose Modules
###############################
# We have to tell script where to find the Goose module in parent directory
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.compat import raw
from scapy.all import rdpcap
from goose.goose import GOOSE
from goose.goose import GOOSEPDU
from goose.goose_pdu import AllData
from goose.goose_pdu import Data
from goose.goose_pdu import IECGoosePDU
from goose.goose_pdu import UtcTime

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
# Identify packets containing GOOSE messages. 
# Sometimes these will be hidden within VLAN packets, so account for these
###############################

GOOSE_TYPE = 0x88b8
def gooseTest(pkt):
    isGoose = False
    # Test for a Goose Ether Type
    if pkt.haslayer('Dot1Q'):
        if pkt['Dot1Q'].type == GOOSE_TYPE: isGoose = True
    if pkt.haslayer('Ether'):
        if pkt['Ether'].type == GOOSE_TYPE: isGoose = True
    return isGoose

GOOSE_TYPE1 = 0x88b8
GOOSE_MAN   = 0x88b9
GOOSE_SVALS = 0x88ba
GOOSE_TYPES = [GOOSE_TYPE1,GOOSE_MAN,GOOSE_SVALS]
def gooseTypeTest(pkt):
    typeGoose = 0
    # Test for a Goose Ether Type
    if pkt.haslayer('Dot1Q'):
        if pkt['Dot1Q'].type in GOOSE_TYPES: typeGoose = pkt['Dot1Q'].type
    if pkt.haslayer('Ether'):
        if pkt['Ether'].type in GOOSE_TYPES: typeGoose = pkt['Ether'].type
    return typeGoose

###############################
# Process packets and search for GOOSE
###############################
goose_type1   = 0
goose_type1a  = 0
goose_manage  = 0
goose_svalues = 0
goose_sv_appid     = 0x4000
goose_type1a_appid = 0x8000
indent        = '    '
for p in packets:
    # Only process Goose Packets
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Test Ethertype
        gtype = gooseTypeTest(p)
        gappid = d.appid
        if gtype == GOOSE_TYPE1:
            if gappid >= goose_type1a_appid:
                goose_type1a = goose_type1a + 1
            else:
                goose_type1 = goose_type1 + 1
        # TODO: Determine if Sampled Values requires APPID between 0x4000 and 0x7fff and EtherType 0x88ba
        if gtype == GOOSE_SVALS:
            goose_svalues = goose_svalues + 1
        if gtype == GOOSE_MAN:
            goose_manage = goose_manage + 1


###############################
# Print Statements and Functions
###############################
## Normal Print Statement
print('Goose Packets: %d'%(goose_type1 + goose_type1a + goose_manage + goose_svalues))
print('%sType 1        : %d'%(indent,goose_type1))
print('%sType 1a       : %d'%(indent,goose_type1a))
print('%sGSE Management: %d'%(indent,goose_manage))
print('%sSampled Values: %d'%(indent,goose_svalues))