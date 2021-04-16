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

###############################
# Process packets and search for GOOSE
###############################
cnt_sec = 0
cnt_nosec = 0
indent = '    '
for p in packets:
    # Only process Goose Packets
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Test Goose Reserve1 Byte
        # FIXME: This byte also contains bits for simulation and future standardization. 
        #       Ignore until a mask can be made for security bits.

        # Test Goose Reserved2 Byte - this will contain a CRC if security enabled, else 0x0000
        if d.reserved2 > 0x0000:
            cnt_sec = cnt_sec + 1
        else: 
            cnt_nosec = cnt_nosec + 1

        # Test Goose PDU for Security information
        # TODO: Add this test if this can be implemented without setting Reserved1 and / or Reserved2 bytes
        # TODO: Add this test or a separate script to collect and report useful security information.

###############################
# Print Statements and Functions
###############################
## Normal Print Statement
print('Goose Packets: %d'%(cnt_sec + cnt_nosec))
print('%sSecurity: %d'%(indent,cnt_sec))
print('%sNo Security: %d'%(indent,cnt_nosec))
