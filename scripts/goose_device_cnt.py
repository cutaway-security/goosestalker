###############################
# Import Python modules
###############################
import os, sys, datetime, inspect

###############################
# Import ASN1 modules
###############################
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ

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
# Process GOOSE PDU by decoding it with PYASN1
###############################
def goose_pdu_decode(encoded_data):

    # Debugging on
    if DEBUG > 2: 
        from pyasn1 import debug
        debug.setLogger(debug.Debug('all'))

    g = IECGoosePDU().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )
    decoded_data, unprocessed_trail = decoder.decode(
        encoded_data,
        asn1Spec=g
    )
    # This should work, but not sure.
    return decoded_data

###############################
# Process packets and search for GOOSE
###############################
# devsrc = {src_mac:(dst_mac:goid)}
devsrc = {}
for p in packets:
    # Only process Goose Packets
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Grab the Goose PDU for processing
        gpdu = d[GOOSEPDU].original

        # Use PYASN1 to parse the Goose PDU
        gd = goose_pdu_decode(gpdu)

        # Grab Source address, destination address, and Goose ID
        src_mac = p['Ether'].src
        dst_mac = p['Ether'].dst
        goid    = str(gd['goID'])

        # Combine stNum and t as they are related
        devgoose = (dst_mac, goid)
        if src_mac in devsrc.keys():
            if devgoose not in devsrc[src_mac]:
                devsrc[src_mac].append(devgoose)
        else:
            devsrc[src_mac] = [devgoose]

###############################
# Print Statements and Functions
###############################
## Normal Print Statement
print('##################################################')
print('### Goose Source Interface Address and Destination Addresses with Goose ID')
print('##################################################')
indent = '    '
print('Goose Device Count: %s\n'%(len(devsrc.keys())))

print('Source Address,Destivation Address,goID')
for src_mac in devsrc.keys():
    #print('Source Device: %s'%(src_mac))

    # Print all as CSV
    for e in devsrc[src_mac]:
        # Each device should have a destination mac and a goID
        #print('%s%s : %s'%(indent,e[0],e[1]))
        print('%s,%s,%s'%(src_mac,e[0],e[1]))
