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
# vlans = {'src':[],'dst':[],'prio':[]}
vlans = {}
for p in packets:
    # Only process Goose Packets
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Grab the Goose PDU for processing
        gpdu = d[GOOSEPDU].original

        # Use PYASN1 to parse the Goose PDU
        gd = goose_pdu_decode(gpdu)

        gocbRef = str(gd['gocbRef'])
        src_mac = p['Ether'].src
        dst_mac = p['Ether'].dst
        device = ('%s - %s'%(src_mac,gocbRef))
        # Not all Goose networks have VLANs
        if p.haslayer(Dot1Q):
            pvlan = p.vlan
            prio = p.prio
            if pvlan in vlans.keys():
                if device not in vlans[pvlan]['src']:
                    vlans[pvlan]['src'].append(device)
                if dst_mac not in vlans[pvlan]['dst']:
                    vlans[pvlan]['dst'].append(dst_mac)
                # Not sure if a VLAN's priority can change, so build a list, just in case
                if prio not in vlans[pvlan]['prio']:
                    vlans[pvlan]['prio'].append(prio)
            else:
                vlans[pvlan] = {'src':[device],'dst':[dst_mac],'prio':[prio]}

###############################
# Print Statements and Functions
###############################
## Normal Print Statement
if not vlans:
    print('\nERROR: Packets in PCAP did not contain VLAN layers')
    exit()

print('Goose VLANS by Device Hardware Address')
indent    = '    '
for vid in vlans.keys():
    # Print VLAN ID and all priorities. Prio is a list of integers, so convert
    print('VLAN ID: %s has Priorities: %s'%(vid,', '.join(map(str,vlans[vid]['prio']))))
    print('%sSource Devices:'%(indent))
    for s in vlans[vid]['src']:
        print('%s%s'%(indent*2,s))
    print('%sMulticast Addresses:'%(indent))
    for d in vlans[vid]['dst']:
        print('%s%s'%(indent*2,d))
