###############################
# Import Python modules
###############################
import os, sys, datetime, inspect

###############################
# Import SCAPY and ASN1 modules
###############################
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.compat import raw
from scapy.all import rdpcap

###############################
# Import Keith's Goose
###############################
# We have to tell script where to find the Goose module in parent directory
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

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
# Display contents
###############################
def gooseASN1_DataPrint(data):
    print('\n\n')
    for e in list(IECGoosePDU()):
        if not data[e].hasValue():
            continue
        if type(data[e]) == char.VisibleString:
            print('%s: %s'%(e,str(data[e])))
            continue
        if type(data[e]) == univ.Integer:
            print('%s: %s'%(e,int(data[e])))
            continue
        if type(data[e]) == UtcTime:
            print('%s: %s'%(e,datetime.datetime.fromtimestamp(int.from_bytes(bytearray(gd[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S')))
            continue
        if type(data[e]) == univ.Boolean:
            print('%s: %s'%(e,str(data[e])))
            continue
        if type(data[e]) == AllData:
            print('%s'%(e))
            for e in data.getComponentByName('allData'):
                for v in e.values():
                    print('    %s'%(v))
            continue
        if type(data[e]) == univ.OctetString:
            print('%s: %s'%(e,str(data[e])))
            continue

def gooseASN1_DataPrint_vendorA(data):
    print('\n\n')
    for e in list(IECGoosePDU()):
        if not gd[e].hasValue():
            continue
        if type(gd[e]) == char.VisibleString:
            print('%s: %s'%(e,str(gd[e])))
            continue
        if type(gd[e]) == univ.Integer:
            print('%s: %s'%(e,int(gd[e])))
            continue
        if type(gd[e]) == UtcTime:
            print('%s: %s'%(e,datetime.datetime.fromtimestamp(int.from_bytes(bytearray(gd[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S')))
            continue
        if type(gd[e]) == univ.Boolean:
            print('%s: %s'%(e,str(gd[e])))
            continue
        if type(gd[e]) == AllData:
            print('%s'%(e))
            tmpstr = []
            for e in gd.getComponentByName('allData'):
                for v in e.values():
                    tmpstr.append(str(v))
            # Some vendors send two values for each value. Value1) the actual value Value2) quality 
            # Join these into colon seperated values for readability
            for e in [': '.join(x) for x in zip(tmpstr[0::2],tmpstr[1::2])]:
                print('%s%s'%('    ',e))
            continue
        if type(gd[e]) == univ.OctetString:
            print('%s: %s'%(e,str(gd[e])))
            continue

###############################
# Process GOOSE PDU by decoding it
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
for p in packets:
    # Only process Goose Packets
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Grab the Goose PDU for processing
        gpdu = d[GOOSEPDU].original

        # Use PYASN1 to parse the Goose PDU
        gd = goose_pdu_decode(gpdu)

        if DEBUG: 
            print("Raw Load:\n%s\n\n"%d)
        if DEBUG > 1:
            print("Goose Length: %s\n"%d.length)
            print("Goose Load Length: %s\n"%len(d.load))
            print("GPDU:\n%s\n\n"%gpdu)

        ###############################
        # Print Statements and Functions
        ###############################
        ## Normal Print Statement
        #print("Decoded Data:\n%s\n\n"%gd)
        
        # ANS1 Print Function
        #gooseASN1_DataPrint_vendorA(gd)
        gooseASN1_DataPrint(gd)

        if DEBUG > 2: break