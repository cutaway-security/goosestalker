###############################
# Import Python modules
###############################
import os, sys, datetime, inspect, struct, time
from copy import deepcopy

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
# Import Goose module
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
            #print('%s: %s'%(e,datetime.datetime.fromtimestamp(int.from_bytes(bytearray(data[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S')))
            print('%s: %s'%(e,timeStrFrom64bits(bytearray(data[e])[:4])))
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

def curTimeBytes():
    #if DEBUG: print('In curTimeBytes')
    curTime = int(time.time())
    curTimeBytes = struct.pack('>i',int(time.time()))
    return curTimeBytes

def curTime64Bits(utc=False):
    # Microsecond Resolution Ignored
    #if args.DEBUG: print('In curTimeBytes')
    # FIXME: Include designating local or UTC time.
    '''
    if utc:
        curTime = time.mktime(datetime.utcnow().timetuple())
    else:
        curTime = time.mktime(datetime.now().timetuple())
    '''

    curTime = time.mktime(datetime.datetime.utcnow().timetuple())
    curTimeInt = int(curTime)
    curTimeInt64 = (curTimeInt << 32)
    curTimeInt64Str = curTimeInt64.to_bytes(8,'big')
    return curTimeInt64Str

def timeStrFrom64bits(t):
    # Microsecond Resolution Ignored
    #if args.DEBUG: print('In timeToString')
    time32Int = int.from_bytes(t[:4],'big')
    time32Str = datetime.datetime.fromtimestamp(time32Int).strftime('%Y-%m-%d %H:%M:%S')
    return time32Str

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

        # Only process one packet
        break

###############################
# Modify Contents
###############################
tmpT = Data()
tmpF = Data()
tmpT.setComponentByName('boolean',True)
tmpF.setComponentByName('boolean',False)

# Get copy of packet and store the start and end of the payload
mod_p            = p.copy()
mod_p_load_start = mod_p.load[:8]
mod_p_load_end   = mod_p.load[-6:]

# Parse Goose Data
mod_d    = GOOSE(mod_p.load)
mod_gpdu = mod_d[GOOSEPDU].original
mod_gd   = goose_pdu_decode(mod_gpdu)

# Modify Goose Header
tmpSTNUM = mod_gd.getComponentByName('stNum')
tmpSQNUM = mod_gd.getComponentByName('sqNum')

# Toggle Boolean Values
for e in range(mod_gd['numDatSetEntries']):
    if mod_gd['allData'].getComponentByPosition(e) == False:
        mod_gd['allData'].setComponentByPosition(e,tmpT)
        continue
    elif mod_gd['allData'].getComponentByPosition(e) == True:
        mod_gd['allData'].setComponentByPosition(e,tmpF)
        continue

## Increment stNum
mod_gd.setComponentByName('stNum', (int(tmpSTNUM) + 1))
## Reset sqNum, note that we will need to increment this or increment stNum and keep this 0
mod_gd.setComponentByName('sqNum', 0)
new_time = curTime64Bits()
mod_gd.setComponentByName('t',new_time)


# Encode the modified data
en_gd = encoder.encode(mod_gd)
print('EN_GD: %s'%(en_gd))

# Rebuild the packet payload
mod_p.load = mod_p_load_start + en_gd + mod_p_load_end

###############################
# Show original packet
###############################
print('###############################')
print('Original Data')
print('###############################')
gooseASN1_DataPrint(gd)
print('\n\n###############')
print('Original Packet:')
print('###############')
p.show()

###############################
# Show update packet
###############################
print('###############################')
print('Updated Data')
print('###############################')
gooseASN1_DataPrint(mod_gd)
print('\n\n###############')
print('New Packet:')
print('###############')
mod_p.show()