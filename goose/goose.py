from struct import pack

from scapy.packet import Packet
from scapy.fields import XShortField, XByteField, ConditionalField
from scapy.all import bind_layers

# TODO: It might be useful to move from PYASN1 to SCAPY ASN. Need to investigate.
#       Until then, GoosePDU parsing is handled in goose_pdu.py

class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [
        XShortField("appid", 0),
        XShortField("length", 8),
        XShortField("reserved1", 0),
        XShortField("reserved2", 0),
    ]

    def post_build(self, packet, payload):
        goose_pdu_length = len(packet) + len(payload)
        packet = packet[:2] + pack('!H', goose_pdu_length) + packet[4:]
        return packet + payload

class GOOSEPDU(Packet):
    name = "GOOSEPDU"
    fields_desc = [
        XByteField("ID",0x61),
        XByteField("DefLen",0x81),
         # NOTE: Length comes from this byte's Least Significant Nibble. Not sure what MSN is for.
        ConditionalField(XByteField("PDU1ByteLen",0x00),lambda pkt:pkt.DefLen^0x80 == 1), 
        ConditionalField(XShortField("PDU2BytesLen",0x0000),lambda pkt:pkt.DefLen^0x80 == 2)
    ]

bind_layers(GOOSE, GOOSEPDU)