import binascii
import packetEssentials as PE
import re
from rc4 import rc4
# from rc4 import RC4
# from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11WEP, RadioTap
from scapy.all import *
# from scapy.layers.l2 import LLC
# from scapy.packet import Padding
# from scapy.utils import hexstr
from zlib import crc32

class Wep(object):
    """All things WEP related
    Only works proper in Python2x for the time being"""

    def __init__(self):
        self.pt = PE.pt


    def seedGen(self, iv, keyText):
        """Currently works with 40-bit and 104-bit"""
        keyLen = len(keyText)

        ## 40-bit
        if keyLen == 5:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 10:
            key = binascii.unhexlify(keyText)

        ## 104-bit
        elif keyLen == 13:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 26:
            key = binascii.unhexlify(keyText)

        return key


    def deBuilder(self, packet, stream, genFCS):
        """Take the pkt object and apply stream to [LLC]"""

        postPkt = RadioTap()/packet[RadioTap].payload

        ## Rip off the Dot11WEP layer
        del postPkt[Dot11WEP]

        ## Old way of hexstr
        newStream = []
        newStream.append(" ".join(map(lambda stream:"%02x"%ord(stream), stream)))
        newStream = "  ".join(newStream)

        ## Add the stream to LLC
        decodedPkt = postPkt/LLC(binascii.unhexlify(newStream.replace(' ', '')))

        ## Flip FCField bits accordingly
        if decodedPkt[Dot11].FCfield == 65:
            decodedPkt[Dot11].FCfield = 1
        elif decodedPkt[Dot11].FCfield == 66:
            decodedPkt[Dot11].FCfield = 2

        ## Create new FCS
        # del(decodedPkt[Dot11WEP].fcs)                                         ### Strange how this is no longer vis with curr packets
        return decodedPkt.__class__(binascii.unhexlify(hexstr(decodedPkt, onlyhex = 1).replace(' ', '')))


    def decoder(self, pkt, keyText):
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]"""
        iVal = pkt[Dot11WEP].iv.decode('latin1')
        seed = self.seedGen(iVal, keyText).decode('latin1')
        return rc4(pkt.wepdata.decode('latin1'), iVal + seed), iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        # wepICV = self.pt.endSwap(hex(crc32(str(pkt[LLC])) & 0xffffffff))
        wepICV = self.pt.endSwap(hex(crc32(binascii.unhexlify(hexstr(pkt[LLC], onlyhex = 1).replace(' ', ''))) & 0xffffffff))

        ## Concatenate ICV to the [LLC]
        # stream = str(pkt[LLC]) + binascii.unhexlify(wepICV.replace('0x', ''))
        stream = binascii.unhexlify(hexstr(pkt[LLC], onlyhex = 1).replace(' ', '')) + binascii.unhexlify(wepICV.replace('0x', ''))

        # iVal = pkt[Dot11WEP].iv.decode('latin1')
        # seed = self.seedGen(iVal, keyText).decode('latin1')
        # return rc4(pkt.wepdata.decode('latin1'), iVal + seed), iVal, seed


        ## Return the encrypted data
        # return rc4(stream, self.seedGen(iVal, keyText))
        newStream = []
        newStream.append(" ".join(map(lambda stream:"%02x"%ord(stream), stream)))
        newStream = "  ".join(newStream)
        # return rc4(newStream.decode('latin1'), self.seedGen(iVal, keyText))
        return rc4(stream.decode('latin1'), self.seedGen(iVal, keyText))


    def enBuilder(self, pkt, stream, iVal):

        ## Remove the LLC layer
        del pkt[LLC]

        ## Add the Dot11WEP layer
        encodedPacket = pkt/Dot11WEP(iv = iVal, keyid = 0, wepdata = stream)

        ## Flip FCField bits accordingly
        if encodedPacket[Dot11].FCfield == 1:
            encodedPacket[Dot11].FCfield = 65
        elif encodedPacket[Dot11].FCfield == 2:
            encodedPacket[Dot11].FCfield = 66


        ### Why is the FCS blown away to nothing at this point.


        ## Add the ICV
        bRip = self.pt.byteRip(encodedPacket[Dot11], chop = True, qty = 4, output = 'str')   ### GOT IT <<
        encodedPacket[Dot11WEP].icv = int(self.pt.fcsGen(bRip), 16)
        # encodedPacket[Dot11WEP].icv = int(self.pt.fcsGen(encodedPacket[Dot11], end = -2), 16)
        #print('ran -4?  Why are we doing ICV, again? ---> So our ICMP FCS is correct')
        return encodedPacket
