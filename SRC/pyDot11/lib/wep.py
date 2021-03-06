import binascii
import packetEssentials as PE
import re
from rc4 import rc4
from scapy.layers.dot11 import Dot11, Dot11WEP, RadioTap
from scapy.layers.l2 import LLC
from scapy.packet import Padding
from scapy.utils import hexstr
from zlib import crc32

class Wep(object):
    """All things WEP related
    Only works proper in Python2x for the time being"""

    def __init__(self):
        self.pt = PE.pt


    def seedGen(self, iv, keyText):
        """Currently works with 40-bit and 104-bit"""
        # [b"\x15'\x00"] <<< iv -- This is str() in Python2x
        # <class 'bytes'>
        # b"\x15'\x00"
        # 1234567890  <<< keyText str()

        keyLen = len(keyText)
        """
        #iVal = pkt[Dot11WEP].iv
        iVal = re.search("b\'(.*)(?=(\'))", str(pkt[Dot11WEP].iv))[1]  ## Workaround for bytes problem...
        """

        ## 40-bit
        if keyLen == 5:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 10:
            key = binascii.unhexlify(keyText) ###HERE
            #key = re.search("b\'(.*)(?=(\'))", str(binascii.unhexlify(keyText)))[1]

        ## 104-bit
        elif keyLen == 13:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 26:
            key = binascii.unhexlify(keyText) ###HERE
            #key = re.search("b\'(.*)(?=(\'))", str(binascii.unhexlify(keyText)))[1]

        return iv + key


    def deBuilder(self, packet, stream, genFCS):
        """Take the pkt object and apply stream to [LLC]"""

        ## Remove the FCS from the old packet body
        postPkt = RadioTap(self.pt.byteRip(packet.copy(),
                                           chop = True,
                                           order = 'last',
                                           output = 'str',
                                           qty = 4))
        ## Remove RadioTap() info if required
        if genFCS is False:
            postPkt = RadioTap()/postPkt[RadioTap].payload

        ## Rip off the Dot11WEP layer
        del postPkt[Dot11WEP]

        ## Add the stream to LLC
        decodedPkt = postPkt/LLC(str(stream))

        ## Flip FCField bits accordingly
        if decodedPkt[Dot11].FCfield == 65:
            decodedPkt[Dot11].FCfield = 1
        elif decodedPkt[Dot11].FCfield == 66:
            decodedPkt[Dot11].FCfield = 2

        ## Return the decoded packet with or without FCS
        if genFCS is False:
            return decodedPkt
        else:
            return decodedPkt/Padding(load = binascii.unhexlify(self.pt.endSwap(hex(crc32(str(decodedPkt[Dot11])) & 0xffffffff)).replace('0x', '')))


    def decoder(self, pkt, keyText):
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]"""
        ## Re-use the IV for comparative purposes
        # <class 'bytes'>
        # b'z\x00\x00\x124Vx\x90'
        # print('DECODING')
        # print([pkt[Dot11WEP].iv])
        # print(str([pkt[Dot11WEP].iv]))
        # print(type(pkt[Dot11WEP].iv))

        #iVal = pkt[Dot11WEP].iv
        try:
            #iVal = re.search("b\'(.*)(?=(\'))", str(pkt[Dot11WEP].iv))[1]  ## Workaround for bytes problem...
            iVal = pkt[Dot11WEP].iv
        except Exception as E:
            print(E)

        # print(keyText)
        seed = self.seedGen(iVal, keyText)

        ## Remove the FCS so that we maintain packet size
        try:
            pload = self.pt.byteRip(pkt[Dot11WEP],
                                    order = 'last',
                                    qty = 4,
                                    chop = True,
                                    output = 'str')
        except Exception as E:
            print(E)

        ## Return the stream, iv and seed
        #print('\n\n\n')
        #print(type(pload))
        #print('\n')
        #print(pload)
        #print('\n\n\n')
        #print(type(seed))
        #print(seed)
        return rc4(Dot11WEP(pload).wepdata, seed), iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = self.pt.endSwap(hex(crc32(str(pkt[LLC])) & 0xffffffff))

        ## Concatenate ICV to the [LLC]
        stream = str(pkt[LLC]) + binascii.unhexlify(wepICV.replace('0x', ''))

        ## Return the encrypted data
        return rc4(stream, self.seedGen(iVal, keyText))


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
