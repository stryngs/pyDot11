#!/usr/bin/python2

import binascii
import pyDot11
from rc4 import rc4
from scapy.all import *
# from rc4 import RC4

keyText = '0123456789'
pkts = rdpcap('../../../PCAPs/ICMPs/wep_pings.pcap')
pkt = pkts[0]

iVal = pkt[Dot11WEP].iv ## bytes, not str
# iVal = pkt[Dot11WEP].iv.decode('latin1') ## bytes, not str << Wrong translation

seed = pyDot11.wepCrypto.seedGen(iVal, keyText)

## Python2 ONLY
pload = pyDot11.pt.byteRip(pkt[Dot11WEP],
                           order = 'last',
                           qty = 4,
                           chop = True,
                           output = 'str')

stream = rc4(Dot11WEP(pload).wepdata, seed)

# cipher = RC4(iVal + seed, streaming = False)
# ciphertext = cipher.crypt(pkt.wepdata)

# stream = rc4(pkt.wepdata, iVal + seed)


pyDot11.wepCrypto.deBuilder(pkt, stream, False), iVal


## Good HERE


hexstr('\xaa\xaa\x03\x00\x00\x00\x08\x00E\x00\x00T\x00\x00@\x00@\x01\xf0;\xc0\xa8d\x88\xc0\xa8d\x94\x08\x00\x9de\xc7\x06\x00\x00\x9c\xd9\xf6\xb9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')




packet = pkt

postPkt = RadioTap(pyDot11.pt.byteRip(packet.copy(), chop = True, order = 'last', output = 'str', qty = 4))

## We want genFCS as False for now
postPktII = RadioTap()/postPkt[RadioTap].payload

del postPktII[Dot11WEP]

decodedPkt = postPktII/LLC(binascii.unhexlify(hexstr(stream, onlyhex = 1).replace(' ', '')))
decodedPkt[Dot11].FCfield = 1
