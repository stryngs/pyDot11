import binascii
import pyDot11
from rc4 import rc4
from scapy.all import *
# from rc4 import RC4

keyText = '0123456789'
pkts = rdpcap('../PCAPs/ICMPs/wep_pings.pcap')
pkt = pkts[0]

iVal = pkt[Dot11WEP].iv.decode('latin1')  ## bytes, not str
seed = pyDot11.wepCrypto.seedGen(iVal, keyText).decode('latin1')
stream = rc4(pkt.wepdata.decode('latin1'), iVal+ seed)

## python3to2HEXSTR!
newStream = []
newStream.append(" ".join(map(lambda stream:"%02x"%ord(stream), stream)))
newStream = "  ".join(newStream)

## We want genFCS as False for now
postPktII = RadioTap()/pkt[RadioTap].payload

del postPktII[Dot11WEP]

decodedPkt = postPktII/LLC(binascii.unhexlify(newStream.replace(' ', '')))

## Flip FCField bits accordingly
if decodedPkt[Dot11].FCfield == 65:
    decodedPkt[Dot11].FCfield = 1
elif decodedPkt[Dot11].FCfield == 66:
    decodedPkt[Dot11].FCfield = 2

## Oddball and no longer seeing FCS for pings, this packet might be considered legacy?
del(decodedPkt[Dot11FCS].fcs)

## The packet looks like it should and is fully decrypted
patience = decodedPkt.__class__(binascii.unhexlify(hexstr(decodedPkt, onlyhex = 1).replace(' ', '')))


## ENcoding
wepICV = pyDot11.pt.endSwap(hex(crc32(binascii.unhexlify(hexstr(patience[LLC], onlyhex = 1).replace(' ', ''))) & 0xffffffff))
stream = binascii.unhexlify(hexstr(decodedPkt[LLC], onlyhex = 1).replace(' ', '')) + binascii.unhexlify(wepICV.replace('0x', ''))
