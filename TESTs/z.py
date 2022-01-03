import binascii
import pyDot11
from rc4 import rc4
from scapy.all import *

keyText = '0123456789'
pkts = rdpcap('../../PCAPs/ICMPs/wep_pings.pcap')
pkt = pkts[0]

pkt, iVal = pyDot11.wepDecrypt(pkt, keyText)


## encoder
wepICV = pyDot11.pt.endSwap(hex(crc32(binascii.unhexlify(hexstr(pkt[LLC], onlyhex = 1).replace(' ', ''))) & 0xffffffff))
stream = binascii.unhexlify(hexstr(pkt[LLC], onlyhex = 1).replace(' ', '')) + binascii.unhexlify(wepICV.replace('0x', ''))
