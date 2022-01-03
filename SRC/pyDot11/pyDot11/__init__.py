# Copyright (C) 2016 stryngs

from rc4 import rc4
from scapy.layers.dot11 import Dot11, Dot11WEP, RadioTap
from scapy.layers.l2 import LLC
from scapy.packet import Raw
from zlib import crc32
from .lib.ccmp import Ccmp
from .lib.handshake import Handshake
from .lib.nic import Tap
from .lib.tkip import Tkip
from .lib.utils import Pcap
from .lib import utils
from .lib.wep import Wep
import binascii
import packetEssentials as PE

def wepDecrypt(pkt, keyText, genFCS = True):
    """Encompasses the steps needed to decrypt a WEP packet
    By default will generate a packet with an FCS
    """
    stream, iVal, seed = wepCrypto.decoder(pkt, keyText) ### Solved at this pt
    ## Return the decrypted packet and iv
    return wepCrypto.deBuilder(pkt, stream, genFCS), iVal


def wepEncrypt(pkt, keyText, iVal = '\xba0\x0e'):
    """Encompasses the steps needed to encrypt a WEP packet
    iVal represents a known good IV for default usage
    """

    ## Encode the LLC layer via rc4
    stream = wepCrypto.encoder(pkt, iVal, keyText)

    ## Return the encrypted packet
    return wepCrypto.enBuilder(pkt, stream, iVal)


def wpaDecrypt(encKey, origPkt, eType, genFCS = True):
    """Encompasses the steps needed to decrypt a WPA packet
    The PN will have to be stored so it's pointable to a
    specific MAC and packet instance, otherwise we might overflow
    """
    if eType == 'ccmp':
        stream, PN = ccmpCrypto.decoder(origPkt, encKey)
        decodedPkt = ccmpCrypto.deBuilder(origPkt, stream, genFCS)

    ### Need to pregen tkip key
    else:
        stream = tkipCrypto.decoder(origPkt, encKey)
        decodedPkt = tkipCrypto.deBuilder(origPkt, stream)
        PN = None
    return decodedPkt, PN

def wpaEncrypt(encKey, origPkt, decodedPkt, PN, genFCS = True):
    """Encompasses the steps needed to encrypt a WPA packet
    No structure for TKIP has been done as of yet
    """

    ## Increment the PN positively per IEEE spec
    PN[5] += 1

    ## Grab the payload of the decoded packet
    dEverything = decodedPkt[LLC]

    ## Remove the FCS from the original packet
    newPkt = RadioTap((pt.byteRip(origPkt.copy(),
                                  chop = True,
                                  order = 'last',
                                  output = 'str',
                                  qty = 4)))
    del newPkt[Dot11WEP]

    ## The data is ready for encryption
    newPkt = newPkt/dEverything
    encodedPkt = ccmpCrypto.encryptCCMP(newPkt, encKey, PN, genFCS)

    ## Flip FCField bits accordingly
    if encodedPkt[Dot11].FCfield == 1:
        encodedPkt[Dot11].FCfield = 65
    elif encodedPkt[Dot11].FCfield == 2:
        encodedPkt[Dot11].FCfield = 66

    return encodedPkt

### Instantiations
pcap = Pcap()
pt = PE.pt
wepCrypto = Wep()
ccmpCrypto = Ccmp()
tkipCrypto = Tkip()
