#!/usr/bin/python2.7

import binascii, hashlib, hmac, os, re, sys
from pbkdf2 import PBKDF2
from pyDot11 import *
from scapy.utils import rdpcap, hexstr, PcapWriter, wrpcap

from scapy.layers.dot11 import Dot11

if __name__ == '__main__':

    ## Work with pyDot11
    p = utils.Packet()
    ccmpCrypto = Ccmp()
    hs = Handshake()

    ## PCAP specific data
    ssid = 'wifi4'
    passphrase = 'P@$$w0rd1!P@$$w0rd1!'
    pcap = 'demo.pcap'
    pktStream = rdpcap(pcap)
    anoPkt = pktStream[0]
    snoPkt = pktStream[1]
    tgtPkt = pktStream[4]
    ap_mac = binascii.a2b_hex(re.sub(':', '', snoPkt[Dot11].addr1))
    s_mac = binascii.a2b_hex(re.sub(':', '', anoPkt[Dot11].addr1))
    anonce = binascii.a2b_hex(re.sub(' ', '', hexstr(anoPkt.load, onlyhex = 1)[39:134]))
    snonce = binascii.a2b_hex(re.sub(' ', '', hexstr(snoPkt.load, onlyhex = 1)[39:134]))
    pke = "Pairwise key expansion"
    pmk = PBKDF2(passphrase, ssid, 4096).read(32)
    objPMK = pmk.encode('hex')
    key_data = min(ap_mac, s_mac) + max(ap_mac, s_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = hs.xPRF512(pmk, pke, key_data)
    tk = ptk[32:48]
    if os.path.isfile('example.pcap'):
        os.remove('example.pcap')
    if os.path.isfile('inbound.pcap'):
        os.remove('inbound.pcap')

    ### pyDot11 usage
    origPkt, decryptedPkt, stream, PN = wpaDecrypt(tk, tgtPkt, 'ccmp')
    PN[5] += 1
    encryptedPkt = wpaEncrypt(tk, tgtPkt, decryptedPkt, decryptedPkt[LLC], PN)

    ## User output
    pktdump = PcapWriter('example.pcap', append = True, sync = True)
    pktdump.write(pktStream[0:4])
    pktdump.write(encryptedPkt)
    wrpcap('inbound.pcap', decryptedPkt)
    print ('\nCheck out example.pcap')
    print ('ESSID: wifi4')
    print ('PASSWORD: P@$$w0rd1!P@$$w0rd1!')
