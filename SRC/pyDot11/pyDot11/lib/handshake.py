from Cryptodome.Cipher import AES
# from lib.ccmp import Ccmp
# from lib.tkip import Tkip
# from lib.nic import Tap
from pbkdf2 import PBKDF2
from scapy.layers.dot11 import Dot11
from scapy.packet import Raw
from scapy.utils import hexstr, PcapWriter, wrpcap
import binascii, hashlib, hmac, logging, os, re, sys
import sqlite3 as lite
import packetEssentials as PE

class Handshake(object):
    """Deal with any type of EAPOL traffic"""

    def __init__(self, psk = None, essid = None, pcap = False):
        self.pt = PE.pt
        if psk is not None and essid is not None:
            if os.path.isfile('handshakes.sqlite'):
                os.remove('handshakes.sqlite')
            self.con = lite.connect('handshakes.sqlite')
            self.con.text_factory = str
            self.db = self.con.cursor()
            self.tgtInfo = {}
            self.availTgts = set()
            self.catchDict = {}
            self.encDict = {}
            self.alert = set()
            self.pke = 'Pairwise key expansion'
            self.pmk = PBKDF2(psk, essid, 4096).read(32)
            self.db.execute('CREATE TABLE IF NOT EXISTS\
                                "shakes"("pkt" TEXT,\
                                         "vmac" TEXT,\
                                         "bmac" TEXT,\
                                         "nonce" TEXT,\
                                         "e_num" TEXT,\
                                         UNIQUE(vmac, bmac, e_num));')
            self.con.commit()
            if pcap is True:
                self.eapolTrack = PcapWriter('eapols.pcap', sync = True)
                self.pcap = pcap
            else:
                self.eapolTrack = None
                self.pcap = None


    def eapolGrab(self, pkt):
        """Insert an EAPOL pkt into the DB for retrieval later

        A bug was found at BSides Charleston, thus the try statement.
        As no logs exist on this level, we are now hunting this bug.
        If you receive the warning, please pass along to ICSec.  Thanks!
        """
        try:
            eNum = self.pt.nonceDict.get(self.pt.byteRip(pkt[Raw], qty = 3)[6:])

        ## Deal with bug if seen again
        ##File "/usr/local/lib/python2.7/dist-packages/pyDot11/lib/handshake.py", line 49, in eapolGrab
            ##eNum = self.pt.nonceDict.get(self.pt.byteRip(pkt[Raw], qty = 3)[6:])
        ##File "/usr/lib/python2.7/dist-packages/scapy/packet.py", line 817, in __getitem__
            ##raise IndexError("Layer [%s] not found" % lname)
        ##IndexError: Layer [Raw] not found
        except:
            wrpcap('IndexError.pcap', pkt)
            print ('\n***** Unknown encryption type              *****')
            print ('***** Contact ICSec on github for assistance *****')
            print ('***** Bad frame saved to IndexError.pcap     *****')
            return

        ### Lazy workaround for eNum == None
        try:
            if eNum[1] == '1' or eNum[1] == '2' or eNum[1] == '3':
                nonce = hexstr(str(pkt.load), onlyhex = 1)[39:134]
                hexPkt = hexstr(str(pkt), onlyhex = 1)

                ### Discard EAPOL 4 of 4
                if nonce != '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00':
                    vMAC = ''

                    ## Store EAPOLs if requested
                    if self.pcap is True:
                        self.eapolTrack.write(pkt)

                    ## FROM-DS
                    if eNum == 'a1' or eNum == 'a3' or eNum == 't1' or eNum == 't3':
                        vMAC = pkt[Dot11].addr1
                        bMAC = pkt[Dot11].addr2
                        self.eapolStore(hexPkt, vMAC, bMAC, nonce, eNum)

                    ## TO-DS
                    if eNum == 'a2' or eNum == 't2':
                        vMAC = pkt[Dot11].addr2
                        bMAC = pkt[Dot11].addr1
                        encType = self.pt.byteRip(pkt[Raw], qty = 3)[3:]
                        if encType == '01 0a':
                            encType = 'ccmp'
                        elif encType == '01 09':
                            encType = 'tkip'
                        else:
                            wrpcap('encType.pcap', pkt)
                            print ('\n***** Unknown encryption type                *****')
                            print ('***** Contact ICSec on github for assistance *****')
                            print ('***** Bad frame saved to encType.pcap        *****')
                            return
                        self.encDict.update({vMAC: encType})
                        self.eapolStore(hexPkt, vMAC, bMAC, nonce, eNum)

                    ## DEBUG
                    # print ('stored {0} -- {1}'.format(str(eNum), str(nonce)))

                    ## Begin catchDict checks
                    ## Need to deal with clearing out existing entries
                    ## Currently, this isn't done, so we might have good anonce, but bad snonce

                    ## Deal with vMAC not in catchDict
                    if vMAC not in self.catchDict:
                        if eNum[1] == '1':
                            anonce = True
                            snonce = False

                        elif eNum[1] == '2':
                            anonce = False
                            snonce = True

                        elif eNum[1] == '3':
                            anonce = True
                            snonce = False
                        self.catchDict.update({vMAC: (anonce, snonce)})
                        print ('EAPOL STARTED: {0}'.format(str(vMAC)))

                    ## Deal with vMAC in catchDict
                    else:

                        ## Grab current anonce/snonce status
                        storedAnonce, storedSnonce = self.catchDict.get(vMAC)

                        ## Decide how to update
                        if eNum[1] == '1':
                            anonce = True
                            snonce = False

                        elif eNum[1] == '2':
                            anonce = False
                            snonce = True

                        elif eNum[1] == '3':
                            anonce = True
                            snonce = False

                        ## Deal with anonce
                        if anonce:
                            self.catchDict.update({vMAC: (True, storedSnonce)})
                        if snonce:
                            self.catchDict.update({vMAC: (storedAnonce, True)})

                    ## DEBUG
                    # print ('Our catchDict:\n{0}\n'.format(str(self.catchDict)))

                    ## Check for anonce and snonce for the given vMAC
                    if self.catchDict.get(vMAC)[0] is True and self.catchDict.get(vMAC)[1] is True:

                        ## Grab anonce, vbin, bbin and bssid
                        q = self.db.execute('SELECT `vmac`, `bmac`, `nonce` FROM `shakes` WHERE vMAC = "{0}" AND `e_num` LIKE "%1" or `e_num` LIKE "%3" LIMIT 1;'.format(vMAC))
                        r = q.fetchone()

                        ## Grab snonce
                        q2 = self.db.execute('SELECT `nonce` FROM `shakes` WHERE vMAC = "{0}" AND `e_num` LIKE "%2";'.format(vMAC))
                        r2 = q.fetchone()

                        ## Gather tgt specific data
                        authMac = binascii.a2b_hex(r[0].replace(':', ''))
                        supMac = binascii.a2b_hex(r[1].replace(':', ''))
                        aNonce = binascii.a2b_hex(r[2].replace(' ', ''))
                        sNonce = binascii.a2b_hex(r2[0].replace(' ', ''))
                        key_data = min(authMac, supMac) + max(authMac, supMac) + min(aNonce, sNonce) + max(aNonce, sNonce)

                        ### Pull the encryption type and generate PTK
                        encType = self.encDict.get(vMAC)
                        ptk = self.xPRF512(self.pmk, self.pke, key_data)[32:48]

                        ### Once RC4 is dealt with, change back to simple dict
                        ## CCMP cipher generation
                        if encType == 'ccmp':
                            aesCipher = AES.new(str(ptk), AES.MODE_ECB)
                            self.tgtInfo.update({vMAC: (ptk, aesCipher)})

                        ## TKIP
                        ### Until we deal with RC4 handling this at the lib level
                        ### Must regen new just like with WEP so that it doesn't cycle through
                        else:
                            self.tgtInfo.update({vMAC: (ptk, None)})

                        ## Add vMAC to list of available targets
                        self.availTgts.add(vMAC)

                        ## Let user know success
                        if vMAC not in self.alert:
                            print ('EAPOL COMPLETE: %s\n'.format(str(vMAC)))
                            self.alert.add(vMAC)
        except:
            print ('eNum for EAPOL is NULL\n')


    def eapolStore(self, hexPkt, vMAC, bMAC, nonce, eNum):
        """Store the EAPOL info to the DB"""
        self.db.execute('INSERT OR REPLACE INTO\
                            "{0}"\
                        VALUES(?,\
                                ?,\
                                ?,\
                                ?,\
                                ?);'.format('shakes'),\
                                (hexPkt,\
                                vMAC,\
                                bMAC,\
                                nonce,\
                                eNum))
        self.con.commit()


    def xPRF512(self, key, A, B):
        blen = 160
        i = 0
        R = ''
        while i <= ((blen * 8 + 159) / 160):
            hmacsha1 = hmac.new(key, A + chr(0x00) + B + chr(i), hashlib.sha1)
            i += 1
            R = R + hmacsha1.hexdigest()
        return bytearray(R[:blen].decode("hex"))
