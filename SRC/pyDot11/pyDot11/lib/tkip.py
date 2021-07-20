from array import array
from rc4 import rc4
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP
from scapy.layers.l2 import LLC
from zlib import crc32
import binascii, re, struct, sys
import packetEssentials as PE

class Tkip(object):
    """All things TKIP related"""

    def __init__(self):
        self.pt = PE.pt

        ## TKIP auxiliary definitions
        self.sbox_table = [
            [
                0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
                0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
                0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
                0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
                0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
                0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
                0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
                0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
                0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
                0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
                0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
                0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
                0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
                0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
                0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
                0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
                0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
                0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
                0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
                0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
                0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
                0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
                0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
                0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
                0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
                0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
                0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
                0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
                0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
                0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
                0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
                0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
            ],
            [
                0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
                0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
                0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
                0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
                0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
                0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
                0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
                0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
                0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
                0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
                0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
                0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
                0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
                0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
                0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
                0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
                0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
                0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
                0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
                0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
                0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
                0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
                0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
                0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
                0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
                0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
                0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
                0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
                0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
                0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
                0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
                0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C
            ]
        ]


    ## TKIP auxiliary definitions
    def sbox(self, i):
        return self.sbox_table[0][i & 0xff] ^ self.sbox_table[1][(i >> 8)]

    def joinBytes(self, b1, b2):
        #print (b1 << 8) | b2
        return (b1 << 8) | b2

    def ushort(self, i):
        return i & 0x0000ffff

    def rotate(self, i):
        return ((i >> 1) & 0x7fff) | (i << 15)

    def upperByte(self, i):
        return (i >> 8) & 0xff

    def lowerByte(self, i):
        return i & 0xff

    def rc4(self, pload, key):
        i = long(0)
        j = long(0)
        data_size = len(key)

        for k in range(0, len(pload) - 8):
            i = (i + 1) % data_size
            j = (j + key[i]) % data_size
            key[i], key[j] = key[j], key[i]
            pload[k] = pload[k + 8] ^ key[(key[i] + key[j]) % data_size]
        return pload


    ## Here we must find if the packet has FCS. This isn't easy because this field isn't always in the same place.
    def hasFCS(self, pkt):

        ## These bits are relative to a single byte, not 4 bytes.
        TSFT = 1 << 0
        FCS  = 1 << 4
        Ext  = 1 << 7

        pktbytes = bytearray(str(pkt))

        ## If packet has TSFT we have to skip that field later on to find Flags
        hasTSFT = bool(pktbytes[4] & TSFT)

        ## Start seaching for Flags on byte 8
        i = 7
        hasExt = pktbytes[i] & Ext

        ## Skip extra present flags that may be present
        if hasExt:
            radiotap_len = pktbytes[2]
            while i < radiotap_len:
                hasExt = pktbytes[i] & Ext
                if not hasExt:
                    break
                i += 4
        else:
            i += 1

        ## Skip MAC timestamp
        if hasTSFT:
            i += 9

        ## Flags are here
        flags = pktbytes[i]

        if flags & FCS:
            #print 'Packet has FCS'
            return True
        else:
            #print 'Packet has NO FCS'
            return False

    def generateRC4Key(self, pload, addr, tk):
        rc4_key = bytearray(16)
        ppk = array("H") # unsigned ushort array
        data_size = 256

        ## Phase 1
        ppk.append(self.joinBytes(pload[4], pload[5]))
        ppk.append(self.joinBytes(pload[6], pload[7]))
        ppk.append(self.joinBytes(addr[1], addr[0]))
        ppk.append(self.joinBytes(addr[3], addr[2]))
        ppk.append(self.joinBytes(addr[5], addr[4]))

        for i in range(0,4):
            ppk[0] = self.ushort(ppk[0] + self.sbox(ppk[4] ^ self.joinBytes(tk[1], tk[0])))
            ppk[1] = self.ushort(ppk[1] + self.sbox(ppk[0] ^ self.joinBytes(tk[5], tk[4])))
            ppk[2] = self.ushort(ppk[2] + self.sbox(ppk[1] ^ self.joinBytes(tk[9], tk[8])))
            ppk[3] = self.ushort(ppk[3] + self.sbox(ppk[2] ^ self.joinBytes(tk[13], tk[12])))
            ppk[4] = self.ushort(ppk[4] + self.sbox(ppk[3] ^ self.joinBytes(tk[1], tk[0])) + 2*i)
            ppk[0] = self.ushort(ppk[0] + self.sbox(ppk[4] ^ self.joinBytes(tk[3], tk[2])))
            ppk[1] = self.ushort(ppk[1] + self.sbox(ppk[0] ^ self.joinBytes(tk[7], tk[6])))
            ppk[2] = self.ushort(ppk[2] + self.sbox(ppk[1] ^ self.joinBytes(tk[11], tk[10])))
            ppk[3] = self.ushort(ppk[3] + self.sbox(ppk[2] ^ self.joinBytes(tk[15], tk[14])))
            ppk[4] = self.ushort(ppk[4] + self.sbox(ppk[3] ^ self.joinBytes(tk[3], tk[2])) + 2*i + 1)

        ## Phase 2, step 1
        ppk.append(ppk[4] + self.joinBytes(pload[0], pload[2]))

        ## Phase 2, step 2
        ppk[0] = self.ushort(ppk[0] + self.sbox(ppk[5] ^ self.joinBytes(tk[1], tk[0])))
        ppk[1] = self.ushort(ppk[1] + self.sbox(ppk[0] ^ self.joinBytes(tk[3], tk[2])))
        ppk[2] = self.ushort(ppk[2] + self.sbox(ppk[1] ^ self.joinBytes(tk[5], tk[4])))
        ppk[3] = self.ushort(ppk[3] + self.sbox(ppk[2] ^ self.joinBytes(tk[7], tk[6])))
        ppk[4] = self.ushort(ppk[4] + self.sbox(ppk[3] ^ self.joinBytes(tk[9], tk[8])))
        ppk[5] = self.ushort(ppk[5] + self.sbox(ppk[4] ^ self.joinBytes(tk[11], tk[10])))

        ppk[0] = self.ushort(ppk[0] + self.rotate(ppk[5] ^ self.joinBytes(tk[13], tk[12])))
        ppk[1] = self.ushort(ppk[1] + self.rotate(ppk[0] ^ self.joinBytes(tk[15], tk[14])))
        ppk[2] = self.ushort(ppk[2] + self.rotate(ppk[1]))
        ppk[3] = self.ushort(ppk[3] + self.rotate(ppk[2]))
        ppk[4] = self.ushort(ppk[4] + self.rotate(ppk[3]))
        ppk[5] = self.ushort(ppk[5] + self.rotate(ppk[4]))

        ## DEBUG
        #print hex(ppk[0])
        #print hex(ppk[1])
        #print hex(ppk[2])
        #print hex(ppk[3])
        #print hex(ppk[4])
        #print hex(ppk[5])

        ## Phase 2, step 3
        rc4_key = bytearray(16)
        rc4_key[0] = self.upperByte(self.joinBytes(pload[0], pload[2]))
        rc4_key[1] = (rc4_key[0] | 0x20) & 0x7f
        rc4_key[2] = self.lowerByte(self.joinBytes(pload[0], pload[2]))
        rc4_key[3] = self.lowerByte((ppk[5] ^ self.joinBytes(tk[1], tk[0])) >> 1)
        rc4_key[4] = self.lowerByte(ppk[0])
        rc4_key[5] = self.upperByte(ppk[0])
        rc4_key[6] = self.lowerByte(ppk[1])
        rc4_key[7] = self.upperByte(ppk[1])
        rc4_key[8] = self.lowerByte(ppk[2])
        rc4_key[9] = self.upperByte(ppk[2])
        rc4_key[10] = self.lowerByte(ppk[3])
        rc4_key[11] = self.upperByte(ppk[3])
        rc4_key[12] = self.lowerByte(ppk[4])
        rc4_key[13] = self.upperByte(ppk[4])
        rc4_key[14] = self.lowerByte(ppk[5])
        rc4_key[15] = self.upperByte(ppk[5])

        ## DEBUG
        #for i in range(0,16):
            #print hex(rc4_key[i])

        data = bytearray(data_size)
        for i in range(0, data_size):
            data[i] = i

        j = long()
        k = 0
        for i in range(0, data_size):
            j = (j + data[i] + rc4_key[k]) % 256
            k += 1
            if k == len(rc4_key):
                k = 0
            (data[i],data[j]) = (data[j],data[i])

        ## DEBUG
        #for i in range(0,data_size):
            #print hex(data[i])

        return data


    def decoder(self, pkt, tk):
        """Decrypt the packet"""

        ## If the packet has FCS, it should be removed and added later on.
        if self.hasFCS(pkt):
            pload = self.pt.byteRip(pkt[Dot11WEP],
                                   order = 'last',
                                   qty = 4,
                                   chop = True,
                                   output = 'str')
        else:
            pload = str(pkt[Dot11WEP])

        ## The minimum valid TKIP packet has 21 bytes
        if(len(pload) <= 20):
            return

        ## Address required to calculate RC4 key
        addr = bytearray(re.sub(':','', pkt[Dot11].addr2).decode("hex"))
        #print bytearray(pload)
        #print addr
        #print tk
        key = self.generateRC4Key(bytearray(pload), addr, tk)

        ## Decrypt packet
        stream = self.rc4(bytearray(str(pload)), key)

        ## Check if decrypted CRC is correct. If it's not, ignore the packet.
        dlen = len(stream)
        crc = crc32(str(stream[:-12]))

        ### This is an issue, work it out later
        #if (stream[dlen - 12] != (crc & 0xff) or
            #stream[dlen - 11] != ((crc >> 8) & 0xff) or
            #stream[dlen - 10] != ((crc >> 16) & 0xff) or
            #stream[dlen - 9] != ((crc >> 24) & 0xff)):
            #return

        return stream


    def deBuilder(self, tgtPkt, decrypted):
        """Return the decrypted packet"""

        ## This is our encrypted data we need to remove
        eData = self.pt.byteRip(tgtPkt[Dot11WEP].wepdata,
                                qty = 4,
                                chop = True)

        ## This is our decrypted everything, LLC included
        dEverything = self.pt.byteRip(decrypted,
                                      qty = 16,
                                      order = 'last',
                                      chop = True)

        ## Prep the new pkt
        newPkt = tgtPkt.copy()
        del newPkt[Dot11WEP].wepdata

        ## Remove the last four bytes of new pkt and unhexlify
        postPkt = RadioTap((self.pt.byteRip(newPkt.copy(),
                                            chop = True,
                                            order = 'last',
                                            output = 'str',
                                            qty = 4)))

        ## The data is proper in here
        finalPkt = postPkt.copy()/LLC(binascii.unhexlify(dEverything.replace(' ', '')))

        ## Flip FCField bits accordingly
        if finalPkt[Dot11].FCfield == 65:
            finalPkt[Dot11].FCfield = 1
        elif finalPkt[Dot11].FCfield == 66:
            finalPkt[Dot11].FCfield = 2

        ## Calculate and append the FCS
        crcle = crc32(str(finalPkt[Dot11])) & 0xffffffff

        if sys.byteorder == "little":

            ## Convert to big endian
            crc = struct.pack('<L', crcle)
            ## Convert to long
            (fcsstr,) = struct.unpack('!L', crc)

        ### Need to research which NIC causes /Raw(fcs) to be needed
        #fcs = bytearray.fromhex('{:32x}'.format(fcsstr))
        #return finalPkt/Raw(fcs)
        return finalPkt
