from scapy.utils import hexstr, PcapReader, PcapWriter, rdpcap, wrpcap
from scapy.plist import PacketList
from zlib import crc32
import binascii, pyDot11

class Pcap(object):
    """Class to deal with pcap specific tasks"""
    
    def crypt2plain(self, pcapFile, encType, key):
        """Converts an encrypted stream to unencrypted stream
        Returns the unencrypted stream input as a scapy PacketList object
        
        Future plans involve offering a yield parameter so that pcapList,
        instead returns as a generated object; should save memory this way.
        
        Does not have the capability to diff between multiple keys encTypes
        Possible workaround for this is taking the try and using except,
        creating a return to let the user know which objs to retry on
        For now, skipping.
        """
        
        ## Use the generator of PcapReader for memory purposes
        pObj = PcapReader(pcapFile)
        pcapList = []
        
        ## Deal with WEP
        if encType == 'WEP':
            for i in pObj:
                try:
                    pkt, iv = pyDot11.wepDecrypt(i, key)
                except:
                    pkt = i
                pcapList.append(pkt)
        
        ## Return the stream like a normal Scapy PacketList
        return PacketList(res = pcapList)
