# pyDot11

## Growing pains
pyDot11 is currently undergoing the shift from Python2 over to Python3.  This will take time.

## pyDot11 currently supports the following using a combination of Python2 and Python3:
* Decryption of WEP
* Encryption of WEP
* Decryption of WPA
   * TKIP
   * CCMP
* Encryption of WPA</br>
   * CCMP

### Prerequisites:
packetEssentials-1.2.0
pbkdf2-1.3
pycryptodomex-3.4.5
rc4-0.1
scapy 2.4.0

<br><br>

### Setup:

In the RESOURCEs folder you will find the python modules which have been tested.  As newer versions of the modules come out, sufficient testing must be done before they can be made known as "stable" with pyDot11.  Feel free to use pip or whatever method you would like to get these installed.  If you wish to use the modules locally provided with this git, then an installation would be something like so:
````bash
pip install RESOURCEs/packetEssentials-1.4.4.tar.gz
pip install RESOURCEs/pbkdf2-1.3.tar.gz
pip install RESOURCEs/pyDot11-2.1.0.tar.gz
pip install RESOURCEs/pycryptodomex-3.4.5.tar.gz
pip install RESOURCEs/rc4-0.2.tar.gz
pip install RESOURCEs/scapy-2.4.0.tar.gz

## If you run into issues with the scapy module not being found
## Try this local folder workaround
tar zxf RESOURCEs/scapy-2.4.3rc1.dev128.tar.gz
mv scapy-2.4.0/scapy/ .
rm -rf scapy-2.4.0/
````
<br><br>

### Verification tests:
````bash
WEP Live Sniff:
python pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wep



WPA Example: python pyDot11 -i wlan0mon -p <password> -b <tgt BSSID> -t wpa -e <tgt ESSID>
    ## OR ##
WEP Example: python pyDot11 -f <your-pcap> -p <password> -b <tgt BSSID> -t wep
WPA Example: python pyDot11 -f <your-pcap> -p <password> -b <tgt BSSID> -t wpa -e <tgt ESSID>
    ## OR ##
# Install RESOURCEs/pyDot11-2.1.0.tar.gz, then you can:
   from pyDot11 import *
# Avail Modules and where they came from:
    pcap = Pcap()
    pt = utils.Packet()
    wepCrypto = Wep()
    ccmpCrypto = Ccmp()
    tkipCrypto = Tkip()
````
### Need help grabbing an EAPOL?
````bash
## From the pyDot11 folder run the following:
python scripts/airpunt --help
````
### Various examples of other things you can do with pyDot11:
<strong>We can <a href="https://github.com/ICSec/airpwn-ng">airpwn-ng!</href></strong>
````python
## Example of grabbing an encrypted ICMP echo-request, decrypting it, and then replaying it:
from pyDot11 import *
from scapy.utils import rdpcap
encPkts = rdpcap('PCAPs/ICMPs/wep_pings.pcap')
encPkts[1].summary()
decPkt, iVal = wepDecrypt(encPkts[1], keyText='0123456789')
decPkt.summary()
encPkt = wepEncrypt(decPkt, '0123456789', iVal)
encPkt.summary()
encPkt
encPkts[1]

## At one point during development, I thought it created an exact copy.
## Will chew on and debug this later.
#encPkt == encPkts[1]
````

````python
## Example of taking a packet from Open Wifi, and then encrypting it:
from pyDot11 import *
from scapy.utils import rdpcap
openPkts = rdpcap('PCAPs/ICMPs/open_pings.pcap')
openPkts[1].summary()
# input = openPkts[1].__class__(str(openPkts[1])[0:-4])
encPkt = wepEncrypt(openPkts[1], '0123456789')
encPkt.summary()
````

````python
## Example of decrypting a WEP pcap file:
from pyDot11 import *
from scapy.utils import PcapWriter
decList = pcap.crypt2plain('PCAPs/ICMPs/wep_pings.pcap', 'WEP', '0123456789')
decPcap = PcapWriter('decrypted_pings.pcap', sync = True)
for i in decList:
  decPcap.write(i)
````
