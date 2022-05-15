# Cyber Security and Cyber Security Tools and Strategies

<div align="center">
     <h3>A list of Internet Cyber Tools and Resources</h3>
     <a href="https://github.com/johnosbb/Automation/wiki">
         <img alt="Automation" src="https://github.com/johnosbb/CyberTools/blob/main/CyberSecurity.jpg"
         >
      </a>
</div>



# Reference Sites
* [Shodan](https://www.shodan.io/) - Internet Connected Devices
* [SSL Labs - Security Evaluation of Sites](https://www.ssllabs.com/ssltest/)
* [Moxie Marlinspike](https://moxie.org/2011/04/11/ssl-and-the-future-of-authenticity.html)
* [CVE Details](https://www.cvedetails.com/)
* [Crowd Strike](https://www.crowdstrike.com)
* [MXToolBox](https://mxtoolbox.com/) - Port scanning, DNS lookup, Analysis
* [NMAP Onlice](https://nmap.online/) - Port Scanning, Security Analysis
* [Cheat Sheet for NMAP](https://www.stationx.net/nmap-cheat-sheet/)
* [Shieldsup - Gibson Research](https://nmap.online/) - Port Scanning, general security auditing, password generation
* [Vunerability Scanning](https://www.qualys.com/free-trial/)
* [Hashes Database](https://github.com/AdeptusM/hashes)

# Routers and Firewalls
* [Router default passwords](https://www.routerpasswords.com/)
* [DD-WRT](https://dd-wrt.com/)
* [Firewall Builder- Front End for DD-WRT](http://fwbuilder.sourceforge.net/)
* [PC Engines for building custom firewall](https://pcengines.ch)
* [Smoothwall - runs on a dedicated PC](https://www.smoothwall.com/)
* [VYOS - Runs on a Linux PC](https://vyos.net/)


# Reporting Spam and Phishing Emails
* [Reporting Phishing - The Anti-Phishing Working Group at reportphishing@apwg.org: ](reportphishing@apwg.org)
* [Reporting Spam - see ReportFraud.ftc.go](ReportFraud.ftc.gov.)
* [To report Cyber Crime in the UK](https://www.actionfraud.police.uk/)
* [Latest information on emerging scams](https://scambusters.org/)

# Identity Theft
* [What To Know About Credit Freezes and Fraud Alerts](https://www.consumer.ftc.gov/articles/what-know-about-credit-freezes-and-fraud-alerts)

# Resources
* [Windows Virtual Machines](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
* [Linux Virtual Machines](https://www.osboxes.org/)
* [VMWare](https://marketplace.cloud.vmware.com/)

# Tools
* [Volatility - Forensic Memory Analysis](https://www.volatilityfoundation.org/)
* [Disable Win Tracking Tools](https://github.com/10se1ucgo/DisableWinTracking) and [The latest fork of the project](https://github.com/bitlog2/DisableWinTracking)
* [Tools for Changing your Mac Address on Windows](https://technitium.com/tmac/)
* Tools for Changing your Mac Address on Linux - sudo apt install macchanger
* [Windows Hash Extraction Tools - pwdump7](https://www.tarasco.org/security/pwdump_7/)
* [Hacking Tools Cheat Sheet](https://www.stationx.net/hacking-tools-cheat-sheet/)
* [Pen Testing Resources](https://pentest-tools.com/)
* [Email Privacy Tester](https://www.emailprivacytester.com/)
* [Windows Permissions Identifier](https://www.stationx.net/windows-permission-identifier)

## Port Scanning Tools
* [zenmap](https://nmap.org/zenmap/) - Cross platform Port Scanner


## Network Tools
### Arp Spoofing
* [Arp Spoofing](https://medium.com/@samphen92/address-resolution-protocol-poisoning-and-detection-using-cain-abel-and-xarp-bd9c6a42a5ab)
* [Caine and Able - now no longer supported](https://web.archive.org/web/20190603235413/http://www.oxid.it/cain.html)
* [EtterCap](https://www.ettercap-project.org/)
* [ArpSpoof](https://linux.die.net/man/8/arpspoof)
* [TuxCut -Arp Spoofing protection and denial of service](https://github.com/a-atalla/tuxcut)
* [NetCut - similar to TuxCut](https://arcai.com/tag/arp-spoof/)
* [SniffDet] (https://sourceforge.net/projects/sniffdet/)


### Network Monitoring Tools

#### wireshark
* [Wireshark](https://www.wireshark.org/)

![image](https://user-images.githubusercontent.com/12407183/147506418-b0a3b79e-de92-40bf-b424-fc7b2b0a7ed4.png)
![image](https://user-images.githubusercontent.com/12407183/147506446-07827911-2003-486a-a601-f5fc02909927.png)

#### T-Shark

* [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)

#### TCP-Dump

* [TCP Dump](https://www.tcpdump.org/)
* Capturing pcap files over SSH - ssh root@192.168.1.10 -- "tcpdump -w - -s 65535 'not port 22'" > capture.pcap
* Capturing pcap traffic live over SSH - ssh root@192.168.1.10 -- "tcpdump -U -s 65535 -w - 'not port 22'" | wireshark -k -i -

Ideally we need to run Wireshark on the Router. TCPDump is available on alot of routers
![image](https://user-images.githubusercontent.com/12407183/146830676-d5ef0ac1-ecce-447f-9bd1-f6030acd5872.png)
* tcpdump -U = no buffering
* tcpdump -D -- show available interfaces
* tcpdump -i eth0 -- snoop on Eth0
* tcpdump -i any -- snoop on all interfaces
* tcpdump -n -i any dst port 80 -- snoop on port 80, n shows IP addresses and Port numbers rather than domain names.
* tcpdump -n -i any port 554 -- snoop on port 554 for DNS traffic
* tcpdump -n -i any host 192.168.1.254 and not src net 192.168.1.0/24 -- find traffic connecting to 192.168.1.254 which is outside of this local IP range.
* tcpdump -n -i any -s 65535 -w mycapture.cap -- capture traffic of frames 65535 bytes to a file called mycapture.cap

#### Other Tools
* [Network Security Toolkit](https://www.networksecuritytoolkit.org/nst/index.html)
* [Network Miner](https://www.netresec.com/)
* [NetWorx](https://networx.en.lo4d.com/windows)

##### Burp Suite
* [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload)



##### Browser Integrity Checking
* [Panoptoclick](https://www.eff.org/deeplinks/2017/11/panopticlick-30)
* [Quick Java](https://github.com/maximelebreton/quick-javascript-switcher)


##### Browser Hardening
* [Firefox user.js](https://github.com/pyllyukko/user.js/)

##### Cleaners

* [BleachIt](https://www.bleachbit.org/)
* [Checking for resistant to Evercookies or Super Cookies](https://samy.pl/evercookie/)

## Anti Malware Tools and Encryption
* [McAfee Free Tools](https://www.mcafee.com/enterprise/en-us/downloads/free-tools.html)
* [Microsoft Baseline Security Analyser](https://www.microsoft.com/security/blog/2012/10/22/microsoft-free-security-tools-microsoft-baseline-security-analyzer/)
* [OpenVas](https://www.openvas.org/)
* [Nessus Essentials - Free version, formally Home Edition](https://www.tenable.com/products/nessus/nessus-essentials)




# Privacy

## Meta Search Engines

Cookies must be disabled for these to offer anonimity

* [Start Page](https://www.startpage.com/)
* [DuckDuckGo](https://duckduckgo.com/)
* [Disconnect Search](https://search.disconnect.me/)
* [YaCy- Locally installed Search Engine using P2P distributed search](https://yacy.net/)

## Google Activity
* [Google History and Activity Management](https://myactivity.google.com/)

### Secure Browsers
* [Comodo](www.comodo.com/home/browsers-toolbars/browser.php)
* [Thor](https://www.torproject.org/download/)

### Add Blockers and Anti Tracking
* [Ublock Origin](https://ublockorigin.com/)
* [Privacy Badger fro EFF](https://privacybadger.org/)
* [Policeman](https://github.com/futpib/policeman)

### Finger Printing
* [Random User Agent](https://chrome.google.com/webstore/detail/random-user-agent/einpaelgookohagofgnnkcfjbkkgepnp?hl=en)
* [iPleak exposure detection](https://ipleak.net/)
* [BrowserLeaks](https://browserleaks.com/) [See also - CanvasBlocker}(https://addons.mozilla.org/en-US/firefox/addon/canvasblocker/)


### Certificate Management and Integrity
* [RCC Route Certificate Scanner](https://www.softpedia.com/get/Security/Security-Related/RCC.shtml)

# Isolation Strategies
## Portable Applications
* [Portable Apps](https://portableapps.com/)  and [Pendrive Apps](https://pendriveapps.com/)
## Isolations Silos
* [Authentic8](https://www.authentic8.com/)
* [Maxthon's Cloud Browser](https://www.maxthon.com/)

# Firewalls
* Simpler firewalls are based on layers 3 or 4 to accept o reject traffic based on Port, Protocol and Address
* More complex firewalls work at the application layer to do DPI (Deep Packet Inspection), they can determine whether the traffic conforms to the profile set for a particular port. 
* Host based firewalls like Windows Firewall or Linux IP tables are found on computers.
* Egress filtering: - Blocking outgoing traffic. This can prevent malware from communicating back out to a command centre.
* [User Friendly Front End for Windows Firewall Control](https://binisoft.org/wfc)
* [GUFW - GUI for UFW and IP tables](http://gufw.org/)
* [Shorewall - GUI for UFW and IP tables](https://shorewall.org/)



## Network Isolation
* [Yersinia - VLAN Hoping](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Berrueta_Andres/BH_EU_05_Berrueta_Andres.pdf)
* Physical Isolation using seperate switches and routers

## Wireless Security
* The preferred configuration for home networks is WEPA-2 Personal with AES (CCMP) and a 256 bit pre-shared key.
![image](https://user-images.githubusercontent.com/12407183/145888110-12520a1d-7211-4022-a2d3-adfc32cde680.png)
* WPA2 Enterprise uses a radius server which avoids having one fixed key. WEPA2 with a fixed key is open to brute force attacks. The seeding of the encryption is based on the SSID of the network. Rainbow tables are constructed for common SSIDs.
* [WEPA2 Attacks - CowPatty - available in Kali](https://www.willhackforsushi.com/?page_id=50)
* [WEP Vulnerability](https://infosecwriteups.com/exploiting-wps-hack-a-wps-enabled-wifi-using-reaver-and-fake-authentication-7071b222a33b)
* [Evil Twin](https://en.wikipedia.org/wiki/Evil_twin_(wireless_networks))
* [Wifi Pinapple](https://shop.hak5.org/products/wifi-pineapple)

### Wifi Injection Tools
A USB adapter is required with one of the following chips sets:
* Atheros AR9271
* Ralink RT3070
* Ralink RT3522
* Realtek 8187L

The best adapters can be found on [Cyberprogrammers](https://www.cyberprogrammers.net/2015/09/best-usb-wireless-adapterscards.html)

#### Tools
* [Aircrack-ng](https://www.aircrack-ng.org/)
* [WEPA2 Attacks - CowPatty - available in Kali](https://www.willhackforsushi.com/?page_id=50
* [Reaver](https://www.kali.org/tools/reaver/)
* [Fern Wifi Cracker - Tool with GUI front End](https://github.com/savio-code/fern-wifi-cracker)


## BlueTooth Security
* [US Government Advice](https://www.govinfo.gov/content/pkg/GOVPUB-C13-c528fe2437b557e63cc73e6b431be093/pdf/GOVPUB-C13-c528fe2437b557e63cc73e6b431be093.pdf)

## Sandboxes
### Windows
* [BufferZone](https://bufferzonesecurity.com/)
* [ShadowDefender](https://www.shadowdefender.com/)
* [DeepFreeze kernal level driver, and deepfreeze cloud browser](https://www.fanonics.com)
* [Comodo](https://www.comodo.com/)
* [sandboxie](https://sandboxie-plus.com/) --- [See also  guide to setting up sandboxie](http://www.jimopi.net/PDFs/Word%20Pro%20-%20Sandboxie.pdf)

### Linux
* [Apparmor](https://gitlab.com/apparmor)
* [SanFox](https://igurublog.wordpress.com/downloads/script-sandfox/)
* [Sandboxing in Linux](https://www.opensourceforu.com/2016/07/many-approaches-sandboxing-linux/)
* [FireJail](https://firejail.wordpress.com/)

## Virtualization (free and opensource)
### Type 2
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [VMPlayer](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html)

### Type 1
* [Xenserver](https://xenproject.org/developers/teams/xen-hypervisor/)

### Hybrid
#### Linux
* [KVM](https://www.linux-kvm.org/page/Main_Page) - [See also, Virtual Machine Manager](https://virt-manager.org/)
* [OpenVZ](https://openvz.org/)
* [Linux Containers](https://linuxcontainers.org/)
* [Docker](https://www.docker.com/)

### Virtualization Risks
* [Venom](https://www.crowdstrike.com/blog/venom-vulnerability-details/)
* [White Rabbit VT-D attack](https://invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf)

### Virtual Machine Hardening
* Use a USB based network adapter to isolate from the host adapter.
* USe whole disk encryption on the host operating system to prevent logs, caches etc being used as an attack point from the host.
* Clear down swap space and caches after use
* Use Hypervisor encryption
* Disable all unnecessary functions like:
     * 3D accelerateion, serial ports, video acceleration, drag and drop/clipboard. 
     * If possible do not install VMWare tools and VirtualBox extensions.
     *  Do not redirect USB and disable the USB controller (USe a PS2 Mouse on the VM). 
     *  Enable PAE/NX.
     *  Consider live operating systems and if possible do not use persistent storage.
     *  Use snapshots for a clean machine on each new activity.
     *  Avoid hybernating or sleeping VMs - keys are stored in memory or the harddisk.

## Other Isolation Technologies
* Device Guard - Windows 10

# Operating Systems for Security and Privacy
## Whonix
### Strengths
* [whonix](https://www.whonix.org) A whonix workstation connects directly to a thor based gateway and is isolated from a local LAN.
     * Anonymising Relay Monitor - [ARM](https://github.com/katmagic/arm) - similar to top on unix, but for Tor. Command line application for monitoring Tor relays, providing real time status information such as the current configuration, bandwidth usage, message log, connections, etc.
     * SDWdate - an anonomous time service used by whonix, also used by Tor, unlike NTP it preserves anonimity.
     * The whonix gateway can be used by other VMs and non-whonix workstations to provide secure access.
### Weaknesses
* It is easy to identify if someone is using whonix.
* Whonix does not encrypt by default.
* It does not protect again rootkits etc.
* It does not protect against hardware compromise.
* It can be difficult set up requiring virtual machines or additional hardware.
* Unlike tails (and other amnesic operating systems) whonix can leaves traces on the hardware.


## Qubes
### Strengths
* Desktop OS based on xen hypervisor; it uses virtualisation for isolation between security domains.
* Qubes Templates allow the desktop to be comfigured liked popular operating systems.
* Unlike momolithic architectures (Trusted Components Base) were a lot of code runs with elevated privalleges, xen is a type 1 hypervisor and quebes runs a micro kernel on top of this. This provides distinct advantages by reducing the attack space.
* Dom0 controls the screen and desktop, but has no network access.
* Applications run in different VMs, but Dom0 presents this as a single desktop.
* There is a Net VM which takes care of all network activity. Even is the network VM is compromised the malicious code still cannot escalate privellege to reach other isolated components.
* USB can also be isolated in a VM.
* Each application can run in a seperate VM, so we could have a browser for banking and a browser for hacking, for example.
* Qubes has built in integration with Tor.


### Weaknesses
* It supports a limited range of hardware at the moment.- [see the Hardware Compatability List](https://www.qubes-os.org/hcl/)
*
     
### Security Domains and Isolation
* Consider isolating your activites into different domains, use a virtualised or sandboxed browser to surf the web to isolate routine activities from attack.


# Router Security
* Shodan is the world's first search engine for Internet-connected devices. [Shodan Web Site](https://www.shodan.io/)
     * We can use Shodan to search for vunerabilities, for example searching for 'Default Password' shows devices still using the default password and username.
     * It features an exploits database: [https://exploits.shodan.io/welcome](https://exploits.shodan.io/welcome)
     * We can search for an IP address using https://www.shodan.io/host/ followed by the ip address

# Security Frameworks
* [Wazuh](https://wazuh.com/)

# Disk and File Encryption

## File Encryption

- [Peazip](https://peazip.github.io/)
- [AES Crypt](https://www.aescrypt.com/)
- [GPG](https://gnupg.org/)


# SSH
* For Putty - ssh-keygen - generate public keys in a folder of your choosing
* Linux: ssh-copy-id -i /home/${USER}/.ssh/id_rsa.pub  <remote_user_name>@<remote_ip_address>
* [Generating SSH key-pairs on Windows](https://www.ibm.com/docs/en/flashsystem-9x00/8.3.x?topic=host-generating-ssh-key-pair-using-putty)
* [Copying SSH keys from Windows to target device](https://github.com/VijayS1/Scripts/tree/master/ssh-copy-id)
* OpenSSH, use ssh-keygen to create a public key called id_ras.pub, run the script below to install the key on the target: ssh-copy-id.bat username@192.168.1.10 password id_ras.pub

## Windows Example

Create a script called ssh-copy-id.cmd with the following content

```bash
::usage: ssh-copy-id test@example.com password [id_ras.pub]

::@echo off
IF "%~3"=="" GOTO setdefault
set /p id=<%3
GOTO checkparams
:setdefault
set /p id=<id_rsa.pub
:checkparams
IF "%~1"=="" GOTO promptp
IF "%~2"=="" GOTO promptp2

:exec
:: To accept the signature the first time
echo y | plink.exe %1 -pw %2 "exit"
:: now to actually copy the key
echo %id% | plink.exe %1 -pw %2 "umask 077; test -d .ssh || mkdir .ssh ; cat >> .ssh/authorized_keys"
GOTO end

:promptp
set /p user= "Enter username@remotehost.com: "
:promptp2
set /p pw= "Enter password: "
echo y | plink.exe %user% -pw %pw% "exit"
echo %id% | plink.exe %user% -pw %pw% "umask 077; test -d .ssh || mkdir .ssh ; cat >> .ssh/authorized_keys"
:end
pause
```

Example usage

## SSH Configuration on Windows

ssh-copy-id.cmd <target-username>@192.168.1.xxx <password> c:\Users\<windows-username>\.ssh\id_rsa.pub


## SSH Configuration on Ubuntu
* chmod go-w /home/user
* chmod 700 /home/user/.ssh
* chmod 600 /home/user/.ssh/authorized_keys

## Connecting with VSCode

```yaml
Host LinuxBox_191
    HostName 192.168.1.121
    User yourusername


Host RaspberryPI
    HostName 192.168.1.131
    User yourusername

```

# OAuth 2.0
* [Implementation in Nodejs](https://github.com/danba340/oauth-github-example) -- [Video Demo](https://www.youtube.com/watch?v=PdFdd4N6LtI)
* [oAuth and dropbox] (https://docs.runmyprocess.com/Integration_Guide/OAuth2/Dropbox/)


# Two Factor Authentication

## OTP - Soft Tokens
* [authy](https://authy.com/)
* [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en_IE&gl=US)

## Hard Tokens
* [yubico](https://www.yubico.com/products/?utm_source=google&utm_medium=pd:search&utm_campaign=EU_Multiple_B2C_LeadGen_Google_SEM_Brand&utm_content=&gclid=EAIaIQobChMI1rasr7Pf9QIVEoxoCR0ydw0_EAAYASAAEgKH8fD_BwE)


# Windows Package Managers
* [Chocolatey](https://github.com/chocolatey)


# Password Management

## Password Managers
* [Master Password - Stateless Password Generator, no password storage, smallest attack surface](https://js.masterpassword.app/)
* [Keypass - Local Password Storage](https://keepass.info/)
* [Keypass XC](https://keepassxc.org/)
* [LastPass - Cloud Based, largest attack surface](https://www.lastpass.com/)

## Hashing
* [Hash Generator](http://www.sha1-online.com/)
* [PBKDF2 - Password-Based Key Derivation Function, key derivation functions with a sliding computational cost, used to reduce vulnerabilities of brute-force attacks.](https://en.wikipedia.org/wiki/PBKDF2)
* [HashCat](https://hashcat.net/hashcat/)

A useful strategy for creating a hash that is resistant to brute force attacks is to use a salt, the us a derivation function to stretch and then finally encrypt with AES and a master password. A further extension of this method is to use a hardware security moduleto store the master password [HSM](https://en.wikipedia.org/wiki/Hardware_security_module)

It is also possible to additionally embed a key in the hash before encrypting.

## Password Cracking

* [PWDump7](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PwDump7.htm) [Youtube video](https://www.youtube.com/watch?v=A9ZNL3qtqAE)[Here also](https://www.youtube.com/watch?v=K-96JmC2AkE)

## Password Evaluation

* [Password Haystacks](https://www.grc.com/haystack.htm)

     
# End Point Protection - Anti Virus
- FUD, Fully undectable malware that has been obfiscated and encrypted.
- A lot of cheap or free anti virus products used basic signature analysis which cannot detect FUD based walware.
- Heuristic detection analyses code for suspicious patterns and structures. Heuristic techniques are used in mid-range products.
- More advanced products use sandboxes in addition to heuristics.
- Behaviour based blocking - AV onserves the software in action
- Cloud based analysis, uses the softwares integrity rating based on cloud assisted analysis of large numbers of users.
- [Kaspersky White Papers](https://www.kaspersky.com/enterprise-security/resources/white-papers)
     
# Software Restriction Policies
- On Windows: Local Group Policy Editor: security settings->security restriction policies - run gpedit.msc
- [White Paper on SRP](https://www.iad.gov/iad/library/reports/application-whitelisting-using-srp.cfm)
- [Microsoft SRP](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies#:~:text=Software%20Restriction%20Policies%20(SRP)%20is,of%20those%20programs%20to%20run.)
- [App Locker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)

## Anti Exploit Toolkits
- [EMET The Enhanced Mitigation Experience Toolkit (EMET) is a utility that helps prevent vulnerabilities in software from being successfully exploited.](https://support.microsoft.com/en-us/topic/emet-mitigations-guidelines-b529d543-2a81-7b5a-d529-84b30e1ecee0)
- [Hitman Pro](https://www.hitmanpro.com/en-us)

## Virtualization Based Containment

### Device Guard Windows 10     
-  [VBS] (https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
     
     
# Security Models and Access Control Models

- [AppArmour](https://apparmor.net/)
- [SELinux](http://www.selinuxproject.org/page/Main_Page)
- [GRSecurity - Commercial Grade](https://grsecurity.net/)     
- [PAX](https://pax.grsecurity.net/)
- [RSBAC](https://www.rsbac.org/)    
- [Tomoyo](https://tomoyo.osdn.jp/index.html.en)

## Secure Kernel Implementations   
     
- [Alpine](https://www.alpinelinux.org/)
     
# Cyber Security Training
- [PentestingLab](https://www.pentesterlab.com/pro)
     
     
# Deception Strategies

 Detection is key to Cyber Security    
     
## Honeypots
     
- [Canary Tokens from StationX](https://www.stationx.net/canarytokens/)
- [Open Canary](https://github.com/thinkst/opencanary)
- [Artillery Binary Defense](https://github.com/BinaryDefense/artillery)
- [Honey Drive](https://www.honeynet.org/tag/honeydrive/)
     
## Intrusion Detection Systems
     
NIDs HIDs Network and Host intrusion detection. These generally require a lot of setup, configuration and maintenance.

- [Snort](https://www.snort.org/)  
- [Suricata](https://suricata.io/)
- [OSSEC](https://www.ossec.net/)
- [OSQuery](https://osquery.io/)
- [Bricata , formerly Bro](https://bricata.com/)     
- [OpenWIPS-ng](https://openwips-ng.org)     
- [OSSEC](https://www.ossec.net/)
     
     
## Intrusion Prevention Systems
  
 - WIPS - wireless Intrusion Prevention Systems    
 - NBAS - Network Behaviour Analysis Systems 
     

## Network Threat Analysis Systems - These facilitate the practice of Network Security Monitoring, event driven analysis and foreinsic analysis.      
  
- [squil](https://bammv.github.io/sguil/index.html)  
- [xplico](https://www.xplico.org/)   
- [Network Miner](https://www.netresec.com/?page=NetworkMiner)
     
     
 ### Proxt Based Analysis
     
 - [ MITMProxy - Man in the Moddile Proxy](https://mitmproxy.org/)    
 - [Burp, Burp Suite](https://portswigger.net/burp)   
 - [OWASP](https://owasp.org/)    

## File Integrity Monitors

- [OSQuery](https://osquery.io/)    
- [OSSEC](https://www.ossec.net/)   
- [ADAudit for Windows](https://www.manageengine.com/products/active-directory-audit/index.html) 
- [AFick for Linux](http://afick.sourceforge.net/)
- [AIDE](https://aide.github.io/)
- [TripWire](https://www.tripwire.com/)     
     
     
 ## Process Monitoring Tools
 
- [Eljefe - The Boss](https://www.immunityinc.com/products/eljefe/)
     
# Deep Fakes

## AI librarys for Deep Fake Images and Video
### Open Source
* [Deep Face Lab](https://github.com/iperov/DeepFaceLab)
* [Face Swap](https://faceswap.dev/download/)

## Commercial
* [Synthesia](https://www.synthesia.io/)

     
## For Audio
- [Real-Time Voice Cloning](https://github.com/CorentinJ/Real-Time-Voice-Cloning)

## Audio and Video
- [Neural Voice Puppetry](https://github.com/keetsky/NeuralVoicePuppetry)     

     
## AI generation
- [Dall E- Text to Art](https://openai.com/blog/dall-e/)
     
     
     
## Fact Checking Organisations

* APF Fact Check—factcheck.afp.com
* AP Fact—apnews.com/APFactCheck
* BBC Reality Check—bbc.co.uk/news/reality_check
* FullFact—fullfact.org
* Politfact—politifact.com
* Snopes—snopes.com


## Media provenance

* Content Authenticity Initiative (Adobe)—contentauthenticity.org
* Digimac—digimap.edina.ac.uk
* News Provenance Project—newsprovenanceproject.com
* Pressland—pressland.com

## Disinformation detection and protection

* Amped—ampedsoftware.com
* AI Foundation—aifoundation.com
* Bellingcat—bellingcat.com
* DARPA—darpa.mil
* EUvsDisinfo—euvsdisinfo.eu
* The Citizen Lab at the University of Toronto—citizenlab.ca
* DeepTrace—deeptracelabs.com
* Jigsaw—jigsaw.google.com
* NewsGuard—newsguardtech.com
* Truepic—truepic.com

## Social-media analysis

* Botswatch—botswatch.io
* Dataminr—dataminr.com
* Graphika—graphika.com
* Storyful—storyful.com

Best practice (media)

* Duke Reporters’ Lab—reporterslab.org
* Credibility Coalition—credibilitycoalition.org
* First Draft News—firstdraftnews.org
* News Literacy Project—newslit.org
* News Integrity Initiative, Newmark School of Journalism, The City University of New York—journalism.cuny.edu/centers/tow-knight-center-entrepreneurial-journalism/news-integrity-initiative/
* Nieman Lab, Harvard University—niemanlab.org
* Partnership on AI—partnershiponai.org
* Reuters Institute—reutersinstitute.politics.ox.ac.uk

## Policy/society

* Access Now—accessnow.org
* Alliance for Securing Democracy—securingdemocracy.gmfus.org
* Anti-Defamation League—adl.org
* Center for Humane Technology—humanetech.com/problem/
* Center for Media Engagement, Moody College of Communication, University of Texas at Austin—mediaengagement.org/
* Cyber Policy Center, Stanford University—cyber.fsi.stanford.edu
* Data and Society, Disinformation Action Lab—datasociety.net/research/disinformation-action-lab/
* DeepTrust Alliance—deeptrustalliance.org
* Digital Forensics Research Lab and DisinfoPortal, Atlantic Council—atlanticcouncil.org/programs/digital-forensic-research-lab/
* Electronic Frontier Foundation—eff.org
* Information Disorder Lab, Shorenstein Centre, Harvard University—shorensteincenter.org/about-us/areas-of-focus/misinformation/
* Internet Observatory, Stanford University—cyber.fsi.stanford.edu/io/content/io-landing-page-2
* OpenAI—openai.com
* PEN America—pen.org
* Partnership on AI—partnernshiponai.org
* The Truthiness Collaboration, Annenberg Innovation Lab, University of Southern California—annenberglab.com
* Wikimedia—wikimedia.org
* WITNESS—witness.org

