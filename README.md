# CyberTools

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

# Isolation Strategies
## Portable Applications
* [Portable Apps](https://portableapps.com/)  and [Pendrive Apps](https://pendriveapps.com/)
## Isolations Silos
* [Authentic8](https://www.authentic8.com/)
* [Maxthon's Cloud Browser](https://www.maxthon.com/)


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
* [whonix](https://www.whonix.org) A whonix workstation connects directly to a thor based gateway and is isolated from a local LAN.
     * Anonymising Relay Monitor - ARM - similar to top on unix, but for Tor. Shows connections, configurations, etc
     * SDWdate - an anonomous time service used by whonix, also used by Tor, unlike NTP it preserves anonimity.
     * The whonix gateway can be used by other VMs and non-whonix workstations to provide secure access.

# Windows Package Managers
* [Chocolatey](https://github.com/chocolatey)
* 
