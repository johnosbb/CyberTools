# Proxies


Proxies are setup per application and do not use encrtption

- [Free Proxy List - Just Checked Proxy List](https://free-proxy-list.net)
- [Quick Java Firefox Addon](https://download.cnet.com/QuickJava/3000-11745_4-10746083.html)
- [Tor Guard](https://torguard.net/)
- [Largdo Proxy Test](https://www.lagado.com/tools/proxy-test)
- [IP Leak Testing](https://ipleak.net/)
- [Free Proxy Validation Site](http://ww1.proxyorca.com/)

Note: Free Proxies are likely to be highly suspect

Proxy Froms
- [anonymouse](anonymouse.org)
- [webproxy](www.webproxy.ca)
- [Hide My Ass](hidemyass.com)

Webproxies can be detected and are not anonymous if the target machine uses code to direct you out of the proxy.

## Tunneling out through Firewalls

- [corkscrew](https://github.com/bryanpkc/corkscrew)
- [proxytunnel](https://github.com/proxytunnel/proxytunnel)
- [httptunnel](https://github.com/larsbrinkhoff/httptunnel)
- [Super Network Tunnel - Commercial](http://www.networktunnel.net)
- [Cntlm Authentication Proxy](https://cntlm.sourceforge.net/)
- [Barba Tunnel - A layer that hide, redirect. forward, re-encrypt internet packet to keep VPN, Proxies and other p2p software hidden from Firewall.](https://github.com/BarbaTunnelCoder/BarbaTunnel)

## Detecting VPNS

Many providers or sites try to actively detect if you are coming through a VPN. They do this by probing the services on the port you came from. One can evade this by running multiple services on the same port.
A tool that can assist in this is : [sslh ](https://github.com/yrutschle/sslh)
Open VPN also has a port share command.
```sh
port 443
port-share 127.0.0.1 4443
proto tcp
```
with SSL server running on 4443


### Evading Detection
- [Port Knocking](https://wiki.archlinux.org/title/Port_knocking)
- [Archived Homepage of Port Knocking](https://web.archive.org/web/20180726181817/http://www.portknocking.org/)
- [Stunnel is an open-source multi-platform application used to provide a universal TLS/SSL tunneling service](https://www.stunnel.org/)
- [obfsproxy](https://www.makeuseof.com/what-is-obfsproxy/)
- [Psiphon](https://en.wikipedia.org/wiki/Psiphon)
- [DNS Tunneling](https://github.com/iagox86/dnscat2)


## Remote Desktop Options

- [Guacamole -  Apache Guacamole is a clientless remote desktop gateway](https://guacamole.apache.org/)
- [Reverse Shells Cheat Sheets](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
