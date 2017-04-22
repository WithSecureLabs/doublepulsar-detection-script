Author: Luke Jennings (luke.jennings@countercept.com - @jukelennings)

Company: Countercept (@countercept)

Website: https://countercept.com


A set of python2 scripts for sweeping a list of IPs for the presence of both SMB and RDP versions of the DOUBLEPULSAR implant that was released by the Shadow Brokers. Supports both single IP checking and a list of IPs in a file with multi-threading support. 

This is an early release in the interests of allowing people to find compromises on their network now that these exploits are in the wild and no doubt being used to target organizations. It re-implements the ping command of the implant, which can be used remotely without authentication, in order to determine if a system is infected or not. Both SMB and RDP versions of the implant are supported.

Not all OS versions have been tested and some currently fail. For example, 2012 will reject the SMB sequence with ACCESS_DENIED. However, this system is not vulnerable to the ETERNALBLUE exploit and the DOUBLEPULSAR implant receives the same error when trying to ping a target. Therefore, it is possible that errors against certain windows versions may be indicative that the system is not compromised.

Simple usage examples are given below:

root@kali:~# python detect_doublepulsar_smb.py --ip 192.168.175.128

[-] [192.168.175.128] No presence of DOUBLEPULSAR SMB implant


root@kali:~# python detect_doublepulsar_smb.py --ip 192.168.175.128

[+] [192.168.175.128] DOUBLEPULSAR SMB IMPLANT DETECTED!!!


root@kali:~# python detect_doublepulsar_rdp.py --file ips.list --verbose --threads 1

[*] [192.168.175.141] Sending negotiation request
[*] [192.168.175.141] Server explicitly refused SSL, reconnecting
[*] [192.168.175.141] Sending non-ssl negotiation request
[*] [192.168.175.141] Sending ping packet
[-] [192.168.175.141] No presence of DOUBLEPULSAR RDP implant
[*] [192.168.175.143] Sending negotiation request
[*] [192.168.175.143] Server chose to use SSL - negotiating SSL connection
[*] [192.168.175.143] Sending SSL client data
[*] [192.168.175.143] Sending ping packet
[-] [192.168.175.143] No presence of DOUBLEPULSAR RDP implant
[*] [192.168.175.142] Sending negotiation request
[*] [192.168.175.142] Sending client data
[*] [192.168.175.142] Sending ping packet
[+] [192.168.175.142] DOUBLEPULSAR RDP IMPLANT DETECTED!!!


This repository also contains three Snort signatures that can be used for detecting the use of the unimplemented SESSION_SETUP Trans2 command that the SMB ping utility uses and different response cases. While we do not condone the reliance on signatures for effective attack detection, due to how easily they are bypassed, these rules are highly specific and should provide some detection capability against new threat groups reusing these exploits and implants without modification.

For more information on this thinking, see the following article - https://www.countercept.com/our-thinking/missioncontrolasaurus/
