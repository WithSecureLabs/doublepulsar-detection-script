Author: Luke Jennings (luke.jennings@countercept.com - @jukelennings)

Company: Countercept (@countercept)

Website: https://countercept.com


A set of python2 scripts for sweeping a list of IPs for the presence of both SMB and RDP versions of the DOUBLEPULSAR implant that was released by the Shadow Brokers. Supports both single IP checking and a list of IPs in a file with multi-threading support. The SMB version also supports the remote uninstall of the implant for remediation, which was helped by knowledge of the opcode mechanism reversed by @zerosum0x0.  

This is an early release in the interests of allowing people to find compromises on their network now that these exploits are in the wild and no doubt being used to target organizations. It re-implements the ping command of the implant, which can be used remotely without authentication, in order to determine if a system is infected or not. Both SMB and RDP versions of the implant are supported.

Not all OS versions have been tested and some currently fail. For example, 2012 will reject the SMB sequence with ACCESS_DENIED. However, this system is not vulnerable to the ETERNALBLUE exploit and the DOUBLEPULSAR implant receives the same error when trying to ping a target. Therefore, it is possible that errors against certain windows versions may be indicative that the system is not compromised.

## Usage
```
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

root@kali:~# python2 detect_doublepulsar_smb.py --ip 192.168.175.136 --uninstall
[+] [192.168.175.136] DOUBLEPULSAR SMB IMPLANT DETECTED!!! XOR Key: 0x7c3bf3c1
[+] [192.168.175.136] DOUBLEPULSAR uninstall successful
```

## Scanning your network
```shell
# target network (adapt this to your network)
NETWORKRANGE=192.168.33.0/24
# install the required scanning tools
brew install masscan || apt-get install masscan
git clone https://github.com/countercept/doublepulsar-detection-script.git
cd doublepulsar-detection-script
# scan open ports
masscan -p445  $NETWORKRANGE > smb.lst
masscan -p3389 $NETWORKRANGE > rdp.lst
# clean the list of IPs
sed -i "s/^.* on //" smb.lst
sed -i "s/^.* on //" rdp.lst
# check vulnerabilities on the hosts who have the service open
python detect_doublepulsar_smb.py --file smb.lst
python detect_doublepulsar_rdp.py --file rdp.lst

# Or, if you have the python netaddr library
python detect_doublepulsar_smb.py --net 192.168.0.1/24
```

## Snort
This repository also contains three Snort signatures that can be used for detecting the use of the unimplemented SESSION_SETUP Trans2 command that the SMB ping utility uses and different response cases. While we do not condone the reliance on signatures for effective attack detection, due to how easily they are bypassed, these rules are highly specific and should provide some detection capability against new threat groups reusing these exploits and implants without modification.

## More info
https://www.countercept.com/our-thinking/analyzing-the-doublepulsar-kernel-dll-injection-technique/  
https://zerosum0x0.blogspot.co.uk/2017/04/doublepulsar-initial-smb-backdoor-ring.html  

