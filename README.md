A python2 script for sweeping a list of IPs for the presence of the DOUBLEPULSAR SMB implant that was released by the Shadow Brokers. Supports both single IP checking and a list of IPs in a file with multi-threading support. 

This is a very early release in the interests of allowing people to find compromises on their network now that these exploits are in the wild and no doubt being used to target organizations. It re-implements the ping command of the implant, which can be used remotely without authentication, in order to determine if a system is infected or not.

Not all OS versions have been tested and some currently fail. For example, 2012 will reject the SMB sequence with ACCESS_DENIED. However, this system is not vulnerable to the ETERNALBLUE exploit and the DOUBLEPULSAR implant receives the same error when trying to ping a target. Therefore, it is possible that errors against certain windows versions may be indicative that the system is not compromised.

Simple example usage pre and post-exploit:

root@kali:~# python detect_doublepulsar.py --ip 192.168.175.128
[-] [192.168.175.128] No presence of DOUBLEPULSAR

root@kali:~# python detect_doublepulsar.py --ip 192.168.175.128
[+] [192.168.175.128] DOUBLEPULSAR DETECTED!!!
