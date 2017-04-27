#!/usr/bin/python

import binascii
import socket
import argparse
import struct
import threading


# Packets
negotiate_protocol_request = binascii.unhexlify("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
session_setup_request = binascii.unhexlify("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
tree_connect_request = binascii.unhexlify("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
trans2_session_setup = binascii.unhexlify("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")

# Arguments
parser = argparse.ArgumentParser(description="Detect present of DOUBLEPULSAR SMB implant\n\nAuthor: Luke Jennings\nWebsite: https://countercept.com\nTwitter: @countercept", formatter_class=argparse.RawTextHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--ip', help='Single IP address to check')
group.add_argument('--file', help='File containing a list of IP addresses to check')
group.add_argument('--net', help='Network CIDR to check (requires python netaddr library)')
parser.add_argument('--timeout', help="Timeout on connection for socket in seconds", default=None)
parser.add_argument('--verbose', help="Verbose output for checking of commands", action='store_true')
parser.add_argument('--threads', help="Number of connection threads when checking file of IPs (default 10)", default="10")
parser.add_argument('--uninstall', help="Uninstall DOUBLEPULSAR if found", action='store_true')

args = parser.parse_args()
ip = args.ip
filename = args.file
net = args.net
timeout = args.timeout
verbose = args.verbose
num_threads = int(args.threads)
uninstall = args.uninstall
semaphore = threading.BoundedSemaphore(value=num_threads)
print_lock = threading.Lock()


# https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
def calculate_doublepulsar_xor_key(s):
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x


# The arch is adjacent to the XOR key in the SMB signature
def calculate_doublepulsar_arch(s):
    if s & 0xffffffff00000000 == 0:
        return "x86 (32-bit)"
    else:
        return "x64 (64-bit)"


def print_status(ip, message):
    global print_lock

    with print_lock:
        print "[*] [%s] %s" % (ip, message)


def check_ip(ip):
    global negotiate_protocol_request, session_setup_request, tree_connect_request, trans2_session_setup, timeout, verbose

    # Connect to socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout) if timeout else None)
    host = ip
    port = 445
    s.connect((host, port))

    # Send/receive negotiate protocol request
    if verbose:
        print_status(ip, "Sending negotiation protocol request")
    s.send(negotiate_protocol_request)
    s.recv(1024)

    # Send/receive session setup request
    if verbose:
        print_status(ip, "Sending session setup request")
    s.send(session_setup_request)
    session_setup_response = s.recv(1024)

    # Extract user ID from session setup response
    user_id = session_setup_response[32:34]
    if verbose:
        print_status(ip, "User ID = %s" % struct.unpack("<H", user_id)[0])

    # Replace user ID in tree connect request packet
    modified_tree_connect_request = list(tree_connect_request)
    modified_tree_connect_request[32] = user_id[0]
    modified_tree_connect_request[33] = user_id[1]
    modified_tree_connect_request = "".join(modified_tree_connect_request)

    # Send tree connect request
    if verbose:
        print_status(ip, "Sending tree connect")
    s.send(modified_tree_connect_request)
    tree_connect_response = s.recv(1024)

    # Extract tree ID from response
    tree_id = tree_connect_response[28:30]
    if verbose:
        print_status(ip, "Tree ID = %s" % struct.unpack("<H", tree_id)[0])

    # Replace tree ID and user ID in trans2 session setup packet
    modified_trans2_session_setup = list(trans2_session_setup)
    modified_trans2_session_setup[28] = tree_id[0]
    modified_trans2_session_setup[29] = tree_id[1]
    modified_trans2_session_setup[32] = user_id[0]
    modified_trans2_session_setup[33] = user_id[1]
    modified_trans2_session_setup = "".join(modified_trans2_session_setup)

    # Send trans2 sessions setup request
    if verbose:
        print_status(ip, "Sending trans2 session setup - ping command")
    s.send(modified_trans2_session_setup)
    final_response = s.recv(1024)

    # Check for 0x51 response to indicate DOUBLEPULSAR infection
    if final_response[34] == "\x51":
        signature = final_response[18:26]
        signature_long = struct.unpack('<Q', signature)[0]
        key = calculate_doublepulsar_xor_key(signature_long)
        arch = calculate_doublepulsar_arch(signature_long)
        with print_lock:
            print "[+] [%s] DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: %s, XOR Key: %s" % (ip, arch, hex(key))

        if uninstall:
            # Update MID and op code via timeout
            modified_trans2_session_setup = list(modified_trans2_session_setup)
            modified_trans2_session_setup[34] = "\x42"
            modified_trans2_session_setup[49] = "\x0e"
            modified_trans2_session_setup[50] = "\x69"
            modified_trans2_session_setup[51] = "\x00"
            modified_trans2_session_setup[52] = "\x00"
            modified_trans2_session_setup = "".join(modified_trans2_session_setup)

            if verbose:
                print_status(ip, "Sending trans2 session setup - uninstall/burn command")
            s.send(modified_trans2_session_setup)
            uninstall_response = s.recv(1024)
            if uninstall_response[34] == "\x52":
                with print_lock:
                    print "[+] [%s] DOUBLEPULSAR uninstall successful" % ip

    else:
        with print_lock:
            print "[-] [%s] No presence of DOUBLEPULSAR SMB implant" % ip

    s.close()


def threaded_check(ip_address):
    global semaphore

    try:
        check_ip(ip_address)
    except Exception as e:
        with print_lock:
            print "[ERROR] [%s] - %s" % (ip_address, e)
    finally:
        semaphore.release()

if ip:
    check_ip(ip)

elif filename:
    with open(filename, "r") as fp:
        for line in fp:
            semaphore.acquire()
            ip_address = line.strip()
            t = threading.Thread(target=threaded_check, args=(ip_address,))
            t.start()

elif net:
    from netaddr import IPNetwork
    network = IPNetwork(net)
    for addr in network:
        # Skip the network and broadcast addresses
        if (network.size != 1) and ((addr == network.network) or (addr == network.broadcast)):
            continue
        semaphore.acquire()
        ip_address = str(addr)
        t = threading.Thread(target=threaded_check, args=(ip_address,))
        t.start()
