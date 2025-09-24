# ICMP C2 Server and Client Agent

## Project Description
This project implements a simple ICMP-based Command-and-Control (C2) framework for cybersecurity competitions and lab testing. It consists of two main components:

- **C2 Server**: Manages agent beacons, queues commands, and collects results.
- **Client Agent**: Beacons to the C2 server, executes commands, and returns output.

**Purpose:**  
Designed for educational and cybersecurity competition environments to test command-and-control techniques, covert communication, and remote command execution over ICMP.

**Key Features:**
- Multiple agent support
- Lazy pruning of inactive agents
- Reliable command queueing and result collection
- Sequence-based result ordering
---

## Table of Contents
- [Technologies Used](#technologies-used)
- [Installation Instructions](#installation-instructions)
- [Usage Instructions](#usage-instructions)
- [Authors and Acknowledgments](#authors-and-acknowledgments)

---

## Technologies Used
- **Python 3** – main programming language
- **Scapy** – for crafting and sniffing ICMP packets
- **Threading** – for concurrent server operations
- **Subprocess** – for executing shell commands on client agents
- **Standard Python libraries** – `os`, `time`, `random`, `string`

---

## Installation Instructions
1. Clone the repository:

    git clone https://github.com/miller-js/ICMP-Tunneler-C2/

  (or just download files as needed)

2. Ensure Python 3 is installed:

    python3 --version

3. Install required libraries:

    pip install scapy

4. Run the server and client in a lab or isolated VM environment (requires root privileges for raw socket access).

## Usage Instructions
Start the C2 Server:
sudo python3 server.py

Opens an operator console with commands:

  list – Show active agents
  task <agent_id> <command> – Queue a command for an agent
  results <agent_id> – View collected results from an agent
  exit – Stop the server

Start the Client Agent:
  sudo python3 client_agent.py

Beacons to the C2 server automatically.
Executes queued commands and returns results.

Example Workflow:
-Launch the server.
-Launch one or more agents on separate lab VMs.
-Use list to see active agents.
-Queue a command (with example agent id):

  task a1b2 whoami

-Retrieve results (with example agent id):

  results a1b2


Note: This project is designed for lab and educational purposes only. Running it in production networks may violate policies and laws.

## Authors

Author: Miller Swank
Contact: millerswank@gmail.com
LinkedIn: linkedin.com/in/miller-swank
GitHub: github.com/miller-js
