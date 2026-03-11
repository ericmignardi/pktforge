# pktforge 🔨

An interactive packet crafting and protocol analysis tool for your terminal. Build network packets layer-by-layer, send them, inspect responses, and decode protocol headers — all from the CLI or an interactive TUI.

---

## Features

- **Layer-by-Layer Packet Building**: Construct packets from scratch — IP, TCP/UDP/ICMP — with field-level control.
- **Send & Receive**: Transmit crafted packets and capture responses with decoded headers.
- **Hex Dump Viewer**: Real-time hexadecimal and ASCII representation of your packet as you build it.
- **Protocol Templates**: Pre-built packet recipes for common operations (ping, SYN, DNS query).
- **PCAP Support**: Save crafted packets to `.pcap` files and load them back for analysis.
- **Terminal UI**: Interactive dashboard with live hex preview, protocol selection, and background sending.

## Tech Stack

- **Python 3.12+**: Core language.
- **Scapy**: Packet crafting, sending, and raw socket manipulation.
- **Typer**: CLI application framework.
- **Textual / Rich**: Terminal User Interface (TUI) and styling.
- **uv**: Project and dependency management.

---

## Installation & Setup

**Prerequisites:**

- Python 3.12+
- `uv` installed (`pip install uv`)
- **Windows Users**: Must install [Npcap](https://npcap.com/) for raw socket support.
- **Admin Privileges**: Sending crafted packets requires Administrator/sudo privileges.

```bash
# Clone the repository
git clone https://github.com/ericmignardi/pktforge.git
cd pktforge

# Install dependencies and setup the virtual environment using uv
uv sync
```

## Usage

_Note: You must run your terminal as an Administrator._

### CLI Commands

**Craft & Send a Packet:**

```bash
# Send an ICMP ping
uv run main.py craft --target 8.8.8.8 --protocol icmp

# Send a TCP SYN to port 80
uv run main.py craft --target 8.8.8.8 --protocol tcp --dport 80 --flags S

# Send a UDP packet to port 53
uv run main.py craft --target 8.8.8.8 --protocol udp --dport 53
```

**Send a Pre-built Template:**

```bash
# Ping template
uv run main.py template ping --target 8.8.8.8

# TCP SYN template
uv run main.py template syn --target 8.8.8.8 --dport 443

# DNS query template
uv run main.py template dns --target 8.8.8.8
```

**Save & Load Packets:**

```bash
# Save a packet to a pcap file
uv run main.py save --filename packet.pcap --target 8.8.8.8 --protocol tcp --dport 80

# Load and inspect packets from a pcap file
uv run main.py load --filename packet.pcap
```

### Interactive TUI

**Launch the Interactive Packet Builder:**

```bash
uv run main.py ui
```

**TUI Keybindings:**

| Key | Action |
|-----|--------|
| `F5` | Send the current packet |
| `F2` | Clear all fields and logs |
| `q` | Quit the application |

The TUI provides three panels:
- **Left**: Protocol selector (ICMP/TCP/UDP)
- **Center**: Input fields for target IP, port, and TCP flags
- **Right**: Live hex dump preview that updates as you type

Below the panels is a response log that shows decoded packet layers after sending.

---

## Project Structure

```
pktforge/
├── main.py        # CLI commands (craft, template, save, load, ui)
├── ui.py          # Textual TUI application
├── pyproject.toml # Project config and dependencies
└── README.md
```

## Things Learned

Throughout the development of pktforge, several core systems and networking concepts were explored:

- **Protocol Header Anatomy**: Understanding byte-level structure of IP, TCP, UDP, and ICMP headers.
- **Packet Construction**: Building valid packets from raw fields and understanding how protocol layers encapsulate.
- **Binary Data Handling**: Working with hex representations, byte arrays, and bitwise operations.
- **Response Decoding**: Parsing multi-layer responses to extract meaningful protocol information.
- **CLI Architecture**: Designing a multi-command CLI with input validation using `typer`.
- **PCAP I/O**: Reading and writing packet captures for offline analysis.
- **TUI Development**: Building interactive, stateful terminal dashboards with reactive widgets using `textual`.
- **Background Workers**: Using async workers to prevent UI freezing during network operations.
