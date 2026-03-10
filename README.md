# pktforge 🔨

An interactive packet crafting and protocol analysis tool for your terminal. Build network packets layer-by-layer, send them, inspect responses, and decode protocol headers — all from the CLI.

---

## Features

- **Layer-by-Layer Packet Building**: Construct packets from scratch — Ethernet, IP, TCP/UDP, and payload — with field-level control.
- **Send & Receive**: Transmit crafted packets and capture responses with decoded headers and latency.
- **Hex Dump Viewer**: Real-time hexadecimal and ASCII representation of your packet as you build it.
- **Protocol Templates**: Pre-built packet recipes for common operations (ping, SYN, DNS query, etc.).
- **Terminal UI**: Interactive dashboard for visual packet composition, hex inspection, and response analysis.

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
git clone https://github.com/yourusername/pktforge.git
cd pktforge

# Install dependencies and setup the virtual environment using uv
uv sync
```

## Usage

_Note: You must run your terminal as an Administrator._

**Craft & Send a Ping Packet:**

```bash
uv run main.py craft --target <ip_address>
```

**Send a Pre-built Template:**

```bash
uv run main.py template ping --target <ip_address>
```

**Launch the Interactive Packet Builder (Day 3+4):**

```bash
uv run main.py ui
```

---

## Things Learned

Throughout the development of pktforge, several core systems and networking concepts were explored:

- **Protocol Header Anatomy**: Understanding byte-level structure of Ethernet, IP, TCP, UDP, and ICMP headers.
- **Packet Construction**: Building valid packets from raw fields and understanding how protocol layers encapsulate.
- **Binary Data Handling**: Working with hex representations, byte arrays, and bitwise operations.
- **CLI Architecture**: Designing a multi-command CLI with validation using `typer`.
- **TUI Development**: Building interactive, stateful terminal dashboards with custom widgets using `textual`.
