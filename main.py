import ipaddress
from typing import Annotated
import typer
from scapy.all import *
from ui import PktforgeApp

app = typer.Typer()


# ==========================================
# DAY 1: Packet Engine (Craft, Templates, Hex Dump)
# ==========================================
def hexdump(data: bytes) -> None:
    """
    Print a formatted hex dump of raw bytes.
    Displays offset, hex values, and ASCII representation in 16-byte rows.
    """
    for i in range(0, len(data), 16):
        row = data[i : i + 16]

        offset = f"{i:04x}"

        hex_strings = [f"{b:02x}" for b in row]
        hex_string = " ".join(hex_strings)

        ascii_strings = [chr(b) if 32 <= b <= 126 else "." for b in row]
        ascii_string = "".join(ascii_strings)

        print(f"{offset}  {hex_string}  {ascii_string}")


# ==========================================
# DAY 2: Response Decoder & Validation
# ==========================================
def decode_response(response) -> None:
    """
    Decode and display a packet response layer-by-layer.
    Checks for IP, TCP, ICMP, UDP, and DNS layers and prints their key fields.
    """
    if response.haslayer(IP):
        src_ip = response[IP].src
        dst_ip = response[IP].dst
        ttl = response[IP].ttl

        print("  -- IP Layer --")
        print(f"  Source:      {src_ip}")
        print(f"  Destination: {dst_ip}")
        print(f"  TTL:         {ttl}")

    if response.haslayer(TCP):
        src_port = response[TCP].sport
        dst_port = response[TCP].dport
        tcp_flags = response[TCP].flags

        print("  -- TCP Layer --")
        print(f"  Src Port: {src_port}")
        print(f"  Dst Port: {dst_port}")
        print(f"  Flags:    {tcp_flags}")

    if response.haslayer(ICMP):
        icmp_type = response[ICMP].type
        icmp_code = response[ICMP].code
        icmp_id = response[ICMP].id
        icmp_seq = response[ICMP].seq

        print("  -- ICMP Layer --")
        print(f"  Type: {icmp_type}")
        print(f"  Code: {icmp_code}")
        print(f"  ID:   {icmp_id}")
        print(f"  Seq:  {icmp_seq}")

    if response.haslayer(UDP):
        src_port = response[UDP].sport
        dst_port = response[UDP].dport
        udp_len = response[UDP].len

        print("  -- UDP Layer --")
        print(f"  Src Port: {src_port}")
        print(f"  Dst Port: {dst_port}")
        print(f"  Length:   {udp_len}")

    if response.haslayer(DNS):
        queried_name = response[DNS].qd.qname.decode()
        answer_count = response[DNS].ancount
        resolved_ip = response[DNS].an.rdata if answer_count > 0 else "N/A"

        print("  -- DNS Layer --")
        print(f"  Queried Domain: {queried_name}")
        print(f"  Answers:        {answer_count}")
        print(f"  Resolved IP:    {resolved_ip}")


def validate_ip(target: str) -> bool:
    """Validate that a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        print(f"Invalid IP address: {target}")
        return False


def validate_port(dport: int | None) -> bool:
    """Validate that a port number is within the valid range (1-65535)."""
    if dport is not None and not (1 <= dport <= 65535):
        print(f"Port must be between 1 and 65535, got: {dport}")
        return False
    return True


# ==========================================
# DAY 3+4: Textual UI (Packet Builder)
# See ui.py for the interactive TUI application
# ==========================================
# ==========================================
# DAY 1: CLI Commands
# ==========================================
@app.command()
def craft(
    target: Annotated[str, typer.Option(help="The target IP address")],
    protocol: Annotated[str, typer.Option(help="The protocol to use (icmp, tcp, udp)")],
    dport: Annotated[int | None, typer.Option(help="The destination port")] = None,
    flags: Annotated[str | None, typer.Option(help="TCP flags (e.g. S, SA, F)")] = None,
):
    """
    Craft and send a custom network packet.
    Builds a packet from the specified protocol, optional port, and flags, then sends it and displays the response.
    """
    if not validate_ip(target):
        return

    if not validate_port(dport):
        return

    if protocol in ("tcp", "udp") and dport is None:
        print("Port is required for TCP and UDP protocols")
        return

    ip_layer = IP(dst=target)

    if protocol == "icmp":
        protocol_layer = ICMP()
    elif protocol == "tcp":
        protocol_layer = TCP(dport=dport, flags=flags)
    elif protocol == "udp":
        protocol_layer = UDP(dport=dport)
    else:
        print("Protocol must be icmp, tcp, or udp")
        return

    pkt = ip_layer / protocol_layer

    print(pkt.summary())
    hexdump(bytes(pkt))

    response = sr1(pkt, timeout=2, verbose=0)

    if response is None:
        print("No response received (timed out)")
        return

    decode_response(response)


@app.command()
def template(
    name: str,
    target: Annotated[str, typer.Option(help="The target IP address")],
    dport: Annotated[int | None, typer.Option(help="The destination port")] = None,
):
    """
    Send a pre-built packet template by name.
    Supports ping (ICMP), syn (TCP SYN), and dns (DNS query) templates for quick packet operations.
    """
    if not validate_ip(target):
        return

    if name == "ping":
        pkt = IP(dst=target) / ICMP()

    elif name == "syn":
        if dport is None:
            print("Port is required for the syn template")
            return
        if not validate_port(dport):
            return
        pkt = IP(dst=target) / TCP(dport=dport, flags="S")

    elif name == "dns":
        pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))

    else:
        print("Name must be either ping, syn, or dns")
        return

    response = sr1(pkt, timeout=2, verbose=0)

    if response is None:
        print("No response received (timed out)")
        return

    decode_response(response)


# ==========================================
# DAY 2: Save & Load (Pcap)
# ==========================================
@app.command()
def save(
    filename: Annotated[str, typer.Option(help="Output pcap filename")],
    target: Annotated[str, typer.Option(help="The target IP address")],
    protocol: Annotated[str, typer.Option(help="The protocol to use (icmp, tcp, udp)")],
    dport: Annotated[int | None, typer.Option(help="The destination port")] = None,
    flags: Annotated[str | None, typer.Option(help="TCP flags (e.g. S, SA, F)")] = None,
):
    """
    Build a packet and save it to a pcap file without sending.
    Useful for creating packet captures for later analysis or replay.
    """
    if not validate_ip(target):
        return

    ip_layer = IP(dst=target)

    if protocol == "icmp":
        protocol_layer = ICMP()
    elif protocol == "tcp":
        protocol_layer = TCP(dport=dport, flags=flags)
    elif protocol == "udp":
        protocol_layer = UDP(dport=dport)
    else:
        print("Protocol must be icmp, tcp, or udp")
        return

    pkt = ip_layer / protocol_layer

    wrpcap(filename, pkt)
    print(f"Packet saved to {filename}")
    hexdump(bytes(pkt))


@app.command()
def load(
    filename: Annotated[str, typer.Option(help="Path to the pcap file to load")],
):
    """
    Load packets from a pcap file and display their contents.
    Shows hex dump and decoded protocol layers for each packet in the file.
    """
    packets = rdpcap(filename)
    print(f"Loaded {len(packets)} packet(s) from {filename}\n")

    for i, pkt in enumerate(packets):
        print(f"--- Packet {i + 1} ---")
        hexdump(bytes(pkt))
        decode_response(pkt)
        print()


@app.command()
def ui():
    """Launch the interactive terminal packet builder."""
    ui_app = PktforgeApp()
    ui_app.run()


if __name__ == "__main__":
    app()
