from typing import Annotated
import typer
from textual.app import App, ComposeResult
from textual.widgets import RichLog
from scapy.all import *

app = typer.Typer()


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


class PktforgeApp(App):
    """
    Terminal UI Application for pktforge.
    Provides an interactive dashboard for packet composition, hex inspection, and response analysis.
    """

    def compose(self) -> ComposeResult:
        """Construct the UI layout and define the widgets."""
        # self.left_bar = RichLog(id="static", markup=True)
        # yield self.left_bar
        pass

    def on_mount(self):
        """Initialize UI state when the app is fully mounted."""
        # self.left_bar.write("[green]Welcome to pktforge[/green]")
        pass


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

    print(response.summary())


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
    if name == "ping":
        pkt = IP(dst=target) / ICMP()

    elif name == "syn":
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

    print(response.summary())


@app.command()
def ui():
    """Launch the interactive terminal packet builder."""
    ui_app = PktforgeApp()
    ui_app.run()


if __name__ == "__main__":
    app()
