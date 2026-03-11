import ipaddress
from textual.app import App, ComposeResult
from textual.widgets import (
    Input,
    RadioButton,
    RadioSet,
    RichLog,
    Footer,
    Header,
    Static,
)
from textual.containers import Horizontal, Vertical
from textual.binding import Binding
from textual import work
from scapy.all import IP, TCP, UDP, ICMP, DNS, sr1


# ==========================================
# DAY 3+4: Textual UI (Packet Builder)
# See ui.py for the interactive TUI application
# ==========================================
class PktforgeApp(App):
    """
    Terminal UI Application for pktforge.
    Provides an interactive dashboard for packet composition, hex inspection, and response analysis.
    """

    TITLE = "pktforge"

    CSS = """
        Screen {
            layout: vertical;
        }
        #main_area {
            height: 3fr;
        }
        #left_panel {
            width: 20;
            padding: 1;
            border: solid green;
        }
        #center_panel {
            width: 1fr;
            padding: 1;
            border: solid cyan;
        }
        #hex_preview {
            width: 2fr;
            border: solid yellow;
            padding: 0 1;
        }
        #response_log {
            height: 1fr;
            border: solid magenta;
            padding: 0 1;
        }
        Static.panel_title {
            text-style: bold;
            color: white;
            padding-bottom: 1;
        }
        Input {
            margin-bottom: 1;
        }
    """

    BINDINGS = [
        Binding("f5", "send_packet", "Send Packet"),
        Binding("f2", "clear_all", "Clear"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        """Construct the UI layout and define the widgets."""
        self.hex_preview = RichLog(id="hex_preview", markup=True)
        self.response_log = RichLog(id="response_log", markup=True)

        yield Header()
        with Horizontal(id="main_area"):
            with Vertical(id="left_panel"):
                yield Static("Protocol", classes="panel_title")
                yield RadioSet(
                    RadioButton("ICMP", value=True),
                    RadioButton("TCP"),
                    RadioButton("UDP"),
                    id="protocol_select",
                )
            with Vertical(id="center_panel"):
                yield Static("Packet Fields", classes="panel_title")
                yield Input(placeholder="Target IP (e.g. 8.8.8.8)", id="target")
                yield Input(placeholder="Port (e.g. 80)", id="port")
                yield Input(placeholder="Flags (e.g. S, SA, F)", id="flags")
            yield self.hex_preview
        yield self.response_log
        yield Footer()

    def on_mount(self):
        """Initialize UI state when the app is fully mounted."""
        self.response_log.write("[green]Welcome to pktforge![/green]")
        self.response_log.write("[dim]F5 = Send | F2 = Clear | q = Quit[/dim]")

    def get_selected_protocol(self) -> str:
        """Return the currently selected protocol name from the RadioSet."""
        radio_set = self.query_one("#protocol_select", RadioSet)
        protocols = ["icmp", "tcp", "udp"]
        return (
            protocols[radio_set.pressed_index]
            if radio_set.pressed_index >= 0
            else "icmp"
        )

    def build_packet(self):
        """Build a Scapy packet from the current input fields. Returns the packet or None."""
        target = self.query_one("#target", Input).value.strip()
        port = self.query_one("#port", Input).value.strip()
        flags = self.query_one("#flags", Input).value.strip()

        if not target:
            self.hex_preview.clear()
            return None

        try:
            ipaddress.ip_address(target)
        except ValueError:
            self.hex_preview.clear()
            self.hex_preview.write("[red]Invalid IP address[/red]")
            return None

        ip_layer = IP(dst=target)
        protocol = self.get_selected_protocol()

        if protocol == "icmp":
            pkt = ip_layer / ICMP()
        elif protocol == "tcp":
            dport = int(port) if port.isdigit() else 80
            tcp_flags = flags.upper() if flags else "S"
            pkt = ip_layer / TCP(dport=dport, flags=tcp_flags)
        elif protocol == "udp":
            dport = int(port) if port.isdigit() else 53
            pkt = ip_layer / UDP(dport=dport)
        else:
            return None

        return pkt

    def update_hex_preview(self, pkt):
        """Write a formatted hex dump of the packet to the hex preview panel."""
        self.hex_preview.clear()
        self.hex_preview.write("[bold yellow]-- Hex Dump --[/bold yellow]")

        raw = bytes(pkt)
        for i in range(0, len(raw), 16):
            row = raw[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in row)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
            self.hex_preview.write(
                f"[cyan]{i:04x}[/cyan]  {hex_str}  [dim]{ascii_str}[/dim]"
            )

    def decode_to_log(self, response):
        """Decode a response packet and write the decoded layers to the response log."""
        if response.haslayer(IP):
            self.response_log.write("[bold green]  -- IP Layer --[/bold green]")
            self.response_log.write(f"  Source:      {response[IP].src}")
            self.response_log.write(f"  Destination: {response[IP].dst}")
            self.response_log.write(f"  TTL:         {response[IP].ttl}")

        if response.haslayer(TCP):
            self.response_log.write("[bold cyan]  -- TCP Layer --[/bold cyan]")
            self.response_log.write(f"  Src Port: {response[TCP].sport}")
            self.response_log.write(f"  Dst Port: {response[TCP].dport}")
            self.response_log.write(f"  Flags:    {response[TCP].flags}")

        if response.haslayer(ICMP):
            self.response_log.write("[bold blue]  -- ICMP Layer --[/bold blue]")
            self.response_log.write(f"  Type: {response[ICMP].type}")
            self.response_log.write(f"  Code: {response[ICMP].code}")
            self.response_log.write(f"  ID:   {response[ICMP].id}")
            self.response_log.write(f"  Seq:  {response[ICMP].seq}")

        if response.haslayer(UDP):
            self.response_log.write("[bold yellow]  -- UDP Layer --[/bold yellow]")
            self.response_log.write(f"  Src Port: {response[UDP].sport}")
            self.response_log.write(f"  Dst Port: {response[UDP].dport}")
            self.response_log.write(f"  Length:   {response[UDP].len}")

        if response.haslayer(DNS):
            queried_name = response[DNS].qd.qname.decode()
            answer_count = response[DNS].ancount
            resolved_ip = response[DNS].an.rdata if answer_count > 0 else "N/A"
            self.response_log.write("[bold magenta]  -- DNS Layer --[/bold magenta]")
            self.response_log.write(f"  Queried Domain: {queried_name}")
            self.response_log.write(f"  Answers:        {answer_count}")
            self.response_log.write(f"  Resolved IP:    {resolved_ip}")

    def on_input_changed(self, event: Input.Changed):
        """Rebuild the packet preview whenever any input field changes."""
        pkt = self.build_packet()
        if pkt:
            self.update_hex_preview(pkt)

    def on_radio_set_changed(self, event: RadioSet.Changed):
        """Rebuild the packet preview when the protocol selection changes."""
        pkt = self.build_packet()
        if pkt:
            self.update_hex_preview(pkt)

    def action_send_packet(self):
        """Send the current packet when F5 is pressed. Runs in a background worker."""
        pkt = self.build_packet()
        if pkt is None:
            self.response_log.write("[red]Cannot send: invalid or missing fields[/red]")
            return

        self.response_log.write(f"\n[bold]Sending: {pkt.summary()}[/bold]")
        self._send_worker(pkt)

    @work(thread=True)
    def _send_worker(self, pkt):
        """Background worker that sends the packet and logs the response."""
        response = sr1(pkt, timeout=3, verbose=0)

        if response is None:
            self.app.call_from_thread(
                self.response_log.write, "[red]No response received (timed out)[/red]"
            )
        else:
            self.app.call_from_thread(
                self.response_log.write,
                f"[green]Response: {response.summary()}[/green]",
            )
            self.app.call_from_thread(self.decode_to_log, response)

    def action_clear_all(self):
        """Clear all input fields and logs when F2 is pressed."""
        self.query_one("#target", Input).value = ""
        self.query_one("#port", Input).value = ""
        self.query_one("#flags", Input).value = ""
        self.hex_preview.clear()
        self.response_log.clear()
        self.response_log.write("[green]Cleared. Ready for new packet.[/green]")
