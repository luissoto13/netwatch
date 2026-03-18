from scapy.all import sniff
from detector import analyze_packet
from config import INTERFACE


def start_sniffing():
    print(f"[SNIFFER] Starting packet capture on interface: {INTERFACE or 'all'}")
    print("[SNIFFER] Press Ctrl+C to stop.\n")
    sniff(
        iface=INTERFACE,
        prn=analyze_packet,
        store=False
    )