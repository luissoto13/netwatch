# Network interface to sniff on
# Windows: use "Ethernet" or "Wi-Fi" — run `python -c "from scapy.all import get_if_list; print(get_if_list())"` to see options
# Linux/Mac: use "eth0", "wlan0", etc.
INTERFACE = None  # None = sniff on all interfaces

# Port scan detection threshold (unique ports per source IP)
PORT_SCAN_THRESHOLD = 10

# High volume detection threshold (packets per source IP per session)
HIGH_VOLUME_THRESHOLD = 500

# SQLite database file path
DB_PATH = "nids.db"

# Flask dashboard port
DASHBOARD_PORT = 5000