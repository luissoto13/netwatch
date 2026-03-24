# Network interface to sniff on
# Windows: use "Ethernet" or "Wi-Fi" — run `python -c "from scapy.all import get_if_list; print(get_if_list())"` to see options
# Linux/Mac: use "eth0", "wlan0", etc.
INTERFACE = None  # None = sniff on all interfaces

# Port scan detection threshold (unique ports per source IP)
PORT_SCAN_THRESHOLD = 10

# High volume detection threshold (packets per source IP per session)
HIGH_VOLUME_THRESHOLD = 500

# ARP spoofing detection — set to True to enable
ARP_DETECTION_ENABLED = True

# Geo-IP: flag connections from these country codes as suspicious (ISO 3166-1 alpha-2)
# Leave empty to disable country-based alerting; geo info is still logged either way
SUSPICIOUS_COUNTRIES = []  # e.g. ["RU", "CN", "KP", "IR"]

# Path to MaxMind GeoLite2-City database (.mmdb)
# Download free from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# SQLite database file path
DB_PATH = "nids.db"

# Flask dashboard port
DASHBOARD_PORT = 5000
