from collections import defaultdict
from database import (
    log_alert, log_port_scan, update_traffic_summary, get_traffic_summary,
    is_blacklisted, get_cached_geo, cache_geo, log_arp, get_known_mac
)
from config import (
    PORT_SCAN_THRESHOLD, HIGH_VOLUME_THRESHOLD,
    ARP_DETECTION_ENABLED, SUSPICIOUS_COUNTRIES, GEOIP_DB_PATH
)

# In-memory port tracker per source IP (resets when sniffer restarts)
port_tracker = defaultdict(set)

# In-memory ARP table: ip -> first-seen MAC
arp_table = {}

# ── Geo-IP reader (loaded once) ──────────────────────────────
_geoip_reader = None

def _get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            import geoip2.database
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            print(f"[GEO] Loaded GeoIP database: {GEOIP_DB_PATH}")
        except FileNotFoundError:
            print(f"[GEO] GeoIP database not found at {GEOIP_DB_PATH} — geo lookups disabled")
            _geoip_reader = False  # False = tried and failed
        except Exception as e:
            print(f"[GEO] Could not load GeoIP database: {e}")
            _geoip_reader = False
    return _geoip_reader if _geoip_reader is not False else None


def lookup_geo(ip):
    """Look up geo info for an IP. Returns dict or None. Uses DB cache first."""
    # Skip private/reserved ranges
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.", "0.")):
        return None

    # Check cache first
    cached = get_cached_geo(ip)
    if cached:
        return cached

    reader = _get_geoip_reader()
    if not reader:
        return None

    try:
        resp = reader.city(ip)
        info = {
            "country_code": resp.country.iso_code,
            "country_name": resp.country.name or "Unknown",
            "city": resp.city.name or "Unknown",
            "latitude": resp.location.latitude,
            "longitude": resp.location.longitude,
        }
        cache_geo(ip, **info)
        return info
    except Exception:
        return None


def analyze_packet(packet):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP

        # ── ARP spoofing detection ────────────────────────────
        if ARP_DETECTION_ENABLED and packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:  # ARP reply (is-at)
                ip_addr = arp.psrc
                mac_addr = arp.hwsrc

                known_mac = arp_table.get(ip_addr)
                if known_mac is None:
                    # First time seeing this IP
                    arp_table[ip_addr] = mac_addr
                    log_arp(ip_addr, mac_addr)
                elif known_mac != mac_addr:
                    # MAC changed — possible ARP spoof
                    log_alert(
                        alert_type="ARP_SPOOF",
                        severity="HIGH",
                        src_ip=ip_addr,
                        protocol="ARP",
                        description=(
                            f"ARP spoofing detected: {ip_addr} changed from "
                            f"{known_mac} to {mac_addr}"
                        )
                    )
                    # Update to new MAC so we don't alert every packet
                    arp_table[ip_addr] = mac_addr
                    log_arp(ip_addr, mac_addr)

        if not packet.haslayer(IP):
            return

        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        pkt_len = len(packet)

        # Blacklist check
        reason = is_blacklisted(src_ip)
        if reason:
            log_alert(
                alert_type="BLACKLIST_HIT",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="IP",
                description=f"Connection from known bad IP: {reason}"
            )

        # Geo-IP lookup (runs once per unique IP, then cached)
        geo = lookup_geo(src_ip)
        if geo and SUSPICIOUS_COUNTRIES and geo["country_code"] in SUSPICIOUS_COUNTRIES:
            log_alert(
                alert_type="GEO_SUSPECT",
                severity="MEDIUM",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="IP",
                description=(
                    f"Connection from flagged country: "
                    f"{geo['country_name']} ({geo['country_code']}), "
                    f"{geo.get('city', 'Unknown')}"
                )
            )

        # Update traffic volume summary
        update_traffic_summary(src_ip, pkt_len)
        packet_count = get_traffic_summary(src_ip)

        # High volume detection
        if packet_count == HIGH_VOLUME_THRESHOLD:
            log_alert(
                alert_type="HIGH_VOLUME",
                severity="MEDIUM",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="IP",
                description=f"{src_ip} has sent {packet_count} packets this session"
            )

        # TCP port scan detection
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
            port_tracker[src_ip].add(dst_port)
            log_port_scan(src_ip, dst_port)

            if len(port_tracker[src_ip]) == PORT_SCAN_THRESHOLD:
                log_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    description=f"{src_ip} scanned {len(port_tracker[src_ip])} unique ports"
                )

        # UDP port scan detection
        if packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            src_port = packet[UDP].sport
            port_tracker[src_ip].add(dst_port)

            if len(port_tracker[src_ip]) == PORT_SCAN_THRESHOLD:
                log_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="UDP",
                    description=f"{src_ip} scanned {len(port_tracker[src_ip])} unique ports (UDP)"
                )

        # ICMP ping detection
        if packet.haslayer(ICMP):
            log_alert(
                alert_type="ICMP_PING",
                severity="LOW",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="ICMP",
                description=f"ICMP packet from {src_ip} to {dst_ip}"
            )

    except Exception as e:
        print(f"[DETECTOR ERROR] {e}")
