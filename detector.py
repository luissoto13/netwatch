from collections import defaultdict
from database import log_alert, log_port_scan, update_traffic_summary, get_traffic_summary, is_blacklisted
from config import PORT_SCAN_THRESHOLD, HIGH_VOLUME_THRESHOLD

# In-memory port tracker per source IP (resets when sniffer restarts)
port_tracker = defaultdict(set)


def analyze_packet(packet):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

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