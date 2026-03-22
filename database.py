import sqlite3
from config import DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with open("schema.sql", "r") as f:
        schema = f.read()
    conn = get_connection()
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print("[DB] Database initialized.")


def log_alert(alert_type, severity, src_ip, dst_ip=None,
              src_port=None, dst_port=None, protocol=None, description=None):
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts (alert_type, severity, src_ip, dst_ip,
                            src_port, dst_port, protocol, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (alert_type, severity, src_ip, dst_ip,
          src_port, dst_port, protocol, description))
    conn.commit()
    conn.close()


def log_port_scan(src_ip, port):
    conn = get_connection()
    conn.execute("""
        INSERT INTO port_scan_log (src_ip, scanned_port)
        VALUES (?, ?)
    """, (src_ip, port))
    conn.commit()
    conn.close()


def update_traffic_summary(src_ip, byte_count):
    conn = get_connection()
    existing = conn.execute(
        "SELECT summary_id, packet_count, byte_count FROM traffic_summary WHERE src_ip = ?",
        (src_ip,)
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE traffic_summary
            SET packet_count = packet_count + 1,
                byte_count   = byte_count + ?,
                last_seen    = CURRENT_TIMESTAMP
            WHERE src_ip = ?
        """, (byte_count, src_ip))
    else:
        conn.execute("""
            INSERT INTO traffic_summary (src_ip, packet_count, byte_count)
            VALUES (?, 1, ?)
        """, (src_ip, byte_count))

    conn.commit()
    conn.close()


def get_traffic_summary(src_ip):
    conn = get_connection()
    row = conn.execute(
        "SELECT packet_count FROM traffic_summary WHERE src_ip = ?", (src_ip,)
    ).fetchone()
    conn.close()
    return row["packet_count"] if row else 0


def is_blacklisted(ip):
    conn = get_connection()
    row = conn.execute(
        "SELECT reason FROM blacklist WHERE ip_address = ?", (ip,)
    ).fetchone()
    conn.close()
    return row["reason"] if row else None


def get_recent_alerts(limit=50):
    conn = get_connection()
    cursor = conn.execute("""
        SELECT detected_at, alert_type, severity, src_ip, dst_ip, description
        FROM alerts
        ORDER BY detected_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_counts():
    conn = get_connection()
    rows = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """).fetchall()
    conn.close()
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        counts[r["severity"]] = r["count"]
    counts["TOTAL"] = sum(counts.values())
    return counts


def clear_alerts():
    """Delete all rows from the alerts table."""
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()