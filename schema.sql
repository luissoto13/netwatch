-- Stores every flagged alert event
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type      TEXT NOT NULL,
    severity        TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH')) NOT NULL,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    description     TEXT
);

-- Tracks running packet counts per source IP for volume analysis
CREATE TABLE IF NOT EXISTS traffic_summary (
    summary_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip          TEXT NOT NULL,
    packet_count    INTEGER DEFAULT 1,
    byte_count      INTEGER DEFAULT 0,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Logs port scan attempts per source IP
CREATE TABLE IF NOT EXISTS port_scan_log (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip          TEXT NOT NULL,
    scanned_port    INTEGER NOT NULL,
    scanned_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Known bad IPs for blacklist matching
CREATE TABLE IF NOT EXISTS blacklist (
    blacklist_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT UNIQUE NOT NULL,
    reason          TEXT,
    added_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);