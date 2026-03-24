from database import initialize_db
from sniffer import start_sniffing

if __name__ == "__main__":
    print("=" * 40)
    print("  NIDS - Network Intrusion Detection System")
    print("=" * 40)

    print("[INIT] Initializing database...")
    initialize_db()

    start_sniffing()
