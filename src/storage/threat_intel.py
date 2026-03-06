import sqlite3
import requests
import datetime
import os

DB_PATH = "data/ids_logs.db"
FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

class ThreatIntelManager:
    def __init__(self):
        self.malicious_ips = set()
        self.load_from_db()

    def load_from_db(self):
        """Load known malicious IPs from database into memory."""
        try:
            if not os.path.exists(DB_PATH):
                return
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT ip FROM threat_intel")
            rows = cursor.fetchall()
            self.malicious_ips = {row[0] for row in rows}
            conn.close()
            print(f"[*] Threat Intel: Loaded {len(self.malicious_ips)} malicious IPs from database.")
        except Exception as e:
            print(f"[!] Threat Intel Load Error: {e}")

    def update_feed(self):
        """Download latest feed and update database."""
        print("[*] Threat Intel: Fetching latest malicious IP feed...")
        try:
            response = requests.get(FEED_URL, timeout=10)
            if response.status_code != 200:
                print(f"[!] Feed Download Failed: {response.status_code}")
                return

            # Feodo tracker format: lines starting with # are comments
            lines = response.text.splitlines()
            new_ips = []
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                # Feodo blocklist simple ip format
                ip = line.strip()
                new_ips.append(ip)

            if not new_ips:
                print("[!] No IPs found in feed.")
                return

            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Clear old and add new (or just INSERT OR IGNORE)
            # For simplicity, we'll just add new ones
            for ip in new_ips:
                cursor.execute("INSERT OR IGNORE INTO threat_intel (ip, source, added_at) VALUES (?, ?, ?)", 
                             (ip, "abuse.ch Feodo Tracker", now))
            
            conn.commit()
            conn.close()
            
            # Refresh memory
            self.load_from_db()
            print(f"[✓] Threat Intel: Updated. Total unique IPs: {len(self.malicious_ips)}")
        except Exception as e:
            print(f"[!] Threat Intel Update Error: {e}")

    def is_malicious(self, ip):
        """Verify if an IP is in the threat intelligence list."""
        return ip in self.malicious_ips
