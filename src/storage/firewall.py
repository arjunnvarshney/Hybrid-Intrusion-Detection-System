import sqlite3
import datetime
import os

DB_PATH = "data/ids_logs.db"

class VirtualFirewall:
    def __init__(self):
        self.blocked_ips = set()
        self.load_blocks()

    def load_blocks(self):
        """Load blocked IPs from database into memory."""
        try:
            if not os.path.exists(DB_PATH):
                return
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT ip FROM blocked_ips")
            rows = cursor.fetchall()
            self.blocked_ips = {row[0] for row in rows}
            conn.close()
        except Exception as e:
            print(f"[!] Firewall Load Error: {e}")

    def is_blocked(self, ip):
        """Check if an IP is currently blocked."""
        return ip in self.blocked_ips

    def block_ip(self, ip, reason):
        """Block an IP and save to database."""
        if ip in self.blocked_ips:
            return False
            
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip, reason, timestamp) VALUES (?, ?, ?)", 
                         (ip, reason, now))
            conn.commit()
            conn.close()
            
            self.blocked_ips.add(ip)
            print(f"[🔥] FIREWALL: Blocked {ip} for '{reason}'")
            return True
        except Exception as e:
            print(f"[!] Firewall Save Error: {e}")
            return False

    def unblock_ip(self, ip):
        """Unblock an IP."""
        if ip not in self.blocked_ips:
            return False
            
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            
            self.blocked_ips.remove(ip)
            print(f"[🛡️] FIREWALL: Unblocked {ip}")
            return True
        except Exception as e:
            print(f"[!] Firewall Unblock Error: {e}")
            return False
