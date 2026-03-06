import sqlite3
import datetime
import time

DB_PATH = "data/ids_logs.db"

class CorrelationEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.rules = [
            {
                "name": "Port Scan to Brute Force",
                "sequence": ["PORT_SCAN", "BRUTE_FORCE"],
                "window_minutes": 5,
                "severity": "CRITICAL",
                "message": "Potential Multi-Stage Attack: Port Scan followed by Brute Force detected."
            },
            {
                "name": "Failed Logins to Privilege Escalation",
                "sequence": ["FAILED_LOGIN", "PRIVILEGE_ESCALATION"],
                "window_minutes": 10,
                "severity": "CRITICAL",
                "message": "Critical Sequence: Multiple Failed Logins followed by Privilege Escalation attempts."
            }
        ]

    def analyze(self):
        """Analyze recent alerts for patterns matching correlation rules."""
        correlations = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # We'll check each rule
            for rule in self.rules:
                if len(rule['sequence']) < 2:
                    continue

                # Get the first and last events in the sequence
                first_event = rule['sequence'][0]
                second_event = rule['sequence'][1]
                window = rule['window_minutes']

                # Search for IPs that triggered both events within the window
                # This SQL finds pairs of events from the same IP where the second happens after the first within X minutes
                cursor.execute(f"""
                    SELECT a1.src_ip, a1.timestamp, a2.timestamp
                    FROM alerts a1
                    JOIN alerts a2 ON a1.src_ip = a2.src_ip
                    WHERE a1.attack_type = ? 
                      AND a2.attack_type = ?
                      AND a1.id < a2.id
                      AND (strftime('%s', a2.timestamp) - strftime('%s', a1.timestamp)) <= ?
                      AND (strftime('%s', a2.timestamp) - strftime('%s', a1.timestamp)) > 0
                """, (first_event, second_event, window * 60))

                matches = cursor.fetchall()
                for match in matches:
                    src_ip, t1, t2 = match
                    correlations.append({
                        "src_ip": src_ip,
                        "rule_name": rule['name'],
                        "severity": rule['severity'],
                        "message": rule['message'],
                        "triggered_at": t2,
                        "event_chain": f"{first_event} -> {second_event}"
                    })

            # Persistent save
            for corr in correlations:
                cursor.execute("""
                    INSERT OR IGNORE INTO correlations (timestamp, src_ip, rule_name, severity, event_chain, message)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (corr['triggered_at'], corr['src_ip'], corr['rule_name'], corr['severity'], corr['event_chain'], corr['message']))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Correlation Engine Error: {e}")
        
        return correlations
