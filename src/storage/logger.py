import sqlite3
import threading
import queue
import os
import time

DB_PATH = "data/ids_logs.db"

class IDSLogger:
    def __init__(self):
        self.log_queue = queue.Queue()
        self._init_db()
        
        # Start background logging thread
        self.stop_logging = threading.Event()
        self.log_thread = threading.Thread(target=self._logging_worker)
        self.log_thread.daemon = True
        self.log_thread.start()

    def _init_db(self):
        """Initialize SQLite database and alerts table."""
        if not os.path.exists('data'):
            os.makedirs('data')
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                service TEXT,
                port INTEGER,
                packet_size INTEGER,
                flags TEXT,
                payload TEXT,
                signature_triggered BOOLEAN,
                ml_triggered BOOLEAN,
                ml_probability REAL,
                detection_source TEXT,
                severity TEXT,
                attack_type TEXT,
                risk_score INTEGER,
                message TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                timestamp TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                source TEXT,
                added_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                rule_name TEXT,
                severity TEXT,
                event_chain TEXT,
                message TEXT,
                UNIQUE(src_ip, rule_name, timestamp)
            )
        ''')
        conn.commit()
        conn.close()

    def log_event(self, timestamp, src_ip, dst_ip, protocol, service, port, size,
                  flags="", payload="", sig_triggered=False, ml_triggered=False, ml_prob=0.0, 
                  source="SIGNATURE", severity="INFO", attack_type="NORMAL", risk_score=0, message=""):
        """
        Public method to queue a log event. Non-blocking.
        """
        event_data = (
            timestamp, src_ip, dst_ip, str(protocol), str(service), port, size,
            flags, payload, sig_triggered, ml_triggered, ml_prob, source, severity, attack_type, risk_score, message
        )
        self.log_queue.put(event_data)

    def _logging_worker(self):
        """
        Background worker that pulls from queue and writes to SQLite.
        """
        while not self.stop_logging.is_set() or not self.log_queue.empty():
            try:
                # Get event from queue with timeout to check stop signal
                event = self.log_queue.get(timeout=1.0)
                
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (
                        timestamp, src_ip, dst_ip, protocol, service, port, packet_size,
                        flags, payload, signature_triggered, ml_triggered, ml_probability, 
                        detection_source, severity, attack_type, risk_score, message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', event)
                conn.commit()
                conn.close()
                
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Database Error: {e}")

    def stop(self):
        """Stop the background logger."""
        self.stop_logging.set()
        self.log_thread.join(timeout=2)
