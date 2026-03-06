import numpy as np
import pandas as pd
import joblib
import os
from collections import deque
import time

# Paths to artifacts (must match train.py)
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/encoders.pkl"

class FeatureExtractor:
    def __init__(self):
        # State for statistical features (NSL-KDD count features)
        # We'll keep a window of recent connections (IP, Service, Timestamp)
        self.connection_history = deque(maxlen=1000)
        self.WINDOW_SECONDS = 2.0
        
        # Load preprocessing artifacts
        if os.path.exists(SCALER_PATH) and os.path.exists(ENCODER_PATH):
            self.scaler = joblib.load(SCALER_PATH)
            self.encoders = joblib.load(ENCODER_PATH)
            self.ready = True
        else:
            print("[!] FeatureExtractor: Model artifacts not found. Preprocessing will be skipped.")
            self.ready = False

        # Map common ports to NSL-KDD service names
        self.service_map = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain_u', 80: 'http', 110: 'pop_3',
            111: 'sunrpc', 113: 'auth', 119: 'nntp', 123: 'ntp',
            135: 'ntrpc', 139: 'netbios_ssn', 143: 'imap4', 161: 'snmp_get',
            389: 'ldap', 443: 'http_443', 445: 'microsoft_ds', 513: 'login',
            514: 'shell', 520: 'efs', 636: 'ldaps', 993: 'imap4', 995: 'pop_3'
        }

    def _get_flag_string(self, flags):
        """Map TCP flags to NSL-KDD flag types."""
        if 'S' in flags and 'A' not in flags: return 'S0'
        if 'R' in flags: return 'REJ'
        if 'F' in flags: return 'SF' # Simplified
        if 'A' in flags: return 'SF'
        return 'OTH'

    def update_history(self, packet_data):
        """Keep track of recent connections for traffic-based features."""
        now = time.time()
        self.connection_history.append({
            'ts': now,
            'src_ip': packet_data['src_ip'],
            'dst_ip': packet_data['dst_ip'],
            'service': self.service_map.get(packet_data['port'], 'other'),
            'proto': packet_data['protocol_name'].lower()
        })
        
        # Clean up old history
        while self.connection_history and now - self.connection_history[0]['ts'] > self.WINDOW_SECONDS:
            self.connection_history.popleft()

    def extract(self, packet_data):
        """
        Main entry point: Converts packet_data dict to 41-feature vector.
        """
        self.update_history(packet_data)
        
        # 1. Basic features
        duration = 0 # Difficult to calculate for single packets without full flow tracking
        protocol_type = packet_data['protocol_name'].lower()
        service = self.service_map.get(packet_data['port'], 'other')
        flag = self._get_flag_string(packet_data.get('flags', ''))
        src_bytes = packet_data.get('length', 0)
        dst_bytes = 0 # Placeholder: would need response packet capture
        
        # 2. History-based features (count, srv_count)
        # count: number of connections to the same destination host as the current connection in the past two seconds
        history_list = list(self.connection_history)
        count = sum(1 for h in history_list if h['dst_ip'] == packet_data['dst_ip'])
        # srv_count: number of connections to the same service as the current connection in the past two seconds
        srv_count = sum(1 for h in history_list if h['service'] == service)
        
        # 3. Create raw feature vector (41 features)
        # Most "content" features (root_shell, hot, etc) are 0 for generic packets
        # Most "host-based" features (dst_host_*) would need more complex state
        
        features = {
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": 1 if packet_data['src_ip'] == packet_data['dst_ip'] else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": count, # Approximation
            "dst_host_srv_count": srv_count, # Approximation
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0
        }

        # Ensure order matches COL_NAMES from train.py (excluding label and difficulty)
        feature_order = [
            "duration","protocol_type","service","flag","src_bytes",
            "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
            "logged_in","num_compromised","root_shell","su_attempted","num_root",
            "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
            "is_host_login","is_guest_login","count","srv_count","serror_rate",
            "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
            "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate"
        ]

        # Convert to DataFrame for easier encoding
        df_row = pd.DataFrame([features], columns=feature_order)

        if self.ready:
            try:
                # Apply Label Encoding (handle unseen labels by using the most common one in the encoder)
                for col in ['protocol_type', 'service', 'flag']:
                    le = self.encoders[col]
                    # Simple handling for unseen labels: use first class
                    df_row[col] = df_row[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
                    df_row[col] = le.transform(df_row[col])

                # Apply Scaling
                X_scaled = self.scaler.transform(df_row)
                return X_scaled
            except Exception as e:
                print(f"[!] Encoding Error: {e}")
                return None
        
        return df_row.to_numpy() # Unpreprocessed if not ready
