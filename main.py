import datetime
import numpy as np
import random
import time
import threading
import sys
from collections import defaultdict, deque

from src.packet_capture.sniffer import simulate_packets, PacketSniffer
from src.signature_detection.engine import SignatureDetector
from src.anomaly_detection.detector import AnomalyDetector
from src.anomaly_detection.isolation_model import IsolationForestDetector
from src.anomaly_detection.feature_extraction import FeatureExtractor
from src.storage.logger import IDSLogger
from src.storage.firewall import VirtualFirewall
from src.storage.threat_intel import ThreatIntelManager
from src.correlation_engine.engine import CorrelationEngine
from src.dashboard.app import start_dashboard_thread, alert_queue
from src.simulator.replay import replay_attacks

def main():
    print("""
    =========================================
    🛡️  HYBRID INTRUSION DETECTION SYSTEM
    =========================================
    Initializing modules...
    """)
    
    # 1. Initialize Modules
    sig_detector = SignatureDetector()
    anomaly_detector = AnomalyDetector()
    iso_detector = IsolationForestDetector()
    feature_extractor = FeatureExtractor()
    db_logger = IDSLogger()
    firewall = VirtualFirewall()
    intel_manager = ThreatIntelManager()
    corrector = CorrelationEngine()
    
    # Update Threat Intel Feed on startup
    try:
        intel_thread = threading.Thread(target=intel_manager.update_feed)
        intel_thread.daemon = True
        intel_thread.start()
    except Exception as e:
        print(f"[!] Threat Intel Startup Error: {e}")

    # Correlation Analysis Task
    def run_correlation():
        while True:
            time.sleep(30)
            corrector.analyze()

    correlation_thread = threading.Thread(target=run_correlation)
    correlation_thread.daemon = True
    correlation_thread.start()

    # Attack tracker: {ip: deque([timestamps])}
    attack_tracker = defaultdict(lambda: deque(maxlen=20))
    BLOCK_THRESHOLD = 10
    BLOCK_WINDOW = 60 # Seconds

    # 2. Start Dashboard in background
    print("[*] Starting Web Dashboard on http://127.0.0.1:5000")
    start_dashboard_thread()

    def calculate_risk_score(attack_type, attempts, ml_prob, intel_hit):
        """Calculates a unified security risk score (0-100)."""
        score = 10
        
        # Multipliers based on attack severity
        type_weights = {
            "NORMAL": 0,
            "PORT_SCAN": 1.5,
            "BRUTE_FORCE": 2.0,
            "DDOS": 2.5,
            "MALWARE": 3.0,
            "MULTI_VECTOR_ATTACK": 4.0,
            "BLACKLISTED_IP": 3.5
        }
        
        if attack_type in type_weights:
            score += 15 * type_weights[attack_type]
            
        # Attempts factor (Cap at 30)
        score += min(attempts * 5, 30)
        
        # ML Confidence factor (Cap at 20)
        score += (ml_prob * 20)
        
        # Intelligence Hit factor
        if intel_hit:
            score += 30
            
        return int(min(100, score))
    
    def orchestrate_detection(packet_data):
        """
        Orchestration Flow:
        1. Capture -> 2. Block Check -> 3. Threat Intel -> 4. ML/Sig Detection -> 5. Auto-Block -> 6. Alert/Log
        """
        # --- PPS Counter ---
        import src.dashboard.app as dashboard_app
        dashboard_app.packet_counter += 1
        
        src_ip = packet_data.get('src_ip', '0.0.0.0')
        
        # --- Firewall Check ---
        if firewall.is_blocked(src_ip):
            return

        dst_ip = packet_data.get('dst_ip', 'Internal')
        proto = packet_data.get('protocol_name', 'OTHER')
        port = packet_data.get('port', 0)
        size = packet_data.get('length', 0)
        flags = packet_data.get('flags', '')
        payload = packet_data.get('payload', '')
        timestamp = packet_data.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        # --- Threat Intel Check ---
        intel_hit = intel_manager.is_malicious(src_ip)
        
        # --- Detection State ---
        sig_alert = sig_detector.check(packet_data)
        ml_hits = [] # List of (model_name, probability/confidence)

        # --- ML Anomaly Detection ---
        features = None
        if anomaly_detector.ready or iso_detector.ready:
            features = feature_extractor.extract(packet_data)
            
        if features is not None:
            # 1. Random Forest (Supervised)
            if anomaly_detector.ready:
                rf_res = anomaly_detector.predict(features)
                if rf_res and rf_res[1] > 0.65: # Threshold for RF
                    ml_hits.append(("RF", rf_res[1]))
            
            # 2. Isolation Forest (Unsupervised)
            if iso_detector.ready:
                if_res = iso_detector.predict(features)
                if if_res and if_res[0] == 1: # Anomaly detected (1 for anomaly, -1 for normal)
                    ml_hits.append(("IF", if_res[1])) # if_res[1] is anomaly score/confidence

        ml_triggered = len(ml_hits) > 0

        # --- Hybrid Decision Logic ---
        triggers = []
        if sig_alert: triggers.append("SIG")
        for name, conf in ml_hits: triggers.append(name)
        
        detection_source = "NORMAL"
        final_severity = "INFO"
        final_message = "Normal traffic"
        final_type = "NORMAL"
        ml_prob = max([h[1] for h in ml_hits]) if ml_hits else 0.0

        if intel_hit:
            detection_source = "THREAT_INTEL"
            final_severity = "HIGH"
            final_type = "BLACKLISTED_IP"
            final_message = f"DANGER: Blacklisted IP identified via Intelligence Feed!"
        elif len(triggers) >= 2:
            # Multi-vector confirmation
            detection_source = f"HYBRID ({'+'.join(triggers)})"
            final_severity = "CRITICAL"
            final_type = "MULTI_VECTOR_ATTACK"
            msg_parts = []
            if sig_alert: msg_parts.append(sig_alert['message'])
            if ml_hits: msg_parts.append(f"Anomalous behavior verified by {len(ml_hits)} ML models")
            final_message = " | ".join(msg_parts)
        elif triggers:
            # Single trigger
            detection_source = triggers[0]
            if detection_source == "SIG":
                final_severity = sig_alert['severity']
                final_type = sig_alert['type']
                final_message = sig_alert['message']
            elif detection_source == "RF":
                final_severity = "MEDIUM"
                final_type = "ML_ANOMALY"
                final_message = f"Suspicious activity via Random Forest (Conf: {ml_prob:.2f})"
            elif detection_source == "IF":
                final_severity = "MEDIUM"
                final_type = "OUTLIER_DETECTION"
                final_message = f"Unusual pattern detected via Isolation Forest (Outlier)"

        # --- Dynamic Risk Scoring ---
        attempts = len([t for t in attack_tracker[src_ip] if time.time() - t < BLOCK_WINDOW])
        risk_score = calculate_risk_score(final_type, attempts, ml_prob, intel_hit)
        
        # Override severity based on risk thresholds
        if risk_score >= 81: final_severity = "CRITICAL"
        elif risk_score >= 61: final_severity = "HIGH"
        elif risk_score >= 31: final_severity = "MEDIUM"
        else: final_severity = "LOW"
        
        if final_type == "NORMAL": final_severity = "INFO"

        # --- Auto-Blocking Logic ---
        if detection_source != "NORMAL":
            now = time.time()
            attack_tracker[src_ip].append(now)
            
            # Count attacks in the last window
            recent_attacks = [t for t in attack_tracker[src_ip] if now - t < BLOCK_WINDOW]
            
            if len(recent_attacks) >= BLOCK_THRESHOLD:
                if firewall.block_ip(src_ip, f"Exceeded {BLOCK_THRESHOLD} attacks in {BLOCK_WINDOW}s"):
                    # Log a dedicated Block event
                    block_msg = f"AUTO-BLOCK: IP {src_ip} restricted for repeated malicious behavior"
                    db_logger.log_event(
                        timestamp=timestamp, src_ip=src_ip, dst_ip="IDS_INTERNAL",
                        protocol="CONTROL", service="FIREWALL", port=0, size=0,
                        source="FIREWALL", severity="CRITICAL", attack_type="AUTO_BLOCKED",
                        message=block_msg
                    )
                    # Notify Dashboard
                    alert_queue.put({
                        "type": "AUTO_BLOCKED", "severity": "CRITICAL", "source_ip": src_ip,
                        "dst_ip": "FIREWALL", "dst_port": 0, "packet_size": 0,
                        "timestamp": timestamp, "message": block_msg,
                        "detection_source": "FIREWALL", "ml_probability": 1.0
                    })

            # --- Send Normal Alert ---
            alert_payload = {
                "type": final_type,
                "severity": final_severity,
                "source_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": port,
                "packet_size": size,
                "timestamp": timestamp,
                "message": final_message,
                "detection_source": detection_source,
                "ml_probability": ml_prob,
                "risk_score": risk_score
            }
            alert_queue.put(alert_payload)
            print(f"[!] {detection_source} ALERT: {final_type} | {src_ip} -> {final_message}")

        # Persistent Log (Always logged)
        db_logger.log_event(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            service=packet_data.get('port', 'other'),
            port=port,
            size=size,
            flags=flags,
            payload=payload,
            sig_triggered=bool(sig_alert),
            ml_triggered=ml_triggered,
            ml_prob=ml_prob,
            source=detection_source,
            severity=final_severity,
            attack_type=final_type,
            risk_score=risk_score,
            message=final_message
        )

    # 3. Start Packet Capture (Live, Simulated, or Replay)
    try:
        if "--replay" in sys.argv:
            replay_attacks(orchestrate_detection)
        else:
            print("[*] IDS active and monitoring traffic...")
            simulate_packets(orchestrate_detection)
    except KeyboardInterrupt:
        print("\n[!] Shutting down IDS...")
        db_logger.stop()

if __name__ == "__main__":
    main()
