import datetime
import numpy as np
import random
import time
import threading
import sys
import os
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
    
    # Attack tracker: {ip: deque([timestamps])}
    attack_tracker = defaultdict(lambda: deque(maxlen=20))
    BLOCK_THRESHOLD = 10
    BLOCK_WINDOW = 60 # Seconds

    def calculate_risk_score(attack_type, attempts, ml_prob, intel_hit):
        """Calculates a unified security risk score (0-100)."""
        score = 10
        type_weights = {
            "NORMAL": 0, "PORT_SCAN": 1.5, "BRUTE_FORCE": 2.0,
            "DDOS": 2.5, "MALWARE": 3.0, "MULTI_VECTOR_ATTACK": 4.0,
            "BLACKLISTED_IP": 3.5
        }
        if attack_type in type_weights:
            score += 15 * type_weights[attack_type]
        score += min(attempts * 5, 30)
        score += (ml_prob * 20)
        if intel_hit:
            score += 30
        return int(min(100, score))

    def orchestrate_detection(packet_data):
        """Main detection logic."""
        import src.dashboard.app as dashboard_app
        dashboard_app.packet_counter += 1
        
        src_ip = packet_data.get('src_ip', '0.0.0.0')
        if firewall.is_blocked(src_ip):
            return

        dst_ip = packet_data.get('dst_ip', 'Internal')
        proto = packet_data.get('protocol_name', 'OTHER')
        port = packet_data.get('port', 0)
        size = packet_data.get('length', 0)
        flags = packet_data.get('flags', '')
        payload = packet_data.get('payload', '')
        timestamp = packet_data.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        intel_hit = intel_manager.is_malicious(src_ip)
        sig_alert = sig_detector.check(packet_data)
        ml_hits = [] 

        features = None
        if anomaly_detector.ready or iso_detector.ready:
            features = feature_extractor.extract(packet_data)
        if features is not None:
            if anomaly_detector.ready:
                res = anomaly_detector.predict(features)
                if res['prediction'] != 'NORMAL':
                    ml_hits.append(('RF', res['probability']))
            if iso_detector.ready:
                res = iso_detector.predict(features)
                if res['prediction'] != 'NORMAL':
                    ml_hits.append(('IF', res['score']))

        if sig_alert or ml_hits or intel_hit:
            final_type = "UNKNOWN"
            final_severity = "LOW"
            ml_triggered = len(ml_hits) > 0
            ml_prob = max([h[1] for h in ml_hits]) if ml_hits else 0.0
            
            if sig_alert:
                final_type = sig_alert['type']
                final_severity = sig_alert['severity']
            elif ml_triggered:
                final_type = "ANOMALY"
                final_severity = "MEDIUM" if len(ml_hits) == 1 else "HIGH"
            
            if intel_hit:
                final_type = "BLACKLISTED_IP"
                final_severity = "HIGH"
                detection_source = "THREAT_INTEL"
            else:
                detection_source = []
                if sig_alert: detection_source.append("SIGNATURE")
                if ml_triggered: detection_source.append("ML")
                detection_source = "+".join(detection_source)

            attack_tracker[src_ip].append(time.time())
            attempts = len([t for t in attack_tracker[src_ip] if time.time() - t < BLOCK_WINDOW])
            risk_score = calculate_risk_score(final_type, attempts, ml_prob, intel_hit)

            if risk_score > 80: final_severity = "CRITICAL"
            elif risk_score > 60: final_severity = "HIGH"

            if attempts >= BLOCK_THRESHOLD:
                firewall.block_ip(src_ip, f"Exceeded {BLOCK_THRESHOLD} attacks in {BLOCK_WINDOW}s")
                final_severity = "CRITICAL"

            final_message = sig_alert['message'] if sig_alert else f"ML Anomaly detected from {src_ip}"
            if intel_hit: final_message = f"Malicious IP detected: {src_ip} (Threat Intel)"

            alert_queue.put({
                'timestamp': timestamp, 'source_ip': src_ip, 'dest_ip': dst_ip,
                'type': final_type, 'severity': final_severity, 'detection_source': detection_source,
                'ml_confidence': round(ml_prob, 2), 'risk_score': risk_score, 'message': final_message
            })

            db_logger.log_event(
                timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, protocol=proto, service="", 
                port=port, size=size, flags=flags, payload=payload, sig_triggered=bool(sig_alert),
                ml_triggered=ml_triggered, ml_prob=ml_prob, source=detection_source,
                severity=final_severity, attack_type=final_type, risk_score=risk_score, message=final_message
            )

    # 2. Start Threads
    try:
        intel_thread = threading.Thread(target=intel_manager.update_feed)
        intel_thread.daemon = True
        intel_thread.start()
    except Exception as e:
        print(f"[!] Threat Intel Startup Error: {e}")

    def run_correlation():
        while True:
            time.sleep(30)
            corrector.analyze()

    correlation_thread = threading.Thread(target=run_correlation)
    correlation_thread.daemon = True
    correlation_thread.start()

    def run_engine():
        try:
            if "--replay" in sys.argv:
                replay_attacks(orchestrate_detection)
            else:
                print("[*] IDS active and monitoring traffic...")
                simulate_packets(orchestrate_detection)
        except Exception as e:
            print(f"[!] Engine Error: {e}")

    engine_thread = threading.Thread(target=run_engine)
    engine_thread.daemon = True
    engine_thread.start()

    # 3. Start Dashboard on Port
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Initializing Web Dashboard on port {port}...")
    from src.dashboard.app import run_dashboard
    try:
        run_dashboard()
    except KeyboardInterrupt:
        print("\n[!] Shutting down IDS...")
        db_logger.stop()

if __name__ == "__main__":
    main()
