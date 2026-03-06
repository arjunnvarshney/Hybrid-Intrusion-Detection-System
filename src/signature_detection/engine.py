from collections import defaultdict
import time
import datetime

class SignatureDetector:
    def __init__(self):
        # State tracking: {ip: {ports_set, syn_count, login_attempts, last_reset}}
        self.stats = defaultdict(lambda: {
            'ports': set(),
            'syn_count': 0,
            'login_attempts': 0,
            'last_reset': time.time()
        })
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 20
        self.SYN_FLOOD_THRESHOLD = 50
        self.BRUTE_FORCE_THRESHOLD = 10
        self.WINDOW_SIZE = 60 # Seconds

    def _reset_stats_if_needed(self, ip):
        if time.time() - self.stats[ip]['last_reset'] > self.WINDOW_SIZE:
            self.stats[ip]['ports'].clear()
            self.stats[ip]['syn_count'] = 0
            self.stats[ip]['login_attempts'] = 0
            self.stats[ip]['last_reset'] = time.time()

    def detect_port_scan(self, packet):
        ip = packet.get('src_ip')
        port = packet.get('port')
        if not ip or not port: return None
        
        self.stats[ip]['ports'].add(port)
        if len(self.stats[ip]['ports']) > self.PORT_SCAN_THRESHOLD:
            return self._create_alert("PORT_SCAN", "MEDIUM", ip, f"Accessed {len(self.stats[ip]['ports'])} unique ports")
        return None

    def detect_syn_flood(self, packet):
        ip = packet.get('src_ip')
        flags = packet.get('flags', '')
        if not ip or 'S' not in flags: return None # 'S' for SYN flag in Scapy
        
        self.stats[ip]['syn_count'] += 1
        if self.stats[ip]['syn_count'] > self.SYN_FLOOD_THRESHOLD:
            return self._create_alert("SYN_FLOOD", "HIGH", ip, f"Received {self.stats[ip]['syn_count']} SYN packets")
        return None

    def detect_bruteforce(self, packet):
        ip = packet.get('src_ip')
        port = packet.get('port')
        # Simulate detection on SSH (22) or Telnet (23)
        if not ip or port not in [22, 23]: return None
        
        self.stats[ip]['login_attempts'] += 1
        if self.stats[ip]['login_attempts'] > self.BRUTE_FORCE_THRESHOLD:
            service = "SSH" if port == 22 else "Telnet"
            return self._create_alert("BRUTE_FORCE", "HIGH", ip, f"Multiple connection attempts to {service}")
        return None

    def _create_alert(self, alert_type, severity, ip, details):
        return {
            "type": alert_type,
            "severity": severity,
            "source_ip": ip,
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "message": details
        }

    def check(self, packet):
        """Main entry point to check all signatures"""
        ip = packet.get('src_ip')
        if not ip: return None
        
        self._reset_stats_if_needed(ip)
        
        # Run all specialized detectors
        alerts = []
        
        port_scan = self.detect_port_scan(packet)
        if port_scan: alerts.append(port_scan)
        
        syn_flood = self.detect_syn_flood(packet)
        if syn_flood: alerts.append(syn_flood)
        
        brute_force = self.detect_bruteforce(packet)
        if brute_force: alerts.append(brute_force)
        
        # Return the highest severity alert if any found
        return alerts[0] if alerts else None
