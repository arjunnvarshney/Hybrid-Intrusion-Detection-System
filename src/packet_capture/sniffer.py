from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import threading

class PacketSniffer:
    def __init__(self, callback):
        """
        callback: function to receive processed packet data
        """
        self.callback = callback
        self.stop_sniffing = threading.Event()

    def process_packet(self, packet):
        """Extracts core features from raw scapy packets."""
        if IP in packet:
            # Basic Features (Requested: src_ip, dst_ip, protocol, size, flags)
            packet_data = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'protocol_name': 'OTHER',
                'length': len(packet),
                'flags': '',
                'port': None,
                'payload': str(packet[IP].payload)[:100] if hasattr(packet[IP], 'payload') else ""
            }
            
            # Protocol-specific extraction
            if TCP in packet:
                packet_data['protocol_name'] = 'TCP'
                packet_data['port'] = packet[TCP].dport
                packet_data['flags'] = str(packet[TCP].flags) # Extracts TCP flags (SYN, ACK, etc.)
            elif UDP in packet:
                packet_data['protocol_name'] = 'UDP'
                packet_data['port'] = packet[UDP].dport
            elif ICMP in packet:
                packet_data['protocol_name'] = 'ICMP'
                packet_data['type'] = packet[ICMP].type
            
            # Send to detection modules via callback
            self.callback(packet_data)

    def _sniff_thread(self, interface):
        print(f"[*] Sniffer started on {interface if interface else 'default interface'}")
        sniff(iface=interface, prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_sniffing.is_set())

    def start_sniffing(self, interface=None):
        """Non-blocking start of the packet sniffer."""
        self.sniff_thread = threading.Thread(target=self._sniff_thread, args=(interface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        return self.sniff_thread

    def stop(self):
        """Stop the background sniffer."""
        self.stop_sniffing.set()
        if hasattr(self, 'sniff_thread'):
            self.sniff_thread.join(timeout=1)

# Simulation for environments without Root/Pcap
def simulate_packets(callback):
    import time
    import random
    
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [22, 80, 443, 445, 23, 53]
    ips = ['192.168.1.1', '10.0.0.5', '172.16.0.10', '8.8.8.8']
    
    print("[*] Starting packet simulation...")
    while True:
        # Randomly choose between Normal, Signature, and Anomaly simulations
        sim_type = random.random()
        
        packet_data = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': random.choice(ips),
            'dst_ip': random.choice(ips),
            'protocol': 6,
            'protocol_name': 'TCP',
            'port': random.choice(ports),
            'length': random.randint(40, 1500),
            'flags': 'PA',
            'payload': "GET /index.html HTTP/1.1\r\nHost: example.com\r\n..."
        }

        if sim_type > 0.80: # Trigger Brute Force (Port 22)
            packet_data['src_ip'] = '1.2.3.4' 
            packet_data['port'] = 22
        elif sim_type > 0.60: # Trigger SYN Flood
            packet_data['src_ip'] = '5.6.7.8' 
            packet_data['flags'] = 'S'

        callback(packet_data)
        time.sleep(0.1) # Fast simulation (10 packets/sec)
