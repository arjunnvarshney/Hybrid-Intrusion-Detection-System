import sqlite3
import time
import datetime
import os

DB_PATH = "data/ids_logs.db"

def replay_attacks(callback, delay=0.5):
    """
    Loads historical attacks from the database and feeds them into the detection pipeline.
    """
    if not os.path.exists(DB_PATH):
        print(f"[!] Error: Database {DB_PATH} not found. Cannot replay attacks.")
        return

    print("\n" + "="*40)
    print("🚀 ATTACK REPLAY MODE ACTIVATED")
    print("="*40)
    print(f"[*] Fetching historical threats from {DB_PATH}...")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # We only want to replay things that were actually identified as attacks (ignoring NORMAL)
        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, port, packet_size, flags, payload, attack_type
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            ORDER BY timestamp ASC
        """)
        
        attacks = cursor.fetchall()
        conn.close()

        if not attacks:
            print("[!] No historical attacks found to replay.")
            return

        print(f"[*] Found {len(attacks)} attacks. Injecting into pipeline...")

        for attack in attacks:
            src_ip, dst_ip, proto_name, port, size, flags, payload, attack_type = attack
            
            # Construct a packet_data object that looks like it came from the sniffer
            packet_data = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol_name': proto_name if proto_name else 'TCP',
                'port': port,
                'length': size,
                'flags': flags if flags else '',
                'payload': payload if payload else '',
                'is_replay': True # Flag so detection logic knows it's a replay
            }

            print(f"[REPLAY] Sending {attack_type} from {src_ip} -> {dst_ip}")
            callback(packet_data)
            
            # Artificial delay to simulate real-time stream
            time.sleep(delay)

        print("\n[*] Attack replay completed successfully.")

    except Exception as e:
        print(f"[!] Replay Error: {e}")
