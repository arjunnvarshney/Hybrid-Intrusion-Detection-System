from flask import Flask, render_template, jsonify, request, Response, make_response, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import queue
import os
import sqlite3
import pandas as pd
import io
import datetime
from fpdf import FPDF
import psutil
import time

from src.storage.geoip_utils import GeoIPLookup

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids_secret_key' # In production, use env variable
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mock user database
USERS = {
    "admin": generate_password_hash("password")
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

DB_PATH = "data/ids_logs.db"
geoip = GeoIPLookup()

# Shared alert queue for real-time table
alert_queue = queue.Queue()

# System Health Counters
packet_counter = 0
pps = 0

def health_stats_monitor():
    """Background task to calculate Packets Per Second and other health metrics."""
    global packet_counter, pps
    while True:
        # Calculate PPS
        pps = packet_counter
        packet_counter = 0
        time.sleep(1)

def background_alert_emitter():
    """Monitor queue and push alerts to clients via SocketIO."""
    print("[*] SocketIO: Alert emitter background task started.")
    while True:
        try:
            while not alert_queue.empty():
                alert = alert_queue.get()
                
                # Enrich with GeoIP data
                lat, lon, country = geoip.get_location(alert['source_ip'])
                alert['lat'] = lat
                alert['lon'] = lon
                alert['country'] = country
                
                # Broadcast to all connected clients
                socketio.emit('new_alert', alert)
            
            socketio.sleep(1) # Check queue every second
        except Exception as e:
            print(f"[!] SocketIO Error: {e}")
            socketio.sleep(2)

@app.route('/api/alerts')
@login_required
def get_alerts():
    """Fetch recent non-normal alerts from SQLite."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify([])
            
        conn = sqlite3.connect(DB_PATH)
        # Fetch last 100 alerts that are NOT normal
        df = pd.read_sql_query("""
            SELECT id, timestamp, src_ip, dst_ip, port as dst_port, attack_type as type, 
                   severity, detection_source, ml_probability, risk_score, message
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            ORDER BY id DESC LIMIT 100
        """, conn)
        conn.close()
        
        alerts = df.to_dict(orient='records')
        for alert in alerts:
            lat, lon, country = geoip.get_location(alert['src_ip'])
            alert['lat'] = lat
            alert['lon'] = lon
            alert['country'] = country
            
        return jsonify(alerts)
    except Exception as e:
        print(f"Alert API Error: {e}")
        return jsonify([])

@app.route('/api/alert/<int:alert_id>')
@login_required
def get_alert_details(alert_id):
    """Fetch full forensics for a single alert."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM alerts WHERE id = ?", conn, params=(alert_id,))
        conn.close()
        
        if df.empty:
            return jsonify({"error": "Alert not found"}), 404
            
        alert = df.iloc[0].to_dict()
        return jsonify(alert)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    """Fetch summarized stats from SQLite for charts."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({"error": "No data yet"})

        conn = sqlite3.connect(DB_PATH)
        
        # 1. Attack Types (Pie)
        df_types = pd.read_sql_query("SELECT attack_type, COUNT(*) as count FROM alerts WHERE attack_type != 'NORMAL' GROUP BY attack_type", conn)
        attack_types = dict(zip(df_types['attack_type'], df_types['count']))

        # 2. Detection Source (Bar)
        df_sources = pd.read_sql_query("""
            SELECT 
                SUM(CASE WHEN signature_triggered = 1 THEN 1 ELSE 0 END) as sig,
                SUM(CASE WHEN ml_triggered = 1 THEN 1 ELSE 0 END) as ml
            FROM alerts
        """, conn)
        sources = df_sources.iloc[0].to_dict()

        # 3. Top IPs
        df_ips = pd.read_sql_query("""
            SELECT src_ip, COUNT(*) as count 
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            GROUP BY src_ip 
            ORDER BY count DESC LIMIT 5
        """, conn)
        top_ips = df_ips.to_dict(orient='records')

        # 4. Alerts over time (last 10 mins)
        df_time = pd.read_sql_query("""
            SELECT strftime('%H:%M', timestamp) as minute, COUNT(*) as count 
            FROM alerts 
            WHERE attack_type != 'NORMAL'
            GROUP BY minute 
            ORDER BY minute DESC LIMIT 10
        """, conn)
        time_series = df_time.to_dict(orient='records')

        # 5. Blocked IPs
        df_blocked = pd.read_sql_query("SELECT ip, reason, timestamp FROM blocked_ips ORDER BY timestamp DESC", conn)
        blocked_list = df_blocked.to_dict(orient='records')

        # 6. Recent Correlations
        df_corr = pd.read_sql_query("SELECT timestamp, src_ip, rule_name, severity, event_chain, message FROM correlations ORDER BY timestamp DESC LIMIT 10", conn)
        correlation_list = df_corr.to_dict(orient='records')

        conn.close()
        return jsonify({
            "attack_types": attack_types,
            "sources": sources,
            "top_ips": top_ips,
            "time_series": time_series[::-1],
            "blocked_ips": blocked_list,
            "correlations": correlation_list
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/top_attackers')
@login_required
def api_top_attackers():
    """Endpoint for external systems to fetch top 10 attacking IPs."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df_ips = pd.read_sql_query("""
            SELECT src_ip, COUNT(*) as attack_count 
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            GROUP BY src_ip 
            ORDER BY attack_count DESC LIMIT 10
        """, conn)
        conn.close()
        return jsonify(df_ips.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/attack_distribution')
@login_required
def api_attack_distribution():
    """Endpoint for external systems to fetch attack type distribution."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df_dist = pd.read_sql_query("""
            SELECT attack_type, COUNT(*) as count 
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            GROUP BY attack_type
        """, conn)
        conn.close()
        return jsonify(df_dist.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/system_stats')
@login_required
def api_system_stats():
    """Consolidated system statistics for external monitoring."""
    try:
        conn = sqlite3.connect(DB_PATH)
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'NORMAL'").fetchone()[0]
        total_packets = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        blocked_ips = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        conn.close()
        
        # Get health data
        db_size = 0
        if os.path.exists(DB_PATH):
            db_size = os.path.getsize(DB_PATH) / (1024 * 1024)
            
        stats = {
            "summary": {
                "total_alerts": total_alerts,
                "total_packets_processed": total_packets,
                "active_blocked_ips": blocked_ips
            },
            "performance": {
                "pps": pps,
                "cpu_usage_percent": psutil.cpu_percent(),
                "memory_usage_percent": psutil.virtual_memory().percent,
                "db_size_mb": round(db_size, 2)
            }
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
@login_required
def get_health():
    """Fetch system health metrics."""
    try:
        # DB Size in MB
        db_size = 0
        if os.path.exists(DB_PATH):
            db_size = os.path.getsize(DB_PATH) / (1024 * 1024)
            
        health = {
            "pps": pps,
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "db_size_mb": round(db_size, 2),
            "active_sessions": len(socketio.server.eio.sockets) if hasattr(socketio.server, 'eio') else 0
        }
        return jsonify(health)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/unblock/<path:ip>', methods=['POST'])
@login_required
def unblock_ip(ip):
    """Manually unblock an IP."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": f"IP {ip} unblocked"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/export_report')
@login_required
def export_report():
    """Generate and export security report in CSV or PDF format."""
    file_format = request.args.get('format', 'csv').lower()
    
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # 1. Fetch Alert Data (Exclude normal)
        query = """
            SELECT timestamp, src_ip, dst_ip, port as dst_port, protocol, service, 
                   attack_type, severity, detection_source, message
            FROM alerts 
            WHERE attack_type != 'NORMAL' 
            ORDER BY timestamp DESC
        """
        df_alerts = pd.read_sql_query(query, conn)
        
        # 2. Fetch Summary Stats
        df_top_ips = pd.read_sql_query("SELECT src_ip, COUNT(*) as count FROM alerts WHERE attack_type != 'NORMAL' GROUP BY src_ip ORDER BY count DESC LIMIT 10", conn)
        df_dist = pd.read_sql_query("SELECT attack_type, COUNT(*) as count FROM alerts WHERE attack_type != 'NORMAL' GROUP BY attack_type", conn)
        
        conn.close()

        if file_format == 'csv':
            # Generate CSV
            output = io.StringIO()
            df_alerts.to_csv(output, index=False)
            response = Response(output.getvalue(), mimetype="text/csv")
            response.headers["Content-Disposition"] = "attachment; filename=ids_attack_report.csv"
            return response
            
        elif file_format == 'pdf':
            # Generate PDF
            pdf = FPDF()
            pdf.add_page()
            
            # Header
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(190, 10, "HYBRID IDS SECURITY REPORT", ln=True, align='C')
            pdf.set_font("Arial", '', 10)
            pdf.cell(190, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
            pdf.ln(10)
            
            # Executive Summary
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "1. Executive Summary", ln=True)
            pdf.set_font("Arial", '', 10)
            pdf.cell(190, 8, f"Total Attacks Detected: {len(df_alerts)}", ln=True)
            high_sev = len(df_alerts[df_alerts['severity'] == 'HIGH'])
            pdf.cell(190, 8, f"High Severity Alerts: {high_sev}", ln=True)
            pdf.ln(5)
            
            # Attack Distribution
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "2. Attack Distribution", ln=True)
            pdf.set_font("Arial", '', 10)
            for _, row in df_dist.iterrows():
                pdf.cell(190, 8, f"- {row['attack_type']}: {row['count']}", ln=True)
            pdf.ln(5)
            
            # Top Attacking IPs
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "3. Top 10 Attacking IP Addresses", ln=True)
            pdf.set_font("Arial", '', 10)
            for _, row in df_top_ips.iterrows():
                pdf.cell(190, 8, f"- {row['src_ip']}: {row['count']} hits", ln=True)
            pdf.ln(10)
            
            # Recent Logs (Top 20)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "4. Recent Attack Logs (Last 20)", ln=True)
            pdf.set_font("Arial", '', 8)
            
            # Table Header
            pdf.cell(40, 7, "Timestamp", 1)
            pdf.cell(30, 7, "Source IP", 1)
            pdf.cell(40, 7, "Attack Type", 1)
            pdf.cell(20, 7, "Severity", 1)
            pdf.cell(60, 7, "Message", 1)
            pdf.ln()
            
            # Table Rows
            for _, row in df_alerts.head(20).iterrows():
                pdf.cell(40, 6, str(row['timestamp']), 1)
                pdf.cell(30, 6, str(row['src_ip']), 1)
                pdf.cell(40, 6, str(row['attack_type']), 1)
                pdf.cell(20, 6, str(row['severity']), 1)
                pdf.cell(60, 6, str(row['message'])[:40], 1)
                pdf.ln()

            response = make_response(pdf.output())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = 'attachment; filename=ids_security_report.pdf'
            return response

        else:
            return jsonify({"error": "Invalid format. Choose 'csv' or 'pdf'."}), 400
            
    except Exception as e:
        print(f"Report Generation Error: {e}")
        return jsonify({"error": str(e)}), 500

def run_dashboard():
    # Start background tasks
    socketio.start_background_task(background_alert_emitter)
    socketio.start_background_task(health_stats_monitor)
    # Use environment port for deployment (defaults to 5000)
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, use_reloader=False)

def start_dashboard_thread():
    thread = threading.Thread(target=run_dashboard)
    thread.daemon = True
    thread.start()
    return thread
