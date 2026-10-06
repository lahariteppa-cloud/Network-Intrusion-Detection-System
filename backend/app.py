from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure CORS with FRONTEND_URL environment variable
# Supports comma-separated origins for multiple frontends
# Defaults to localhost for local development
frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:8080,http://127.0.0.1:8080')
allowed_origins = [origin.strip() for origin in frontend_url.split(',')]
CORS(app, origins=allowed_origins, supports_credentials=True)

# Database connection pool
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create connection pool
db_pool = SimpleConnectionPool(1, 10, DATABASE_URL)


def get_db_connection():
    """Get a connection from the pool"""
    conn = db_pool.getconn()
    conn.autocommit = False
    return conn


def get_db_cursor(conn):
    """Get a RealDictCursor from a connection"""
    return conn.cursor(cursor_factory=RealDictCursor)


def release_db_connection(conn):
    """Return a connection to the pool"""
    db_pool.putconn(conn)


def init_database():
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Network traffic table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_traffic (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            flags TEXT,
            is_malicious BOOLEAN DEFAULT FALSE,
            threat_type TEXT,
            confidence REAL
        )
    """)

    # Alerts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attack_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT,
            severity TEXT NOT NULL,  -- 'high', 'medium', 'low', 'info'
            status TEXT DEFAULT 'detected',  -- 'detected', 'blocked', 'monitoring', 'resolved'
            description TEXT,
            network_traffic_id INTEGER,
            FOREIGN KEY (network_traffic_id) REFERENCES network_traffic(id)
        )
    """)

    # Reports table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,  -- 'security_analysis', 'threat_analysis', 'intrusion_detection', 'traffic_analysis'
            status TEXT DEFAULT 'pending',  -- 'pending', 'in_progress', 'completed', 'failed'
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            file_path TEXT,
            summary TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ML Model predictions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            model_name TEXT NOT NULL,
            model_version TEXT,
            input_features TEXT,  -- JSON string of features
            prediction TEXT NOT NULL,  -- 'benign', 'malicious', or specific attack type
            confidence REAL,
            is_correct BOOLEAN,  -- For feedback/retraining
            network_traffic_id INTEGER,
            FOREIGN KEY (network_traffic_id) REFERENCES network_traffic(id)
        )
    """)

    # Blocked IPs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id SERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_by INTEGER,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (blocked_by) REFERENCES users(id)
        )
    """)

    # Create indexes for better query performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_network_traffic_timestamp ON network_traffic(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_network_traffic_source_ip ON network_traffic(source_ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ml_predictions_timestamp ON ml_predictions(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)")

    conn.commit()
    cur.close()
    release_db_connection(conn)


def seed_sample_data():
    """Seed the database with sample data for testing"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Check if data already exists
    cur.execute("SELECT COUNT(*) as count FROM network_traffic")
    existing = cur.fetchone()
    if existing['count'] > 0:
        cur.close()
        release_db_connection(conn)
        return

    # Create a default admin user first
    from werkzeug.security import generate_password_hash
    hashed_password = generate_password_hash('admin123')
    cur.execute("""
        INSERT INTO users (full_name, email, username, password)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
        RETURNING id
    """, ('Admin User', 'admin@nids.local', 'admin', hashed_password))

    user_result = cur.fetchone()
    user_id = user_result['id'] if user_result else 1

    # Sample network traffic data - insert and get IDs
    sample_traffic = [
        ('192.168.1.10', '10.0.0.1', 54321, 80, 'TCP', 1500, 'SYN', True, 'DDoS Attack', 0.95),
        ('172.16.0.25', '10.0.0.2', 12345, 3306, 'TCP', 2048, 'PSH,ACK', True, 'SQL Injection', 0.88),
        ('10.0.0.15', '10.0.0.3', 2222, 22, 'TCP', 512, 'SYN', True, 'Brute Force Attack', 0.92),
        ('192.168.0.55', '10.0.0.4', 3333, 80, 'TCP', 1024, 'SYN', True, 'Port Scan', 0.75),
        ('203.0.113.10', '10.0.0.5', 4444, 443, 'TCP', 1500, 'SYN,ACK', False, None, 0.0),
        ('198.51.100.20', '10.0.0.6', 5555, 8080, 'TCP', 2048, 'ACK', False, None, 0.0),
        ('192.168.1.100', '10.0.0.7', 6666, 22, 'TCP', 512, 'SYN', True, 'Brute Force Attack', 0.85),
        ('172.16.1.50', '10.0.0.8', 7777, 3306, 'TCP', 1024, 'PSH,ACK', True, 'SQL Injection', 0.90),
    ]

    traffic_ids = []
    for traffic in sample_traffic:
        cur.execute("""
            INSERT INTO network_traffic (source_ip, destination_ip, source_port, destination_port,
                                         protocol, packet_size, flags, is_malicious, threat_type, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, traffic)
        traffic_ids.append(cur.fetchone()['id'])

    # Sample alerts - use actual traffic IDs
    sample_alerts = [
        ('DDoS Attack', '192.168.1.10', '10.0.0.1', 'high', 'blocked', 'DDoS attack detected from 192.168.1.10', traffic_ids[0]),
        ('SQL Injection', '172.16.0.25', '10.0.0.2', 'high', 'detected', 'SQL injection attempt on database server', traffic_ids[1]),
        ('Brute Force Attack', '10.0.0.15', '10.0.0.3', 'high', 'blocked', 'Multiple failed SSH login attempts', traffic_ids[2]),
        ('Port Scan', '192.168.0.55', '10.0.0.4', 'medium', 'monitoring', 'Port scanning activity detected', traffic_ids[3]),
        ('Brute Force Attack', '192.168.1.100', '10.0.0.7', 'high', 'blocked', 'SSH brute force attack', traffic_ids[6]),
        ('SQL Injection', '172.16.1.50', '10.0.0.8', 'high', 'detected', 'SQL injection attempt on web application', traffic_ids[7]),
    ]

    for alert in sample_alerts:
        cur.execute("""
            INSERT INTO alerts (attack_type, source_ip, destination_ip, severity, status, description, network_traffic_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, alert)

    # Sample reports
    sample_reports = [
        ('Network Security Report', 'security_analysis', 'completed', '/reports/network_security_20260906.pdf', 'Comprehensive network security analysis', user_id),
        ('Threat Detection Report', 'threat_analysis', 'completed', '/reports/threat_detection_20260905.pdf', 'Threat detection and analysis summary', user_id),
        ('Intrusion Analysis Report', 'intrusion_detection', 'completed', '/reports/intrusion_analysis_20260904.pdf', 'Intrusion detection system analysis', user_id),
        ('Network Traffic Report', 'traffic_analysis', 'completed', '/reports/traffic_analysis_20260903.pdf', 'Network traffic pattern analysis', user_id),
    ]

    for report in sample_reports:
        cur.execute("""
            INSERT INTO reports (name, type, status, file_path, summary, user_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, report)

    # Sample ML predictions - use actual traffic IDs
    sample_predictions = [
        ('NIDS-RF-v1', '1.0', '{"packet_size": 1500, "protocol": "TCP", "flags": "SYN"}', 'DDoS Attack', 0.95, traffic_ids[0]),
        ('NIDS-RF-v1', '1.0', '{"packet_size": 2048, "protocol": "TCP", "flags": "PSH,ACK"}', 'SQL Injection', 0.88, traffic_ids[1]),
        ('NIDS-RF-v1', '1.0', '{"packet_size": 512, "protocol": "TCP", "flags": "SYN"}', 'Brute Force Attack', 0.92, traffic_ids[2]),
        ('NIDS-RF-v1', '1.0', '{"packet_size": 1024, "protocol": "TCP", "flags": "SYN"}', 'Port Scan', 0.75, traffic_ids[3]),
        ('NIDS-RF-v1', '1.0', '{"packet_size": 1500, "protocol": "TCP", "flags": "SYN,ACK"}', 'Benign', 0.99, traffic_ids[4]),
        ('NIDS-RF-v1', '1.0', '{"packet_size": 2048, "protocol": "TCP", "flags": "ACK"}', 'Benign', 0.98, traffic_ids[5]),
    ]

    for pred in sample_predictions:
        cur.execute("""
            INSERT INTO ml_predictions (model_name, model_version, input_features, prediction, confidence, network_traffic_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, pred)

    # Sample blocked IPs
    sample_blocked = [
        ('192.168.1.10', 'DDoS Attack', user_id, None),
        ('10.0.0.15', 'Brute Force Attack', user_id, None),
        ('192.168.1.100', 'Brute Force Attack', user_id, None),
    ]

    for blocked in sample_blocked:
        cur.execute("""
            INSERT INTO blocked_ips (ip_address, reason, blocked_by, expires_at)
            VALUES (%s, %s, %s, %s)
        """, blocked)

    conn.commit()
    cur.close()
    release_db_connection(conn)


@app.route("/")
def home():
    return "NIDS Backend is Running!"


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No data received"
        }), 400

    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")

    if not full_name or not email or not username or not password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    if password != confirm_password:
        return jsonify({
            "success": False,
            "message": "Passwords do not match"
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 6 characters"
        }), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cur = get_db_cursor(conn)

        cur.execute("""
            INSERT INTO users (full_name, email, username, password)
            VALUES (%s, %s, %s, %s)
        """, (
            full_name,
            email,
            username,
            hashed_password
        ))

        conn.commit()
        cur.close()
        release_db_connection(conn)

        return jsonify({
            "success": True,
            "message": "Account created successfully"
        }), 201

    except psycopg2.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Username or email already exists"
        }), 409

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No data received"
        }), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        }), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )
    user = cur.fetchone()

    cur.close()
    release_db_connection(conn)

    if user is None:
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

    if not check_password_hash(user["password"], password):
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "username": user["username"]
        }
    }), 200

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Get total traffic count
    cur.execute("SELECT COUNT(*) as count FROM network_traffic")
    total_traffic = cur.fetchone()['count']

    # Get threats detected (malicious traffic)
    cur.execute("SELECT COUNT(*) as count FROM network_traffic WHERE is_malicious = TRUE")
    threats_detected = cur.fetchone()['count']

    # Get detection accuracy from ML predictions
    cur.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN prediction != 'Benign' AND is_malicious = TRUE THEN 1 ELSE 0 END) as true_positives,
            SUM(CASE WHEN prediction = 'Benign' AND is_malicious = FALSE THEN 1 ELSE 0 END) as true_negatives
        FROM ml_predictions mp
        JOIN network_traffic nt ON mp.network_traffic_id = nt.id
    """)
    accuracy_result = cur.fetchone()

    if accuracy_result['total'] > 0:
        correct = (accuracy_result['true_positives'] or 0) + (accuracy_result['true_negatives'] or 0)
        detection_accuracy = round((correct / accuracy_result['total']) * 100, 1)
    else:
        detection_accuracy = 0.0

    # Get blocked IPs count
    cur.execute("SELECT COUNT(*) as count FROM blocked_ips WHERE is_active = TRUE")
    blocked_ips = cur.fetchone()['count']

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "total_traffic": total_traffic,
        "threats_detected": threats_detected,
        "detection_accuracy": detection_accuracy,
        "blocked_ips": blocked_ips
    })

@app.route("/api/alerts", methods=["GET"])
def alerts():
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Get alert statistics
    cur.execute("SELECT COUNT(*) as count FROM alerts")
    total_alerts = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'high'")
    high_risk = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'medium'")
    medium_risk = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'low'")
    low_risk = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'info'")
    info_risk = cur.fetchone()['count']

    # Get recent alerts (last 10)
    cur.execute("""
        SELECT attack_type, source_ip as ip_address,
               to_char(timestamp, 'HH12:MI AM') as time,
               status,
               severity
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    alerts_data = cur.fetchall()

    alerts_list = []
    for alert in alerts_data:
        alerts_list.append({
            "attack_type": alert['attack_type'],
            "ip_address": alert['ip_address'],
            "time": alert['time'],
            "status": alert['status'].capitalize(),
            "severity": alert['severity']
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "total_alerts": total_alerts,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk + info_risk,
        "alerts": alerts_list
    })

@app.route("/api/reports", methods=["GET"])
def reports():
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        SELECT id, name,
               to_char(generated_at, 'DD Mon YYYY') as date,
               type,
               status
        FROM reports
        ORDER BY generated_at DESC
    """)
    reports_data = cur.fetchall()

    reports_list = []
    for report in reports_data:
        # Format type for display
        type_map = {
            'security_analysis': 'Security Analysis',
            'threat_analysis': 'Threat Analysis',
            'intrusion_detection': 'Intrusion Detection',
            'traffic_analysis': 'Traffic Analysis'
        }
        reports_list.append({
            "id": report['id'],
            "name": report['name'],
            "date": report['date'],
            "type": type_map.get(report['type'], report['type']),
            "status": report['status'].capitalize()
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "reports": reports_list
    })

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No data received"
        }), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not username or not email or not new_password or not confirm_password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "message": "Passwords do not match"
        }), 400

    if len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 6 characters"
        }), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute(
        "SELECT * FROM users WHERE username = %s AND email = %s",
        (username, email)
    )
    user = cur.fetchone()

    if user is None:
        cur.close()
        release_db_connection(conn)

        return jsonify({
            "success": False,
            "message": "Username and email do not match"
        }), 404

    hashed_password = generate_password_hash(new_password)

    cur.execute(
        "UPDATE users SET password = %s WHERE username = %s AND email = %s",
        (hashed_password, username, email)
    )

    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": "Password reset successfully"
    }), 200


# ===============================
# NEW API ENDPOINTS FOR ML INTEGRATION AND EXTENDED FUNCTIONALITY
# ===============================

@app.route("/api/network-traffic", methods=["GET"])
def get_network_traffic():
    """Get network traffic data with pagination and filtering"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    is_malicious = request.args.get('is_malicious', type=lambda x: x.lower() == 'true')
    source_ip = request.args.get('source_ip')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Build query
    query = "SELECT * FROM network_traffic WHERE 1=1"
    params = []

    if is_malicious is not None:
        query += " AND is_malicious = %s"
        params.append(is_malicious)

    if source_ip:
        query += " AND source_ip = %s"
        params.append(source_ip)

    if start_date:
        query += " AND timestamp >= %s"
        params.append(start_date)

    if end_date:
        query += " AND timestamp <= %s"
        params.append(end_date)

    # Get total count (without ORDER BY)
    count_query = "SELECT COUNT(*) as count FROM network_traffic WHERE 1=1"
    count_params = []

    if is_malicious is not None:
        count_query += " AND is_malicious = %s"
        count_params.append(is_malicious)

    if source_ip:
        count_query += " AND source_ip = %s"
        count_params.append(source_ip)

    if start_date:
        count_query += " AND timestamp >= %s"
        count_params.append(start_date)

    if end_date:
        count_query += " AND timestamp <= %s"
        count_params.append(end_date)

    cur.execute(count_query, count_params)
    total = cur.fetchone()['count']

    query += " ORDER BY timestamp DESC"

    # Add pagination
    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])

    cur.execute(query, params)
    traffic_data = cur.fetchall()

    traffic_list = []
    for row in traffic_data:
        traffic_list.append({
            "id": row['id'],
            "timestamp": row['timestamp'],
            "source_ip": row['source_ip'],
            "destination_ip": row['destination_ip'],
            "source_port": row['source_port'],
            "destination_port": row['destination_port'],
            "protocol": row['protocol'],
            "packet_size": row['packet_size'],
            "flags": row['flags'],
            "is_malicious": bool(row['is_malicious']),
            "threat_type": row['threat_type'],
            "confidence": row['confidence']
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "data": traffic_list,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page
        }
    })


@app.route("/api/network-traffic", methods=["POST"])
def add_network_traffic():
    """Add new network traffic entry (for ML model or packet capture)"""
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    required_fields = ['source_ip', 'destination_ip', 'protocol']
    for field in required_fields:
        if field not in data:
            return jsonify({"success": False, "message": f"Missing required field: {field}"}), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        INSERT INTO network_traffic (source_ip, destination_ip, source_port, destination_port,
                                     protocol, packet_size, flags, is_malicious, threat_type, confidence)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        data.get('source_ip'),
        data.get('destination_ip'),
        data.get('source_port'),
        data.get('destination_port'),
        data.get('protocol'),
        data.get('packet_size'),
        data.get('flags'),
        data.get('is_malicious', False),
        data.get('threat_type'),
        data.get('confidence')
    ))

    traffic_id = cur.fetchone()['id']
    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": "Network traffic recorded",
        "traffic_id": traffic_id
    }), 201


@app.route("/api/ml/predict", methods=["POST"])
def ml_predict():
    """Endpoint for ML model to submit predictions"""
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    required_fields = ['network_traffic_id', 'model_name', 'prediction', 'confidence']
    for field in required_fields:
        if field not in data:
            return jsonify({"success": False, "message": f"Missing required field: {field}"}), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Verify network traffic exists
    cur.execute("SELECT * FROM network_traffic WHERE id = %s",
              (data['network_traffic_id'],))
    traffic = cur.fetchone()

    if not traffic:
        cur.close()
        release_db_connection(conn)
        return jsonify({"success": False, "message": "Network traffic not found"}), 404

    # Insert prediction
    cur.execute("""
        INSERT INTO ml_predictions (model_name, model_version, input_features, prediction, confidence, network_traffic_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        data['model_name'],
        data.get('model_version', '1.0'),
        json.dumps(data.get('input_features', {})),
        data['prediction'],
        data['confidence'],
        data['network_traffic_id']
    ))

    # Update network traffic with prediction if malicious
    if data['prediction'] != 'Benign':
        cur.execute("""
            UPDATE network_traffic
            SET is_malicious = TRUE, threat_type = %s, confidence = %s
            WHERE id = %s
        """, (data['prediction'], data['confidence'], data['network_traffic_id']))

        # Create alert
        severity_map = {
            'DDoS Attack': 'high',
            'SQL Injection': 'high',
            'Brute Force Attack': 'high',
            'Port Scan': 'medium',
            'Malware': 'high',
            'Phishing': 'medium'
        }
        severity = severity_map.get(data['prediction'], 'medium')

        cur.execute("""
            INSERT INTO alerts (attack_type, source_ip, destination_ip, severity, status, description, network_traffic_id)
            VALUES (%s, %s, %s, %s, 'detected', %s, %s)
        """, (
            data['prediction'],
            traffic['source_ip'],
            traffic['destination_ip'],
            severity,
            f"{data['prediction']} detected by ML model with {data['confidence']*100:.1f}% confidence",
            data['network_traffic_id']
        ))

    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": "Prediction recorded"
    }), 201


@app.route("/api/ml/predictions", methods=["GET"])
def get_ml_predictions():
    """Get ML predictions with pagination"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    model_name = request.args.get('model_name')

    query = """
        SELECT mp.*, nt.source_ip, nt.destination_ip, nt.protocol
        FROM ml_predictions mp
        JOIN network_traffic nt ON mp.network_traffic_id = nt.id
        WHERE 1=1
    """
    params = []

    if model_name:
        query += " AND mp.model_name = %s"
        params.append(model_name)

    # Get total count (without ORDER BY)
    count_query = """
        SELECT COUNT(*) as count
        FROM ml_predictions mp
        JOIN network_traffic nt ON mp.network_traffic_id = nt.id
        WHERE 1=1
    """
    count_params = []

    if model_name:
        count_query += " AND mp.model_name = %s"
        count_params.append(model_name)

    cur.execute(count_query, count_params)
    total = cur.fetchone()['count']

    query += " ORDER BY mp.timestamp DESC"

    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])

    cur.execute(query, params)
    predictions = cur.fetchall()

    pred_list = []
    for row in predictions:
        pred_list.append({
            "id": row['id'],
            "timestamp": row['timestamp'],
            "model_name": row['model_name'],
            "model_version": row['model_version'],
            "input_features": json.loads(row['input_features']) if row['input_features'] else {},
            "prediction": row['prediction'],
            "confidence": row['confidence'],
            "is_correct": row['is_correct'],
            "source_ip": row['source_ip'],
            "destination_ip": row['destination_ip'],
            "protocol": row['protocol']
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "data": pred_list,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page
        }
    })


@app.route("/api/ml/accuracy", methods=["GET"])
def get_ml_accuracy():
    """Get ML model accuracy metrics"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    model_name = request.args.get('model_name')

    query = """
        SELECT
            mp.model_name,
            mp.model_version,
            COUNT(*) as total_predictions,
            SUM(CASE WHEN mp.prediction != 'Benign' AND nt.is_malicious = TRUE THEN 1 ELSE 0 END) as true_positives,
            SUM(CASE WHEN mp.prediction = 'Benign' AND nt.is_malicious = FALSE THEN 1 ELSE 0 END) as true_negatives,
            SUM(CASE WHEN mp.prediction != 'Benign' AND nt.is_malicious = FALSE THEN 1 ELSE 0 END) as false_positives,
            SUM(CASE WHEN mp.prediction = 'Benign' AND nt.is_malicious = TRUE THEN 1 ELSE 0 END) as false_negatives
        FROM ml_predictions mp
        JOIN network_traffic nt ON mp.network_traffic_id = nt.id
    """
    params = []

    if model_name:
        query += " WHERE mp.model_name = %s"
        params.append(model_name)

    query += " GROUP BY mp.model_name, mp.model_version"

    cur.execute(query, params)
    results = cur.fetchall()

    accuracy_data = []
    for row in results:
        total = row['total_predictions']
        tp = row['true_positives'] or 0
        tn = row['true_negatives'] or 0
        fp = row['false_positives'] or 0
        fn = row['false_negatives'] or 0

        accuracy = round(((tp + tn) / total * 100), 2) if total > 0 else 0
        precision = round((tp / (tp + fp) * 100), 2) if (tp + fp) > 0 else 0
        recall = round((tp / (tp + fn) * 100), 2) if (tp + fn) > 0 else 0
        f1 = round((2 * precision * recall / (precision + recall)), 2) if (precision + recall) > 0 else 0

        accuracy_data.append({
            "model_name": row['model_name'],
            "model_version": row['model_version'],
            "total_predictions": total,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "data": accuracy_data
    })


@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    """Get list of blocked IPs"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        SELECT ip_address, reason, blocked_at, expires_at, is_active
        FROM blocked_ips
        WHERE is_active = TRUE
        ORDER BY blocked_at DESC
    """)
    blocked = cur.fetchall()

    blocked_list = []
    for row in blocked:
        blocked_list.append({
            "ip_address": row['ip_address'],
            "reason": row['reason'],
            "blocked_at": row['blocked_at'],
            "expires_at": row['expires_at'],
            "is_active": bool(row['is_active'])
        })

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "data": blocked_list
    })


@app.route("/api/blocked-ips", methods=["POST"])
def block_ip():
    """Block an IP address"""
    data = request.get_json()

    if not data or 'ip_address' not in data:
        return jsonify({"success": False, "message": "IP address required"}), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    try:
        cur.execute("""
            INSERT INTO blocked_ips (ip_address, reason, blocked_by, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (
            data['ip_address'],
            data.get('reason', 'Manual block'),
            data.get('blocked_by', 1),
            data.get('expires_at')
        ))
        conn.commit()
        cur.close()
        release_db_connection(conn)

        return jsonify({
            "success": True,
            "message": f"IP {data['ip_address']} blocked successfully"
        }), 201
    except psycopg2.IntegrityError:
        cur.close()
        release_db_connection(conn)
        return jsonify({
            "success": False,
            "message": "IP address already blocked"
        }), 409


@app.route("/api/blocked-ips/<ip_address>", methods=["DELETE"])
def unblock_ip(ip_address):
    """Unblock an IP address"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("UPDATE blocked_ips SET is_active = FALSE WHERE ip_address = %s", (ip_address,))
    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": f"IP {ip_address} unblocked successfully"
    })

@app.route("/api/reports/<int:report_id>", methods=["GET"])
def get_report_detail(report_id):
    """Get detailed report information"""

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        SELECT
            id,
            name,
            type,
            status,
            generated_at,
            completed_at,
            file_path,
            summary
        FROM reports
        WHERE id = %s
    """, (report_id,))

    report = cur.fetchone()

    cur.close()
    release_db_connection(conn)

    if not report:
        return jsonify({
            "success": False,
            "message": "Report not found"
        }), 404

    type_map = {
        "security_analysis": "Security Analysis",
        "threat_analysis": "Threat Analysis",
        "intrusion_detection": "Intrusion Detection",
        "traffic_analysis": "Traffic Analysis"
    }

    return jsonify({
        "success": True,
        "data": {
            "id": report["id"],
            "name": report["name"],
            "type": type_map.get(report["type"], report["type"]),
            "status": report["status"].capitalize(),
            "generated_at": report["generated_at"],
            "completed_at": report["completed_at"],
            "file_path": report["file_path"],
            "summary": report["summary"]
        }
    })
# your existing get_report_detail() function ends here


@app.route("/api/reports/<int:report_id>/download", methods=["GET"])
def download_report(report_id):
    """Download a report PDF"""

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        SELECT id, name, file_path
        FROM reports
        WHERE id = %s
    """, (report_id,))

    report = cur.fetchone()

    cur.close()
    release_db_connection(conn)

    if not report:
        return jsonify({
            "success": False,
            "message": "Report not found"
        }), 404

    file_path = report["file_path"]

    if not file_path:
        return jsonify({
            "success": False,
            "message": "PDF file is not available for this report"
        }), 404

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    relative_path = file_path.lstrip("/\\")
    local_file = os.path.join(backend_dir, relative_path)

    if not os.path.isfile(local_file):
        return jsonify({
            "success": False,
            "message": "PDF file is not available on the server yet"
        }), 404

    from flask import send_file

    return send_file(
        local_file,
        as_attachment=True,
        download_name=os.path.basename(local_file),
        mimetype="application/pdf"
    )
@app.route("/api/reports", methods=["POST"])
def create_report():
    """Create a new report"""
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    required_fields = ['name', 'type']
    for field in required_fields:
        if field not in data:
            return jsonify({"success": False, "message": f"Missing required field: {field}"}), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        INSERT INTO reports (name, type, status, summary, user_id)
        VALUES (%s, %s, 'pending', %s, %s)
        RETURNING id
    """, (
        data['name'],
        data['type'],
        data.get('summary', ''),
        data.get('user_id', 1)
    ))

    report_id = cur.fetchone()['id']
    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": "Report created",
        "report_id": report_id
    }), 201


@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert_detail(alert_id):
    """Get detailed alert information"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("""
        SELECT a.*, nt.source_port, nt.destination_port, nt.protocol, nt.packet_size, nt.flags
        FROM alerts a
        LEFT JOIN network_traffic nt ON a.network_traffic_id = nt.id
        WHERE a.id = %s
    """, (alert_id,))
    alert = cur.fetchone()

    cur.close()
    release_db_connection(conn)

    if not alert:
        return jsonify({"success": False, "message": "Alert not found"}), 404

    return jsonify({
        "success": True,
        "data": {
            "id": alert['id'],
            "timestamp": alert['timestamp'],
            "attack_type": alert['attack_type'],
            "source_ip": alert['source_ip'],
            "destination_ip": alert['destination_ip'],
            "source_port": alert['source_port'],
            "destination_port": alert['destination_port'],
            "protocol": alert['protocol'],
            "packet_size": alert['packet_size'],
            "flags": alert['flags'],
            "severity": alert['severity'],
            "status": alert['status'],
            "description": alert['description']
        }
    })


@app.route("/api/alerts/<int:alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    """Update alert status"""
    data = request.get_json()

    if not data or 'status' not in data:
        return jsonify({"success": False, "message": "Status required"}), 400

    valid_statuses = ['detected', 'blocked', 'monitoring', 'resolved']
    if data['status'] not in valid_statuses:
        return jsonify({"success": False, "message": "Invalid status"}), 400

    conn = get_db_connection()
    cur = get_db_cursor(conn)

    cur.execute("UPDATE alerts SET status = %s WHERE id = %s", (data['status'], alert_id))
    conn.commit()
    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "message": "Alert status updated"
    })


@app.route("/api/stats/summary", methods=["GET"])
def get_stats_summary():
    """Get comprehensive statistics summary"""
    conn = get_db_connection()
    cur = get_db_cursor(conn)

    # Traffic stats
    cur.execute("SELECT COUNT(*) as count FROM network_traffic")
    total_traffic = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM network_traffic WHERE is_malicious = TRUE")
    malicious_traffic = cur.fetchone()['count']
    benign_traffic = total_traffic - malicious_traffic

    # Alert stats by severity
    cur.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
    alert_severity = cur.fetchall()

    # Alert stats by status
    cur.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
    alert_status = cur.fetchall()

    # Top attacking IPs
    cur.execute("""
        SELECT source_ip, COUNT(*) as attack_count
        FROM alerts
        GROUP BY source_ip
        ORDER BY attack_count DESC
        LIMIT 10
    """)
    top_attackers = cur.fetchall()

    # Attack type distribution
    cur.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM alerts
        GROUP BY attack_type
        ORDER BY count DESC
    """)
    attack_types = cur.fetchall()

    # Traffic over time (last 24 hours)
    cur.execute("""
        SELECT
            to_char(timestamp, 'YYYY-MM-DD HH24:00') as hour,
            COUNT(*) as total,
            SUM(CASE WHEN is_malicious = TRUE THEN 1 ELSE 0 END) as malicious
        FROM network_traffic
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
    """)
    traffic_timeline = cur.fetchall()

    cur.close()
    release_db_connection(conn)

    return jsonify({
        "success": True,
        "data": {
            "traffic": {
                "total": total_traffic,
                "malicious": malicious_traffic,
                "benign": benign_traffic,
                "malicious_percentage": round((malicious_traffic / total_traffic * 100), 2) if total_traffic > 0 else 0
            },
            "alerts_by_severity": {row['severity']: row['count'] for row in alert_severity},
            "alerts_by_status": {row['status']: row['count'] for row in alert_status},
            "top_attackers": [{"ip": row['source_ip'], "count": row['attack_count']} for row in top_attackers],
            "attack_types": [{"type": row['attack_type'], "count": row['count']} for row in attack_types],
            "traffic_timeline": [
                {"hour": row['hour'], "total": row['total'], "malicious": row['malicious']}
                for row in traffic_timeline
            ]
        }
    })


if __name__ == "__main__":
    init_database()
    seed_sample_data()
    app.run(debug=True)
