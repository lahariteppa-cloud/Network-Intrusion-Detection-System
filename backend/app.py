from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)
CORS(app)

DATABASE = "nids.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


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

        conn.execute("""
            INSERT INTO users (full_name, email, username, password)
            VALUES (?, ?, ?, ?)
        """, (
            full_name,
            email,
            username,
            hashed_password
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Account created successfully"
        }), 201

    except sqlite3.IntegrityError:
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

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

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
    return jsonify({
        "success": True,
        "total_traffic": 12845,
        "threats_detected": 27,
        "detection_accuracy": 99.2,
        "blocked_ips": 15
    })

@app.route("/api/alerts", methods=["GET"])
def alerts():
    return jsonify({
        "success": True,
        "total_alerts": 27,
        "high_risk": 12,
        "medium_risk": 8,
        "low_risk": 7,
        "alerts": [
            {
                "attack_type": "DDoS Attack",
                "ip_address": "192.168.1.10",
                "time": "10:20 AM",
                "status": "Blocked"
            },
            {
                "attack_type": "SQL Injection",
                "ip_address": "172.16.0.25",
                "time": "10:45 AM",
                "status": "Detected"
            },
            {
                "attack_type": "Brute Force Attack",
                "ip_address": "10.0.0.15",
                "time": "11:10 AM",
                "status": "Blocked"
            },
            {
                "attack_type": "Port Scan",
                "ip_address": "192.168.0.55",
                "time": "11:35 AM",
                "status": "Monitoring"
            }
        ]
    })

@app.route("/api/reports", methods=["GET"])
def reports():
    return jsonify({
        "success": True,
        "reports": [
            {
                "id": 1,
                "name": "Network Security Report",
                "date": "06 Sep 2026",
                "type": "Security Analysis",
                "status": "Completed"
            },
            {
                "id": 2,
                "name": "Threat Detection Report",
                "date": "05 Sep 2026",
                "type": "Threat Analysis",
                "status": "Completed"
            },
            {
                "id": 3,
                "name": "Intrusion Analysis Report",
                "date": "04 Sep 2026",
                "type": "Intrusion Detection",
                "status": "Completed"
            },
            {
                "id": 4,
                "name": "Network Traffic Report",
                "date": "03 Sep 2026",
                "type": "Traffic Analysis",
                "status": "Completed"
            }
        ]
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

    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND email = ?",
        (username, email)
    ).fetchone()

    if user is None:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Username and email do not match"
        }), 404

    hashed_password = generate_password_hash(new_password)

    conn.execute(
        "UPDATE users SET password = ? WHERE username = ? AND email = ?",
        (hashed_password, username, email)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Password reset successfully"
    }), 200
if __name__ == "__main__":
    init_database()
    app.run(debug=True)