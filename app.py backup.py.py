from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import mysql.connector
from mysql.connector import Error
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

app = Flask(__name__, static_folder=".")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-secret-key-before-production")

MODEL_FILE = "threat_model.joblib"

# -----------------------------
# Demo training data
# Replace/extend this with your
# real labelled cybersecurity
# dataset for a stronger model.
# -----------------------------
TRAINING_TEXTS = [
    "malware exe download executable payload trojan virus",
    "run this bat script powershell payload malicious file",
    "suspicious executable attachment ransomware malware",
    "fake login verify account password reset http link",
    "urgent account update click login credentials",
    "free reward claim verify identity phishing link",
    "credential harvesting fake banking portal",
    "otp password brute force admin 1234 authentication attack",
    "multiple password attempts otp bypass admin login",
    "brute force credential attack",
    "urgent invoice attached payment request",
    "unknown sender invoice claim attachment email",
    "business email compromise urgent payment",
    "hello meeting tomorrow agenda",
    "thank you for the information",
    "google.com normal website",
    "safe internal network traffic",
]
TRAINING_LABELS = [
    "Malware", "Malware", "Malware",
    "Phishing", "Phishing", "Phishing", "Phishing",
    "Password/OTP Attack", "Password/OTP Attack", "Password/OTP Attack",
    "Suspicious Mail", "Suspicious Mail", "Suspicious Mail",
    "Safe", "Safe", "Safe", "Safe"
]

def get_model():
    if os.path.exists(MODEL_FILE):
        try:
            return joblib.load(MODEL_FILE)
        except Exception:
            pass

    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
        ("classifier", LogisticRegression(max_iter=2000, random_state=42))
    ])
    model.fit(TRAINING_TEXTS, TRAINING_LABELS)
    joblib.dump(model, MODEL_FILE)
    return model

MODEL = get_model()

# -----------------------------
# MySQL configuration
# Set these environment vars
# before running if needed:
# DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
# -----------------------------
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cyber_threat_db"),
}

def db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def init_db():
    # First connect without selecting a database.
    base = dict(DB_CONFIG)
    db_name = base.pop("database")
    conn = mysql.connector.connect(**base)
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.close()
    conn.close()

    conn = db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            source TEXT NOT NULL,
            prediction VARCHAR(50) NOT NULL,
            confidence DECIMAL(5,2) NOT NULL,
            INDEX idx_timestamp (timestamp),
            INDEX idx_prediction (prediction)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            created_at DATETIME NOT NULL
        )
    """)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'")
    except Error:
        pass
    conn.commit()
    cur.close()
    conn.close()

def db_is_available():
    try:
        conn = db_connection()
        conn.close()
        return True
    except Error:
        return False

def login_required():
    return "user_id" in session


def developer_required():
    return login_required() and session.get("role") == "developer"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if login_required():
            return redirect(url_for("home"))
        return send_from_directory(".", "login.html")

    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        if request.is_json:
            return jsonify({"error": "Username and password are required."}), 400
        return redirect(url_for("login"))

    try:
        conn = db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
    except Error as exc:
        if request.is_json:
            return jsonify({"error": "Database error.", "details": str(exc)}), 500
        return "Database error. Make sure MySQL is running and configured.", 500

    if not user or not check_password_hash(user["password_hash"], password):
        if request.is_json:
            return jsonify({"error": "Invalid username or password."}), 401
        return redirect(url_for("login", error="1"))

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    if request.is_json:
        return jsonify({"success": True, "redirect": "/"})
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        if login_required():
            return redirect(url_for("home"))
        return send_from_directory(".", "register.html")

    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if len(username) < 3 or len(username) > 100:
        return jsonify({"error": "Username must be between 3 and 100 characters."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Username already exists. Please choose another."}), 409

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)",
            (username, password_hash, "user", datetime.now())
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True})
    except Error as exc:
        return jsonify({"error": "Database error. Please try again.", "details": str(exc)}), 500


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/developer")
def developer():
    if not developer_required():
        return redirect(url_for("home")) if login_required() else redirect(url_for("login"))
    return send_from_directory(".", "developer.html")


@app.route("/")
def home():
    if not login_required():
        return redirect(url_for("login"))
    return send_from_directory(".", "index.html")

@app.route("/api/me")
def me():
    if not login_required():
        return jsonify({"error": "Authentication required."}), 401
    return jsonify({
        "username": session.get("username"),
        "role": session.get("role", "user")
    })


@app.route("/api/db-status")
def db_status():
    if not login_required():
        return jsonify({"error": "Authentication required."}), 401

    return jsonify({"connected": db_is_available()})

@app.route("/api/scan", methods=["POST"])
def scan():
    if not login_required():
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    user_input = str(data.get("input", "")).strip()

    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    probabilities = MODEL.predict_proba([user_input])[0]
    classes = MODEL.classes_
    best_index = probabilities.argmax()
    prediction = str(classes[best_index])
    confidence = round(float(probabilities[best_index]) * 100, 2)

    # Store every scan in MySQL.
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO threat_logs
            (timestamp, source, prediction, confidence)
            VALUES (%s, %s, %s, %s)
            """,
            (datetime.now(), user_input, prediction, confidence)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Error as exc:
        return jsonify({
            "error": "Prediction succeeded, but MySQL storage failed.",
            "details": str(exc)
        }), 500

    return jsonify({
        "prediction": prediction,
        "confidence": confidence
    })

@app.route("/api/logs")
def logs():
    if not developer_required():
        return jsonify({"error": "Developer access required."}), 403

    try:
        limit = min(max(int(request.args.get("limit", 8)), 1), 50)
        conn = db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, timestamp, source, prediction, confidence
            FROM threat_logs
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,)
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        for row in rows:
            row["timestamp"] = row["timestamp"].isoformat()

        return jsonify({"logs": rows})
    except (Error, ValueError) as exc:
        return jsonify({"error": str(exc)}), 500

@app.route("/api/stats")
def stats():
    if not login_required():
        return jsonify({"error": "Authentication required."}), 401

    try:
        conn = db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT prediction, COUNT(*) AS count FROM threat_logs GROUP BY prediction")
        rows = cur.fetchall()
        cur.close()
        conn.close()

        counts = {
            "Malware": 0,
            "Phishing": 0,
            "Password/OTP Attack": 0,
            "Suspicious Mail": 0,
            "Safe": 0
        }
        for row in rows:
            counts[row["prediction"]] = int(row["count"])

        total = sum(counts.values())
        percentages = {
            key: round((value / total) * 100, 1) if total else 0
            for key, value in counts.items()
        }

        return jsonify({
            "total": total,
            "counts": counts,
            "percentages": percentages
        })
    except Error as exc:
        return jsonify({"error": str(exc)}), 500

if __name__ == "__main__":
    try:
        init_db()
        print("MySQL database/table ready.")
    except Error as exc:
        print("\nWARNING: MySQL is not available yet.")
        print("Flask will still start, but scans cannot be saved until MySQL is configured.")
        print("MySQL error:", exc)

    app.run(debug=True)
