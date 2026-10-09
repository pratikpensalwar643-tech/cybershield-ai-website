from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import mysql.connector
from mysql.connector import Error, pooling
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

app = Flask(__name__, static_folder=".")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Unique normal-user presence. Multiple tabs for the same username count once.
ACTIVE_USERS = {}
ACTIVE_USER_TIMEOUT = 60*1

app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-secret-key-before-production")
DEVELOPER_COOKIE_NAME = "cyber_developer_session"
DEVELOPER_COOKIE_MAX_AGE = 60 * 60 * 12

def developer_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="cyber-developer-session-v1")

def get_developer_identity():
    token = request.cookies.get(DEVELOPER_COOKIE_NAME)
    if not token:
        return None
    try:
        data = developer_serializer().loads(token, max_age=DEVELOPER_COOKIE_MAX_AGE)
        if data.get("role") != "developer" or not data.get("user_id"):
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None


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
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cyber_threat_db"),
    "ssl_disabled": False,
    "connection_timeout": 10,
}

# Reuse MySQL connections instead of opening a brand-new TCP connection
# for every dashboard API request. This noticeably reduces page load time
# when MySQL is hosted remotely.
DB_POOL = None
DB_POOL_LOCK = None

def _get_db_pool():
    global DB_POOL, DB_POOL_LOCK
    if DB_POOL is None:
        import threading
        if DB_POOL_LOCK is None:
            DB_POOL_LOCK = threading.Lock()
        with DB_POOL_LOCK:
            if DB_POOL is None:
                pool_config = dict(DB_CONFIG)
                pool_config.setdefault("connection_timeout", 8)
                DB_POOL = pooling.MySQLConnectionPool(
                    pool_name="cyber_threat_pool",
                    pool_size=8,
                    pool_reset_session=True,
                    **pool_config
                )
    return DB_POOL

def db_connection():
    return _get_db_pool().get_connection()

def init_db():
    # Connect directly to the configured database

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
        CREATE TABLE IF NOT EXISTS site_visitors (
            visitor_id VARCHAR(64) PRIMARY KEY,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL
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

DB_STATUS_CACHE = {"value": None, "checked_at": 0.0}
DB_STATUS_CACHE_TTL = 5.0

def db_is_available():
    now = time.time()
    if DB_STATUS_CACHE["value"] is not None and now - DB_STATUS_CACHE["checked_at"] < DB_STATUS_CACHE_TTL:
        return bool(DB_STATUS_CACHE["value"])

    try:
        conn = db_connection()
        conn.close()
        DB_STATUS_CACHE["value"] = True
    except Error:
        DB_STATUS_CACHE["value"] = False
    DB_STATUS_CACHE["checked_at"] = now
    return bool(DB_STATUS_CACHE["value"])

TAB_SESSION_MAX_AGE = 60 * 60 * 12
TAB_SESSION_STORAGE_KEY = "cybershield_tab_token"

def tab_session_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="cyber-tab-session-v1")

def create_tab_token(user_id, username, role):
    return tab_session_serializer().dumps({
        "user_id": int(user_id),
        "username": str(username),
        "role": role
    })

def get_tab_identity():
    token = request.headers.get("X-Tab-Session", "").strip()
    if not token:
        return None
    try:
        data = tab_session_serializer().loads(token, max_age=TAB_SESSION_MAX_AGE)
        if not data.get("user_id") or not data.get("username"):
            return None
        if data.get("role") not in {"user", "developer"}:
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None

def login_required():
    identity = get_tab_identity()
    return identity is not None and identity.get("role") == "user"

def developer_required():
    identity = get_tab_identity()
    return identity is not None and identity.get("role") == "developer"


def login_mode_from_request(data=None):
    """Resolve whether /login was opened in normal or developer mode.

    The existing login.html POSTs to /login without forwarding ?mode=developer.
    We therefore also inspect the page referrer so developer login cannot
    accidentally create a normal-user session.
    """
    data = data or {}
    mode = str(data.get("mode") or request.args.get("mode") or request.cookies.get("login_mode") or "").strip().lower()
    if mode in {"user", "developer"}:
        return mode

    referrer = request.referrer or ""
    try:
        query = parse_qs(urlparse(referrer).query)
        ref_mode = str(query.get("mode", [""])[0]).strip().lower()
        if ref_mode in {"user", "developer"}:
            return ref_mode
    except Exception:
        pass

    return "user"


def request_is_developer_dashboard():
    """True when an API request originated from the developer dashboard."""
    path = urlparse(request.referrer or "").path.rstrip("/")
    return path in {"/developer/dashboard", "/developer"}


def request_is_user_dashboard():
    """True when an API request originated from the normal dashboard."""
    path = urlparse(request.referrer or "").path.rstrip("/")
    return path in {"", "/"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        mode = request.args.get("mode", "user").lower()
        if mode == "developer":
            response = send_from_directory(".", "login.html")
            # login.html submits POST /login without the query string. Keep
            # the requested mode briefly so the server can still distinguish
            # developer login from normal-user login.
            response.set_cookie("login_mode", "developer", max_age=300, httponly=True, samesite="Lax", path="/login")
            return response
        response = send_from_directory(".", "login.html")
        response.set_cookie("login_mode", "user", max_age=300, httponly=True, samesite="Lax", path="/login")
        return response

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

    # Developer login is kept separate from the normal-user session.
    # This allows a normal user and a developer to be logged in at the
    # same time in the same browser without overwriting each other.
    mode = login_mode_from_request(data)

    if mode == "developer":
        if user["role"] != "developer":
            if request.is_json:
                return jsonify({"error": "Developer access required."}), 403
            return redirect(url_for("login", mode="developer", error="developer"))
        token = developer_serializer().dumps({
            "user_id": user["id"],
            "username": user["username"],
            "role": "developer"
        })

        tab_token = create_tab_token(user["id"], user["username"], "developer")
        response = jsonify({"success": True, "redirect": "/developer", "tab_token": tab_token}) if request.is_json else redirect(url_for("developer"))
        response.set_cookie(
            DEVELOPER_COOKIE_NAME,
            token,
            max_age=DEVELOPER_COOKIE_MAX_AGE,
            httponly=True,
            samesite="Lax",
            secure=False
        )
        response.delete_cookie("login_mode", path="/login")
        return response

    session.clear()
    session.permanent = False

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    try:
        conn = db_connection()
        cur = conn.cursor()
        visitor_id = f"user_{user['id']}"
        now = datetime.now()

        cur.execute(
            "SELECT visitor_id FROM site_visitors WHERE visitor_id=%s",
            (visitor_id,)
        )
        if cur.fetchone():
            cur.execute(
                "UPDATE site_visitors SET last_seen=%s WHERE visitor_id=%s",
                (now, visitor_id)
            )
        else:
            cur.execute(
                "INSERT INTO site_visitors (visitor_id, first_seen, last_seen) VALUES (%s,%s,%s)",
                (visitor_id, now, now)
            )

        conn.commit()
        cur.close()
        conn.close()
    except Error:
      pass

    tab_token = create_tab_token(user["id"], user["username"], "user")
    if request.is_json:
        response = jsonify({"success": True, "redirect": "/", "tab_token": tab_token})
    else:
        response = redirect(url_for("home"))
    response.delete_cookie("login_mode", path="/login")
    return response


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
    # Tab-specific logout is performed by the page using sessionStorage.
    # Do not clear shared browser cookies, which could disrupt other tabs.
    return redirect(url_for("login"))

@app.route("/developer-logout")
def developer_logout():
    # Keep shared developer cookie intact for other open tabs.
    return redirect(url_for("login", mode="developer"))


@app.route("/developer/dashboard")
def developer_dashboard():
    if not get_developer_identity():
        return redirect(url_for("login", mode="developer"))

    response = send_from_directory(".", "index.html")
    response.set_cookie("dashboard_view", "developer", max_age=60*60*12, samesite="Lax")
    return response


@app.route("/developer")
def developer():
    if not get_developer_identity():
        return redirect(url_for("login", mode="developer"))
    return send_from_directory(".", "developer.html")


@app.route("/logo.png")
def logo():
    return send_from_directory(".", "logo.png")

@app.route("/")
def home():
    # HTML navigation cannot send sessionStorage tokens, so use the Flask
    # browser session only to serve the shell. APIs validate the tab token.
    if "user_id" not in session:
     return redirect(url_for("login"))

    visitor_id = f"user_{session['user_id']}"
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT visitor_id FROM site_visitors WHERE visitor_id=%s", (visitor_id,))
        exists = cur.fetchone()
        now = datetime.now()
        if exists:
            cur.execute("UPDATE site_visitors SET last_seen=%s WHERE visitor_id=%s", (now, visitor_id))
        else:
            cur.execute(
                "INSERT INTO site_visitors (visitor_id, first_seen, last_seen) VALUES (%s,%s,%s)",
                (visitor_id, now, now)
            )
        conn.commit()
        cur.close()
        conn.close()
    except Error:
        pass

    response = send_from_directory(".", "index.html")
    response.set_cookie("site_visitor_id", visitor_id, max_age=60*60*24*365, httponly=True, samesite="Lax")
    response.set_cookie("dashboard_view", "user", max_age=60*60*12, samesite="Lax")
    return response


@app.route("/api/presence", methods=["POST"])
def presence():
    identity = get_tab_identity()
    if not identity or identity.get("role") != "user":
        return jsonify({"error": "Authentication required."}), 401

    username = identity.get("username")
    if username:
        ACTIVE_USERS[username] = time.time()

    return jsonify({"success": True})


@app.route("/api/website-visitors")
def website_visitors():
    if not login_required() and not developer_required():
        return jsonify({"error": "Authentication required."}), 401
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM site_visitors")
        total = int(cur.fetchone()[0])
        cur.close()
        conn.close()
        return jsonify({"total_visitors": total})
    except Error as exc:
        return jsonify({"error": "Database error.", "details": str(exc)}), 500


@app.route("/api/active-users")
def active_users():
    if not developer_required():
        return jsonify({"error": "Developer access required."}), 403

    now = time.time()
    expired = [
        username for username, last_seen in ACTIVE_USERS.items()
        if now - last_seen > ACTIVE_USER_TIMEOUT
    ]
    for username in expired:
        ACTIVE_USERS.pop(username, None)

    return jsonify({"active_users": len(ACTIVE_USERS)})


@app.route("/api/me")
def me():
    identity = get_tab_identity()
    if not identity:
        return jsonify({"error": "Authentication required."}), 401

    is_developer = identity.get("role") == "developer"
    return jsonify({
        "username": identity.get("username"),
        "role": identity.get("role"),
        "developer_logged_in": is_developer,
        "developer_username": identity.get("username") if is_developer else None,
        "user_logged_in": not is_developer,
        "user_username": identity.get("username") if not is_developer else None
    })


@app.route("/api/db-status")
def db_status():
    # Both normal-user and developer sessions may view the connection indicator.
    if not login_required() and not developer_required():
        return jsonify({"error": "Authentication required."}), 401

    return jsonify({"connected": db_is_available()})

@app.route("/api/scan", methods=["POST"])
def scan():
    # Scanning is available to both authenticated normal users and developers.
    if not login_required() and not developer_required():
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
        STATS_CACHE["data"] = None
        STATS_CACHE["checked_at"] = 0.0
    except Error as exc:
        return jsonify({
            "error": "Prediction succeeded, but MySQL storage failed.",
            "details": str(exc)
        }), 500

    return jsonify({
        "prediction": prediction,
        "confidence": confidence
    })


@app.route("/api/developer-control-center")
def developer_control_center():
    if not developer_required():
        return jsonify({"error": "Developer access required."}), 403

    try:
        conn = db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(CASE WHEN prediction <> 'Safe' THEN 1 ELSE 0 END), 0) AS threats
            FROM threat_logs
        """)
        row = cur.fetchone() or {}
        cur.close()
        conn.close()

        return jsonify({
            "live_scans": int(row.get("total_scans") or 0),
            "threats": int(row.get("threats") or 0)
        })
    except Error as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/developer-live-vectors")
def developer_live_vectors():
    if not developer_required():
        return jsonify({"error": "Developer access required."}), 403

    try:
        conn = db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN prediction = 'Malware' THEN 1 ELSE 0 END), 0) AS malware,
                COALESCE(SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END), 0) AS phishing,
                COALESCE(SUM(CASE WHEN prediction = 'Password/OTP Attack' THEN 1 ELSE 0 END), 0) AS auth,
                COALESCE(SUM(CASE WHEN prediction = 'Suspicious Mail' THEN 1 ELSE 0 END), 0) AS mail,
                COALESCE(SUM(CASE WHEN prediction = 'Safe' THEN 1 ELSE 0 END), 0) AS safe,
                COALESCE(SUM(CASE WHEN prediction <> 'Safe' THEN 1 ELSE 0 END), 0) AS threats
            FROM threat_logs
        """)
        row = cur.fetchone() or {}
        cur.close()
        conn.close()

        return jsonify({
            "total": int(row.get("total") or 0),
            "threats": int(row.get("threats") or 0),
            "malware": int(row.get("malware") or 0),
            "phishing": int(row.get("phishing") or 0),
            "auth": int(row.get("auth") or 0),
            "mail": int(row.get("mail") or 0),
            "safe": int(row.get("safe") or 0)
        })
    except Error as exc:
        return jsonify({"error": str(exc)}), 500

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

STATS_CACHE = {"data": None, "checked_at": 0.0}
STATS_CACHE_TTL = 2.0

@app.route("/api/stats")
def stats():
    # Stats are used by both dashboards.
    if not login_required() and not developer_required():
        return jsonify({"error": "Authentication required."}), 401

    now = time.time()
    if STATS_CACHE["data"] is not None and now - STATS_CACHE["checked_at"] < STATS_CACHE_TTL:
        return jsonify(STATS_CACHE["data"])

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

        result = {
            "total": total,
            "counts": counts,
            "percentages": percentages
        }
        STATS_CACHE["data"] = result
        STATS_CACHE["checked_at"] = now
        return jsonify(result)
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

    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
