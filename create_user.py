import os
import getpass
import mysql.connector
from werkzeug.security import generate_password_hash

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cyber_threat_db"),
}

username = input("Enter login username: ").strip()
password = getpass.getpass("Enter password: ")
confirm = getpass.getpass("Confirm password: ")
role = input("Role (user/developer) [user]: ").strip().lower() or "user"

if role not in ("user", "developer"):
    raise SystemExit("Role must be 'user' or 'developer'.")

if not username or not password:
    raise SystemExit("Username and password are required.")
if password != confirm:
    raise SystemExit("Passwords do not match.")

conn = mysql.connector.connect(**DB_CONFIG)
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        created_at DATETIME NOT NULL
    )
""")
cur.execute("""
    INSERT INTO users (username, password_hash, role, created_at)
    VALUES (%s, %s, %s, NOW())
    ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), role=VALUES(role)
""", (username, generate_password_hash(password), role))
conn.commit()
cur.close()
conn.close()

print(f"User '{username}' is ready. You can now log in.")
