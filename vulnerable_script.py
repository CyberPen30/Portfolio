#!/usr/bin/env python3
"""
Patched vulnerable_script.py — secure Flask app keeping original features.

Security fixes:
- Input validation & sanitization
- Strong password hashing (werkzeug)
- Session fixation protection (session.clear())
- Removed insecure pickle, replaced with JSON
- Replaced xml.etree with defusedxml (prevents XXE)
- Removed shell=True execution; implemented command whitelist
- Secure file upload (secure_filename, extension whitelist, size limit)
- Log safely via logger, not raw writes
- Environment-based secrets (no hardcoded secret keys)
"""

import os
import re
import json
import secrets
import sqlite3
import hmac
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from flask import (
    Flask, request, session, redirect, render_template_string,
    make_response, jsonify, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from defusedxml.ElementTree import fromstring as safe_fromstring

# ------------------- App config -------------------
app = Flask(__name__)

# Use env var for secret key; fallback to strong random (do NOT hardcode)
app.secret_key = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)

BASE_DIR = Path.home() / "vuln_lab"
UPLOAD_DIR = BASE_DIR / "uploads"
LOG_DIR = BASE_DIR / "logs"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR) + os.sep
app.config['LOG_PATH'] = str(LOG_DIR) + os.sep
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

# Configure logger (do not log raw user input)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(app.config['LOG_PATH'], 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ------------------- DB helpers -------------------
DB_PATH = BASE_DIR / "enterprise.db"

def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    db = get_db_connection()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      role TEXT DEFAULT 'user',
      reset_token TEXT,
      reset_expires TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY,
      bio TEXT,
      website TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT NOT NULL,
      price REAL,
      description TEXT
    );
    CREATE TABLE IF NOT EXISTS user_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      original_name TEXT,
      stored_name TEXT,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()
    db.close()

init_database()

# ------------------- Utilities -------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,30}$')
EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
ALLOWED_EXT = {'jpg','jpeg','png','pdf','txt'}

def valid_username(u):
    return bool(USERNAME_RE.match(u or ""))

def valid_email(e):
    return bool(EMAIL_RE.match(e or ""))

def sanitize_text(s, maxlen=2000):
    if s is None:
        return ""
    return str(s).strip()[:maxlen]

def allowed_file(filename):
    ext = filename.rsplit('.',1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXT

def hash_password(pw):
    return generate_password_hash(pw)

def verify_password(pw, hashed):
    return check_password_hash(hashed, pw)

# ------------------- Views -------------------
HOME_HTML = """<!doctype html>
<title>Patched Python App</title>
<h1>Patched Python App</h1>
{% if not session.get('user_id') %}
<form method=post action="/register">
  <h3>Register</h3>
  <input name=username placeholder="username" required><br>
  <input name=email placeholder="email" required><br>
  <input name=password type=password placeholder="password" required><br>
  <button>Register</button>
</form>

<form method=post action="/login">
  <h3>Login</h3>
  <input name=username placeholder="username" required><br>
  <input name=password type=password placeholder="password" required><br>
  <button>Login</button>
</form>
{% else %}
<p>Welcome {{ session.get('username') }} ({{ session.get('role') }})</p>

<form method=post action="/update_profile">
  <h4>Profile</h4>
  <textarea name=bio rows=3 placeholder="bio"></textarea><br>
  <input name=website placeholder="website"><br>
  <button>Update Profile</button>
</form>

<form method=post action="/upload" enctype=multipart/form-data>
  <h4>Upload</h4>
  <input type=file name=user_file required><br>
  <button>Upload</button>
</form>

<form method=get action="/search">
  <h4>Search</h4>
  <input name=search placeholder="search term"><button>Search</button>
</form>

<form method=post action="/set_preference">
  <h4>Preference</h4>
  <input name=preference placeholder="preference">
  <button>Set</button>
</form>

<form method=post action="/reset_password">
  <h4>Reset</h4>
  <input name=email placeholder="email"><button>Reset</button>
</form>

{% if session.get('role') == 'admin' %}
  <p><a href="/admin?action=list_users">Admin: list users</a></p>
{% endif %}

<p><a href="/logout">Logout</a></p>
{% endif %}
"""

@app.route("/", methods=["GET"])
def index():
    name = request.args.get("name", "Guest")
    # escape user input to avoid XSS
    safe_name = escape(name)
    return render_template_string(HOME_HTML, session=session, safe_name=safe_name)

# ----- Register -----
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not valid_username(username) or not valid_email(email) or len(password) < 8:
        return "Invalid registration data", 400

    hashed = hash_password(password)
    db = get_db_connection()
    try:
        db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed, email))
        db.commit()
    except Exception:
        logger.info("Registration failed for %s", username)
        db.close()
        return "Registration failed", 400
    # prevent session fixation
    session.clear()
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    session['user_id'] = row['id']
    session['username'] = username
    session['role'] = 'user'
    db.close()
    return redirect("/")

# ----- Login -----
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    db = get_db_connection()
    row = db.execute("SELECT id, username, role, password FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    if not row or not verify_password(password, row["password"]):
        logger.info("Failed login for %s", username)
        return "Invalid credentials", 401
    session.clear()
    session['user_id'] = row['id']
    session['username'] = row['username']
    session['role'] = row['role']
    return redirect("/")

# ----- Update Profile -----
@app.route("/update_profile", methods=["POST"])
def update_profile():
    if not session.get('user_id'):
        return "Unauthorized", 401
    bio = sanitize_text(request.form.get("bio", "")) 
    website = sanitize_text(request.form.get("website", ""))
    db = get_db_connection()
    db.execute("INSERT OR REPLACE INTO user_profiles (user_id, bio, website) VALUES (?, ?, ?)", (session['user_id'], bio, website))
    db.commit()
    db.close()
    return redirect("/")

# ----- Upload -----
@app.route("/upload", methods=["POST"])
def upload():
    if not session.get('user_id'):
        return "Unauthorized", 401
    if 'user_file' not in request.files:
        return "No file", 400
    f = request.files['user_file']
    filename = secure_filename(f.filename)
    if filename == "":
        return "Invalid filename", 400
    if not allowed_file(filename):
        return "Invalid file type", 400
    # random stored name
    ext = filename.rsplit('.',1)[-1].lower()
    stored = secrets.token_hex(12) + "." + ext
    path = UPLOAD_DIR / stored
    f.save(path)
    os.chmod(path, 0o640)
    db = get_db_connection()
    db.execute("INSERT INTO user_files (user_id, original_name, stored_name) VALUES (?, ?, ?)", (session['user_id'], filename, stored))
    db.commit()
    db.close()
    logger.info("User %s uploaded a file", session.get('username'))
    return redirect("/")

# ----- Search (parameterized) -----
@app.route("/search", methods=["GET"])
def search():
    term = sanitize_text(request.args.get("search", ""))
    db = get_db_connection()
    rows = db.execute("SELECT name, price FROM products WHERE name LIKE ?", (f"%{term}%",)).fetchall()
    db.close()
    out = "<h3>Results</h3><ul>"
    for r in rows:
        out += f"<li>{escape(r['name'])} - ${escape(str(r['price']))}</li>"
    out += "</ul><p><a href='/'>Back</a></p>"
    return out

# ----- Admin -----
@app.route("/admin", methods=["GET"])
def admin():
    if session.get('role') != 'admin':
        return "Unauthorized", 403
    action = request.args.get('action', '')
    if action == 'list_users':
        db = get_db_connection()
        rows = db.execute("SELECT id, username, email, role FROM users").fetchall()
        db.close()
        return "<pre>" + "\n".join([f"{r['id']}: {escape(r['username'])} ({escape(r['email'])}) role={escape(r['role'])}" for r in rows]) + "</pre>"
    if action == 'exec':
        # whitelist commands — do NOT use shell=True
        cmd_key = request.args.get('cmd', '')
        allowed = {
            'whoami': ['whoami'],
            'uptime': ['uptime'],
            'date': ['date']
        }
        if cmd_key not in allowed:
            return "Command not allowed", 400
        try:
            result = subprocess.check_output(allowed[cmd_key], text=True)
            return "<pre>" + escape(result) + "</pre>"
        except Exception:
            logger.exception("Admin command failed")
            return "Command failed", 500
    return "Admin panel"

# ----- Reset Password -----
@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get('email', '').strip()
    if not valid_email(email):
        return "Invalid email", 400
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    db = get_db_connection()
    db.execute("UPDATE users SET reset_token=?, reset_expires=? WHERE email=?", (token, expires, email))
    db.commit()
    db.close()
    logger.info("Reset token for %s: %s", email, token)
    return "If the email exists, a reset link was issued (logged)."

# ----- XML processing (defusedxml prevents XXE) -----
@app.route("/xml", methods=["POST"])
def xml_process():
    xml_data = request.form.get('xml_data', '')
    try:
        root = safe_fromstring(xml_data)
        return "Processed XML root: " + escape(root.tag)
    except Exception:
        logger.info("Invalid XML submitted")
        return "Invalid XML", 400

# ----- Download file (owner or admin only) -----
@app.route("/download/<int:file_id>", methods=["GET"])
def download(file_id):
    db = get_db_connection()
    row = db.execute("SELECT * FROM user_files WHERE id=?", (file_id,)).fetchone()
    db.close()
    if not row:
        return "Not found", 404
    if session.get('user_id') != row['user_id'] and session.get('role') != 'admin':
        return "Unauthorized", 403
    path = UPLOAD_DIR / row['stored_name']
    if not path.exists():
        return "Missing", 404
    return send_file(path, as_attachment=True, download_name=row['original_name'])

# ----- Preference cookie -----
@app.route("/set_preference", methods=["POST"])
def set_preference():
    pref = sanitize_text(request.form.get('preference',''), maxlen=100)
    resp = make_response(redirect("/"))
    resp.set_cookie("user_preference", pref, max_age=365*24*3600, httponly=True, samesite='Lax')
    return resp

# ----- Logout -----
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ----- Error handlers -----
@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return "Internal server error", 500

@app.errorhandler(413)
def payload_too_large(e):
    return "File too large", 413

# ----- Run -----
if __name__ == "__main__":
    # Run on localhost for lab testing
    app.run(host="127.0.0.1", port=5000, debug=False)
