from flask import Flask, render_template, request, redirect, session, url_for
from flask import Flask, render_template, jsonify, request
import time, json, subprocess, os
import json, os
import hashlib
import sqlite3

app = Flask(__name__)

app.secret_key = 'wdcwamulumbiabifostaer1234danibri'

IP_LOG_FILE = "data/ip_logs.json"

USER_FILE = "data/users.json"

def get_db_connection():
    conn = sqlite3.connect("data/app.db")
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=2)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template("dashboard.html")

@app.route('/system-stats')
def system_stats():
    cpu = subprocess.getoutput("top -bn1 | grep 'CPU' | awk '{print $2}'")
    mem = subprocess.getoutput("free | grep Mem | awk '{print ($3/$2) * 100}'")
    disk = subprocess.getoutput("df /data | awk 'NR==2 {print $5}'")

    return jsonify({
        "cpu": cpu or "N/A",
        "memory": mem or "N/A",
        "disk": disk or "N/A",
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/log-ip', methods=['POST'])
def log_ip():
    data = request.get_json()
    ip = data.get("ip")
    reason = data.get("reason")

    if not ip or not reason:
        return jsonify({"status": "error", "message": "Missing IP or reason"}), 400

    entry = {
        "ip": ip,
        "reason": reason,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    logs = []
    if os.path.exists(IP_LOG_FILE):
        with open(IP_LOG_FILE, "r") as f:
            logs = json.load(f)

    logs.append(entry)

    with open(IP_LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

    return jsonify({"status": "success", "message": "IP logged"})

@app.route('/get-ips')
def get_ips():
    if not os.path.exists(IP_LOG_FILE):
        return jsonify([])
    with open(IP_LOG_FILE, "r") as f:
        return jsonify(json.load(f))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        user_type = request.form['user_type']
        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)",
                (username, password, user_type)
            )
            conn.commit()
            session['logged_in'] = True
            session['user_type'] = user_type
            session['username'] = username
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            error = "Username already exists"
        finally:
            conn.close()

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['user_type'] = user['user_type']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
