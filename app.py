from email.mime.text import MIMEText
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, url_for
from flask import Flask, render_template, jsonify, request
import time, json, subprocess, os
import json, os
import hashlib
import sqlite3
import smtplib

app = Flask(__name__)

app.secret_key = 'wdcwamulumbiabifostaer1234danibri'

IP_LOG_FILE = "data/ip_logs.json"

USER_FILE = "data/users.json"

def send_password_change_email(to_email, username):
    from_email = "phoneguardianshield@gmail.com"
    app_password = "oqcw bcvd gauq xxlv"

    subject = "Password Changed for Your Account"
    body = f"Hello {username},\n\nYour password was just changed.\n\nIf this wasn't you, reset your password immediately."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(from_email, app_password)
            smtp.send_message(msg)
    except Exception as e:
        print("Email failed:", e)

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
    message = None

    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])  # Make sure hash_password() is defined
        user_type = request.form['user_type']
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password, user_type, email) VALUES (?, ?, ?, ?)",
                (username, password, user_type, email)
            )
            conn.commit()

            # Auto-login after signup
            session['logged_in'] = True
            session['username'] = username
            session['user_type'] = user_type

            return redirect(url_for('dashboard'))

        except sqlite3.IntegrityError:
            error = "Username already exists. Please choose a different one."

        finally:
            conn.close()

    return render_template("signup.html", error=error, message=message)

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

        if user:
            # ✅ Set session
            session['logged_in'] = True
            session['user_type'] = user['user_type']
            session['username'] = user['username']

            # ✅ Record login to logins table
            cursor.execute(
                "INSERT INTO logins (username, login_time, ip) VALUES (?, ?, ?)",
                (
                    user['username'],
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    request.remote_addr
                )
            )
            conn.commit()
            conn.close()

            return redirect(url_for('dashboard'))

        else:
            conn.close()
            error = "Invalid username or password"

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login-history')
def login_history():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logins ORDER BY login_time DESC")
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('login_history.html', logs=logs)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    message = None
    error = None

    if request.method == 'POST':
        old_password = hash_password(request.form['old_password'])
        new_password = hash_password(request.form['new_password'])
        username = session['username']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and user["password"] == old_password:
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
            conn.commit()

            # ✅ Send email alert
            send_password_change_email(user['email'], username)

            message = "Password updated and email sent successfully."
        else:
            error = "Old password is incorrect."

        conn.close()

    return render_template("reset_password.html", message=message, error=error)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
