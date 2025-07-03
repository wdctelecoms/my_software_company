from flask import send_from_directory
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask import Flask, render_template, request, redirect, url_for, session
from email.mime.text import MIMEText
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, url_for
from functools import wraps
from flask import Flask, render_template, jsonify, request
import time, json, subprocess, os
import json, os
import hashlib
import sqlite3
import smtplib

app = Flask(__name__)

DEVELOPERS = {}  # You can later replace this with SQLite

app.secret_key = 'wdcwamulumbiabifostaer1234danibri'
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "mypassword"

IP_LOG_FILE = "data/ip_logs.json"

USER_FILE = "data/users.json"

UPLOAD_FOLDER = 'uploaded_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def send_signup_confirmation_email(email, username, user_type):
    subject = "Welcome to cybersentinental 360"
    if user_type == "person":
        message = f"Hi {username},\n\nThank you for signing up as a person. We're excited to have you on board!"
    else:
        message = f"Hi {username},\n\nThank you for signing up as a company. We look forward to working with your team!"

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = "phoneguardianshield@gmail.com"
    msg['To'] = email

    try:
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.login("phoneguardianshield@gmail.com", "oqcw bcvd gauq xxlv")  # 🔐 Use app password
        smtp_server.send_message(msg)
        smtp_server.quit()
        print("Signup confirmation email sent.")
    except Exception as e:
        print("Failed to send confirmation email:", e)

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


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print("Entered username:", username)
        print("Entered password:", password)

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/developers')
@admin_login_required
def admin_dashboard():
    # Placeholder data or pull from DB
    return render_template('admin_developers.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/developer')
def developer_intro():
    return render_template('developer_intro.html')

@app.route('/dev_uploads/<path:filename>')
def serve_dev_upload(filename):
    return send_from_directory('dev_uploads', filename)

@app.route('/developer/verify', methods=['GET', 'POST'])
def developer_verify():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        project_desc = request.form['project_desc']

        file_path = ''
        file = request.files.get('proof')
        if file and file.filename != '':
            os.makedirs('dev_uploads', exist_ok=True)
            file_path = os.path.join('dev_uploads', file.filename)
            file.save(file_path)

        conn = sqlite3.connect('cybersentinel.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO developer_verifications (fullname, email, project_desc, file_path)
            VALUES (?, ?, ?, ?)
        ''', (fullname, email, project_desc, file_path))
        conn.commit()
        conn.close()

        return render_template('developer_success.html')

    return render_template('developer_verify.html')

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/company-access-request')
def company_access_request():
    if session.get('user_type') != 'person':
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    companies = conn.execute("SELECT username, email FROM users WHERE user_type = 'company'").fetchall()
    conn.close()

    return render_template('company_access_request.html', companies=companies)

@app.route('/company-dashboard/<company_username>')
def access_company_dashboard(company_username):
    if session.get('user_type') != 'person':
        return redirect(url_for('dashboard'))

    # Here you would add real access logic later
    conn = get_db_connection()
    company = conn.execute("SELECT * FROM users WHERE username = ? AND user_type = 'company'", (company_username,)).fetchone()
    conn.close()

    if company:
        return render_template('company_dashboard.html', company=company)
    else:
        flash("Company not found.")
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    # Example tools data (replace with DB or JSON load later)
    tools = [
        {
            "name": "Mobile Firewall Pro",
            "description": "Protect your mobile apps with deep traffic inspection.",
            "filename": "mobile-firewall-pro.apk",
            "category": "Mobile Security"
        },
        {
            "name": "NetGuardian",
            "description": "Monitor your network for intrusions and anomalies.",
            "filename": "netguardian.zip",
            "category": "Network Monitoring"
        }
    ]
    return render_template("dashboard.html", tools=tools)


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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']
        email = request.form['email']

        hashed_pw = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, user_type, email) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, user_type, email)
            )
            conn.commit()

            session['logged_in'] = True
            session['username'] = username
            session['user_type'] = user_type

            send_signup_confirmation_email(email, username, user_type)

            # ✅ ADD THIS CONFIRMATION MESSAGE:
            if user_type == 'person':
                flash(f"Welcome {username}! You've signed up as a person.")
            elif user_type == 'company':
                flash(f"Welcome {username}! You've signed up as a company.")

            return redirect(url_for('dashboard'))

        except sqlite3.IntegrityError:
            error = "Username already exists"
            return render_template('signup.html', error=error)

        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        identifier = request.form['identifier']  # username or email
        password = hash_password(request.form['password'])

        conn = get_db_connection()
        cursor = conn.cursor()

        # Allow login by either username or email
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier)
        )
        user = cursor.fetchone()
        conn.close()

        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = user['username']
            session['user_type'] = user['user_type']

            if user['user_type'] == 'person':
                return redirect(url_for('dashboard_person'))
            elif user['user_type'] == 'company':
                return redirect(url_for('dashboard_company'))
        else:
            error = "Invalid username/email or password."

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

@app.route('/dashboard-person')
def dashboard_person():
    if 'logged_in' in session and session['user_type'] == 'person':
        return render_template('person_dashboard.html')
    return redirect(url_for('login'))

@app.route('/dashboard-company')
def dashboard_company():
    if not session.get('logged_in') or session.get('user_type') != 'company':
        return redirect(url_for('login'))
    return render_template('dashboard_company.html', username=session['username'])

@app.route('/person-dashboard')
def person_dashboard():
    if session.get('user_type') != 'person':
        return redirect(url_for('dashboard'))
    return render_template('person_dashboard.html')

@app.route('/company-dashboard')
def company_dashboard():
    if session.get('user_type') != 'company':
        return redirect(url_for('dashboard'))
    return render_template('company_dashboard.html')

@app.route('/download/<filename>')
def download_tool(filename):
    return send_from_directory('uploaded_files', filename, as_attachment=True)

@app.route('/upload', methods=['GET', 'POST'])
def upload_tool():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/developer')
def developer_dashboard():
    return render_template('developer_dashboard.html')

@app.route('/developer/upload', methods=['POST'])
def developer_upload():
    if not session.get('developer_logged_in'):
        return redirect(url_for('developer_login'))

    # Upload logic here

if __name__ == '__main__':
    app.run(debug=True, port=5000)
