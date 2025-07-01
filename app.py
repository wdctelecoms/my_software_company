from flask import Flask, render_template, jsonify, request
import time, json, subprocess, os

app = Flask(__name__)

IP_LOG_FILE = "data/ip_logs.json"

@app.route('/')
def home():
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
