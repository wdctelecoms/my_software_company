import subprocess
from flask import Flask, render_template, jsonify
import time

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("dashboard.html")

@app.route('/system-stats')
def system_stats():
    # Use Linux commands for Termux compatibility
    cpu = subprocess.getoutput("top -bn1 | grep 'CPU' | awk '{print $2}'")
    mem = subprocess.getoutput("free | grep Mem | awk '{print ($3/$2) * 100}'")
    disk = subprocess.getoutput("df /data | awk 'NR==2 {print $5}'")

    return jsonify({
        "cpu": cpu or "N/A",
        "memory": mem or "N/A",
        "disk": disk or "N/A",
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
