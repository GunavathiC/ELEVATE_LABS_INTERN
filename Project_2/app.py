from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import os
import json
import random
import time
from utils.mock_data import get_mock_threat_feed, get_mock_summary, GEO_IP_MAP, recommendations, USERS, PLAYBOOKS

app = Flask(__name__)
app.secret_key = "superrandomkey"
FEED = get_mock_threat_feed()
SOC_LOG = []

def soc_log(user, action):
    SOC_LOG.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {user}: {action}")

@app.route('/login', methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        if u in USERS and USERS[u] == p:
            session["user"] = u
            soc_log(u, "Logged in")
            return redirect(url_for('dashboard'))
        else:
            msg = "Invalid user/pass."
    return render_template("login.html", msg=msg)

@app.route('/logout')
def logout():
    u = session.get("user", "Unknown")
    session.clear()
    soc_log(u, "Logged out")
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    summary = get_mock_summary(feed=FEED)
    chart_data = { "labels": ["Critical", "High", "Medium", "Low"],
                   "values": [summary["critical"],summary["high"],summary["medium"],summary["low"]]}
    return render_template('dashboard.html',
        user=user, feed=FEED, summary=summary,
        chart_data=json.dumps(chart_data),
        geo_points=json.dumps([GEO_IP_MAP.get(item["name"], {"lat": 22, "lng": 79, "label": item["name"]}) for item in FEED]),
        recommendations=recommendations(summary)
    )

@app.route('/soclog')
def soclog():
    user = session.get("user")
    if not user: return redirect(url_for("login"))
    return render_template("soclog.html", log=SOC_LOG, user=user)

@app.route('/lookup', methods=['POST'])
def lookup():
    d = request.json
    query = d.get('query', '')
    soc_log(session.get("user"), f"Threat lookup: {query}")
    threat_types = ['Malware', 'Phishing', 'Botnet', 'Clean']
    threat_type = random.choice(threat_types)
    reputation = random.choice(['Low', 'Medium', 'High'])
    details = f"Mock threat intelligence details about {query}."
    geo = GEO_IP_MAP.get(query, {"lat": 27, "lng": 77, "label": query})
    return jsonify({
        "query": query,
        "threat_type": threat_type,
        "reputation": reputation,
        "details": details,
        "playbook": PLAYBOOKS.get(threat_type, ["General triage/check logs"]),
        "geo": geo
    })

@app.route('/add_threat', methods=['POST'])
def add_threat():
    d = request.json
    user = session.get("user","Unknown")
    new = {
        "name": d.get("name"),
        "type": d.get("type"),
        "level": d.get("level"),
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    FEED.append(new)
    soc_log(user, f"Added threat {new['name']} {new['type']} {new['level']}")
    return jsonify({"ok": True})

@app.route('/export/json')
def export_json():
    soc_log(session.get("user"), "Exported JSON")
    os.makedirs('reports', exist_ok=True)
    fn = f'reports/export_{int(time.time())}.json'
    with open(fn, 'w') as f:
        json.dump(FEED, f, indent=2)
    return send_file(fn, as_attachment=True)

@app.route('/export/csv')
def export_csv():
    import csv
    soc_log(session.get("user"), "Exported CSV")
    os.makedirs('reports', exist_ok=True)
    fn = f'reports/export_{int(time.time())}.csv'
    with open(fn, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FEED[0].keys())
        writer.writeheader()
        writer.writerows(FEED)
    return send_file(fn, as_attachment=True)

@app.route('/export/pdf')
def export_pdf():
    from fpdf import FPDF
    soc_log(session.get("user"), "Exported PDF")
    os.makedirs('reports', exist_ok=True)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, 'Cyber Threat Intelligence Report', ln=True, align='C')
    pdf.ln(10)
    pdf.set_font('Arial', '', 12)
    for it in FEED:
        line = f"Threat: {it['name']} | Type: {it['type']} | Level: {it['level']}"
        pdf.cell(0, 10, line, ln=True)
    fn = f'reports/export_{int(time.time())}.pdf'
    pdf.output(fn)
    return send_file(fn, as_attachment=True)

@app.route('/feed')
def get_feed():
    summary = get_mock_summary(feed=FEED)
    return jsonify({"feed": FEED, "summary": summary})

# Simulate live data ingestion — every 90 sec
import threading
def live_ingest():
    levels = ["Critical","High","Medium"]
    types = ["Malware","Phishing", "Botnet"]
    name = "live-" + str(random.randint(1,200))
    FEED.append({
        "name": name,
        "type": random.choice(types),
        "level": random.choice(levels),
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    })
    soc_log("ingest",f"Auto-ingested threat {name}")
    threading.Timer(90, live_ingest).start()
live_ingest()

if __name__ == '__main__':
    app.run(debug=True)
