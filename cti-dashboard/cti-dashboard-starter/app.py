# app.py - complete CTI Dashboard with CSV ingest, enrichment, geolocation, timeseries, and scoring.

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
import csv
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
from werkzeug.utils import secure_filename
import json
import requests

# === Configuration ===
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}
DB_PATH = os.path.join(os.path.dirname(__file__), 'cti.db')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')  # Optional: set in .env to call AbuseIPDB
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv('FLASK_SECRET', 'dev-secret-for-local')

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# === Database initialization ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT,
        type TEXT,
        first_seen TEXT,
        ingested_at TEXT
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS enrichments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        data TEXT,
        enriched_at TEXT
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# === Utilities ===
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def insert_ioc(value, ioc_type, first_seen, ingested_at):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO iocs (value, type, first_seen, ingested_at) VALUES (?, ?, ?, ?)',
                (value, ioc_type, first_seen, ingested_at))
    conn.commit()
    conn.close()

def save_enrichment(ip, data):
    """Persist enrichment JSON into enrichments table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO enrichments (ip, data, enriched_at) VALUES (?, ?, ?)',
                    (ip, json.dumps(data), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Failed to save enrichment:", e)

# === Enrichment helpers ===
def enrich_abuseipdb(ip):
    """Call AbuseIPDB (if key) or return a safe mock for demo."""
    if not ip:
        return {"error": "no ip provided"}
    mock = {
        "ipAddress": ip,
        "abuseConfidenceScore": 5,
        "countryCode": "ZZ",
        "lastReportedAt": "2024-01-01T00:00:00Z",
        "reports": 0,
        "source": "mock"
    }
    if not ABUSEIPDB_API_KEY:
        return mock
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        result = {
            "ipAddress": data.get("data", {}).get("ipAddress"),
            "abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore"),
            "countryCode": data.get("data", {}).get("countryCode"),
            "lastReportedAt": data.get("data", {}).get("lastReportedAt"),
            "reports": len(data.get("data", {}).get("reports", [])),
            "source": "abuseipdb"
        }
        return result
    except Exception as e:
        return {"error": "abuseipdb_request_failed", "detail": str(e)}

# === Geolocation helper ===
def geolocate_ip_api(ip):
    """Use ip-api.com (no key) to get lat/lon; return mock on failure."""
    if not ip:
        return {"ip": ip, "lat": None, "lon": None, "country": None, "source": "invalid"}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,lat,lon,countryCode,query"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip": data.get("query"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "country": data.get("countryCode"),
                "source": "ip-api"
            }
        else:
            return {"ip": ip, "lat": None, "lon": None, "country": None, "source": "ip-api-failed"}
    except Exception:
        return {"ip": ip, "lat": None, "lon": None, "country": None, "source": "mock"}

# === Threat scoring helper ===
def compute_threat_score_for_ioc(value, ioc_type='ip'):
    """
    Explainable scoring:
      - base from abuseConfidenceScore (if present)
      - +2 per report (capped to +20)
      - +10 for example high-risk countries
      - clamp to 0..100
    """
    baseline = 5
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT data FROM enrichments WHERE ip = ? ORDER BY id DESC LIMIT 1", (value,))
        row = cur.fetchone()
        conn.close()
    except Exception:
        return {"value": value, "score": baseline, "reason": "db_error"}

    if not row:
        return {"value": value, "score": baseline, "reason": "no_enrichment"}

    try:
        edata = json.loads(row[0])
    except Exception:
        return {"value": value, "score": baseline, "reason": "bad_enrichment_json"}

    base_score = 0
    if isinstance(edata, dict):
        base_score = int(edata.get("abuseConfidenceScore") or 0) if edata.get("abuseConfidenceScore") is not None else 0

    reports = edata.get("reports", 0) if isinstance(edata, dict) else 0
    try:
        reports = int(reports)
    except Exception:
        reports = 0

    score = base_score
    score += min(20, reports * 2)

    country = (edata.get("countryCode") if isinstance(edata, dict) else None) or None
    if country in ("RU", "CN", "KP", "IR"):
        score += 10

    score = max(0, min(100, int(score)))

    return {
        "value": value,
        "score": score,
        "base_score": base_score,
        "reports": reports,
        "country": country,
        "source": edata.get("source") if isinstance(edata, dict) else None,
        "reason": "computed"
    }

# === Routes ===

@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, value, type, first_seen, ingested_at FROM iocs ORDER BY id DESC LIMIT 50')
    iocs = cur.fetchall()
    cur.execute('SELECT id, ip, substr(data,1,200), enriched_at FROM enrichments ORDER BY id DESC LIMIT 20')
    enrichments = cur.fetchall()
    conn.close()
    return render_template('index.html', iocs=iocs, enrichments=enrichments)

@app.route('/upload', methods=['POST'])
def upload_csv():
    if 'file' not in request.files:
        flash('No file part in the request')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(saved_path)

        inserted = 0
        with open(saved_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                value = (row.get('value') or row.get('ip') or row.get('domain') or row.get('url') or '').strip()
                ioc_type = (row.get('type') or 'unknown').strip()
                first_seen = (row.get('first_seen') or row.get('firstseen') or '').strip()
                if value:
                    ingested_at = datetime.utcnow().isoformat()
                    insert_ioc(value, ioc_type, first_seen, ingested_at)
                    inserted += 1

        flash(f'Imported {inserted} IOC(s) from {filename}')
        return redirect(url_for('index'))

    else:
        flash('Invalid file type — please upload a .csv file')
        return redirect(url_for('index'))

@app.route('/lookup')
def lookup():
    ip = request.args.get('ip')
    result = enrich_abuseipdb(ip)
    print("ENRICHMENT RESULT:", json.dumps(result, indent=2))
    save_enrichment(ip, result)
    return "<pre>{}</pre>".format(json.dumps(result, indent=2))

@app.route('/timeseries')
def timeseries():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT substr(ingested_at,1,10) as day, COUNT(*) FROM iocs GROUP BY day ORDER BY day")
    rows = cur.fetchall()
    conn.close()
    labels = [r[0] for r in rows]
    counts = [r[1] for r in rows]
    return jsonify({"labels": labels, "counts": counts})

@app.route('/geolocations')
def geolocations():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, value FROM iocs WHERE type='ip' ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        ioc_id, ip = r[0], r[1]
        geo = geolocate_ip_api(ip)
        geo["id"] = ioc_id
        results.append(geo)

    return jsonify(results)

@app.route('/scores')
def scores():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, value, type FROM iocs ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    out = []
    for r in rows:
        ioc_id, value, ioc_type = r
        s = compute_threat_score_for_ioc(value, ioc_type)
        s["id"] = ioc_id
        s["type"] = ioc_type
        out.append(s)
    return jsonify(out)



@app.route('/stories')
def stories():
    """
    Group IOCs into simple clusters and generate short natural-language summaries.
    """
    # 1) load recent iocs (note: iocs table columns: id, value, type, first_seen)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, value, type, first_seen FROM iocs ORDER BY first_seen DESC LIMIT 50;")
    rows = cur.fetchall()
    conn.close()

    # 2) load any saved enrichments keyed by ip (enrichments table: ip, data)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT ip, data FROM enrichments;")
    enrichments = {}
    for r in cur.fetchall():
        ip_key = r[0]
        try:
            enrichments[ip_key] = json.loads(r[1])
        except Exception:
            enrichments[ip_key] = {}
    conn.close()

    # 3) cluster by country (use enrichment countryCode when present)
    clusters = {}
    for row in rows:
        ioc_id, value, typ, first_seen = row
        e = enrichments.get(value, {}) if value else {}
        country = e.get("countryCode") if isinstance(e, dict) else None
        country = country or "??"
        clusters.setdefault(country, []).append({
            "id": ioc_id, "value": value, "type": typ, "first_seen": first_seen
        })

    # 4) build short stories for clusters with 2+ items
    stories = []
    for country, items in clusters.items():
        if len(items) < 2:
            continue
        ioc_list = ", ".join([i["value"] for i in items])
        story_text = f"{len(items)} IOCs from {country} were observed, including {ioc_list}. This may suggest coordinated or related activity."
        stories.append({"country": country, "count": len(items), "story": story_text})

    return jsonify(stories)





# === Export CSV endpoints ===
@app.route('/export/iocs.csv')
def export_iocs():
    """Export IOCs as CSV (id,value,type,first_seen,ingested_at)"""
    from flask import Response
    import io, csv
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, value, type, first_seen, ingested_at FROM iocs ORDER BY id;")
    rows = cur.fetchall()
    conn.close()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','value','type','first_seen','ingested_at'])
    for r in rows:
        writer.writerow(r)
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition':'attachment; filename="iocs.csv"'})

@app.route('/export/enrichments.csv')
def export_enrichments():
    """Export enrichments as CSV (id,ip,enriched_at,data_json)"""
    from flask import Response
    import io, csv
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, ip, enriched_at, data FROM enrichments ORDER BY id;")
    rows = cur.fetchall()
    conn.close()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','ip','enriched_at','data_json'])
    for r in rows:
        # r[3] is data JSON string; keep it as-is inside CSV field
        writer.writerow([r[0], r[1], r[2], r[3]])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition':'attachment; filename="enrichments.csv"'})


if __name__ == '__main__':
    print('REGISTERED ROUTES:', [r.rule for r in app.url_map.iter_rules()])
    app.run(host='127.0.0.1', port=5000, debug=True)

