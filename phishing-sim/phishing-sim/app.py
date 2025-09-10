from pathlib import Path
from datetime import datetime
from flask import Flask, jsonify, redirect, url_for, make_response, render_template, request
import smtplib
from email.message import EmailMessage
from flask_sqlalchemy import SQLAlchemy

# ----- Paths -----
BASE_DIR = Path(__file__).resolve().parent.parent   # top-level ~/phishing-sim
DB_PATH = BASE_DIR / "emails.db"

# ----- Flask app -----
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----- Model -----
class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200))
    recipient = db.Column(db.String(200))
    clicked = db.Column(db.Boolean, default=False)
    clicked_at = db.Column(db.DateTime, nullable=True)
    opened = db.Column(db.Boolean, default=False)            # NEW
    opened_at = db.Column(db.DateTime, nullable=True)        # NEW

SMTP_HOST = "127.0.0.1"
SMTP_PORT = 1025

@app.route("/")
def home():
    return "Phishing Sim — clicks + opens"

@app.route("/send")
def send_mail():
    # Create DB entry first to get ID
    entry = EmailLog(subject="Phishing Sim (with click+open)", recipient="user@local")
    db.session.add(entry)
    db.session.commit()

    track_url = f"http://127.0.0.1:5000/track/{entry.id}"
    open_pixel = f"http://127.0.0.1:5000/open/{entry.id}.png"

    # Plain-text + show the open-pixel as a link for demo (email clients hide images by default)
    body = (
        "Demo email for click + open tracking.\n\n"
        f"Click tracking link: {track_url}\n\n"
        "Open tracking pixel (normally invisible image):\n"
        f"{open_pixel}\n"
    )

    msg = EmailMessage()
    msg["Subject"] = entry.subject
    msg["From"] = "sim@local"
    msg["To"] = entry.recipient
    msg.set_content(body)

    # Send
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.send_message(msg)

    return jsonify({"status": "sent and logged", "track_url": track_url, "open_pixel": open_pixel, "email_id": entry.id})

@app.route("/track/<int:email_id>")
def track_click(email_id):
    row = EmailLog.query.get_or_404(email_id)
    if not row.clicked:
        row.clicked = True
        row.clicked_at = datetime.utcnow()
        db.session.commit()
    return redirect(url_for("thanks", email_id=email_id))

@app.route("/open/<int:email_id>.png")
def track_open(email_id):
    row = EmailLog.query.get_or_404(email_id)
    # mark opened
    if not row.opened:
        row.opened = True
        row.opened_at = datetime.utcnow()
        db.session.commit()

    # return a 1x1 transparent PNG
    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        b"\x00\x00\x00\x0AIEND\xaeB`\x82"
    )
    resp = make_response(png_1x1)
    resp.headers["Content-Type"] = "image/png"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

@app.route("/thanks/<int:email_id>")
def thanks(email_id):
    # ensure the ID exists in the DB, then render the nice template
    row = EmailLog.query.get_or_404(email_id)
    return render_template("thanks.html", email_id=email_id)

@app.route("/stats")
def stats():
    total = EmailLog.query.count()
    clicks = EmailLog.query.filter_by(clicked=True).count()
    opens = EmailLog.query.filter_by(opened=True).count()
    return jsonify({"total_sent": total, "opens": opens, "clicks": clicks})
@app.route("/dashboard")
def dashboard():
    total = EmailLog.query.count()
    clicks = EmailLog.query.filter_by(clicked=True).count()
    opens = EmailLog.query.filter_by(opened=True).count()
    rows = EmailLog.query.order_by(EmailLog.id.desc()).all()

    # calculate scores
    scores = {}
    for r in rows:
        score = 100
        if r.clicked:
            score -= 40
        if r.opened and not r.clicked:
            score += 20
        if not r.opened:
            score += 10
        scores[r.id] = score

    
    return render_template(
        "dashboard.html",
        total=total,
        opens=opens,
        clicks=clicks,
        rows=rows,
        scores=scores
    )

@app.route("/send-demo", methods=["GET", "POST"])
def send_demo():
    # alias: if anything calls 'send_demo', forward it to your existing send_mail
    return redirect(url_for("send_mail"))

@app.route("/landing/<int:log_id>")
def landing(log_id):
    return f"""
    <h3>Simulation Complete ✅</h3>
    <p>This was a <strong>lab-only</strong> phishing test.</p>
    <p>Entry ID: {log_id}</p>
    <p><b>Tips to stay safe:</b></p>
    <ul>
      <li>Always check the sender’s email domain</li>
      <li>Hover links before clicking</li>
      <li>Be cautious with urgent “reset password” messages</li>
      <li>Report suspicious emails as per company policy</li>
    </ul>
    <p><a href="/dashboard">Back to Dashboard</a></p>
    """

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print(f"DB ready at: {DB_PATH} (tables created if missing)")
    app.run(host="127.0.0.1", port=5000, debug=True)











