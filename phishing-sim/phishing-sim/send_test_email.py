import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["Subject"] = "Phishing Sim Test"
msg["From"] = "sim@local"
msg["To"] = "user@local"
msg.set_content("Hello! If you see this in the SMTP window, your test server works.")

with smtplib.SMTP("127.0.0.1", 1025) as s:
    s.send_message(msg)

print("Sent.")
