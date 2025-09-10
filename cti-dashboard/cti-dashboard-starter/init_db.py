import sqlite3, os
DB_PATH = os.path.join(os.path.dirname(__file__), 'cti.db')
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute('''CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY,
    value TEXT,
    type TEXT,
    first_seen TEXT,
    ingested_at TEXT
)''')
conn.commit()
conn.close()
print("Initialized database at", DB_PATH)
