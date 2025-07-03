import sqlite3

conn = sqlite3.connect('cybersentinel.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS developer_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT NOT NULL,
    project_desc TEXT,
    file_path TEXT,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()
print("Developer verification table created.")
