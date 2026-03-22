import sqlite3

DB_PATH = "code_cwe.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS burp_scan_result (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        code_id      INTEGER NOT NULL,
        scan_id      TEXT NOT NULL,
        scan_type    TEXT NOT NULL DEFAULT 'crawl_and_audit',
        issue_name   TEXT,
        type_index   INTEGER,
        mapped_cwe   TEXT,
        severity     TEXT,
        confidence   TEXT,
        path         TEXT,
        origin       TEXT,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (code_id) REFERENCES code_cwe(id)
    )
""")

conn.commit()
conn.close()

print("burp_scan_result tablosu oluşturuldu.")