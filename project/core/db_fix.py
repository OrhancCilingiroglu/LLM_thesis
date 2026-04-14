import sqlite3
import re
from core.db_handler import DBManager
import os
DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

def fix_broken_code_in_db(start_id: int = 4571):
    db = DBManager()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT id, code FROM code_cwe WHERE id >= ?", (start_id,))
    rows = cur.fetchall()

    fixed = 0
    for code_id, code in rows:
        if not code:
            continue
        if not code.strip().startswith("```"):
            continue  # already clean

        # strip markdown fences
        pattern = r"```(?:python)?\s*\n?(.*?)```"
        match = re.search(pattern, code, re.DOTALL)
        if match:
            clean = match.group(1).strip()
        else:
            # fence at start but no closing — just strip the first line
            clean = re.sub(r"^```(?:python)?\s*\n?", "", code).strip()
            clean = re.sub(r"\n?```$", "", clean).strip()

        cur.execute("UPDATE code_cwe SET code = ? WHERE id = ?", (clean, code_id))
        fixed += 1

    conn.commit()
    conn.close()
    print(f"Fixed {fixed} rows starting from id={start_id}")

def reset_docker_status(start_id: int = 4571):
    db = DBManager()
    conn = sqlite3.connect(db.db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE code_cwe 
        SET bandit = 'not-tested'
        WHERE id >= ?
    """, (start_id,))
    updated = cur.rowcount
    conn.commit()
    conn.close()
    print(f"Reset {updated} rows to 'not-tested'")

reset_docker_status(start_id=4571)

#fix_broken_code_in_db(start_id=4571)