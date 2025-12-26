# Idea of this codepiece is to fill tool columns in database for rows that already has the code but no tool output.
# I don't want to manually orchestrate sast and dast tools for each row. Just Save the codes and fill db later.
from core.db_handler import DBManager  # filepath: core/db_handler.py
from core.file_handler import FileManager  # filepath: core/file_handler.py
from core.docker_handler import DockerManager  # filepath: core/docker_handler.py
import logic.dast_pipeline as dast  # filepath: logic/dast_pipeline.py
import logic.sast_pipeline as sast  # filepath: logic/sast_pipeline.py

def needs_analysis_row(row):
    # row is a tuple from DB with columns: id, bandit, semgrep, sonarqube, docker (etc)
    # return True if any important analisys field is missing / not-tested
    _, bandit, semgrep, sonarqube, docker = row
    checks = [bandit, semgrep, sonarqube, docker]
    for v in checks: 
        if v is None or v == "" or str(v).lower() in {"not-tested", "not-tested", "not tested"}:
            return True
    return False

def gather_targets(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # select id and the columns we'll check/update
    cursor.execute("SELECT id, bandit, semgrep, sonarqube, docker FROM code_cwe")
    rows = cursor.fetchall()
    conn.close()
    # return ids that have missing/not-tested entries
    targets = [row[0] for row in rows if needs_analysis_row(row)]
    return targets
