import os
import sqlite3
import shutil

class FileManager:
    def __init__(self, base_dir=None):
        if base_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))  # .../project/core
            self.base_dir = os.path.abspath(os.path.join(current_dir, "..", "app_data"))  # .../project/app_data
        else:
            self.base_dir = base_dir

        os.makedirs(self.base_dir, exist_ok=True)

    def setup_files(self, code_id, code, dockerfile, sql_script, requirements):
        workdir = os.path.join(self.base_dir, f"app_{code_id}")
        os.makedirs(workdir, exist_ok=True)

        with open(os.path.join(workdir, "app.py"), "w") as f:
            f.write(code)
        with open(os.path.join(workdir, "Dockerfile"), "w") as f:
            f.write(dockerfile)
        with open(os.path.join(workdir, "init.sql"), "w") as f:
            f.write(sql_script)
        with open(os.path.join(workdir, "requirements.txt"), "w") as f:
            f.write(requirements)

        return workdir

    def run_sql_script(self, code_id, sql_script):
        workdir = os.path.join(self.base_dir, f"app_{code_id}")
        db_path = os.path.join(workdir, "database.db")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.executescript(sql_script)
            conn.commit()
            conn.close()
            print(f"SUCCESS: SQL db created for app_{code_id}")
            return True
        except Exception as e:
            print(f"FAIL: SQL script failed for app_{code_id}: {e}")
            return False

    def remove_files(self, code_id):
        workdir = os.path.join(self.base_dir, f"app_{code_id}")
        if os.path.exists(workdir):
            try:
                shutil.rmtree(workdir)
                print(f"[+] Removed directory: {workdir}")
            except Exception as e:
                print(f"[!] Failed to remove directory {workdir}: {e}")