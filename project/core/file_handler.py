import os
import sqlite3
import shutil
import subprocess

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
        if not os.path.exists(workdir):
            return
        try:
            shutil.rmtree(workdir)
            print(f"[+] Removed directory: {workdir}")
            return
        except Exception as e:
            print(f"[!] Failed to remove directory {workdir}: {e} -- retrying via Docker")

        # Containerized apps (e.g. Flask-Session writing to disk) create files
        # owned by root inside the bind-mounted workdir; the host user can't
        # delete them, and shutil.rmtree above just fails on that subtree.
        # A throwaway container's root user has the same UID (0) that wrote
        # them, so it can remove what the host user can't -- confirmed this
        # was silently leaving ~86 leftover app_data/app_<id> directories
        # (2.7 MB) after sql-failed runs, and in the worse case (Flask-Session
        # apps) blocked the *next* build outright with a PermissionError from
        # Docker's own build-context tar step, since it can't even read a
        # root-owned file to package it.
        try:
            # `rm -rf /cleanup` (the mount point itself) fails with "Resource
            # busy" from inside the container -- confirmed by reproducing it
            # directly. Clear the mount's *contents* as root instead (find
            # -delete, not a `*` glob, so dotfiles/dot-directories aren't
            # left behind), then remove the now-empty, host-owned top-level
            # directory the normal way.
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{workdir}:/cleanup", "alpine",
                 "find", "/cleanup", "-mindepth", "1", "-delete"],
                capture_output=True, text=True, timeout=60, check=True,
            )
            shutil.rmtree(workdir)
            print(f"[+] Removed directory via Docker fallback: {workdir}")
        except Exception as e2:
            print(f"[!] Docker fallback also failed to remove {workdir}: {e2}")