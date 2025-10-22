from core.file_handler import FileManager
from core.docker_handler import DockerManager
from core.db_handler import DBManager
from logic.dast_pipeline import owasp_zap_scan
from logic.sast_pipeline import sast_scan
import traceback
import json
db = DBManager()
fm = FileManager()
policy = "API"

def run_zap_scan(id, chosenpolicy):
    code, dockerfile, sql_script, port_temp, reqs, docker = db.get_files_by_id(id)
    if docker != "tested-successful":
        print(f"SKIP DAST : code_id = {id} because docker status was {docker}")

    else:
        try:
            workdir_temp = fm.setup_files(id, code, dockerfile, sql_script, reqs)
            fm.run_sql_script(id, sql_script)
            tag = id
            dm = DockerManager(workdir=workdir_temp, tag=id, port=port_temp)
            dm.build_image()
            dm.run_container()
            alerts = owasp_zap_scan(port_temp, chosenpolicy)
            db.save_scan_results(id, "owasp_zap" , json.dumps(alerts)) 
            print(f"[DEBUG] ALERTS FOUND FOR ID {id}:")
            print(json.dumps(alerts, indent=2))
            dm.stop_and_remove()
            fm.remove_files(id)
        except Exception as e:
            traceback.print_exc()
            print(f"FAIL: code_id={id} owasp zap error: {e}")

for id in range(1, 2426):
    run_zap_scan(id, policy)


sast_scan(startid, lastid, run_bandit=True, run_semgrep=True, run_sonarqube=True)
