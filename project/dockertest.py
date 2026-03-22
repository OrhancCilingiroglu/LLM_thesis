from core.file_handler import FileManager
from core.docker_handler import DockerManager
from core.db_handler import DBManager
import traceback
import json
db = DBManager()
fm = FileManager()
policy = "API"


from core import api_handler, db_handler, docker_handler, file_handler
from logic import code_pipeline, dast_pipeline, sast_pipeline
from utils import message_parsers, promptvariables
import traceback
import random

db = db_handler.DBManager()
fm = file_handler.FileManager()
#docker = docker_handler.DockerManager()
zappolicy = "API"
api_router = api_handler.ApiHandlerRouter()


def run_docker_id(id):
    code, dockerfile, sql_script, port_temp, reqs, docker = db.get_files_by_id(id)
    workdir_temp = fm.setup_files(id, code, dockerfile, sql_script, reqs)
    if fm.run_sql_script(id, sql_script):
        print(f"SQL script executed successfully for code_id={id}.")
    else:
        print(f"SQL script execution failed for code_id={id}.")
        db.mark_sql_failed(id)
    dm = DockerManager(workdir=workdir_temp, tag=id, port=port_temp)
    if dm.build_image():
        if dm.run_container():
            print(f"DOCKER RUN SUCCESS: code_id={id} Docker container ran successfully.")
        else:
            print(f"DOCKER RUN FAIL: code_id={id} Docker container failed to run.")
    else:
        print(f"DOCKER BUILD FAIL: code_id={id} Docker image build failed.")
            

def test_docker_runs(first_id, last_id):
    for code_id in range(first_id, last_id + 1):
        code, dockerfile, sql_script, port_temp, reqs, docker_status = db.get_files_by_id(code_id)

        #if docker_status != "not-tested":
        #    print(f"SKIP DOCKER TEST : code_id={code_id} because docker status was {docker_status}")
        #    continue

        dm = None
        workdir_temp = None

        try:
            # 1) Prepare files
            workdir_temp = fm.setup_files(code_id, code, dockerfile, sql_script, reqs)

            # 2) Optional: run SQL script (doesn't have to block docker test)
            if fm.run_sql_script(code_id, sql_script):
                print(f"SQL script executed successfully for code_id={code_id}.")
            else:
                print(f"SQL script execution failed for code_id={code_id}.")
                db.mark_sql_failed(code_id)

            # 3) Build + run
            dm = DockerManager(workdir=workdir_temp, tag=code_id, port=port_temp)

            if not dm.build_image():
                print(f"DOCKER BUILD FAIL: code_id={code_id} Docker image build failed.")
                db.mark_docker_tested_failed(code_id)
                continue

            # run_container() should include "real run" verification (running + HTTP)
            container = dm.run_container()
            if container:
                print(f"DOCKER RUN SUCCESS: code_id={code_id} App is running/responding.")
                db.mark_docker_tested_successful(code_id)
            else:
                print(f"DOCKER RUN FAIL: code_id={code_id} Container did not stay up / no HTTP response.")
                db.mark_docker_tested_failed(code_id)

        except Exception as e:
            traceback.print_exc()
            print(f"FAIL: code_id={code_id} Docker test error: {e}")
            # mark failed on unexpected exceptions too
            try:
                db.mark_docker_tested_failed(code_id)
            except Exception:
                pass

        finally:
            # Always cleanup
            try:
                if dm is not None:
                    dm.stop_and_remove()
            except Exception:
                pass

            try:
                if workdir_temp is not None:
                    fm.remove_files(code_id)
            except Exception:
                pass

run_docker_id(172)