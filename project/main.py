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



def test_docker_runs(first_id, last_id):
    for id in range(first_id, last_id):
        code, dockerfile, sql_script, port_temp, reqs, docker = db.get_files_by_id(id)
        if docker != "not-tested":
            print(f"SKIP DOCKER TEST : code_id = {id} because docker status was {docker}")
        else:
            try:
                workdir_temp = fm.setup_files(id, code, dockerfile, sql_script, reqs)
                if fm.run_sql_script(id, sql_script):
                    print(f"SQL script executed successfully for code_id={id}.")
                else:
                    print(f"SQL script execution failed for code_id={id}.")
                    db.mark_sql_failed(id)
                tag = id
                dm = DockerManager(workdir=workdir_temp, tag=id, port=port_temp)
                if dm.build_image():
                    if dm.run_container():
                        print(f"DOCKER RUN SUCCESS: code_id={id} Docker container ran successfully.")
                        db.mark_docker_tested_successful(id)
                    else:
                        print(f"DOCKER RUN FAIL: code_id={id} Docker container failed to run.")
                        db.mark_docker_tested_failed(id)
                else:
                    print(f"DOCKER BUILD FAIL: code_id={id} Docker image build failed.")
                    db.mark_docker_tested_failed
                dm.stop_and_remove()
                fm.remove_files(id)
            except Exception as e:
                traceback.print_exc()
                print(f"FAIL: code_id={id} Docker test error: {e}")


port_allo_openai_sec = code_pipeline.PortAllocator(5000)
port_allo_openai_vuln = code_pipeline.PortAllocator(6000)
port_allo_groq_sec = code_pipeline.PortAllocator(7000)
port_allo_groq_vuln = code_pipeline.PortAllocator(8000)
port_array = [port_allo_openai_sec, port_allo_openai_vuln, port_allo_groq_sec, port_allo_groq_vuln] # Same order with objects just created for reusing port numbers without jumps

def generate_code(cwe_list):
    for cwe in cwe_list:
        coding_task = random.choice(promptvariables.coding_tasks)
        webstyle = random.choice(promptvariables.website_styles)
        webproduct = random.choice(promptvariables.website_products)
        secure_openai_app = code_pipeline.AppSample(cwe=cwe, task=coding_task,  webstyle=webstyle, webproduct=webproduct, is_secure=True, port = port_allo_openai_sec.get_port(), producer="openai")
        vuln_openai_app = code_pipeline.AppSample(cwe=cwe, task=coding_task, webstyle=webstyle, webproduct=webproduct, is_secure=False, port = port_allo_openai_vuln.get_port(), producer="openai")
        secure_groq_app = code_pipeline.AppSample(cwe=cwe, task=coding_task,  webstyle=webstyle, webproduct=webproduct, is_secure=True, port = port_allo_groq_sec.get_port(), producer="groq")
        vuln_groq_app = code_pipeline.AppSample(cwe=cwe, task=coding_task, webstyle=webstyle, webproduct=webproduct, is_secure=False, port = port_allo_groq_vuln.get_port(), producer="groq")
        samples = [secure_openai_app, vuln_openai_app, secure_groq_app, vuln_groq_app]
        #Send prompt to LLM for code and save response
        for sample in samples:
            sample.set_code(api_router.send_prompt(in_prompt=sample.generate_code_prompt(),producer=sample.producer))
        #Decide which codes are not verified by producer LLM. If it fails delete it.
        samples_to_delete = []
        for i in range [0,3]:
            for sample in samples:
                control = sample.control_checks(api_router.send_prompt(in_prompt = sample.generate_check_prompt()),producer=sample.producer)
                if control == False:
                    samples_to_delete.append(sample)
                    port_array[samples.index(sample)].decrement()  # Decrease port number one by 
                    # sample.__del__() not used because of bad practice, garbage collector will handle
        samples = [s for s in samples if s not in samples_to_delete]
        #send necessary prompt to make LLMs write dockerfile, req.txt etc. then make sure it is runnable and add to the sample object.
        #? Daha düzgün nasıl yazılır şimdilik aklıma gelmedi ileride düzeltilebilir. Çok nested func. ama sırf güzel gözüksün diye araya başka parametre mi atayım?
        for sample in samples:
            sample.set_reqs(message_parsers(message_parsers.extract_reqs(api_router(in_prompt=sample.generate_reqs_prompt(),producer=sample.producer))))
            row = sample.get_all()
            db.fill_row_to_database(
                cwe = row["cwe"],
                producer = row["producer"],
                codetask = row["task"],
                webproduct = row["product"],
                webstyle = row["webstyle"],
                secure = row["is_secure"],
                code = row["code"],
                dockerfile = row["dockerfile"],
                sql_script = row["sql_script"],
                requirements = row["requirements"],
                port = row["port"]
            )


'''
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

for id in range(661, 2426):
    run_zap_scan(id, policy)
'''

