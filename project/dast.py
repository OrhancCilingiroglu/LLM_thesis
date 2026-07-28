from core import api_handler, db_handler, docker_handler, file_handler
from logic import code_pipeline, dast_pipeline, sast_pipeline
from utils import message_parsers, promptvariables
import traceback
import random
from utils import OWASP

db = db_handler.DBManager()
fm = file_handler.FileManager()
#docker = docker_handler.DockerManager()
zappolicy = "API"
api_router = api_handler.ApiHandlerRouter()


ids = db.get_docker_info_by_cwe(287)
ids2 = db.get_docker_info_by_cwe(295)
ids3 = db.get_docker_info_by_cwe(346)
ids4 = db.get_docker_info_by_cwe(384)
ids5 = db.get_docker_info_by_cwe(345)
ids6 = db.get_docker_info_by_cwe(502)
ids7 = db.get_docker_info_by_cwe(565)
ids8 = db.get_docker_info_by_cwe(829)


id_list = [row[0] for row in ids + ids2 + ids3 + ids4 + ids5 + ids6 + ids7 + ids8]

dast_pipeline.dast_scan(    # pending control will prevent retest of applications. not worling now should update
        start_id= None,
        end_id = None,
        id_list = id_list,
        save_result = db.save_scan_results,
        run_zap = False,
        run_nikto = False,
        run_burp = True,
        )