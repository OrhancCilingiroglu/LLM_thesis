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

# [20, 74, 76, 79, 80, 83, 89, 93, 94, 95, 99, 113, 115, 116, 129, 159, 610, 644]
ids = db.get_docker_info_by_cwe(116)
ids2 = db.get_docker_info_by_cwe(159)
ids3 = db.get_docker_info_by_cwe(20)

id_list = [row[0] for row in ids + ids2 + ids3]

dast_pipeline.dast_scan(    # pending control will prevent retest of applications.
        start_id= None,
        end_id = None,
        id_list = id_list,
        save_result = db.save_scan_results,
        run_zap = False,
        run_nikto = False,
        run_burp = True,
        )