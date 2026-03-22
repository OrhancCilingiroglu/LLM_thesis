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

ids__SQL = db.get_docker_info_by_cwe(89)
ids_leftover = [(474, 5065), (476, 5066), (478, 5067), (479, 6068), (480, 5068), (481, 6069), (482, 5069), (483, 6070), (487, 6072), (488, 5072), (489, 6073), (491, 6074), (492, 5074), (493, 6075), (495, 6076), (496, 5076), (497, 6077), (498, 5077), (499, 6078), (500, 5078), (501, 6079), (502, 5079), (504, 5080), (505, 6081), (508, 5082), (511, 6084), (512, 5084), (513, 6085), (3068, 5094), (3069, 6094), (3071, 8063), (3566, 5010), (3567, 6010), (3691, 6010), (3693, 8006)]
sql_lists = [row[0] for row in ids_leftover]  # take only id number for now → [439, 441, 442, ...]
ids_OScommand = db.get_docker_info_by_cwe(77)
os_list = [row[0] for row in ids_OScommand]

dast_pipeline.dast_scan(
    start_id= None,
    end_id = None,
    id_list = os_list,
    save_result = db.save_scan_results,
    run_zap = False,
    run_nikto = False,
    run_burp = True,
)