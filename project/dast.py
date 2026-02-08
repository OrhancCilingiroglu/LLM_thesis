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


dast_pipeline.dast_scan(
    start_id= 2811,
    end_id = 3531,
    save_result = db.save_scan_results,
    run_zap = True,
    run_nikto = False,
    run_burp = False,
)