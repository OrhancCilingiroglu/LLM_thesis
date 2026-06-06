# dockertest.py  →  artık sadece bu kadar
from logic.docker_pipeline import docker_scan
from core.db_handler import DBManager

db = DBManager()
docker_scan(
    start_id=21491,
    end_id=25000,
    update_status=db.update_docker_flag,
    skip_already_tested = True,

)