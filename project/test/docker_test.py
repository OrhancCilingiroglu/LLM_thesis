# dockertest.py  →  artık sadece bu kadar
from logic.docker_pipeline import docker_scan
from core.db_handler import DBManager

db = DBManager()
docker_scan(
    start_id=12394,
    end_id=12419,
    update_status=db.update_docker_flag,
    skip_already_tested = False,

)