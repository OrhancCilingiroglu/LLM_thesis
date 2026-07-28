# dockertest.py  →  artık sadece bu kadar
from logic.docker_pipeline import docker_scan
from core.db_handler import DBManager

db = DBManager()
docker_scan(
    start_id=26041,
    end_id=30000,
    update_status=db.update_docker_flag,
    skip_already_tested = True,

)