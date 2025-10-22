from core.file_handler import FileManager
from core.db_handler import DBManager
from core.docker_handler import DockerManager
import os


def test_file_setup():
    code_id = "test2"
    code = "print('Hello')"
    dockerfile = "FROM python:3.12"
    sql_script = "CREATE TABLE test(id INTEGER);"
    requirements = "flask"

    fm = FileManager()
    path = fm.setup_files(code_id, code, dockerfile, sql_script, requirements)

    assert os.path.exists(os.path.join(path, "app.py"))
    assert os.path.exists(os.path.join(path, "Dockerfile"))
    assert os.path.exists(os.path.join(path, "init.sql"))
    assert os.path.exists(os.path.join(path, "requirements.txt"))
    print("[✓] test_file_setup passed")


def test_docker(id):
    #973 seems successfull on previous work
    db = DBManager()
    fm = FileManager()
    code, dockerfile, sql_script, port, reqs, docker = db.get_files_by_id(id)
    workdir = fm.setup_files(id, code, dockerfile, sql_script, reqs)
    fm.run_sql_script(id, sql_script)
    dcm = DockerManager(workdir, id, port)
    dcm.build_image()
    dcm.run_container()
    dcm.stop_and_remove()

test_docker()