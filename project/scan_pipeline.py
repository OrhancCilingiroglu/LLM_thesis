from concurrent.futures import ThreadPoolExecutor, as_completed
from core import api_handler, db_handler, docker_handler, file_handler
from logic import code_pipeline, dast_pipeline, sast_pipeline
from utils import message_parsers, promptvariables
import threading
import traceback
import time

db  = db_handler.DBManager()
fm  = file_handler.FileManager()
api_router = api_handler.ApiHandlerRouter()
zappolicy  = "API"


def _test_single_docker(code_id):
    # grab everything we need for this container from the db
    code, dockerfile, sql_script, port_temp, reqs, docker_status = db.get_files_by_id(code_id)

    if docker_status != "not-tested":
        print(f"SKIP: code_id={code_id} status={docker_status}")
        return

    dm, workdir_temp = None, None
    try:
        workdir_temp = fm.setup_files(code_id, code, dockerfile, sql_script, reqs)

        if fm.run_sql_script(code_id, sql_script):
            print(f"SQL OK: code_id={code_id}")
        else:
            print(f"SQL FAIL: code_id={code_id}")
            db.mark_sql_failed(code_id)

        dm = docker_handler.DockerManager(workdir=workdir_temp, tag=code_id, port=port_temp)

        if not dm.build_image():
            print(f"DOCKER BUILD FAIL: code_id={code_id}")
            db.mark_docker_tested_failed(code_id)
            return

        if dm.run_container():
            print(f"DOCKER RUN SUCCESS: code_id={code_id}")
            db.mark_docker_tested_successful(code_id)
        else:
            print(f"DOCKER RUN FAIL: code_id={code_id}")
            db.mark_docker_tested_failed(code_id)

    except Exception as e:
        traceback.print_exc()
        print(f"FAIL: code_id={code_id} — {e}")
        try:
            db.mark_docker_tested_failed(code_id)
        except Exception:
            pass
    finally:
        try:
            if dm:
                dm.stop_and_remove()
        except Exception:
            pass
        try:
            if workdir_temp:
                fm.remove_files(code_id)
        except Exception:
            pass


def test_docker_runs2(first_id=None, last_id=None, max_workers: int = 2):
    # each code already has a fixed port in the db so no collision risk here
    # keep max_workers low, docker is heavy on cpu and ram
    not_tested = db.get_not_tested_tools()["docker"]

    # narrow down to given range if provided
    if first_id is not None and last_id is not None:
        not_tested = [i for i in not_tested if first_id <= i <= last_id]

    if not not_tested:
        print("[DOCKER] Nothing to test.")
        return

    print(f"[DOCKER] {len(not_tested)} IDs to test, max_workers={max_workers}")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_test_single_docker, cid): cid for cid in not_tested}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                print(f"[DOCKER THREAD ERR] {e}")


def run_full_pipeline(
    first_id:    int  = None,
    last_id:     int  = None,
    run_bandit:  bool = True,
    run_semgrep: bool = True,
    run_sonar:   bool = True,
    run_zap:     bool = True,
    run_nikto:   bool = False,
    run_burp:    bool = False,
    docker_workers: int = 2,
):
    # fall back to full db range if no ids given
    if first_id is None or last_id is None:
        db_min, db_max = db.get_id_range()
        first_id = first_id if first_id is not None else db_min
        last_id  = last_id  if last_id  is not None else db_max
        print(f"[INFO] ID range set automatically: {first_id} – {last_id}")

    print(f"\n{'='*60}")
    print(f"PIPELINE START  |  range: [{first_id} – {last_id}]")
    print(f"{'='*60}\n")

    # step 1: only test docker for ids that haven't been tested yet
    print(f"[STEP 1] Docker tests starting... (workers={docker_workers})")
    test_docker_runs2(first_id, last_id, max_workers=docker_workers)
    print("[STEP 1] Docker tests done.\n")

    # step 2: figure out which ids still need sast and/or dast
    # get_not_tested_tools returns per-tool not-tested id lists
    not_tested_map = db.get_not_tested_tools()  

    # only care about ids that passed docker and fall in our range
    docker_ok = db.get_ids_by_docker_status("tested-successful")
    docker_ok = set(i for i in docker_ok if first_id <= i <= last_id)

    # ids that need sast = docker ok AND at least one sast tool not yet run
    sast_tools   = ["bandit", "semgrep", "sonarqube"]
    dast_tools   = ["owasp_zap", "nicto", "burpsuite"]

    needs_sast = set()
    for tool in sast_tools:
        needs_sast.update(i for i in not_tested_map.get(tool, []) if i in docker_ok)

    needs_dast = set()
    for tool in dast_tools:
        needs_dast.update(i for i in not_tested_map.get(tool, []) if i in docker_ok)

    print(f"[INFO] {len(needs_sast)} ID(s) need SAST | {len(needs_dast)} ID(s) need DAST")

    if not needs_sast and not needs_dast:
        print("[!] Everything already scanned. Pipeline stopping.")
        return

    # run sast and dast in parallel, they don't depend on each other
    print("[STEP 2] SAST + DAST starting in parallel...")

    threads = []

    if needs_sast:
        sast_start = min(needs_sast)
        sast_end   = max(needs_sast)
        sast_kwargs = dict(
            start_id    = sast_start,
            end_id      = sast_end,
            get_code    = db.get_code,
            save_result = db.save_scan_results,
            run_bandit  = run_bandit,
            run_semgrep = run_semgrep,
            run_sonar   = run_sonar,
        )
        t = threading.Thread(target=sast_pipeline.sast_scan, kwargs=sast_kwargs, name="SAST-Thread")
        threads.append(("SAST", t))

    if needs_dast:
        dast_start = min(needs_dast)
        dast_end   = max(needs_dast)
        dast_kwargs = dict(
            start_id    = dast_start,
            end_id      = dast_end,
            save_result = db.save_scan_results,
            run_zap     = run_zap,
            run_nikto   = run_nikto,
            run_burp    = run_burp,
        )
        t = threading.Thread(target=dast_pipeline.dast_scan, kwargs=dast_kwargs, name="DAST-Thread")
        threads.append(("DAST", t))

    for name, t in threads:
        t.start()

    for name, t in threads:
        t.join()
        print(f"[STEP 2] {name} done.")

    print(f"\n{'='*60}")
    print(f"PIPELINE COMPLETE")
    print(f"{'='*60}\n")


def run_scan_loop(interval_seconds: int = 120, **pipeline_kwargs):
    # meant to run alongside the generation script in a separate terminal
    # picks up newly generated rows automatically without needing manual id ranges
    print(f"[LOOP] Continuous scan loop started. Interval: {interval_seconds}s")
    while True:
        not_tested_map = db.get_not_tested_tools()
        has_work = any(len(ids) > 0 for ids in not_tested_map.values())
        if has_work:
            print(f"[LOOP] Pending work found, running pipeline...")
            run_full_pipeline(**pipeline_kwargs)
        else:
            print(f"[LOOP] Nothing new. Waiting {interval_seconds}s...")
            time.sleep(interval_seconds)


if __name__ == "__main__":
    run_full_pipeline(
        first_id = 4494,
        last_id=  4571,
        run_bandit     = True,
        run_semgrep    = True,
        run_sonar      = True,
        run_zap        = True,
        run_nikto      = False,
        run_burp       = False,
        docker_workers = 2,
    )

    #! uncomment to run as a continuous loop alongside the generation script
    # run_scan_loop(
    #     interval_seconds = 120,
    #     run_bandit  = True,
    #     run_semgrep = True,
    #     run_sonar   = True,
    #     run_zap     = True,
    # )