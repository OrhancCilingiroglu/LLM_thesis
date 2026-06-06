from concurrent.futures import ThreadPoolExecutor, as_completed
from core import api_handler, db_handler, docker_handler, file_handler
from logic import code_pipeline, dast_pipeline, sast_pipeline
from logic.docker_pipeline import docker_scan_parallel
from utils import message_parsers, promptvariables
import threading
import traceback
import time

db  = db_handler.DBManager()
fm  = file_handler.FileManager()
api_router = api_handler.ApiHandlerRouter()
zappolicy  = "API"

_docker_done = threading.Event()
def _sast_worker(
    first_id, last_id,
    run_bandit, run_semgrep, run_sonar,
    poll_interval: int = 30,
):
    """
    Docker thread'i çalışırken SAST tarafı da bağımsız ilerler.
    Her poll_interval saniyede bir DB'ye bakıp yeni successful ID'leri tarar.
    Docker thread bitince docker_done event'i set edilir, o tur biter ve çıkar.
    """
    sast_tools  = ["bandit", "semgrep", "sonarqube"]
    scanned_ids = set()   # bu oturumda zaten tarananları tekrar işleme

    while True:
        not_tested_map = db.get_not_tested_tools()

        docker_ok = set(
            i for i in db.get_ids_by_docker_status("tested-successful")
            if first_id <= i <= last_id
        )

        needs_sast = set()
        for tool in sast_tools:
            needs_sast.update(i for i in not_tested_map.get(tool, []) if i in docker_ok)

        # bu turda taranacak yeni ID'ler
        to_scan = sorted(needs_sast - scanned_ids)

        if to_scan:
            print(f"[SAST] {len(to_scan)} finding new ID: {to_scan[:5]}{'...' if len(to_scan) > 5 else ''}")
            sast_pipeline.sast_scan(
                id_list     = to_scan,
                get_code    = db.get_code,
                save_result = db.save_scan_results,
                run_bandit  = run_bandit,
                run_semgrep = run_semgrep,
                run_sonar   = run_sonar,
            )
            scanned_ids.update(to_scan)
        else:
            print(f"[SAST] No new codes to SAST, {poll_interval} is waiting...")

        # Docker thread bittiyse bir tur daha yap (son gelen successful'lar için) sonra çık
        if _docker_done.is_set():
            # son bir tarama daha
            not_tested_map = db.get_not_tested_tools()
            docker_ok = set(
                i for i in db.get_ids_by_docker_status("tested-successful")
                if first_id <= i <= last_id
            )
            needs_sast = set()
            for tool in sast_tools:
                needs_sast.update(i for i in not_tested_map.get(tool, []) if i in docker_ok)
            final_scan = sorted(needs_sast - scanned_ids)
            if final_scan:
                print(f"[SAST] Docker finished, last{len(final_scan)} ID is going through SAST...")
                sast_pipeline.sast_scan(
                    id_list     = final_scan,
                    get_code    = db.get_code,
                    save_result = db.save_scan_results,
                    run_bandit  = run_bandit,
                    run_semgrep = run_semgrep,
                    run_sonar   = run_sonar,
                )
            print("[SAST] Worker is idle.")
            return

        time.sleep(poll_interval)


def run_full_pipeline(
    first_id:    int  = None,
    last_id:     int  = None,
    run_bandit:  bool = True,
    run_semgrep: bool = True,
    run_sonar:   bool = True,
    run_zap:     bool = False,
    run_nikto:   bool = False,
    run_burp:    bool = False,
    docker_workers:  int = 2,
    sast_poll_interval: int = 30,   # SAST checks for incoming jobs
):
    if first_id is None or last_id is None:
        db_min, db_max = db.get_id_range()
        first_id = first_id if first_id is not None else db_min
        last_id  = last_id  if last_id  is not None else db_max
        print(f"[INFO] ID range automatic: {first_id} – {last_id}")

    print(f"\n{'='*60}")
    print(f"PIPELINE START  |  [{first_id} – {last_id}]")
    print(f"{'='*60}\n")

    _docker_done.clear()

    # --- Docker thread ---
    def _docker_worker():
        print(f"[DOCKER] Thread started, workers={docker_workers}")
        docker_scan_parallel(          # ← girintiye al
        start_id      = first_id,
        end_id        = last_id,
        update_status = db.update_docker_flag,
        max_workers   = docker_workers,
        )
        print("[DOCKER] Thread finished.")
        _docker_done.set()             # ← girintiye al

    threads = []
    t_docker = threading.Thread(target=_docker_worker, name="Docker-Thread")
    threads.append(("Docker", t_docker))

    # --- SAST thread (Docker ile paralel) ---
    t_sast = threading.Thread(
        target=_sast_worker,
        kwargs=dict(
            first_id     = first_id,
            last_id      = last_id,
            run_bandit   = run_bandit,
            run_semgrep  = run_semgrep,
            run_sonar    = run_sonar,
            poll_interval= sast_poll_interval,
        ),
        name="SAST-Thread",
    )
    threads.append(("SAST", t_sast))

    # --- DAST thread (sadece mevcut successful'lar, Docker bitince tekrar çağrılabilir) ---
    sast_tools = ["bandit", "semgrep", "sonarqube"]
    dast_tools = ["owasp_zap", "nicto", "burpsuite"]

    not_tested_map = db.get_not_tested_tools()
    docker_ok_now  = set(
        i for i in db.get_ids_by_docker_status("tested-successful")
        if first_id <= i <= last_id
    )
    needs_dast = set()
    for tool in dast_tools:
        needs_dast.update(i for i in not_tested_map.get(tool, []) if i in docker_ok_now)

    if needs_dast and (run_zap or run_nikto or run_burp):
        dast_id_list = sorted(needs_dast)
        print(f"[DAST] {len(dast_id_list)} ID taranacak")
        t_dast = threading.Thread(
            target=dast_pipeline.dast_scan,
            kwargs=dict(
                start_id    = None,
                end_id      = None,
                id_list     = dast_id_list,
                save_result = db.save_scan_results,
                run_zap     = run_zap,
                run_nikto   = run_nikto,
                run_burp    = run_burp,
            ),
            name="DAST-Thread",
        )
        threads.append(("DAST", t_dast))

    for name, t in threads:
        print(f"[START] {name} thread başlatılıyor...")
        t.start()

    for name, t in threads:
        t.join()
        print(f"[DONE] {name} thread bitti.")

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
        first_id = None,
        last_id= None,
        run_bandit     = True,
        run_semgrep    = True,
        run_sonar      = True,
        run_zap        = False,
        run_nikto      = False,
        run_burp       = False,
        docker_workers = 6,
    )

    #! uncomment to run as a continuous loop alongside the generation script
    '''
    run_scan_loop(
         interval_seconds = 120,
         run_bandit  = True,
         run_semgrep = True,
         run_sonar   = True,
         run_zap     = True,
    )'''