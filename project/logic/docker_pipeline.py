# logic/docker_pipeline.py
from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from core import db_handler, docker_handler, file_handler

UpdateStatusFn = Callable[[int, str], None]   # (code_id, status)

# Prune dangling images and build cache after every N completed tests
# to prevent disk exhaustion during long batch runs.
_PRUNE_EVERY_N = 50


#* Low-level: single container lifecycle

def _run_single(
    code_id: int,
    db: db_handler.DBManager,
    fm: file_handler.FileManager,
) -> str:
    """Build, run, health-check, and fully clean up one container.
    Returns the final docker status string so the caller can persist it.
    Cleanup order in the finally block is intentional:
      1. dm.full_cleanup()  — stop container → remove container → remove image
      2. fm.remove_files()  — delete the app_data/app_{id} directory on disk
    This ensures the Docker daemon has released all file handles before the
    source directory is removed, which prevents 'device busy' errors on Linux.
    """
    try:
        code, dockerfile, sql_script, port, reqs, _ = db.get_files_by_id(code_id)
    except ValueError:
        print(f"SKIP: code_id={code_id} not found in DB.")
        return None   # None = caller should not call update_status

    dm = None
    workdir = None
    status = "tested-failed"

    try:
        # 1.Prepare working directory
        workdir = fm.setup_files(code_id, code, dockerfile, sql_script, reqs)

        if not fm.run_sql_script(code_id, sql_script):
            print(f"SQL FAIL: code_id={code_id}")
            return "sql-failed"

        # 2.Build
        dm = docker_handler.DockerManager(workdir=workdir, tag=code_id, port=port)

        if not dm.build_image():
            print(f"DOCKER BUILD FAIL: code_id={code_id}")
            return "tested-failed"

        #3.Run + liveness check
        container = dm.run_container()
        if container:
            print(f"DOCKER RUN SUCCESS: code_id={code_id}")
            status = "tested-successful"
        else:
            print(f"DOCKER RUN FAIL: code_id={code_id}")
            status = "tested-failed"

    except Exception as e:
        traceback.print_exc()
        print(f"FAIL: code_id={code_id} — {e}")
        status = "tested-failed"

    finally:
        # 4.Container + image removal
        try:
            if dm is not None:
                dm.full_cleanup()
            else:
                # dm was never assigned (e.g. setup_files raised) but a stale
                # image from a previous crash may still exist.
                _emergency = docker_handler.DockerManager(
                    workdir=".", tag=code_id, port=0
                )
                _emergency.full_cleanup()
        except Exception:
            pass

        # 5. Disk cleanup
        try:
            if workdir is not None:
                fm.remove_files(code_id)
        except Exception:
            pass

    return status


# ---------------------------------------------------------------------------
# Public API: sequential scan
# ---------------------------------------------------------------------------

def docker_scan(
    *,
    start_id: int | None = None,
    end_id:   int | None = None,
    id_list:  list[int] | None = None,
    update_status: UpdateStatusFn,
    skip_already_tested: bool = True,
) -> None:
    """Run Docker build/run tests sequentially for the given ID range or list.

    Parameters
    ----------
    start_id / end_id:
        Inclusive range to process. Ignored when id_list is given.
    id_list:
        Explicit list of IDs to process. Takes priority over start/end range.
    update_status:
        Callback that persists the final docker status to the database.
        Signature: (code_id: int, status: str) -> None
        Example:   db.update_docker_flag
    skip_already_tested:
        When True (default), IDs whose docker column is not 'not-tested' are
        silently skipped. Set to False to force re-testing.
    """
    db = db_handler.DBManager()
    fm = file_handler.FileManager()

    # Resolve ID list
    if id_list is not None:
        code_ids = id_list
    elif start_id is not None and end_id is not None:
        all_db_ids = set(db.get_all_ids())
        code_ids = [i for i in range(start_id, end_id + 1) if i in all_db_ids]
    else:
        raise ValueError("Provide either start_id + end_id, or id_list.")

    # Filter to not-tested IDs if requested
    if skip_already_tested:
        not_tested = set(db.get_not_tested_tools().get("docker", []))
        code_ids = [i for i in code_ids if i in not_tested]

    if not code_ids:
        print("[DOCKER] Nothing to test.")
        return

    print(f"[DOCKER] Sequential scan — {len(code_ids)} IDs")

    completed = 0
    for code_id in code_ids:
        final_status = _run_single(code_id, db, fm)
        if final_status is None:
            continue
        update_status(code_id, final_status)
        if final_status == "tested-successful":
            completed += 1          

        # Periodic prune to reclaim disk during long runs
        if completed > 0 and completed % _PRUNE_EVERY_N == 0:
            docker_handler.DockerManager.prune_dangling_images()
            docker_handler.DockerManager.prune_build_cache()

    # Final prune after the full batch
    docker_handler.DockerManager.prune_dangling_images()
    docker_handler.DockerManager.prune_build_cache()
    print(f"[DOCKER] Sequential scan complete — {completed}/{len(code_ids)} successful.")


# ---------------------------------------------------------------------------
# Public API: parallel scan
# ---------------------------------------------------------------------------

def docker_scan_parallel(
    *,
    start_id: int | None = None,
    end_id:   int | None = None,
    id_list:  list[int] | None = None,
    update_status: UpdateStatusFn,
    max_workers: int = 2,
    skip_already_tested: bool = True,
) -> None:
    """Run Docker build/run tests in parallel using a thread pool.

    Keep max_workers low (default 2): each worker occupies a host port and
    Docker is CPU/RAM-heavy. Running too many in parallel causes flaky failures
    that are difficult to distinguish from genuine application errors.

    Parameters
    ----------
    max_workers:
        Number of concurrent Docker workers. Each code_id has a fixed port in
        the DB so there is no port-collision risk within the same batch.
    All other parameters are identical to docker_scan().
    """
    db = db_handler.DBManager()
    fm = file_handler.FileManager()

    # Resolve ID list
    if id_list is not None:
        code_ids = id_list
    elif start_id is not None and end_id is not None:
        code_ids = list(range(start_id, end_id + 1))
    else:
        raise ValueError("Provide either start_id + end_id, or id_list.")

    # Filter to not-tested IDs if requested
    if skip_already_tested:
        not_tested = set(db.get_not_tested_tools().get("docker", []))
        code_ids = [i for i in code_ids if i in not_tested]

    if not code_ids:
        print("[DOCKER] Nothing to test.")
        return

    print(f"[DOCKER] Parallel scan — {len(code_ids)} IDs, max_workers={max_workers}")

    completed = 0

    def _worker(code_id: int) -> tuple[int, str]:
        """Thread entry point — returns (code_id, status) for the main thread."""
        status = _run_single(code_id, db, fm)
        return code_id, status

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_worker, cid): cid for cid in code_ids}
        for future in as_completed(futures):
            try:
                code_id, final_status = future.result()
                if final_status is None:
                    continue
                update_status(code_id, final_status)
                if final_status == "tested-successful":
                    completed += 1

                # Periodic prune — runs in the main thread, not workers
                if completed > 0 and completed % _PRUNE_EVERY_N == 0:
                    docker_handler.DockerManager.prune_dangling_images()
                    docker_handler.DockerManager.prune_build_cache()

            except Exception as e:
                print(f"[DOCKER THREAD ERR] {e}")

    # Final prune after the full batch
    docker_handler.DockerManager.prune_dangling_images()
    docker_handler.DockerManager.prune_build_cache()
    print(f"[DOCKER] Parallel scan complete — {completed}/{len(code_ids)} successful.")