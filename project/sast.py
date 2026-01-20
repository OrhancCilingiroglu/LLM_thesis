from logic.sast_pipeline import sast_scan
from core.db_handler import DBManager

db = DBManager()



if __name__ == "__main__":
    sast_scan(
        start_id=2427,
        end_id=2458,
        get_code=db.get_code,
        save_result=db.save_scan_results,
        run_bandit=True,
        run_semgrep=True,
        run_sonar=True
    )
