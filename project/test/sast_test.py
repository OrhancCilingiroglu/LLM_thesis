from logic.sast_pipeline import sast_scan
from core.db_handler import DBManager

db = DBManager()

def fake_save_result(code_id: int, tool: str, result: str) -> None:
    print(f"[SAVE-FAKE] id={code_id} | tool={tool} | result={result[:100]}")

# --- Test Run ---
if __name__ == "__main__":
    sast_scan(
        start_id=1,
        end_id=20,
        get_code=db.get_code,
        save_result=fake_save_result,
        run_bandit=False,
        run_semgrep=True,
        run_sonar=False
    )
