import os
import json
import argparse
from datetime import datetime

from core.db_handler import DBManager


EVAL_PROMPT = """You are a Static Application Security Testing (SAST) tool.
List the CWE IDs present in the following code.
Output ONLY a comma-separated list like: CWE-xx, CWE-yy.
If none, output: NONE.

<CODE>
{code}
</CODE>
"""


TRAINING_PROMPT = """You are a Static Application Security Testing (SAST) tool.
Use the following tool outputs as additional evidence and list the CWE IDs present in the code.
Output ONLY a comma-separated list like: CWE-xx, CWE-yy.
If none, output: NONE.

### Code
<CODE>
{code}
</CODE>

### Tool Outputs
- bandit:
{bandit}

- semgrep:
{semgrep}

- sonarqube:
{sonarqube}

- owasp_zap:
{owasp_zap}
"""


def export_local_llm_jsonl(out_dir, mode, file_name, docker_status, limit):
    # Prepare output path
    os.makedirs(out_dir, exist_ok=True)

    if file_name:
        if file_name.endswith(".py"):
            file_name = file_name[:-3]
    else:
        file_name = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Add mode to filename
    out_path = os.path.join(out_dir, f"local_llm_{mode}_{file_name}.jsonl")

    db = DBManager()

    # Get IDs
    if docker_status:
        ids = db.get_ids_by_docker_status(docker_status)
    else:
        ids = db.get_all_ids()

    if limit:
        ids = ids[:limit]

    written = 0
    created_at = datetime.now().isoformat(timespec="seconds")

    with open(out_path, "w", encoding="utf-8") as f:
        for code_id in ids:
            code_row = db.get_code(code_id)
            if not code_row:
                continue

            code = (code_row[0] or "").strip()
            if not code:
                continue

            if mode == "eval":
                prompt = EVAL_PROMPT.format(code=code)

                record = {
                    "id": code_id,
                    "code": code,
                    "prompt": prompt,
                    "local_llm_response": "",
                    "local_llm_model": "",
                    "meta": {
                        "created_at": created_at,
                        "docker_status": docker_status,
                    }
                }

            elif mode == "training":
                # Read SAST columns via DBManager
                sast_row = db.fetch_sast_data_by_id(code_id, ["bandit", "semgrep", "sonarqube"])
                bandit = ""
                semgrep = ""
                sonarqube = ""
                if sast_row:
                    # sast_row = (id, bandit, semgrep, sonarqube)
                    bandit = str(sast_row[1] or "")
                    semgrep = str(sast_row[2] or "")
                    sonarqube = str(sast_row[3] or "")

                # Read DAST column (OWASP ZAP) via DBManager
                dast_row = db.fetch_dast_data_by_id(code_id)
                owasp_zap = ""
                if dast_row:
                    # dast_row = (id, owasp_zap)
                    owasp_zap = str(dast_row[1] or "")

                # Build training prompt with tool evidence
                prompt = TRAINING_PROMPT.format(
                    code=code,
                    bandit=bandit if bandit else "NONE",
                    semgrep=semgrep if semgrep else "NONE",
                    sonarqube=sonarqube if sonarqube else "NONE",
                    owasp_zap=owasp_zap if owasp_zap else "NONE",
                )

                db_cwe = db.get_CWE_by_id(code_id)

                record = {
                    "id": code_id,
                    "code": code,
                    "prompt": prompt,
                    "target": db_cwe,  # training label
                    "tools": {
                        "bandit": bandit,
                        "semgrep": semgrep,
                        "sonarqube": sonarqube,
                        "owasp_zap": owasp_zap,
                    },
                    "meta": {
                        "created_at": created_at,
                        "docker_status": docker_status,
                        "db_secure": db.is_secure_by_id(code_id),
                    }
                }

            else:
                raise ValueError("Invalid mode. Use 'eval' or 'training'.")

            json.dump(record, f, ensure_ascii=False)
            f.write("\n")
            written += 1

    print(f"JSONL written: {out_path}")
    print(f"Total rows: {written}")
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="eval", choices=["eval", "training"])
    parser.add_argument("--docker_status", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--file_name", default=None)

    args = parser.parse_args()

    BASE_DIR = os.path.dirname(__file__)
    OUT_DIR = os.path.join(BASE_DIR, "exports")

    export_local_llm_jsonl(
        out_dir=OUT_DIR,
        mode=args.mode,
        file_name=args.file_name,
        docker_status=args.docker_status,
        limit=args.limit,
    )
