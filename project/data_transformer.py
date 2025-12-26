import os
from core.db_handler import DBManager 

def main():
    db = DBManager()
    out_path = os.path.join(os.path.dirname(__file__), "code_cwe_llm_train.jsonl")

    db.export_llm_jsonl(
        out_path=out_path,
        only_docker_status="tested-successful", 
        limit=2209,  # None => take all
    )
    print(f"\n✅ JSONL export complete!\nSaved to: {out_path}\n")

if __name__ == "__main__":
    main()
