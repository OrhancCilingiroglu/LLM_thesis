from concurrent.futures import ThreadPoolExecutor, as_completed
from core import api_handler, db_handler, docker_handler, file_handler
from logic import code_pipeline, dast_pipeline, sast_pipeline
from utils import message_parsers, promptvariables
import traceback
import random
from utils import OWASP
db = db_handler.DBManager()
fm = file_handler.FileManager()
zappolicy = "API"
api_router = api_handler.ApiHandlerRouter()

port_allo_openai_sec  = code_pipeline.PortAllocator(5000)
port_allo_openai_vuln = code_pipeline.PortAllocator(6000)
port_allo_groq_sec    = code_pipeline.PortAllocator(7000)
port_allo_groq_vuln   = code_pipeline.PortAllocator(8000)
port_allo_claude_vuln = code_pipeline.PortAllocator(9000)
port_allo_claude_sec  = code_pipeline.PortAllocator(10000)

PORT_MAP = {
    "openai": [port_allo_openai_sec,  port_allo_openai_vuln],
    "groq":   [port_allo_groq_sec,    port_allo_groq_vuln],
    "claude": [port_allo_claude_sec,  port_allo_claude_vuln],
}

PRODUCERS = list(PORT_MAP.keys())
TARGET_PER_CWE = 60


def needed_iterations(cwe: int) -> int:
    existing        = db.count_rows_by_cwe(cwe)
    shortage        = max(0, TARGET_PER_CWE - existing)
    codes_per_round = len(PRODUCERS) * 2
    return -(-shortage // codes_per_round)


# ── Thread worker'ları ────────────────────────────────────────────────────────

def _produce_code(sample):
    """Adım 1 — tek sample için kod üret (thread'de çalışır)"""
    try:
        code_resp    = api_router.send_prompt(
            in_prompt=sample.generate_code_prompt(),
            producer=sample.producer
        )
        cleaned_code = message_parsers.clean_code_response(code_resp)
        sample.set_code(cleaned_code)
        print(f"[CODE OK] {sample.producer} | CWE-{sample.cwe} | secure={sample.is_secure} | len={len(cleaned_code)}")
    except Exception as e:
        print(f"[CODE ERR] {sample.producer} | CWE-{sample.cwe} | {e}")
        sample.set_code(None)
    return sample


def _control_check(sample):
    """Adım 2 — tek sample için kontrol isteği at (thread'de çalışır)"""
    try:
        resp = api_router.send_prompt(
            in_prompt=sample.generate_check_prompt(),
            producer=sample.producer
        )
        ok = sample.control_checks(resp)
        print(f"[CHECK] {sample.producer} | CWE-{sample.cwe} | secure={sample.is_secure} | ok={ok} | resp='{resp[:60]}'")
        return sample, ok
    except Exception as e:
        print(f"[CHECK ERR] {sample.producer} | CWE-{sample.cwe} | {e}")
        return sample, False


def _produce_reqs(sample):
    """Adım 3 — tek sample için dockerfile/reqs üret (thread'de çalışır)"""
    try:
        resp = api_router.send_prompt(
            in_prompt=sample.generate_reqs_prompt(),
            producer=sample.producer
        )
        dockerfile_s, sql_script_s, requirements_s = message_parsers.extract_reqs(resp)
        sample.set_reqs(
            dockerfile=dockerfile_s,
            sql_script=sql_script_s,
            requirements=requirements_s
        )
        print(f"[REQS OK] {sample.producer} | CWE-{sample.cwe}")
    except Exception as e:
        print(f"[REQS ERR] {sample.producer} | CWE-{sample.cwe} | {e}")
    return sample


# ── Ana üretim fonksiyonu ─────────────────────────────────────────────────────

def generate_code(cwe_list: list, producers: list = None, max_workers: int = 3):
    if producers is None:
        producers = PRODUCERS

    for cwe in cwe_list:
        iterations = needed_iterations(cwe)
        if iterations == 0:
            print(f"CWE-{cwe} samples are enough, skipping...")
            continue
        print(f"\n[~] CWE-{cwe}: {iterations} iterations starting...")

        for i in range(iterations):
            print(f"  [iter {i+1}/{iterations}]")
            coding_task = random.choice(promptvariables.coding_tasks)
            webstyle    = random.choice(promptvariables.website_styles)
            webproduct  = random.choice(promptvariables.website_products)

            # ── 1) Sample listesi oluştur ─────────────────────────
            samples = []
            for producer in producers:
                sec_port, vuln_port = PORT_MAP[producer]
                samples.append(code_pipeline.AppSample(
                    cwe=cwe, task=coding_task, webstyle=webstyle,
                    product=webproduct, is_secure=True,
                    port=sec_port.get_port(), producer=producer
                ))
                samples.append(code_pipeline.AppSample(
                    cwe=cwe, task=coding_task, webstyle=webstyle,
                    product=webproduct, is_secure=False,
                    port=vuln_port.get_port(), producer=producer
                ))

            # ── 2) Paralel kod üretimi ────────────────────────────
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_produce_code, s): s for s in samples}
                samples = [f.result() for f in as_completed(futures)]

            # None kod üretilenler çıkar
            samples = [s for s in samples if s.code is not None]
            if not samples:
                print(f"  [!] Tüm sample'lar başarısız, iter atlanıyor.")
                continue

            # ── 3) Paralel kontrol döngüsü (3 tur) ───────────────
            for round_no in range(3):
                samples_to_delete = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(_control_check, s): s for s in samples}
                    for f in as_completed(futures):
                        sample, ok = f.result()
                        if not ok and sample not in samples_to_delete:
                            samples_to_delete.append(sample)
                            sec_p, vuln_p = PORT_MAP[sample.producer]
                            (sec_p if sample.is_secure else vuln_p).decrement()

                samples = [s for s in samples if s not in samples_to_delete]
                print(f"  [CHECK round {round_no+1}] {len(samples)} sample(s) passed.")

            if not samples:
                print(f"  [!] Kontrol geçemeyen sample kalmadı, iter atlanıyor.")
                continue

            # ── 4) Paralel dockerfile/reqs üretimi ───────────────
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_produce_reqs, s): s for s in samples}
                samples = [f.result() for f in as_completed(futures)]

            # ── 5) DB'ye sıralı kaydet (SQLite thread-safe değil) ─
            for sample in samples:
                row = sample.get_all()
                if not row["dockerfile"]:
                    print(f"  [SKIP] {row['producer']} | CWE-{row['cwe']} — dockerfile boş")
                    continue
                print(f"[DB SAVE] producer={row['producer']} | cwe={row['cwe']} | code_len={len(row['code'] or '')}")
                db.fill_row_to_database(
                    cwe=row["cwe"],           producer=row["producer"],
                    codetask=row["task"],     webproduct=row["product"],
                    webstyle=row["webstyle"], secure=row["is_secure"],
                    code=row["code"],         dockerfile=row["dockerfile"],
                    sql_script=row["sql_script"], requirements=row["requirements"],
                    port=row["port"],         producer_model=api_router.get_model(row["producer"]),
                )


if __name__ == "__main__":
    # Guarded so `import main` (e.g. to reuse generate_code()/needed_iterations()
    # from another script) can't accidentally trigger a full, unbounded,
    # real-API-cost generation run across all 10 OWASP categories as a side
    # effect of the import. `python main.py` still runs all ten, unchanged.
    generate_code(cwe_list=OWASP.A01_2025_Broken_Access_Control_list)
    generate_code(cwe_list=OWASP.A02_2025_Security_Misconfiguration_list)
    generate_code(cwe_list=OWASP.A03_2025_Sofware_Supply_Chain_list)
    generate_code(cwe_list=OWASP.A04_2025_Cryptographic_Failures_list)
    generate_code(cwe_list=OWASP.A05_2025_Injection_list)
    generate_code(cwe_list=OWASP.A06_2025_Insecure_Design_list)
    generate_code(cwe_list=OWASP.A07_2025_Authentication_Failures_list)
    generate_code(cwe_list=OWASP.A08_2025_Software_or_Data_Integrity_Failures_list)
    generate_code(cwe_list=OWASP.A09_2025_Security_Logging_and_Alerting_Failures_list)
    generate_code(cwe_list=OWASP.A10_2025_Mishandling_of_Exceptional_Conditions_list)

#Production continues below here

 