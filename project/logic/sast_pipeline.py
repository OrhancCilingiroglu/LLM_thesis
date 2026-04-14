# logic/static_pipeline.py
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
import utils.message_parsers
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple
from dotenv import load_dotenv
import requests
import time

load_dotenv()
sonar_token = os.getenv("usertoken")

# SAST Commands
def run_bandit_on_code(code):
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name
    try:
        result = subprocess.run(["bandit", "-r", fname], capture_output=True, text=True)
        #print(result)
        bandit_result = utils.message_parsers.analyze_static_output(result.stdout)
        #print(bandit_result)
    except Exception:
        bandit_result = "error"
    #    result ="error"
    os.remove(fname)
    return bandit_result
    #return result

def run_semgrep_on_code(code: str, rulesets: default_semgrep_rules) -> str:
    rulesets = [r.strip() for r in (rulesets or []) if r and r.strip()]
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name

    cwes_found: set[str] = set()
    try:
        for ruleset in rulesets:
            try:
                proc = subprocess.run(
                    ["semgrep", "--quiet", "--config", ruleset, "--json", fname],
                    capture_output=True, text=True
                )
                # 0: no findings, 1: findings 
                if proc.returncode not in (0, 1):
                    continue
                data = json.loads(proc.stdout or "{}")  
                for finding in data.get("results", []):
                    meta = finding.get("extra", {}).get("metadata", {})
                    cwe_list = meta.get("cwe", []) or []
                    for c in cwe_list:
                        cwes_found.add(str(c).split(":")[0].strip())
            except Exception:
                continue
        return ",".join(sorted(cwes_found)) if cwes_found else "None"
    except Exception as e:
        return f"error: {e}"
    finally:
        try: os.remove(fname)  # type: ignore[name-defined]
        except Exception: pass

def default_semgrep_rules() -> list[str]:
    return [
        "p/owasp-top-ten",
        "p/cwe-top-25",
        "p/python",
        "p/injection",
        "p/sql-injection",
    ]

##! Part for Sonarqube and necessary functions

def _extract_ce_task_id(scanner_stdout: str) -> str | None:
        """
        Sonar Scanner generally contains a line at the output like
        "More about the report processing at http://.../api/ce/task?id=AX..."
        Take id from that
        """
        if not scanner_stdout:
            return None
        for line in scanner_stdout.splitlines():
            if "/api/ce/task?id=" in line:
                try:
                    return line.split("/api/ce/task?id=", 1)[1].strip()
                except Exception:
                    pass
        for line in scanner_stdout.splitlines():
            if "ceTaskId" in line and "=" in line:
                # kaba yakalama
                parts = line.split("=", 1)
                if len(parts) == 2:
                    candidate = parts[1].strip()
                    if candidate:
                        return candidate
        return None
def _wait_for_ce_task(base_url: str, ce_task_id: str, headers: dict, timeout_s: int = 120, poll_s: float = 1.0) -> dict:
    """
    Wait until SonarQube CE task is done, return the final payload.
    """
    deadline = time.time() + timeout_s
    url = f"{base_url}/api/ce/task?id={ce_task_id}"

    last_payload = None
    while time.time() < deadline:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"CE task API error: {r.status_code} {r.text}")

        payload = r.json()
        last_payload = payload
        status = (payload.get("task") or {}).get("status")
        if status == "SUCCESS":
            return payload
        if status in ("FAILED", "CANCELED"):
            raise RuntimeError(f"CE task ended with status={status}: {payload}")

        time.sleep(poll_s)

    raise TimeoutError(f"CE task did not finish within {timeout_s}s. Last payload: {last_payload}")

def _paginate(endpoint_url: str, headers: dict, page_size: int = 500, list_key: str = "issues") -> list[dict]:
    """
    SonarQube API paging:
      - p: page number (1..n)
      - ps: page size
    response -> paging.total learn the total page.
    list_key: issues/hotspots key of list
    To make sure we get everything
    """
    out: list[dict] = []
    p = 1
    total = None

    while True:
        url = f"{endpoint_url}&p={p}&ps={page_size}"
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"Pagination API error: {r.status_code} {r.text}")
        payload = r.json()
        paging = payload.get("paging") or {}
        if total is None:
            total = paging.get("total")
        items = payload.get(list_key, []) or []
        out.extend(items)
        # total bilinmiyorsa en azından boş gelince dur
        if total is None:
            if not items:
                break
        else:
            if len(out) >= total:
                break
        if not items:
            break
        p += 1
    return out

    
def run_sonarqube_on_code(code):
    """"
     - Run scanner on temp python file
     - Wait until task is done
     - take issues and hotspots via API
     - for futher analysis use utils.parsers
    """
    base_url = "http://localhost:9000"
    sonar_token = os.getenv("sonar_user_token")
    if not sonar_token:
        print("SonarQube token not found in env: sonar_user_token")
        return "error"
    

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = os.path.join(tmpdir, "app.py")
        # to prevent any name collision
        project_key = f"project_{os.getpid()}_{uuid.uuid4().hex[:8]}"

        with open(code_path, "w") as f:
            f.write(code)

        with open(os.path.join(tmpdir, "sonar-project.properties"), "w") as f:
            f.write(f"""
sonar.projectKey={project_key}
sonar.sources=.
sonar.language=py
sonar.python.version=3
sonar.sourceEncoding=UTF-8
sonar.log.level=INFO
sonar.host.url={base_url}
sonar.token={sonar_token}
""".strip() + "\n")
#sonar-scanner is built on a docker host
        try:
            # 1. Run scanner
            result = subprocess.run(["/opt/sonar-scanner/bin/sonar-scanner"],
                                     cwd=tmpdir,
                                     capture_output=True,
                                     text=True)
            scanner_stdout = result.stdout or ""
            scanner_stderr = result.stderr or ""

            if result.returncode != 0:
                print("SonarQube Scanner Error (stderr):", scanner_stderr)
                print("SonarQube Scanner Output (stdout):", scanner_stdout)
                return "error"
            headers = {"Authorization": f"Bearer {sonar_token}"}
            # 2. Wait for the scanner to finish its task
            ce_task_id = _extract_ce_task_id(scanner_stdout)
            ce_payload = None
            if ce_task_id:
                ce_payload = _wait_for_ce_task(base_url, ce_task_id, headers=headers, timeout_s=180, poll_s=1.0)
            else:
                # if dont catch ceTaskId, wait (opsiyonel)
                # Delete if it waits for eternity
                time.sleep(2)

            cwe_list = set()

            # 3. Issues API, for all pages (ALL ISSUES NOT ONLY SEC)
            issues_url = f"http://localhost:9000/api/issues/search?componentKeys={project_key}"
            all_issues = _paginate(issues_url, headers=headers, page_size=500, list_key="issues")
            
            # 3.2. SEC Issues
            security_issues = []

            # gerçek vulnerability'ler
            vuln_url = f"{base_url}/api/issues/search?componentKeys={project_key}&types=VULNERABILITY"
            security_issues.extend(
                 _paginate(vuln_url, headers=headers, page_size=500, list_key="issues")
                                )
            # security tags
            tag_sec_url = f"{base_url}/api/issues/search?componentKeys={project_key}&tags=security"
            security_issues.extend(
            _paginate(tag_sec_url, headers=headers, page_size=500, list_key="issues")
                                )
            #clean duplicates
            security_issues = {i["key"]: i for i in security_issues}.values()
            security_issues = list(security_issues)

            # 4. Hotspots API, for all pages
            hotspots_url = f"{base_url}/api/hotspots/search?projectKey={project_key}"
            all_hotspots = _paginate(hotspots_url, headers=headers, page_size=500, list_key="hotspots")

            # format the outputs
            issues_data = {"issues": all_issues}
            hotspot_data = {"hotspots": all_hotspots}
            security_issue_data = {"issues": security_issues}
            security_hotspot_data = {"hotspots": all_hotspots}

            # 5. Collect Tag/CWE
            cwe_list = set()
            for issue in all_issues:
                cwe_list.update(utils.message_parsers.extract_security_tags(issue))
            for hs in all_hotspots:
                cwe_list.update(utils.message_parsers.extract_security_tags(hs))

            filtered_issues = utils.message_parsers.filter_issues(issues_data)
            filtered_hotspots = utils.message_parsers.filter_hotspots(hotspot_data)
            filtered_security_issues = utils.message_parsers.filter_issues(security_issue_data)
            filtered_security_hotspots = utils.message_parsers.filter_hotspots(security_hotspot_data)

            tags = (",".join(sorted(cwe_list)) if cwe_list else "None")

            # RAW DATA is ready here
            raw_bundle = {
                "project_key": project_key,
                "scanner_stdout": scanner_stdout,
                "scanner_stderr": scanner_stderr,
                "ce_task_id": ce_task_id,
                "ce_payload": ce_payload,
                "issues": all_issues,
                "hotspots": all_hotspots,
            }
            results = (
            f"security: tags={tags}; "
            f"issues={filtered_security_issues}; "
            f"hotspots={filtered_security_hotspots}; "
            f"all_issues={filtered_issues}; "
            f"all_hotspots={filtered_hotspots}"
                    )   
            return results
        
        except Exception as e:
            print("SonarQube Exception:", e)
            return "error"
        

GetCodeFn = Callable[[int], str | Tuple[str, ...]]
SaveFn    = Callable[[int, str, str], None]   # (id, tool, results)

def sast_scan(
    *,
    start_id: int = None,
    end_id: int = None,
    id_list: list = None,
    get_code: GetCodeFn,
    save_result: SaveFn,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    run_sonar: bool = True,
    rulesets: Optional[Sequence[str]] = None,
) -> None:
    from core import db_handler
    db = db_handler.DBManager()
    rules = list(rulesets) if rulesets else default_semgrep_rules()

    # pull not-tested ids once, no need to hit db on every iteration
    not_tested_map  = db.get_not_tested_tools()
    bandit_pending  = set(not_tested_map.get("bandit", []))
    semgrep_pending = set(not_tested_map.get("semgrep", []))
    sonar_pending   = set(not_tested_map.get("sonarqube", []))

 # if id list exist use that
    if id_list is not None:
        code_ids = sorted(id_list)
    else:
        code_ids = range(start_id, end_id + 1)
        
    for code_id in code_ids:
        # skip if none of the tools need to run for this id
        needs_any = (
            (run_bandit  and code_id in bandit_pending)  or
            (run_semgrep and code_id in semgrep_pending) or
            (run_sonar   and code_id in sonar_pending)
        )
        if not needs_any:
            print(f"SKIP SAST: code_id={code_id} already scanned")
            continue

        try:
            got = get_code(code_id)
        except Exception:
            continue

        code = got[0] if isinstance(got, tuple) else got

        b = run_bandit_on_code(code)  if (run_bandit  and code_id in bandit_pending)  else None
        s = run_semgrep_on_code(code, rules) if (run_semgrep and code_id in semgrep_pending) else None
        q = run_sonarqube_on_code(code) if (run_sonar   and code_id in sonar_pending)   else None

        if b is not None: save_result(code_id, "bandit",    b)
        if s is not None: save_result(code_id, "semgrep",   s)
        if q is not None: save_result(code_id, "sonarqube", q)

        print(f"id={code_id} bandit={b} semgrep={s} sonar={q}")
    print("SAST analysis completed.")