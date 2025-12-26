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

load_dotenv()
sonar_token = os.getenv("usertoken")

# SAST Commands
def run_bandit_on_code(code):
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name
    try:
        result = subprocess.run(["bandit", "-r", fname], capture_output=True, text=True)
        bandit_result = utils.message_parsers.analyze_static_output(result.stdout)
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

'''
def run_snyk_on_code(code):
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name
    try:
        result = subprocess.run(["snyk", "test", "--file="+fname, "--json"], capture_output=True, text=True)
        if result.returncode == 0:
            snyk_result = "None"
        elif result.returncode == 1:
            data = json.loads(result.stdout or "{}")
            cwe_list = set()
            for vuln in data.get("vulnerabilities", []):
                identifiers = vuln.get("identifiers", {})
                cwes = identifiers.get("CWE", [])
                for cwe in cwes:
                    cwe_list.add(str(cwe).split(":")[0].strip())
            snyk_result = ",".join(sorted(cwe_list)) if cwe_list else "None"
        else:
            snyk_result = "error"
    except Exception:
        snyk_result = "error"
    os.remove(fname)
    return snyk_result
'''
    
def run_sonarqube_on_code(code):

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = os.path.join(tmpdir, "app.py")
        project_key = f"project_{os.getpid()}"
        sonar_token = os.getenv("sonar_user_token")

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
sonar.host.url=http://localhost:9000
sonar.token={sonar_token}
""")
#sonar-scanner is built on the host machine
        try:
            result = subprocess.run(["/opt/sonar-scanner/bin/sonar-scanner"], cwd=tmpdir, capture_output=True, text=True)
            if result.returncode != 0:
                print("SonarQube Error:", result.stderr)
                return "error"

            headers = {"Authorization": f"Bearer {sonar_token}"}
            cwe_list = set()

            # 1. Issues API
            issues_url = f"http://localhost:9000/api/issues/search?componentKeys={project_key}"
            response_issues = requests.get(issues_url, headers=headers)
            if response_issues.status_code != 200:
                print("SonarQube issues API error:", response_issues.text)
                return "error"
            issues_data = response_issues.json()

            for issue in issues_data.get("issues", []):
                cwe_list.update(utils.message_parsers.extract_security_tags(issue))

            # 2. Hotspots API
            hotspot_url = f"http://localhost:9000/api/hotspots/search?projectKey={project_key}"
            response_hotspot = requests.get(hotspot_url, headers=headers)
            if response_hotspot.status_code != 200:
                print("SonarQube hotspots API error:", response_hotspot.text)
                return "error"
            hotspot_data = response_hotspot.json()

            for hotspot in hotspot_data.get("hotspots", []):
                cwe_list.update(utils.message_parsers.extract_security_tags(hotspot))

            filtered_issues = utils.message_parsers.filter_issues(issues_data)
            filtered_hotspots = utils.message_parsers.filter_hotspots(hotspot_data)

            tags = (",".join(sorted(cwe_list)) if cwe_list else "None")
            results = f"tags = {tags}; issues = {filtered_issues}; hotspot= {filtered_hotspots}"
            return results

        except Exception as e:
            print("SonarQube Exception:", e)
            return "error"

# Moved functions to callbacks for clean logic/core seperation

GetCodeFn = Callable[[int], str | Tuple[str, ...]]
SaveFn    = Callable[[int, str, str], None]   # (id, tool, results)

def sast_scan(
    *,
    start_id: int,
    end_id: int,
    get_code: GetCodeFn,
    save_result: SaveFn,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    run_sonar: bool = True,
    rulesets: Optional[Sequence[str]] = None,
) -> None:
    rules = list(rulesets) if rulesets else default_semgrep_rules()

    for code_id in range(start_id, end_id + 1):
        try:
            got = get_code(code_id)
        except Exception:
            # no id returned -> skip
            continue

        code = got[0] if isinstance(got, tuple) else got

        b = run_bandit_on_code(code) if run_bandit else None
        s = run_semgrep_on_code(code, rules) if run_semgrep else None
        q = run_sonarqube_on_code(code) if run_sonar else None

        if b is not None: save_result(code_id, "bandit", b)
        if s is not None: save_result(code_id, "semgrep", s)
        if q is not None: save_result(code_id, "sonarqube", q)

       # print(f"id={code_id} bandit={b} semgrep={s} sonar={q}")
    print("Analysis completed.")
