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

load_dotenv()
sonar_token = os.getenv("usertoken")

# SAST Commands
def run_bandit_on_code(code: str) -> str:
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name
    try:
        proc = subprocess.run(["bandit", "-r", fname], capture_output=True, text=True)
        return utils.message_parsers.summarize_cwes(proc.stdout)
    except Exception as e:
        return f"error: {e}"
    finally:
        try: os.remove(fname)  # type: ignore[name-defined]
        except Exception: pass

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


def run_sonarqube_on_code(code: str,
                          host_url: Optional[str] = None,
                          scanner_bin: Optional[str] = None,
                          token_env_key: str = sonar_token) -> str:
    token = os.getenv(token_env_key)
    if not token:
        return "error: sonar token missing"

    host = host_url or os.getenv("SONAR_HOST_URL", "http://localhost:9000")
    scanner = scanner_bin or os.getenv("SONAR_SCANNER_BIN", "/opt/sonar-scanner/bin/sonar-scanner")

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = Path(tmpdir) / "app.py"
        code_path.write_text(code, encoding="utf-8")

        project_key = f"project_{uuid.uuid4().hex}"
        props = (
            f"sonar.projectKey={project_key}\n"
            f"sonar.sources=.\n"
            f"sonar.language=py\n"
            f"sonar.python.version=3\n"
            f"sonar.sourceEncoding=UTF-8\n"
            f"sonar.log.level=INFO\n"
            f"sonar.host.url={host}\n"
            f"sonar.token={token}\n"
        )
        (Path(tmpdir) / "sonar-project.properties").write_text(props, encoding="utf-8")

        try:
            proc = subprocess.run([scanner], cwd=tmpdir, capture_output=True, text=True)
            if proc.returncode != 0:
                return "error"
        except Exception as e:
            return f"error: {e}"

        try:
            import requests
            headers = {"Authorization": f"Bearer {token}"}
            cwes: set[str] = set()

            issues_url = f"{host}/api/issues/search?componentKeys={project_key}"
            r1 = requests.get(issues_url, headers=headers, timeout=15)
            if r1.status_code != 200:
                return "error"
            for issue in r1.json().get("issues", []):
                cwes.update(utils.message_parsers.extract_sonar_tags(issue))

            hot_url = f"{host}/api/hotspots/search?projectKey={project_key}"
            r2 = requests.get(hot_url, headers=headers, timeout=15)
            if r2.status_code != 200:
                return "error"
            for h in r2.json().get("hotspots", []):
                cwes.update(utils.message_parsers.extract_sonar_tags(h))

            return ",".join(sorted(cwes)) if cwes else "None"
        except Exception as e:
            return f"error: {e}"

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
