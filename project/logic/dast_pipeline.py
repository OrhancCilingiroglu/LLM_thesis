import requests
import time
import json
import logging
import os
import argparse
import sqlite3
from dotenv import load_dotenv
from zapv2 import ZAPv2
import re
import subprocess
import traceback
import json
from typing import Callable, Optional, Sequence, Tuple
from core import api_handler, db_handler, docker_handler, file_handler
from utils import message_parsers

load_dotenv()

db = db_handler.DBManager()
fm = file_handler.FileManager()
zap_key = os.getenv("owasp_zap_api_key")

#! CONFIGS

zappolicy = "API"

BURP_API_URL = "http://127.0.0.1:1337"
BURP_SCAN_CONFIGS = {
    "crawl_and_audit": [
        {"name": "Crawl strategy - fastest", "type": "NamedConfiguration"},
        {"name": "Audit checks - all except time-based detection methods", "type": "NamedConfiguration"}
    ],
    "active_scan": [
        {"name": "Audit checks - all except time-based detection methods", "type": "NamedConfiguration"}
    ],
    "passive_scan": [
        {"name": "Crawl strategy - fastest", "type": "NamedConfiguration"}
    ],
    "os_command_injection": [
        {"name": "Crawl strategy - fastest", "type": "NamedConfiguration"},
        {
            "type": "CustomConfiguration",
            "config": {
                "audit_optimization": {
                    "issue_types": [1048832]   # OS Command Injection for CWE-77 and CWE-78
                }
            }
        }
    ],
}


def setup_env(id):
    db = db_handler.DBManager()
    code, dockerfile, sql_script, port, reqs, docker = db.get_files_by_id(id)
    workdir = fm.setup_files(id, code, dockerfile, sql_script, reqs)
    fm.run_sql_script(id, sql_script)
    dcm = docker_handler.DockerManager(workdir, id, port)
    dcm.build_image()
    dcm.run_container()

def owasp_zap_scan(port, chosenpolicy):

    zap = ZAPv2(apikey=zap_key, proxies={'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'})
    target = f"http://localhost:{port}"

    # BUG FIX: redirect loop'u yakala — bazı Flask kodları koşulsuz redirect yapıyor
    try:
        zap.urlopen(target)
    except Exception as e:
        print(f"WARN: ZAP urlopen failed (likely redirect loop), continuing anyway: {e}")
    time.sleep(3)

    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider scan %{zap.spider.status(scan_id)}")
        time.sleep(10)
    print("[+] Spider completed.")

    print('[+] Active scanning has started...')
    scan_id = zap.ascan.scan(target ,scanpolicyname=chosenpolicy)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Active scann %{zap.ascan.status(scan_id)}")
        time.sleep(1)
    print("[+] Active scann completed.")

    print('Security Alerts:')
    alerts = zap.core.alerts(baseurl=target)
    for alert in alerts:
        print(f"[{alert['risk']}] {alert['alert']} - {alert['url']}")
    return alerts


def build_zap_auth_context(zap, target, auth_candidate, context_name):
    """Wire a ZAP context for form-based auth from one auth_candidates row.

    ZAP's form-based auth uses two layers of naming that must not be
    confused: `loginRequestData` uses the SITE's own form field names (e.g.
    "username", but could be "user" or "email" -- read from the sample's
    actual code, not assumed) on the left of each `=`, with ZAP's own fixed
    `{%username%}`/`{%password%}` placeholders on the right. The actual
    credential values are set separately via set_authentication_credentials
    using those same fixed "username"/"password" keys, regardless of what
    the site calls its fields. Mixing these up silently produces a login
    POST that submits the literal string "{%username%}" instead of a real
    value.
    """
    context_id = zap.context.new_context(context_name)
    zap.context.include_in_context(context_name, re.escape(target) + ".*")

    login_url = target.rstrip("/") + auth_candidate["login_path"]
    login_request_data = (
        f"{auth_candidate['username_field']}={{%username%}}"
        f"&{auth_candidate['password_field']}={{%password%}}"
    )
    zap.authentication.set_authentication_method(
        context_id, "formBasedAuthentication",
        f"loginUrl={login_url}&loginRequestData={login_request_data}",
    )

    user_id = zap.users.new_user(context_id, "auth_user")
    zap.users.set_authentication_credentials(
        context_id, user_id,
        f"username={auth_candidate['username']}&password={auth_candidate['password']}",
    )
    zap.users.set_user_enabled(context_id, user_id, "true")
    return context_id, user_id


def owasp_zap_scan_authenticated(port, chosenpolicy, auth_candidate):
    """Same as owasp_zap_scan, but spiders and actively scans as a logged-in
    user via ZAP's scan_as_user (built from a project/core/build_auth_candidates.py
    row) instead of anonymously. Without this, samples that gate their real
    functionality behind a login expose almost no surface to ZAP -- see
    changes_summary.md's ZAP entry for why this matters for A01.
    """
    zap = ZAPv2(apikey=zap_key, proxies={'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'})
    target = f"http://localhost:{port}"

    try:
        zap.urlopen(target)
    except Exception as e:
        print(f"WARN: ZAP urlopen failed (likely redirect loop), continuing anyway: {e}")
    time.sleep(3)

    context_name = f"auth_ctx_{port}"
    context_id, user_id = build_zap_auth_context(zap, target, auth_candidate, context_name)

    try:
        print(f"[+] Authenticated spider starting (context={context_id}, user={user_id})...")
        scan_id = zap.spider.scan_as_user(context_id, user_id, target)
        while int(zap.spider.status(scan_id)) < 100:
            print(f"Auth spider %{zap.spider.status(scan_id)}")
            time.sleep(5)
        print("[+] Authenticated spider completed.")

        print('[+] Authenticated active scan starting...')
        scan_id = zap.ascan.scan_as_user(
            url=target, contextid=context_id, userid=user_id, scanpolicyname=chosenpolicy
        )
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Auth active scan %{zap.ascan.status(scan_id)}")
            time.sleep(1)
        print("[+] Authenticated active scan completed.")

        print('Security Alerts (authenticated):')
        alerts = zap.core.alerts(baseurl=target)
        for alert in alerts:
            print(f"[{alert['risk']}] {alert['alert']} - {alert['url']}")
        return alerts
    finally:
        # Contexts persist in the ZAP session across calls; remove ours so
        # they don't pile up (and collide by name) across thousands of samples.
        try:
            zap.context.remove_context(context_name)
        except Exception:
            pass


def build_and_zap(id, chosenpolicy):
    code, dockerfile, sql_script, port_temp, reqs, docker = db.get_files_by_id(id)
    if docker != "tested-successful":
        print(f"SKIP DAST : code_id = {id} because docker status was {docker}")
        return None

    alerts = []      # BUG FIX: UnboundLocalError — alerts her zaman tanımlı olsun
    dm = None
    workdir_temp = None
    try:
        # BUG FIX: 409 Conflict — aynı isimde container kalmış olabilir, önce temizle
        try:
            stale = docker_handler.DockerManager(workdir=".", tag=id, port=port_temp)
            stale.stop_and_remove()
        except Exception:
            pass

        workdir_temp = fm.setup_files(id, code, dockerfile, sql_script, reqs)
        fm.run_sql_script(id, sql_script)
        dm = docker_handler.DockerManager(workdir=workdir_temp, tag=id, port=port_temp)
        if not dm.build_image():
            print(f"FAIL: code_id={id} build failed, skipping ZAP")
            return None
        if not dm.run_container():
            print(f"FAIL: code_id={id} container didn't start, skipping ZAP")
            return None
        auth_candidate = db.get_auth_candidate(id)
        if auth_candidate:
            print(f"[+] code_id={id}: login flow detected ({auth_candidate['login_path']}), "
                  f"scanning authenticated")
            alerts = owasp_zap_scan_authenticated(port_temp, chosenpolicy, auth_candidate)
        else:
            alerts = owasp_zap_scan(port_temp, chosenpolicy)
    except Exception as e:
        traceback.print_exc()
        print(f"FAIL: code_id={id} owasp zap error: {e}")
    finally:
        # BUG FIX: cleanup her durumda çalışsın (exception sonrası da)
        try:
            if dm:
                dm.stop_and_remove()
        except Exception:
            pass
        try:
            if workdir_temp:
                fm.remove_files(id)
        except Exception:
            pass
    return json.dumps(alerts, ensure_ascii=False)


def rescan_authenticated_zap(id_list, chosenpolicy="API", db_manager=None):
    """Re-scan samples with authentication via build_and_zap(), bypassing
    dast_scan()'s pending check -- deliberately, since most auth_candidates
    already have old *unauthenticated* owasp_zap data and dast_scan treats
    "has any zap data" as "already scanned". Saves into the new
    owasp_zap_authenticated column (save_authenticated_zap_result), never
    touching the legacy owasp_zap column.

    Resumable on its own: skips ids that already have
    owasp_zap_authenticated set, so an interrupted run can just be called
    again with the same id_list.

    `db_manager=None` uses the real project/core/code_cwe.db; pass an
    instance pointed at a scratch DB to test safely first.
    """
    if db_manager is None:
        db_manager = db

    conn_check = sqlite3.connect(db_manager.db_path)
    cols = {row[1] for row in conn_check.execute("PRAGMA table_info(code_cwe)").fetchall()}
    if "owasp_zap_authenticated" in cols:
        placeholders = ",".join("?" * len(id_list))
        already = {
            row[0] for row in conn_check.execute(
                f"SELECT id FROM code_cwe WHERE id IN ({placeholders}) "
                "AND owasp_zap_authenticated IS NOT NULL",
                id_list,
            ).fetchall()
        }
    else:
        already = set()
    conn_check.close()
    pending = [cid for cid in id_list if cid not in already]

    print(f"[AUTH ZAP] {len(already)} already done, {len(pending)} pending")
    completed = 0
    for code_id in pending:
        alerts_json = build_and_zap(code_id, chosenpolicy)
        if alerts_json is None:
            print(f"[AUTH ZAP] SKIP code_id={code_id}: build/run failed")
            continue
        db_manager.save_authenticated_zap_result(code_id, alerts_json)
        completed += 1
        if completed % 25 == 0:
            docker_handler.DockerManager.prune_dangling_images()
            docker_handler.DockerManager.prune_build_cache()
    print(f"[AUTH ZAP] Done: {completed}/{len(pending)} scanned and saved.")


#nikto kullanacaksan output aldıktan sonraki kısmını da ekle
def nikto_scan(targetport, outputname):

    output_file = f"{outputname}.txt"
    command = [
        "nikto", "-h", "localhost",
        "-p", str(targetport),
        "-o", output_file
    ]

    print(f"[+] Running Nikto scan on http://localhost:{targetport} ...")
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Scan complete. Output saved to {output_file}")

def burp_scan(port, config_name, max_wait_seconds=300, poll_interval=5):

    target = f"http://localhost:{port}"

    scan_payload = {
        "urls": [target],
        "scan_configurations": [
            {
                "type": "NamedConfiguration",
                "name": config_name   # Configuration Library'deki isim
            }
        ],
        "scope": {
            "include": [{"rule": target, "type": "PrefixMatch"}],
            "type": "SimpleScope"
        }
    }

    response = requests.post(
        f"{BURP_API_URL}/v0.1/scan",
        headers={"Content-Type": "application/json"},
        json=scan_payload
    )

    if response.status_code != 201:
        raise Exception(f"Burp scan didnt start: {response.status_code}")

    scan_id = response.headers.get("Location", "").strip("/").split("/")[-1]
    print(f"[+] Burp scan started → scan_id={scan_id}, config={config_name}, target={target}")

    paused_count = 0
    start_time = time.time()
    data = {}

    while True:
        # Hard timeout: if scan hasn't finished within max_wait_seconds, abort polling
        elapsed = time.time() - start_time
        if elapsed > max_wait_seconds:
            print(f"SKIP: Burp scan timed out after {elapsed:.0f}s, scan_id={scan_id}, port={port}")
            return None, []

        status_resp = requests.get(f"{BURP_API_URL}/v0.1/scan/{scan_id}")
        data = status_resp.json()
        status = data.get("scan_status")
        issue_count = len(data.get("issue_events", []))
        print(f"    Burp scan status: {status} | found issue: {issue_count} | elapsed: {elapsed:.0f}s")

        if status == "succeeded":
            break
        if status == "failed":
            raise Exception(f"Burp scan fail: scan_id={scan_id}")
        if status == "paused":
            paused_count += 1
            if paused_count >= 3:
                print(f"SKIP: Burp scan paused, container erişilemiyor port={port}")
                return None, []

        time.sleep(poll_interval)

    return scan_id, data.get("issue_events", [])


def build_and_burp(id):
    code, dockerfile, sql_script, port, reqs, docker = db.get_files_by_id(id)

    if docker != "tested-successful":
        print(f"SKIP BURP: code_id={id} docker status: {docker}")
        return None

    try:
        cwe_raw = db.get_CWE_by_id(id)
        if cwe_raw is None:
            raise ValueError(f"code_id={id} CWE not found")
        cwe_key = f"CWE-{cwe_raw}"
        if cwe_key not in message_parsers.CWE_TO_BURP_CONFIG:
            raise ValueError(f"CWE_TO_BURP_CONFIG '{cwe_key}' not found")

        config_name = message_parsers.CWE_TO_BURP_CONFIG[cwe_key]
        #!config_name = message_parsers.CWE_TO_BURP_CONFIG['default']
        print(f"    CWE: {cwe_key} → Config: {config_name}")

        workdir = fm.setup_files(id, code, dockerfile, sql_script, reqs)
        fm.run_sql_script(id, sql_script)
        dm = docker_handler.DockerManager(workdir=workdir, tag=id, port=port)
        dm.build_image()
        dm.run_container()

        scan_id, issue_events = burp_scan(port, config_name)

        if scan_id is None:
            dm.stop_and_remove()
            fm.remove_files(workdir)
            return None

        results = []
        for event in issue_events:
            if event.get("type") != "issue_found":
                continue
            issue = event["issue"]
            mapped_cwes = message_parsers.BURP_TYPE_TO_CWE.get(issue.get("type_index"))
            if mapped_cwes is None:
                continue
            for cwe in mapped_cwes:               # her CWE için ayrı kayıt
                results.append({
                "scan_id":    scan_id,
                "scan_type":  config_name,
                "issue_name": issue.get("name"),
                "type_index": issue.get("type_index"),
                "mapped_cwe": cwe,            # tek CWE per kayıt
                "severity":   issue.get("severity"),
                "confidence": issue.get("confidence"),
                "path":       issue.get("path"),
                "origin":     issue.get("origin"),
                })

        dm.stop_and_remove()
        fm.remove_files(workdir)
        return json.dumps(results, ensure_ascii=False)

    except Exception as e:
        traceback.print_exc()
        print(f"FAIL: code_id={id} burp error: {e}")
        try:
            dm.stop_and_remove()
            fm.remove_files(workdir)
        except:
            pass
        return None
    
def build_and_nikto(id):
    return None

#! WORK TO DO

GetCodeFn = Callable[[int], str | Tuple[str, ...]]
SaveFn    = Callable[[int, str, str], None]   # (id, tool, results)

def dast_scan(
    *,
    start_id: int,
    end_id: int,
    id_list: list = None,
    save_result: SaveFn,
    run_zap:   bool = True,
    run_nikto: bool = True,
    run_burp:  bool = False,
    zappolicy_in: Optional[Sequence[str]] = None,
) -> None:

    zappolicy = zappolicy_in if zappolicy_in is not None else "API"

    # pull not-tested ids once at the start, no need to hit db on every iteration
    not_tested_map = db.get_not_tested_tools()
    zap_pending    = set(not_tested_map.get("owasp_zap", []))
    nikto_pending  = set(not_tested_map.get("nicto", []))
    burp_pending   = set(not_tested_map.get("burpsuite", []))

    # determine ids for scanning
    if id_list is not None:
        code_ids = id_list
    elif start_id is not None and end_id is not None:
        code_ids = range(start_id, end_id + 1)
    else:
        raise ValueError("start_id/end_id veya id_list verilmeli")


    for code_id in code_ids:

        if run_zap:
            if code_id in zap_pending:
                o = build_and_zap(code_id, zappolicy)
                if o is not None:
                    save_result(code_id, "owasp_zap", o)
            else:
                print(f"SKIP ZAP: code_id={code_id} already scanned")

        if run_nikto and code_id in nikto_pending:
            s = build_and_nikto(code_id)
            if s is not None:
                save_result(code_id, "nicto", s)

        #if run_burp and code_id in burp_pending:
        if run_burp and code_id in burp_pending:
            q = build_and_burp(code_id)
            if q is not None:
                save_result(code_id, "burpsuite", q)

    print("DAST automation completed.")