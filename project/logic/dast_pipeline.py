import requests
import time
import json
import logging
import os
import argparse
from dotenv import load_dotenv
from zapv2 import ZAPv2
import re
import subprocess
import traceback
import json
from typing import Callable, Optional, Sequence, Tuple
from core import api_handler, db_handler, docker_handler, file_handler

load_dotenv()

db = db_handler.DBManager()
fm = file_handler.FileManager()
zap_key = os.getenv("owasp_zap_api_key")
zappolicy = "API"

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
    zap.urlopen(target)
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

def build_and_zap(id, chosenpolicy):
    code, dockerfile, sql_script, port_temp, reqs, docker = db.get_files_by_id(id)
    if docker != "tested-successful":
        print(f"SKIP DAST : code_id = {id} because docker status was {docker}")
        return("not-tested")
    else:
        try:
            workdir_temp = fm.setup_files(id, code, dockerfile, sql_script, reqs)
            fm.run_sql_script(id, sql_script)
            dm = docker_handler.DockerManager(workdir=workdir_temp, tag=id, port=port_temp)
            dm.build_image()
            dm.run_container()
            alerts = owasp_zap_scan(port_temp, chosenpolicy)
            #db.save_scan_results(id, "owasp-zap", alerts)
            dm.stop_and_remove()
            fm.remove_files(workdir_temp)
        except Exception as e:
            traceback.print_exc()
            print(f"FAIL: code_id={id} owasp zap error: {e}")
        return json.dumps(alerts, ensure_ascii=False)

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

def build_and_burp(id):
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

    for code_id in range(start_id, end_id + 1):

        if run_zap and code_id in zap_pending:
            o = build_and_zap(code_id, zappolicy)
            if o is not None:
                save_result(code_id, "owasp_zap", o)
        else:
            print(f"SKIP ZAP: code_id={code_id} already scanned or not selected")

        if run_nikto and code_id in nikto_pending:
            s = build_and_nikto(code_id)
            if s is not None:
                save_result(code_id, "nicto", s)

        if run_burp and code_id in burp_pending:
            q = build_and_burp(code_id)
            if q is not None:
                save_result(code_id, "burpsuite", q)

    print("DAST automation completed.")