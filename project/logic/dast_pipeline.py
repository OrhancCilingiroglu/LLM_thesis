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

load_dotenv()

zap_key = os.getenv("owasp_zap_api_key")

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


#! WORK TO DO
"""
def run_dast_pipeline(target_url, policy=None):
    
    Full Dast scans and returns 
    
    start_scan(target_url, policy)
    alerts = get_alerts(target_url)
    for alert in alerts:
        print(f"[{alert['risk']}] {alert['alert']} - {alert['url']}")

    return alerts
"""