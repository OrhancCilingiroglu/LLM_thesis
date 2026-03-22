import requests
import time

BURP_URL = "http://localhost:1337"
API_KEY = "YOUR_API_KEY_HERE"
TARGET_URL = "127.0.0.1:8108"

HEADERS = {
    "Content-Type": "application/json",
    "X-Burp-Suite-Api-Key": API_KEY
}

scan_config = {
    "urls": [TARGET_URL],
    "scan_configurations": [
        {
            # Burp'ün Configuration Library'sindeki tam isim
            "type": "NamedConfiguration",
            "name": "CWE-77-78-Command-Injection"
        }
    ],
    "scope": {
        "include": [{"rule": TARGET_URL, "type": "PrefixMatch"}],
        "type": "SimpleScope"
    }
}

# --- Scan başlat ---
resp = requests.post(
    f"{BURP_URL}/v0.1/scan",
    headers=HEADERS,
    json=scan_config
)

# raise_for_status'tan önce body'yi yazdır — hata ayıklamak için kritik
print("Status:", resp.status_code)
print("Body:", resp.text)
resp.raise_for_status()

# Burp, scan ID'yi Location header'ında döndürür
scan_id = resp.headers["Location"].split("/")[-1]
print(f"Scan başladı, ID: {scan_id}")

# --- Tamamlanana kadar polling ---
while True:
    status_resp = requests.get(
        f"{BURP_URL}/v0.1/scan/{scan_id}",
        headers=HEADERS
    ).json()

    state = status_resp.get("scan_status")
    print(f"  Durum: {state}")

    if state in ("succeeded", "failed"):
        break

    time.sleep(10)

# --- Sonuçları yazdır ---
issues = status_resp.get("issue_events", [])
print(f"\nToplam bulunan issue: {len(issues)}")

for ev in issues:
    issue = ev["issue"]
    print(f"  [{issue['severity']}] {issue['name']} — {issue['path']}")