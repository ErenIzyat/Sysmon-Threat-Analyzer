import requests
import json
import os
import time
from src.config_loader import load_config

def check_ips_with_abuseip(ips, api_key=None, excluded_ips=None):
    if api_key is None:
        api_key = load_config().get("abuseipdb_api_key")

    if excluded_ips is None:
        excluded_ips = []

    results = {}

    for ip in ips:
        if ip in excluded_ips:
            print(f"[INFO] Skipping excluded IP: {ip}")
            continue

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            resp = requests.get(url, headers=headers, params=params)
            time.sleep(3)

            if resp.status_code == 200:
                data = resp.json()
                results[ip] = data["data"]["abuseConfidenceScore"]
            else:
                results[ip] = f"Error {resp.status_code}"
        except Exception as e:
            results[ip] = f"Exception: {str(e)}"

    return results
