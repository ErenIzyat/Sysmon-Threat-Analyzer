import os
import json
from src.event_parser import parse_sysmon_events
from src.virustotal_check import check_hashes_with_virustotal, extract_sha256_from_hashes
from src.abuseip_check import check_ips_with_abuseip
from src.config_loader import load_config

EXCLUSIONS_FILE = "config/exclusions.json"
LOG_FILE = "data/logs/sysmon_events.json"
RESULT_FILE = os.path.join("data", "results", "analysis.json")

def load_exclusions():
    if os.path.exists(EXCLUSIONS_FILE):
        with open(EXCLUSIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"excluded_ips": [], "excluded_paths": []}

def main():
    exclusions = load_exclusions()
    excluded_ips = exclusions.get("excluded_ips", [])
    excluded_paths = exclusions.get("excluded_paths", [])

    print("[*] Sysmon eventleri işleniyor...")
    process_events, network_events = parse_sysmon_events(LOG_FILE, excluded_paths)

    hashes = []
    hash_to_process = {}
    for p in process_events:
        h = p.get("Hashes")
        process_name = p.get("ProcessName")
        if h and process_name:
            sha256 = extract_sha256_from_hashes(h)
            if sha256:
                hashes.append(sha256)
                hash_to_process[sha256] = process_name

    ips = [n.get("DestinationIP") for n in network_events if n.get("DestinationIP")]
    ip_to_process = {}
    for n in network_events:
        destination_ip = n.get("DestinationIP")
        process_name = n.get("ProcessName")
        if destination_ip and process_name:
            ip_to_process[destination_ip] = process_name

    print("[*] VirusTotal sorguları yapılıyor...")
    vt_results = check_hashes_with_virustotal(list(hash_to_process.keys()), hash_to_process)

    print("[*] AbuseIPDB sorguları yapılıyor...")
    config = load_config()
    abuseipdb_api_key = config.get("abuseipdb_api_key")
    abuse_results = check_ips_with_abuseip(ips, api_key=abuseipdb_api_key, excluded_ips=excluded_ips)

    high_risk_communications = []
    for event in network_events:
        destination_ip = event.get("DestinationIP")
        process_name = event.get("ProcessName")
        if destination_ip and process_name and destination_ip in abuse_results:
            score = abuse_results[destination_ip]
            if isinstance(score, (int, float)) and score >= 20:
                high_risk_communications.append(f"{destination_ip}:{process_name}")

    unique_high_risk_processes = set()
    for event in process_events:
        process_name = event.get("ProcessName")
        hashes_str = event.get("Hashes")
        if hashes_str and process_name:
            sha256 = None
            parts = hashes_str.split(",")
            for part in parts:
                if part.startswith("SHA256="):
                    sha256 = part.replace("SHA256=", "").strip()
                    break
            if not sha256 and parts and len(parts[0]) == 64 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
                sha256 = parts[0].strip()

            if sha256 and sha256 in vt_results:
                vt_score = vt_results[sha256].get("risk_score", 0)
                if isinstance(vt_score, (int, float)) and vt_score > 0:
                    unique_high_risk_processes.add(f"{sha256}:{process_name}:{vt_score}")

    high_risk_processes = list(unique_high_risk_processes)

    formatted_virustotal_results = {}
    for hash_val, vt_data in vt_results.items():
        formatted_virustotal_results[hash_val] = {
            "process_name": vt_data.get("process_name", "Bilinmiyor"),
            "risk_score": vt_data.get("risk_score", 0)
        }

    formatted_abuseipdb_results = {}
    for event in network_events:
        destination_ip = event.get("DestinationIP")
        destination_port = event.get("DestinationPort")
        process_name = event.get("ProcessName")

        if destination_ip and destination_port and process_name and destination_ip in abuse_results:
            score = abuse_results[destination_ip]
            formatted_abuseipdb_results[f"{destination_ip}:{destination_port}->{process_name}"] = score

    final_data = {
        "virustotal": formatted_virustotal_results,
        "abuseipdb": formatted_abuseipdb_results,
        "high_risk_communications": high_risk_communications,
        "high_risk_processes": high_risk_processes
    }

    os.makedirs(os.path.dirname(RESULT_FILE), exist_ok=True)
    with open(RESULT_FILE, "w") as f:
        json.dump(final_data, f, indent=4)

    print(f"[+] Analiz tamamlandı. Sonuçlar: {RESULT_FILE}")

if __name__ == "__main__":
    main()
