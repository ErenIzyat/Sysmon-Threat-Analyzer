import requests
import json
import os
import time

def load_config():
    config_path = os.path.join("config", "config.json")
    with open(config_path) as f:
        return json.load(f)

def extract_sha256_from_hashes(hash_string):
    parts = hash_string.split(",")
    for part in parts:
        if part.startswith("SHA256="):
            sha256_value = part.replace("SHA256=", "").strip()
            if len(sha256_value) == 64 and all(c in "0123456789abcdefABCDEF" for c in sha256_value):
                return sha256_value
    if parts:
        first_part = parts[0].strip()
        if len(first_part) == 64 and all(c in "0123456789abcdefABCDEF" for c in first_part):
            return first_part
    return None

def check_hashes_with_virustotal(hashes, hash_to_process, api_key=None):
    if api_key is None:
        api_key = load_config().get("virustotal_api_key")

    results = {}
    for sha256 in hashes:
        process_name = hash_to_process.get(sha256, "Bilinmiyor")

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key}

        try:
            resp = requests.get(url, headers=headers)
            time.sleep(6)

            if resp.status_code == 200:
                data = resp.json()
                malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                results[sha256] = {"process_name": process_name, "risk_score": malicious}
            else:
                results[sha256] = {"process_name": process_name, "risk_score": f"Error {resp.status_code}"}
        except Exception as e:
            results[sha256] = {"process_name": process_name, "risk_score": f"Exception: {str(e)}"}
    return results

def get_all_hashes_from_sysmon_log(log_file_path):
    all_sha256_hashes = []
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if 'Event' in event and 'EventData' in event['Event']:
                        event_data = event['Event']['EventData']
                        if '#data' in event_data and isinstance(event_data['#data'], list):
                            for item in event_data['#data']:
                                if isinstance(item, dict) and 'Hashes' in item:
                                    hash_string = item['Hashes']
                                    sha256 = extract_sha256_from_hashes(hash_string)
                                    if sha256:
                                        all_sha256_hashes.append(sha256)
                        elif 'Hashes' in event_data:
                            hash_string = event_data['Hashes']
                            sha256 = extract_sha256_from_hashes(hash_string)
                            if sha256:
                                all_sha256_hashes.append(sha256)
                except json.JSONDecodeError as e:
                    print(f"[ERROR] JSON ayrıştırma hatası: {e} - Satır: {line.strip()}")
                except Exception as e:
                    print(f"[ERROR] Olay işleme hatası: {e} - Satır: {line.strip()}")
    except FileNotFoundError:
        print(f"[ERROR] Dosya bulunamadı: {log_file_path}")
    except Exception as e:
        print(f"[ERROR] Dosya okuma hatası: {e}")
    return all_sha256_hashes

if __name__ == "__main__":
    config = load_config()
    api_key = config.get("virustotal_api_key")
    if not api_key:
        print("VirusTotal API anahtarı 'config.json' dosyasında bulunamadı.")
        exit()

    sysmon_log_path = "data/logs/sysmon_events.json"
    print(f"[{sysmon_log_path}] dosyasından SHA256 hash'leri çıkarılıyor...")
    all_sha256_hashes = get_all_hashes_from_sysmon_log(sysmon_log_path)
    print(f"Toplam {len(all_sha256_hashes)} adet SHA256 hash'i bulundu.")

    if all_sha256_hashes:
        print("VirusTotal ile hash'ler kontrol ediliyor...")
        results = check_hashes_with_virustotal(all_sha256_hashes, all_sha256_hashes)
        for hash_val, status in results.items():
            print(f"Hash: {hash_val}, Durum: {status}")
    else:
        print("Kontrol edilecek hash bulunamadı.")
