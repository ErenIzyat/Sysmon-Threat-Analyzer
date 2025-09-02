import json
import os

def parse_sysmon_events(log_file_path, excluded_paths=None):
    if excluded_paths is None:
        excluded_paths = []
    if not os.path.exists(log_file_path):
        raise FileNotFoundError(f"Log file not found: {log_file_path}")

    with open(log_file_path, "r", encoding="utf-16") as f:
        events = json.load(f)

    process_events = []
    network_events = []

    for event in events:
        if event.get("EventID") == 1:
            process_events.append({
                "TimeCreated": event.get("TimeCreated"),
                "ProcessName": event.get("ProcessName"),
                "CommandLine": event.get("CommandLine") if not isinstance(event.get("CommandLine"), dict) else None,
                "Hashes": event.get("Hashes") if not isinstance(event.get("Hashes"), dict) else None
            })
        elif event.get("EventID") == 3:
            network_events.append({
                "TimeCreated": event.get("TimeCreated"),
                "ProcessName": event.get("ProcessName"),
                "DestinationIP": event.get("DestinationIP"),
                "DestinationPort": event.get("DestinationPort"),
                "DestinationHost": event.get("DestinationHost")
            })

    filtered_process_events = []
    for event in process_events:
        process_name = event.get("ProcessName", "").lower()
        command_line = event.get("CommandLine", "").lower()
        is_excluded = False
        for p in excluded_paths:
            if p.lower() in process_name or p.lower() in command_line:
                is_excluded = True
                break
        if not is_excluded:
            filtered_process_events.append(event)


    return filtered_process_events, network_events
