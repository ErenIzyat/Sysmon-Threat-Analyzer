# Sysmon Threat Analyzer

## Overview

Sysmon Threat Analyzer is a Python application designed to automatically analyze Sysmon event logs to identify potential security threats on your system. The application processes process creation and network connection events, compares them with threat intelligence sources like VirusTotal and AbuseIPDB, and presents the results as a readable Excel report.

## Features

- Parses Sysmon event logs (Event ID 1 and Event ID 3).
- Filters events based on predefined exclusion lists (IP addresses, file paths).
- Checks process hashes with the VirusTotal API to detect malware or suspicious files.
- Checks destination IP addresses in network connection events with the AbuseIPDB API to identify IPs with a history of abuse.
- Saves detailed analysis results to a JSON file.
- Converts JSON analysis results into an easy-to-understand Excel report with separate sheets for each analysis category. (The VirusTotal report now includes process name, hash, and risk score).

## Prerequisites

To run this project, the following software must be installed on your system:

-   **Python 3.x**: Required to run the project.
-   **pip**: Python package installer.
-   **Sysmon**: Required to collect event logs.
-   **PowerShell**: Required to export Sysmon events.
-   **Microsoft Visual C++ Build Tools**: May be required to install some Python libraries like `pandas` on Windows.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/ErenIzyat/Sysmon-Threat-Analyzer
    cd SysmonThreatAnalyzer
    ```

2.  Install the required Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

### `config/config.json`

You need to add your VirusTotal and AbuseIPDB API keys to the `config/config.json` file:

```json
{
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY"
}
```

### `config/exclusions.json`

If you want to exclude specific IP addresses or file paths from the analysis, you can edit the `config/exclusions.json` file:

```json
{
    "excluded_ips": [
        "1.1.1.1",
        "8.8.8.8"
    ],
    "excluded_paths": [
        "C:\\Users\\LAB\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
        "C:\\Windows\\System32\\svchost.exe"
    ]
}
```

## Usage

### 1. Exporting Sysmon Event Logs

To export your Sysmon event logs in JSON format, use the `powershell_export.ps1` script. You need to run this script as an administrator in PowerShell:

```powershell
.\powershell_export.ps1
```
This will save the Sysmon events to `data/logs/sysmon_events.json`.

### 2. Running the Threat Analysis

After configuring your API keys and exporting your Sysmon event logs, run the `main.py` file to perform the threat analysis:

```bash
python main.py
```
This command will generate the analysis results, which will be saved to `data/results/analysis.json`.

### 3. Exporting Analysis Results to Excel

To convert the analysis results into a readable Excel file, run the `export_to_excel.py` file:

```bash
python src/export_to_excel.py
```
The generated Excel report will be located at `data/results/analysis.xlsx`. This report will contain separate sheets for VirusTotal, AbuseIPDB, high-risk communications, and high-risk processes.
