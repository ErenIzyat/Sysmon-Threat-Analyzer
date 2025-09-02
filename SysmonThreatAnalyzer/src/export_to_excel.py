
import json
import os
import pandas as pd

def export_analysis_to_excel(json_file_path, excel_file_path):
    with open(json_file_path, 'r') as f:
        data = json.load(f)

    writer = pd.ExcelWriter(excel_file_path, engine='xlsxwriter')

    virustotal_data = []
    for hash_val, data_entry in data.get('virustotal', {}).items():
        virustotal_data.append({'HASH': hash_val, 'Process Name': data_entry.get('process_name', 'Bilinmiyor'), 'Risk Score': data_entry.get('risk_score', 0)})
    if virustotal_data:
        df_virustotal = pd.DataFrame(virustotal_data)
        df_virustotal.drop_duplicates(subset=['HASH', 'Process Name'], inplace=True)
        df_virustotal.to_excel(writer, sheet_name='virustotal', index=False)

    abuseipdb_data = []
    for ip_process, risk_score in data.get('abuseipdb', {}).items():
        parts = ip_process.split('->')
        ip_port = parts[0]
        process = parts[1] if len(parts) > 1 else ''
        ip, port = ip_port.split(':', 1) if ':' in ip_port else (ip_port, '')
        abuseipdb_data.append({'IP': ip, 'Port': port, 'Process': process, 'Risk Score': risk_score})
    if abuseipdb_data:
        df_abuseipdb = pd.DataFrame(abuseipdb_data)
        df_abuseipdb.drop_duplicates(subset=['IP', 'Port', 'Process'], inplace=True)
        df_abuseipdb.to_excel(writer, sheet_name='abuseipdb', index=False)

    high_risk_comm_data = []
    for comm in data.get('high_risk_communications', []):
        ip, process = comm.split(':', 1)
        high_risk_comm_data.append({'IP': ip, 'Process': process})
    if high_risk_comm_data:
        df_high_risk_comm = pd.DataFrame(high_risk_comm_data)
        df_high_risk_comm.drop_duplicates(subset=['IP', 'Process'], inplace=True)
        df_high_risk_comm.to_excel(writer, sheet_name='high_risk_communications', index=False)

    high_risk_proc_data = []
    for proc in data.get('high_risk_processes', []):
        hash_val, process_name = proc.split(':', 1)
        high_risk_proc_data.append({'HASH': hash_val, 'Process Name': process_name})
    if high_risk_proc_data:
        df_high_risk_proc = pd.DataFrame(high_risk_proc_data)
        df_high_risk_proc.drop_duplicates(subset=['HASH', 'Process Name'], inplace=True)
        df_high_risk_proc.to_excel(writer, sheet_name='high_risk_processes', index=False)

    writer.close()

if __name__ == '__main__':
    script_dir = os.path.dirname(__file__)
    project_root = os.path.join(script_dir, os.pardir)
    json_file = os.path.join(project_root, 'data', 'results', 'analysis.json')
    excel_file = os.path.join(project_root, 'data', 'results', 'analysis.xlsx')
    
    print(f"JSON File Path: {os.path.abspath(json_file)}")
    print(f"Excel File Path: {os.path.abspath(excel_file)}")
    
    export_analysis_to_excel(json_file, excel_file)
    print(f"Analysis exported to {excel_file}")

