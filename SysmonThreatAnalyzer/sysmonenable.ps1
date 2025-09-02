Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" "$env:TEMP\Sysmon" -Force
$exe = if (Test-Path "$env:TEMP\Sysmon\Sysmon64.exe") { "$env:TEMP\Sysmon\Sysmon64.exe" } else { "$env:TEMP\Sysmon\Sysmon.exe" }
Start-Process -FilePath $exe -ArgumentList "-accepteula -i `"C:\Users\LAB\Downloads\sysmon-config-master\sysmon-config-master\sysmonconfig-export.xml`"" -Verb RunAs -Wait