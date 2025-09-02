$eventsID1 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 1} | Select-Object -First 30 #If u want you can change this export number like first 200 on event id 1
$eventsID3 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3} | Select-Object -First 30 #If u want you can change this export number like first 200 on event id 3


$events = $eventsID1 + $eventsID3

$parsedEvents = foreach ($sysmonEvent in $events) {
    $xml = [xml]$sysmonEvent.ToXml()

    $eventID = $sysmonEvent.Id
    $timeCreated = $sysmonEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"} | Select-Object -ExpandProperty '#text'
    $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"} | Select-Object -ExpandProperty '#text'
    $hash = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "Hashes"} | Select-Object -ExpandProperty '#text'

    if ($eventID -eq 3) {
        $destinationIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
        $destinationPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "DestinationPort"} | Select-Object -ExpandProperty '#text'
        $destinationHostname = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "DestinationHostname"} | Select-Object -ExpandProperty '#text'
    }

    [PSCustomObject]@{
        EventID        = $eventID
        TimeCreated    = $timeCreated
        ProcessName    = $processName
        CommandLine    = $commandLine
        Hashes         = $hash
        DestinationIP  = if ($eventID -eq 3) {$destinationIP} else {$null}
        DestinationPort= if ($eventID -eq 3) {$destinationPort} else {$null}
        DestinationHost= if ($eventID -eq 3) {$destinationHostname} else {$null}
    }
}

$parsedEvents | ConvertTo-Json -Depth 5 | Out-File ".\data\logs\sysmon_events.json"
