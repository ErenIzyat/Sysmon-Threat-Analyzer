$ip = "X.X.X.X"
$port = 80

while ($true) {
    $tcpConnection = Test-NetConnection -ComputerName $ip -Port $port
    $tcpConnection
    Start-Sleep -Seconds 15
}