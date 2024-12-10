$date = Get-Date -Format yyMMdd
New-NetEventSession -Name "DnsAnalytic_$date" -CaptureMode SaveToFile -LocalFilePath C:\DnsAna.etl -MaxFileSize 1 
Add-NetEventProvider -Name "Microsoft-Windows-DNSServer" -MatchAnyKeyword "0x8000000000000000" -Level 0x4 -SessionName "DnsAnalytic_$date"
Start-NetEventSession -Name "DnsAnalytic_$date"
Resolve-DnsName -Name "www.example.com" -Server 127.0.0.1
Stop-NetEventSession -Name "DnsAnalytic_$date"
Remove-NetEventSession -Name "DnsAnalytic_$date"
$binVersion = (Get-ItemProperty $env:windir\System32\dns.exe).VersionInfo.ProductVersion
tracerpt C:\dnsana.etl -export "C:\$binVersion.man"