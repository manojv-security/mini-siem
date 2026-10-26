<#
.SYNOPSIS
  Export Windows logon events (4624 success, 4625 failure) to a CSV that Mini-SIEM can ingest.

.DESCRIPTION
  Reads the Security event log on this Windows 11 machine and writes one row per logon event with
  the columns Mini-SIEM understands: timestamp (UTC), event_id, username, source_ip, logon_type,
  status, host. Upload the resulting file on the "Ingest logs" page (format: CSV / Auto-detect).

  Reading the Security log requires an elevated PowerShell ("Run as administrator").

.EXAMPLE
  .\scripts\export_windows_security_events.ps1 -Hours 48 -OutFile .\windows_logons.csv
#>
param(
    [int]$Hours = 24,
    [string]$OutFile = "windows_security_events.csv"
)

$ErrorActionPreference = "Stop"
$start = (Get-Date).AddHours(-$Hours)

try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $start }
} catch [System.Exception] {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "No logon events in the last $Hours hour(s)."
        exit 0
    }
    Write-Error "Could not read the Security log. Run PowerShell as Administrator. ($($_.Exception.Message))"
    exit 1
}

$rows = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    # Skip machine accounts (COMPUTER$) and the SYSTEM / service logons that create a lot of noise.
    $user = $data['TargetUserName']
    if ($user -like '*$' -or $data['LogonType'] -eq '5') { continue }

    [PSCustomObject]@{
        timestamp  = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        event_id   = $e.Id
        username   = if ($data['TargetDomainName']) { "$($data['TargetDomainName'])\$user" } else { $user }
        source_ip  = $data['IpAddress']
        logon_type = $data['LogonType']
        status     = if ($e.Id -eq 4624) { 'success' } else { 'failure' }
        host       = $e.MachineName
    }
}

$rows | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $(@($rows).Count) logon event(s) to $OutFile"
