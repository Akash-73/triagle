# =====================================================================
#  Triagle demo - endpoint reconnaissance + obfuscation chain
#  Run on the LAPTOP enrolled in Wazuh: double-click
#  triagle_detection_test.cmd beside this file, or run this script in
#  PowerShell. It does not need to be run as administrator.
#
#  This is a DETECTION TEST (adversary simulation). Every command below
#  is non-destructive:
#    - the discovery commands only READ information (whoami, net, systeminfo)
#    - the "encoded" command decodes to Get-Date and nothing else
#    - the "cradle" runs IEX on the literal string 'Get-Date' - no download,
#      no remote code
#  Nothing is deleted, installed, disabled or persisted. There is nothing
#  to undo. It is safe to run on your own machine.
#
#  What it is FOR: it generates the same telemetry the recon and obfuscation
#  stage of a real intrusion would, so you can watch Wazuh raise the alerts
#  and Triagle (a) close the discovery as noise and (b) escalate the two
#  obfuscation steps and open one incident on this host.
# =====================================================================

function Step($n, $what) { Write-Host "`n[$n] $what" -ForegroundColor Cyan; Start-Sleep -Seconds 8 }

Write-Host "Triagle detection test - starting. Watch the Wazuh dashboard and the Triagle console." -ForegroundColor Green

# ---- 1. Discovery (read-only). A SIEM rates these low; Triagle closes them as noise.
Step 1 "Who am I, and what can I do"
cmd /c "whoami /all" | Out-Null

Step 2 "Local user accounts"
cmd /c "net user" | Out-Null

Step 3 "Members of the Administrators group"
cmd /c "net localgroup administrators" | Out-Null

Step 4 "Domain admins (will say 'no domain' on a standalone laptop - that is fine)"
cmd /c "net group `"domain admins`" /domain" | Out-Null

Step 5 "Host and network information"
cmd /c "systeminfo" | Out-Null
cmd /c "ipconfig /all" | Out-Null

# ---- 2. Obfuscation. Triagle escalates these on the command line alone,
#         whatever level Wazuh gives them, and opens an incident.
Step 6 "Encoded PowerShell command (decodes to 'Get-Date' - harmless)"
$benign = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-Date"))
powershell.exe -EncodedCommand $benign | Out-Null

Step 7 "Invoke-Expression cradle pattern (runs IEX on the literal 'Get-Date' - no download)"
powershell.exe -Command "IEX('Get-Date')" | Out-Null

Write-Host "`nDone. Nothing was changed on this machine." -ForegroundColor Green
Write-Host "In Wazuh you should see the discovery alerts and the two PowerShell alerts." -ForegroundColor Green
Write-Host "In Triagle: the discovery closed as noise, the two PowerShell steps escalated, one incident on this host." -ForegroundColor Green
