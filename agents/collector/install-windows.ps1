$ErrorActionPreference = "Stop"
$Root = "C:\Program Files\TRUST-SOC\Collector"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
Copy-Item -Recurse -Force .\trust_agent, .\requirements.txt, .\agent.env $Root
python -m venv "$Root\.venv"
& "$Root\.venv\Scripts\pip.exe" install -r "$Root\requirements.txt"
$Action = New-ScheduledTaskAction -Execute "$Root\.venv\Scripts\python.exe" -Argument "-m trust_agent.main" -WorkingDirectory $Root
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "TRUST-SOC Collector" -Action $Action -Trigger $Trigger -Principal $Principal -Force
Start-ScheduledTask -TaskName "TRUST-SOC Collector"
Write-Host "TRUST-SOC Collector installed. Protect agent.env with Windows ACLs and rotate the source secret after imaging."
