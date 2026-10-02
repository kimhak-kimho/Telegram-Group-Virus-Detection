# Starts Docker Desktop (if needed) and brings the virus-detection bot up.
# Used by the Windows logon scheduled task so the bot runs every time you sign in.

$ErrorActionPreference = "Continue"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ProjectDir "data\boot.log"
$DockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"

function Write-BootLog([string]$Message) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $line
}

Write-BootLog "Boot helper started"

if (-not (Get-Process "Docker Desktop" -ErrorAction SilentlyContinue)) {
    if (Test-Path $DockerExe) {
        Start-Process $DockerExe
        Write-BootLog "Launched Docker Desktop"
        Start-Sleep -Seconds 20
    } else {
        Write-BootLog "Docker Desktop.exe not found"
        exit 1
    }
}

$deadline = (Get-Date).AddMinutes(10)
do {
    docker info --format "{{.ServerVersion}}" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-BootLog "Docker engine is ready"
        break
    }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

docker info --format "{{.ServerVersion}}" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-BootLog "Docker engine did not become ready in time"
    exit 1
}

Set-Location $ProjectDir
docker compose up -d
Write-BootLog "docker compose up -d finished with exit code $LASTEXITCODE"
exit $LASTEXITCODE
