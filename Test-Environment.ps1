#Requires -Version 7.0

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "        RiskNoX Agent - Simple Startup Test" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Test Python availability
Write-Host "`n1. Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Python not found" -ForegroundColor Red
}

# Test agent script
Write-Host "`n2. Checking Agent Script..." -ForegroundColor Yellow
$agentScript = Join-Path $PSScriptRoot "agent\agent_main.py"
if (Test-Path $agentScript) {
    Write-Host "✓ Agent script found: $agentScript" -ForegroundColor Green
} else {
    Write-Host "✗ Agent script not found" -ForegroundColor Red
}

# Test virtual environment
Write-Host "`n3. Checking Virtual Environment..." -ForegroundColor Yellow
$venvPath = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
if (Test-Path $venvPath) {
    Write-Host "✓ Virtual environment found" -ForegroundColor Green
    try {
        $venvVersion = & $venvPath --version 2>&1
        Write-Host "✓ Virtual Python: $venvVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠ Virtual environment exists but not working" -ForegroundColor Yellow
    }
} else {
    Write-Host "○ Virtual environment not found (will be created)" -ForegroundColor Yellow
}

# Test antivirus
Write-Host "`n4. Checking Antivirus..." -ForegroundColor Yellow
$clamPath = Join-Path $PSScriptRoot "vendor\clamscan.exe"
if (Test-Path $clamPath) {
    Write-Host "✓ ClamAV scanner found" -ForegroundColor Green
} else {
    Write-Host "✗ ClamAV scanner not found" -ForegroundColor Red
}

# Test directories
Write-Host "`n5. Checking Directories..." -ForegroundColor Yellow
$logsDir = Join-Path $PSScriptRoot "logs"
$configDir = Join-Path $PSScriptRoot "config"

if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    Write-Host "✓ Created logs directory" -ForegroundColor Green
} else {
    Write-Host "✓ Logs directory exists" -ForegroundColor Green
}

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-Host "✓ Created config directory" -ForegroundColor Green
} else {
    Write-Host "✓ Config directory exists" -ForegroundColor Green
}

Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Environment check complete. Ready for agent startup!" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan