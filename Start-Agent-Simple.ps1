#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Security Agent - Simple Start Script
    
.DESCRIPTION
    Simplified script to start the RiskNoX Security Agent with all components
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('start', 'stop', 'status', 'help')]
    [string]$Action = 'start'
)

# Configuration
$Script:Config = @{
    RootPath = $PSScriptRoot
    VirtualEnvPath = "venv"
    LogsPath = "logs"
    ConfigPath = "config"
    VendorPath = "vendor"
    BackendPort = 8000
}

# Ensure directories exist
$logsDir = Join-Path $Script:Config.RootPath $Script:Config.LogsPath
$configDir = Join-Path $Script:Config.RootPath $Script:Config.ConfigPath

if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $colors = @{
        'INFO' = 'White'
        'SUCCESS' = 'Green'
        'WARN' = 'Yellow'
        'ERROR' = 'Red'
    }
    
    Write-Host $logMessage -ForegroundColor $colors[$Level]
}

function Start-SimpleAgent {
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "        RiskNoX Security Agent - Simple Start" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    
    # Check Python
    try {
        $pythonVersion = python --version 2>&1
        Write-Log "✓ Python available: $pythonVersion" -Level SUCCESS
    }
    catch {
        Write-Log "✗ Python not found. Please install Python 3.7+" -Level ERROR
        return $false
    }
    
    # Check agent script
    $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
    if (-not (Test-Path $agentScript)) {
        Write-Log "✗ Agent script not found: $agentScript" -Level ERROR
        return $false
    }
    Write-Log "✓ Agent script found" -Level SUCCESS
    
    # Check for existing process
    $existingProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
            return $cmdLine -and $cmdLine -like "*agent_main.py*"
        }
        catch {
            return $false
        }
    }
    
    if ($existingProcesses) {
        Write-Log "⚠ Agent already running (PID: $($existingProcesses[0].Id))" -Level WARN
        return $true
    }
    
    # Start agent
    Write-Log "Starting agent process..." -Level INFO
    try {
        Push-Location $Script:Config.RootPath
        
        $process = Start-Process -FilePath "python" -ArgumentList $agentScript -NoNewWindow -PassThru -RedirectStandardOutput "logs\agent_stdout.log" -RedirectStandardError "logs\agent_stderr.log"
        
        Write-Log "✓ Agent started (PID: $($process.Id))" -Level SUCCESS
        Write-Log "Logs: logs\agent_stdout.log" -Level INFO
        Write-Log "Errors: logs\agent_stderr.log" -Level INFO
        
        # Wait a moment to verify it's running
        Start-Sleep -Seconds 3
        if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
            Write-Log "✓ Agent is running successfully" -Level SUCCESS
            return $true
        } else {
            Write-Log "✗ Agent process terminated" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "✗ Failed to start agent: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Pop-Location
    }
}

function Stop-SimpleAgent {
    Write-Log "Stopping RiskNoX Agent..." -Level INFO
    
    $processes = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
            return $cmdLine -and $cmdLine -like "*agent_main.py*"
        }
        catch {
            return $false
        }
    }
    
    if ($processes) {
        foreach ($proc in $processes) {
            Stop-Process -Id $proc.Id -Force
            Write-Log "✓ Stopped agent process (PID: $($proc.Id))" -Level SUCCESS
        }
    } else {
        Write-Log "○ No agent processes found" -Level INFO
    }
}

function Show-SimpleStatus {
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "        RiskNoX Security Agent - Status" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    
    # Check agent processes
    $processes = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
            return $cmdLine -and $cmdLine -like "*agent_main.py*"
        }
        catch {
            return $false
        }
    }
    
    if ($processes) {
        Write-Log "✓ Agent Status: Running (PID: $($processes[0].Id))" -Level SUCCESS
    } else {
        Write-Log "✗ Agent Status: Stopped" -Level ERROR
    }
    
    # Check components
    $clamPath = Join-Path $Script:Config.RootPath "vendor\clamscan.exe"
    if (Test-Path $clamPath) {
        Write-Log "✓ Antivirus: Available" -Level SUCCESS
    } else {
        Write-Log "✗ Antivirus: Not found" -Level WARN
    }
    
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
}

function Show-SimpleHelp {
    Write-Host @"
RiskNoX Security Agent - Simple Control Script

Usage:
    .\Start-Agent-Simple.ps1 -Action <action>

Actions:
    start   - Start the RiskNoX Security Agent
    stop    - Stop the RiskNoX Security Agent
    status  - Show agent status
    help    - Show this help message

Examples:
    .\Start-Agent-Simple.ps1 -Action start
    .\Start-Agent-Simple.ps1 -Action status
    .\Start-Agent-Simple.ps1 -Action stop

"@ -ForegroundColor Cyan
}

# Main execution
switch ($Action.ToLower()) {
    'start' {
        Start-SimpleAgent
    }
    'stop' {
        Stop-SimpleAgent
    }
    'status' {
        Show-SimpleStatus
    }
    'help' {
        Show-SimpleHelp
    }
    default {
        Write-Log "Unknown action: $Action" -Level ERROR
        Show-SimpleHelp
    }
}