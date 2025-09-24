
#requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    RiskNoX Security Agent Setup Script
    
.DESCRIPTION
    Initial setup script for RiskNoX Security Agent.
    Verifies dependencies and prepares the system for first run.
    
.NOTES
    Author: RiskNoX Security Team
    Version: 1.0.0
    Requires: PowerShell 7.0 or later
#>

param(
    [switch]$SkipChecks,
    [switch]$Quiet
)

function Write-SetupLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    if ($Quiet -and $Level -eq 'INFO') { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'INFO' { 'White' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-PowerShellVersion {
    Write-SetupLog "Checking PowerShell version..." -Level INFO
    
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-SetupLog "PowerShell 7.0 or later is required. Current version: $($PSVersionTable.PSVersion)" -Level ERROR
        Write-SetupLog "Please install PowerShell 7 from: https://github.com/PowerShell/PowerShell/releases" -Level ERROR
        return $false
    }
    
    Write-SetupLog "PowerShell version check passed: $($PSVersionTable.PSVersion)" -Level SUCCESS
    return $true
}

function Test-PythonEnvironment {
    Write-SetupLog "Checking Python virtual environment..." -Level INFO
    
    $venvPath = Join-Path $PSScriptRoot ".venv"
    $pythonPath = Join-Path $venvPath "Scripts\python.exe"
    
    if (-not (Test-Path $venvPath)) {
        Write-SetupLog "Python virtual environment not found at: $venvPath" -Level WARN
        Write-SetupLog "Virtual environment should have been created during initial setup" -Level WARN
        return $false
    }
    
    if (-not (Test-Path $pythonPath)) {
        Write-SetupLog "Python executable not found at: $pythonPath" -Level ERROR
        return $false
    }
    
    Write-SetupLog "Python virtual environment found" -Level SUCCESS
    return $true
}

function Test-ClamAVInstallation {
    Write-SetupLog "Checking ClamAV installation..." -Level INFO
    
    $clamScanPath = Join-Path $PSScriptRoot "vendor\clamscan.exe"
    $databasePath = Join-Path $PSScriptRoot "vendor\database"
    
    if (-not (Test-Path $clamScanPath)) {
        Write-SetupLog "ClamAV scanner not found at: $clamScanPath" -Level ERROR
        return $false
    }
    
    if (-not (Test-Path $databasePath)) {
        Write-SetupLog "ClamAV database directory not found at: $databasePath" -Level ERROR
        return $false
    }
    
    # Check for virus definition files
    $mainCvd = Join-Path $databasePath "main.cvd"
    $dailyCvd = Join-Path $databasePath "daily.cvd"
    
    if (-not (Test-Path $mainCvd) -or -not (Test-Path $dailyCvd)) {
        Write-SetupLog "ClamAV virus definitions are missing" -Level WARN
        Write-SetupLog "Consider running update to download latest definitions" -Level WARN
    } else {
        Write-SetupLog "ClamAV installation verified" -Level SUCCESS
    }
    
    return $true
}

function Test-RequiredFiles {
    Write-SetupLog "Checking required files..." -Level INFO
    
    $requiredFiles = @(
        "backend_server.py",
        "RiskNoX-Control.ps1",
        "web\index.html",
        "web\app.js",
        "config\agent_config.xml"
    )
    
    $missing = @()
    foreach ($file in $requiredFiles) {
        $filePath = Join-Path $PSScriptRoot $file
        if (-not (Test-Path $filePath)) {
            $missing += $file
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-SetupLog "Missing required files:" -Level ERROR
        foreach ($file in $missing) {
            Write-SetupLog "  - $file" -Level ERROR
        }
        return $false
    }
    
    Write-SetupLog "All required files present" -Level SUCCESS
    return $true
}

function Initialize-Directories {
    Write-SetupLog "Initializing directories..." -Level INFO
    
    $directories = @("logs", "config")
    
    foreach ($dir in $directories) {
        $dirPath = Join-Path $PSScriptRoot $dir
        if (-not (Test-Path $dirPath)) {
            New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
            Write-SetupLog "Created directory: $dir" -Level INFO
        }
    }
    
    Write-SetupLog "Directory initialization completed" -Level SUCCESS
}

function Test-NetworkPort {
    Write-SetupLog "Checking if port 5000 is available..." -Level INFO
    
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 5000)
        $listener.Start()
        $listener.Stop()
        Write-SetupLog "Port 5000 is available" -Level SUCCESS
        return $true
    }
    catch {
        Write-SetupLog "Port 5000 is already in use or blocked" -Level WARN
        Write-SetupLog "You may need to stop other services using this port" -Level WARN
        return $false
    }
}

function Show-WelcomeMessage {
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                    RiskNoX Security Agent                    ║
║                        Setup Complete                        ║
╚══════════════════════════════════════════════════════════════╝

Welcome to RiskNoX Security Agent! Your system is now ready.

QUICK START:
  1. Start the service:    .\RiskNoX-Control.ps1 -Action start
  2. Open web interface:   http://localhost:5000
  3. Check system status:  .\RiskNoX-Control.ps1 -Action status

FEATURES:
  🛡️ Antivirus Scanner     - Real-time virus protection
  🌐 Web Blocking          - URL-based website blocking  
  🔄 Patch Management      - Windows update management

ADMIN ACCESS:
  Username: admin
  Password: RiskNoX@2024

For help and documentation, see README.md or run:
  .\RiskNoX-Control.ps1 -Action help

"@ -ForegroundColor Cyan
}

function Main {
    Write-SetupLog "Starting RiskNoX Security Agent Setup..." -Level INFO
    Write-SetupLog "Setup Location: $PSScriptRoot" -Level INFO
    
    $allPassed = $true
    
    if (-not $SkipChecks) {
        # Run all checks
        $checks = @(
            { Test-PowerShellVersion },
            { Test-RequiredFiles },
            { Test-PythonEnvironment },
            { Test-ClamAVInstallation },
            { Test-NetworkPort }
        )
        
        foreach ($check in $checks) {
            if (-not (& $check)) {
                $allPassed = $false
            }
        }
    }
    
    # Initialize directories regardless of check results
    Initialize-Directories
    
    if ($allPassed) {
        Write-SetupLog "Setup completed successfully!" -Level SUCCESS
        Show-WelcomeMessage
    } else {
        Write-SetupLog "Setup completed with warnings. Please review the issues above." -Level WARN
        Write-SetupLog "The system may still be functional, but some features might not work properly." -Level WARN
    }
    
    Write-SetupLog "Setup finished" -Level INFO
}

# Execute main function
Main