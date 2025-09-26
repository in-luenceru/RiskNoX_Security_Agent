#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Security Agent Control Script
    
.DESCRIPTION
    Unified PowerShell 7 control script for managing RiskNoX Security Agent services.
    Provides easy management of antivirus, web blocking, and professional patch management features.
    Includes integrated patch management setup with WUA API integration and policy enforcement.
    
.PARAMETER Action
    The action to perform: start, stop, restart, status, install, uninstall, scan, block, unblock, update
    
.PARAMETER Path
    Path for scanning operations
    
.PARAMETER Url
    URL for web blocking operations
    
.PARAMETER Service
    Specific service to manage: backend, all
    
.EXAMPLE
    .\RiskNoX-Control.ps1 -Action start
    Starts the RiskNoX Security Agent backend service
    
.EXAMPLE
    .\RiskNoX-Control.ps1 -Action scan -Path "C:\Users\Username\Downloads"
    Performs an antivirus scan on the specified directory
    
.EXAMPLE
    .\RiskNoX-Control.ps1 -Action block -Url "malicious-site.com"
    Blocks access to the specified URL
    
.NOTES
    Author: RiskNoX Security Team
    Version: 1.0.0
    Requires: PowerShell 7.0 or later, Administrator privileges for some operations
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'restart', 'status', 'install', 'uninstall', 'scan', 'block', 'unblock', 'update', 
                 'patch-check', 'patch-install', 'patch-enforce', 'patch-compliance', 'patch-reset', 'patch-setup', 'help')]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$Url,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('backend', 'all')]
    [string]$Service = 'all',
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [switch]$FullSetup,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode
)

# Configuration
$Script:Config = @{
    RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    BackendScript = "backend_server.py"
    BackendPort = 5000
    VirtualEnvPath = ".venv"
    LogsPath = "logs"
    WebPath = "web"
    VendorPath = "vendor"
    ConfigPath = "config"
    ServiceName = "RiskNoXAgent"
    ProcessName = "python"
}

# Logging functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'INFO' { 'White' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Also log to file
    $logFile = Join-Path $Script:Config.LogsPath "control.log"
    $logDir = Split-Path $logFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    "[$timestamp] [$Level] $Message" | Out-File -FilePath $logFile -Append
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Dependencies {
    Write-Log "Checking dependencies..." -Level INFO
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Log "PowerShell 7.0 or later is required. Current version: $($PSVersionTable.PSVersion)" -Level ERROR
        return $false
    }
    
    # Check Python virtual environment
    $venvPath = Join-Path $Script:Config.RootPath $Script:Config.VirtualEnvPath
    if (-not (Test-Path $venvPath)) {
        Write-Log "Python virtual environment not found at: $venvPath" -Level ERROR
        Write-Log "Please run the setup first to create the virtual environment" -Level ERROR
        return $false
    }
    
    # Check backend script
    $backendPath = Join-Path $Script:Config.RootPath $Script:Config.BackendScript
    if (-not (Test-Path $backendPath)) {
        Write-Log "Backend script not found at: $backendPath" -Level ERROR
        return $false
    }
    
    # Check ClamAV
    $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
    if (-not (Test-Path $clamScanPath)) {
        Write-Log "ClamAV scanner not found at: $clamScanPath" -Level WARN
    } else {
        Write-Log "ClamAV scanner found" -Level SUCCESS
    }
    
    Write-Log "Dependency check completed" -Level SUCCESS
    return $true
}

function Get-ProcessByPort {
    param([int]$Port)
    
    try {
        $netstat = netstat -ano | Select-String ":$Port "
        if ($netstat) {
            $processes = @()
            foreach ($line in $netstat) {
                $processId = ($line -split '\s+')[-1]
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($process) {
                    $processes += $process
                }
            }
            return $processes
        }
    }
    catch {
        return $null
    }
    
    return $null
}

function Get-AllBackendProcesses {
    # Get all Python processes that might be running the backend
    $allPythonProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue
    $backendProcesses = @()
    $processIds = @()
    
    # Check processes on the backend port
    $portProcesses = Get-ProcessByPort $Script:Config.BackendPort
    if ($portProcesses) {
        foreach ($proc in $portProcesses) {
            if ($proc.Id -notin $processIds -and $proc.Id -gt 0) {
                $backendProcesses += $proc
                $processIds += $proc.Id
            }
        }
    }
    
    # Also check for Python processes running backend_server.py
    if ($allPythonProcesses) {
        foreach ($proc in $allPythonProcesses) {
            try {
                # Skip if already added or system process
                if ($proc.Id -in $processIds -or $proc.Id -le 0) {
                    continue
                }
                
                $commandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
                if ($commandLine -and $commandLine -like "*backend_server.py*") {
                    $backendProcesses += $proc
                    $processIds += $proc.Id
                }
            }
            catch {
                # Continue if we can't get command line
            }
        }
    }
    
    return $backendProcesses
}

function Start-Backend {
    param([switch]$ShowLogs)
    
    Write-Log "Starting RiskNoX Security Agent Backend..." -Level INFO
    
    # Check if already running
    $existingProcesses = Get-AllBackendProcesses
    if ($existingProcesses -and $existingProcesses.Count -gt 0) {
        $firstProcess = $existingProcesses[0]
        Write-Log "Backend is already running ($($existingProcesses.Count) process(es), first PID: $($firstProcess.Id))" -Level WARN
        if ($ShowLogs) {
            Write-Log "Showing live logs... Press Ctrl+C to exit" -Level INFO
            Show-LiveLogs -ProcessId $firstProcess.Id
        }
        return $firstProcess
    }
    
    # Set up paths
    $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
    $backendScript = Join-Path $Script:Config.RootPath $Script:Config.BackendScript
    
    # Start the backend
    try {
        Push-Location $Script:Config.RootPath
        
        if ($ShowLogs) {
            # Start with live logs visible
            Write-Log "Starting backend with live logs... Press Ctrl+C to exit" -Level INFO
            $process = Start-Process -FilePath $venvPython -ArgumentList $backendScript -NoNewWindow -PassThru
        } else {
            $process = Start-Process -FilePath $venvPython -ArgumentList $backendScript -WindowStyle Hidden -PassThru
        }
        
        # Wait longer for Flask to fully initialize
        Write-Log "Waiting for backend to initialize..." -Level INFO
        Start-Sleep -Seconds 2
        
        # Check multiple times with increasing delays
        $maxAttempts = 10
        $attempt = 1
        $runningProcess = $null
        
        while ($attempt -le $maxAttempts -and -not $runningProcess) {
            Start-Sleep -Seconds 1
            $runningProcesses = Get-AllBackendProcesses
            if ($runningProcesses -and $runningProcesses.Count -gt 0) {
                $runningProcess = $runningProcesses[0]
            } else {
                Write-Log "Attempt $attempt/$maxAttempts - Backend still initializing..." -Level INFO
                $attempt++
            }
        }
        
        if ($runningProcess) {
            Write-Log "Backend started successfully (PID: $($runningProcess.Id))" -Level SUCCESS
            Write-Log "Web interface available at: http://localhost:$($Script:Config.BackendPort)" -Level SUCCESS
            
            if ($ShowLogs) {
                Write-Log "Showing live logs... Press Ctrl+C to exit" -Level INFO
                Show-LiveLogs -ProcessId $runningProcess.Id
            }
            
            return $runningProcess
        } else {
            Write-Log "Backend failed to start or is not listening on port $($Script:Config.BackendPort)" -Level ERROR
            Write-Log "Please check the logs directory for error details" -Level INFO
            return $null
        }
    }
    catch {
        Write-Log "Failed to start backend: $($_.Exception.Message)" -Level ERROR
        return $null
    }
    finally {
        Pop-Location
    }
}

function Stop-Backend {
    Write-Log "Stopping RiskNoX Security Agent Backend..." -Level INFO
    
    $processes = Get-AllBackendProcesses
    if ($processes -and $processes.Count -gt 0) {
        $stopped = 0
        foreach ($process in $processes) {
            try {
                Write-Log "Stopping backend process (PID: $($process.Id))" -Level INFO
                Stop-Process -Id $process.Id -Force
                $stopped++
            }
            catch {
                Write-Log "Failed to stop process $($process.Id): $($_.Exception.Message)" -Level ERROR
            }
        }
        
        if ($stopped -gt 0) {
            Write-Log "Successfully stopped $stopped backend process(es)" -Level SUCCESS
            
            # Wait a moment and verify they're really stopped
            Start-Sleep -Seconds 2
            $remainingProcesses = Get-AllBackendProcesses
            if ($remainingProcesses -and $remainingProcesses.Count -gt 0) {
                Write-Log "Warning: $($remainingProcesses.Count) backend process(es) still running" -Level WARN
            } else {
                Write-Log "All backend processes stopped successfully" -Level SUCCESS
            }
        }
    } else {
        Write-Log "Backend is not running" -Level WARN
    }
}

function Get-ServiceStatus {
    Write-Log "Checking RiskNoX Security Agent Status..." -Level INFO
    
    # Backend status
    $backendProcesses = Get-AllBackendProcesses
    if ($backendProcesses -and $backendProcesses.Count -gt 0) {
        if ($backendProcesses.Count -eq 1) {
            Write-Log "✓ Backend Service: Running (PID: $($backendProcesses[0].Id))" -Level SUCCESS
        } else {
            $pidList = ($backendProcesses | ForEach-Object { $_.Id }) -join ", "
            Write-Log "✓ Backend Service: Running ($($backendProcesses.Count) processes - PIDs: $pidList)" -Level SUCCESS
        }
        Write-Log "  └─ Web Interface: http://localhost:$($Script:Config.BackendPort)" -Level INFO
    } else {
        Write-Log "✗ Backend Service: Stopped" -Level WARN
    }
    
    # ClamAV status
    $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
    if (Test-Path $clamScanPath) {
        Write-Log "✓ ClamAV Antivirus: Available" -Level SUCCESS
    } else {
        Write-Log "✗ ClamAV Antivirus: Not Found" -Level ERROR
    }
    
    # Configuration status
    $configPath = Join-Path $Script:Config.RootPath $Script:Config.ConfigPath
    if (Test-Path $configPath) {
        Write-Log "✓ Configuration: Available" -Level SUCCESS
    } else {
        Write-Log "✗ Configuration: Missing" -Level WARN
    }
    
    # Logs status
    $logsPath = Join-Path $Script:Config.RootPath $Script:Config.LogsPath
    if (Test-Path $logsPath) {
        $logFiles = Get-ChildItem $logsPath -File | Measure-Object
        Write-Log "✓ Logs: $($logFiles.Count) log files" -Level SUCCESS
    } else {
        Write-Log "✗ Logs: Directory not found" -Level WARN
    }
}

function Invoke-AntivirusScan {
    param([string]$ScanPath)
    
    if (-not $ScanPath) {
        Write-Log "Scan path is required for antivirus scan" -Level ERROR
        return
    }
    
    if (-not (Test-Path $ScanPath)) {
        Write-Log "Scan path does not exist: $ScanPath" -Level ERROR
        return
    }
    
    Write-Log "Starting antivirus scan on: $ScanPath" -Level INFO
    
    $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
    
    if (-not (Test-Path $clamScanPath)) {
        Write-Log "ClamAV scanner not found. Please ensure ClamAV is properly installed." -Level ERROR
        return
    }
    
    try {
        $logFile = Join-Path $Script:Config.LogsPath "manual_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $logDir = Split-Path $logFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        $arguments = @(
            "--recursive"
            "--infected" 
            "--bell"
            "--log=$logFile"
            "--database=$(Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\database")"
            "$ScanPath"
        )
        
        Write-Log "Executing: $clamScanPath $($arguments -join ' ')" -Level INFO
        
        $process = Start-Process -FilePath $clamScanPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru
        
        Write-Log "Scan completed with exit code: $($process.ExitCode)" -Level INFO
        
        if (Test-Path $logFile) {
            Write-Log "Scan results saved to: $logFile" -Level INFO
            
            # Display summary
            $content = Get-Content $logFile -Raw
            if ($content -match "Infected files: (\d+)") {
                $infectedCount = $Matches[1]
                if ($infectedCount -eq "0") {
                    Write-Log "✓ No threats found" -Level SUCCESS
                } else {
                    Write-Log "⚠ $infectedCount threat(s) detected. Check log file for details." -Level WARN
                }
            }
        }
    }
    catch {
        Write-Log "Scan failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Block-WebUrl {
    param([string]$UrlToBlock)
    
    if (-not $UrlToBlock) {
        Write-Log "URL is required for web blocking" -Level ERROR
        return
    }
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required for web blocking" -Level ERROR
        return
    }
    
    Write-Log "Blocking URL: $UrlToBlock" -Level INFO
    
    try {
        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
        $backupFile = "$hostsFile.backup.$(Get-Date -Format 'yyyyMMdd')"
        
        # Create backup
        if (-not (Test-Path $backupFile)) {
            Copy-Item $hostsFile $backupFile
            Write-Log "Hosts file backed up to: $backupFile" -Level INFO
        }
        
        # Read current content
        $content = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
        if (-not $content) { $content = "" }
        
        # Check if URL is already blocked
        $cleanUrl = $UrlToBlock -replace '^https?://', ''
        if ($content -match "127\.0\.0\.1\s+$cleanUrl\s+# RiskNoX Block") {
            Write-Log "URL is already blocked: $cleanUrl" -Level WARN
            return
        }
        
        # Add blocking entries
        $newEntries = @(
            "127.0.0.1 $cleanUrl # RiskNoX Block"
            "127.0.0.1 www.$cleanUrl # RiskNoX Block"
        )
        
        $updatedContent = $content + "`n" + ($newEntries -join "`n")
        Set-Content -Path $hostsFile -Value $updatedContent -Force
        
        Write-Log "✓ URL blocked successfully: $cleanUrl" -Level SUCCESS
        
        # Save to blocked URLs config
        $configFile = Join-Path $Script:Config.RootPath "$($Script:Config.ConfigPath)\blocked_urls.json"
        $configDir = Split-Path $configFile -Parent
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        
        $blockedUrls = @()
        if (Test-Path $configFile) {
            $blockedUrls = Get-Content $configFile | ConvertFrom-Json
        }
        
        $blockedUrls += @{
            url = $cleanUrl
            blocked_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            status = "active"
        }
        
        $blockedUrls | ConvertTo-Json -Depth 3 | Set-Content $configFile
        
    }
    catch {
        Write-Log "Failed to block URL: $($_.Exception.Message)" -Level ERROR
    }
}

function Unblock-WebUrl {
    param([string]$UrlToUnblock)
    
    if (-not $UrlToUnblock) {
        Write-Log "URL is required for web unblocking" -Level ERROR
        return
    }
    
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required for web unblocking" -Level ERROR
        return
    }
    
    Write-Log "Unblocking URL: $UrlToUnblock" -Level INFO
    
    try {
        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
        $cleanUrl = $UrlToUnblock -replace '^https?://', ''
        
        # Read and filter content
        $lines = Get-Content $hostsFile
        $filteredLines = $lines | Where-Object { 
            $_ -notmatch "127\.0\.0\.1\s+(www\.)?$cleanUrl\s+# RiskNoX Block" 
        }
        
        Set-Content -Path $hostsFile -Value $filteredLines -Force
        
        Write-Log "✓ URL unblocked successfully: $cleanUrl" -Level SUCCESS
        
        # Update blocked URLs config
        $configFile = Join-Path $Script:Config.RootPath "$($Script:Config.ConfigPath)\blocked_urls.json"
        if (Test-Path $configFile) {
            $blockedUrls = Get-Content $configFile | ConvertFrom-Json
            $updatedUrls = $blockedUrls | Where-Object { $_.url -ne $cleanUrl }
            $updatedUrls | ConvertTo-Json -Depth 3 | Set-Content $configFile
        }
        
    }
    catch {
        Write-Log "Failed to unblock URL: $($_.Exception.Message)" -Level ERROR
    }
}

function Update-AntivirusDatabase {
    Write-Log "Updating antivirus database..." -Level INFO
    
    $freshclamPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\freshclam.exe"
    
    if (-not (Test-Path $freshclamPath)) {
        Write-Log "FreshClam updater not found. Please ensure ClamAV is properly installed." -Level ERROR
        return
    }
    
    try {
        $arguments = @(
            "--datadir=$(Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\database")"
            "--log=$(Join-Path $Script:Config.LogsPath "freshclam_$(Get-Date -Format 'yyyyMMdd').log")"
        )
        
        Write-Log "Executing: $freshclamPath $($arguments -join ' ')" -Level INFO
        
        $process = Start-Process -FilePath $freshclamPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "✓ Antivirus database updated successfully" -Level SUCCESS
        } else {
            Write-Log "⚠ Update completed with exit code: $($process.ExitCode)" -Level WARN
        }
    }
    catch {
        Write-Log "Database update failed: $($_.Exception.Message)" -Level ERROR
    }
}

function Show-Help {
    Write-Host @"

RiskNoX Security Agent Control Script - Professional Edition
===========================================================

USAGE:
    .\RiskNoX-Control.ps1 -Action <action> [options]

CORE ACTIONS:
    start               Start the security agent backend service
    stop                Stop the security agent backend service  
    restart             Restart the security agent backend service
    status              Show current status of all services
    help                Show this help message

ANTIVIRUS ACTIONS:
    scan                Perform antivirus scan (requires -Path)
    update              Update antivirus database

WEB BLOCKING ACTIONS:
    block               Block a website URL (requires -Url, admin privileges)
    unblock             Unblock a website URL (requires -Url, admin privileges)

PROFESSIONAL PATCH MANAGEMENT ACTIONS:
    patch-setup         Setup professional patch management system (admin privileges)
    patch-check         Check for available Windows updates
    patch-install       Install all available Windows updates (admin privileges)
    patch-enforce       Enforce Windows Update policies to block manual updates (admin privileges)
    patch-compliance    Check compliance status of Windows Update policies
    patch-reset         Reset Windows Update service and clear cache (admin privileges)

OPTIONS:
    -Force              Skip confirmation prompts for patch management operations
    -FullSetup          Enable complete setup with policy enforcement
    -TestMode           Run setup in test mode without making permanent changes
    -Path <path>        Specify path for scan operations
    -Url <url>          Specify URL for web blocking operations
    -Service <service>  Specify service (backend, all)

EXAMPLES:

Basic Operations:
    .\RiskNoX-Control.ps1 -Action start
        Start the RiskNoX backend service
        
    .\RiskNoX-Control.ps1 -Action status
        Show current service status
        
Antivirus Operations:
    .\RiskNoX-Control.ps1 -Action scan -Path "C:\Users\Username\Downloads"
        Scan Downloads folder for viruses
        
    .\RiskNoX-Control.ps1 -Action update
        Update antivirus virus definitions

Web Blocking Operations:
    .\RiskNoX-Control.ps1 -Action block -Url "malicious-site.com"
        Block access to a malicious website
        
    .\RiskNoX-Control.ps1 -Action unblock -Url "safe-site.com"
        Unblock access to a previously blocked website

Professional Patch Management Operations:
    .\RiskNoX-Control.ps1 -Action patch-setup
        Setup professional patch management system (basic setup)
        
    .\RiskNoX-Control.ps1 -Action patch-setup -FullSetup
        Complete setup with policy enforcement enabled
        
    .\RiskNoX-Control.ps1 -Action patch-setup -TestMode
        Test setup without making permanent changes
        
    .\RiskNoX-Control.ps1 -Action patch-check
        Check for available Windows updates
        
    .\RiskNoX-Control.ps1 -Action patch-install -Force
        Install all available updates without confirmation
        
    .\RiskNoX-Control.ps1 -Action patch-enforce
        Block manual Windows updates and enforce centralized control
        
    .\RiskNoX-Control.ps1 -Action patch-compliance
        Check Windows Update policy compliance status
        
    .\RiskNoX-Control.ps1 -Action patch-reset
        Reset Windows Update service if experiencing issues

PROFESSIONAL PATCH MANAGEMENT FEATURES:
    ✓ Enterprise-grade Windows Update API integration
    ✓ Centralized patch management and control
    ✓ Automatic blocking of manual user updates
    ✓ Policy compliance monitoring and enforcement
    ✓ Detailed update tracking and reporting
    ✓ Service troubleshooting and repair capabilities
    ✓ Dashboard integration for remote management

NOTES:
    - Web interface available at: http://localhost:5000
    - Admin credentials: username=admin, password=RiskNoX@2024
    - First-time users: Run ".\RiskNoX-Control.ps1 -Action patch-setup" for initial setup
    - Patch management requires administrator privileges
    - Logs stored in the 'logs' directory
    - Professional patch module located in 'scripts\PatchManagement.ps1'

"@ -ForegroundColor Cyan
}

function Show-LiveLogs {
    param([int]$ProcessId)
    
    $controlLogFile = Join-Path $Script:Config.LogsPath "control.log"
    $lastLogPosition = 0
    
    Write-Log "Monitoring backend logs... Press Ctrl+C to exit" -Level INFO
    Write-Host "`n--- Live Logs (Real-time) ---" -ForegroundColor Yellow
    
    try {
        # Get initial log position
        if (Test-Path $controlLogFile) {
            $initialContent = Get-Content $controlLogFile -Raw -ErrorAction SilentlyContinue
            if ($initialContent) {
                $lastLogPosition = $initialContent.Length
                # Show last few lines initially
                $lines = Get-Content $controlLogFile -Tail 5 -ErrorAction SilentlyContinue
                if ($lines) {
                    $lines | ForEach-Object {
                        Write-Host $_ -ForegroundColor Gray
                    }
                }
                Write-Host "--- End of existing logs, showing new entries only ---" -ForegroundColor Cyan
            }
        }
        
        # Keep monitoring for new content only
        while ($true) {
            Start-Sleep -Seconds 2
            
            # Check if process is still running
            if ($ProcessId -and -not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
                Write-Log "Backend process has stopped" -Level WARN
                break
            }
            
            # Check for new log content only
            if (Test-Path $controlLogFile) {
                try {
                    $currentContent = Get-Content $controlLogFile -Raw -ErrorAction SilentlyContinue
                    if ($currentContent -and $currentContent.Length -gt $lastLogPosition) {
                        # Get only new content
                        $newContent = $currentContent.Substring($lastLogPosition)
                        $newLines = $newContent -split "`r?`n" | Where-Object { $_.Trim() -ne "" }
                        
                        if ($newLines) {
                            $newLines | ForEach-Object {
                                if ($_ -match '\[ERROR\]') {
                                    Write-Host $_ -ForegroundColor Red
                                } elseif ($_ -match '\[WARN\]') {
                                    Write-Host $_ -ForegroundColor Yellow
                                } elseif ($_ -match '\[SUCCESS\]') {
                                    Write-Host $_ -ForegroundColor Green
                                } elseif ($_ -match '\[INFO\]') {
                                    Write-Host $_ -ForegroundColor White
                                } else {
                                    Write-Host $_ -ForegroundColor Gray
                                }
                            }
                        }
                        
                        $lastLogPosition = $currentContent.Length
                    }
                } catch {
                    # Skip errors when file is being written to
                    continue
                }
            }
        }
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        Write-Log "Log monitoring stopped by user (Ctrl+C)" -Level INFO
    }
    catch {
        Write-Log "Log monitoring interrupted: $($_.Exception.Message)" -Level WARN
    }

# Professional Patch Management Setup Functions
function Test-PatchManagementPrerequisites {
    Write-Log "Checking patch management prerequisites..." -Level INFO
    
    $issues = @()
    
    # Check PowerShell version
    $requiredVersion = [Version]"7.0.0"
    if ($PSVersionTable.PSVersion -lt $requiredVersion) {
        $issues += "PowerShell $requiredVersion or later is required. Current version: $($PSVersionTable.PSVersion)"
    }
    
    # Check if running as Administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues += "This script must be run as Administrator for patch management setup"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        $issues += "Windows 10 or later is required for professional patch management"
    }
    
    # Check required services
    $requiredServices = @("wuauserv", "cryptsvc", "bits", "msiserver")
    foreach ($service in $requiredServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction Stop
            if ($svc.StartType -eq 'Disabled') {
                $issues += "Service '$service' is disabled. It should be enabled for proper patch management."
            }
        }
        catch {
            $issues += "Required service '$service' not found"
        }
    }
    
    # Check Windows Update Agent
    try {
        $wua = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        if ($wua) {
            Write-Log "Windows Update Agent COM interface available" -Level SUCCESS
        }
    }
    catch {
        $issues += "Windows Update Agent COM interface not available: $($_.Exception.Message)"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Prerequisites check failed:" -Level ERROR
        foreach ($issue in $issues) {
            Write-Log "- $issue" -Level ERROR
        }
        return $false
    }
    
    Write-Log "All patch management prerequisites met" -Level SUCCESS
    return $true
}

function Initialize-PatchManagementDirectories {
    Write-Log "Creating patch management directory structure..." -Level INFO
    
    $directories = @(
        "logs",
        "scripts", 
        "config",
        "web",
        "vendor"
    )
    
    foreach ($dir in $directories) {
        $path = Join-Path $Script:Config.RootPath $dir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Log "Created directory: $dir" -Level SUCCESS
        } else {
            Write-Log "Directory exists: $dir" -Level INFO
        }
    }
    return $true
}

function Test-PatchManagementModule {
    Write-Log "Validating patch management module..." -Level INFO
    
    $modulePath = "scripts\PatchManagement.ps1"
    
    if (-not (Test-Path $modulePath)) {
        Write-Log "Patch management module not found at: $modulePath" -Level ERROR
        Write-Log "Please ensure the professional patch management module is installed" -Level ERROR
        return $false
    }
    
    try {
        # Test loading the module
        . $modulePath
        
        # Test creating a patch manager instance
        $logPath = "logs\setup_test.log"
        $patchManager = Initialize-PatchManager -LogPath $logPath
        
        if ($patchManager) {
            Write-Log "Patch management module loaded successfully" -Level SUCCESS
            return $true
        } else {
            Write-Log "Failed to initialize patch manager" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Error loading patch management module: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-WindowsUpdateConnectivity {
    Write-Log "Testing Windows Update connectivity..." -Level INFO
    
    try {
        # Test basic internet connectivity
        $testUrls = @(
            "https://www.microsoft.com",
            "https://update.microsoft.com"
        )
        
        $connectivityResults = @()
        foreach ($url in $testUrls) {
            try {
                $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing
                if ($response.StatusCode -eq 200) {
                    Write-Log "✓ $url - Accessible" -Level SUCCESS
                    $connectivityResults += $true
                }
            }
            catch {
                Write-Log "✗ $url - $($_.Exception.Message)" -Level WARN
                $connectivityResults += $false
            }
        }
        
        # Test Windows Update API
        try {
            . "scripts\PatchManagement.ps1"
            $patchManager = Initialize-PatchManager -LogPath "logs\connectivity_test.log"
            
            Write-Log "Testing Windows Update API..." -Level INFO
            $updateCheck = Get-AvailableUpdates -PatchManager $patchManager
            
            if ($updateCheck.Success) {
                Write-Log "✓ Windows Update API - Functional (Found $($updateCheck.UpdateCount) updates)" -Level SUCCESS
                return $true
            } else {
                Write-Log "✗ Windows Update API - Error: $($updateCheck.Error)" -Level WARN
                return $false
            }
        }
        catch {
            Write-Log "✗ Windows Update API - Exception: $($_.Exception.Message)" -Level WARN
            return $false
        }
    }
    catch {
        Write-Log "Connectivity test failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Initialize-WindowsUpdateConfiguration {
    Write-Log "Initializing Windows Update configuration..." -Level INFO
    
    if ($TestMode) {
        Write-Log "Running in test mode - no permanent changes will be made" -Level WARN
        return $true
    }
    
    try {
        # Ensure Windows Update service is properly configured
        Write-Log "Configuring Windows Update service..." -Level INFO
        
        $wuService = Get-Service -Name "wuauserv"
        if ($wuService.StartType -eq 'Disabled') {
            if ($FullSetup -or $Force -or (Read-Host "Windows Update service is disabled. Enable it? (Y/n)") -ne 'n') {
                Set-Service -Name "wuauserv" -StartupType Manual
                Write-Log "Enabled Windows Update service" -Level SUCCESS
            }
        }
        
        # Start the service if it's not running
        if ($wuService.Status -ne 'Running') {
            Start-Service -Name "wuauserv"
            Write-Log "Started Windows Update service" -Level SUCCESS
        }
        
        # Configure related services
        $relatedServices = @("cryptsvc", "bits")
        foreach ($serviceName in $relatedServices) {
            $service = Get-Service -Name $serviceName
            if ($service.StartType -eq 'Disabled') {
                Set-Service -Name $serviceName -StartupType Manual
                Write-Log "Enabled $serviceName service" -Level SUCCESS
            }
            if ($service.Status -ne 'Running') {
                Start-Service -Name $serviceName
                Write-Log "Started $serviceName service" -Level SUCCESS
            }
        }
        
        # Create initial configuration
        $configPath = "config\patch_config.json"
        $config = @{
            Version = "2.0.0"
            SetupDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
            ProfessionalMode = $true
            AutoUpdateCheck = $true
            LogRetentionDays = 30
            MaxConcurrentDownloads = 3
            RebootPolicy = "Prompt"
        }
        
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Log "Created patch management configuration" -Level SUCCESS
        
        return $true
    }
    catch {
        Write-Log "Failed to initialize Windows Update configuration: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-PatchManagementPolicies {
    if (-not $FullSetup) {
        Write-Log "Skipping policy installation (use -FullSetup to enable)" -Level INFO
        return $true
    }
    
    if ($TestMode) {
        Write-Log "Test mode: Would install patch management policies" -Level WARN
        return $true
    }
    
    Write-Log "Installing patch management policies..." -Level INFO
    
    $confirmation = if ($Force) { 'y' } else { 
        Read-Host "This will enforce Windows Update policies and block manual updates. Continue? (Y/n)"
    }
    
    if ($confirmation -eq 'n') {
        Write-Log "Policy installation skipped by user" -Level INFO
        return $true
    }
    
    try {
        # Load the patch management module
        . "scripts\PatchManagement.ps1"
        $patchManager = Initialize-PatchManager -LogPath "logs\policy_setup.log"
        
        # Enforce policies
        $policyResult = Set-UpdatePolicies -PatchManager $patchManager
        
        if ($policyResult.Success) {
            Write-Log "Patch management policies installed successfully" -Level SUCCESS
            Write-Log "Policy changes applied:" -Level INFO
            foreach ($result in $policyResult.Results) {
                Write-Log "- $result" -Level INFO
            }
            
            # Verify compliance
            $complianceResult = Test-UpdateCompliance -PatchManager $patchManager
            if ($complianceResult.Success) {
                Write-Log "Policy compliance: $($complianceResult.CompliancePercentage)%" -Level SUCCESS
            }
            
            return $true
        } else {
            Write-Log "Failed to install policies: $($policyResult.Error)" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Exception during policy installation: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-PatchSetupValidation {
    Write-Log "Validating patch management setup..." -Level INFO
    
    $validationResults = @{
        ModuleLoads = $false
        APIAccess = $false
        ServiceStatus = $false
        ConfigExists = $false
        LoggingWorks = $false
    }
    
    try {
        # Test module loading
        . "scripts\PatchManagement.ps1"
        $patchManager = Initialize-PatchManager -LogPath "logs\validation_test.log"
        $validationResults.ModuleLoads = ($null -ne $patchManager)
        
        # Test API access
        if ($validationResults.ModuleLoads) {
            $updateCheck = Get-AvailableUpdates -PatchManager $patchManager
            $validationResults.APIAccess = $updateCheck.Success
        }
        
        # Test service status
        $wuService = Get-Service -Name "wuauserv"
        $validationResults.ServiceStatus = ($wuService.Status -eq 'Running')
        
        # Test configuration
        $configPath = "config\patch_config.json"
        $validationResults.ConfigExists = (Test-Path $configPath)
        
        # Test logging
        $testLogPath = "logs\validation_test.log"
        $validationResults.LoggingWorks = (Test-Path $testLogPath)
        
        # Report results
        Write-Log "Validation Results:" -Level INFO
        foreach ($test in $validationResults.Keys) {
            $status = if ($validationResults[$test]) { "✓ PASS" } else { "✗ FAIL" }
            $level = if ($validationResults[$test]) { "SUCCESS" } else { "ERROR" }
            Write-Log "- $test : $status" -Level $level
        }
        
        $allPassed = ($validationResults.Values | Where-Object { $_ -eq $false }).Count -eq 0
        
        if ($allPassed) {
            Write-Log "All validation tests passed!" -Level SUCCESS
            return $true
        } else {
            Write-Log "Some validation tests failed. Check the issues above." -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Validation failed with exception: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Invoke-PatchManagementSetup {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Professional Patch Management Setup          ║
║                        Version 2.0.0                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Log "Starting RiskNoX Professional Patch Management setup..." -Level INFO
    $setupModeText = if ($FullSetup) { "Full Setup" } else { "Basic Setup" }
    $testModeText = if ($TestMode) { " (Test Mode)" } else { "" }
    Write-Log "Setup mode: $setupModeText$testModeText" -Level INFO
    
    $setupSteps = @(
        @{ Name = "Prerequisites Check"; Function = { Test-PatchManagementPrerequisites } },
        @{ Name = "Directory Initialization"; Function = { Initialize-PatchManagementDirectories } },
        @{ Name = "Module Validation"; Function = { Test-PatchManagementModule } },
        @{ Name = "Connectivity Test"; Function = { Test-WindowsUpdateConnectivity } },
        @{ Name = "Windows Update Configuration"; Function = { Initialize-WindowsUpdateConfiguration } },
        @{ Name = "Policy Installation"; Function = { Install-PatchManagementPolicies } },
        @{ Name = "Setup Validation"; Function = { Test-PatchSetupValidation } }
    )
    
    $success = $true
    $stepNumber = 1
    
    foreach ($step in $setupSteps) {
        Write-Log "[$stepNumber/$($setupSteps.Count)] $($step.Name)..." -Level INFO
        
        try {
            $result = & $step.Function
            if ($result) {
                Write-Log "$($step.Name) completed successfully" -Level SUCCESS
            } else {
                Write-Log "$($step.Name) failed" -Level ERROR
                $success = $false
                if (-not $Force) {
                    $continue = Read-Host "Continue with setup anyway? (y/N)"
                    if ($continue -ne 'y') {
                        Write-Log "Setup aborted by user" -Level ERROR
                        return
                    }
                }
            }
        }
        catch {
            Write-Log "$($step.Name) failed with exception: $($_.Exception.Message)" -Level ERROR
            $success = $false
            if (-not $Force) {
                $continue = Read-Host "Continue with setup anyway? (y/N)"
                if ($continue -ne 'y') {
                    Write-Log "Setup aborted by user" -Level ERROR
                    return
                }
            }
        }
        
        $stepNumber++
        Start-Sleep -Milliseconds 500
    }
    
    if ($success) {
        Write-Log "Setup completed successfully!" -Level SUCCESS
        Show-PatchSetupSummary
    } else {
        Write-Log "Setup completed with some issues. Check the logs for details." -Level WARN
    }
    
    Write-Log "Setup finished at $(Get-Date)" -Level INFO
}

function Show-PatchSetupSummary {
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Professional Patch Management Setup          ║
║                     Setup Complete!                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

SETUP SUMMARY:
✓ Prerequisites validated
✓ Directory structure created  
✓ Patch management module installed
✓ Windows Update services configured
$(if ($FullSetup) { "✓ Update policies enforced" } else { "○ Update policies not installed (use -FullSetup)" })
✓ Configuration files created
✓ System validation passed

NEXT STEPS:
1. Start the RiskNoX service:
   .\RiskNoX-Control.ps1 -Action start

2. Access the web interface:
   http://localhost:5000

3. Test patch management:
   .\RiskNoX-Control.ps1 -Action patch-check

PROFESSIONAL FEATURES NOW AVAILABLE:
• Enterprise-grade Windows Update API integration
• Centralized patch management and control  
• Policy enforcement and compliance monitoring
• Real-time installation progress tracking
• Comprehensive audit logging and reporting
• Service troubleshooting and repair tools

For complete documentation, see:
PATCH_MANAGEMENT_DOCUMENTATION.md

"@ -ForegroundColor Green
}

# Professional Patch Management Functions
function Invoke-PatchCheck {
    Write-Log "Checking for available Windows updates..." -Level INFO
    
    try {
        # Load the professional patch management module
        . "scripts\PatchManagement.ps1"
        
        # Initialize patch manager
        $patchManager = Initialize-PatchManager -LogPath "logs\patch_management.log"
        
        # Check for updates
        $updates = Get-AvailableUpdates -PatchManager $patchManager
        
        if ($updates.Success) {
            Write-Log "Found $($updates.UpdateCount) available updates" -Level SUCCESS
            
            if ($updates.UpdateCount -gt 0) {
                Write-Log "Available Updates:" -Level INFO
                foreach ($update in $updates.Updates) {
                    Write-Log "- $($update.Title)" -Level INFO
                    Write-Log "  Size: $($update.MaxDownloadSize) MB, Severity: $($update.MsrcSeverity)" -Level INFO
                }
            } else {
                Write-Log "System is up to date" -Level SUCCESS
            }
        } else {
            Write-Log "Failed to check for updates: $($updates.Error)" -Level ERROR
        }
    }
    catch {
        Write-Log "Exception during update check: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-PatchInstall {
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required for patch installation" -Level ERROR
        return
    }
    
    Write-Log "Installing Windows updates..." -Level INFO
    
    if (-not $Force) {
        $confirmation = Read-Host "This will install all available updates and may require a reboot. Continue? (y/N)"
        if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
            Write-Log "Installation cancelled by user" -Level WARN
            return
        }
    }
    
    try {
        # Load the professional patch management module
        . "scripts\PatchManagement.ps1"
        
        # Initialize patch manager
        $patchManager = Initialize-PatchManager -LogPath "logs\patch_management.log"
        
        # Install updates
        $result = Install-Updates -PatchManager $patchManager
        
        if ($result.Success) {
            Write-Log "Update installation completed successfully" -Level SUCCESS
            Write-Log "Updates installed: $($result.UpdatesInstalled)" -Level INFO
            Write-Log "Updates failed: $($result.UpdatesFailed)" -Level INFO
            
            if ($result.RebootRequired) {
                Write-Log "SYSTEM RESTART REQUIRED to complete installation!" -Level WARN
            }
        } else {
            Write-Log "Update installation failed: $($result.Error)" -Level ERROR
        }
    }
    catch {
        Write-Log "Exception during update installation: $($_.Exception.Message)" -Level ERROR
    }
}

function Invoke-PatchPolicyEnforcement {
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required for policy enforcement" -Level ERROR
        return
    }
    
    Write-Log "Enforcing Windows Update policies..." -Level INFO
    
    if (-not $Force) {
        $confirmation = Read-Host "This will block manual Windows updates and enforce centralized control. Continue? (y/N)"
        if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
            Write-Log "Policy enforcement cancelled by user" -Level WARN
            return
        }
    }
    
    try {
        # Load the professional patch management module
        . "scripts\PatchManagement.ps1"
        
        # Initialize patch manager
        $patchManager = Initialize-PatchManager -LogPath "logs\patch_management.log"
        
        # Enforce policies
        $result = Set-UpdatePolicies -PatchManager $patchManager
        
        if ($result.Success) {
            Write-Log "Windows Update policies enforced successfully" -Level SUCCESS
            Write-Log "Policy changes applied:" -Level INFO
            foreach ($change in $result.Results) {
                Write-Log "- $change" -Level INFO
            }
        } else {
            Write-Log "Policy enforcement failed: $($result.Error)" -Level ERROR
        }
    }
    catch {
        Write-Log "Exception during policy enforcement: $($_.Exception.Message)" -Level ERROR
    }
}

function Test-PatchCompliance {
    Write-Log "Checking Windows Update policy compliance..." -Level INFO
    
    try {
        # Load the professional patch management module
        . "scripts\PatchManagement.ps1"
        
        # Initialize patch manager
        $patchManager = Initialize-PatchManager -LogPath "logs\patch_management.log"
        
        # Check compliance
        $result = Test-UpdateCompliance -PatchManager $patchManager
        
        if ($result.Success) {
            Write-Log "Compliance check completed" -Level SUCCESS
            Write-Log "Overall compliance: $($result.OverallCompliance)" -Level INFO
            Write-Log "Compliance percentage: $($result.CompliancePercentage)%" -Level INFO
            
            Write-Log "Policy compliance details:" -Level INFO
            foreach ($policy in $result.ComplianceDetails) {
                $status = if ($policy.IsCompliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
                $color = if ($policy.IsCompliant) { "SUCCESS" } else { "ERROR" }
                Write-Log "- $($policy.PolicyName): $status (Expected: $($policy.ExpectedValue), Actual: $($policy.ActualValue))" -Level $color
            }
        } else {
            Write-Log "Compliance check failed: $($result.Error)" -Level ERROR
        }
    }
    catch {
        Write-Log "Exception during compliance check: $($_.Exception.Message)" -Level ERROR
    }
}

function Reset-PatchService {
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required for service reset" -Level ERROR
        return
    }
    
    Write-Log "Resetting Windows Update service..." -Level INFO
    
    try {
        # Load the professional patch management module
        . "scripts\PatchManagement.ps1"
        
        # Initialize patch manager
        $patchManager = Initialize-PatchManager -LogPath "logs\patch_management.log"
        
        # Reset service and clear cache
        $serviceResult = Reset-WindowsUpdateService -PatchManager $patchManager
        $cacheResult = Clear-WindowsUpdateCache -PatchManager $patchManager
        
        if ($serviceResult.Success -and $cacheResult.Success) {
            Write-Log "Windows Update service reset and cache cleared successfully" -Level SUCCESS
        } elseif ($serviceResult.Success) {
            Write-Log "Windows Update service reset successfully, but cache clearing had issues" -Level WARN
        } elseif ($cacheResult.Success) {
            Write-Log "Cache cleared successfully, but service reset had issues" -Level WARN
        } else {
            Write-Log "Failed to reset service and clear cache" -Level ERROR
        }
    }
    catch {
        Write-Log "Exception during service reset: $($_.Exception.Message)" -Level ERROR
    }
}

}

# Main execution
function Main {
    Write-Log "RiskNoX Security Agent Control Script v1.0.0" -Level INFO
    Write-Log "Action: $Action" -Level INFO
    
    # Change to script directory
    Set-Location $Script:Config.RootPath
    
    switch ($Action.ToLower()) {
        'start' {
            if (-not (Test-Dependencies)) { return }
            
            # Check if patch management is set up
            $patchModulePath = "scripts\PatchManagement.ps1"
            $patchConfigPath = "config\patch_config.json"
            
            if ((Test-Path $patchModulePath) -and -not (Test-Path $patchConfigPath)) {
                Write-Log "Professional patch management module detected but not configured" -Level WARN
                $setupChoice = Read-Host "Would you like to set up patch management now? (Y/n)"
                if ($setupChoice -ne 'n') {
                    Write-Log "Running patch management setup..." -Level INFO
                    Invoke-PatchManagementSetup
                    Write-Log "Continuing with service startup..." -Level INFO
                }
            }
            
            Start-Backend -ShowLogs
        }
        
        'stop' {
            Stop-Backend
        }
        
        'restart' {
            if (-not (Test-Dependencies)) { return }
            Stop-Backend
            Start-Sleep -Seconds 2
            Start-Backend -ShowLogs
        }
        
        'status' {
            Get-ServiceStatus
        }
        
        'scan' {
            if (-not $Path) {
                Write-Log "Path parameter is required for scan action" -Level ERROR
                Write-Log "Usage: .\RiskNoX-Control.ps1 -Action scan -Path 'C:\Path\To\Scan'" -Level INFO
                return
            }
            Invoke-AntivirusScan -ScanPath $Path
        }
        
        'block' {
            if (-not $Url) {
                Write-Log "Url parameter is required for block action" -Level ERROR
                Write-Log "Usage: .\RiskNoX-Control.ps1 -Action block -Url 'example.com'" -Level INFO
                return
            }
            Block-WebUrl -UrlToBlock $Url
        }
        
        'unblock' {
            if (-not $Url) {
                Write-Log "Url parameter is required for unblock action" -Level ERROR
                Write-Log "Usage: .\RiskNoX-Control.ps1 -Action unblock -Url 'example.com'" -Level INFO
                return
            }
            Unblock-WebUrl -UrlToUnblock $Url
        }
        
        'update' {
            Update-AntivirusDatabase
        }
        
        'patch-check' {
            Invoke-PatchCheck
        }
        
        'patch-install' {
            Invoke-PatchInstall
        }
        
        'patch-enforce' {
            Invoke-PatchPolicyEnforcement
        }
        
        'patch-compliance' {
            Test-PatchCompliance
        }
        
        'patch-reset' {
            Reset-PatchService
        }
        
        'patch-setup' {
            Invoke-PatchManagementSetup
        }
        
        'help' {
            Show-Help
        }
        
        default {
            Write-Log "Unknown action: $Action" -Level ERROR
            Show-Help
        }
    }
    
    Write-Log "Operation completed" -Level INFO
}

# Execute main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}