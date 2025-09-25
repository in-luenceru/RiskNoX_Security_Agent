#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Security Agent Control Script
    
.DESCRIPTION
    Unified PowerShell 7 control script for managing RiskNoX Security Agent services.
    Provides easy management of antivirus, web blocking, and patch management features.
    
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
    [ValidateSet('start', 'stop', 'restart', 'status', 'install', 'uninstall', 'scan', 'block', 'unblock', 'update', 'help')]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$Url,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('backend', 'all')]
    [string]$Service = 'all'
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

RiskNoX Security Agent Control Script
====================================

USAGE:
    .\RiskNoX-Control.ps1 -Action <action> [options]

ACTIONS:
    start               Start the security agent backend service
    stop                Stop the security agent backend service  
    restart             Restart the security agent backend service
    status              Show current status of all services
    scan                Perform antivirus scan (requires -Path)
    block               Block a website URL (requires -Url, admin privileges)
    unblock             Unblock a website URL (requires -Url, admin privileges)  
    update              Update antivirus database
    help                Show this help message

EXAMPLES:
    .\RiskNoX-Control.ps1 -Action start
        Start the RiskNoX backend service
        
    .\RiskNoX-Control.ps1 -Action status
        Show current service status
        
    .\RiskNoX-Control.ps1 -Action scan -Path "C:\Users\Username\Downloads"
        Scan Downloads folder for viruses
        
    .\RiskNoX-Control.ps1 -Action block -Url "malicious-site.com"
        Block access to a malicious website
        
    .\RiskNoX-Control.ps1 -Action unblock -Url "safe-site.com"
        Unblock access to a previously blocked website
        
    .\RiskNoX-Control.ps1 -Action update
        Update antivirus virus definitions

NOTES:
    - Web interface will be available at: http://localhost:5000
    - Some operations require administrator privileges
    - Logs are stored in the 'logs' directory
    - Admin credentials: username=admin, password=RiskNoX@2024

"@ -ForegroundColor Cyan
}

function Show-LiveLogs {
    param([int]$ProcessId)
    
    $controlLogFile = Join-Path $Script:Config.LogsPath "control.log"
    
    Write-Log "Monitoring backend logs... Press Ctrl+C to exit" -Level INFO
    Write-Host "`n--- Live Logs ---" -ForegroundColor Yellow
    
    try {
        # Monitor the control log file
        if (Test-Path $controlLogFile) {
            Get-Content $controlLogFile -Tail 10
        }
        
        # Keep monitoring
        while ($true) {
            Start-Sleep -Seconds 1
            
            # Check if process is still running
            if ($ProcessId -and -not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
                Write-Log "Backend process has stopped" -Level WARN
                break
            }
            
            # Show new log entries if the file exists
            if (Test-Path $controlLogFile) {
                $newContent = Get-Content $controlLogFile -Tail 5
                if ($newContent) {
                    $newContent | ForEach-Object {
                        if ($_ -match '\[ERROR\]') {
                            Write-Host $_ -ForegroundColor Red
                        } elseif ($_ -match '\[WARN\]') {
                            Write-Host $_ -ForegroundColor Yellow
                        } elseif ($_ -match '\[SUCCESS\]') {
                            Write-Host $_ -ForegroundColor Green
                        } else {
                            Write-Host $_
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Log monitoring interrupted" -Level INFO
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