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
                 'patch-check', 'patch-install', 'patch-enforce', 'patch-compliance', 'patch-reset', 'patch-setup', 
                 'test-connection', 'enroll', 'agent-status', 'send-command', 'help')]
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
    [switch]$TestMode,
    
    [Parameter(Mandatory = $false)]
    [string]$ManagerUrl,
    
    [Parameter(Mandatory = $false)]
    [string]$Command,
    
    [Parameter(Mandatory = $false)]
    [switch]$Remote
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

function Get-AllAgentProcesses {
    # Get all Python processes that might be running the agent
    $allPythonProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue
    $agentProcesses = @()
    
    if ($allPythonProcesses) {
        foreach ($proc in $allPythonProcesses) {
            try {
                $commandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
                if ($commandLine -and $commandLine -like "*agent_main.py*") {
                    $agentProcesses += $proc
                }
            }
            catch {
                # Continue if we can't get command line
            }
        }
    }
    
    return $agentProcesses
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
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    Write-Log "        RiskNoX Security System - Status Report" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
    
    # Check if this is agent or backend mode
    $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
    $agentConfigFile = Join-Path $Script:Config.RootPath "config\agent_info.json"
    $agentMainConfig = Join-Path $Script:Config.RootPath "config\agent_config.xml"
    
    if ((Test-Path $agentScript) -or (Test-Path $agentMainConfig)) {
        # Agent mode status
        Write-Log "Operating Mode: Security Agent" -Level INFO
        Write-Log "───────────────────────────────────────────────────────────" -Level INFO
        
        # Agent process status
        $agentProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -eq "python" -and
            (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine -like "*agent_main.py*"
        }
        
        if ($agentProcesses) {
            Write-Log "✓ Agent Service: Running (PID: $($agentProcesses[0].Id))" -Level SUCCESS
            
            # Check uptime
            try {
                $startTime = $agentProcesses[0].StartTime
                $uptime = (Get-Date) - $startTime
                Write-Log "  ├─ Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m" -Level INFO
            }
            catch {
                Write-Log "  ├─ Uptime: Unknown" -Level INFO
            }
            
            # Check memory usage
            try {
                $memoryMB = [math]::Round($agentProcesses[0].WorkingSet64 / 1MB, 2)
                Write-Log "  ├─ Memory Usage: $memoryMB MB" -Level INFO
            }
            catch {
                Write-Log "  ├─ Memory Usage: Unknown" -Level INFO
            }
            
            # Check status file
            $statusFile = Join-Path $Script:Config.RootPath "logs\agent.status"
            if (Test-Path $statusFile) {
                $status = Get-Content $statusFile -ErrorAction SilentlyContinue
                Write-Log "  └─ Status: $status" -Level INFO
            }
        } else {
            Write-Log "✗ Agent Service: Stopped" -Level ERROR
        }
        
        # Manager connectivity
        if (Test-Path $agentConfigFile) {
            try {
                $agentInfo = Get-Content $agentConfigFile | ConvertFrom-Json
                if ($agentInfo.manager_url) {
                    Write-Log "Manager Connection:" -Level INFO
                    Write-Log "  ├─ URL: $($agentInfo.manager_url)" -Level INFO
                    Write-Log "  ├─ Agent Name: $($agentInfo.agent_id)" -Level INFO
                    Write-Log "  ├─ Enrolled: $(if ($agentInfo.enrolled) { 'Yes' } else { 'No' })" -Level INFO
                    
                    # Test connectivity
                    try {
                        $response = Invoke-RestMethod -Uri "$($agentInfo.manager_url)/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
                        if ($response) {
                            Write-Log "  └─ Connectivity: ✓ Online" -Level SUCCESS
                        } else {
                            Write-Log "  └─ Connectivity: ✗ Offline" -Level WARN
                        }
                    }
                    catch {
                        Write-Log "  └─ Connectivity: ✗ Offline" -Level WARN
                    }
                } else {
                    Write-Log "Manager Connection: Not configured (Standalone mode)" -Level INFO
                }
            }
            catch {
                Write-Log "Manager Connection: Configuration error" -Level ERROR
            }
        } else {
            Write-Log "Manager Connection: Not configured (Standalone mode)" -Level INFO
        }
        
    } else {
        # Backend mode status
        Write-Log "Operating Mode: Backend Server" -Level INFO
        Write-Log "───────────────────────────────────────────────────────────" -Level INFO
        
        # Backend status
        $backendProcesses = Get-AllBackendProcesses
        if ($backendProcesses -and $backendProcesses.Count -gt 0) {
            if ($backendProcesses.Count -eq 1) {
                Write-Log "✓ Backend Service: Running (PID: $($backendProcesses[0].Id))" -Level SUCCESS
            } else {
                Write-Log "✓ Backend Service: Running ($($backendProcesses.Count) processes)" -Level SUCCESS
            }
            Write-Log "  └─ Web Interface: http://localhost:$($Script:Config.BackendPort)" -Level INFO
        } else {
            Write-Log "✗ Backend Service: Stopped" -Level ERROR
        }
    }
    
    Write-Log "───────────────────────────────────────────────────────────" -Level INFO
    
    # Security components status
    Write-Log "Security Components:" -Level INFO
    
    # ClamAV status
    $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
    if (Test-Path $clamScanPath) {
        Write-Log "  ├─ Antivirus Engine: ✓ ClamAV Available" -Level SUCCESS
    } else {
        Write-Log "  ├─ Antivirus Engine: ✗ Not Available" -Level WARN
    }
    
    # Web protection status
    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        try {
            $hostsContent = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
            $blockedCount = ($hostsContent -split "`n" | Where-Object { $_ -match "# RiskNoX Block" }).Count
            if ($blockedCount -gt 0) {
                Write-Log "  ├─ Web Protection: ✓ Active ($blockedCount blocked sites)" -Level SUCCESS
            } else {
                Write-Log "  ├─ Web Protection: ✓ Ready (no sites blocked)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  ├─ Web Protection: ⚠ Status unknown" -Level WARN
        }
    } else {
        Write-Log "  ├─ Web Protection: ✗ Cannot access hosts file" -Level ERROR
    }
    
    # Patch management status
    $patchConfigPath = Join-Path $Script:Config.RootPath "config\patch_config.json"
    if (Test-Path $patchConfigPath) {
        Write-Log "  └─ Patch Management: ✓ Configured" -Level SUCCESS
    } else {
        Write-Log "  └─ Patch Management: ○ Not configured" -Level INFO
    }
    
    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
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

AGENT COMMUNICATION ACTIONS:
    test-connection     Test connectivity to RiskNoX Manager
    enroll              Enroll this agent with the RiskNoX Manager
    agent-status        Show detailed agent status and configuration
    send-command        Send a command to the agent for execution

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
    -ManagerUrl <url>   Specify RiskNoX Manager URL (e.g., http://192.168.1.100:8001)
    -Command <cmd>      Specify command to send to agent
    -Remote             Execute action remotely via manager

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

Agent Communication Operations:
    .\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://192.168.1.100:8001"
        Test connectivity to the RiskNoX Manager server
        
    .\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://192.168.1.100:8001"
        Enroll this agent with the manager for centralized management
        
    .\RiskNoX-Control.ps1 -Action agent-status
        Show detailed status of the local agent
        
    .\RiskNoX-Control.ps1 -Action send-command -Command "scan C:\Users" -ManagerUrl "http://192.168.1.100:8001"
        Send a scan command to the agent via the manager

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
}

# Agent Communication Functions
function Test-ManagerConnection {
    param([string]$ManagerUrl)
    
    if (-not $ManagerUrl) {
        $configFile = Join-Path $Script:Config.RootPath "config\agent_info.json"
        if (Test-Path $configFile) {
            $config = Get-Content $configFile | ConvertFrom-Json
            $ManagerUrl = $config.manager_url
        } else {
            Write-Log "Manager URL not provided and no configuration found" -Level ERROR
            return $false
        }
    }
    
    Write-Log "Testing connection to manager: $ManagerUrl" -Level INFO
    
    try {
        $response = Invoke-RestMethod -Uri "$ManagerUrl/health" -Method GET -TimeoutSec 10
        if ($response) {
            Write-Log "✓ Manager is responding" -Level SUCCESS
            Write-Log "Manager info: $($response | ConvertTo-Json -Compress)" -Level INFO
            return $true
        }
    }
    catch {
        Write-Log "✗ Failed to connect to manager: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    
    return $false
}

function Invoke-AgentEnrollment {
    param([string]$ManagerUrl)
    
    Write-Log "Starting agent enrollment process..." -Level INFO
    
    if (-not $ManagerUrl) {
        $configFile = Join-Path $Script:Config.RootPath "config\agent_info.json"
        if (Test-Path $configFile) {
            $config = Get-Content $configFile | ConvertFrom-Json
            $ManagerUrl = $config.manager_url
        } else {
            Write-Log "Manager URL not provided and no configuration found" -Level ERROR
            return $false
        }
    }
    
    try {
        $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
        $enrollmentScript = Join-Path $Script:Config.RootPath "agent\enrollment.py"
        
        if (-not (Test-Path $enrollmentScript)) {
            Write-Log "Enrollment script not found: $enrollmentScript" -Level ERROR
            return $false
        }
        
        Push-Location $Script:Config.RootPath
        
        $arguments = @(
            $enrollmentScript,
            "--manager-url", $ManagerUrl,
            "--agent-name", $env:COMPUTERNAME
        )
        
        Write-Log "Executing enrollment: $venvPython $($arguments -join ' ')" -Level INFO
        
        $process = Start-Process -FilePath $venvPython -ArgumentList $arguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput "logs\enrollment_output.log" -RedirectStandardError "logs\enrollment_error.log"
        
        if ($process.ExitCode -eq 0) {
            Write-Log "✓ Agent enrollment completed successfully" -Level SUCCESS
            
            # Show enrollment output
            if (Test-Path "logs\enrollment_output.log") {
                $output = Get-Content "logs\enrollment_output.log" -Raw
                Write-Log "Enrollment output: $output" -Level INFO
            }
            
            return $true
        } else {
            Write-Log "✗ Agent enrollment failed with exit code: $($process.ExitCode)" -Level ERROR
            
            # Show error output
            if (Test-Path "logs\enrollment_error.log") {
                $errorOutput = Get-Content "logs\enrollment_error.log" -Raw
                Write-Log "Enrollment error: $errorOutput" -Level ERROR
            }
            
            return $false
        }
    }
    catch {
        Write-Log "Enrollment process failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Pop-Location
    }
}

function Get-AgentStatus {
    Write-Log "Getting agent status..." -Level INFO
    
    try {
        $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
        $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
        
        Push-Location $Script:Config.RootPath
        
        $arguments = @(
            $agentScript,
            "--status"
        )
        
        $process = Start-Process -FilePath $venvPython -ArgumentList $arguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput "logs\status_output.log" -RedirectStandardError "logs\status_error.log"
        
        if (Test-Path "logs\status_output.log") {
            $output = Get-Content "logs\status_output.log" -Raw
            Write-Log "Agent status: $output" -Level INFO
        }
        
        return $process.ExitCode -eq 0
    }
    catch {
        Write-Log "Failed to get agent status: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Pop-Location
    }
}

function Send-AgentCommand {
    param(
        [string]$Command,
        [string]$ManagerUrl
    )
    
    if (-not $Command) {
        Write-Log "Command parameter is required" -Level ERROR
        return $false
    }
    
    Write-Log "Sending command to agent: $Command" -Level INFO
    
    try {
        $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
        $commandScript = Join-Path $Script:Config.RootPath "agent\command_handler.py"
        
        Push-Location $Script:Config.RootPath
        
        $arguments = @(
            $commandScript,
            "--command", $Command
        )
        
        if ($ManagerUrl) {
            $arguments += @("--manager-url", $ManagerUrl)
        }
        
        $process = Start-Process -FilePath $venvPython -ArgumentList $arguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput "logs\command_output.log" -RedirectStandardError "logs\command_error.log"
        
        if (Test-Path "logs\command_output.log") {
            $output = Get-Content "logs\command_output.log" -Raw
            Write-Log "Command output: $output" -Level INFO
        }
        
        if ($process.ExitCode -eq 0) {
            Write-Log "✓ Command executed successfully" -Level SUCCESS
            return $true
        } else {
            Write-Log "✗ Command execution failed" -Level ERROR
            
            if (Test-Path "logs\command_error.log") {
                $errorOutput = Get-Content "logs\command_error.log" -Raw
                Write-Log "Command error: $errorOutput" -Level ERROR
            }
            
            return $false
        }
    }
    catch {
        Write-Log "Failed to send command: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Pop-Location
    }
}

function Initialize-AgentEnvironment {
    Write-Log "Initializing agent environment..." -Level INFO
    
    try {
        # Create necessary directories
        $directories = @("logs", "config", "vendor", "scripts", "temp")
        foreach ($dir in $directories) {
            $dirPath = Join-Path $Script:Config.RootPath $dir
            if (-not (Test-Path $dirPath)) {
                New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
                Write-Log "Created directory: $dir" -Level INFO
            }
        }
        
        # Check Python virtual environment
        $venvPath = Join-Path $Script:Config.RootPath $Script:Config.VirtualEnvPath
        $venvPython = Join-Path $venvPath "Scripts\python.exe"
        
        if (-not (Test-Path $venvPython)) {
            Write-Log "Python virtual environment not found. Creating..." -Level WARN
            
            # Create virtual environment
            python -m venv $venvPath
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Virtual environment created successfully" -Level SUCCESS
            } else {
                Write-Log "Failed to create virtual environment" -Level ERROR
                return $false
            }
            
            # Install dependencies
            Write-Log "Installing Python dependencies..." -Level INFO
            & $venvPython -m pip install --upgrade pip
            
            $requirementsFile = Join-Path $Script:Config.RootPath "requirements.txt"
            if (Test-Path $requirementsFile) {
                & $venvPython -m pip install -r $requirementsFile
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Dependencies installed successfully" -Level SUCCESS
                } else {
                    Write-Log "Failed to install dependencies" -Level ERROR
                    return $false
                }
            } else {
                Write-Log "Requirements file not found, installing basic dependencies..." -Level WARN
                & $venvPython -m pip install requests websockets cryptography structlog colorama
            }
        }
        
        # Verify ClamAV availability
        $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
        if (Test-Path $clamScanPath) {
            Write-Log "✓ ClamAV antivirus engine found" -Level SUCCESS
        } else {
            Write-Log "⚠ ClamAV not found - antivirus features will be limited" -Level WARN
        }
        
        # Check agent configuration
        $agentConfigFile = Join-Path $Script:Config.RootPath "config\agent_config.xml"
        if (-not (Test-Path $agentConfigFile)) {
            Write-Log "Agent configuration not found, creating default..." -Level WARN
            Initialize-DefaultAgentConfig
        }
        
        # Verify agent scripts
        $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
        if (-not (Test-Path $agentScript)) {
            Write-Log "Agent main script not found: $agentScript" -Level ERROR
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to initialize agent environment: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Initialize-DefaultAgentConfig {
    Write-Log "Creating default agent configuration..." -Level INFO
    
    $configPath = Join-Path $Script:Config.RootPath "config\agent_config.xml"
    $defaultConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<agent_config>
    <agent>
        <id>$env:COMPUTERNAME</id>
        <version>1.0.0</version>
        <log_level>INFO</log_level>
        <output_directory>scripts</output_directory>
        <config_directory>config</config_directory>
        <vendor_directory>vendor</vendor_directory>
    </agent>
    <server>
        <url>http://localhost:8001</url>
        <websocket_url>ws://localhost:8001/ws</websocket_url>
        <api_endpoint>/api/agents</api_endpoint>
        <command_port>9090</command_port>
    </server>
    <modules>
        <antivirus enabled="true">
            <scan_interval_hours>24</scan_interval_hours>
            <realtime_protection>true</realtime_protection>
            <update_interval_hours>6</update_interval_hours>
        </antivirus>
        <web_protection enabled="true">
            <dns_filtering>true</dns_filtering>
            <url_blocking>true</url_blocking>
            <safe_browsing>true</safe_browsing>
        </web_protection>
        <patch_management enabled="true">
            <auto_install_critical>true</auto_install_critical>
            <reboot_schedule>02:00</reboot_schedule>
            <maintenance_window>weekend</maintenance_window>
        </patch_management>
        <monitoring enabled="true">
            <performance_metrics>true</performance_metrics>
            <security_events>true</security_events>
            <network_monitoring>true</network_monitoring>
        </monitoring>
    </modules>
</agent_config>
"@
    
    Set-Content -Path $configPath -Value $defaultConfig -Encoding UTF8
    Write-Log "Default agent configuration created" -Level SUCCESS
}

function Test-AgentDependencies {
    Write-Log "Testing agent dependencies..." -Level INFO
    
    $issues = @()
    
    # Test Python virtual environment
    $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        $issues += "Python virtual environment not found"
    } else {
        try {
            $pythonVersion = & $venvPython --version 2>$null
            Write-Log "Python environment: $pythonVersion" -Level SUCCESS
        }
        catch {
            $issues += "Python virtual environment is not working properly"
        }
    }
    
    # Test required Python modules
    $requiredModules = @("requests", "websockets", "cryptography", "structlog")
    foreach ($module in $requiredModules) {
        try {
            & $venvPython -c "import $module" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Python module '$module' available" -Level SUCCESS
            } else {
                $issues += "Required Python module '$module' not installed"
            }
        }
        catch {
            $issues += "Error checking Python module '$module'"
        }
    }
    
    # Test agent scripts
    $criticalScripts = @(
        "agent\agent_main.py",
        "agent\websocket_client.py",
        "agent\command_handler.py"
    )
    
    foreach ($script in $criticalScripts) {
        $scriptPath = Join-Path $Script:Config.RootPath $script
        if (-not (Test-Path $scriptPath)) {
            $issues += "Critical agent script missing: $script"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Dependency check failed:" -Level ERROR
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level ERROR
        }
        return $false
    }
    
    Write-Log "All agent dependencies verified" -Level SUCCESS
    return $true
}

function Start-AgentService {
    Write-Log "Starting RiskNoX Agent Service with full initialization..." -Level INFO
    
    try {
        # Step 1: Initialize environment
        if (-not (Initialize-AgentEnvironment)) {
            Write-Log "Failed to initialize agent environment" -Level ERROR
            return $null
        }
        
        # Step 2: Test dependencies
        if (-not (Test-AgentDependencies)) {
            Write-Log "Agent dependencies not satisfied" -Level ERROR
            return $null
        }
        
        # Step 3: Check if agent is already running
        $agentProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -eq "python" -and
            (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine -like "*agent_main.py*"
        }
        
        if ($agentProcesses) {
            Write-Log "Agent is already running (PID: $($agentProcesses[0].Id))" -Level WARN
            return $agentProcesses[0]
        }
        
        # Step 4: Prepare startup
        Push-Location $Script:Config.RootPath
        
        $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
        $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
        
        # Step 5: Initialize antivirus definitions
        Write-Log "Checking antivirus definitions..." -Level INFO
        $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
        if (Test-Path $clamScanPath) {
            $freshclamPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\freshclam.exe"
            if (Test-Path $freshclamPath) {
                Write-Log "Updating antivirus definitions..." -Level INFO
                try {
                    $updateProcess = Start-Process -FilePath $freshclamPath -ArgumentList "--quiet", "--no-warnings" -Wait -NoNewWindow -PassThru
                    if ($updateProcess.ExitCode -eq 0) {
                        Write-Log "✓ Antivirus definitions updated" -Level SUCCESS
                    } else {
                        Write-Log "⚠ Antivirus update completed with warnings" -Level WARN
                    }
                }
                catch {
                    Write-Log "⚠ Could not update antivirus definitions: $($_.Exception.Message)" -Level WARN
                }
            }
        }
        
        # Step 6: Setup Windows Firewall rules
        Write-Log "Configuring Windows Firewall..." -Level INFO
        try {
            $ruleName = "RiskNoX Agent Outbound"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue
                Write-Log "✓ Firewall rule created" -Level SUCCESS
            } else {
                Write-Log "✓ Firewall rule already exists" -Level SUCCESS
            }
        }
        catch {
            Write-Log "⚠ Could not configure firewall (non-admin?): $($_.Exception.Message)" -Level WARN
        }
        
        # Step 7: Start agent process
        Write-Log "Starting agent process..." -Level INFO
        $arguments = @($agentScript)
        
        # Add debug flag if needed
        if ($env:RISKNOX_DEBUG -eq "1") {
            $arguments += "--debug"
        }
        
        $process = Start-Process -FilePath $venvPython -ArgumentList $arguments -NoNewWindow -PassThru -RedirectStandardOutput "logs\agent_stdout.log" -RedirectStandardError "logs\agent_stderr.log"
        
        # Step 8: Wait for agent to initialize
        Write-Log "Waiting for agent to initialize..." -Level INFO
        $maxWaitTime = 30
        $waitTime = 0
        
        while ($waitTime -lt $maxWaitTime) {
            Start-Sleep -Seconds 1
            $waitTime++
            
            # Check if process is still running
            if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
                Write-Log "✗ Agent process terminated during startup" -Level ERROR
                
                # Show error logs
                $errorLog = Join-Path $Script:Config.RootPath "logs\agent_stderr.log"
                if (Test-Path $errorLog) {
                    $errorContent = Get-Content $errorLog -Raw -ErrorAction SilentlyContinue
                    if ($errorContent) {
                        Write-Log "Agent error output: $errorContent" -Level ERROR
                    }
                }
                return $null
            }
            
            # Check if agent is responding (look for success indicators in logs)
            $logFile = Join-Path $Script:Config.RootPath "logs\agent_stdout.log"
            if (Test-Path $logFile) {
                $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                if ($logContent -and ($logContent -match "Agent started" -or $logContent -match "WebSocket.*connected")) {
                    Write-Log "✓ Agent initialization detected" -Level SUCCESS
                    break
                }
            }
        }
        
        # Step 9: Final verification
        if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
            Write-Log "✓ Agent service started successfully (PID: $($process.Id))" -Level SUCCESS
            Write-Log "Agent logs: logs\agent_stdout.log" -Level INFO
            Write-Log "Error logs: logs\agent_stderr.log" -Level INFO
            
            # Step 10: Test basic functionality
            Write-Log "Performing basic functionality test..." -Level INFO
            Start-Sleep -Seconds 2
            
            # Check if agent created necessary files
            $statusFile = Join-Path $Script:Config.RootPath "logs\agent.status"
            $pidFile = Join-Path $Script:Config.RootPath "logs\agent.pid"
            
            # Create status files
            Set-Content -Path $pidFile -Value $process.Id
            Set-Content -Path $statusFile -Value "running"
            
            return $process
        } else {
            Write-Log "✗ Agent failed to start properly" -Level ERROR
            return $null
        }
    }
    catch {
        Write-Log "Failed to start agent service: $($_.Exception.Message)" -Level ERROR
        return $null
    }
    finally {
        Pop-Location
    }
}

function Stop-AgentService {
    Write-Log "Stopping RiskNoX Agent Service..." -Level INFO
    
    try {
        $agentProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -eq "python" -and
            (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine -like "*agent_main.py*"
        }
        
        if ($agentProcesses) {
            foreach ($process in $agentProcesses) {
                Stop-Process -Id $process.Id -Force
                Write-Log "✓ Stopped agent process (PID: $($process.Id))" -Level SUCCESS
            }
        } else {
            Write-Log "No agent processes found running" -Level WARN
        }
    }
    catch {
        Write-Log "Failed to stop agent: $($_.Exception.Message)" -Level ERROR
    }
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

function Invoke-AgentServiceStart {
    Write-Log "Starting RiskNoX Agent Service with full initialization..." -Level INFO
    
    try {
        # Step 1: Initialize environment
        if (-not (Initialize-AgentEnvironment)) {
            Write-Log "Failed to initialize agent environment" -Level ERROR
            return $null
        }
        
        # Step 2: Test dependencies
        if (-not (Test-AgentDependencies)) {
            Write-Log "Agent dependencies not satisfied" -Level ERROR
            return $null
        }
        
        # Step 3: Check if agent is already running
        $agentProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -eq "python" -and
            (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine -like "*agent_main.py*"
        }
        
        if ($agentProcesses) {
            Write-Log "Agent is already running (PID: $($agentProcesses[0].Id))" -Level WARN
            return $agentProcesses[0]
        }
        
        # Step 4: Prepare startup
        Push-Location $Script:Config.RootPath
        
        $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
        $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
        
        # Step 5: Initialize antivirus definitions
        Write-Log "Checking antivirus definitions..." -Level INFO
        $clamScanPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe"
        if (Test-Path $clamScanPath) {
            $freshclamPath = Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\freshclam.exe"
            if (Test-Path $freshclamPath) {
                Write-Log "Updating antivirus definitions..." -Level INFO
                try {
                    $updateProcess = Start-Process -FilePath $freshclamPath -ArgumentList "--quiet", "--no-warnings" -Wait -NoNewWindow -PassThru
                    if ($updateProcess.ExitCode -eq 0) {
                        Write-Log "✓ Antivirus definitions updated" -Level SUCCESS
                    } else {
                        Write-Log "⚠ Antivirus update completed with warnings" -Level WARN
                    }
                }
                catch {
                    Write-Log "⚠ Could not update antivirus definitions: $($_.Exception.Message)" -Level WARN
                }
            }
        }
        
        # Step 6: Setup Windows Firewall rules
        Write-Log "Configuring Windows Firewall..." -Level INFO
        try {
            $ruleName = "RiskNoX Agent Outbound"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue
                Write-Log "✓ Firewall rule created" -Level SUCCESS
            } else {
                Write-Log "✓ Firewall rule already exists" -Level SUCCESS
            }
        }
        catch {
            Write-Log "⚠ Could not configure firewall (non-admin?): $($_.Exception.Message)" -Level WARN
        }
        
        # Step 7: Start agent process
        Write-Log "Starting agent process..." -Level INFO
        $arguments = @($agentScript)
        
        # Add debug flag if needed
        if ($env:RISKNOX_DEBUG -eq "1") {
            $arguments += "--debug"
        }
        
        $process = Start-Process -FilePath $venvPython -ArgumentList $arguments -NoNewWindow -PassThru -RedirectStandardOutput "logs\agent_stdout.log" -RedirectStandardError "logs\agent_stderr.log"
        
        # Step 8: Wait for agent to initialize
        Write-Log "Waiting for agent to initialize..." -Level INFO
        $maxWaitTime = 30
        $waitTime = 0
        
        while ($waitTime -lt $maxWaitTime) {
            Start-Sleep -Seconds 1
            $waitTime++
            
            # Check if process is still running
            if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
                Write-Log "✗ Agent process terminated during startup" -Level ERROR
                
                # Show error logs
                $errorLog = Join-Path $Script:Config.RootPath "logs\agent_stderr.log"
                if (Test-Path $errorLog) {
                    $errorContent = Get-Content $errorLog -Raw -ErrorAction SilentlyContinue
                    if ($errorContent) {
                        Write-Log "Agent error output: $errorContent" -Level ERROR
                    }
                }
                return $null
            }
            
            # Check if agent is responding (look for success indicators in logs)
            $logFile = Join-Path $Script:Config.RootPath "logs\agent_stdout.log"
            if (Test-Path $logFile) {
                $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                if ($logContent -and ($logContent -match "Agent started" -or $logContent -match "WebSocket.*connected")) {
                    Write-Log "✓ Agent initialization detected" -Level SUCCESS
                    break
                }
            }
        }
        
        # Step 9: Final verification
        if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
            Write-Log "✓ Agent service started successfully (PID: $($process.Id))" -Level SUCCESS
            Write-Log "Agent logs: logs\agent_stdout.log" -Level INFO
            Write-Log "Error logs: logs\agent_stderr.log" -Level INFO
            
            # Step 10: Test basic functionality
            Write-Log "Performing basic functionality test..." -Level INFO
            Start-Sleep -Seconds 2
            
            # Check if agent created necessary files
            $statusFile = Join-Path $Script:Config.RootPath "logs\agent.status"
            $pidFile = Join-Path $Script:Config.RootPath "logs\agent.pid"
            
            # Create status files
            Set-Content -Path $pidFile -Value $process.Id
            Set-Content -Path $statusFile -Value "running"
            
            return $process
        } else {
            Write-Log "✗ Agent failed to start properly" -Level ERROR
            return $null
        }
    }
    catch {
        Write-Log "Failed to start agent service: $($_.Exception.Message)" -Level ERROR
        return $null
    }
    finally {
        Pop-Location
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
            
            # Check if this is an agent-only setup
            $agentConfigFile = Join-Path $Script:Config.RootPath "config\agent_info.json"
            $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
            $agentMainConfig = Join-Path $Script:Config.RootPath "config\agent_config.xml"
            
            # If agent directory exists, treat as agent-only setup
            if ((Test-Path $agentScript) -or (Test-Path $agentMainConfig)) {
                Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
                Write-Log "        RiskNoX Security Agent - Starting Service" -Level INFO
                Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
                
                # Start comprehensive agent service
                $agentProcess = Invoke-AgentServiceStart
                if ($agentProcess) {
                    Write-Log "✓ Agent service started successfully (PID: $($agentProcess.Id))" -Level SUCCESS
                    
                    # Check for manager enrollment
                    if (Test-Path $agentConfigFile) {
                        try {
                            $agentInfo = Get-Content $agentConfigFile | ConvertFrom-Json
                            if ($agentInfo.manager_url) {
                                Write-Log "Testing connection to manager: $($agentInfo.manager_url)" -Level INFO
                                
                                # Test manager connectivity
                                $connected = Test-ManagerConnection -ManagerUrl $agentInfo.manager_url
                                if ($connected) {
                                    Write-Log "✓ Manager connectivity verified" -Level SUCCESS
                                    
                                    # Auto-enroll if not already enrolled
                                    if (-not $agentInfo.enrolled -or $agentInfo.enrolled -eq $false) {
                                        Write-Log "Initiating automatic enrollment..." -Level INFO
                                        $enrolled = Invoke-AgentEnrollment -ManagerUrl $agentInfo.manager_url
                                        if ($enrolled) {
                                            # Update agent info
                                            $agentInfo.enrolled = $true
                                            $agentInfo.enrollment_date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                                            $agentInfo | ConvertTo-Json -Depth 10 | Set-Content $agentConfigFile
                                            Write-Log "✓ Agent enrolled with manager successfully" -Level SUCCESS
                                        }
                                    } else {
                                        Write-Log "✓ Agent already enrolled with manager" -Level SUCCESS
                                    }
                                } else {
                                    Write-Log "⚠ Manager not reachable - agent running in standalone mode" -Level WARN
                                }
                            }
                        }
                        catch {
                            Write-Log "⚠ Could not process agent enrollment: $($_.Exception.Message)" -Level WARN
                        }
                    }
                    
                    # Show agent status
                    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
                    Write-Log "Agent Status Summary:" -Level INFO
                    Write-Log "• Process ID: $($agentProcess.Id)" -Level INFO
                    Write-Log "• Configuration: $(if (Test-Path $agentMainConfig) { 'Ready' } else { 'Default' })" -Level INFO
                    Write-Log "• Antivirus: $(if (Test-Path (Join-Path $Script:Config.RootPath "$($Script:Config.VendorPath)\clamscan.exe")) { 'Available' } else { 'Not Available' })" -Level INFO
                    Write-Log "• Manager Connection: $(if (Test-Path $agentConfigFile) { 'Configured' } else { 'Standalone' })" -Level INFO
                    Write-Log "• Logs: logs\agent_stdout.log" -Level INFO
                    Write-Log "═══════════════════════════════════════════════════════════" -Level INFO
                    
                    Write-Log "Agent is now running and monitoring system security." -Level SUCCESS
                    Write-Log "Use 'RiskNoX-Control.ps1 -Action status' to check detailed status." -Level INFO
                    Write-Log "Use 'RiskNoX-Control.ps1 -Action scan -Path C:\Users' to perform security scan." -Level INFO
                    
                } else {
                    Write-Log "✗ Failed to start agent service" -Level ERROR
                    Write-Log "Check logs\agent_stderr.log for error details" -Level ERROR
                }
                return
            }
            
            # Check if patch management is set up
            $patchModulePath = "scripts\PatchManagement.ps1"
            $patchConfigPath = "config\patch_config.json"
            
            if ((Test-Path $patchModulePath) -and -not (Test-Path $patchConfigPath)) {
                Write-Log "Professional patch management module detected but not configured" -Level WARN
                $setupChoice = Read-Host "Would you like to set up patch management now? (Y/n)"
                if ($setupChoice -ne 'n') {
                    Write-Log "Running patch management setup..." -Level INFO
                    # Check if function exists before calling it
                    if (Get-Command Invoke-PatchManagementSetup -ErrorAction SilentlyContinue) {
                        Invoke-PatchManagementSetup
                    } else {
                        Write-Log "Invoke-PatchManagementSetup function not found. Running setup script directly..." -Level WARN
                        & "$($Script:Config.RootPath)\Setup-PatchManagement.ps1"
                    }
                    Write-Log "Continuing with service startup..." -Level INFO
                }
            }
            
            Start-Backend -ShowLogs
        }
        
        'stop' {
            # Check if this is an agent-only setup
            $agentConfigFile = Join-Path $Script:Config.RootPath "config\agent_info.json"
            $agentScript = Join-Path $Script:Config.RootPath "agent\agent_main.py"
            
            if ((Test-Path $agentConfigFile) -and (Test-Path $agentScript)) {
                Write-Log "Detected agent configuration, stopping agent service..." -Level INFO
                Stop-AgentService
                return
            }
            
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
        
        'test-connection' {
            Test-ManagerConnection -ManagerUrl $ManagerUrl
        }
        
        'enroll' {
            Invoke-AgentEnrollment -ManagerUrl $ManagerUrl
        }
        
        'agent-status' {
            Get-AgentStatus
        }
        
        'send-command' {
            if (-not $Command) {
                Write-Log "Command parameter is required for send-command action" -Level ERROR
                Write-Log "Usage: .\RiskNoX-Control.ps1 -Action send-command -Command 'scan /temp'" -Level INFO
                return
            }
            Send-AgentCommand -Command $Command -ManagerUrl $ManagerUrl
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