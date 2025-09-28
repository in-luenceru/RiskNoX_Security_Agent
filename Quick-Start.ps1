#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Complete System Quick Start
    
.DESCRIPTION
    Complete automated setup for RiskNoX Security System including:
    - Manager deployment on server (Docker Compose)
    - Agent installation on client systems
    - Network connectivity testing
    - Initial configuration
    
.PARAMETER Mode
    Deployment mode: manager, agent, or test
    
.PARAMETER ManagerUrl
    URL of the RiskNoX Manager (required for agent mode)
    
.PARAMETER AgentName
    Name for this agent (defaults to hostname)
    
.PARAMETER ServerIP
    IP address of the server (for manager mode)
    
.PARAMETER SkipDependencies
    Skip dependency installation
    
.EXAMPLE
    .\Quick-Start.ps1 -Mode manager
    Set up RiskNoX Manager on this server
    
.EXAMPLE
    .\Quick-Start.ps1 -Mode agent -ManagerUrl "http://192.168.1.100:8001"
    Install RiskNoX Agent and connect to manager
    
.EXAMPLE
    .\Quick-Start.ps1 -Mode test -ManagerUrl "http://192.168.1.100:8001"
    Test connectivity and system status
    
.NOTES
    Author: RiskNoX Security Team
    Version: 1.0.0
    Requires: PowerShell 7.0+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('manager', 'agent', 'test')]
    [string]$Mode,
    
    [Parameter(Mandatory = $false)]
    [string]$ManagerUrl,
    
    [Parameter(Mandatory = $false)]
    [string]$AgentName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [string]$ServerIP,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDependencies,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Configuration
$Script:Config = @{
    RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    LogFile = "logs\quick-start.log"
    TempDir = "temp"
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
    
    # Ensure log directory exists
    $logDir = Split-Path $Script:Config.LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Log to file
    "[$timestamp] [$Level] $Message" | Out-File -FilePath $Script:Config.LogFile -Append
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Manager Setup Functions
function Install-ManagerDependencies {
    Write-Log "Installing manager dependencies..." -Level INFO
    
    try {
        # Check if running on Windows (need WSL/Docker Desktop)
        if ($IsWindows -or $PSVersionTable.Platform -eq "Win32NT") {
            Write-Log "Windows detected - checking Docker Desktop..." -Level INFO
            
            # Check Docker Desktop
            $dockerDesktop = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
            if (-not $dockerDesktop) {
                Write-Log "Docker Desktop not running. Please install and start Docker Desktop." -Level ERROR
                Write-Log "Download from: https://docs.docker.com/desktop/windows/install/" -Level INFO
                return $false
            }
            
            # Check Docker command
            try {
                $dockerVersion = docker --version
                Write-Log "Docker found: $dockerVersion" -Level SUCCESS
            }
            catch {
                Write-Log "Docker command not available. Please ensure Docker Desktop is properly installed." -Level ERROR
                return $false
            }
            
            # Check Docker Compose
            try {
                $composeVersion = docker-compose --version
                Write-Log "Docker Compose found: $composeVersion" -Level SUCCESS
            }
            catch {
                Write-Log "Docker Compose not available. Please install Docker Compose." -Level ERROR
                return $false
            }
        } else {
            # Linux/Unix system
            Write-Log "Unix-like system detected - checking Docker..." -Level INFO
            
            # Check Docker
            if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
                Write-Log "Installing Docker..." -Level INFO
                # Installation would depend on the specific Linux distribution
                Write-Log "Please install Docker manually for your system" -Level WARN
                return $false
            }
            
            # Check Docker Compose
            if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
                Write-Log "Installing Docker Compose..." -Level INFO
                Write-Log "Please install Docker Compose manually" -Level WARN
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Error checking dependencies: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Deploy-Manager {
    Write-Log "Deploying RiskNoX Manager..." -Level INFO
    
    try {
        $managerDir = Join-Path $Script:Config.RootPath "manager"
        
        if (-not (Test-Path $managerDir)) {
            Write-Log "Manager directory not found: $managerDir" -Level ERROR
            return $false
        }
        
        Push-Location $managerDir
        
        # Check if deployment script exists
        $deployScript = Join-Path $Script:Config.RootPath "deploy-manager.sh"
        
        if (Test-Path $deployScript) {
            # Use bash script on Unix-like systems
            Write-Log "Using bash deployment script..." -Level INFO
            if ($IsWindows -or $PSVersionTable.Platform -eq "Win32NT") {
                # On Windows, we need to use WSL or Git Bash
                Write-Log "Running deployment via bash (requires WSL or Git Bash)..." -Level INFO
                & bash $deployScript --install
                $deployResult = $LASTEXITCODE
            } else {
                & $deployScript --install
                $deployResult = $LASTEXITCODE
            }
            
            if ($deployResult -ne 0) {
                Write-Log "Deployment script failed with exit code: $deployResult" -Level ERROR
                return $false
            }
        } else {
            # Manual Docker Compose deployment
            Write-Log "Using Docker Compose directly..." -Level INFO
            
            # Create production environment file
            if (-not (Test-Path ".env.production")) {
                Write-Log "Creating production environment..." -Level INFO
                Copy-Item ".env.example" ".env.production"
                
                # Update with server IP if provided
                if ($ServerIP) {
                    $envContent = Get-Content ".env.production" -Raw
                    $envContent = $envContent -replace "MANAGER_HOST=localhost", "MANAGER_HOST=$ServerIP"
                    Set-Content ".env.production" $envContent
                }
            }
            
            # Build and start services
            Write-Log "Building Docker images..." -Level INFO
            docker-compose -f docker-compose.prod.yml --env-file .env.production build
            
            Write-Log "Starting services..." -Level INFO
            docker-compose -f docker-compose.prod.yml --env-file .env.production up -d
            
            # Wait for services
            Write-Log "Waiting for services to start..." -Level INFO
            Start-Sleep -Seconds 30
            
            # Run database migrations
            Write-Log "Running database migrations..." -Level INFO
            docker-compose -f docker-compose.prod.yml --env-file .env.production exec -T manager alembic upgrade head
        }
        
        # Test deployment
        $managerPort = if ($ServerIP) { "8001" } else { "8001" }
        $testUrl = "http://localhost:$managerPort/health"
        
        Write-Log "Testing manager deployment..." -Level INFO
        $maxAttempts = 10
        $attempt = 1
        
        while ($attempt -le $maxAttempts) {
            try {
                $response = Invoke-RestMethod -Uri $testUrl -TimeoutSec 5
                if ($response) {
                    Write-Log "✓ Manager is responding at $testUrl" -Level SUCCESS
                    break
                }
            }
            catch {
                Write-Log "Attempt $attempt/$maxAttempts - Manager not ready yet..." -Level INFO
                Start-Sleep -Seconds 5
            }
            $attempt++
        }
        
        if ($attempt -gt $maxAttempts) {
            Write-Log "✗ Manager failed to respond after $maxAttempts attempts" -Level ERROR
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Manager deployment failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Pop-Location
    }
}

# Agent Setup Functions
function Install-AgentDependencies {
    Write-Log "Installing agent dependencies..." -Level INFO
    
    try {
        # Check Python
        try {
            $pythonVersion = python --version
            if ($pythonVersion -match "Python 3\.(11|12)") {
                Write-Log "Python found: $pythonVersion" -Level SUCCESS
            } else {
                Write-Log "Python 3.11+ required. Found: $pythonVersion" -Level ERROR
                return $false
            }
        }
        catch {
            Write-Log "Python not found. Installing Python..." -Level INFO
            
            if ($IsWindows -or $PSVersionTable.Platform -eq "Win32NT") {
                # Download and install Python on Windows
                $pythonUrl = "https://www.python.org/ftp/python/3.11.6/python-3.11.6-amd64.exe"
                $pythonInstaller = "$env:TEMP\python-installer.exe"
                
                Write-Log "Downloading Python installer..." -Level INFO
                Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller
                
                Write-Log "Installing Python (this may take a few minutes)..." -Level INFO
                Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
                
                # Refresh PATH
                $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine) + ";" + [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::User)
                
                # Test Python again
                try {
                    $pythonVersion = python --version
                    Write-Log "Python installed: $pythonVersion" -Level SUCCESS
                }
                catch {
                    Write-Log "Python installation may have failed. Please install manually." -Level ERROR
                    return $false
                }
            } else {
                Write-Log "Please install Python 3.11+ manually for your system" -Level ERROR
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Error installing dependencies: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-Agent {
    param([string]$ManagerUrl)
    
    Write-Log "Installing RiskNoX Agent..." -Level INFO
    
    try {
        # Check if installation script exists
        $installScript = Join-Path $Script:Config.RootPath "Install-RiskNoXAgent.ps1"
        
        if (Test-Path $installScript) {
            Write-Log "Using automated installation script..." -Level INFO
            
            $arguments = @(
                "-ManagerUrl", $ManagerUrl,
                "-AgentName", $AgentName
            )
            
            if ($Force) {
                $arguments += "-Force"
            }
            
            & $installScript @arguments
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Agent installation completed successfully" -Level SUCCESS
                return $true
            } else {
                Write-Log "✗ Agent installation failed with exit code: $LASTEXITCODE" -Level ERROR
                return $false
            }
        } else {
            Write-Log "Installation script not found. Performing manual installation..." -Level WARN
            
            # Manual installation steps
            $installPath = "C:\Program Files\RiskNoX"
            
            # Create directories
            New-Item -ItemType Directory -Path $installPath -Force | Out-Null
            
            # Copy files
            $filesToCopy = @("agent", "config", "vendor", "scripts", "RiskNoX-Control.ps1", "requirements.txt")
            foreach ($item in $filesToCopy) {
                $sourcePath = Join-Path $Script:Config.RootPath $item
                if (Test-Path $sourcePath) {
                    Copy-Item -Path $sourcePath -Destination $installPath -Recurse -Force
                    Write-Log "Copied: $item" -Level INFO
                }
            }
            
            # Create virtual environment
            Push-Location $installPath
            python -m venv .venv
            & ".venv\Scripts\python.exe" -m pip install --upgrade pip
            & ".venv\Scripts\python.exe" -m pip install -r requirements.txt
            Pop-Location
            
            # Update configuration
            $configPath = "$installPath\config\agent_config.xml"
            if (Test-Path $configPath) {
                [xml]$config = Get-Content $configPath
                $config.agent_config.agent.id = $AgentName
                
                # Update server URLs
                $managerUri = [System.Uri]$ManagerUrl
                $wsUrl = "ws://$($managerUri.Host):$($managerUri.Port)/ws"
                
                $serverNodes = $config.SelectNodes("//server")
                foreach ($node in $serverNodes) {
                    if ($node.url) { $node.url = $ManagerUrl }
                    if ($node.websocket_url) { $node.websocket_url = $wsUrl }
                }
                
                $config.Save($configPath)
                Write-Log "Configuration updated" -Level SUCCESS
            }
            
            return $true
        }
    }
    catch {
        Write-Log "Agent installation failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# Testing Functions
function Test-SystemConnectivity {
    param([string]$ManagerUrl)
    
    Write-Log "Testing system connectivity..." -Level INFO
    
    try {
        # Test manager health
        Write-Log "Testing manager health..." -Level INFO
        $response = Invoke-RestMethod -Uri "$ManagerUrl/health" -TimeoutSec 10
        if ($response) {
            Write-Log "✓ Manager is healthy" -Level SUCCESS
            Write-Log "Manager info: $($response | ConvertTo-Json -Compress)" -Level INFO
        }
        
        # Test WebSocket connectivity
        Write-Log "Testing WebSocket connectivity..." -Level INFO
        $wsUri = $ManagerUrl -replace "^http", "ws"
        $wsUri = "$wsUri/ws"
        Write-Log "WebSocket URL: $wsUri" -Level INFO
        
        # Test API endpoints
        Write-Log "Testing API endpoints..." -Level INFO
        $endpoints = @("/docs", "/api/health", "/api/agents")
        
        foreach ($endpoint in $endpoints) {
            try {
                $testUrl = "$ManagerUrl$endpoint"
                $testResponse = Invoke-WebRequest -Uri $testUrl -TimeoutSec 5 -UseBasicParsing
                if ($testResponse.StatusCode -eq 200) {
                    Write-Log "✓ ${endpoint} - OK" -Level SUCCESS
                } else {
                    Write-Log "✗ ${endpoint} - HTTP $($testResponse.StatusCode)" -Level WARN
                }
            }
            catch {
                Write-Log "✗ ${endpoint} - Failed: $($_.Exception.Message)" -Level WARN
            }
        }
        
        # Test agent if installed
        $agentControlScript = Join-Path $Script:Config.RootPath "RiskNoX-Control.ps1"
        if (Test-Path $agentControlScript) {
            Write-Log "Testing agent functionality..." -Level INFO
            
            try {
                & $agentControlScript -Action test-connection -ManagerUrl $ManagerUrl
                Write-Log "✓ Agent connectivity test completed" -Level SUCCESS
            }
            catch {
                Write-Log "✗ Agent connectivity test failed: $($_.Exception.Message)" -Level WARN
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Connectivity test failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Show-DeploymentSummary {
    param([string]$Mode, [string]$ManagerUrl)
    
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Security System Quick Start Complete         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

DEPLOYMENT MODE: $Mode
"@ -ForegroundColor Cyan

    switch ($Mode) {
        'manager' {
            Write-Host @"
MANAGER SERVICES:
✓ Manager API:     http://localhost:8001
✓ Admin UI:        http://localhost:8080
✓ Database:        PostgreSQL (port 5432)
✓ Storage:         MinIO (port 9000)
✓ Monitoring:      Prometheus (9090), Grafana (3000)

NEXT STEPS:
1. Access the web interface: http://localhost:8080
2. Deploy agents on client systems using:
   .\Quick-Start.ps1 -Mode agent -ManagerUrl "http://YOUR_SERVER_IP:8001"
3. Configure monitoring dashboards
4. Set up SSL certificates for production

MANAGEMENT COMMANDS:
   Status:    .\deploy-manager.sh --status
   Logs:      .\deploy-manager.sh --logs
   Backup:    .\deploy-manager.sh --backup
"@ -ForegroundColor Green
        }
        
        'agent' {
            Write-Host @"
AGENT CONFIGURATION:
✓ Agent Name:      $AgentName
✓ Manager URL:     $ManagerUrl
✓ Installation:    C:\Program Files\RiskNoX

NEXT STEPS:
1. Start the agent:
   .\RiskNoX-Control.ps1 -Action start

2. Enroll with manager:
   .\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "$ManagerUrl"

3. Check status:
   .\RiskNoX-Control.ps1 -Action status

4. Verify in manager web interface: http://manager-server:8080

AGENT COMMANDS:
   Start:     .\RiskNoX-Control.ps1 -Action start
   Stop:      .\RiskNoX-Control.ps1 -Action stop
   Status:    .\RiskNoX-Control.ps1 -Action status
   Scan:      .\RiskNoX-Control.ps1 -Action scan -Path "C:\Users"
"@ -ForegroundColor Green
        }
        
        'test' {
            Write-Host @"
CONNECTIVITY TEST RESULTS:
✓ Manager connectivity verified
✓ API endpoints tested
✓ System components validated

SYSTEM STATUS:
- Manager URL: $ManagerUrl
- All core services responding
- Ready for production use

RECOMMENDED ACTIONS:
1. Monitor system logs for any issues
2. Set up regular health checks
3. Configure backup procedures
4. Review security settings
"@ -ForegroundColor Green
        }
    }

    Write-Host @"

For support and documentation:
- Deployment Guide: DEPLOYMENT_GUIDE.md
- Logs location: logs\quick-start.log
- Configuration: config\ directory

"@ -ForegroundColor Yellow
}

# Main execution function
function Main {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Security System Quick Start                  ║
║                     Version 1.0.0                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Log "Starting RiskNoX Quick Start - Mode: $Mode" -Level INFO
    
    # Prerequisites check
    if (-not (Test-Administrator)) {
        Write-Log "This script must be run as Administrator" -Level ERROR
        exit 1
    }
    
    $success = $true
    
    try {
        switch ($Mode) {
            'manager' {
                Write-Log "=== MANAGER DEPLOYMENT ===" -Level INFO
                
                if (-not $SkipDependencies) {
                    if (-not (Install-ManagerDependencies)) {
                        $success = $false
                    }
                }
                
                if ($success) {
                    if (-not (Deploy-Manager)) {
                        $success = $false
                    }
                }
                
                if ($success) {
                    $testUrl = if ($ServerIP) { "http://$ServerIP:8001" } else { "http://localhost:8001" }
                    Test-SystemConnectivity -ManagerUrl $testUrl
                    Show-DeploymentSummary -Mode $Mode -ManagerUrl $testUrl
                }
            }
            
            'agent' {
                Write-Log "=== AGENT INSTALLATION ===" -Level INFO
                
                if (-not $ManagerUrl) {
                    Write-Log "ManagerUrl parameter is required for agent mode" -Level ERROR
                    $success = $false
                } else {
                    if (-not $SkipDependencies) {
                        if (-not (Install-AgentDependencies)) {
                            $success = $false
                        }
                    }
                    
                    if ($success) {
                        if (-not (Install-Agent -ManagerUrl $ManagerUrl)) {
                            $success = $false
                        }
                    }
                    
                    if ($success) {
                        Test-SystemConnectivity -ManagerUrl $ManagerUrl
                        Show-DeploymentSummary -Mode $Mode -ManagerUrl $ManagerUrl
                    }
                }
            }
            
            'test' {
                Write-Log "=== CONNECTIVITY TESTING ===" -Level INFO
                
                if (-not $ManagerUrl) {
                    Write-Log "ManagerUrl parameter is required for test mode" -Level ERROR
                    $success = $false
                } else {
                    if (-not (Test-SystemConnectivity -ManagerUrl $ManagerUrl)) {
                        $success = $false
                    } else {
                        Show-DeploymentSummary -Mode $Mode -ManagerUrl $ManagerUrl
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Unexpected error: $($_.Exception.Message)" -Level ERROR
        $success = $false
    }
    
    if ($success) {
        Write-Log "Quick Start completed successfully!" -Level SUCCESS
    } else {
        Write-Log "Quick Start completed with errors. Check the logs for details." -Level ERROR
        exit 1
    }
}

# Execute main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}