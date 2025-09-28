#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Agent Installation Script
    
.DESCRIPTION
    Automated installation script for RiskNoX Security Agent.
    Sets up Python environment, installs dependencies, and configures the agent.
    
.PARAMETER ManagerUrl
    URL of the RiskNoX Manager server (e.g., http://192.168.1.100:8001)
    
.PARAMETER AgentName
    Unique name for this agent (defaults to hostname)
    
.PARAMETER InstallPath
    Installation directory (defaults to C:\Program Files\RiskNoX)
    
.PARAMETER CreateService
    Create Windows service for the agent
    
.PARAMETER SkipFirewall
    Skip Windows Firewall configuration
    
.EXAMPLE
    .\Install-RiskNoXAgent.ps1 -ManagerUrl "http://192.168.1.100:8001" -AgentName "WorkStation-001"
    
.NOTES
    Author: RiskNoX Security Team
    Version: 1.0.0
    Requires: PowerShell 7.0+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ManagerUrl,
    
    [Parameter(Mandatory = $false)]
    [string]$AgentName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "C:\Program Files\RiskNoX",
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateService,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipFirewall,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Configuration
$Script:Config = @{
    PythonVersion = "3.11"
    RequiredModules = @("requests", "websockets", "cryptography", "structlog", "colorama")
    ServiceName = "RiskNoXAgent"
    ServiceDisplayName = "RiskNoX Security Agent"
    ServiceDescription = "RiskNoX Security Agent - Endpoint protection and monitoring"
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
}

function Test-Prerequisites {
    Write-Log "Checking installation prerequisites..." -Level INFO
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $issues += "PowerShell 7.0 or later is required. Current version: $($PSVersionTable.PSVersion)"
    }
    
    # Check if running as Administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues += "This script must be run as Administrator"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        $issues += "Windows 10 or later is required"
    }
    
    # Check Python availability
    try {
        $pythonVersion = python --version 2>$null
        if (-not $pythonVersion -or $pythonVersion -notmatch "Python 3\.(11|12)") {
            $issues += "Python 3.11+ is required. Current: $pythonVersion"
        }
    }
    catch {
        $issues += "Python 3.11+ is not installed or not in PATH"
    }
    
    # Test manager connectivity
    try {
        $response = Invoke-WebRequest -Uri "$ManagerUrl/health" -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -ne 200) {
            $issues += "Manager server is not responding correctly at $ManagerUrl"
        }
    }
    catch {
        $issues += "Cannot connect to manager server at $ManagerUrl : $($_.Exception.Message)"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "Prerequisites check failed:" -Level ERROR
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level ERROR
        }
        return $false
    }
    
    Write-Log "All prerequisites met" -Level SUCCESS
    return $true
}

function Install-Agent {
    Write-Log "Installing RiskNoX Agent to $InstallPath..." -Level INFO
    
    try {
        # Create installation directory
        if (Test-Path $InstallPath) {
            if ($Force) {
                Write-Log "Removing existing installation..." -Level WARN
                Remove-Item -Path $InstallPath -Recurse -Force
            } else {
                Write-Log "Installation directory already exists. Use -Force to overwrite." -Level ERROR
                return $false
            }
        }
        
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-Log "Created installation directory: $InstallPath" -Level SUCCESS
        
        # Create subdirectories
        $subDirs = @("agent", "config", "logs", "vendor", "scripts")
        foreach ($dir in $subDirs) {
            New-Item -ItemType Directory -Path "$InstallPath\$dir" -Force | Out-Null
        }
        
        # Copy agent files
        $sourceFiles = @(
            @{Source = "agent\*"; Destination = "$InstallPath\agent\"},
            @{Source = "config\*"; Destination = "$InstallPath\config\"},
            @{Source = "vendor\*"; Destination = "$InstallPath\vendor\"},
            @{Source = "scripts\*"; Destination = "$InstallPath\scripts\"},
            @{Source = "RiskNoX-Control.ps1"; Destination = "$InstallPath\"},
            @{Source = "requirements.txt"; Destination = "$InstallPath\"}
        )
        
        foreach ($file in $sourceFiles) {
            if (Test-Path $file.Source) {
                Copy-Item -Path $file.Source -Destination $file.Destination -Recurse -Force
                Write-Log "Copied: $($file.Source)" -Level INFO
            } else {
                Write-Log "Warning: Source file not found: $($file.Source)" -Level WARN
            }
        }
        
        # Create Python virtual environment
        Write-Log "Creating Python virtual environment..." -Level INFO
        Push-Location $InstallPath
        
        python -m venv .venv
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Virtual environment created successfully" -Level SUCCESS
        } else {
            Write-Log "Failed to create virtual environment" -Level ERROR
            Pop-Location
            return $false
        }
        
        # Install Python dependencies
        Write-Log "Installing Python dependencies..." -Level INFO
        & ".venv\Scripts\python.exe" -m pip install --upgrade pip
        & ".venv\Scripts\python.exe" -m pip install -r requirements.txt
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Python dependencies installed successfully" -Level SUCCESS
        } else {
            Write-Log "Failed to install Python dependencies" -Level ERROR
            Pop-Location
            return $false
        }
        
        Pop-Location
        return $true
    }
    catch {
        Write-Log "Installation failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Update-AgentConfiguration {
    Write-Log "Configuring agent for manager: $ManagerUrl" -Level INFO
    
    try {
        $configPath = "$InstallPath\config\agent_config.xml"
        
        if (-not (Test-Path $configPath)) {
            Write-Log "Configuration file not found: $configPath" -Level ERROR
            return $false
        }
        
        # Load and update XML configuration
        [xml]$config = Get-Content $configPath
        
        # Update agent ID
        $config.agent_config.agent.id = $AgentName
        
        # Update server URLs
        $managerUri = [System.Uri]$ManagerUrl
        $wsUrl = "ws://$($managerUri.Host):$($managerUri.Port)/ws"
        
        # Update all server URL references
        $serverNodes = $config.SelectNodes("//server")
        foreach ($node in $serverNodes) {
            if ($node.url) { $node.url = $ManagerUrl }
            if ($node.websocket_url) { $node.websocket_url = $wsUrl }
        }
        
        # Update netblock_monitor server
        if ($config.agent_config.modules.netblock_monitor.server) {
            $config.agent_config.modules.netblock_monitor.server.url = $ManagerUrl
        }
        
        # Save updated configuration
        $config.Save($configPath)
        Write-Log "Agent configuration updated successfully" -Level SUCCESS
        
        # Create additional config files
        $additionalConfigs = @{
            "agent_info.json" = @{
                agent_id = $AgentName
                manager_url = $ManagerUrl
                install_path = $InstallPath
                install_date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                version = "1.0.0"
            }
        }
        
        foreach ($configFile in $additionalConfigs.Keys) {
            $configData = $additionalConfigs[$configFile]
            $configJson = $configData | ConvertTo-Json -Depth 10
            $configFilePath = "$InstallPath\config\$configFile"
            Set-Content -Path $configFilePath -Value $configJson
            Write-Log "Created configuration file: $configFile" -Level SUCCESS
        }
        
        return $true
    }
    catch {
        Write-Log "Configuration update failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-WindowsService {
    if (-not $CreateService) {
        Write-Log "Skipping Windows service creation" -Level INFO
        return $true
    }
    
    Write-Log "Creating Windows service..." -Level INFO
    
    try {
        # Check if service already exists
        $existingService = Get-Service -Name $Script:Config.ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Log "Service already exists. Removing..." -Level WARN
            if ($existingService.Status -eq 'Running') {
                Stop-Service -Name $Script:Config.ServiceName -Force
            }
            & sc.exe delete $Script:Config.ServiceName
            Start-Sleep -Seconds 2
        }
        
        # Create service
        $pythonExe = "$InstallPath\.venv\Scripts\python.exe"
        $agentScript = "$InstallPath\agent\agent_main.py"
        $serviceBinary = "`"$pythonExe`" `"$agentScript`" --service"
        
        $result = & sc.exe create $Script:Config.ServiceName binpath= $serviceBinary displayname= $Script:Config.ServiceDisplayName start= auto
        
        if ($LASTEXITCODE -eq 0) {
            & sc.exe description $Script:Config.ServiceName $Script:Config.ServiceDescription
            Write-Log "Windows service created successfully" -Level SUCCESS
            
            # Start the service
            Start-Service -Name $Script:Config.ServiceName
            Write-Log "Service started successfully" -Level SUCCESS
            return $true
        } else {
            Write-Log "Failed to create Windows service: $result" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Service creation failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Configure-Firewall {
    if ($SkipFirewall) {
        Write-Log "Skipping Windows Firewall configuration" -Level INFO
        return $true
    }
    
    Write-Log "Configuring Windows Firewall..." -Level INFO
    
    try {
        # Allow outbound connections to manager
        $managerUri = [System.Uri]$ManagerUrl
        $managerPort = $managerUri.Port
        
        $ruleName = "RiskNoX Agent Outbound"
        
        # Remove existing rule
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existingRule) {
            Remove-NetFirewallRule -DisplayName $ruleName
        }
        
        # Create new rule
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $managerPort -Action Allow -Profile Any
        
        Write-Log "Firewall rule created: $ruleName" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Firewall configuration failed: $($_.Exception.Message)" -Level WARN
        Write-Log "Agent will still function, but firewall may need manual configuration" -Level WARN
        return $true
    }
}

function Test-Installation {
    Write-Log "Testing agent installation..." -Level INFO
    
    try {
        Push-Location $InstallPath
        
        # Test Python environment
        $pythonTest = & ".venv\Scripts\python.exe" -c "import sys; print(f'Python {sys.version}')" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Python environment: $pythonTest" -Level SUCCESS
        } else {
            Write-Log "Python environment test failed" -Level ERROR
            Pop-Location
            return $false
        }
        
        # Test agent imports
        $importTest = & ".venv\Scripts\python.exe" -c "
import sys
sys.path.insert(0, 'agent')
try:
    from agent_main import RiskNoXAgent
    print('Agent imports successful')
except Exception as e:
    print(f'Import error: {e}')
    exit(1)
" 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Agent module test: $importTest" -Level SUCCESS
        } else {
            Write-Log "Agent module test failed: $importTest" -Level ERROR
            Pop-Location
            return $false
        }
        
        # Test manager connectivity
        $connectivityTest = & ".venv\Scripts\python.exe" -c "
import requests
try:
    response = requests.get('$ManagerUrl/health', timeout=10)
    if response.status_code == 200:
        print('Manager connectivity: OK')
    else:
        print(f'Manager responded with status: {response.status_code}')
        exit(1)
except Exception as e:
    print(f'Connectivity error: {e}')
    exit(1)
" 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Manager connectivity: $connectivityTest" -Level SUCCESS
        } else {
            Write-Log "Manager connectivity test failed: $connectivityTest" -Level ERROR
            Pop-Location
            return $false
        }
        
        Pop-Location
        return $true
    }
    catch {
        Write-Log "Installation test failed: $($_.Exception.Message)" -Level ERROR
        Pop-Location
        return $false
    }
}

function Show-InstallationSummary {
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║            RiskNoX Agent Installation Complete              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

INSTALLATION SUMMARY:
✓ Agent installed to: $InstallPath
✓ Agent name: $AgentName  
✓ Manager URL: $ManagerUrl
✓ Python environment configured
✓ Dependencies installed
✓ Configuration updated
$(if ($CreateService) { "✓ Windows service created" } else { "○ Windows service not created" })
$(if (-not $SkipFirewall) { "✓ Firewall configured" } else { "○ Firewall configuration skipped" })

NEXT STEPS:

1. Start the agent:
   cd "$InstallPath"
   .\RiskNoX-Control.ps1 -Action start

2. Check agent status:
   .\RiskNoX-Control.ps1 -Action status

3. View logs:
   Get-Content -Path "$InstallPath\logs\agent.log" -Tail 20

4. Test connectivity:
   .\RiskNoX-Control.ps1 -Action test-connection

MANAGEMENT COMMANDS:
   Start:    .\RiskNoX-Control.ps1 -Action start
   Stop:     .\RiskNoX-Control.ps1 -Action stop  
   Status:   .\RiskNoX-Control.ps1 -Action status
   Scan:     .\RiskNoX-Control.ps1 -Action scan -Path "C:\Users"

WEB INTERFACE:
   Manager UI: $ManagerUrl
   Agent should appear in the dashboard after successful enrollment.

"@ -ForegroundColor Green
}

# Main installation function
function Main {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              RiskNoX Agent Installation                     ║
║                     Version 1.0.0                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Log "Starting RiskNoX Agent installation..." -Level INFO
    Write-Log "Target: $AgentName -> $ManagerUrl" -Level INFO
    Write-Log "Install Path: $InstallPath" -Level INFO
    
    $installSteps = @(
        @{Name = "Prerequisites Check"; Function = { Test-Prerequisites }},
        @{Name = "Agent Installation"; Function = { Install-Agent }},
        @{Name = "Configuration Update"; Function = { Update-AgentConfiguration }},
        @{Name = "Windows Service"; Function = { Install-WindowsService }},
        @{Name = "Firewall Configuration"; Function = { Configure-Firewall }},
        @{Name = "Installation Test"; Function = { Test-Installation }}
    )
    
    $success = $true
    $stepNumber = 1
    
    foreach ($step in $installSteps) {
        Write-Log "Step $stepNumber/$($installSteps.Count): $($step.Name)" -Level INFO
        $stepResult = & $step.Function
        
        if ($stepResult) {
            Write-Log "✓ $($step.Name) completed successfully" -Level SUCCESS
        } else {
            Write-Log "✗ $($step.Name) failed" -Level ERROR
            $success = $false
            break
        }
        
        $stepNumber++
        Start-Sleep -Seconds 1
    }
    
    if ($success) {
        Write-Log "Installation completed successfully!" -Level SUCCESS
        Show-InstallationSummary
    } else {
        Write-Log "Installation failed. Please check the errors above and try again." -Level ERROR
        exit 1
    }
}

# Execute main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}