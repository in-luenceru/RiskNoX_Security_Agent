# RiskNoX Agent Startup Script
# Starts the RiskNoX security agent

param(
    [string]$Config = "agent_config.yaml",
    [string]$LogLevel = "INFO",
    [switch]$EnrollOnly,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status
)

$ErrorActionPreference = "Stop"

# Script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = $ScriptDir

# Agent service details
$ServiceName = "RiskNoXAgent"
$ServiceDisplayName = "RiskNoX Security Agent"
$ServiceDescription = "RiskNoX Security Management Agent"

function Write-ColoredOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-AgentDependencies {
    Write-ColoredOutput "🔧 Installing agent dependencies..." "Yellow"
    
    # Check if Python is installed
    try {
        $pythonVersion = python --version 2>&1
        Write-ColoredOutput "✅ Python found: $pythonVersion" "Green"
    }
    catch {
        Write-ColoredOutput "❌ Python not found. Please install Python 3.8+ first." "Red"
        exit 1
    }
    
    # Install requirements
    $requirementsFile = Join-Path $AgentDir "requirements.txt"
    if (Test-Path $requirementsFile) {
        Write-ColoredOutput "📦 Installing Python packages..." "Cyan"
        python -m pip install --upgrade pip
        python -m pip install -r $requirementsFile
        Write-ColoredOutput "✅ Dependencies installed successfully" "Green"
    }
    else {
        Write-ColoredOutput "⚠️ requirements.txt not found, skipping dependency installation" "Yellow"
    }
}

function Install-AgentService {
    if (-not (Test-AdminRights)) {
        Write-ColoredOutput "❌ Administrator rights required for service installation" "Red"
        exit 1
    }
    
    Write-ColoredOutput "🔧 Installing RiskNoX Agent Service..." "Yellow"
    
    # Install dependencies first
    Install-AgentDependencies
    
    # Create service using nssm (if available) or sc.exe
    $agentScript = Join-Path $AgentDir "agent_main.py"
    $pythonExe = (Get-Command python).Source
    
    try {
        # Try using nssm first (better for Python services)
        $nssmPath = Get-Command nssm -ErrorAction SilentlyContinue
        if ($nssmPath) {
            & nssm install $ServiceName $pythonExe $agentScript
            & nssm set $ServiceName Description $ServiceDescription
            & nssm set $ServiceName Start SERVICE_AUTO_START
            & nssm set $ServiceName AppDirectory $AgentDir
        }
        else {
            # Fallback to sc.exe
            $servicePath = "`"$pythonExe`" `"$agentScript`""
            & sc.exe create $ServiceName binPath= $servicePath start= auto DisplayName= $ServiceDisplayName
            & sc.exe description $ServiceName $ServiceDescription
        }
        
        Write-ColoredOutput "✅ Service installed successfully" "Green"
        Write-ColoredOutput "▶️ Starting service..." "Cyan"
        Start-Service $ServiceName
        Write-ColoredOutput "✅ RiskNoX Agent service started" "Green"
    }
    catch {
        Write-ColoredOutput "❌ Failed to install service: $_" "Red"
        exit 1
    }
}

function Uninstall-AgentService {
    if (-not (Test-AdminRights)) {
        Write-ColoredOutput "❌ Administrator rights required for service removal" "Red"
        exit 1
    }
    
    Write-ColoredOutput "🗑️ Uninstalling RiskNoX Agent Service..." "Yellow"
    
    try {
        # Stop service if running
        $service = Get-Service $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service $ServiceName -Force
            Write-ColoredOutput "⏹️ Service stopped" "Cyan"
        }
        
        # Remove service
        $nssmPath = Get-Command nssm -ErrorAction SilentlyContinue
        if ($nssmPath) {
            & nssm remove $ServiceName confirm
        }
        else {
            & sc.exe delete $ServiceName
        }
        
        Write-ColoredOutput "✅ Service uninstalled successfully" "Green"
    }
    catch {
        Write-ColoredOutput "❌ Failed to uninstall service: $_" "Red"
        exit 1
    }
}

function Get-AgentStatus {
    Write-ColoredOutput "📊 RiskNoX Agent Status" "Cyan"
    Write-ColoredOutput "========================" "Cyan"
    
    # Check service status
    $service = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        $statusColor = if ($service.Status -eq "Running") { "Green" } else { "Red" }
        Write-ColoredOutput "Service Status: $($service.Status)" $statusColor
        Write-ColoredOutput "Service Name: $($service.ServiceName)" "White"
        Write-ColoredOutput "Display Name: $($service.DisplayName)" "White"
    }
    else {
        Write-ColoredOutput "Service Status: Not Installed" "Red"
    }
    
    # Check configuration
    $configFile = Join-Path $AgentDir $Config
    if (Test-Path $configFile) {
        Write-ColoredOutput "Config File: ✅ Found" "Green"
    }
    else {
        Write-ColoredOutput "Config File: ❌ Not Found" "Red"
    }
    
    # Check certificates
    $certDir = Join-Path $AgentDir "certs"
    if (Test-Path $certDir) {
        $certFiles = Get-ChildItem $certDir -Filter "*.pem" | Measure-Object
        Write-ColoredOutput "Certificates: $($certFiles.Count) files found" "White"
    }
    else {
        Write-ColoredOutput "Certificates: ❌ Directory not found" "Red"
    }
}

function Start-Agent {
    Write-ColoredOutput "🚀 Starting RiskNoX Agent..." "Green"
    Write-ColoredOutput "Config: $Config" "Cyan"
    Write-ColoredOutput "Log Level: $LogLevel" "Cyan"
    
    # Build Python command
    $agentScript = Join-Path $AgentDir "agent_main.py"
    $pythonArgs = @($agentScript, "--config", $Config, "--log-level", $LogLevel)
    
    if ($EnrollOnly) {
        $pythonArgs += "--enroll-only"
        Write-ColoredOutput "🔐 Enrollment-only mode" "Yellow"
    }
    
    # Change to agent directory
    Push-Location $AgentDir
    
    try {
        # Start agent
        if ($EnrollOnly) {
            & python @pythonArgs
        }
        else {
            Write-ColoredOutput "✅ Agent started. Press Ctrl+C to stop." "Green"
            & python @pythonArgs
        }
    }
    catch {
        Write-ColoredOutput "❌ Failed to start agent: $_" "Red"
        exit 1
    }
    finally {
        Pop-Location
    }
}

# Main execution
Write-ColoredOutput "🛡️ RiskNoX Security Agent" "Green"
Write-ColoredOutput "=========================" "Green"

# Handle command line options
if ($Install) {
    Install-AgentService
}
elseif ($Uninstall) {
    Uninstall-AgentService  
}
elseif ($Status) {
    Get-AgentStatus
}
else {
    # Install dependencies if requirements.txt exists
    $requirementsFile = Join-Path $AgentDir "requirements.txt"
    if ((Test-Path $requirementsFile) -and -not $EnrollOnly) {
        Write-ColoredOutput "📦 Checking dependencies..." "Cyan"
        try {
            python -c "import aiohttp, websockets, cryptography" 2>$null
        }
        catch {
            Install-AgentDependencies
        }
    }
    
    # Start agent
    Start-Agent
}

Write-ColoredOutput "👋 RiskNoX Agent session ended" "Green"