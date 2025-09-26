#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Professional Patch Management Setup Script
    
.DESCRIPTION
    This script sets up the professional patch management system for RiskNoX Security Agent.
    It configures all necessary components, validates system requirements, and prepares
    the environment for enterprise-grade patch management.
    
.PARAMETER FullSetup
    Perform complete setup including policy enforcement and service configuration
    
.PARAMETER TestMode
    Run in test mode without making permanent system changes
    
.EXAMPLE
    .\Setup-PatchManagement.ps1
    Basic setup with interactive prompts
    
.EXAMPLE
    .\Setup-PatchManagement.ps1 -FullSetup
    Complete setup with policy enforcement
    
.NOTES
    Author: RiskNoX Security Team
    Version: 2.0.0
    Requires: Administrator privileges, PowerShell 7.0+
#>

param(
    [Parameter(Mandatory = $false)]
    [switch]$FullSetup,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Configuration
$Script:Config = @{
    RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    LogFile = "logs\patch_setup.log"
    PatchModule = "scripts\PatchManagement.ps1"
    RequiredPSVersion = [Version]"7.0.0"
    RequiredServices = @("wuauserv", "cryptsvc", "bits", "msiserver")
}

# Initialize logging
function Write-SetupLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'INFO' { 'Cyan' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Log to file
    $logDir = Join-Path $Script:Config.RootPath "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logFile = Join-Path $Script:Config.RootPath $Script:Config.LogFile
    "[$timestamp] [$Level] $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Test-Prerequisites {
    Write-SetupLog "Checking system prerequisites..." -Level INFO
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion -lt $Script:Config.RequiredPSVersion) {
        $issues += "PowerShell $($Script:Config.RequiredPSVersion) or later is required. Current version: $($PSVersionTable.PSVersion)"
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
        $issues += "Windows 10 or later is required for professional patch management"
    }
    
    # Check required services
    foreach ($service in $Script:Config.RequiredServices) {
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
        Write-SetupLog "Windows Update Agent COM interface available" -Level SUCCESS
    }
    catch {
        $issues += "Windows Update Agent COM interface not available: $($_.Exception.Message)"
    }
    
    # Check .NET Framework version
    try {
        $netVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release).Release
        if ($netVersion -lt 461808) { # .NET 4.7.2
            $issues += ".NET Framework 4.7.2 or later is required"
        }
    }
    catch {
        $issues += "Unable to determine .NET Framework version"
    }
    
    if ($issues.Count -gt 0) {
        Write-SetupLog "Prerequisites check failed:" -Level ERROR
        foreach ($issue in $issues) {
            Write-SetupLog "- $issue" -Level ERROR
        }
        return $false
    }
    
    Write-SetupLog "All prerequisites met" -Level SUCCESS
    return $true
}

function Initialize-PatchManagementDirectories {
    Write-SetupLog "Creating directory structure..." -Level INFO
    
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
            Write-SetupLog "Created directory: $dir" -Level SUCCESS
        } else {
            Write-SetupLog "Directory exists: $dir" -Level INFO
        }
    }
}

function Test-PatchManagementModule {
    Write-SetupLog "Validating patch management module..." -Level INFO
    
    $modulePath = Join-Path $Script:Config.RootPath $Script:Config.PatchModule
    
    if (-not (Test-Path $modulePath)) {
        Write-SetupLog "Patch management module not found at: $modulePath" -Level ERROR
        return $false
    }
    
    try {
        # Test loading the module
        . $modulePath
        
        # Test creating a patch manager instance
        $logPath = Join-Path $Script:Config.RootPath "logs\setup_test.log"
        $patchManager = Initialize-PatchManager -LogPath $logPath
        
        if ($patchManager) {
            Write-SetupLog "Patch management module loaded successfully" -Level SUCCESS
            return $true
        } else {
            Write-SetupLog "Failed to initialize patch manager" -Level ERROR
            return $false
        }
    }
    catch {
        Write-SetupLog "Error loading patch management module: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-WindowsUpdateConnectivity {
    Write-SetupLog "Testing Windows Update connectivity..." -Level INFO
    
    try {
        # Test basic internet connectivity
        $testUrls = @(
            "https://www.microsoft.com",
            "https://update.microsoft.com", 
            "https://windowsupdate.microsoft.com"
        )
        
        $connectivityResults = @()
        foreach ($url in $testUrls) {
            try {
                $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing
                $connectivityResults += @{
                    Url = $url
                    StatusCode = $response.StatusCode
                    Success = ($response.StatusCode -eq 200)
                }
                Write-SetupLog "✓ $url - Accessible" -Level SUCCESS
            }
            catch {
                $connectivityResults += @{
                    Url = $url
                    Error = $_.Exception.Message
                    Success = $false
                }
                Write-SetupLog "✗ $url - $($_.Exception.Message)" -Level WARN
            }
        }
        
        # Test Windows Update API
        try {
            . (Join-Path $Script:Config.RootPath $Script:Config.PatchModule)
            $patchManager = Initialize-PatchManager -LogPath (Join-Path $Script:Config.RootPath "logs\connectivity_test.log")
            
            Write-SetupLog "Testing Windows Update API..." -Level INFO
            $updateCheck = Get-AvailableUpdates -PatchManager $patchManager
            
            if ($updateCheck.Success) {
                Write-SetupLog "✓ Windows Update API - Functional (Found $($updateCheck.UpdateCount) updates)" -Level SUCCESS
                return $true
            } else {
                Write-SetupLog "✗ Windows Update API - Error: $($updateCheck.Error)" -Level WARN
                return $false
            }
        }
        catch {
            Write-SetupLog "✗ Windows Update API - Exception: $($_.Exception.Message)" -Level WARN
            return $false
        }
    }
    catch {
        Write-SetupLog "Connectivity test failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Initialize-WindowsUpdateConfiguration {
    Write-SetupLog "Initializing Windows Update configuration..." -Level INFO
    
    if ($TestMode) {
        Write-SetupLog "Running in test mode - no permanent changes will be made" -Level WARN
        return $true
    }
    
    try {
        # Ensure Windows Update service is properly configured
        Write-SetupLog "Configuring Windows Update service..." -Level INFO
        
        $wuService = Get-Service -Name "wuauserv"
        if ($wuService.StartType -eq 'Disabled') {
            if ($FullSetup -or $Force -or (Read-Host "Windows Update service is disabled. Enable it? (Y/n)") -ne 'n') {
                Set-Service -Name "wuauserv" -StartupType Manual
                Write-SetupLog "Enabled Windows Update service" -Level SUCCESS
            }
        }
        
        # Start the service if it's not running
        if ($wuService.Status -ne 'Running') {
            Start-Service -Name "wuauserv"
            Write-SetupLog "Started Windows Update service" -Level SUCCESS
        }
        
        # Configure related services
        $relatedServices = @("cryptsvc", "bits")
        foreach ($serviceName in $relatedServices) {
            $service = Get-Service -Name $serviceName
            if ($service.StartType -eq 'Disabled') {
                Set-Service -Name $serviceName -StartupType Manual
                Write-SetupLog "Enabled $serviceName service" -Level SUCCESS
            }
            if ($service.Status -ne 'Running') {
                Start-Service -Name $serviceName
                Write-SetupLog "Started $serviceName service" -Level SUCCESS
            }
        }
        
        # Create initial configuration
        $configPath = Join-Path $Script:Config.RootPath "config\patch_config.json"
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
        Write-SetupLog "Created patch management configuration" -Level SUCCESS
        
        return $true
    }
    catch {
        Write-SetupLog "Failed to initialize Windows Update configuration: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-PatchManagementPolicies {
    if (-not $FullSetup) {
        Write-SetupLog "Skipping policy installation (use -FullSetup to enable)" -Level INFO
        return $true
    }
    
    if ($TestMode) {
        Write-SetupLog "Test mode: Would install patch management policies" -Level WARN
        return $true
    }
    
    Write-SetupLog "Installing patch management policies..." -Level INFO
    
    $confirmation = if ($Force) { 'y' } else { 
        Read-Host "This will enforce Windows Update policies and block manual updates. Continue? (Y/n)"
    }
    
    if ($confirmation -eq 'n') {
        Write-SetupLog "Policy installation skipped by user" -Level INFO
        return $true
    }
    
    try {
        # Load the patch management module
        . (Join-Path $Script:Config.RootPath $Script:Config.PatchModule)
        $patchManager = Initialize-PatchManager -LogPath (Join-Path $Script:Config.RootPath "logs\policy_setup.log")
        
        # Enforce policies
        $policyResult = Set-UpdatePolicies -PatchManager $patchManager
        
        if ($policyResult.Success) {
            Write-SetupLog "Patch management policies installed successfully" -Level SUCCESS
            Write-SetupLog "Policy changes applied:" -Level INFO
            foreach ($result in $policyResult.Results) {
                Write-SetupLog "- $result" -Level INFO
            }
            
            # Verify compliance
            $complianceResult = Test-UpdateCompliance -PatchManager $patchManager
            if ($complianceResult.Success) {
                Write-SetupLog "Policy compliance: $($complianceResult.CompliancePercentage)%" -Level SUCCESS
            }
            
            return $true
        } else {
            Write-SetupLog "Failed to install policies: $($policyResult.Error)" -Level ERROR
            return $false
        }
    }
    catch {
        Write-SetupLog "Exception during policy installation: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-SetupValidation {
    Write-SetupLog "Validating setup..." -Level INFO
    
    $validationResults = @{
        ModuleLoads = $false
        APIAccess = $false
        ServiceStatus = $false
        ConfigExists = $false
        LoggingWorks = $false
    }
    
    try {
        # Test module loading
        . (Join-Path $Script:Config.RootPath $Script:Config.PatchModule)
        $patchManager = Initialize-PatchManager -LogPath (Join-Path $Script:Config.RootPath "logs\validation_test.log")
        $validationResults.ModuleLoads = ($patchManager -ne $null)
        
        # Test API access
        if ($validationResults.ModuleLoads) {
            $updateCheck = Get-AvailableUpdates -PatchManager $patchManager
            $validationResults.APIAccess = $updateCheck.Success
        }
        
        # Test service status
        $wuService = Get-Service -Name "wuauserv"
        $validationResults.ServiceStatus = ($wuService.Status -eq 'Running')
        
        # Test configuration
        $configPath = Join-Path $Script:Config.RootPath "config\patch_config.json"
        $validationResults.ConfigExists = (Test-Path $configPath)
        
        # Test logging
        $testLogPath = Join-Path $Script:Config.RootPath "logs\validation_test.log"
        $validationResults.LoggingWorks = (Test-Path $testLogPath)
        
        # Report results
        Write-SetupLog "Validation Results:" -Level INFO
        foreach ($test in $validationResults.Keys) {
            $status = if ($validationResults[$test]) { "✓ PASS" } else { "✗ FAIL" }
            $level = if ($validationResults[$test]) { "SUCCESS" } else { "ERROR" }
            Write-SetupLog "- $test : $status" -Level $level
        }
        
        $allPassed = ($validationResults.Values | Where-Object { $_ -eq $false }).Count -eq 0
        
        if ($allPassed) {
            Write-SetupLog "All validation tests passed!" -Level SUCCESS
            return $true
        } else {
            Write-SetupLog "Some validation tests failed. Check the issues above." -Level ERROR
            return $false
        }
    }
    catch {
        Write-SetupLog "Validation failed with exception: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Show-SetupSummary {
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

4. View comprehensive help:
   .\RiskNoX-Control.ps1 -Action help

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

# Main setup execution
function Main {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        RiskNoX Professional Patch Management Setup          ║
║                        Version 2.0.0                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-SetupLog "Starting RiskNoX Professional Patch Management setup..." -Level INFO
    Write-SetupLog "Setup mode: $(if ($FullSetup) { "Full Setup" } else { "Basic Setup" })$(if ($TestMode) { " (Test Mode)" } else { "" })" -Level INFO
    
    # Change to script directory
    Set-Location $Script:Config.RootPath
    
    $setupSteps = @(
        @{ Name = "Prerequisites Check"; Function = { Test-Prerequisites } },
        @{ Name = "Directory Initialization"; Function = { Initialize-PatchManagementDirectories } },
        @{ Name = "Module Validation"; Function = { Test-PatchManagementModule } },
        @{ Name = "Connectivity Test"; Function = { Test-WindowsUpdateConnectivity } },
        @{ Name = "Windows Update Configuration"; Function = { Initialize-WindowsUpdateConfiguration } },
        @{ Name = "Policy Installation"; Function = { Install-PatchManagementPolicies } },
        @{ Name = "Setup Validation"; Function = { Test-SetupValidation } }
    )
    
    $success = $true
    $stepNumber = 1
    
    foreach ($step in $setupSteps) {
        Write-SetupLog "[$stepNumber/$($setupSteps.Count)] $($step.Name)..." -Level INFO
        
        try {
            $result = & $step.Function
            if ($result) {
                Write-SetupLog "$($step.Name) completed successfully" -Level SUCCESS
            } else {
                Write-SetupLog "$($step.Name) failed" -Level ERROR
                $success = $false
                if (-not $Force) {
                    $continue = Read-Host "Continue with setup anyway? (y/N)"
                    if ($continue -ne 'y') {
                        Write-SetupLog "Setup aborted by user" -Level ERROR
                        return
                    }
                }
            }
        }
        catch {
            Write-SetupLog "$($step.Name) failed with exception: $($_.Exception.Message)" -Level ERROR
            $success = $false
            if (-not $Force) {
                $continue = Read-Host "Continue with setup anyway? (y/N)"
                if ($continue -ne 'y') {
                    Write-SetupLog "Setup aborted by user" -Level ERROR
                    return
                }
            }
        }
        
        $stepNumber++
        Start-Sleep -Milliseconds 500
    }
    
    if ($success) {
        Write-SetupLog "Setup completed successfully!" -Level SUCCESS
        Show-SetupSummary
    } else {
        Write-SetupLog "Setup completed with some issues. Check the logs for details." -Level WARN
        Write-SetupLog "Log file: $($Script:Config.LogFile)" -Level INFO
    }
    
    Write-SetupLog "Setup finished at $(Get-Date)" -Level INFO
}

# Execute main function
Main