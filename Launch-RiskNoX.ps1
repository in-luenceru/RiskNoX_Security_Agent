#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Security Agent - Quick Launch Script
    
.DESCRIPTION
    Simple launcher that automatically sets up and starts the RiskNoX Security Agent
    with professional patch management capabilities. This is the easiest way to get started.
    
.NOTES
    Author: RiskNoX Security Team  
    Version: 2.0.0
    Requires: Administrator privileges, PowerShell 7.0+
#>

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              🛡️  RiskNoX Security Agent 2.0  🛡️               ║
║                     Quick Launcher                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "`nWelcome to RiskNoX Security Agent - Professional Edition!" -ForegroundColor Green
Write-Host "This script will set up and launch your complete security solution.`n" -ForegroundColor White

# Check prerequisites
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ Administrator privileges required!" -ForegroundColor Red
    Write-Host "Please run this script as Administrator." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "❌ PowerShell 7.0+ required!" -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "Please install PowerShell 7+ from: https://github.com/PowerShell/PowerShell" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Prerequisites check passed!" -ForegroundColor Green

# Check if patch management is set up
$patchModulePath = "scripts\PatchManagement.ps1"
$patchConfigPath = "config\patch_config.json"

$needsSetup = $false
if (Test-Path $patchModulePath) {
    if (-not (Test-Path $patchConfigPath)) {
        $needsSetup = $true
        Write-Host "`n🔧 Professional patch management module detected but not configured." -ForegroundColor Yellow
    } else {
        Write-Host "`n✅ Professional patch management already configured!" -ForegroundColor Green
    }
} else {
    Write-Host "`n⚠️  Professional patch management module not found." -ForegroundColor Yellow
    Write-Host "Please ensure scripts\PatchManagement.ps1 exists." -ForegroundColor Yellow
}

# Setup if needed
if ($needsSetup) {
    Write-Host "`nSETUP OPTIONS:" -ForegroundColor Cyan
    Write-Host "1. Basic Setup (recommended for most users)" -ForegroundColor White
    Write-Host "2. Full Setup with Policy Enforcement (enterprise environments)" -ForegroundColor White
    Write-Host "3. Skip setup for now" -ForegroundColor Gray
    
    do {
        $choice = Read-Host "`nEnter your choice (1-3)"
    } while ($choice -notin @('1', '2', '3'))
    
    switch ($choice) {
        '1' {
            Write-Host "`n🚀 Starting basic setup..." -ForegroundColor Green
            .\RiskNoX-Control.ps1 -Action patch-setup -Force
        }
        '2' {
            Write-Host "`n🚀 Starting full setup with policy enforcement..." -ForegroundColor Green
            .\RiskNoX-Control.ps1 -Action patch-setup -FullSetup -Force
        }
        '3' {
            Write-Host "`n⏭️  Skipping setup..." -ForegroundColor Yellow
        }
    }
}

# Start the service
Write-Host "`n🚀 Starting RiskNoX Security Agent..." -ForegroundColor Green
Write-Host "The web interface will be available at: http://localhost:5000" -ForegroundColor Cyan
Write-Host "Admin credentials: username=admin, password=RiskNoX@2024`n" -ForegroundColor Cyan

# Launch with live logs
.\RiskNoX-Control.ps1 -Action start