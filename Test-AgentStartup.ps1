#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script to verify complete RiskNoX agent startup functionality
#>

param(
    [switch]$FullTest,
    [switch]$StatusOnly
)

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "        RiskNoX Agent Startup Verification Test" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

$scriptPath = Join-Path $PSScriptRoot "RiskNoX-Control.ps1"

if (-not (Test-Path $scriptPath)) {
    Write-Host "✗ RiskNoX-Control.ps1 not found in current directory" -ForegroundColor Red
    exit 1
}

Write-Host "Testing script: $scriptPath" -ForegroundColor Yellow

# Test 1: Check if agent directory exists
Write-Host "`n1. Checking Agent Configuration..." -ForegroundColor Yellow
$agentScript = Join-Path $PSScriptRoot "agent\agent_main.py"
$agentConfig = Join-Path $PSScriptRoot "config\agent_config.xml"

if (Test-Path $agentScript) {
    Write-Host "✓ Agent script found: $agentScript" -ForegroundColor Green
} else {
    Write-Host "○ Agent script not found (backend mode)" -ForegroundColor Yellow
}

if (Test-Path $agentConfig) {
    Write-Host "✓ Agent configuration found: $agentConfig" -ForegroundColor Green
} else {
    Write-Host "○ Agent configuration not found (default config will be used)" -ForegroundColor Yellow
}

# Test 2: Check dependencies
Write-Host "`n2. Checking Dependencies..." -ForegroundColor Yellow
$vendorPath = Join-Path $PSScriptRoot "vendor\clamscan.exe"
if (Test-Path $vendorPath) {
    Write-Host "✓ ClamAV antivirus engine found" -ForegroundColor Green
} else {
    Write-Host "✗ ClamAV antivirus engine not found" -ForegroundColor Red
}

# Test 3: Test status command
Write-Host "`n3. Testing Status Command..." -ForegroundColor Yellow
try {
    $statusOutput = & $scriptPath -Action status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Status command executed successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠ Status command completed with warnings" -ForegroundColor Yellow
    }
    
    # Show last 10 lines of status output
    if ($statusOutput) {
        Write-Host "Status output preview:" -ForegroundColor Gray
        $statusOutput | Select-Object -Last 10 | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "✗ Status command failed: $($_.Exception.Message)" -ForegroundColor Red
}

if ($StatusOnly) {
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Status test completed. Use -FullTest for complete verification." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    exit 0
}

# Test 4: Test start command (if FullTest)
if ($FullTest) {
    Write-Host "`n4. Testing Agent Start Command..." -ForegroundColor Yellow
    Write-Host "Note: This will actually start the agent service" -ForegroundColor Yellow
    
    $response = Read-Host "Continue with start test? (y/N)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        try {
            Write-Host "Starting agent service..." -ForegroundColor Yellow
            $startOutput = & $scriptPath -Action start 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ Start command executed successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠ Start command completed with issues" -ForegroundColor Yellow
            }
            
            # Show output
            if ($startOutput) {
                Write-Host "Start command output:" -ForegroundColor Gray
                $startOutput | ForEach-Object {
                    Write-Host "  $_" -ForegroundColor Gray
                }
            }
            
            # Wait a moment and check status again
            Start-Sleep -Seconds 3
            Write-Host "`nChecking post-start status..." -ForegroundColor Yellow
            $postStatusOutput = & $scriptPath -Action status 2>&1
            if ($postStatusOutput) {
                Write-Host "Post-start status:" -ForegroundColor Gray
                $postStatusOutput | Select-Object -Last 15 | ForEach-Object {
                    Write-Host "  $_" -ForegroundColor Gray
                }
            }
        }
        catch {
            Write-Host "✗ Start command failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "○ Start test skipped by user" -ForegroundColor Yellow
    }
}

Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "        Agent Startup Verification Complete" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Summary
Write-Host "`nSummary:" -ForegroundColor White
Write-Host "• RiskNoX-Control.ps1 provides comprehensive agent management" -ForegroundColor White
Write-Host "• Use '.\RiskNoX-Control.ps1 -Action start' to start the agent" -ForegroundColor White
Write-Host "• Use '.\RiskNoX-Control.ps1 -Action status' to check status" -ForegroundColor White
Write-Host "• Agent includes antivirus, web protection, and manager communication" -ForegroundColor White
Write-Host "• All security features are integrated into single startup command" -ForegroundColor White

Write-Host "`nQuick Commands:" -ForegroundColor Cyan
Write-Host "  Start Agent:   .\RiskNoX-Control.ps1 -Action start" -ForegroundColor Green
Write-Host "  Check Status:  .\RiskNoX-Control.ps1 -Action status" -ForegroundColor Green
Write-Host "  Stop Agent:    .\RiskNoX-Control.ps1 -Action stop" -ForegroundColor Green
Write-Host "  Scan Files:    .\RiskNoX-Control.ps1 -Action scan -Path 'C:\Path\To\Scan'" -ForegroundColor Green
Write-Host "  Block URL:     .\RiskNoX-Control.ps1 -Action block -Url 'malicious-site.com'" -ForegroundColor Green