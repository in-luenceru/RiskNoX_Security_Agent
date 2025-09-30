#!/usr/bin/env pwsh
# Comprehensive Patch Management System Verification
# Tests all components of the comprehensive Windows Update control system

param(
    [string]$BackendUrl = "http://localhost:5000",
    [string]$AdminUsername = "admin",
    [string]$AdminPassword = "RiskNoX2024!",
    [switch]$Detailed = $false
)

$ErrorActionPreference = "Continue"
Write-Host "=== RiskNoX Comprehensive Patch Management System Verification ===" -ForegroundColor Cyan
Write-Host "Backend URL: $BackendUrl" -ForegroundColor Green
Write-Host "Testing comprehensive Windows Update control capabilities..." -ForegroundColor Yellow
Write-Host ""

# Color functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "⚠️  $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Info { param($Message) Write-Host "ℹ️  $Message" -ForegroundColor Cyan }

# Test results tracking
$TestResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Warnings = 0
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [bool]$RequiresAuth = $false
    )
    
    $TestResults.Total++
    Write-Host "Testing: $Name" -ForegroundColor White
    
    try {
        $uri = "$BackendUrl$Endpoint"
        $requestParams = @{
            Uri = $uri
            Method = $Method
            Headers = $Headers
            TimeoutSec = 30
        }
        
        if ($Body) {
            $requestParams.Body = $Body
            $requestParams.ContentType = "application/json"
        }
        
        $response = Invoke-RestMethod @requestParams
        
        if ($response) {
            Write-Success "$Name - Response received"
            if ($Detailed) {
                Write-Host "Response: $($response | ConvertTo-Json -Depth 2)" -ForegroundColor Gray
            }
            $TestResults.Passed++
            return $response
        } else {
            Write-Warning "$Name - Empty response"
            $TestResults.Warnings++
            return $null
        }
    } catch {
        Write-Error "$Name - Failed: $($_.Exception.Message)"
        $TestResults.Failed++
        return $null
    }
}

# 1. Test Backend Connectivity
Write-Host "`n1. Testing Backend Connectivity..." -ForegroundColor Magenta
Test-Endpoint -Name "Backend Health Check" -Endpoint "/api/system/status"

# 2. Test Authentication
Write-Host "`n2. Testing Authentication..." -ForegroundColor Magenta
$authBody = @{
    username = $AdminUsername
    password = $AdminPassword
} | ConvertTo-Json

$authResponse = Test-Endpoint -Name "Admin Authentication" -Endpoint "/api/auth/login" -Method "POST" -Body $authBody

$authHeaders = @{}
if ($authResponse -and $authResponse.token) {
    $authHeaders = @{ "Authorization" = "Bearer $($authResponse.token)" }
    Write-Success "Authentication token obtained"
} else {
    Write-Error "Failed to obtain authentication token"
}

# 3. Test Basic Patch Management APIs
Write-Host "`n3. Testing Basic Patch Management APIs..." -ForegroundColor Magenta
Test-Endpoint -Name "Get Patch Information" -Endpoint "/api/patch-management/info"
Test-Endpoint -Name "Check for Updates" -Endpoint "/api/patch-management/updates/check" -Method "POST" -Headers $authHeaders -RequiresAuth $true

# 4. Test Comprehensive Windows Update Blocking
Write-Host "`n4. Testing Comprehensive Windows Update Control..." -ForegroundColor Magenta
Test-Endpoint -Name "Get Control Status" -Endpoint "/api/patch-management/control-status"
Test-Endpoint -Name "Verify Control Status" -Endpoint "/api/patch-management/verify-control" -Method "POST" -Headers $authHeaders -RequiresAuth $true

# Only test comprehensive blocking if user confirms (requires admin rights and system changes)
$blockingConsent = Read-Host "`n⚠️  Test comprehensive Windows Update blocking? This will modify system settings (y/N)"
if ($blockingConsent -eq 'y' -or $blockingConsent -eq 'Y') {
    Write-Warning "Testing comprehensive blocking - this will modify system registry and services!"
    Test-Endpoint -Name "Implement Comprehensive Blocking" -Endpoint "/api/patch-management/comprehensive-block" -Method "POST" -Headers $authHeaders -RequiresAuth $true
} else {
    Write-Info "Skipping comprehensive blocking test (user declined)"
}

# 5. Test Policy Management
Write-Host "`n5. Testing Policy Management..." -ForegroundColor Magenta
Test-Endpoint -Name "Check Compliance" -Endpoint "/api/patch-management/compliance/check" -Headers $authHeaders

$policyConsent = Read-Host "`n⚠️  Test policy enforcement? This will modify Windows Update policies (y/N)"
if ($policyConsent -eq 'y' -or $policyConsent -eq 'Y') {
    Test-Endpoint -Name "Enforce Policies" -Endpoint "/api/patch-management/policies/enforce" -Method "POST" -Headers $authHeaders -RequiresAuth $true
} else {
    Write-Info "Skipping policy enforcement test (user declined)"
}

# 6. Test Update Installation
Write-Host "`n6. Testing Update Installation..." -ForegroundColor Magenta
$installConsent = Read-Host "`n⚠️  Test update installation? This may install actual Windows updates (y/N)"
if ($installConsent -eq 'y' -or $installConsent -eq 'Y') {
    Test-Endpoint -Name "Install All Updates" -Endpoint "/api/patch-management/install" -Method "POST" -Headers $authHeaders -RequiresAuth $true
    
    # Test specific update installation with a dummy ID
    $specificUpdateBody = @{
        update_id = "TEST-UPDATE-ID"
    } | ConvertTo-Json
    Test-Endpoint -Name "Install Specific Update" -Endpoint "/api/patch-management/install-specific" -Method "POST" -Headers $authHeaders -Body $specificUpdateBody -RequiresAuth $true
} else {
    Write-Info "Skipping update installation tests (user declined)"
}

# 7. Test Service Management
Write-Host "`n7. Testing Service Management..." -ForegroundColor Magenta
$serviceConsent = Read-Host "`n⚠️  Test Windows Update service reset? This will restart the service (y/N)"
if ($serviceConsent -eq 'y' -or $serviceConsent -eq 'Y') {
    Test-Endpoint -Name "Reset Update Service" -Endpoint "/api/patch-management/service/reset" -Method "POST" -Headers $authHeaders -RequiresAuth $true
} else {
    Write-Info "Skipping service reset test (user declined)"
}

# 8. Test Web Interface Endpoints
Write-Host "`n8. Testing Web Interface..." -ForegroundColor Magenta
try {
    $webResponse = Invoke-WebRequest -Uri "$BackendUrl/" -TimeoutSec 30
    if ($webResponse.StatusCode -eq 200) {
        Write-Success "Web interface accessible"
        $TestResults.Passed++
    } else {
        Write-Warning "Web interface returned status code: $($webResponse.StatusCode)"
        $TestResults.Warnings++
    }
    $TestResults.Total++
} catch {
    Write-Error "Web interface not accessible: $($_.Exception.Message)"
    $TestResults.Failed++
    $TestResults.Total++
}

# 9. Test PowerShell Integration
Write-Host "`n9. Testing PowerShell Integration..." -ForegroundColor Magenta
$psModulePath = ".\scripts\PatchManagement.ps1"
if (Test-Path $psModulePath) {
    Write-Success "PowerShell module found"
    try {
        . $psModulePath
        if (Get-Command "Get-WindowsUpdateInfo" -ErrorAction SilentlyContinue) {
            Write-Success "PowerShell functions loaded successfully"
            $TestResults.Passed++
        } else {
            Write-Warning "PowerShell functions not loaded properly"
            $TestResults.Warnings++
        }
        $TestResults.Total++
    } catch {
        Write-Error "PowerShell module loading failed: $($_.Exception.Message)"
        $TestResults.Failed++
        $TestResults.Total++
    }
} else {
    Write-Error "PowerShell module not found at $psModulePath"
    $TestResults.Failed++
    $TestResults.Total++
}

# 10. Test Registry-based Controls
Write-Host "`n10. Testing Registry-based Controls..." -ForegroundColor Magenta
Write-Info "Checking current Windows Update registry settings..."

$registryTests = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; Expected = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions"; Expected = 2 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Expected = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "SetDisableUXWUAccess"; Expected = 1 }
)

foreach ($regTest in $registryTests) {
    $TestResults.Total++
    try {
        $value = Get-ItemProperty -Path $regTest.Path -Name $regTest.Name -ErrorAction Stop
        if ($value.($regTest.Name) -eq $regTest.Expected) {
            Write-Success "Registry value $($regTest.Name) correctly set to $($regTest.Expected)"
            $TestResults.Passed++
        } else {
            Write-Warning "Registry value $($regTest.Name) is $($value.($regTest.Name)), expected $($regTest.Expected)"
            $TestResults.Warnings++
        }
    } catch {
        Write-Info "Registry value $($regTest.Name) not set (this is normal if blocking not yet implemented)"
        $TestResults.Warnings++
    }
}

# 11. Test Windows Update Service Status
Write-Host "`n11. Testing Windows Update Service Status..." -ForegroundColor Magenta
$TestResults.Total++
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
    Write-Success "Windows Update service status: $($wuService.Status)"
    if ($wuService.Status -eq "Stopped") {
        Write-Info "Service is stopped (this may be expected if comprehensive blocking is active)"
    }
    $TestResults.Passed++
} catch {
    Write-Error "Failed to check Windows Update service: $($_.Exception.Message)"
    $TestResults.Failed++
}

# 12. Test Network Connectivity for Updates
Write-Host "`n12. Testing Network Connectivity..." -ForegroundColor Magenta
$TestResults.Total++
try {
    $connectTest = Test-NetConnection -ComputerName "update.microsoft.com" -Port 80 -WarningAction SilentlyContinue
    if ($connectTest.TcpTestSucceeded) {
        Write-Success "Network connectivity to Microsoft Update servers available"
        $TestResults.Passed++
    } else {
        Write-Warning "Network connectivity to Microsoft Update servers blocked or unavailable"
        $TestResults.Warnings++
    }
} catch {
    Write-Warning "Network connectivity test failed: $($_.Exception.Message)"
    $TestResults.Warnings++
}

# Final Results Summary
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "COMPREHENSIVE PATCH MANAGEMENT SYSTEM TEST RESULTS" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan

Write-Host "Total Tests: $($TestResults.Total)" -ForegroundColor White
Write-Success "Passed: $($TestResults.Passed)"
Write-Warning "Warnings: $($TestResults.Warnings)"
Write-Error "Failed: $($TestResults.Failed)"

$successRate = [math]::Round(($TestResults.Passed / $TestResults.Total) * 100, 1)
Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 60) { "Yellow" } else { "Red" })

Write-Host "`nSYSTEM STATUS SUMMARY:" -ForegroundColor Cyan
if ($TestResults.Failed -eq 0) {
    if ($TestResults.Warnings -eq 0) {
        Write-Success "🎉 All systems operational! Comprehensive patch management system is fully functional."
    } else {
        Write-Warning "✅ System functional with minor issues. Check warnings above for details."
    }
} else {
    Write-Error "⚠️  System has issues that need attention. Check failed tests above."
}

Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Start the backend server: python backend_server.py" -ForegroundColor White
Write-Host "2. Open web interface: $BackendUrl" -ForegroundColor White
Write-Host "3. Login with admin credentials" -ForegroundColor White
Write-Host "4. Navigate to Patch Management tab" -ForegroundColor White
Write-Host "5. Use Update Control tab for comprehensive Windows Update blocking" -ForegroundColor White
Write-Host "6. Test specific update installation and control verification" -ForegroundColor White

Write-Host "`nDOCUMENTATION:" -ForegroundColor Cyan
Write-Host "- See PATCH_MANAGEMENT_IMPLEMENTATION_COMPLETE.md for detailed implementation notes" -ForegroundColor White
Write-Host "- Check PATCH_MANAGEMENT_DOCUMENTATION.md for usage instructions" -ForegroundColor White
Write-Host "- Review backend_server.py for API endpoint details" -ForegroundColor White

Write-Host ""