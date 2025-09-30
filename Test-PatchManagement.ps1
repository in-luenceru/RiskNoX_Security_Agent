# Complete Patch Management System Verification Script
# This script tests all components of the enhanced patch management system

param(
    [Parameter(Mandatory=$false)]
    [switch]$TestBackend,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestPowerShell,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestUI,
    
    [Parameter(Mandatory=$false)]
    [switch]$FullTest
)

$ErrorActionPreference = "Continue"
$TestResults = @()

function Write-TestResult {
    param(
        [string]$Component,
        [string]$Test,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $result = @{
        Component = $Component
        Test = $Test
        Passed = $Passed
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $color = if ($Passed) { "Green" } else { "Red" }
    
    Write-Host "[$status] $Component - $Test" -ForegroundColor $color
    if ($Details) {
        Write-Host "    Details: $Details" -ForegroundColor Gray
    }
}

function Test-PowerShellScript {
    Write-Host "`n=== Testing PowerShell Patch Management Script ===" -ForegroundColor Cyan
    
    $scriptPath = Join-Path $PSScriptRoot "scripts\AdvancedPatchManagement.ps1"
    
    # Test 1: Script file exists
    $exists = Test-Path $scriptPath
    Write-TestResult "PowerShell" "Script File Exists" $exists $scriptPath
    
    if ($exists) {
        # Test 2: Script syntax validation
        try {
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$null)
            Write-TestResult "PowerShell" "Script Syntax Valid" $true
        } catch {
            Write-TestResult "PowerShell" "Script Syntax Valid" $false $_.Exception.Message
        }
        
        # Test 3: Test blocking automatic updates
        try {
            $result = & $scriptPath -Action "BlockAutoUpdates"
            $resultObj = $result | ConvertFrom-Json
            Write-TestResult "PowerShell" "Block Auto Updates" $resultObj.Success $resultObj.Message
        } catch {
            Write-TestResult "PowerShell" "Block Auto Updates" $false $_.Exception.Message
        }
        
        # Test 4: Test getting updates
        try {
            $result = & $scriptPath -Action "GetUpdates"
            $resultObj = $result | ConvertFrom-Json
            Write-TestResult "PowerShell" "Get Available Updates" $resultObj.Success "Found $($resultObj.Count) updates"
        } catch {
            Write-TestResult "PowerShell" "Get Available Updates" $false $_.Exception.Message
        }
        
        # Test 5: Test re-enabling updates
        try {
            $result = & $scriptPath -Action "EnableUpdates"
            $resultObj = $result | ConvertFrom-Json
            Write-TestResult "PowerShell" "Re-enable Updates" $resultObj.Success $resultObj.Message
        } catch {
            Write-TestResult "PowerShell" "Re-enable Updates" $false $_.Exception.Message
        }
    }
}

function Test-BackendAPI {
    Write-Host "`n=== Testing Backend API Endpoints ===" -ForegroundColor Cyan
    
    $backendPath = Join-Path $PSScriptRoot "backend_server.py"
    
    # Test 1: Backend file exists
    $exists = Test-Path $backendPath
    Write-TestResult "Backend" "Server File Exists" $exists $backendPath
    
    if ($exists) {
        # Test 2: Check for required methods
        $content = Get-Content $backendPath -Raw
        
        $requiredMethods = @(
            "block_automatic_updates",
            "block_user_updates", 
            "enable_updates",
            "get_available_updates",
            "install_selected_updates"
        )
        
        foreach ($method in $requiredMethods) {
            $found = $content -match "def $method"
            Write-TestResult "Backend" "Method $method exists" $found
        }
        
        # Test 3: Check for API endpoints
        $requiredEndpoints = @(
            "/api/patch/block-auto",
            "/api/patch/block-user",
            "/api/patch/enable",
            "/api/patch/scan",
            "/api/patch/install"
        )
        
        foreach ($endpoint in $requiredEndpoints) {
            $found = $content -match [regex]::Escape($endpoint)
            Write-TestResult "Backend" "Endpoint $endpoint exists" $found
        }
    }
}

function Test-UIComponents {
    Write-Host "`n=== Testing UI Components ===" -ForegroundColor Cyan
    
    $webPath = Join-Path $PSScriptRoot "web"
    
    # Test 1: Web directory exists
    $exists = Test-Path $webPath
    Write-TestResult "UI" "Web Directory Exists" $exists $webPath
    
    if ($exists) {
        # Test 2: Main HTML file
        $htmlPath = Join-Path $webPath "index.html"
        $htmlExists = Test-Path $htmlPath
        Write-TestResult "UI" "Main HTML File Exists" $htmlExists $htmlPath
        
        if ($htmlExists) {
            $htmlContent = Get-Content $htmlPath -Raw
            
            # Test for enhanced patch management tabs
            $requiredTabs = @(
                "available-updates",
                "pending-updates", 
                "installed-patches",
                "update-history",
                "policy-management",
                "update-control"
            )
            
            foreach ($tab in $requiredTabs) {
                $found = $htmlContent -match $tab
                Write-TestResult "UI" "Tab '$tab' exists" $found
            }
            
            # Test for JavaScript inclusions
            $jsFiles = @(
                "patch-management-functions.js",
                "patch-management-extensions.js"
            )
            
            foreach ($jsFile in $jsFiles) {
                $found = $htmlContent -match [regex]::Escape($jsFile)
                Write-TestResult "UI" "JavaScript '$jsFile' referenced" $found
            }
        }
        
        # Test 3: JavaScript files
        $jsPath1 = Join-Path $webPath "patch-management-functions.js"
        $js1Exists = Test-Path $jsPath1
        Write-TestResult "UI" "Patch Functions JS Exists" $js1Exists $jsPath1
        
        $jsPath2 = Join-Path $webPath "patch-management-extensions.js"
        $js2Exists = Test-Path $jsPath2
        Write-TestResult "UI" "Patch Extensions JS Exists" $js2Exists $jsPath2
        
        if ($js1Exists) {
            $jsContent = Get-Content $jsPath1 -Raw
            $requiredFunctions = @(
                "toggleUpdateSelection",
                "blockAutomaticUpdates",
                "installSelectedUpdates",
                "refreshPatchData"
            )
            
            foreach ($func in $requiredFunctions) {
                $found = $jsContent -match "function $func"
                Write-TestResult "UI" "Function '$func' exists" $found
            }
        }
        
        if ($js2Exists) {
            $extContent = Get-Content $jsPath2 -Raw
            $requiredMethods = @(
                "displayAvailableUpdates",
                "displayInstalledPatches",
                "updateControlStatus",
                "getSeverityClass"
            )
            
            foreach ($method in $requiredMethods) {
                $found = $extContent -match $method
                Write-TestResult "UI" "Extension method '$method' exists" $found
            }
        }
    }
}

function Test-SystemIntegration {
    Write-Host "`n=== Testing System Integration ===" -ForegroundColor Cyan
    
    # Test 1: Windows Update service status
    try {
        $service = Get-Service -Name "wuauserv" -ErrorAction Stop
        Write-TestResult "Integration" "Windows Update Service Found" $true $service.Status
    } catch {
        Write-TestResult "Integration" "Windows Update Service Found" $false $_.Exception.Message
    }
    
    # Test 2: Registry access for update control
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $canAccess = Test-Path $regPath -ErrorAction SilentlyContinue
        if (-not $canAccess) {
            # Try to create it to test permissions
            New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            $canAccess = Test-Path $regPath
        }
        Write-TestResult "Integration" "Registry Access Available" $canAccess $regPath
    } catch {
        Write-TestResult "Integration" "Registry Access Available" $false $_.Exception.Message
    }
    
    # Test 3: PowerShell execution policy
    $policy = Get-ExecutionPolicy
    $allowsScripts = $policy -in @("Unrestricted", "RemoteSigned", "Bypass")
    Write-TestResult "Integration" "PowerShell Execution Allowed" $allowsScripts "Current policy: $policy"
    
    # Test 4: Administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-TestResult "Integration" "Administrative Privileges" $isAdmin
}

function Show-TestSummary {
    Write-Host "`n=== Test Summary ===" -ForegroundColor Yellow
    
    $totalTests = $TestResults.Count
    $passedTests = ($TestResults | Where-Object { $_.Passed }).Count
    $failedTests = $totalTests - $passedTests
    $successRate = if ($totalTests -gt 0) { [math]::Round(($passedTests / $totalTests) * 100, 2) } else { 0 }
    
    Write-Host "Total Tests: $totalTests" -ForegroundColor White
    Write-Host "Passed: $passedTests" -ForegroundColor Green
    Write-Host "Failed: $failedTests" -ForegroundColor Red
    Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 60) { "Yellow" } else { "Red" })
    
    if ($failedTests -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        $TestResults | Where-Object { -not $_.Passed } | ForEach-Object {
            Write-Host "  - $($_.Component): $($_.Test)" -ForegroundColor Red
            if ($_.Details) {
                Write-Host "    $($_.Details)" -ForegroundColor Gray
            }
        }
    }
    
    # Generate recommendations
    Write-Host "`n=== Recommendations ===" -ForegroundColor Cyan
    
    $failedComponents = $TestResults | Where-Object { -not $_.Passed } | Group-Object Component
    
    foreach ($component in $failedComponents) {
        switch ($component.Name) {
            "PowerShell" {
                Write-Host "- Check PowerShell script syntax and permissions" -ForegroundColor Yellow
                Write-Host "- Ensure script execution policy allows running scripts" -ForegroundColor Yellow
            }
            "Backend" {
                Write-Host "- Verify backend_server.py has all required methods" -ForegroundColor Yellow
                Write-Host "- Check Python dependencies are installed" -ForegroundColor Yellow
            }
            "UI" {
                Write-Host "- Ensure all JavaScript files are properly referenced" -ForegroundColor Yellow
                Write-Host "- Validate HTML structure and CSS classes" -ForegroundColor Yellow
            }
            "Integration" {
                Write-Host "- Run PowerShell as Administrator for full functionality" -ForegroundColor Yellow
                Write-Host "- Verify Windows Update service is available" -ForegroundColor Yellow
            }
        }
    }
    
    if ($successRate -ge 90) {
        Write-Host "`n✅ Patch Management System is ready for production!" -ForegroundColor Green
    } elseif ($successRate -ge 70) {
        Write-Host "`n⚠️ Patch Management System is mostly functional but needs attention." -ForegroundColor Yellow
    } else {
        Write-Host "`n❌ Patch Management System requires significant fixes before use." -ForegroundColor Red
    }
}

# Main execution
Write-Host "RiskNoX Patch Management System Verification" -ForegroundColor Magenta
Write-Host "=============================================" -ForegroundColor Magenta

if ($FullTest -or $TestPowerShell) {
    Test-PowerShellScript
}

if ($FullTest -or $TestBackend) {
    Test-BackendAPI
}

if ($FullTest -or $TestUI) {
    Test-UIComponents
}

if ($FullTest) {
    Test-SystemIntegration
}

if (-not ($TestBackend -or $TestPowerShell -or $TestUI)) {
    # Default: run all tests
    Test-PowerShellScript
    Test-BackendAPI
    Test-UIComponents
    Test-SystemIntegration
}

Show-TestSummary

# Export results to JSON for programmatic access
$resultsPath = Join-Path $PSScriptRoot "patch_management_test_results.json"
$TestResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultsPath -Encoding UTF8
Write-Host "`nDetailed results exported to: $resultsPath" -ForegroundColor Gray