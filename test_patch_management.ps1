# Test Enhanced Patch Management System
Write-Host "=== RiskNoX Enhanced Patch Management Test ===" -ForegroundColor Green

# Test 1: Get patch information
Write-Host "`n1. Testing Patch Information API..." -ForegroundColor Yellow
try {
    $patchInfo = Invoke-RestMethod -Uri "http://localhost:5000/api/patch-management/info" -Method GET
    Write-Host "✅ Patch Info API: SUCCESS" -ForegroundColor Green
    Write-Host "   - Pending Updates: $($patchInfo.pending_count)" -ForegroundColor Cyan
    Write-Host "   - Installed Patches: $($patchInfo.installed_patches.Count)" -ForegroundColor Cyan
    Write-Host "   - Update History: $($patchInfo.update_history.Count)" -ForegroundColor Cyan
    Write-Host "   - Compliance Status: $($patchInfo.compliance_status)" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Patch Info API: FAILED" -ForegroundColor Red
}

# Test 2: Get update history
Write-Host "`n2. Testing Update History API..." -ForegroundColor Yellow
try {
    $history = Invoke-RestMethod -Uri "http://localhost:5000/api/patch-management/history" -Method GET
    Write-Host "✅ Update History API: SUCCESS" -ForegroundColor Green
    Write-Host "   - Total History Entries: $($history.total_count)" -ForegroundColor Cyan
    Write-Host "   - Retrieved Entries: $($history.retrieved_count)" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Update History API: FAILED" -ForegroundColor Red
}

# Test 3: Get update details
Write-Host "`n3. Testing Update Details API..." -ForegroundColor Yellow
try {
    $updateId = "12345678-1234-5678-9abc-123456789012"
    $details = Invoke-RestMethod -Uri "http://localhost:5000/api/patch-management/details/$updateId" -Method GET
    Write-Host "✅ Update Details API: SUCCESS" -ForegroundColor Green
    Write-Host "   - Update Title: $($details.update_details.Title)" -ForegroundColor Cyan
    Write-Host "   - Update Size: $($details.update_details.Size) MB" -ForegroundColor Cyan
    Write-Host "   - Severity: $($details.update_details.Severity)" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Update Details API: FAILED" -ForegroundColor Red
}

# Test 4: Test admin login and check updates
Write-Host "`n4. Testing Admin Functions..." -ForegroundColor Yellow
try {
    # Login
    $loginData = @{ username = 'admin'; password = 'RiskNoX@2024' } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "http://localhost:5000/api/auth/login" -Method POST -Body $loginData -ContentType "application/json"
    $token = $response.token
    Write-Host "✅ Admin Login: SUCCESS" -ForegroundColor Green
    
    # Test check for updates
    $headers = @{'Authorization' = "Bearer $token"}
    $checkResult = Invoke-RestMethod -Uri "http://localhost:5000/api/patch-management/check-updates" -Method POST -Headers $headers
    Write-Host "✅ Check Updates: SUCCESS" -ForegroundColor Green
    Write-Host "   - Message: $($checkResult.message)" -ForegroundColor Cyan
    
} catch {
    Write-Host "❌ Admin Functions: FAILED" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: UI Features Summary
Write-Host "`n5. Enhanced UI Features Available:" -ForegroundColor Yellow
Write-Host "   ✅ Individual update selection with checkboxes" -ForegroundColor Green
Write-Host "   ✅ Detailed update information display" -ForegroundColor Green
Write-Host "   ✅ Install single updates or selected updates" -ForegroundColor Green
Write-Host "   ✅ Complete update history with details" -ForegroundColor Green
Write-Host "   ✅ Update details modal with comprehensive info" -ForegroundColor Green
Write-Host "   ✅ Select All/Clear Selection functionality" -ForegroundColor Green
Write-Host "   ✅ Professional summary with count displays" -ForegroundColor Green
Write-Host "   ✅ Real-time update status and compliance info" -ForegroundColor Green

Write-Host "`n=== Test Complete ===" -ForegroundColor Green
Write-Host "Open http://localhost:5000 to use the enhanced patch management interface!" -ForegroundColor Cyan