#Requires -Version 7.0

# Test script to isolate the Start-AgentService function issue

Write-Host "Testing function definition..." -ForegroundColor Green

function Test-Function {
    Write-Host "Test function works" -ForegroundColor Green
    return $true
}

function Start-AgentService {
    Write-Host "Start-AgentService function called" -ForegroundColor Green
    return $true
}

# Test if functions are available
Write-Host "Testing Test-Function..." -ForegroundColor Yellow
if (Get-Command Test-Function -ErrorAction SilentlyContinue) {
    Write-Host "✓ Test-Function is available" -ForegroundColor Green
    Test-Function
} else {
    Write-Host "✗ Test-Function not found" -ForegroundColor Red
}

Write-Host "Testing Start-AgentService..." -ForegroundColor Yellow
if (Get-Command Start-AgentService -ErrorAction SilentlyContinue) {
    Write-Host "✓ Start-AgentService is available" -ForegroundColor Green
    Start-AgentService
} else {
    Write-Host "✗ Start-AgentService not found" -ForegroundColor Red
}

Write-Host "Test completed" -ForegroundColor Cyan