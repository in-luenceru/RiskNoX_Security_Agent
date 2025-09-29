# Test script to trigger virus scan via Manager API
Write-Host "Testing RiskNoX Manager API for virus scan..." -ForegroundColor Green

# Step 1: Check Manager health
Write-Host "`n1. Checking Manager health..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8001/health" -Method GET
    Write-Host "✓ Manager is healthy: $($health.status)" -ForegroundColor Green
    Write-Host "  Service: $($health.service)" -ForegroundColor Gray
    Write-Host "  Timestamp: $($health.timestamp)" -ForegroundColor Gray
} catch {
    Write-Host "✗ Manager health check failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 2: Get list of agents
Write-Host "`n2. Getting list of agents..." -ForegroundColor Yellow
try {
    $agents = Invoke-RestMethod -Uri "http://localhost:8001/api/v1/agents" -Method GET
    Write-Host "✓ Found $($agents.total) agent(s)" -ForegroundColor Green
    
    if ($agents.total -eq 0) {
        Write-Host "✗ No agents found!" -ForegroundColor Red
        exit 1
    }
    
    foreach ($agent in $agents.agents) {
        Write-Host "  Agent ID: $($agent.agent_id)" -ForegroundColor Gray
        Write-Host "  Hostname: $($agent.hostname)" -ForegroundColor Gray
        Write-Host "  Status: $($agent.status)" -ForegroundColor Gray
        Write-Host "  OS: $($agent.os_type) $($agent.os_version)" -ForegroundColor Gray
        Write-Host "  Last Seen: $($agent.last_seen_at)" -ForegroundColor Gray
    }
    
    $agentId = $agents.agents[0].agent_id
    Write-Host "  Using Agent ID: $agentId" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Failed to get agents: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 3: Check WebSocket connections
Write-Host "`n3. Checking WebSocket connections..." -ForegroundColor Yellow
try {
    $wsStats = Invoke-RestMethod -Uri "http://localhost:8001/ws/stats" -Method GET
    Write-Host "✓ WebSocket stats retrieved" -ForegroundColor Green
    Write-Host "  Total connections: $($wsStats.total_connections)" -ForegroundColor Gray
    Write-Host "  Active agents: $($wsStats.active_agents)" -ForegroundColor Gray
    Write-Host "  Queued messages: $($wsStats.queued_messages)" -ForegroundColor Gray
    
    if ($wsStats.active_agents -eq 0) {
        Write-Host "⚠ Warning: No active agent connections detected" -ForegroundColor Yellow
        Write-Host "  The scan command will be sent but agent may be offline" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Failed to get WebSocket stats: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 4: Trigger virus scan
Write-Host "`n4. Triggering virus scan..." -ForegroundColor Yellow
try {
    $scanRequest = @{
        agent_ids = @($agentId)
        scan_type = "quick"
        options = @{}
    }
    
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    $scanResponse = Invoke-RestMethod -Uri "http://localhost:8001/api/v1/scans/trigger" -Method POST -Body ($scanRequest | ConvertTo-Json) -Headers $headers
    
    if ($scanResponse.success) {
        Write-Host "✓ Scan triggered successfully!" -ForegroundColor Green
        Write-Host "  Successful agents: $($scanResponse.successful_agents)" -ForegroundColor Green
        Write-Host "  Total agents: $($scanResponse.total_agents)" -ForegroundColor Gray
        
        foreach ($cmd in $scanResponse.scan_commands) {
            Write-Host "  Scan Command ID: $($cmd.command_id)" -ForegroundColor Cyan
            Write-Host "  Agent ID: $($cmd.agent_id)" -ForegroundColor Gray
        }
    } else {
        Write-Host "⚠ Scan trigger had issues:" -ForegroundColor Yellow
        Write-Host "  Message: $($scanResponse.message)" -ForegroundColor Yellow
        Write-Host "  Successful agents: $($scanResponse.successful_agents)" -ForegroundColor Gray
        Write-Host "  Failed agents: $($scanResponse.failed_agents.Count)" -ForegroundColor Gray
        
        foreach ($failed in $scanResponse.failed_agents) {
            Write-Host "  Failed Agent: $($failed.agent_id) - $($failed.error)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "✗ Failed to trigger scan: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $responseBody = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseBody)
        $errorDetails = $reader.ReadToEnd()
        Write-Host "  Error details: $errorDetails" -ForegroundColor Red
    }
    exit 1
}

# Step 5: Check scan status (if successful)
if ($scanResponse.success -and $scanResponse.scan_commands.Count -gt 0) {
    Write-Host "`n5. Checking scan status..." -ForegroundColor Yellow
    
    Start-Sleep -Seconds 2  # Wait a moment for the scan to potentially start
    
    try {
        $scansResponse = Invoke-RestMethod -Uri "http://localhost:8001/api/v1/scans" -Method GET
        Write-Host "✓ Retrieved scan list" -ForegroundColor Green
        Write-Host "  Total scans: $($scansResponse.total)" -ForegroundColor Gray
        
        if ($scansResponse.total -gt 0) {
            $latestScan = $scansResponse.items[0]
            Write-Host "  Latest Scan ID: $($latestScan.id)" -ForegroundColor Cyan
            Write-Host "  Status: $($latestScan.status)" -ForegroundColor Gray
            Write-Host "  Scan Type: $($latestScan.scan_type)" -ForegroundColor Gray
            Write-Host "  Started: $($latestScan.started_at)" -ForegroundColor Gray
            Write-Host "  Progress: $($latestScan.progress)%" -ForegroundColor Gray
        }
    } catch {
        Write-Host "⚠ Could not retrieve scan status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "`n✓ API scan test completed!" -ForegroundColor Green
Write-Host "You can monitor scan progress in the manager logs or admin UI at: http://localhost:8080" -ForegroundColor Cyan