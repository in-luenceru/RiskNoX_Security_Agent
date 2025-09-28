# RiskNoX Agent-Manager Quick Start Guide
## Fast Setup for Remote Docker Manager

### 🚀 Quick Setup (15 minutes)

#### 1. Server Setup (Docker Manager)
```bash
# On your server (replace with actual server commands)
cd /opt/risknox-manager/manager

# Create production environment
cat > .env << 'EOF'
POSTGRES_PASSWORD=MySecurePassword123!
REDIS_PASSWORD=MyRedisPassword123!
S3_SECRET_KEY=MyS3SecretKey123!
JWT_SECRET_KEY=MyJWTSecret123!
ADMIN_PASSWORD=AdminPassword123!
MANAGER_PORT=8001
EOF

# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Verify manager is running
curl http://localhost:8001/health
```

#### 2. Agent Setup (Client Device)
```powershell
# On each agent device (Windows PowerShell 7+)
cd C:\Path\To\RiskNoX\Agent

# Replace with your server's IP address
$ManagerUrl = "http://YOUR_SERVER_IP:8001"

# Test connection (verify manager is accessible)
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl $ManagerUrl

# Enroll agent (generates CSR, gets signed certificate)
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $ManagerUrl

# Start agent service
.\RiskNoX-Control.ps1 -Action start

# Verify everything is working
.\RiskNoX-Control.ps1 -Action status
```

**✅ After successful enrollment, these files will be created:**
- `config/agent_info.json` - Agent configuration
- `config/agent.crt` - Agent certificate  
- `config/agent.key` - Agent private key

### 🔧 Common Commands

#### Manager Commands (On Server)
```bash
# Check all services
docker-compose -f docker-compose.prod.yml ps

# View manager logs
docker-compose -f docker-compose.prod.yml logs -f manager

# Restart manager
docker-compose -f docker-compose.prod.yml restart manager

# Stop all services
docker-compose -f docker-compose.prod.yml down

# Update and restart
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

#### Agent Commands (On Client Devices)
```powershell
# Check agent status
.\RiskNoX-Control.ps1 -Action status

# Test manager connection
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://YOUR_SERVER_IP:8001"

# Send command through manager
.\RiskNoX-Control.ps1 -Action send-command -Command "system-info" -ManagerUrl "http://YOUR_SERVER_IP:8001"

# Restart agent
.\RiskNoX-Control.ps1 -Action restart

# View agent logs
Get-Content logs\agent_stderr.log -Tail 20
```

### 🌐 Network Configuration

#### Required Ports
- **8001**: Manager API (Agent → Manager)
- **5432, 6379, 9000-9001**: Internal Docker services

#### Firewall Rules
```bash
# On server (allow agent connections)
sudo ufw allow 8001/tcp

# Test from agent
Test-NetConnection -ComputerName YOUR_SERVER_IP -Port 8001
```

### 🚨 Troubleshooting Quick Fixes

#### Manager Not Responding
```bash
# Check if services are running
docker-compose -f docker-compose.prod.yml ps

# Restart if needed
docker-compose -f docker-compose.prod.yml restart
```

#### Agent Can't Connect
```powershell
# Test network connectivity
Test-NetConnection -ComputerName YOUR_SERVER_IP -Port 8001

# Check firewall on server
# Check if manager is accessible: curl http://YOUR_SERVER_IP:8001/health
```

#### Agent Enrollment Failed
```powershell
# Reset and try again
Remove-Item config\agent_info.json -ErrorAction SilentlyContinue
Remove-Item config\*.crt -ErrorAction SilentlyContinue
Remove-Item config\*.key -ErrorAction SilentlyContinue

# Re-enroll
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://YOUR_SERVER_IP:8001"
```

### 📱 Access Web Interfaces

- **Manager Dashboard**: `http://YOUR_SERVER_IP:8001/admin`
- **Grafana Monitoring**: `http://YOUR_SERVER_IP:3000` (admin/admin)
- **Prometheus**: `http://YOUR_SERVER_IP:9090`

### 📋 Pre-flight Checklist

Before starting:
- [ ] Server has Docker and Docker Compose installed
- [ ] Server firewall allows port 8001
- [ ] Agent device has PowerShell 7+ and Python 3.8+
- [ ] Network connectivity between agent and server
- [ ] Strong passwords set in `.env` file

### 🔄 Deployment Script for Multiple Agents

```powershell
# deploy-multiple-agents.ps1
param(
    [string[]]$ComputerNames,
    [string]$ManagerUrl,
    [string]$AgentPath = "C:\RiskNoX\Agent"
)

foreach ($computer in $ComputerNames) {
    Write-Host "Deploying to $computer..." -ForegroundColor Green
    Invoke-Command -ComputerName $computer -ScriptBlock {
        param($url, $path)
        Set-Location $path
        .\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $url
        .\RiskNoX-Control.ps1 -Action start
    } -ArgumentList $ManagerUrl, $AgentPath
}

# Usage:
# .\deploy-multiple-agents.ps1 -ComputerNames @("PC1", "PC2", "PC3") -ManagerUrl "http://192.168.1.100:8001"
```

### 📞 Need Help?

1. **Check logs**: Manager logs in Docker, Agent logs in `logs/` folder
2. **Test connectivity**: Use `Test-NetConnection` and `curl` commands
3. **Reset configuration**: Remove config files and re-enroll
4. **Verify services**: Use `docker-compose ps` to check manager services

For detailed instructions, see `AGENT_MANAGER_CONNECTION_GUIDE.md`