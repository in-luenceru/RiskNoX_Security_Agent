# Production Configuration Template for Remote Manager

## Manager Server Configuration (.env file)

Create this file in your `manager/` directory on the server:

```bash
# manager/.env

# ===========================================
# DATABASE CONFIGURATION
# ===========================================
POSTGRES_DB=risknox_production
POSTGRES_USER=risknox_admin
POSTGRES_PASSWORD=CHANGE_THIS_SECURE_DB_PASSWORD_123!
POSTGRES_PORT=5432

# ===========================================
# REDIS CONFIGURATION
# ===========================================
REDIS_PASSWORD=CHANGE_THIS_REDIS_PASSWORD_123!
REDIS_PORT=6379

# ===========================================
# MINIO S3 STORAGE CONFIGURATION
# ===========================================
S3_ACCESS_KEY=risknox_storage_admin
S3_SECRET_KEY=CHANGE_THIS_S3_SECRET_KEY_123!
S3_BUCKET=risknox-production-storage
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001

# ===========================================
# MANAGER APPLICATION CONFIGURATION
# ===========================================
MANAGER_PORT=8001
JWT_SECRET_KEY=CHANGE_THIS_JWT_SECRET_KEY_VERY_LONG_AND_SECURE_123!
ADMIN_PASSWORD=CHANGE_THIS_ADMIN_PASSWORD_123!

# ===========================================
# ENVIRONMENT SETTINGS
# ===========================================
ENVIRONMENT=production
LOG_LEVEL=INFO

# ===========================================
# OPTIONAL: SSL/HTTPS CONFIGURATION
# ===========================================
# SSL_CERT_PATH=/etc/ssl/certs/risknox.crt
# SSL_KEY_PATH=/etc/ssl/private/risknox.key
# FORCE_HTTPS=true
```

## Server Deployment Script

Save as `deploy-manager.sh` on your server:

```bash
#!/bin/bash
# deploy-manager.sh - Production Manager Deployment Script

set -e

# Configuration
INSTALL_DIR="/opt/risknox-manager"
BACKUP_DIR="/opt/risknox-backups"
SERVICE_USER="risknox"

echo "🚀 Starting RiskNoX Manager Production Deployment..."

# Create directories
sudo mkdir -p $INSTALL_DIR
sudo mkdir -p $BACKUP_DIR
sudo mkdir -p /var/log/risknox

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    sudo useradd -r -s /bin/false $SERVICE_USER
    echo "✅ Created service user: $SERVICE_USER"
fi

# Set permissions
sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
sudo chown -R $SERVICE_USER:$SERVICE_USER $BACKUP_DIR

# Copy manager files (adjust path as needed)
echo "📁 Copying manager files..."
sudo cp -r manager/ $INSTALL_DIR/
sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $SERVICE_USER
    rm get-docker.sh
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "📦 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# Configure firewall
echo "🔥 Configuring firewall..."
sudo ufw allow 8001/tcp comment "RiskNoX Manager API"
sudo ufw allow 22/tcp comment "SSH"
sudo ufw --force enable

# Create systemd service
cat > /tmp/risknox-manager.service << 'EOF'
[Unit]
Description=RiskNoX Manager Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/risknox-manager/manager
ExecStart=/usr/local/bin/docker-compose -f docker-compose.prod.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.prod.yml down
User=risknox
Group=risknox

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/risknox-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable risknox-manager

echo "✅ RiskNoX Manager deployment completed!"
echo ""
echo "📋 Next Steps:"
echo "1. Edit $INSTALL_DIR/manager/.env with your configuration"
echo "2. Start the service: sudo systemctl start risknox-manager"
echo "3. Check status: sudo systemctl status risknox-manager"
echo "4. View logs: docker-compose -f $INSTALL_DIR/manager/docker-compose.prod.yml logs -f"
echo ""
echo "🌐 Manager will be available at: http://$(hostname -I | awk '{print $1}'):8001"
```

## Agent Configuration Template

Save as `agent-config-template.ps1` on each agent device:

```powershell
# agent-config-template.ps1
# Agent Configuration Script for Remote Manager

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,
    
    [Parameter(Mandatory=$false)]
    [int]$ManagerPort = 8001,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME
)

$ManagerUrl = "http://${ManagerIP}:${ManagerPort}"

Write-Host "🔧 Configuring RiskNoX Agent for Remote Manager..." -ForegroundColor Green
Write-Host "Manager URL: $ManagerUrl" -ForegroundColor Cyan
Write-Host "Agent Name: $AgentName" -ForegroundColor Cyan

# Test prerequisites
Write-Host "`n📋 Checking prerequisites..." -ForegroundColor Yellow

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "PowerShell 7.0+ required. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "Python not found. Please install Python 3.8+"
    exit 1
}

# Check network connectivity
Write-Host "`n🌐 Testing network connectivity..." -ForegroundColor Yellow
try {
    $connection = Test-NetConnection -ComputerName $ManagerIP -Port $ManagerPort -WarningAction SilentlyContinue
    if ($connection.TcpTestSucceeded) {
        Write-Host "✅ Network connectivity to manager successful" -ForegroundColor Green
    } else {
        Write-Error "❌ Cannot connect to manager at ${ManagerIP}:${ManagerPort}"
        exit 1
    }
} catch {
    Write-Error "❌ Network test failed: $_"
    exit 1
}

# Test manager health endpoint
Write-Host "`n🏥 Testing manager health..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$ManagerUrl/health" -TimeoutSec 10
    Write-Host "✅ Manager is healthy: $($response.status)" -ForegroundColor Green
} catch {
    Write-Error "❌ Manager health check failed: $_"
    exit 1
}

# Create agent configuration
Write-Host "`n⚙️ Creating agent configuration..." -ForegroundColor Yellow

# Ensure config directory exists
New-Item -ItemType Directory -Path "config" -Force | Out-Null

# Create agent info configuration
$agentConfig = @{
    agent_id = "agent-$AgentName"
    agent_name = $AgentName
    manager_url = $ManagerUrl
    enrolled = $false
    created_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json -Depth 3

$agentConfig | Out-File -FilePath "config\agent_info.json" -Encoding UTF8 -Force

Write-Host "✅ Agent configuration created" -ForegroundColor Green

# Install Python dependencies
Write-Host "`n📦 Installing Python dependencies..." -ForegroundColor Yellow
try {
    pip install -r requirements.txt --quiet
    Write-Host "✅ Python dependencies installed" -ForegroundColor Green
} catch {
    Write-Warning "⚠️ Python dependencies installation had issues: $_"
}

# Enroll agent
Write-Host "`n🔐 Enrolling agent with manager..." -ForegroundColor Yellow
try {
    .\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $ManagerUrl
    Write-Host "✅ Agent enrollment completed" -ForegroundColor Green
} catch {
    Write-Error "❌ Agent enrollment failed: $_"
    exit 1
}

# Start agent
Write-Host "`n🚀 Starting agent service..." -ForegroundColor Yellow
try {
    .\RiskNoX-Control.ps1 -Action start
    Write-Host "✅ Agent service started" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to start agent service: $_"
    exit 1
}

# Verify status
Write-Host "`n📊 Verifying agent status..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
.\RiskNoX-Control.ps1 -Action status

Write-Host "`n🎉 Agent configuration completed successfully!" -ForegroundColor Green
Write-Host "📱 Manager Dashboard: $ManagerUrl/admin" -ForegroundColor Cyan
Write-Host "📋 Agent Status: .\RiskNoX-Control.ps1 -Action status" -ForegroundColor Cyan
```

## Batch Agent Deployment Script

Save as `deploy-agents-batch.ps1` for deploying to multiple computers:

```powershell
# deploy-agents-batch.ps1
# Batch deployment script for multiple agents

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,
    
    [Parameter(Mandatory=$true)]
    [string[]]$ComputerNames,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentPath = "C:\RiskNoX\Agent",
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential
)

$ManagerUrl = "http://${ManagerIP}:8001"
$successCount = 0
$failCount = 0
$results = @()

Write-Host "🚀 Starting batch agent deployment..." -ForegroundColor Green
Write-Host "Manager: $ManagerUrl" -ForegroundColor Cyan
Write-Host "Agents: $($ComputerNames.Count) computers" -ForegroundColor Cyan
Write-Host "Path: $AgentPath" -ForegroundColor Cyan

foreach ($computer in $ComputerNames) {
    Write-Host "`n🖥️ Deploying to $computer..." -ForegroundColor Yellow
    
    try {
        $session = if ($Credential) {
            New-PSSession -ComputerName $computer -Credential $Credential -ErrorAction Stop
        } else {
            New-PSSession -ComputerName $computer -ErrorAction Stop
        }
        
        # Copy configuration script
        Copy-Item -Path "agent-config-template.ps1" -Destination $AgentPath -ToSession $session -Force
        
        # Execute deployment
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($ManagerIP, $AgentPath)
            
            Set-Location $AgentPath
            .\agent-config-template.ps1 -ManagerIP $ManagerIP
            
        } -ArgumentList $ManagerIP, $AgentPath
        
        Remove-PSSession $session
        
        $results += [PSCustomObject]@{
            Computer = $computer
            Status = "Success"
            Message = "Deployment completed successfully"
        }
        
        $successCount++
        Write-Host "✅ $computer - Success" -ForegroundColor Green
        
    } catch {
        $results += [PSCustomObject]@{
            Computer = $computer
            Status = "Failed"
            Message = $_.Exception.Message
        }
        
        $failCount++
        Write-Host "❌ $computer - Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n📊 Deployment Summary:" -ForegroundColor Cyan
Write-Host "✅ Successful: $successCount" -ForegroundColor Green
Write-Host "❌ Failed: $failCount" -ForegroundColor Red

# Export results
$results | Export-Csv -Path "deployment-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
Write-Host "📄 Results exported to deployment-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -ForegroundColor Cyan

# Usage Examples:
# .\deploy-agents-batch.ps1 -ManagerIP "192.168.1.100" -ComputerNames @("PC1", "PC2", "PC3")
# .\deploy-agents-batch.ps1 -ManagerIP "192.168.1.100" -ComputerNames @("PC1", "PC2") -Credential (Get-Credential)
```

## Security Hardening Checklist

```bash
# security-hardening.sh
# Security hardening script for production manager

#!/bin/bash

echo "🔒 Applying security hardening..."

# Update system
sudo apt update && sudo apt upgrade -y

# Configure fail2ban
sudo apt install fail2ban -y
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Secure SSH
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Configure automatic security updates
sudo apt install unattended-upgrades -y
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades

# Set up log rotation
cat > /etc/logrotate.d/risknox << 'EOF'
/var/log/risknox/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
}
EOF

echo "✅ Security hardening completed"
```

## Usage Instructions

1. **On Manager Server:**
   ```bash
   chmod +x deploy-manager.sh security-hardening.sh
   ./deploy-manager.sh
   ./security-hardening.sh
   ```

2. **On Each Agent Device:**
   ```powershell
   .\agent-config-template.ps1 -ManagerIP "YOUR_SERVER_IP"
   ```

3. **For Multiple Agents:**
   ```powershell
   .\deploy-agents-batch.ps1 -ManagerIP "YOUR_SERVER_IP" -ComputerNames @("PC1", "PC2", "PC3")
   ```

Remember to:
- Change all default passwords in the `.env` file
- Update firewall rules based on your network
- Test all connections before production deployment
- Set up regular backups and monitoring