# RiskNoX Agent-Manager Connection Guide
## Connecting Agents to Remote Docker-hosted Manager

### Overview
This guide provides step-by-step instructions for connecting RiskNoX Agents running on client devices to a RiskNoX Manager hosted in Docker on a remote server. This setup enables centralized security management across multiple devices and networks.

## Architecture Overview
```
┌─────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│   Agent Device 1    │      │   Server (Docker)    │      │   Agent Device 2    │
│   (Windows/Linux)   │─────▶│   Manager + Services │◀─────│   (Windows/Linux)   │
│                     │      │   Port: 8001         │      │                     │
└─────────────────────┘      └──────────────────────┘      └─────────────────────┘
```

## Prerequisites

### Server Requirements (Manager Host)
- **Operating System**: Linux (Ubuntu 20.04+ recommended) or Windows Server
- **Docker**: Docker Engine 20.10+ and Docker Compose v2.0+
- **Hardware**: Minimum 4GB RAM, 20GB storage, 2 CPU cores
- **Network**: Static IP address or domain name
- **Ports**: 8001 (Manager API), 5432 (PostgreSQL), 6379 (Redis), 9000-9001 (MinIO)

### Agent Device Requirements
- **Operating System**: Windows 10/11 or Linux
- **PowerShell**: 7.0+ (for Windows agents)
- **Python**: 3.8+ with pip
- **Network**: Internet connectivity to reach the manager server

## Part 1: Setting Up the Manager on Server

### 1.1 Server Preparation

#### Install Docker and Docker Compose (Ubuntu/Debian)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

#### For Windows Server
```powershell
# Install Docker Desktop for Windows Server or use Docker Engine
# Download from: https://docs.docker.com/desktop/install/windows-install/
```

### 1.2 Deploy Manager with Docker Compose

#### Download and Setup Manager
```bash
# Clone or copy the RiskNoX Manager files to server
cd /opt
sudo mkdir risknox-manager
cd risknox-manager

# Copy your manager files here, then:
cd manager
```

#### Configure Production Environment
Create a `.env` file for production settings:
```bash
# Create production environment file
cat > .env << 'EOF'
# Database Configuration
POSTGRES_DB=risknox_db
POSTGRES_USER=risknox_user
POSTGRES_PASSWORD=YOUR_SECURE_DB_PASSWORD_HERE

# Redis Configuration  
REDIS_PASSWORD=YOUR_REDIS_PASSWORD_HERE

# MinIO S3 Storage
S3_ACCESS_KEY=risknox_storage_access
S3_SECRET_KEY=YOUR_SECURE_S3_SECRET_HERE
S3_BUCKET=risknox-storage

# Manager Configuration
MANAGER_PORT=8001
JWT_SECRET_KEY=YOUR_JWT_SECRET_KEY_HERE
ADMIN_PASSWORD=YOUR_ADMIN_PASSWORD_HERE

# Environment
ENVIRONMENT=production
LOG_LEVEL=INFO
EOF
```

#### Start Manager Services
```bash
# Start all services in production mode
docker-compose -f docker-compose.prod.yml up -d

# Check service status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f manager
```

### 1.3 Configure Firewall and Network

#### Ubuntu/Debian Firewall
```bash
# Allow required ports
sudo ufw allow 8001/tcp  # Manager API
sudo ufw allow 22/tcp    # SSH (if needed)
sudo ufw enable

# Optional: Allow specific IP ranges only
# sudo ufw allow from 192.168.1.0/24 to any port 8001
```

#### Windows Server Firewall
```powershell
# Allow Manager port
New-NetFirewallRule -DisplayName "RiskNoX Manager" -Direction Inbound -Protocol TCP -LocalPort 8001 -Action Allow
```

### 1.4 Verify Manager Installation

```bash
# Test manager health endpoint
curl -X GET http://localhost:8001/health

# Expected response:
# {"status": "healthy", "version": "1.0.0", "timestamp": "..."}
```

## Part 2: Configuring Agent Devices

### 2.1 Prepare Agent Device (Windows)

#### Install Prerequisites
```powershell
# Install PowerShell 7+ (if not already installed)
winget install Microsoft.PowerShell

# Install Python 3.8+
winget install Python.Python.3.11

# Verify installations
python --version
pwsh --version
```

#### Setup Agent Files
```powershell
# Copy RiskNoX Agent files to target location
# Example: C:\RiskNoX\Agent\

# Navigate to agent directory
cd C:\RiskNoX\Agent

# Install Python dependencies
python -m pip install -r requirements.txt
```

### 2.2 Agent Configuration for Remote Manager

#### Method 1: Using RiskNoX-Control.ps1 (Recommended)

##### Test Manager Connectivity
```powershell
# Replace with your server's IP address or domain name
$ManagerIP = "192.168.1.100"  # Example server IP
$ManagerUrl = "http://${ManagerIP}:8001"

# Test connection to manager
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl $ManagerUrl
```

Expected output:
```
✓ Manager is responding
Manager info: {"status": "healthy", "version": "1.0.0"}
```

##### Enroll Agent with Remote Manager
```powershell
# Enroll agent with the remote manager
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $ManagerUrl
```

This process will:
1. Generate a Certificate Signing Request (CSR)
2. Send it to the remote manager
3. Receive a signed certificate
4. Configure agent for secure communication

##### Start Agent Service
```powershell
# Start the enrolled agent
.\RiskNoX-Control.ps1 -Action start
```

#### Method 2: Manual Configuration

##### Create Agent Configuration File
If `config/agent_info.json` doesn't exist, create it:
```powershell
# Create configuration directory if needed
New-Item -ItemType Directory -Path "config" -Force

# Create agent configuration
$config = @{
    agent_id = "agent-$(hostname)"
    manager_url = "http://192.168.1.100:8001"  # Replace with your server IP
    enrolled = $false
} | ConvertTo-Json

$config | Out-File -FilePath "config\agent_info.json" -Encoding UTF8
```

### 2.3 Agent Configuration for Linux Devices

#### Install Prerequisites (Ubuntu/Debian)
```bash
# Update system
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Install PowerShell (for cross-platform compatibility)
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install powershell -y
```

#### Setup and Enroll Linux Agent
```bash
# Navigate to agent directory
cd /opt/risknox-agent

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set manager URL (replace with your server IP)
MANAGER_URL="http://192.168.1.100:8001"

# Test connection (if using PowerShell script)
pwsh -Command ".\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl '$MANAGER_URL'"

# Enroll agent
pwsh -Command ".\RiskNoX-Control.ps1 -Action enroll -ManagerUrl '$MANAGER_URL'"

# Start agent
pwsh -Command ".\RiskNoX-Control.ps1 -Action start"
```

## Part 3: Verification and Management

### 3.1 Verify Agent Connection

#### Check Agent Status
```powershell
# Check overall system status
.\RiskNoX-Control.ps1 -Action status

# Get detailed agent status
.\RiskNoX-Control.ps1 -Action agent-status -ManagerUrl $ManagerUrl
```

#### Test Agent-Manager Communication
```powershell
# Send test command to agent through manager
.\RiskNoX-Control.ps1 -Action send-command -Command "system-info" -ManagerUrl $ManagerUrl
```

### 3.2 Access Web Interfaces

#### Manager Dashboard
- **URL**: `http://[SERVER_IP]:8001/admin`
- **Default Login**: Check your `.env` file for `ADMIN_PASSWORD`

#### Agent Web Interface (if enabled)
- **URL**: `http://[AGENT_IP]:5000`

### 3.3 Managing Multiple Agents

#### Bulk Agent Deployment Script
Create a PowerShell script for deploying to multiple agents:

```powershell
# deploy-agents.ps1
param(
    [string[]]$AgentIPs,
    [string]$ManagerUrl,
    [string]$AgentPath = "C:\RiskNoX\Agent"
)

foreach ($ip in $AgentIPs) {
    Write-Host "Deploying to agent at $ip..." -ForegroundColor Green
    
    # Remote PowerShell session (requires WinRM enabled)
    Invoke-Command -ComputerName $ip -ScriptBlock {
        param($ManagerUrl, $AgentPath)
        
        Set-Location $AgentPath
        .\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl $ManagerUrl
        .\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $ManagerUrl
        .\RiskNoX-Control.ps1 -Action start
    } -ArgumentList $ManagerUrl, $AgentPath
}
```

Usage:
```powershell
.\deploy-agents.ps1 -AgentIPs @("192.168.1.10", "192.168.1.11", "192.168.1.12") -ManagerUrl "http://192.168.1.100:8001"
```

## Part 4: Network Configuration and Security

### 4.1 Network Requirements

#### Required Ports
| Service | Port | Direction | Description |
|---------|------|-----------|-------------|
| Manager API | 8001 | Agent → Manager | Main API communication |
| PostgreSQL | 5432 | Internal only | Database (Docker internal) |
| Redis | 6379 | Internal only | Cache/Queue (Docker internal) |
| MinIO | 9000-9001 | Internal only | File storage (Docker internal) |

#### Firewall Configuration
**Server (Manager) side:**
```bash
# Allow agent connections
sudo ufw allow from [AGENT_NETWORK]/24 to any port 8001
```

**Agent side:**
```powershell
# Usually no inbound rules needed, only outbound to manager
```

### 4.2 Security Best Practices

#### Manager Security
1. **Change Default Passwords**: Update all passwords in `.env` file
2. **Use HTTPS**: Configure SSL/TLS certificates for production
3. **Network Security**: Use VPN or private networks when possible
4. **Regular Updates**: Keep Docker images and system updated

#### Agent Security
1. **Certificate Management**: Certificates are auto-generated during enrollment
2. **Secure Storage**: Agent certificates stored in `config/` directory
3. **Access Control**: Run agent with minimal required privileges

### 4.3 SSL/TLS Configuration (Production)

#### Setup HTTPS with Let's Encrypt
```bash
# Install certbot
sudo apt install certbot -y

# Get certificate (replace yourdomain.com)
sudo certbot certonly --standalone -d yourdomain.com

# Update docker-compose to use SSL
# Add SSL configuration to nginx service
```

## Part 5: Troubleshooting

### 5.1 Common Connection Issues

#### Manager Not Accessible
```bash
# Check if manager is running
docker-compose -f docker-compose.prod.yml ps

# Check manager logs
docker-compose -f docker-compose.prod.yml logs manager

# Test local connectivity
curl -X GET http://localhost:8001/health
```

#### Agent Enrollment Failed
```powershell
# Check network connectivity
Test-NetConnection -ComputerName [SERVER_IP] -Port 8001

# Check agent logs
Get-Content logs\agent_stderr.log -Tail 50
Get-Content logs\enrollment_error.log -ErrorAction SilentlyContinue
```

#### Certificate Issues
```powershell
# Reset agent certificates and re-enroll
Remove-Item config\agent_info.json -ErrorAction SilentlyContinue
Remove-Item config\agent.crt -ErrorAction SilentlyContinue  
Remove-Item config\agent.key -ErrorAction SilentlyContinue

# Re-enroll
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl $ManagerUrl
```

### 5.2 Performance Monitoring

#### Manager Resource Usage
```bash
# Check Docker container resources
docker stats

# Check disk usage
df -h

# Check memory usage
free -h
```

#### Agent Performance
```powershell
# Check agent resource usage
Get-Process -Name "python" | Where-Object {$_.ProcessName -like "*agent*"}

# Check log file sizes
Get-ChildItem logs\ | Select-Object Name, Length
```

### 5.3 Debugging Steps

#### Enable Debug Logging
1. **Manager**: Set `LOG_LEVEL=DEBUG` in `.env` file
2. **Agent**: Update `log_level` in `config/agent_config.xml`

#### Collect Diagnostic Information
```powershell
# Agent diagnostic script
$diagnostics = @{
    timestamp = Get-Date
    agent_status = .\RiskNoX-Control.ps1 -Action status
    network_test = Test-NetConnection -ComputerName [MANAGER_IP] -Port 8001
    config_files = Get-ChildItem config\
    recent_logs = Get-Content logs\agent_stderr.log -Tail 20
}

$diagnostics | ConvertTo-Json | Out-File "diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
```

## Part 6: Advanced Configuration

### 6.1 Load Balancing Multiple Managers

#### Using nginx as Load Balancer
```nginx
upstream risknox_managers {
    server 192.168.1.100:8001;
    server 192.168.1.101:8001;
    server 192.168.1.102:8001;
}

server {
    listen 80;
    location / {
        proxy_pass http://risknox_managers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 6.2 Database Backup and Recovery

#### Automated Backup Script
```bash
#!/bin/bash
# backup-manager.sh

BACKUP_DIR="/backups/risknox"
DB_CONTAINER="manager_postgres_1"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker exec $DB_CONTAINER pg_dump -U risknox_user risknox_db > "$BACKUP_DIR/backup_$DATE.sql"

# Compress backup
gzip "$BACKUP_DIR/backup_$DATE.sql"

# Keep only last 7 days of backups
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
```

### 6.3 Monitoring and Alerting

#### Setup Prometheus Monitoring
The Docker Compose includes Prometheus and Grafana:
- **Prometheus**: `http://[SERVER_IP]:9090`
- **Grafana**: `http://[SERVER_IP]:3000` (admin/admin)

## Conclusion

This guide provides a comprehensive approach to connecting RiskNoX Agents to a remote Docker-hosted Manager. The setup enables:

- **Centralized Management**: Control multiple agents from a single manager
- **Scalability**: Easy addition of new agents across different networks
- **Security**: Encrypted communication using mutual TLS certificates
- **Monitoring**: Built-in monitoring and logging capabilities
- **High Availability**: Optional load balancing and backup strategies

For production deployments, ensure proper security measures including SSL/TLS, strong passwords, network segmentation, and regular security updates.

## Support and Maintenance

### Regular Maintenance Tasks
1. **Weekly**: Check agent connectivity and certificate expiration
2. **Monthly**: Review logs and performance metrics
3. **Quarterly**: Update Docker images and system packages
4. **Annually**: Review and rotate passwords and certificates

### Getting Help
- Check log files in `logs/` directory on both manager and agents
- Review network connectivity between components
- Verify firewall and security group configurations
- Ensure all required ports are accessible

For technical support, collect diagnostic information using the provided scripts and include relevant log files when reporting issues.