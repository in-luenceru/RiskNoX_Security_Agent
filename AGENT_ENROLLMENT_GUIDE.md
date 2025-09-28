# RiskNoX Agent-Manager Enrollment Guide

## Overview
This guide will walk you through enrolling a RiskNoX Agent with the Manager for centralized security management.

## Prerequisites
- PowerShell 7.0 or later
- Administrator privileges (for some operations)
- Python 3.8+ with virtual environment
- Docker (optional, but recommended for manager)

## Step 1: Start the Manager Service

### Option A: Using Docker (Recommended)
```powershell
# Navigate to manager directory
cd manager

# Start all services (PostgreSQL, Redis, MinIO, Manager)
docker-compose up -d

# Check if services are running
docker-compose ps
```

### Option B: Manual Setup (Development)
```powershell
# Navigate to manager directory
cd manager

# Install Python dependencies (if not already done)
pip install -r requirements.txt

# Start the manager manually
python run_manager.py
```

The manager will start on **http://localhost:8001**

## Step 2: Verify Manager is Running

Test the manager connectivity:
```powershell
# Go back to root directory
cd ..

# Test manager connection
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://localhost:8001"
```

Expected output:
```
✓ Manager is responding
Manager info: {"status": "healthy", "version": "1.0.0"}
```

## Step 3: Enroll the Agent

Now enroll your agent with the manager:

```powershell
# Enroll agent with manager
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://localhost:8001"
```

This will:
1. Generate a Certificate Signing Request (CSR)
2. Send it to the manager for approval
3. Receive a signed certificate
4. Configure the agent for secure communication

## Step 4: Start the Agent Service

After successful enrollment, start the agent:

```powershell
# Start the agent service
.\RiskNoX-Control.ps1 -Action start
```

## Step 5: Verify Agent Status

Check that everything is working:

```powershell
# Check overall system status
.\RiskNoX-Control.ps1 -Action status

# Get detailed agent status
.\RiskNoX-Control.ps1 -Action agent-status
```

## Step 6: Access the Web Interface

1. **Manager Dashboard**: http://localhost:8001/admin
2. **Agent Web Interface**: http://localhost:5000 (if running in backend mode)

## Troubleshooting

### Manager Not Starting
```powershell
# Check if required ports are available
netstat -ano | findstr :8001
netstat -ano | findstr :5432
netstat -ano | findstr :6379
```

### Agent Enrollment Failed
```powershell
# Check manager connectivity
curl -X GET http://localhost:8001/health

# Check agent logs
type logs\agent_stderr.log
type logs\enrollment_error.log
```

### Certificate Issues
```powershell
# Reset agent configuration
Remove-Item config\agent_info.json -ErrorAction SilentlyContinue
Remove-Item config\agent.crt -ErrorAction SilentlyContinue
Remove-Item config\agent.key -ErrorAction SilentlyContinue

# Re-enroll
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://localhost:8001"
```

## Advanced Usage

### Remote Manager
If your manager is on a different machine:
```powershell
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://192.168.1.100:8001"
```

### Send Commands to Agent
```powershell
# Send scan command
.\RiskNoX-Control.ps1 -Action send-command -Command "scan C:\Users" -ManagerUrl "http://localhost:8001"

# Send system info command
.\RiskNoX-Control.ps1 -Action send-command -Command "system-info" -ManagerUrl "http://localhost:8001"
```

### Multiple Agents
Each agent needs to be enrolled separately. The manager can handle multiple agents:
1. Run enrollment on each machine
2. Each agent gets a unique certificate
3. Manager tracks all agents in the dashboard

## Security Notes

- **Certificates**: Agent-Manager communication uses mutual TLS (mTLS)
- **Enrollment**: Each agent gets a unique certificate during enrollment
- **Commands**: All commands are encrypted and authenticated
- **Logs**: All activities are logged for audit purposes

## Configuration Files

After enrollment, these files are created:
- `config/agent_info.json` - Agent configuration and manager URL
- `config/agent.crt` - Agent certificate (public key)
- `config/agent.key` - Agent private key
- `logs/enrollment_*.log` - Enrollment process logs

## Next Steps

Once enrolled and running:
1. Configure antivirus scans
2. Set up web blocking rules
3. Configure patch management policies
4. Monitor agent status via web interface
5. Schedule automated security tasks

## Support

For issues:
1. Check logs in the `logs/` directory
2. Verify network connectivity between agent and manager
3. Ensure firewall allows communication on ports 8001 (manager) and 5000 (agent)
4. Check certificate validity and permissions