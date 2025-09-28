# RiskNoX Security System - Complete Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the RiskNoX Security System with:
- **Manager**: Centralized server running on Docker with frontend UI
- **Agents**: Distributed clients running on target systems

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    SERVER                       │
│  ┌─────────────────────────────────────────┐   │
│  │          Manager (Docker)               │   │
│  │  ┌─────────────┬─────────────────────┐  │   │
│  │  │  FastAPI    │    Admin UI         │  │   │
│  │  │  Backend    │    (React)          │  │   │
│  │  │  :8001      │    :8080            │  │   │
│  │  └─────────────┴─────────────────────┘  │   │
│  │  ┌─────────────┬─────────────────────┐  │   │
│  │  │ PostgreSQL  │    Redis/MinIO      │  │   │
│  │  │  :5432      │    :6379/:9000      │  │   │
│  │  └─────────────┴─────────────────────┘  │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
                        │
                        │ WebSocket/HTTP API
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
┌───▼────┐          ┌───▼────┐          ┌───▼────┐
│ Agent  │          │ Agent  │          │ Agent  │
│System 1│          │System 2│          │System N│
└────────┘          └────────┘          └────────┘
```

## Part 1: Manager Deployment (Server)

### Prerequisites
- Docker and Docker Compose installed
- Server with minimum 4GB RAM, 2 CPU cores
- Ports 8001, 8080, 5432, 6379, 9000, 9001 available

### Step 1: Prepare Manager Directory

1. Create a dedicated directory on your server:
```bash
mkdir -p /opt/risknox-manager
cd /opt/risknox-manager
```

2. Copy the manager files:
```bash
# Copy entire manager directory to server
scp -r ./manager/* /opt/risknox-manager/
```

### Step 2: Environment Configuration

Create production environment file:
```bash
cp .env.example .env.production
```

Edit `.env.production` with production values:
```env
# Database
DATABASE_URL=postgresql://risknox_user:CHANGE_THIS_PASSWORD@postgres:5432/risknox_db
POSTGRES_DB=risknox_db
POSTGRES_USER=risknox_user
POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD

# Redis
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1

# MinIO S3 Storage
S3_ENDPOINT=http://minio:9000
S3_ACCESS_KEY=CHANGE_THIS_ACCESS_KEY
S3_SECRET_KEY=CHANGE_THIS_SECRET_KEY
S3_BUCKET=risknox-storage

# Security
JWT_SECRET_KEY=CHANGE_THIS_JWT_SECRET
ADMIN_PASSWORD=CHANGE_THIS_ADMIN_PASSWORD

# Application
LOG_LEVEL=INFO
PROMETHEUS_ENABLED=true
ENVIRONMENT=production
```

### Step 3: Production Docker Compose

Create production-ready docker-compose:
```bash
cp docker-compose.yml docker-compose.prod.yml
```

### Step 4: Start Manager Services

```bash
# Start all services
docker-compose -f docker-compose.prod.yml --env-file .env.production up -d

# Check service health
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f manager
```

### Step 5: Initialize Database

```bash
# Run database migrations
docker-compose -f docker-compose.prod.yml exec manager alembic upgrade head

# Create admin user (optional)
docker-compose -f docker-compose.prod.yml exec manager python -c "
from src.manager_app.db.database import get_session
from src.manager_app.models.user import User
from src.manager_app.core.security import get_password_hash
import asyncio

async def create_admin():
    async with get_session() as session:
        admin = User(
            username='admin',
            email='admin@risknox.local',
            hashed_password=get_password_hash('RiskNoX@2024'),
            is_admin=True,
            is_active=True
        )
        session.add(admin)
        await session.commit()
        print('Admin user created')

asyncio.run(create_admin())
"
```

### Step 6: Verify Manager Deployment

1. **Health Check**: `curl http://your-server:8001/health`
2. **Admin UI**: Visit `http://your-server:8080`
3. **API Documentation**: Visit `http://your-server:8001/docs`

## Part 2: Agent Deployment (Client Systems)

### Prerequisites for Each Agent System
- Windows 10/11 or Windows Server 2016+
- PowerShell 7.0+
- Python 3.11+
- Administrator privileges

### Step 1: Prepare Agent Package

Create agent deployment package:
```powershell
# On development machine, create agent package
mkdir RiskNoX-Agent-Package
Copy-Item -Recurse -Path "agent", "config", "vendor", "scripts" -Destination "RiskNoX-Agent-Package\"
Copy-Item -Path "RiskNoX-Control.ps1", "requirements.txt" -Destination "RiskNoX-Agent-Package\"
```

### Step 2: Agent Installation Script

Create automated installation script:
```powershell
# Save as Install-RiskNoXAgent.ps1
```

### Step 3: Deploy Agent to Target Systems

1. **Copy agent package** to each target system
2. **Run installation** with admin privileges:
```powershell
.\Install-RiskNoXAgent.ps1 -ManagerUrl "http://your-server:8001" -AgentName "System-001"
```

### Step 4: Configure Agent Connection

Update agent configuration to point to manager:
```xml
<!-- In config/agent_config.xml -->
<server>
    <url>http://your-server:8001</url>
    <websocket_url>ws://your-server:8001/ws</websocket_url>
    <api_endpoint>/api/agents</api_endpoint>
</server>
```

### Step 5: Start Agent Service

```powershell
# Start the agent
.\RiskNoX-Control.ps1 -Action start

# Check status
.\RiskNoX-Control.ps1 -Action status

# View logs
Get-Content -Path "logs\agent.log" -Tail 50 -Wait
```

## Part 3: System Integration & Testing

### Step 1: Verify Agent Registration

1. Check manager logs for agent enrollment:
```bash
docker-compose -f docker-compose.prod.yml logs manager | grep enrollment
```

2. Verify in admin UI at `http://your-server:8080/agents`

### Step 2: Test Communication

```powershell
# On agent system, test connectivity
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://your-server:8001"

# Test command execution
.\RiskNoX-Control.ps1 -Action scan -Path "C:\Temp" -Remote
```

### Step 3: Monitoring Setup

1. **Prometheus**: `http://your-server:9090`
2. **Grafana**: `http://your-server:3000` (admin/admin)
3. **Logs**: Centralized in manager database

## Part 4: Production Hardening

### Security Configuration

1. **Enable HTTPS**:
```nginx
# Add reverse proxy with SSL
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

2. **Firewall Rules**:
```bash
# Allow only necessary ports
ufw allow 22/tcp    # SSH
ufw allow 443/tcp   # HTTPS
ufw allow 8001/tcp  # Manager API
ufw allow 8080/tcp  # Admin UI
ufw enable
```

3. **Change Default Passwords**: Update all default credentials

### Backup Configuration

```bash
# Database backup script
#!/bin/bash
docker-compose -f docker-compose.prod.yml exec postgres pg_dump -U risknox_user risknox_db > backup_$(date +%Y%m%d).sql

# MinIO backup
docker-compose -f docker-compose.prod.yml exec minio mc mirror risknox-storage /backup/minio/
```

## Part 5: Maintenance & Operations

### Daily Operations

1. **Health Checks**:
```bash
# Check all services
docker-compose -f docker-compose.prod.yml ps

# Check logs for errors
docker-compose -f docker-compose.prod.yml logs --since 24h | grep ERROR
```

2. **Agent Status**:
```powershell
# On each agent system
.\RiskNoX-Control.ps1 -Action status
```

### Updates

1. **Manager Updates**:
```bash
# Pull latest images
docker-compose -f docker-compose.prod.yml pull

# Restart services
docker-compose -f docker-compose.prod.yml up -d
```

2. **Agent Updates**:
```powershell
# Update agent package
.\RiskNoX-Control.ps1 -Action update
```

## Troubleshooting

### Common Issues

1. **Agent Connection Failed**:
   - Check firewall settings
   - Verify manager URL in agent config
   - Check manager logs for certificate issues

2. **Manager Services Not Starting**:
   - Check Docker logs: `docker-compose logs`
   - Verify environment variables
   - Check disk space and memory

3. **Database Connection Issues**:
   - Verify PostgreSQL is running
   - Check connection string
   - Review database logs

### Support

For technical support:
- Check logs in `/opt/risknox-manager/logs/`
- Review agent logs in `logs\` directory
- Contact support with system information

## Quick Commands Reference

### Manager Commands
```bash
# Start services
docker-compose -f docker-compose.prod.yml up -d

# Stop services
docker-compose -f docker-compose.prod.yml down

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale celery=3
```

### Agent Commands
```powershell
# Start agent
.\RiskNoX-Control.ps1 -Action start

# Stop agent
.\RiskNoX-Control.ps1 -Action stop

# Check status
.\RiskNoX-Control.ps1 -Action status

# Perform scan
.\RiskNoX-Control.ps1 -Action scan -Path "C:\Users"
```

This completes the comprehensive deployment guide for the RiskNoX Security System.