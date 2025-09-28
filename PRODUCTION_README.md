# RiskNoX Security System - Complete Production Deployment

## 🚀 Quick Start - Production Ready

The fastest way to get RiskNoX Security System up and running in production:

### Option 1: Automated Quick Start (Recommended)

**For Manager (Server):**
```powershell
# Run as Administrator
.\Quick-Start.ps1 -Mode manager
```

**For Agent (Client Systems):**
```powershell
# Run as Administrator (replace with your manager server IP)
.\Quick-Start.ps1 -Mode agent -ManagerUrl "http://192.168.1.100:8001" -AgentName "WorkStation-001"
```

**For Testing:**
```powershell
.\Quick-Start.ps1 -Mode test -ManagerUrl "http://192.168.1.100:8001"
```

### Option 2: Manual Step-by-Step

#### Manager Deployment (Server)

1. **Prerequisites:**
   - Docker & Docker Compose installed
   - Server with 4GB+ RAM, 2+ CPU cores
   - Ports 8001, 8080, 5432, 6379, 9000 available

2. **Deploy Manager:**
   ```bash
   cd manager
   chmod +x ../deploy-manager.sh
   ../deploy-manager.sh --install
   ```

3. **Verify Deployment:**
   - Manager API: http://your-server:8001
   - Admin UI: http://your-server:8080
   - Health Check: http://your-server:8001/health

#### Agent Installation (Client Systems)

1. **Prerequisites:**
   - Windows 10/11 or Windows Server 2016+
   - PowerShell 7.0+
   - Python 3.11+
   - Administrator privileges

2. **Install Agent:**
   ```powershell
   # Run as Administrator
   .\Install-RiskNoXAgent.ps1 -ManagerUrl "http://your-server:8001" -AgentName "System-001"
   ```

3. **Start Agent:**
   ```powershell
   .\RiskNoX-Control.ps1 -Action start
   ```

## 📋 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MANAGER SERVER                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          Docker Compose Stack                      │   │
│  │  ┌─────────────┬─────────────┬─────────────────┐  │   │
│  │  │   Manager   │   Admin UI  │   Nginx Proxy   │  │   │
│  │  │  (FastAPI)  │   (React)   │                 │  │   │
│  │  │   :8000     │    :80      │   :80/:443      │  │   │
│  │  └─────────────┴─────────────┴─────────────────┘  │   │
│  │  ┌─────────────┬─────────────┬─────────────────┐  │   │
│  │  │ PostgreSQL  │    Redis    │     MinIO       │  │   │
│  │  │   :5432     │   :6379     │  :9000/:9001    │  │   │
│  │  └─────────────┴─────────────┴─────────────────┘  │   │
│  │  ┌─────────────┬─────────────┬─────────────────┐  │   │
│  │  │ Prometheus  │   Grafana   │    Celery       │  │   │
│  │  │   :9090     │   :3000     │   (Workers)     │  │   │
│  │  └─────────────┴─────────────┴─────────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ WebSocket/HTTP API
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
    ┌───▼────┐            ┌───▼────┐            ┌───▼────┐
    │ Agent  │            │ Agent  │            │ Agent  │
    │System 1│            │System 2│            │System N│
    │        │            │        │            │        │
    │Windows │            │Windows │            │Windows │
    │Client  │            │Server  │            │Client  │
    └────────┘            └────────┘            └────────┘
```

## 🔧 Agent Security Features

The agent provides comprehensive security modules:

1. **Network Block Monitor**
   - Monitors and blocks malicious IP addresses
   - Integrates with Windows Firewall
   - Real-time threat intelligence updates
   - Automatic rule management

2. **API Log Ingestion**
   - Collects security logs from various sources
   - HTTP-based log collection endpoint
   - XML-based log processing
   - Integration with central logging systems

3. **Access Monitor**
   - Tracks user access patterns
   - Monitors failed login attempts
   - Real-time security event detection
   - Bookmark-based event tracking

4. **Log Monitor**
   - Windows Event Log monitoring
   - Security event filtering
   - Multi-log source support
   - Configurable event ID tracking

5. **Professional Patch Management**
   - Enterprise-grade Windows Update API integration
   - Centralized patch management and control
   - Automatic blocking of manual user updates
   - Policy compliance monitoring and enforcement

6. **Antivirus Integration**
   - ClamAV-powered virus scanning
   - Real-time protection
   - Automatic definition updates
   - Quarantine management

7. **Web Protection**
   - URL blocking and filtering
   - DNS-level protection
   - Real-time threat intelligence
   - Custom blacklist/whitelist management

## 🛠️ Management Commands

### Manager Operations

```bash
# Start all services
./deploy-manager.sh --start

# Stop all services
./deploy-manager.sh --stop

# View status
./deploy-manager.sh --status

# View logs
./deploy-manager.sh --logs

# Create backup
./deploy-manager.sh --backup

# Setup SSL
./deploy-manager.sh --ssl-setup your-domain.com

# Clean up old data
./deploy-manager.sh --cleanup
```

### Agent Operations

```powershell
# Basic Operations
.\RiskNoX-Control.ps1 -Action start
.\RiskNoX-Control.ps1 -Action stop
.\RiskNoX-Control.ps1 -Action restart
.\RiskNoX-Control.ps1 -Action status

# Agent Communication
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://your-server:8001"
.\RiskNoX-Control.ps1 -Action enroll -ManagerUrl "http://your-server:8001"
.\RiskNoX-Control.ps1 -Action agent-status
.\RiskNoX-Control.ps1 -Action send-command -Command "scan /temp"

# Security Operations
.\RiskNoX-Control.ps1 -Action scan -Path "C:\Users"
.\RiskNoX-Control.ps1 -Action block -Url "malicious-site.com"
.\RiskNoX-Control.ps1 -Action unblock -Url "safe-site.com"
.\RiskNoX-Control.ps1 -Action update

# Professional Patch Management
.\RiskNoX-Control.ps1 -Action patch-setup
.\RiskNoX-Control.ps1 -Action patch-check
.\RiskNoX-Control.ps1 -Action patch-install
.\RiskNoX-Control.ps1 -Action patch-enforce
.\RiskNoX-Control.ps1 -Action patch-compliance
.\RiskNoX-Control.ps1 -Action patch-reset
```

## 📊 Monitoring & Access

### Built-in Interfaces

1. **Manager API:** http://your-server:8001
2. **Admin Dashboard:** http://your-server:8080
3. **API Documentation:** http://your-server:8001/docs
4. **Prometheus Metrics:** http://your-server:9090
5. **Grafana Dashboards:** http://your-server:3000
6. **MinIO Console:** http://your-server:9001

### Default Credentials

- **Admin Username:** admin
- **Admin Password:** RiskNoX@2024 (change in production)
- **Grafana:** admin/admin (change on first login)

## 📁 Configuration Files

### Manager Configuration
- `manager/.env.production` - Production environment variables
- `manager/docker-compose.prod.yml` - Production Docker Compose
- `manager/nginx/nginx.conf` - Nginx reverse proxy configuration

### Agent Configuration
- `config/agent_config.xml` - Main agent configuration
- `config/blocked_ips.xml` - IP blocking rules
- `config/blocked_urls.json` - URL blocking rules
- `config/api_logs.xml` - API log configuration
- `config/agent_info.json` - Agent enrollment information
- `config/patch_config.json` - Patch management settings

## 🔐 Security Features

- **Encrypted Communication**: All agent-to-manager communication is encrypted
- **Certificate Management**: Automatic certificate generation and validation
- **Access Control**: Role-based access control for all operations
- **Audit Logging**: Comprehensive audit trail of all activities
- **Professional Patch Management**: Enterprise-grade update control
- **Real-time Monitoring**: Continuous security monitoring and alerting
- **Multi-layer Protection**: Network, endpoint, and application security

## 📋 Requirements

### Manager (Server)
- **OS:** Linux (preferred) or Windows Server
- **Docker:** Docker Engine 20.10+ and Docker Compose 2.0+
- **Hardware:** 4GB+ RAM, 2+ CPU cores, 50GB+ storage
- **Network:** Ports 80, 443, 8001, 8080, 5432, 6379, 9000, 9001, 9090, 3000
- **SSL:** Valid SSL certificates for production

### Agent (Client)
- **OS:** Windows 10/11 or Windows Server 2016+
- **PowerShell:** 7.0+ required
- **Python:** 3.11+ required
- **Privileges:** Administrator privileges required
- **Network:** Outbound HTTPS/WSS to manager
- **Storage:** 2GB+ free space

## 🚨 Production Deployment Checklist

### Pre-Deployment
- [ ] Server hardware meets requirements
- [ ] Docker and Docker Compose installed
- [ ] SSL certificates obtained
- [ ] Firewall rules configured
- [ ] DNS records set up
- [ ] Backup strategy planned

### Manager Setup
- [ ] Manager deployed via `deploy-manager.sh --install`
- [ ] SSL certificates configured
- [ ] Default passwords changed
- [ ] Database backups scheduled
- [ ] Monitoring configured
- [ ] Load balancer set up (if needed)

### Agent Deployment
- [ ] Agent installer package prepared
- [ ] Installation script tested
- [ ] Firewall rules configured on clients
- [ ] Group Policy settings applied (if needed)
- [ ] Mass deployment tool configured
- [ ] Enrollment process tested

### Security Hardening
- [ ] All default credentials changed
- [ ] Unnecessary services disabled
- [ ] Firewall rules minimized
- [ ] SSL/TLS properly configured
- [ ] Access logs enabled
- [ ] Intrusion detection configured
- [ ] Regular security updates scheduled

### Monitoring & Maintenance
- [ ] Grafana dashboards configured
- [ ] Alerting rules set up
- [ ] Log rotation configured
- [ ] Backup verification tested
- [ ] Disaster recovery plan documented
- [ ] Performance baselines established

## 📈 Scaling Considerations

### Horizontal Scaling
- **Multiple Manager Instances:** Use load balancer with session affinity
- **Database Clustering:** PostgreSQL with replication
- **Redis Clustering:** Redis Cluster for high availability
- **Storage Scaling:** MinIO distributed mode

### Vertical Scaling
- **Resource Limits:** Adjust Docker resource limits
- **Database Optimization:** Tune PostgreSQL settings
- **Caching:** Implement Redis caching strategies
- **CDN:** Use CDN for static assets

## 🔄 Backup & Disaster Recovery

### Automated Backups
```bash
# Schedule daily backups
0 2 * * * /opt/risknox/deploy-manager.sh --backup

# Weekly full system backup
0 3 * * 0 /opt/risknox/scripts/full-backup.sh
```

### Recovery Procedures
```bash
# Restore from backup
./deploy-manager.sh --restore /path/to/backup.tar.gz

# Database point-in-time recovery
./scripts/db-restore.sh --time "2024-01-01 12:00:00"
```

## 🚨 Troubleshooting

### Common Issues

**Manager not responding:**
```bash
# Check service status
./deploy-manager.sh --status

# View logs
./deploy-manager.sh --logs

# Restart services
./deploy-manager.sh --restart
```

**Agent connection failed:**
```powershell
# Test network connectivity
Test-NetConnection your-server-ip -Port 8001

# Check agent configuration
.\RiskNoX-Control.ps1 -Action test-connection -ManagerUrl "http://your-server:8001"

# View agent logs
Get-Content "logs\agent.log" -Tail 50
```

**Performance issues:**
```bash
# Monitor resource usage
docker stats

# Check database performance
docker-compose -f docker-compose.prod.yml exec postgres psql -U risknox_user -c "\timing on; EXPLAIN ANALYZE SELECT * FROM agents;"

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale celery=4
```

## 🆘 Support & Documentation

### Support Resources
- **Deployment Guide:** `DEPLOYMENT_GUIDE.md`
- **API Documentation:** http://your-server:8001/docs
- **System Logs:** `logs/` directory
- **Health Checks:** Built-in monitoring endpoints

### Advanced Configuration
- **Custom Modules:** See `docs/custom-modules.md`
- **API Integration:** See `docs/api-integration.md`
- **Enterprise Features:** See `docs/enterprise-features.md`

### Community & Enterprise Support
- **Community Forum:** [Link to forum]
- **Documentation:** [Link to docs]
- **Enterprise Support:** [Contact information]

---

## 📊 Feature Matrix

| Feature | Community | Professional | Enterprise |
|---------|-----------|--------------|------------|
| Basic Agent Protection | ✅ | ✅ | ✅ |
| Centralized Management | ✅ | ✅ | ✅ |
| Real-time Monitoring | ✅ | ✅ | ✅ |
| Professional Patch Management | ❌ | ✅ | ✅ |
| Advanced Threat Detection | ❌ | ✅ | ✅ |
| Custom Integrations | ❌ | ❌ | ✅ |
| 24/7 Support | ❌ | ❌ | ✅ |
| SLA Guarantee | ❌ | ❌ | ✅ |

---

**Ready for production deployment? Follow the deployment checklist above! 🚀**

For immediate deployment, use: `.\Quick-Start.ps1 -Mode manager` on your server and `.\Quick-Start.ps1 -Mode agent -ManagerUrl "http://your-server:8001"` on client systems.