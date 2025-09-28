# RiskNoX Security Agent - Codebase Analysis

## Executive Summary

The current RiskNoX Security Agent is a **monolithic, single-host Flask application** providing antivirus scanning, web blocking, and patch management capabilities. It operates as a standalone service with basic web UI and hardcoded authentication. **Migration to a centralized Manager + Agent architecture requires complete restructuring**, including security hardening, proper authentication, and scalable C2 infrastructure.

## Current Architecture Analysis

### Core Files and Components

| File | Purpose | Lines | Security Risk | Migration Required |
|------|---------|--------|---------------|-------------------|
| `backend_server.py` | Main Flask API server | 3,984 | **HIGH** - Hardcoded credentials | Complete refactor |
| `web/app.js` | Frontend JavaScript | 2,233 | MEDIUM - No CSRF protection | Partial refactor |
| `RiskNoX-Control.ps1` | PowerShell management | 1,540 | LOW - Local admin only | Agent wrapper |
| `config/agent_config.xml` | Agent configuration | 269 | LOW - Local config | Replace with enrollment |
| `requirements.txt` | Dependencies | 4 | MEDIUM - Outdated versions | Update & expand |

### Security Vulnerabilities Found

#### Critical Issues (from bandit scan)
- **Hardcoded Password**: Line 182 in `backend_server.py` - `password == "RiskNoX@2024"`
- **Shell Injection Risk**: Multiple `subprocess.call()` without proper sanitization
- **Token Storage**: In-memory token storage (line 57) - not persistent or secure
- **No Input Validation**: API endpoints lack proper input sanitization
- **HTTP Only**: No HTTPS/TLS enforcement

#### Medium Issues
- **Flask Debug Mode**: Potentially enabled in production
- **CORS Wide Open**: `CORS(app)` allows all origins
- **No Rate Limiting**: Authentication endpoints vulnerable to brute force
- **Session Management**: Tokens expire but no proper invalidation

### Current API Endpoints

#### Authentication
- `POST /api/auth/login` - Hardcoded credentials
- No logout, session management, or MFA

#### Antivirus Module  
- `POST /api/antivirus/scan` - Directory/system scanning
- `GET /api/antivirus/status/<session_id>` - Scan status
- `POST /api/antivirus/scheduled` - Schedule management
- `GET /api/antivirus/checkpoints` - Resume capability

#### Web Blocking Module
- `GET /api/web-blocking/urls` - List blocked URLs
- `POST /api/web-blocking/block` - Block URL via hosts file
- `POST /api/web-blocking/unblock` - Unblock URL
- `POST /api/web-blocking/restore-hosts` - Reset hosts file

#### Patch Management Module
- `GET /api/patch-management/info` - Windows Update status
- `POST /api/patch-management/install` - Install patches (admin only)
- `GET /api/patch-management/compliance/check` - Compliance status

### Technology Stack Assessment

#### Current Stack
- **Backend**: Flask 3.0.0 + CORS
- **Frontend**: Vanilla JavaScript + HTML/CSS
- **OS Integration**: PowerShell scripts, Windows APIs
- **Storage**: File-based (JSON, logs)
- **Security**: Basic token auth, no encryption

#### Required Stack (Target)
- **Backend**: FastAPI + SQLAlchemy + Alembic
- **Database**: PostgreSQL
- **Queue/Broker**: Redis/Celery for async tasks
- **Storage**: S3/MinIO for artifacts
- **Security**: mTLS + X.509 certificates + signed commands
- **Frontend**: Next.js Admin UI

## Security & Dependency Analysis

### Dependency Issues
```
Flask==3.0.0         ✓ Recent version
flask-cors==4.0.0    ✓ Recent version  
schedule==1.2.0      ✓ Recent version
psutil==6.0.0        ✓ Recent version
```

**Missing Critical Dependencies:**
- Database ORM (SQLAlchemy)
- Migration tool (Alembic) 
- Async task queue (Celery/Redis)
- Cryptography libraries
- Certificate management
- WebSocket support
- Input validation (Pydantic)

### Hard-coded Secrets Found
```python
# Line 182 - backend_server.py
if username == "admin" and password == "RiskNoX@2024":
```

**Other Security Patterns:**
- No secret management system
- Tokens stored in memory only
- No audit logging for admin actions
- Direct OS command execution without sanitization

## Migration Plan - Prioritized PRs

### Phase 1: Foundation (PRs #1-3)
**PR #1: Manager Skeleton + Database Setup**
- Create `manager/` directory structure
- FastAPI skeleton with `/health` endpoint
- PostgreSQL + Alembic migrations for core tables
- Docker compose for local development
- **Timeline**: 2 days

**PR #2: Certificate Authority + Enrollment API**
- Internal CA or Vault integration
- `POST /enroll` endpoint for CSR processing
- X.509 certificate generation and storage
- Agent identity management database tables
- **Timeline**: 3 days

**PR #3: mTLS WebSocket Infrastructure**
- WebSocket connection manager with mTLS
- Agent connection tracking and heartbeat
- Message routing and queuing foundation
- **Timeline**: 3 days

### Phase 2: Command & Control (PRs #4-6)
**PR #4: Command Queue + Scheduling**
- Celery integration for async task processing
- Command creation, queuing, and delivery
- Redis streams for reliable message delivery
- **Timeline**: 2 days

**PR #5: Command Signing + Verification**
- Digital signature for all commands
- TTL and freshness validation
- Agent-side signature verification
- **Timeline**: 2 days

**PR #6: Agent Modernization**
- Convert current agent to WebSocket client
- CSR generation and enrollment flow
- Fallback polling mechanism
- **Timeline**: 3 days

### Phase 3: Manager Features (PRs #7-9)
**PR #7: Patch Artifact Management**
- S3/MinIO integration for patch storage
- Artifact signing and verification
- Canary rollout and rollback mechanisms
- **Timeline**: 3 days

**PR #8: Admin UI**
- Next.js admin interface
- Real-time agent status monitoring
- Command creation and scheduling UI
- **Timeline**: 4 days

**PR #9: Monitoring + Observability**
- Prometheus metrics endpoint
- Structured JSON logging
- OpenTelemetry instrumentation
- Health checks and alerting
- **Timeline**: 2 days

### Phase 4: Production Readiness (PRs #10-12)
**PR #10: Security Hardening**
- Rate limiting and DDoS protection
- Input validation and sanitization
- Security headers and CSRF protection
- **Timeline**: 2 days

**PR #11: CI/CD Pipeline**
- GitHub Actions for testing and building
- Docker image building and scanning
- Security vulnerability scanning
- **Timeline**: 2 days

**PR #12: Deployment + Documentation**
- Kubernetes manifests
- Production runbook
- Rollback procedures
- **Timeline**: 3 days

## Key Architecture Changes Required

### 1. Authentication Model
**Current**: Hardcoded username/password
**Target**: X.509 client certificates with mTLS

### 2. Communication Model  
**Current**: HTTP API polling only
**Target**: mTLS WebSocket (primary) + authenticated polling (fallback)

### 3. Data Storage
**Current**: File-based JSON storage
**Target**: PostgreSQL with proper schema and migrations

### 4. Command Execution
**Current**: Synchronous HTTP requests
**Target**: Asynchronous message queues with ACK/NACK

### 5. Security Model
**Current**: No encryption, basic tokens
**Target**: End-to-end encryption, signed commands, certificate rotation

## Risk Assessment

### High Risk Items
1. **Zero-downtime migration** - Current agents must continue working during transition
2. **Secret management** - Hardcoded credentials need immediate replacement
3. **Certificate rotation** - Need automated cert lifecycle management
4. **Backward compatibility** - Support legacy agents during rollout

### Medium Risk Items
1. **Performance scalability** - Current code blocks on long operations
2. **Database migrations** - Schema changes need rollback capability
3. **Network connectivity** - WebSocket connections may be blocked by firewalls

## Acceptance Criteria

### Technical Requirements
- [ ] Manager can enroll new agents via CSR exchange
- [ ] mTLS WebSocket C2 with fallback polling
- [ ] Commands are signed, delivered, and ACK'd
- [ ] Database stores agent state, commands, and audit logs
- [ ] Admin UI shows real-time agent status
- [ ] Patch artifacts can be distributed and verified

### Security Requirements  
- [ ] No hardcoded credentials anywhere
- [ ] All communication encrypted with mTLS
- [ ] Commands digitally signed with freshness checks
- [ ] Certificate rotation without service interruption
- [ ] Audit logging for all admin actions

###Performance Requirements
- [ ] Support 1000+ concurrent agent connections
- [ ] Command delivery within 5 seconds
- [ ] Manager startup time under 30 seconds
- [ ] Database queries under 100ms average

## Development Environment Setup

```bash
# Required for local development
docker-compose up -d  # PostgreSQL + Redis + MinIO
cd manager && python -m uvicorn main:app --reload
cd admin-ui && npm run dev
```

**Next Steps**: Begin PR #1 implementation with manager skeleton and database setup.