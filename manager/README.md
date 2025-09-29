# RiskNoX Security Manager

Production-ready centralized management server for RiskNoX Security Agents.

## Features

- **mTLS WebSocket C2**: Secure command and control with X.509 client certificates
- **Agent Enrollment**: Automated CSR processing and certificate issuance
- **Command Queue**: Reliable message delivery with Celery + Redis
- **Patch Management**: Secure artifact distribution with digital signatures
- **Admin UI**: Real-time monitoring and control interface
- **High Availability**: Designed for production deployment with monitoring

## Quick Start

### Development Environment

```bash
# Start infrastructure services
docker-compose up -d postgres redis minio

# Install dependencies
pip install -e ".[dev]"

# Run database migrations
alembic upgrade head

# Start development server
uvicorn src.manager_app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production Deployment

```bash
# Build and run with Docker
docker build -t risknox-manager .
docker run -d --name manager \
  -e DATABASE_URL=postgresql://user:pass@db:5432/manager \
  -e REDIS_URL=redis://redis:6379/0 \
  -p 8000:8000 \
  risknox-manager
```

## Architecture

```
┌─────────────────┐     mTLS WebSocket     ┌─────────────────┐
│   Agent Fleet   │◄──────────────────────►│   Manager API   │
└─────────────────┘                        └─────────────────┘
                                                     │
                                           ┌─────────┼─────────┐
                                           │         │         │
                                     ┌─────▼───┐ ┌──▼──┐ ┌────▼────┐
                                     │PostgreSQL│ │Redis│ │ MinIO   │
                                     │         │ │     │ │ (S3)    │
                                     └─────────┘ └─────┘ └─────────┘
```

## API Endpoints

### Core Management
- `GET /health` - Health check and metrics
- `POST /enroll` - Agent enrollment via CSR
- `GET /agents` - List enrolled agents
- `WebSocket /ws/agent` - mTLS agent connections

### Command & Control
- `POST /commands` - Create and queue commands
- `GET /commands/{id}` - Command status and results
- `POST /schedules` - Schedule recurring tasks

### Patch Management
- `POST /patches` - Upload patch artifacts
- `POST /patches/{id}/rollout` - Initiate rollout with canary
- `POST /patches/{id}/rollback` - Emergency rollback

## Security Model

### Authentication
- **Agents**: X.509 client certificates with mTLS
- **Admins**: JWT tokens with role-based access control
- **Commands**: Digital signatures with TTL validation

### Encryption
- **Transport**: TLS 1.3 for all communications
- **Storage**: Encrypted database columns for sensitive data
- **Artifacts**: GPG signatures for patch verification

### Certificate Management
- **Enrollment**: Automated CSR processing with validation
- **Rotation**: 90-day certificate lifecycle with auto-renewal
- **Revocation**: CRL distribution for compromised certificates

## Configuration

Environment variables:

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/manager
DATABASE_POOL_SIZE=20

# Redis
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1

# S3 Storage
S3_ENDPOINT=https://s3.amazonaws.com
S3_BUCKET=risknox-artifacts
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key

# Security
JWT_SECRET_KEY=your-jwt-secret
CA_PRIVATE_KEY_PATH=/etc/ssl/ca-key.pem
CA_CERTIFICATE_PATH=/etc/ssl/ca-cert.pem

# Monitoring
PROMETHEUS_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:14268
LOG_LEVEL=INFO
```

## Manager Bridge System

The Manager Bridge enables remote triggering of agent operations exactly as the local UI does.

### Bridge Components

```
┌─────────────────┐    Admin Actions    ┌─────────────────┐
│   Admin UI      │──────────────────►│  Manager API    │
└─────────────────┘                    └─────────────────┘
                                                │
                        Bridge System           │
                     ┌─────────────────────────┼─────────────────────────┐
                     │                         │                         │
                ┌────▼─────┐           ┌─────▼──────┐           ┌─────▼──────┐
                │Translator│           │  Sender    │           │Connection  │
                │          │           │            │           │Manager     │
                └────┬─────┘           └─────┬──────┘           └─────┬──────┘
                     │                       │                        │
                     │    Signed Commands    │        WebSocket       │
                     └───────────┬───────────┘                        │
                                 │                                    │
                                 ▼                                    ▼
                      ┌─────────────────┐         mTLS         ┌─────────────────┐
                      │Command Database │◄─────────────────────►│     Agent       │
                      └─────────────────┘                      └─────────────────┘
```

### Triggering Agent Actions

#### Individual Agent Actions
```bash
# Quick antivirus scan
curl -X POST "http://localhost:8000/api/admin-actions/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-uuid-here",
    "action": "run_scan", 
    "payload": {
      "scan_type": "quick_system",
      "options": {"heuristics": true}
    }
  }'

# Block malicious URLs
curl -X POST "http://localhost:8000/api/admin-actions/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-uuid-here",
    "action": "block_url",
    "payload": {
      "urls": ["malicious-site.com", "phishing-site.org"],
      "category": "security_block"
    }
  }'

# Install Windows patches
curl -X POST "http://localhost:8000/api/admin-actions/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-uuid-here", 
    "action": "install_patches",
    "payload": {
      "patch_ids": ["KB5028166", "KB5028167"],
      "auto_reboot": false
    }
  }'
```

#### Bulk Agent Actions
```bash
# Scan multiple agents
curl -X POST "http://localhost:8000/api/admin-actions/bulk-trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_ids": ["agent-1", "agent-2", "agent-3"],
    "action": "run_scan",
    "payload": {"scan_type": "full_system"}
  }'
```

### Debugging Commands

#### Check Agent Connection Status
```bash
# List all agents and connection status  
curl "http://localhost:8000/api/agents" | jq '.[] | {id: .id, name: .name, connected: .connected, last_seen: .last_seen}'

# Check specific agent
curl "http://localhost:8000/api/agents/{agent-id}" | jq '{connected: .connected, last_command: .last_command_at}'
```

#### Monitor Command Status
```bash
# Get command status and results
curl "http://localhost:8000/api/commands/{command-id}" | jq '{status: .status, results: .results, error: .error}'

# List pending commands for agent
curl "http://localhost:8000/api/agents/{agent-id}/commands?status=pending" | jq '.[] | {id: .id, type: .command_type, issued_at: .issued_at}'

# List failed commands (last 24 hours)
curl "http://localhost:8000/api/commands?status=failed&since=24h" | jq '.[] | {id: .id, agent_id: .agent_id, error: .error}'
```

#### Bridge System Diagnostics
```bash
# Test bridge translator
python -c "
from src.bridge.translator import CommandTranslator
translator = CommandTranslator()
result = translator.translate_action('run_scan', {'scan_type': 'quick_system'})
print(f'Translated command: {result}')
"

# Test command signing
python -c "
from src.bridge.sender import CommandSender
sender = CommandSender()
command = {'command_type': 'scan', 'payload': {'scan_type': 'quick'}}
signature = sender._sign_command(command)
print(f'Command signature: {signature[:50]}...')
"

# Verify agent certificate
openssl x509 -in /etc/ssl/agent.crt -text -noout | grep -E "(Subject|Issuer|Not After)"
```

#### Troubleshooting Offline Agents

##### Check Agent Connection Issues
```bash
# View agent WebSocket connection logs
docker logs manager 2>&1 | grep -E "(WebSocket|agent)" | tail -20

# Check certificate validity
curl -k "https://agent-hostname:8443/health" --cert /etc/ssl/agent.crt --key /etc/ssl/agent.key

# Test network connectivity
telnet agent-hostname 8443
```

##### Retry Failed Commands
```bash
# Retry all failed commands for specific agent
curl -X POST "http://localhost:8000/api/agents/{agent-id}/retry-failed"

# Retry specific command
curl -X POST "http://localhost:8000/api/commands/{command-id}/retry"

# Clear old queued commands (older than 7 days)
curl -X DELETE "http://localhost:8000/api/commands?status=queued&older_than=7d"
```

##### Force Command Queue Flush
```bash
# When agent reconnects, manually trigger queue processing
curl -X POST "http://localhost:8000/api/agents/{agent-id}/process-queue"

# Check queue depth
curl "http://localhost:8000/api/agents/{agent-id}/queue-status" | jq '{pending: .pending_commands, last_processed: .last_processed_at}'
```

#### Database Diagnostics
```bash
# Connect to database
psql $DATABASE_URL

# Check command statistics
SELECT 
  command_type,
  status, 
  COUNT(*) as count,
  AVG(EXTRACT(EPOCH FROM (completed_at - issued_at))) as avg_duration_seconds
FROM commands 
WHERE issued_at > NOW() - INTERVAL '24 hours'
GROUP BY command_type, status;

# Find agents with communication issues
SELECT 
  a.id,
  a.name,
  a.last_seen,
  COUNT(c.id) as failed_commands
FROM agents a
LEFT JOIN commands c ON a.id = c.agent_id AND c.status = 'failed'
WHERE a.last_seen < NOW() - INTERVAL '1 hour'
GROUP BY a.id, a.name, a.last_seen
ORDER BY failed_commands DESC;
```

#### Emergency Procedures

##### Agent Recovery
```bash
# Reset agent connection state
curl -X POST "http://localhost:8000/api/agents/{agent-id}/reset-connection"

# Revoke and reissue agent certificate  
curl -X POST "http://localhost:8000/api/agents/{agent-id}/revoke-cert"
curl -X POST "http://localhost:8000/api/agents/{agent-id}/reissue-cert"
```

##### Command Queue Recovery
```bash
# Cancel all pending commands for problematic agent
curl -X DELETE "http://localhost:8000/api/agents/{agent-id}/commands?status=pending"

# Emergency stop all commands
curl -X POST "http://localhost:8000/api/admin/emergency-stop"
```

### Development

#### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests (requires Docker)
pytest tests/integration/

# Bridge-specific tests
pytest tests/test_manager_bridge_unit.py -v
pytest tests/test_manager_bridge_integration.py -v

# Load tests
locust -f tests/load/test_agent_connections.py
```

#### Code Quality
```bash
# Format code
black src/ tests/
isort src/ tests/

# Type checking
mypy src/

# Security scan
bandit -r src/

# Dependency scan
safety check
```

## Deployment

### Docker Compose (Development)
```bash
docker-compose up -d
```

### Kubernetes (Production)
```bash
kubectl apply -f charts/manager/
```

### Monitoring
- **Metrics**: Prometheus endpoint at `/metrics`
- **Health**: Health check at `/health`
- **Logs**: Structured JSON logs with OpenTelemetry tracing

## License

MIT License - see LICENSE file for details.