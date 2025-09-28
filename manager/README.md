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

## Development

### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests (requires Docker)
pytest tests/integration/

# Load tests
locust -f tests/load/test_agent_connections.py
```

### Code Quality
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