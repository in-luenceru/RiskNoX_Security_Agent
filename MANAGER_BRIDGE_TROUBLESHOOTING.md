# Manager Bridge Troubleshooting Guide

This guide provides comprehensive troubleshooting procedures for the RiskNoX Manager Bridge system that enables remote triggering of agent operations.

## Common Issues and Solutions

### 1. Agent Not Receiving Commands

#### Symptoms
- Commands show as "dispatched" but agent never executes them
- Agent appears connected but doesn't respond to triggers
- Commands timeout without completion

#### Diagnosis Steps
```bash
# 1. Check agent connection status
curl "http://localhost:8000/api/agents/{agent-id}" | jq '{connected: .connected, last_seen: .last_seen}'

# 2. View recent WebSocket activity
docker logs manager 2>&1 | grep -E "(WebSocket|agent-{agent-id})" | tail -20

# 3. Test agent health endpoint
curl -k "https://agent-hostname:8443/health" --cert /etc/ssl/agent.crt --key /etc/ssl/agent.key

# 4. Check for queued commands
curl "http://localhost:8000/api/agents/{agent-id}/commands?status=pending" | jq '.[] | {id: .id, issued_at: .issued_at}'
```

#### Solutions
```bash
# Reset agent connection
curl -X POST "http://localhost:8000/api/agents/{agent-id}/reset-connection"

# Manually trigger queue processing
curl -X POST "http://localhost:8000/api/agents/{agent-id}/process-queue"

# If agent certificate issues, reissue certificate
curl -X POST "http://localhost:8000/api/agents/{agent-id}/reissue-cert"
```

### 2. Command Translation Errors

#### Symptoms
- API returns "validation_error" for admin actions
- Commands fail with "unsupported action" errors
- Payload validation failures

#### Diagnosis Steps
```bash
# Test translator directly
python -c "
from manager.src.bridge.translator import CommandTranslator
translator = CommandTranslator()
try:
    result = translator.translate_action('run_scan', {'scan_type': 'quick_system'})
    print(f'Success: {result}')
except Exception as e:
    print(f'Error: {e}')
"

# Check supported actions
curl "http://localhost:8000/api/admin-actions/supported"
```

#### Solutions
- Verify payload format matches expected schema
- Check action name is exactly correct (case-sensitive)
- Ensure required parameters are included
- Review `ui-to-agent-mapping.md` for correct payload format

### 3. Command Signing Failures

#### Symptoms
- Commands fail with "signature verification failed"
- "Invalid signature" errors in agent logs
- Commands show as "failed" immediately after dispatch

#### Diagnosis Steps
```bash
# Test command signing
python -c "
from manager.src.bridge.sender import CommandSender
sender = CommandSender()
command = {'command_type': 'scan', 'payload': {'scan_type': 'quick'}}
try:
    signature = sender._sign_command(command)
    print(f'Signature generated: {signature[:50]}...')
except Exception as e:
    print(f'Signing error: {e}')
"

# Check private key file
ls -la /etc/ssl/manager-private-key.pem
openssl rsa -in /etc/ssl/manager-private-key.pem -check -noout
```

#### Solutions
```bash
# Regenerate manager private key if corrupted
openssl genrsa -out /etc/ssl/manager-private-key.pem 4096
chmod 600 /etc/ssl/manager-private-key.pem

# Update agent with new public key if needed
openssl rsa -in /etc/ssl/manager-private-key.pem -pubout > /etc/ssl/manager-public-key.pem
```

### 4. WebSocket Connection Issues

#### Symptoms
- Agents show as "disconnected" in admin UI
- Connection drops frequently
- Unable to establish initial connection

#### Diagnosis Steps
```bash
# Check WebSocket endpoint accessibility
curl -I "http://localhost:8000/ws/agent"

# Test TLS certificate chain
openssl s_client -connect manager-hostname:8000 -cert /etc/ssl/agent.crt -key /etc/ssl/agent.key

# Check firewall/network connectivity
telnet manager-hostname 8000
```

#### Solutions
```bash
# Restart connection manager
curl -X POST "http://localhost:8000/api/admin/restart-connection-manager"

# Check certificate expiration
openssl x509 -in /etc/ssl/agent.crt -dates -noout

# Review firewall rules
sudo ufw status
sudo iptables -L
```

### 5. Command Queue Backup

#### Symptoms
- Large number of "queued" commands accumulating
- Commands not processing even when agents connect
- Memory usage growing on manager

#### Diagnosis Steps
```bash
# Check queue depths across all agents
curl "http://localhost:8000/api/commands?status=queued" | jq 'group_by(.agent_id) | map({agent: .[0].agent_id, count: length})'

# Monitor queue processing rate
curl "http://localhost:8000/api/metrics" | grep command_queue

# Check for stuck commands
curl "http://localhost:8000/api/commands?status=pending&older_than=1h" | jq '.[] | {id: .id, agent_id: .agent_id, issued_at: .issued_at}'
```

#### Solutions
```bash
# Cancel old queued commands
curl -X DELETE "http://localhost:8000/api/commands?status=queued&older_than=7d"

# Restart queue processor
curl -X POST "http://localhost:8000/api/admin/restart-queue-processor"

# Emergency clear all pending commands
curl -X POST "http://localhost:8000/api/admin/emergency-stop"
```

## Monitoring and Alerting

### Health Check Commands

```bash
# Overall system health
curl "http://localhost:8000/health" | jq '{status: .status, components: .components}'

# Bridge component health
curl "http://localhost:8000/api/admin-actions/health" | jq '{translator: .translator, sender: .sender, queue_size: .queue_size}'

# Agent fleet status summary
curl "http://localhost:8000/api/agents/summary" | jq '{total: .total, connected: .connected, disconnected: .disconnected}'
```

### Performance Metrics

```bash
# Command processing statistics
curl "http://localhost:8000/api/metrics/commands" | jq '{
  total_today: .total_today,
  success_rate: .success_rate,
  avg_response_time: .avg_response_time,
  by_type: .by_type
}'

# WebSocket connection metrics
curl "http://localhost:8000/api/metrics/connections" | jq '{
  active_connections: .active_connections,
  connection_churn: .connection_churn,
  failed_auths: .failed_auths
}'
```

### Log Analysis

```bash
# Parse command flow logs
docker logs manager 2>&1 | grep -E "(command_id|agent_id)" | \
  grep -E "(translated|dispatched|completed|failed)" | tail -20

# Find signature verification failures
docker logs manager 2>&1 | grep "signature.*failed" | tail -10

# Monitor connection events
docker logs manager 2>&1 | grep -E "(connected|disconnected)" | tail -20

# Track error patterns
docker logs manager 2>&1 | grep -i error | \
  awk '{print $NF}' | sort | uniq -c | sort -nr
```

## Database Troubleshooting

### Command Table Analysis

```sql
-- Connect to database
psql $DATABASE_URL

-- Command success rates by type
SELECT 
  command_type,
  COUNT(*) as total,
  COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
  COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
  ROUND(COUNT(CASE WHEN status = 'completed' THEN 1 END)::float / COUNT(*) * 100, 2) as success_rate
FROM commands 
WHERE issued_at > NOW() - INTERVAL '24 hours'
GROUP BY command_type;

-- Slowest commands
SELECT 
  id,
  command_type,
  agent_id,
  EXTRACT(EPOCH FROM (completed_at - issued_at)) as duration_seconds
FROM commands 
WHERE completed_at IS NOT NULL
ORDER BY duration_seconds DESC
LIMIT 10;

-- Agents with most failures
SELECT 
  a.name,
  a.id,
  COUNT(c.id) as failed_commands,
  a.last_seen
FROM agents a
LEFT JOIN commands c ON a.id = c.agent_id AND c.status = 'failed'
WHERE c.issued_at > NOW() - INTERVAL '24 hours'
GROUP BY a.id, a.name, a.last_seen
ORDER BY failed_commands DESC;
```

### Queue Cleanup

```sql
-- Remove old completed commands (older than 30 days)
DELETE FROM commands 
WHERE status = 'completed' 
AND completed_at < NOW() - INTERVAL '30 days';

-- Cancel abandoned pending commands (older than 2 hours)
UPDATE commands 
SET status = 'cancelled', 
    error = 'Cancelled due to timeout'
WHERE status = 'pending' 
AND issued_at < NOW() - INTERVAL '2 hours';

-- Clear queue for specific agent
DELETE FROM commands 
WHERE agent_id = 'agent-uuid-here' 
AND status IN ('queued', 'pending');
```

## Emergency Procedures

### Complete System Reset

```bash
# 1. Stop command processing
curl -X POST "http://localhost:8000/api/admin/emergency-stop"

# 2. Clear all queues
curl -X DELETE "http://localhost:8000/api/commands?status=queued"
curl -X DELETE "http://localhost:8000/api/commands?status=pending"

# 3. Reset all agent connections
curl -X POST "http://localhost:8000/api/agents/reset-all-connections"

# 4. Restart services
docker-compose restart manager

# 5. Verify system health
curl "http://localhost:8000/health"
```

### Agent Certificate Recovery

```bash
# Revoke compromised certificate
curl -X POST "http://localhost:8000/api/agents/{agent-id}/revoke-cert"

# Generate new agent certificate
curl -X POST "http://localhost:8000/api/agents/{agent-id}/reissue-cert" \
  -H "Content-Type: application/json" \
  -d '{"common_name": "agent-hostname"}'

# Update agent with new certificate
scp new-agent.crt agent-hostname:/etc/ssl/agent.crt
scp new-agent.key agent-hostname:/etc/ssl/agent.key
ssh agent-hostname "systemctl restart risknox-agent"
```

### Manager Certificate Recovery

```bash
# Generate new manager signing key
openssl genrsa -out /etc/ssl/new-manager-key.pem 4096
chmod 600 /etc/ssl/new-manager-key.pem

# Update manager configuration
export MANAGER_PRIVATE_KEY_PATH=/etc/ssl/new-manager-key.pem

# Distribute new public key to all agents
openssl rsa -in /etc/ssl/new-manager-key.pem -pubout > manager-public-key.pem
for agent in $(curl -s "http://localhost:8000/api/agents" | jq -r '.[].hostname'); do
  scp manager-public-key.pem $agent:/etc/ssl/manager-public-key.pem
  ssh $agent "systemctl restart risknox-agent"
done

# Restart manager
docker-compose restart manager
```

## Performance Optimization

### Queue Processing Tuning

```bash
# Increase queue worker threads
export COMMAND_QUEUE_WORKERS=10

# Adjust batch sizes for bulk operations
export BULK_COMMAND_BATCH_SIZE=50

# Set command timeout limits
export COMMAND_TIMEOUT_SECONDS=300
```

### Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX IF NOT EXISTS idx_commands_agent_status 
ON commands(agent_id, status);

CREATE INDEX IF NOT EXISTS idx_commands_issued_at 
ON commands(issued_at) WHERE issued_at > NOW() - INTERVAL '7 days';

-- Update table statistics
ANALYZE commands;
ANALYZE agents;
```

### Connection Pool Tuning

```bash
# Increase database connection pool
export DATABASE_POOL_SIZE=50
export DATABASE_MAX_OVERFLOW=20

# Adjust WebSocket connection limits
export MAX_WEBSOCKET_CONNECTIONS=1000
export WEBSOCKET_PING_INTERVAL=30
```

## Support Information

### Log Locations
- Manager logs: `docker logs manager`
- Database logs: `docker logs postgres`
- Redis logs: `docker logs redis`

### Configuration Files
- Main config: `manager/src/manager_app/config.py`
- Bridge config: `manager/src/bridge/config.py`
- Database schema: `manager/alembic/versions/`

### Useful Commands Reference
```bash
# View all environment variables
docker exec manager env | grep -E "(DATABASE|REDIS|MANAGER)"

# Check resource usage
docker stats manager postgres redis

# View active connections
ss -tuln | grep -E "(8000|5432|6379)"

# Test internal connectivity
docker exec manager curl -s http://postgres:5432
docker exec manager redis-cli -h redis ping
```