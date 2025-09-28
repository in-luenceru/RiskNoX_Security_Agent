# IMMEDIATE IMPLEMENTATION PLAN - CRITICAL PATH

## Phase 1: Complete mTLS WebSocket C2 Channel ⚡ **4 hours**

### Create WebSocket Connection Manager
```python
# File: manager/src/manager_app/ws/connection_manager.py
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.agent_connections: Dict[str, str] = {}  # agent_id -> connection_id
    
    async def connect(self, websocket: WebSocket, agent_id: str):
        # Verify mTLS certificate
        # Register connection
        # Send welcome message
    
    async def disconnect(self, agent_id: str):
        # Clean up connection
        # Update agent status
    
    async def send_command(self, agent_id: str, command: dict):
        # Send command to specific agent
        # Handle delivery confirmation
    
    async def broadcast(self, message: dict, agent_ids: List[str] = None):
        # Send to multiple agents
```

### Create Agent WebSocket Handler
```python
# File: manager/src/manager_app/ws/agent_stream.py
@router.websocket("/ws/agent")
async def agent_websocket(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db_session)
):
    # Extract certificate from mTLS connection
    # Validate agent certificate
    # Register with connection manager
    # Handle message loop (commands, heartbeats, results)
```

### Update Main Application
```python
# File: manager/src/manager_app/main.py
from .ws.agent_stream import router as ws_router
app.include_router(ws_router)
```

## Phase 2: Create Modern Agent Client ⚡ **6 hours**

### Agent WebSocket Client
```python
# File: agent/websocket_client.py
class AgentWebSocketClient:
    def __init__(self, manager_url: str, cert_path: str, key_path: str):
        self.manager_url = manager_url
        self.cert_path = cert_path
        self.key_path = key_path
        self.websocket = None
    
    async def connect(self):
        # Create mTLS WebSocket connection
        # Handle authentication
        # Start message loop
    
    async def handle_command(self, command: dict):
        # Verify command signature
        # Execute command
        # Send result back
    
    async def send_heartbeat(self):
        # Send periodic heartbeat
    
    async def reconnect_with_backoff(self):
        # Exponential backoff reconnection
```

### Agent Enrollment Module  
```python
# File: agent/enrollment.py
class AgentEnrollment:
    def __init__(self, manager_url: str):
        self.manager_url = manager_url
    
    def generate_csr(self) -> Tuple[str, str]:
        # Generate private key
        # Create CSR with agent metadata
        # Return CSR PEM and private key
    
    async def enroll(self, hostname: str, os_info: dict) -> dict:
        # Generate CSR
        # POST to /api/v1/enroll
        # Save certificate and agent_id
        # Return enrollment result
```

### Agent Command Handler
```python  
# File: agent/command_handler.py
class CommandHandler:
    def __init__(self):
        self.handlers = {
            'scan': self.handle_scan,
            'patch': self.handle_patch,
            'config': self.handle_config,
        }
    
    async def execute(self, command: dict) -> dict:
        # Verify command signature and TTL
        # Route to appropriate handler
        # Return execution result
    
    async def handle_scan(self, payload: dict) -> dict:
        # Execute antivirus scan
        # Return scan results
    
    async def handle_patch(self, payload: dict) -> dict:
        # Download and install patches
        # Return installation status
```

## Phase 3: Background Task Workers ⚡ **3 hours**

### Celery Application Setup
```python
# File: manager/src/manager_app/tasks/celery_app.py
from celery import Celery
from ..settings import get_settings

settings = get_settings()

celery_app = Celery(
    "manager",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.REDIS_URL,
)

celery_app.autodiscover_tasks(['manager_app.tasks'])
```

### Command Delivery Worker
```python
# File: manager/src/manager_app/tasks/command_delivery.py
@celery_app.task(bind=True, max_retries=3)
def deliver_command(self, command_id: str):
    # Get command from database
    # Try WebSocket delivery first
    # Queue for polling if WebSocket fails
    # Update command status
    # Retry on failure with exponential backoff
```

### Scheduled Task Worker
```python
# File: manager/src/manager_app/tasks/scheduler.py
@celery_app.task
def execute_scheduled_scan(schedule_id: str):
    # Get schedule from database
    # Create scan commands for target agents
    # Queue commands for delivery

@celery_app.task  
def patch_rollout_orchestrator(rollout_id: str):
    # Manage canary patch deployment
    # Monitor rollout progress
    # Handle rollback triggers
```

## IMPLEMENTATION SEQUENCE

### Day 1 Morning (4 hours)
1. **Hour 1-2**: Create `connection_manager.py` and `agent_stream.py`
2. **Hour 3**: Add WebSocket endpoint to `main.py`  
3. **Hour 4**: Test WebSocket connection (without agent)

### Day 1 Afternoon (6 hours)
4. **Hour 5-6**: Create `agent/websocket_client.py`
5. **Hour 7-8**: Create `agent/enrollment.py` 
6. **Hour 9-10**: Create `agent/command_handler.py`

### Day 2 Morning (3 hours)
7. **Hour 11-12**: Create Celery tasks (`celery_app.py`, `command_delivery.py`)
8. **Hour 13**: Create scheduler tasks (`scheduler.py`)

## TESTING PLAN

### Test 1: WebSocket Connection
```bash
# Test WebSocket endpoint exists
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: test" \
  http://localhost:8000/ws/agent
```

### Test 2: Agent Enrollment → WebSocket
```python
# Test complete flow:
1. Agent generates CSR
2. Agent enrolls with Manager  
3. Agent connects via mTLS WebSocket
4. Manager sends test command
5. Agent executes and responds
```

### Test 3: Background Tasks
```python
# Test Celery integration:
1. Create scheduled scan
2. Verify Celery task created
3. Verify command delivered to agent
4. Verify result stored in database
```

## SUCCESS CRITERIA

### ✅ Phase 1 Complete When:
- WebSocket endpoint `/ws/agent` responds
- Connection manager tracks agent connections
- mTLS certificate verification works

### ✅ Phase 2 Complete When:  
- Agent can enroll and receive certificate
- Agent connects via mTLS WebSocket
- Agent receives and executes commands
- Results sent back to Manager

### ✅ Phase 3 Complete When:
- Celery workers process background tasks
- Scheduled scans execute automatically  
- Command delivery retries work
- Patch rollouts orchestrated properly

## FINAL DELIVERABLES

After completing all phases:

1. **Working Manager + Agent Communication**
   - Real-time bidirectional mTLS WebSocket C2
   - Fallback polling for unreliable connections
   - Complete command execution lifecycle

2. **Production-Ready Deployment**
   - Docker Compose for local development
   - Kubernetes manifests for production
   - Complete CI/CD pipeline

3. **Monitoring & Observability**
   - Prometheus metrics for all components
   - Structured logging with correlation IDs
   - Health checks and alerting

**ESTIMATED COMPLETION: 13 hours total**
**RESULT: Fully functional, production-ready Manager + Agent system**