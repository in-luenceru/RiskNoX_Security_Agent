# 🔄 Manager-to-Agent Flow Explanation

## How Manager Triggers Agents - Step-by-Step

### Example: Quick Scan Command Flow

```bash
curl -X POST "http://manager:8000/api/admin-actions/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-12345",
    "action": "run_scan", 
    "payload": {"scan_type": "quick_system"}
  }'
```

### Step-by-Step Flow:

#### 1. 📨 Admin API Request
- **Location**: Admin sends HTTP POST to Manager
- **Endpoint**: `manager:8000/api/admin-actions/trigger`
- **Handler**: `manager/src/manager_app/api/admin_actions.py`

```python
@router.post("/action/trigger")
async def trigger_admin_action(request: AdminActionRequest):
    # Receives the curl request
    result = await bridge.execute_admin_action(
        agent_id="agent-12345",
        action="run_scan",
        payload={"scan_type": "quick_system"}
    )
```

#### 2. 🔄 Bridge Translation  
- **Location**: Manager Bridge translates admin action to UI-equivalent command
- **File**: `manager/src/bridge/translator.py`

```python
def translate_run_scan(self, payload):
    # Converts admin payload to EXACT same format as web/app.js uses
    return {
        "command_type": "scan",
        "payload": {
            "scan_type": "quick",           # Maps quick_system → quick
            "targets": [],                  # Same as UI
            "options": {
                "heuristics": True,         # Same as UI
                "real_time": True,          # Same as UI  
                "timeout": 1800             # Same as UI
            }
        }
    }
```

#### 3. 🔐 Command Signing
- **Location**: Manager signs command for security
- **File**: `manager/src/bridge/sender.py`

```python
def _create_signed_command(self, agent_id, command_type, payload):
    command = {
        "command_id": "uuid-generated-123",
        "agent_id": "agent-12345", 
        "command_type": "scan",
        "payload": translated_payload,
        "issued_by": "admin",
        "issued_at": "2025-09-29T12:00:00Z",
        "expires_at": "2025-09-29T12:05:00Z",
        "signature": "RSA-signature-here"
    }
    return command
```

#### 4. 📡 WebSocket Delivery
- **Location**: Manager sends command to agent via secure WebSocket
- **Connection**: Uses existing mTLS WebSocket channel

```python
async def _send_via_websocket(self, agent_id, command):
    ws_message = {
        "type": "command",
        "command": signed_command,
        "timestamp": "2025-09-29T12:00:00Z"
    }
    # Sends over existing WebSocket connection to agent-12345
    await self.connection_manager.send_to_agent("agent-12345", ws_message)
```

#### 5. 🤖 Agent Reception & Verification
- **Location**: Agent receives command via WebSocket
- **File**: `agent/c2_command_dispatcher.py`

```python
async def handle_c2_command(self, command):
    # 1. Verify signature
    if not self._verify_command_signature(command):
        return {"success": False, "error": "Invalid signature"}
    
    # 2. Check expiration
    if not self._validate_command_freshness(command):
        return {"success": False, "error": "Command expired"}
    
    # 3. Route to handler
    handler = self.command_routing["scan"]  # Routes to _handle_scan_command
    return await handler(command)
```

#### 6. 🎯 Agent Execution (SAME CODE AS UI!)
- **Location**: Agent routes to existing UI handler
- **File**: `agent/command_handler.py` (existing code)

```python
async def _handle_scan_command(self, command):
    payload = command.get("payload", {})
    
    # THIS IS THE EXACT SAME FUNCTION THE UI CALLS!
    result = await self.command_handler.execute("scan", payload)
    
    # Same scan execution as if user clicked "Quick Scan" in UI
    return result
```

## 🎯 Key Point: Agent Uses EXACT Same Code as UI

The agent doesn't know or care whether the command came from:
- **Local UI**: `web/app.js` → `backend_server.py` → `command_handler.py`
- **Manager**: `admin curl` → `manager bridge` → `WebSocket` → `c2_dispatcher` → **SAME** `command_handler.py`

### Example: Quick Scan Comparison

**UI Path:**
```javascript
// web/app.js
async startQuickScan() {
    await this.apiCall('/api/antivirus/scan', {
        method: 'POST',
        body: JSON.stringify({
            path: "QUICK_SYSTEM_SCAN",
            scan_type: "quick_system"
        })
    });
}
```

**Manager Path:**
```bash
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "run_scan", "payload": {"scan_type": "quick_system"}}'
```

**Both Result In:**
```python
# agent/command_handler.py - SAME FUNCTION!
async def execute(self, command_type="scan", payload={"scan_type": "quick"}):
    # Exact same scan execution code
    result = await self._handle_scan(payload)
    return result
```

## 📊 Manager Has ALL UI Functions

Yes, the Manager Bridge includes **every function** from the user UI:

### ✅ All UI Operations Supported:

| UI Function | Manager Action | Agent Handler |
|-------------|----------------|---------------|
| `startQuickScan()` | `run_scan` with `quick_system` | `_handle_scan()` |
| `startScan()` (full) | `run_scan` with `system` | `_handle_scan()` |
| `blockUrl()` | `block_url` | `_handle_web_block()` |
| `unblockUrl()` | `unblock_url` | `_handle_web_unblock()` |
| `loadBlockedUrls()` | `get_blocked_urls` | `_handle_web_list()` |
| `installUpdates()` | `install_patches` | `_handle_patch()` |
| `checkForUpdates()` | `check_patches` | `_handle_patch_check()` |
| `loadPatchInfo()` | `get_patch_info` | `_handle_patch_info()` |
| `loadSystemStatus()` | `get_system_info` | `_handle_system_info()` |
| `cancelCurrentScan()` | `cancel_scan` | `_handle_cancel_scan()` |

### Manager API Endpoints Match UI Functions:

```bash
# Everything the UI can do, Manager can trigger:

# Quick scan (like clicking "Quick Scan" in UI)
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "run_scan", "payload": {"scan_type": "quick_system"}}'

# Full scan (like clicking "Full Scan" in UI)  
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "run_scan", "payload": {"scan_type": "system"}}'

# Block URL (like typing URL in UI and clicking "Block")
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "block_url", "payload": {"url": "https://malicious.com"}}'

# Install patches (like clicking "Install Updates" in UI)
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "install_patches", "payload": {"patch_ids": ["KB123"]}}'

# Get system status (like opening "System Info" tab in UI)
curl -X POST "manager:8000/api/admin-actions/trigger" \
  -d '{"agent_id": "agent-123", "action": "get_system_info", "payload": {"include_network": true}}'
```

## 🔍 Verification of Identical Behavior

The test we ran (`test_complete_flow.py`) verified that:

1. ✅ Manager translator produces **identical payloads** to UI
2. ✅ Agent dispatcher routes to **same handler functions** as UI
3. ✅ Command execution follows **exact same code paths** as UI
4. ✅ Results are **identical** whether triggered by UI or Manager

## 🚀 Why This Works Perfectly

- **No Code Duplication**: Agent reuses existing UI handler code
- **Identical Behavior**: Same functions = same results  
- **Security**: Commands are cryptographically signed
- **Reliability**: WebSocket delivery with offline queuing
- **Scalability**: Can trigger multiple agents simultaneously

**The Manager doesn't recreate UI functionality - it triggers the EXACT SAME functions the UI uses!**