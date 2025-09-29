# UI-to-Agent Operation Mapping

This document maps how the user UI currently triggers agent-side operations and provides the exact API calls and payloads that the Manager bridge needs to replicate.

## System Architecture Overview

The current system has:
- **Web UI** (`web/app.js`) - Simple local UI that calls the backend server directly
- **React Admin UI** (`manager/admin-ui/`) - Admin interface that calls manager API and agent action endpoints
- **Backend Server** (`backend_server.py`) - Local agent API server that handles scan/patch/webblock operations
- **Agent** (`agent/`) - Remote agent with command handler and WebSocket client
- **Manager** (`manager/`) - Remote management server with database and WebSocket server

## UI Operation Mappings

### 1. Antivirus Scan Operations

#### 1.1 Quick System Scan

**UI Implementation:**
- File: `web/app.js`, function: `startQuickScan()`
- React UI: `AntivirusScannerPage.tsx`, `commandApi.runScan(agentId, 'quick')`

**Current API Call:**
```http
POST /api/antivirus/scan
Content-Type: application/json
Authorization: Bearer <token>

{
  "path": "QUICK_SYSTEM_SCAN",
  "scan_type": "quick_system",
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_scan()` with `scan_type: "quick"`

**Manager Bridge Translation:**
```json
{
  "command_type": "scan",
  "payload": {
    "scan_type": "quick_system",
    "path": "QUICK_SYSTEM_SCAN",
    "options": {
      "heuristics": true,
      "real_time": true
    }
  }
}
```

#### 1.2 Full System Scan

**UI Implementation:**
- File: `web/app.js`, function: `startScan()` with `scanType === 'system'`
- React UI: `AntivirusScannerPage.tsx`, `commandApi.runScan(agentId, 'full')`

**Current API Call:**
```http
POST /api/antivirus/scan
Content-Type: application/json
Authorization: Bearer <token>

{
  "path": "SYSTEM_SCAN",
  "scan_type": "system",
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_scan()` with `scan_type: "full"`

**Manager Bridge Translation:**
```json
{
  "command_type": "scan",
  "payload": {
    "scan_type": "system", 
    "path": "SYSTEM_SCAN",
    "options": {
      "recursive": true,
      "follow_symlinks": false
    }
  }
}
```

#### 1.3 Directory Scan

**UI Implementation:**
- File: `web/app.js`, function: `startScan()` with `scanType === 'directory'`
- React UI: `AntivirusScannerPage.tsx`, `commandApi.runScanMultiple()` with custom path

**Current API Call:**
```http
POST /api/antivirus/scan
Content-Type: application/json
Authorization: Bearer <token>

{
  "path": "/path/to/directory",
  "scan_type": "directory",
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_scan()` with `scan_type: "custom"` and specific targets

**Manager Bridge Translation:**
```json
{
  "command_type": "scan",
  "payload": {
    "scan_type": "custom",
    "targets": ["/path/to/directory"],
    "options": {
      "recursive": true
    }
  }
}
```

#### 1.4 Cancel Scan

**UI Implementation:**
- File: `web/app.js`, function: `cancelCurrentScan()`

**Current API Call:**
```http
POST /api/antivirus/cancel-scan/<session_id>
Authorization: Bearer <token>
```

**Manager Bridge Translation:**
```json
{
  "command_type": "cancel_scan",
  "payload": {
    "session_id": "<session_id>"
  }
}
```

### 2. Web Blocking Operations

#### 2.1 Block URL

**UI Implementation:**
- File: `web/app.js`, function: `blockUrl()`
- React UI: `commandApi.runWebBlockCommand(agentIds, 'block', urls)`

**Current API Call:**
```http
POST /api/web-blocking/block
Content-Type: application/json
Authorization: Bearer <token>

{
  "url": "https://malicious-site.com",
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_web_block()`

**Manager Bridge Translation:**
```json
{
  "command_type": "web_block",
  "payload": {
    "urls": ["https://malicious-site.com"]
  }
}
```

#### 2.2 Unblock URL

**UI Implementation:**
- File: `web/app.js`, function: `unblockUrl()`
- React UI: `commandApi.runWebBlockCommand(agentIds, 'unblock', urls)`

**Current API Call:**
```http
POST /api/web-blocking/unblock
Content-Type: application/json
Authorization: Bearer <token>

{
  "url": "https://malicious-site.com",
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_web_unblock()`

**Manager Bridge Translation:**
```json
{
  "command_type": "web_unblock",
  "payload": {
    "urls": ["https://malicious-site.com"]
  }
}
```

#### 2.3 Get Blocked URLs

**UI Implementation:**
- File: `web/app.js`, function: `loadBlockedUrls()`

**Current API Call:**
```http
GET /api/web-blocking/urls
Authorization: Bearer <token>
```

**Agent Handler:** Read hosts file and return blocked URLs

**Manager Bridge Translation:**
```json
{
  "command_type": "web_list_blocked",
  "payload": {}
}
```

### 3. Patch Management Operations

#### 3.1 Install Updates

**UI Implementation:**
- File: `web/app.js`, function: `installUpdates()`
- React UI: `commandApi.runPatchCommand(agentIds, 'install', patchIds)`

**Current API Call:**
```http
POST /api/patch-management/install
Content-Type: application/json
Authorization: Bearer <token>

{
  "patch_ids": ["KB5028166", "KB5028167"],  // Optional, if empty installs all pending
  "agent_id": "<agent_id>"  // Only in React UI
}
```

**Agent Handler:** `command_handler.py._handle_patch()`

**Manager Bridge Translation:**
```json
{
  "command_type": "patch",
  "payload": {
    "patch_ids": ["KB5028166", "KB5028167"],
    "install_options": {
      "auto_reboot": false,
      "backup_before_install": true,
      "rollback_on_failure": true
    }
  }
}
```

#### 3.2 Check for Updates

**UI Implementation:**
- File: `web/app.js`, function: `checkForUpdates()`

**Current API Call:**
```http
POST /api/patch-management/updates/check
Authorization: Bearer <token>
```

**Agent Handler:** Windows Update PowerShell check

**Manager Bridge Translation:**
```json
{
  "command_type": "patch_check",
  "payload": {
    "include_optional": false,
    "include_drivers": true
  }
}
```

#### 3.3 Get Patch Info

**UI Implementation:**
- File: `web/app.js`, function: `loadPatchInfo()`

**Current API Call:**
```http
GET /api/patch-management/info
Authorization: Bearer <token>
```

**Manager Bridge Translation:**
```json
{
  "command_type": "patch_info",
  "payload": {}
}
```

### 4. System Information

#### 4.1 Get System Status

**UI Implementation:**
- File: `web/app.js`, function: `loadSystemStatus()`

**Current API Call:**
```http
GET /api/system/status
Authorization: Bearer <token>
```

**Agent Handler:** `command_handler.py._handle_system_info()`

**Manager Bridge Translation:**
```json
{
  "command_type": "system_info",
  "payload": {
    "include_network": true,
    "include_processes": false
  }
}
```

## Authentication and Headers

### Current Authentication

**Local Web UI:**
- Uses Bearer token stored in localStorage
- Token obtained via `POST /api/auth/login`

**React Admin UI:**
- Uses Bearer token in axios interceptor
- Token from localStorage: `auth_token`

### Manager Bridge Requirements

The Manager bridge must:
1. Accept admin authentication from the admin UI
2. Sign commands with Manager private key
3. Include command metadata (issuer, timestamp, TTL)

### Command Signature Format

```json
{
  "command_id": "uuid-v4",
  "type": "scan",
  "payload": {...},
  "issued_by": "admin@company.com",
  "issued_at": "2025-09-29T12:34:56Z",
  "ttl_seconds": 60,
  "signature": "base64-signature-of-command-content"
}
```

## Connection Architecture

### Current State
- **Web UI** → **Backend Server** (local HTTP)
- **React Admin UI** → **Manager API** (remote HTTP) → **Agent** (not implemented)
- **Agent** → **Manager** (WebSocket enrollment, but no command execution)

### Target State with Bridge
- **Admin UI** → **Manager Bridge** → **Agent** (via WebSocket C2)
- **Manager Bridge** constructs identical payloads to what local UI would send
- **Agent C2 Dispatcher** routes commands to existing `command_handler.py` functions

## Implementation Notes

### Agent-side Integration Points

The agent's `command_handler.py` already has the right handlers:
- `_handle_scan()` - Maps to all scan operations
- `_handle_patch()` - Maps to patch installation
- `_handle_web_block()` / `_handle_web_unblock()` - Maps to web blocking
- `_handle_system_info()` - Maps to system status

### Manager-side Requirements

1. **Translator** - Convert admin actions to agent command payloads
2. **Sender** - Sign and deliver commands via WebSocket
3. **Status Tracker** - Monitor command status and results
4. **Admin API** - Accept admin UI actions via REST endpoint

### Command Flow

```
Admin UI Action → Manager /admin/action/trigger → Translator → Sender → Agent WebSocket → Command Handler → Existing Functions → Response → Manager → Admin UI
```

### Example curl Commands for Testing

#### Trigger Scan from Manager
```bash
curl -X POST 'https://manager.local/admin/action/trigger' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "agent_id": "uuid-here",
    "action": "run_scan",
    "payload": {
      "scan_type": "quick_system"
    }
  }'
```

#### Trigger Web Block from Manager
```bash
curl -X POST 'https://manager.local/admin/action/trigger' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "agent_id": "uuid-here", 
    "action": "block_url",
    "payload": {
      "url": "https://malicious-site.com"
    }
  }'
```

#### Trigger Patch Install from Manager
```bash
curl -X POST 'https://manager.local/admin/action/trigger' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "agent_id": "uuid-here",
    "action": "install_patches", 
    "payload": {
      "patch_ids": ["KB5028166"]
    }
  }'
```