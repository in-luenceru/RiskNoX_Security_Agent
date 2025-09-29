#!/usr/bin/env python3
"""
RiskNoX Manager API Virus Scan Test
Tests the manager API to trigger virus scans on connected agents
"""

import requests
import json
import time
import sys

def main():
    print('=== RiskNoX Manager API Scan Test ===\n')
    
    base_url = "http://localhost:8001"
    
    try:
        # Step 1: Health check
        print('1. Testing Manager health...')
        health_resp = requests.get(f'{base_url}/health', timeout=10)
        health_resp.raise_for_status()
        health = health_resp.json()
        print(f'✓ Manager status: {health["status"]}')
        print(f'  Service: {health["service"]}\n')
        
        # Step 2: Get agents
        print('2. Getting agents...')
        agents_resp = requests.get(f'{base_url}/api/v1/agents', timeout=10)
        agents_resp.raise_for_status()
        agents_data = agents_resp.json()
        print(f'✓ Found {agents_data["total"]} agent(s)')
        
        if agents_data['total'] == 0:
            print('❌ No agents found!')
            return False
            
        agent = agents_data['agents'][0]
        agent_id = agent['agent_id']
        print(f'  Agent ID: {agent_id}')
        print(f'  Hostname: {agent["hostname"]}')
        print(f'  Status: {agent["status"]}')
        print(f'  OS: {agent["os_type"]} {agent["os_version"]}\n')
        
        # Step 3: Check WebSocket connections
        print('3. Checking WebSocket connections...')
        ws_resp = requests.get(f'{base_url}/ws/stats', timeout=10)
        ws_resp.raise_for_status()
        ws_stats = ws_resp.json()
        print(f'✓ Total connections: {ws_stats["total_connections"]}')
        print(f'  Active agents: {ws_stats["active_agents"]}')
        print(f'  Queued messages: {ws_stats["queued_messages"]}')
        
        if ws_stats['active_agents'] == 0:
            print('⚠ Warning: No active agent connections detected')
            print('  Scan command will be queued but may not execute immediately\n')
        else:
            print('✓ Agent connections detected\n')
        
        # Step 4: Trigger virus scan
        print('4. Triggering virus scan...')
        scan_data = {
            'agent_ids': [agent_id],
            'scan_type': 'quick',
            'options': {}
        }
        
        scan_resp = requests.post(
            f'{base_url}/api/v1/scans/trigger',
            json=scan_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        scan_resp.raise_for_status()
        scan_result = scan_resp.json()
        
        print(f'✓ Scan API call completed')
        print(f'  Success: {scan_result.get("success", False)}')
        print(f'  Message: {scan_result.get("message", "N/A")}')
        print(f'  Successful agents: {scan_result.get("successful_agents", 0)}')
        print(f'  Total agents: {scan_result.get("total_agents", 0)}')
        
        if scan_result.get('scan_commands'):
            for cmd in scan_result['scan_commands']:
                print(f'  ✓ Scan Command ID: {cmd["command_id"]}')
                print(f'    Agent: {cmd["agent_id"]}')
        
        if scan_result.get('failed_agents'):
            for failed in scan_result['failed_agents']:
                print(f'  ❌ Failed: {failed["agent_id"]} - {failed["error"]}')
        
        print()
        
        # Step 5: Check scan list
        print('5. Checking scan list...')
        time.sleep(2)  # Wait for scan to potentially start
        
        scans_resp = requests.get(f'{base_url}/api/v1/scans', timeout=10)
        scans_resp.raise_for_status()
        scans_data = scans_resp.json()
        
        print(f'✓ Total scans in system: {scans_data["total"]}')
        
        if scans_data['total'] > 0:
            # Show latest scans
            for i, scan in enumerate(scans_data['items'][:3]):  # Show top 3
                print(f'  Scan {i+1}:')
                print(f'    ID: {scan["id"]}')
                print(f'    Agent: {scan["agent_id"]}')
                print(f'    Type: {scan["scan_type"]}')
                print(f'    Status: {scan["status"]}')
                print(f'    Started: {scan["started_at"]}')
                if scan.get("progress"):
                    print(f'    Progress: {scan["progress"]}%')
                print()
        
        print('=== API Test Results ===')
        print('✓ Manager API is accessible and responding')
        print('✓ Agent enrollment confirmed')
        print('✓ Scan trigger API functional')
        
        if ws_stats['active_agents'] > 0:
            print('✓ Agent is connected and should receive commands')
        else:
            print('⚠ Agent appears offline - commands will be queued')
            
        print('\n🌐 Access admin UI at: http://localhost:8080')
        print('📊 Monitor scans and agent status through the web interface')
        
        return True
        
    except requests.exceptions.ConnectionError:
        print('❌ Cannot connect to manager API at localhost:8001')
        print('   Make sure the manager is running in Docker')
        return False
    except requests.exceptions.Timeout:
        print('❌ Manager API request timed out')
        return False
    except requests.exceptions.HTTPError as e:
        print(f'❌ HTTP error: {e}')
        if hasattr(e.response, 'text'):
            print(f'   Response: {e.response.text}')
        return False
    except Exception as e:
        print(f'❌ Unexpected error: {e}')
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)