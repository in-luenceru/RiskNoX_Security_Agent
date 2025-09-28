#!/usr/bin/env python3
"""
Modern RiskNoX Agent - Main Entry Point
Integrates with Manager via mTLS WebSocket
"""

import asyncio
import sys
import json
import socket
from pathlib import Path

from websocket_client import AgentWebSocketClient

async def main():
    """Main agent application"""
    
    # Load configuration
    config_file = Path("agent_config.json")
    if config_file.exists():
        with open(config_file) as f:
            config = json.load(f)
    else:
        # Default configuration
        config = {
            "manager_url": "wss://localhost:8000",
            "hostname": socket.gethostname(),
            "tags": ["windows", "workstation"] if sys.platform == "win32" else ["linux", "server"],
            "cert_dir": "./certs",
            "log_level": "INFO"
        }
        
        # Save default config
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    # Create and start agent
    agent = AgentWebSocketClient(config)
    
    try:
        print(f"Starting RiskNoX Agent v2.0.0")
        print(f"Manager URL: {config['manager_url']}")
        print(f"Hostname: {config['hostname']}")
        print(f"Tags: {', '.join(config['tags'])}")
        print("-" * 50)
        
        # Start agent
        success = await agent.start()
        if not success:
            print("Failed to start agent")
            return 1
            
        print("Agent started successfully! Press Ctrl+C to stop.")
        
        # Keep running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("\nAgent interrupted by user")
    except Exception as e:
        print(f"Agent crashed: {e}")
        return 1
    finally:
        await agent.stop()
        print("Agent stopped")
        
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nShutdown requested")
        sys.exit(0)