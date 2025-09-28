#!/usr/bin/env python3
"""
RiskNoX Agent Main
Secure agent client for RiskNoX security management system
"""

import asyncio
import argparse
import logging
import os
import signal
import socket
import sys
from pathlib import Path

import structlog
import colorama

# Add agent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from websocket_client import AgentWebSocketClient
from enrollment import AgentEnrollment
from certificate_manager import CertificateManager
from command_handler import CommandHandler

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class RiskNoXAgent:
    """Main RiskNoX agent class"""
    
    def __init__(self, config_file: str = "agent_config.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self.running = False
        
        # Initialize components
        self.cert_manager = CertificateManager(
            cert_dir=self.config.get("cert_dir", "certs")
        )
        self.command_handler = CommandHandler()
        self.ws_client = None
        
    def _load_config(self) -> dict:
        """Load agent configuration"""
        import yaml
        
        config_path = Path(self.config_file)
        if not config_path.exists():
            # Create default config
            default_config = {
                "manager_host": "localhost",
                "manager_port": 8443,  
                "manager_ws_port": 8444,
                "agent_id": None,  # Will be generated during enrollment
                "cert_dir": "certs",
                "log_level": "INFO",
                "reconnect_interval": 30,
                "heartbeat_interval": 60,
                "command_timeout": 300,
                "scan_paths": [
                    "C:\\" if sys.platform == "win32" else "/"
                ]
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            logger.info("Created default configuration", config_file=self.config_file)
            return default_config
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        logger.info("Configuration loaded", config_file=self.config_file)
        return config
    
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal", signal=signum)
            self.stop()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def start(self):
        """Start the agent"""
        self.running = True
        logger.info("Starting RiskNoX Agent", version="1.0.0")
        
        try:
            # Check if agent is enrolled
            if not self.cert_manager.has_valid_certificate():
                logger.info("Agent not enrolled, starting enrollment process")
                await self._enroll_agent()
            
            # Initialize WebSocket client
            ws_config = {
                "manager_url": f"ws://{self.config['manager_host']}:{self.config['manager_ws_port']}",
                "agent_id": self.config.get("agent_id"),
                "hostname": socket.gethostname(),
                "heartbeat_interval": self.config["heartbeat_interval"],
                "reconnect_interval": self.config["reconnect_interval"]
            }
            self.ws_client = AgentWebSocketClient(ws_config
            )
            
            # Start WebSocket connection
            await self.ws_client.start()
            
            # Main event loop
            while self.running:
                try:
                    await asyncio.sleep(1)
                    
                    # Check WebSocket health
                    if not self.ws_client.is_connected():
                        logger.warning("WebSocket disconnected, attempting reconnection")
                        await self.ws_client.reconnect()
                        
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in main loop", error=str(e))
                    await asyncio.sleep(5)
                    
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error("Agent startup failed", error=str(e))
            raise
        finally:
            await self.cleanup()
    
    async def _enroll_agent(self):
        """Enroll agent with manager"""
        manager_base_url = f"http://{self.config['manager_host']}:{self.config['manager_port']}"
        enrollment = AgentEnrollment(manager_base_url)
        
        try:
            import platform
            hostname = platform.node()
            os_type = platform.system()
            os_version = platform.version()
            agent_version = "1.0.0"
            
            result = await enrollment.enroll(
                hostname=hostname,
                os_type=os_type,
                os_version=os_version,
                agent_version=agent_version
            )
            agent_id = result.get("agent_id")
            
            # Update config with agent ID
            self.config["agent_id"] = agent_id
            
            # Save updated config
            import yaml
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
                
            logger.info("Agent enrolled successfully", agent_id=agent_id)
            
        except Exception as e:
            logger.error("Agent enrollment failed", error=str(e))
            raise
    
    def stop(self):
        """Stop the agent"""
        logger.info("Stopping RiskNoX Agent")
        self.running = False
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.ws_client:
            await self.ws_client.stop()
        logger.info("Agent cleanup completed")


async def main():
    """Main entry point"""
    # Initialize colorama for Windows terminal colors
    colorama.init()
    
    parser = argparse.ArgumentParser(description="RiskNoX Security Agent")
    parser.add_argument(
        "--config", 
        default="agent_config.yaml",
        help="Configuration file path"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level"
    )
    parser.add_argument(
        "--enroll-only",
        action="store_true",
        help="Perform enrollment only and exit"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=getattr(logging, args.log_level))
    
    # Create agent instance
    agent = RiskNoXAgent(config_file=args.config)
    
    # Set up signal handlers
    agent._setup_signal_handlers()
    
    try:
        if args.enroll_only:
            # Enrollment only mode
            if not agent.cert_manager.has_valid_certificate():
                await agent._enroll_agent()
                print("✅ Agent enrollment completed successfully!")
            else:
                print("✅ Agent already enrolled")
        else:
            # Normal operation mode
            await agent.start()
            
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error("Agent failed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())