#!/usr/bin/env python3
"""
Build and run script for RiskNoX Manager with Admin UI
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(command, cwd=None, shell=True):
    """Run a command and return success status"""
    try:
        print(f"Running: {command}")
        result = subprocess.run(command, shell=shell, cwd=cwd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return False

def main():
    """Main build and run process"""
    # Get paths
    script_dir = Path(__file__).parent
    admin_ui_dir = script_dir / "admin-ui"
    static_dir = script_dir / "static" / "admin"
    
    print("🚀 Building RiskNoX Manager with Admin UI...")
    
    # Check if admin-ui directory exists
    if not admin_ui_dir.exists():
        print("❌ Admin UI directory not found!")
        return False
    
    # Change to admin-ui directory
    os.chdir(admin_ui_dir)
    
    # Install dependencies if node_modules doesn't exist
    if not (admin_ui_dir / "node_modules").exists():
        print("📦 Installing Admin UI dependencies...")
        if not run_command("npm install"):
            print("❌ Failed to install dependencies")
            return False
    
    # Build the UI
    print("🏗️  Building Admin UI...")
    if not run_command("npm run build"):
        print("❌ Failed to build Admin UI")
        return False
    
    # Copy build files to static directory
    build_dir = admin_ui_dir / "dist"
    if build_dir.exists():
        print("📂 Copying build files to static directory...")
        
        # Create static directory
        static_dir.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove existing static files
        if static_dir.exists():
            shutil.rmtree(static_dir)
        
        # Copy build files
        shutil.copytree(build_dir, static_dir)
        print("✅ Admin UI built and deployed")
    else:
        print("❌ Build directory not found!")
        return False
    
    # Change back to manager directory
    os.chdir(script_dir)
    
    # Start the manager
    print("🔥 Starting RiskNoX Manager...")
    try:
        import uvicorn
        uvicorn.run(
            "src.manager_app.main:app",
            host="0.0.0.0",
            port=8001,
            reload=False
        )
    except KeyboardInterrupt:
        print("\n⏹️  Manager stopped")
        return True
    except Exception as e:
        print(f"❌ Failed to start manager: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)