#!/usr/bin/env python3
"""
Manager startup script
"""
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "manager_app.main:app",
        host="0.0.0.0",
        port=8001,
        reload=False
    )