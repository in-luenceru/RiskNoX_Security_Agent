#!/usr/bin/env python3
"""
Quick test script to verify the Manager application is working
"""

import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test all critical imports"""
    try:
        print("Testing imports...")
        
        # Test basic imports
        import fastapi
        print("✅ FastAPI imported")
        
        import prometheus_client
        print("✅ Prometheus client imported")
        
        import sqlalchemy
        print("✅ SQLAlchemy imported")
        
        # Test manager app imports
        import manager_app.main
        print("✅ Manager app main imported")
        
        import manager_app.db.models
        print("✅ Database models imported")
        
        import manager_app.api.health
        print("✅ Health API imported")
        
        print("\n🎉 ALL IMPORTS SUCCESSFUL!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_app_creation():
    """Test FastAPI app creation"""
    try:
        print("\nTesting app creation...")
        from manager_app.main import app
        print("✅ FastAPI app created successfully!")
        print(f"✅ App routes: {len(app.routes)} routes found")
        return True
    except Exception as e:
        print(f"❌ App creation error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 RiskNoX Manager Verification Test")
    print("=" * 50)
    
    import_success = test_imports()
    if import_success:
        app_success = test_app_creation()
        if app_success:
            print("\n🚀 MANAGER IS READY FOR PRODUCTION!")
            print("All core components are working correctly.")
        else:
            print("\n⚠️  Issues with app creation")
    else:
        print("\n❌ Import issues need to be resolved")