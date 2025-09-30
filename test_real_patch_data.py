#!/usr/bin/env python3
"""
Test script to verify that patch management is using real system data
instead of hardcoded values.
"""

import sys
import os
import json
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

# Import the SecurityAgent
from backend_server import SecurityAgent

def test_patch_management_real_data():
    """Test that patch management returns real system data"""
    print("🔍 Testing Patch Management System - Real Data Verification")
    print("=" * 60)
    
    # Initialize SecurityAgent
    agent = SecurityAgent()
    
    print("📊 Getting patch information...")
    patch_info = agent.get_patch_info()
    
    print(f"\n✅ Patch Info Results:")
    print(f"  - Success: {patch_info.get('success', False)}")
    print(f"  - Data Source: {patch_info.get('data_source', 'unknown')}")
    print(f"  - System: {patch_info.get('system_info', {}).get('OSName', 'Unknown')}")
    print(f"  - Computer: {patch_info.get('system_info', {}).get('ComputerName', 'Unknown')}")
    print(f"  - Installed Patches: {len(patch_info.get('installed_patches', []))}")
    print(f"  - Pending Updates: {patch_info.get('pending_count', 0)}")
    print(f"  - Compliance Status: {patch_info.get('compliance_status', 'Unknown')}")
    
    # Check if using real data indicators
    real_data_indicators = []
    
    # Check for real system info
    system_info = patch_info.get('system_info', {})
    if system_info.get('ComputerName') and system_info.get('ComputerName') != 'Unknown':
        real_data_indicators.append("✅ Real computer name detected")
    
    if system_info.get('OSName') and 'Windows' in system_info.get('OSName', ''):
        real_data_indicators.append("✅ Real OS name detected")
    
    # Check for real patches (not hardcoded KB numbers)
    installed_patches = patch_info.get('installed_patches', [])
    if installed_patches:
        # Look for variety in KB numbers (real systems have diverse patches)
        kb_numbers = [p.get('HotFixID', '') for p in installed_patches if p.get('HotFixID')]
        if len(set(kb_numbers)) > 1:  # More than one unique KB number
            real_data_indicators.append(f"✅ Multiple real KB patches detected: {len(kb_numbers)} patches")
        
        # Check for real installation dates
        install_dates = [p.get('InstalledOn', '') for p in installed_patches if p.get('InstalledOn') and p.get('InstalledOn') != 'Unknown']
        if install_dates:
            real_data_indicators.append(f"✅ Real installation dates detected")
    
    # Check data source
    data_source = patch_info.get('data_source', '')
    if data_source in ['live_system', 'python_fallback', 'wmic_fallback']:
        real_data_indicators.append(f"✅ Using real data source: {data_source}")
    
    # Check for absence of hardcoded indicators
    hardcoded_indicators = []
    
    # Look for old hardcoded KB numbers
    hardcoded_kbs = ['KB5005463', 'KB5006670', 'KB5007186', 'KB5008212', 'KB5008213', 'KB5030219', 'KB5007651', 'KB5008876']
    for patch in installed_patches:
        if patch.get('HotFixID') in hardcoded_kbs:
            hardcoded_indicators.append(f"⚠️  Hardcoded KB detected: {patch.get('HotFixID')}")
    
    # Check for hardcoded pending updates
    pending_updates = patch_info.get('pending_updates', [])
    for update in pending_updates:
        title = update.get('Title', '')
        if any(kb in title for kb in hardcoded_kbs):
            hardcoded_indicators.append(f"⚠️  Hardcoded pending update: {title}")
    
    print(f"\n📋 Real Data Verification:")
    if real_data_indicators:
        for indicator in real_data_indicators:
            print(f"  {indicator}")
    else:
        print("  ❌ No real data indicators found")
    
    print(f"\n🚨 Hardcoded Data Check:")
    if hardcoded_indicators:
        for indicator in hardcoded_indicators:
            print(f"  {indicator}")
        print(f"  ❌ STILL USING HARDCODED DATA!")
    else:
        print("  ✅ No hardcoded data detected - using real system data!")
    
    # Summary
    print(f"\n📊 Summary:")
    real_data_score = len(real_data_indicators)
    hardcoded_score = len(hardcoded_indicators)
    
    if real_data_score > 0 and hardcoded_score == 0:
        print(f"  🎉 SUCCESS: Patch management is using real system data!")
        print(f"     Real data indicators: {real_data_score}")
        print(f"     Hardcoded indicators: {hardcoded_score}")
        return True
    elif real_data_score > 0 and hardcoded_score > 0:
        print(f"  ⚠️  PARTIAL: Mix of real and hardcoded data detected")
        print(f"     Real data indicators: {real_data_score}")
        print(f"     Hardcoded indicators: {hardcoded_score}")
        return False
    else:
        print(f"  ❌ FAILED: Still using primarily hardcoded data")
        print(f"     Real data indicators: {real_data_score}")
        print(f"     Hardcoded indicators: {hardcoded_score}")
        return False

def test_update_history():
    """Test update history for real data"""
    print(f"\n🔍 Testing Update History...")
    
    agent = SecurityAgent()
    history = agent.get_detailed_update_history()
    
    print(f"  - Success: {history.get('success', False)}")
    print(f"  - Data Source: {history.get('data_source', 'unknown')}")
    print(f"  - History Entries: {history.get('retrieved_count', 0)}")
    
    # Check for real data in history
    history_entries = history.get('history_entries', [])
    if history_entries:
        first_entry = history_entries[0]
        print(f"  - First Entry: {first_entry.get('Title', 'Unknown')}")
        print(f"  - Install Date: {first_entry.get('Date', 'Unknown')}")
        
        # Check for real KB numbers (not hardcoded ones)
        real_kbs = [e.get('UpdateID', '') for e in history_entries if e.get('UpdateID') and not e.get('UpdateID').startswith('demo-')]
        if real_kbs:
            print(f"  - Real KB patches found: {len(real_kbs)}")
            return True
    
    return False

if __name__ == "__main__":
    print("🚀 RiskNoX Patch Management Real Data Test")
    print("=" * 50)
    
    # Test patch information
    patch_test_passed = test_patch_management_real_data()
    
    # Test update history
    history_test_passed = test_update_history()
    
    print(f"\n🏁 Final Results:")
    print(f"  - Patch Info Test: {'✅ PASSED' if patch_test_passed else '❌ FAILED'}")
    print(f"  - Update History Test: {'✅ PASSED' if history_test_passed else '❌ FAILED'}")
    
    if patch_test_passed and history_test_passed:
        print(f"\n🎉 ALL TESTS PASSED - Patch management is using real system data!")
        sys.exit(0)
    else:
        print(f"\n❌ SOME TESTS FAILED - Hardcoded data may still be present")
        sys.exit(1)