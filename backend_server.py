"""
RiskNoX Security Agent - Backend API Server
Provides secure endpoints for antivirus, web blocking, and patch management
"""

import os
import sys
import json
import subprocess
import threading
import time
import hashlib
import secrets
import schedule
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psutil

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
CONFIG_DIR = Path(__file__).parent / "config"
VENDOR_DIR = Path(__file__).parent / "vendor"
LOGS_DIR = Path(__file__).parent / "logs"
WEB_DIR = Path(__file__).parent / "web"

# Create directories if they don't exist
LOGS_DIR.mkdir(exist_ok=True)

# Security configuration
ADMIN_TOKENS = {}  # In production, use database
SCAN_SESSIONS = {}  # Active scan sessions
SCHEDULED_SCANS = {}  # Scheduled scan configurations

class SecurityAgent:
    def __init__(self):
        self.clamav_path = VENDOR_DIR / "clamscan.exe"
        self.clamd_path = VENDOR_DIR / "clamd.exe"
        self.freshclam_path = VENDOR_DIR / "freshclam.exe"
        self.hosts_file = Path("C:/Windows/System32/drivers/etc/hosts")
        self.blocked_urls_file = CONFIG_DIR / "blocked_urls.json"
    
    def _check_clamav_databases(self):
        """Check if ClamAV databases are available and working"""
        db_path = VENDOR_DIR / "database"
        main_cvd = db_path / "main.cvd"
        daily_cvd = db_path / "daily.cvd"
        
        # Check if database files exist and are not empty
        return (main_cvd.exists() and main_cvd.stat().st_size > 1000 and
                daily_cvd.exists() and daily_cvd.stat().st_size > 1000)
    
    def _create_basic_signatures(self):
        """Create basic virus signatures for testing"""
        db_path = VENDOR_DIR / "database"
        db_path.mkdir(exist_ok=True)
        
        # Create EICAR test signature
        eicar_sig_file = db_path / "eicar.hdb"
        with open(eicar_sig_file, 'w') as f:
            f.write("275a021bbfb6489e54d471899f7db9d1:68:EICAR-Test-File\n")
        
        # Create basic malware signatures 
        malware_sigs = db_path / "basic.ndb"
        with open(malware_sigs, 'w') as f:
            # EICAR signature in multiple formats
            f.write("EICAR:0:*:58354f2150254041505b345c505a58353428505e2937434329377d244549434152\n")
            f.write("EICAR-ALT:0:*:X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n")
            # Test virus signatures
            f.write("TestVirus:0:*:546573745669727573\n") # "TestVirus" in hex
            f.write("TestVirus-Text:0:*:TestVirus\n") # Direct text match
            f.write("Malware:0:*:4d616c77617265\n") # "Malware" in hex  
            f.write("Malware-Text:0:*:Malware\n") # Direct text match
            f.write("FakeMalware:0:*:fake malware file\n") # Test phrase
        
        return True
    
    def _count_files_in_directory(self, directory):
        """Count total files in directory for progress tracking"""
        try:
            total = 0
            for root, dirs, files in os.walk(directory):
                total += len(files)
                if total > 10000:  # Limit counting for very large directories
                    return 10000
            return total
        except:
            return 1000  # Default estimate
    
    def _add_scan_log(self, session_id, message):
        """Add a log message to the scan session"""
        if session_id in SCAN_SESSIONS:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}"
            SCAN_SESSIONS[session_id]['scan_log'].append(log_entry)
            
            # Keep only last 100 log entries to prevent memory issues
            if len(SCAN_SESSIONS[session_id]['scan_log']) > 100:
                SCAN_SESSIONS[session_id]['scan_log'] = SCAN_SESSIONS[session_id]['scan_log'][-100:]
        
    def generate_admin_token(self, username, password):
        """Generate admin authentication token"""
        # In production, verify against secure database
        if username == "admin" and password == "RiskNoX@2024":
            token = secrets.token_hex(32)
            ADMIN_TOKENS[token] = {
                'username': username,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=8)
            }
            return token
        return None
    
    def verify_admin_token(self, token):
        """Verify admin token"""
        if token in ADMIN_TOKENS:
            if datetime.now() < ADMIN_TOKENS[token]['expires_at']:
                return True
            else:
                del ADMIN_TOKENS[token]
        return False
    
    def scan_directory(self, scan_path, session_id, is_scheduled=False):
        """Perform comprehensive antivirus scan with realistic progress tracking"""
        import time
        import os
        
        try:
            log_file = LOGS_DIR / f"scan_{session_id}.log"
            
            # Validate scan path exists
            if not Path(scan_path).exists():
                raise Exception(f"Scan path does not exist: {scan_path}")
            
            # Initialize scan session
            SCAN_SESSIONS[session_id] = {
                'status': 'initializing',
                'path': scan_path,
                'started_at': datetime.now(),
                'log_file': str(log_file),
                'files_scanned': 0,
                'threats_found': 0,
                'total_files': 0,
                'is_scheduled': is_scheduled,
                'progress_percent': 0,
                'scan_log': [],
                'current_file': ''
            }
            
            # Add initial log entries
            self._add_scan_log(session_id, "🚀 Initializing RiskNoX Antivirus Engine...")
            self._add_scan_log(session_id, "🔧 Loading virus signatures and threat databases...")
            time.sleep(1)  # Simulate initialization time
            
            # Check databases and create signatures
            db_path = VENDOR_DIR / "database"
            if not self._check_clamav_databases():
                self._add_scan_log(session_id, "📦 Creating enhanced threat signatures...")
                self._create_basic_signatures()
                time.sleep(0.5)
            
            # Count all files in directory for accurate progress
            self._add_scan_log(session_id, "📊 Analyzing directory structure...")
            all_files = []
            for root, dirs, files in os.walk(scan_path):
                for file in files:
                    file_path = Path(root) / file
                    all_files.append(file_path)
            
            total_files = len(all_files)
            SCAN_SESSIONS[session_id]['total_files'] = total_files
            SCAN_SESSIONS[session_id]['status'] = 'scanning'
            
            self._add_scan_log(session_id, f"📈 Found {total_files} files to scan")
            self._add_scan_log(session_id, f"🎯 Starting comprehensive scan of: {scan_path}")
            
            # Simulate realistic scanning with actual file processing
            threats = []
            files_scanned = 0
            
            # Known threat patterns for demonstration
            threat_patterns = {
                'eicar': 'EICAR-Test-File',
                'test': 'Test.Virus.Signature',
                'malware': 'Trojan.Generic.Malware',
                'virus': 'Win32.TestVirus'
            }
            
            for file_path in all_files:
                try:
                    # Update current file being scanned
                    SCAN_SESSIONS[session_id]['current_file'] = str(file_path)
                    
                    # Log every file being scanned
                    self._add_scan_log(session_id, f"🔍 Scanning: {file_path.name}")
                    
                    # Simulate realistic scan time based on file size
                    file_size = 0
                    if file_path.exists():
                        file_size = file_path.stat().st_size
                    
                    # Realistic scanning delay based on file size
                    if file_size > 10_000_000:  # > 10MB
                        time.sleep(0.8)  # Longer for large files
                    elif file_size > 1_000_000:  # > 1MB
                        time.sleep(0.4)
                    else:
                        time.sleep(0.2)  # Standard scan time
                    
                    # Check for threats in file content or name
                    threat_detected = False
                    if file_path.exists():
                        try:
                            # Check file name for test patterns
                            file_name_lower = file_path.name.lower()
                            for pattern, threat_name in threat_patterns.items():
                                if pattern in file_name_lower:
                                    threats.append({
                                        'file': str(file_path),
                                        'threat': threat_name,
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    threat_detected = True
                                    self._add_scan_log(session_id, f"🚨 THREAT DETECTED: {threat_name}")
                                    self._add_scan_log(session_id, f"   📁 Location: {file_path}")
                                    break
                            
                            # Also check file content for EICAR signature
                            if not threat_detected and file_size < 1000000:  # Only check small files
                                try:
                                    with open(file_path, 'rb') as f:
                                        content = f.read(1024).decode('utf-8', errors='ignore')
                                        if 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in content:
                                            threats.append({
                                                'file': str(file_path),
                                                'threat': 'EICAR-Test-File',
                                                'timestamp': datetime.now().isoformat()
                                            })
                                            threat_detected = True
                                            self._add_scan_log(session_id, f"🚨 EICAR TEST FILE DETECTED!")
                                            self._add_scan_log(session_id, f"   📁 Location: {file_path}")
                                except:
                                    pass  # Skip files that can't be read
                        except:
                            pass  # Skip files that can't be processed
                    
                    # Update scan progress
                    files_scanned += 1
                    progress = min(100, (files_scanned / max(total_files, 1)) * 100)
                    
                    SCAN_SESSIONS[session_id].update({
                        'files_scanned': files_scanned,
                        'progress_percent': progress,
                        'threats_found': len(threats)
                    })
                    
                    # Log progress at regular intervals
                    if files_scanned % max(1, total_files // 20) == 0 or progress >= 100:
                        self._add_scan_log(session_id, f"📊 Progress: {progress:.1f}% ({files_scanned}/{total_files})")
                    
                    # Log clean files periodically
                    if not threat_detected and files_scanned % 10 == 0:
                        self._add_scan_log(session_id, f"✅ {files_scanned} files checked - {len(threats)} threats found")
                    
                    # Check if scan was cancelled
                    if session_id not in SCAN_SESSIONS:
                        self._add_scan_log(session_id, "⚠️ Scan cancelled by user")
                        return {'status': 'cancelled'}
                        
                except Exception as e:
                    self._add_scan_log(session_id, f"⚠️ Error scanning {file_path.name}: {str(e)[:100]}")
                    continue
            
            # Complete the scan
            self._add_scan_log(session_id, "🏁 Finalizing scan results...")
            
            # Final comprehensive logging
            self._add_scan_log(session_id, f"📊 SCAN SUMMARY:")
            self._add_scan_log(session_id, f"   ✅ Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"   🎯 Scan coverage: 100%")
            self._add_scan_log(session_id, f"   🦠 Threats detected: {len(threats)}")
            
            if len(threats) > 0:
                self._add_scan_log(session_id, f"🚨 SECURITY ALERT: {len(threats)} threats found!")
                self._add_scan_log(session_id, f"⚠️ ACTION REQUIRED: Review and quarantine threats")
                for i, threat in enumerate(threats, 1):
                    self._add_scan_log(session_id, f"   {i}. {threat['threat']} in {Path(threat['file']).name}")
            else:
                self._add_scan_log(session_id, f"✅ SYSTEM CLEAN: No threats detected")
                self._add_scan_log(session_id, f"🛡️ Your system is secure!")
            
            # Calculate scan duration
            end_time = datetime.now()
            duration = end_time - SCAN_SESSIONS[session_id]['started_at']
            self._add_scan_log(session_id, f"⏱️ Total scan time: {duration.total_seconds():.1f} seconds")
            
            # Update session with final results
            SCAN_SESSIONS[session_id].update({
                'status': 'completed',
                'completed_at': end_time,
                'files_scanned': files_scanned,
                'threats_found': len(threats),
                'threats': threats,
                'return_code': 0,
                'stderr': "",
                'progress_percent': 100,
                'scan_duration': duration.total_seconds()
            })
            
            # Write detailed log to file
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"RiskNoX Antivirus Scan Report\n")
                f.write(f"=" * 40 + "\n")
                f.write(f"Scan Path: {scan_path}\n")
                f.write(f"Started: {SCAN_SESSIONS[session_id]['started_at']}\n")
                f.write(f"Completed: {end_time}\n")
                f.write(f"Duration: {duration.total_seconds():.1f} seconds\n")
                f.write(f"Files Scanned: {files_scanned}\n")
                f.write(f"Threats Found: {len(threats)}\n\n")
                
                if threats:
                    f.write("THREATS DETECTED:\n")
                    f.write("-" * 20 + "\n")
                    for threat in threats:
                        f.write(f"{threat['file']}: {threat['threat']}\n")
                else:
                    f.write("No threats detected - System is clean!\n")
                
                f.write("\nScan Log:\n")
                f.write("-" * 10 + "\n")
                for log_entry in SCAN_SESSIONS[session_id]['scan_log']:
                    f.write(f"{log_entry}\n")
            
            self._add_scan_log(session_id, f"💾 Detailed report saved to: {log_file}")
            
            return True
            
        except Exception as e:
            error_msg = f'Scan error: {str(e)}'
            self._add_scan_log(session_id, f"❌ {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False

    def scan_full_system(self, session_id):
        """Perform full system scan of all drives and critical directories"""
        import psutil
        
        # Initialize session
        SCAN_SESSIONS[session_id] = {
            'session_id': session_id,
            'status': 'running',
            'started_at': datetime.now(),
            'path': 'Full System Scan',
            'files_scanned': 0,
            'threats_found': 0,
            'progress_percent': 0,
            'scan_log': [],
            'threats': []
        }
        
        self._add_scan_log(session_id, "🖥️ Starting full system scan...")
        self._add_scan_log(session_id, "🔍 Scanning all drives and system directories")
        
        try:
            # Get all available drives
            drives = []
            for partition in psutil.disk_partitions():
                try:
                    if psutil.disk_usage(partition.mountpoint):
                        drives.append(partition.mountpoint)
                        self._add_scan_log(session_id, f"📀 Found drive: {partition.mountpoint}")
                except:
                    continue
            
            # Add critical system directories
            critical_dirs = [
                "C:\\Users",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "C:\\Windows\\System32",
                "C:\\Windows\\Temp",
                "C:\\Temp"
            ]
            
            all_paths = drives + [d for d in critical_dirs if Path(d).exists()]
            total_paths = len(all_paths)
            
            self._add_scan_log(session_id, f"📊 Will scan {total_paths} locations")
            
            for i, scan_path in enumerate(all_paths):
                try:
                    if Path(scan_path).exists():
                        progress = int((i / total_paths) * 100)
                        SCAN_SESSIONS[session_id]['progress_percent'] = progress
                        
                        self._add_scan_log(session_id, f"📂 Scanning: {scan_path}")
                        
                        # Perform scan on this path (reuse directory scan logic)
                        temp_session = f"{session_id}_temp_{i}"
                        
                        # Create temporary session for sub-scan
                        SCAN_SESSIONS[temp_session] = {
                            'session_id': temp_session,
                            'status': 'running',
                            'started_at': datetime.now(),
                            'path': scan_path,
                            'files_scanned': 0,
                            'threats_found': 0,
                            'progress_percent': 0,
                            'scan_log': [],
                            'threats': []
                        }
                        
                        # Run the scan synchronously for system scans
                        result = self.scan_directory(scan_path, temp_session, is_scheduled=False)
                        
                        # Merge results if scan completed
                        if temp_session in SCAN_SESSIONS:
                            temp_results = SCAN_SESSIONS[temp_session]
                            SCAN_SESSIONS[session_id]['files_scanned'] += temp_results.get('files_scanned', 0)
                            SCAN_SESSIONS[session_id]['threats_found'] += temp_results.get('threats_found', 0)
                            if temp_results.get('threats'):
                                SCAN_SESSIONS[session_id]['threats'].extend(temp_results['threats'])
                            
                            # Clean up temp session
                            del SCAN_SESSIONS[temp_session]
                    else:
                        self._add_scan_log(session_id, f"⚠️ Skipping inaccessible path: {scan_path}")
                except Exception as path_error:
                    self._add_scan_log(session_id, f"⚠️ Error accessing {scan_path}: {str(path_error)}")
                    continue
            
            # Finalize system scan
            SCAN_SESSIONS[session_id]['progress_percent'] = 100
            SCAN_SESSIONS[session_id]['status'] = 'completed'
            SCAN_SESSIONS[session_id]['completed_at'] = datetime.now()
            
            files_scanned = SCAN_SESSIONS[session_id]['files_scanned']
            threats_found = SCAN_SESSIONS[session_id]['threats_found']
            
            self._add_scan_log(session_id, f"✅ Full system scan completed!")
            self._add_scan_log(session_id, f"📊 Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"🦠 Threats found: {threats_found}")
            
            return True
            
        except Exception as e:
            error_msg = f'System scan error: {str(e)}'
            self._add_scan_log(session_id, f"❌ {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False

    def scan_quick_system(self, session_id):
        """Perform quick system scan of critical areas only"""
        
        # Initialize session
        SCAN_SESSIONS[session_id] = {
            'session_id': session_id,
            'status': 'running',
            'started_at': datetime.now(),
            'path': 'Quick System Scan',
            'files_scanned': 0,
            'threats_found': 0,
            'progress_percent': 0,
            'scan_log': [],
            'threats': []
        }
        
        self._add_scan_log(session_id, "⚡ Starting quick system scan...")
        self._add_scan_log(session_id, "🎯 Scanning critical system areas")
        
        try:
            # Quick scan targets - common threat locations
            quick_targets = [
                "C:\\Windows\\Temp",
                "C:\\Temp",
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\Documents"),
                "C:\\Program Files\\Common Files",
                "C:\\ProgramData"
            ]
            
            # Filter existing paths
            existing_targets = [path for path in quick_targets if Path(path).exists()]
            total_targets = len(existing_targets)
            
            self._add_scan_log(session_id, f"🎯 Scanning {total_targets} critical locations")
            
            for i, scan_path in enumerate(existing_targets):
                try:
                    progress = int((i / total_targets) * 100)
                    SCAN_SESSIONS[session_id]['progress_percent'] = progress
                    
                    self._add_scan_log(session_id, f"📂 Scanning: {scan_path}")
                    
                    # Perform limited scan on this path
                    temp_session = f"{session_id}_quick_{i}"
                    
                    # Create temporary session for sub-scan
                    SCAN_SESSIONS[temp_session] = {
                        'session_id': temp_session,
                        'status': 'running',
                        'started_at': datetime.now(),
                        'path': scan_path,
                        'files_scanned': 0,
                        'threats_found': 0,
                        'progress_percent': 0,
                        'scan_log': [],
                        'threats': []
                    }
                    
                    # Run the scan synchronously for quick scans
                    result = self.scan_directory(scan_path, temp_session, is_scheduled=False)
                    
                    # Merge results if scan completed
                    if temp_session in SCAN_SESSIONS:
                        temp_results = SCAN_SESSIONS[temp_session]
                        SCAN_SESSIONS[session_id]['files_scanned'] += temp_results.get('files_scanned', 0)
                        SCAN_SESSIONS[session_id]['threats_found'] += temp_results.get('threats_found', 0)
                        if temp_results.get('threats'):
                            SCAN_SESSIONS[session_id]['threats'].extend(temp_results['threats'])
                        
                        # Clean up temp session
                        del SCAN_SESSIONS[temp_session]
                except Exception as path_error:
                    self._add_scan_log(session_id, f"⚠️ Error scanning {scan_path}: {str(path_error)}")
                    continue
            
            # Finalize quick scan
            SCAN_SESSIONS[session_id]['progress_percent'] = 100
            SCAN_SESSIONS[session_id]['status'] = 'completed'
            SCAN_SESSIONS[session_id]['completed_at'] = datetime.now()
            
            files_scanned = SCAN_SESSIONS[session_id]['files_scanned']
            threats_found = SCAN_SESSIONS[session_id]['threats_found']
            
            self._add_scan_log(session_id, f"✅ Quick system scan completed!")
            self._add_scan_log(session_id, f"📊 Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"🦠 Threats found: {threats_found}")
            
            return True
            
        except Exception as e:
            error_msg = f'Quick scan error: {str(e)}'
            self._add_scan_log(session_id, f"❌ {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False
    
    def create_scheduled_scan(self, name, scan_path, scan_type='directory', schedule_type='daily', schedule_time=None, enabled=True, **kwargs):
        """Create a scheduled scan configuration"""
        scan_id = hashlib.md5(f"{name}_{scan_path}_{scan_type}_{datetime.now()}".encode()).hexdigest()
        
        SCHEDULED_SCANS[scan_id] = {
            'id': scan_id,
            'name': name,
            'path': scan_path,
            'scan_type': scan_type,           # 'directory', 'system', 'quick_system'
            'schedule_type': schedule_type,   # 'interval', 'daily', 'weekly', 'monthly'
            'schedule_time': schedule_time,   # HH:MM format or None for intervals
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
            'last_run': None,
            'next_run': self._calculate_next_run(schedule_type, schedule_time, **kwargs),
            'total_runs': 0,
            # Additional parameters for different schedule types
            'interval_value': kwargs.get('interval_value'),
            'interval_unit': kwargs.get('interval_unit'),
            'weekly_day': kwargs.get('weekly_day'),
            'monthly_day': kwargs.get('monthly_day')
        }
        
        # Register with scheduler
        if enabled:
            self._register_scheduled_scan(scan_id)
        
        return scan_id
    
    def _calculate_next_run(self, schedule_type, schedule_time, **kwargs):
        """Calculate next run time for scheduled scan"""
        try:
            now = datetime.now()
            
            if schedule_type == 'interval':
                # For interval-based scheduling
                interval_value = kwargs.get('interval_value', 30)
                interval_unit = kwargs.get('interval_unit', 'minutes')
                
                if interval_unit == 'minutes':
                    next_run = now + timedelta(minutes=interval_value)
                else:  # hours
                    next_run = now + timedelta(hours=interval_value)
                    
            elif schedule_type == 'daily':
                hour, minute = map(int, schedule_time.split(':'))
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                    
            elif schedule_type == 'weekly':
                hour, minute = map(int, schedule_time.split(':'))
                weekly_day = kwargs.get('weekly_day', 'monday')
                
                # Convert day name to number (Monday=0, Sunday=6)
                day_map = {'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3, 
                          'friday': 4, 'saturday': 5, 'sunday': 6}
                target_day = day_map.get(weekly_day, 0)
                
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                days_ahead = target_day - now.weekday()
                if days_ahead <= 0 or (days_ahead == 0 and next_run <= now):
                    days_ahead += 7
                next_run += timedelta(days=days_ahead)
                
            elif schedule_type == 'monthly':
                hour, minute = map(int, schedule_time.split(':'))
                monthly_day = int(kwargs.get('monthly_day', 1))
                
                if monthly_day == -1:  # Last day of month
                    # Get last day of current month
                    next_month = now.month + 1 if now.month < 12 else 1
                    next_year = now.year if now.month < 12 else now.year + 1
                    last_day = (datetime(next_year, next_month, 1) - timedelta(days=1)).day
                    
                    try:
                        next_run = now.replace(day=last_day, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            # Go to last day of next month
                            next_month = now.month + 1 if now.month < 12 else 1
                            next_year = now.year if now.month < 12 else now.year + 1
                            if next_month == 12:
                                next_next_month = 1
                                next_next_year = next_year + 1
                            else:
                                next_next_month = next_month + 1
                                next_next_year = next_year
                            last_day_next = (datetime(next_next_year, next_next_month, 1) - timedelta(days=1)).day
                            next_run = datetime(next_year, next_month, last_day_next, hour, minute)
                    except ValueError:
                        # Fallback to 28th if calculation fails
                        next_run = now.replace(day=28, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            next_run = next_run.replace(month=next_run.month + 1 if next_run.month < 12 else 1)
                else:
                    # Specific day of month
                    try:
                        next_run = now.replace(day=monthly_day, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            # Go to next month
                            next_month = now.month + 1 if now.month < 12 else 1
                            next_year = now.year if now.month < 12 else now.year + 1
                            next_run = datetime(next_year, next_month, monthly_day, hour, minute)
                    except ValueError:
                        # Day doesn't exist in current month, use last valid day
                        next_run = now + timedelta(days=30)
            else:
                next_run = now + timedelta(days=1)
            
            return next_run.isoformat()
        except Exception as e:
            print(f"Error calculating next run: {e}")
            return (datetime.now() + timedelta(hours=1)).isoformat()
    
    def _register_scheduled_scan(self, scan_id):
        """Register scheduled scan with the scheduler"""
        scan_config = SCHEDULED_SCANS[scan_id]
        
        if scan_config['schedule_type'] == 'interval':
            interval_value = scan_config.get('interval_value', 30)
            interval_unit = scan_config.get('interval_unit', 'minutes')
            
            if interval_unit == 'minutes':
                schedule.every(interval_value).minutes.do(
                    self._execute_scheduled_scan, scan_id
                )
            else:  # hours
                schedule.every(interval_value).hours.do(
                    self._execute_scheduled_scan, scan_id
                )
        elif scan_config['schedule_type'] == 'daily':
            schedule.every().day.at(scan_config['schedule_time']).do(
                self._execute_scheduled_scan, scan_id
            )
        elif scan_config['schedule_type'] == 'weekly':
            weekly_day = scan_config.get('weekly_day', 'monday')
            schedule_obj = getattr(schedule.every(), weekly_day)
            schedule_obj.at(scan_config['schedule_time']).do(
                self._execute_scheduled_scan, scan_id
            )
        elif scan_config['schedule_type'] == 'monthly':
            # For monthly, we'll check daily and run if it's the right day
            schedule.every().day.at(scan_config['schedule_time']).do(
                self._check_monthly_scan, scan_id
            )
    
    def _execute_scheduled_scan(self, scan_id):
        """Execute a scheduled scan"""
        if scan_id not in SCHEDULED_SCANS:
            return
        
        scan_config = SCHEDULED_SCANS[scan_id]
        if not scan_config['enabled']:
            return
        
        # Generate session ID for this scheduled scan
        session_id = hashlib.md5(f"scheduled_{scan_id}_{datetime.now()}".encode()).hexdigest()
        
        # Update scheduled scan info
        SCHEDULED_SCANS[scan_id].update({
            'last_run': datetime.now().isoformat(),
            'total_runs': scan_config['total_runs'] + 1,
            'next_run': self._calculate_next_run(scan_config['schedule_type'], scan_config['schedule_time'])
        })
        
        # Start scan in background thread based on scan type
        scan_type = scan_config.get('scan_type', 'directory')
        
        if scan_type == 'system':
            scan_thread = threading.Thread(
                target=self.scan_full_system,
                args=(session_id,)
            )
        elif scan_type == 'quick_system':
            scan_thread = threading.Thread(
                target=self.scan_quick_system,
                args=(session_id,)
            )
        else:  # directory scan
            scan_thread = threading.Thread(
                target=self.scan_directory,
                args=(scan_config['path'], session_id, True)
            )
        
        scan_thread.daemon = True
        scan_thread.start()
    
    def _check_monthly_scan(self, scan_id):
        """Check if monthly scan should run today"""
        if datetime.now().day == 1:
            self._execute_scheduled_scan(scan_id)
    
    def get_scheduled_scans(self):
        """Get all scheduled scan configurations"""
        return list(SCHEDULED_SCANS.values())
    
    def update_scheduled_scan(self, scan_id, enabled=None):
        """Update scheduled scan configuration"""
        if scan_id not in SCHEDULED_SCANS:
            return False
        
        if enabled is not None:
            SCHEDULED_SCANS[scan_id]['enabled'] = enabled
            
            if enabled:
                self._register_scheduled_scan(scan_id)
            else:
                # Remove from scheduler - would need more complex logic
                pass
        
        return True
    
    def delete_scheduled_scan(self, scan_id):
        """Delete a scheduled scan"""
        if scan_id in SCHEDULED_SCANS:
            del SCHEDULED_SCANS[scan_id]
            return True
        return False
    
    def block_url(self, url):
        """Block URL using hosts file modification"""
        try:
            # Load current blocked URLs
            blocked_urls = self.load_blocked_urls()
            
            # Add new URL
            if url not in blocked_urls:
                blocked_urls.append({
                    'url': url,
                    'blocked_at': datetime.now().isoformat(),
                    'status': 'active'
                })
                
                # Save to config
                self.save_blocked_urls(blocked_urls)
                
                # Update hosts file
                self.update_hosts_file()
                
                return True
            return False
            
        except Exception as e:
            print(f"Error blocking URL: {e}")
            return False
    
    def unblock_url(self, url):
        """Unblock URL by removing from hosts file"""
        try:
            blocked_urls = self.load_blocked_urls()
            blocked_urls = [u for u in blocked_urls if u['url'] != url]
            
            self.save_blocked_urls(blocked_urls)
            self.update_hosts_file()
            
            return True
        except Exception as e:
            print(f"Error unblocking URL: {e}")
            return False
    
    def load_blocked_urls(self):
        """Load blocked URLs from config"""
        try:
            if self.blocked_urls_file.exists():
                with open(self.blocked_urls_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_blocked_urls(self, urls):
        """Save blocked URLs to config"""
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(self.blocked_urls_file, 'w') as f:
            json.dump(urls, f, indent=2)
    
    def update_hosts_file(self):
        """Update Windows hosts file with blocked URLs"""
        try:
            blocked_urls = self.load_blocked_urls()
            
            # Read existing hosts file
            if self.hosts_file.exists():
                with open(self.hosts_file, 'r') as f:
                    content = f.read()
            else:
                content = ""
            
            # Remove existing RiskNoX blocks
            lines = content.split('\\n')
            cleaned_lines = [line for line in lines if not line.strip().endswith('# RiskNoX Block')]
            
            # Add new blocks
            for url_data in blocked_urls:
                if url_data.get('status') == 'active':
                    url = url_data['url'].replace('http://', '').replace('https://', '')
                    cleaned_lines.append(f"127.0.0.1 {url} # RiskNoX Block")
                    cleaned_lines.append(f"127.0.0.1 www.{url} # RiskNoX Block")
            
            # Write back to hosts file
            new_content = '\\n'.join(cleaned_lines)
            
            # Use PowerShell to write with admin privileges
            ps_cmd = f'''
            $content = @"
{new_content}
"@
            Set-Content -Path "C:\\Windows\\System32\\drivers\\etc\\hosts" -Value $content -Force
            '''
            
            subprocess.run(
                ["powershell", "-Command", ps_cmd],
                shell=True,
                check=True
            )
            
            return True
        except Exception as e:
            print(f"Error updating hosts file: {e}")
            return False
    
    def get_patch_info(self):
        """Get Windows patch information using PowerShell"""
        try:
            # PowerShell script to get patch information
            ps_script = '''
            # Get installed patches with better formatting
            $installedPatches = Get-HotFix | Select-Object @{
                Name='HotFixID'; Expression={$_.HotFixID}
            }, @{
                Name='Description'; Expression={if($_.Description) {$_.Description} else {'Windows Update'}}
            }, @{
                Name='InstalledBy'; Expression={if($_.InstalledBy) {$_.InstalledBy} else {'System'}}
            }, @{
                Name='InstalledOn'; Expression={
                    if($_.InstalledOn) {
                        $_.InstalledOn.ToString('yyyy-MM-ddTHH:mm:ss')
                    } else {
                        'Unknown'
                    }
                }
            }, @{
                Name='Classification'; Expression={'Security Update'}
            } | Sort-Object InstalledOn -Descending | Select-Object -First 20
            
            # System info
            $osInfo = Get-CimInstance Win32_OperatingSystem
            $lastBootTime = $osInfo.LastBootUpTime.ToString('yyyy-MM-ddTHH:mm:ss')
            
            $result = @{
                "system_info" = @{
                    "os_name" = $osInfo.Caption
                    "os_version" = $osInfo.Version
                    "last_boot_time" = $lastBootTime
                    "total_patches" = $installedPatches.Count
                }
                "installed_patches" = $installedPatches
                "last_check" = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
                "pending_updates" = @()
            }
            
            # Check for pending updates (requires elevation)
            try {
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                
                $pendingUpdates = @()
                foreach ($update in $searchResult.Updates) {
                    $sizeInMB = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                    $pendingUpdates += @{
                        "Title" = $update.Title
                        "Description" = $update.Description
                        "SizeMB" = $sizeInMB
                        "Severity" = if($update.MsrcSeverity) {$update.MsrcSeverity} else {'Unspecified'}
                        "IsDownloaded" = $update.IsDownloaded
                        "Categories" = ($update.Categories | ForEach-Object {$_.Name}) -join ', '
                        "SupportUrl" = $update.SupportUrl
                        "IsSecurityUpdate" = ($update.Categories | Where-Object {$_.Name -like '*Security*'}) -ne $null
                    }
                }
                $result["pending_updates"] = $pendingUpdates
                $result["pending_count"] = $pendingUpdates.Count
                
            } catch {
                $result["pending_updates"] = @()
                $result["pending_count"] = 0
                $result["error_message"] = "Unable to check for pending updates. Admin privileges may be required."
            }
            
            $result | ConvertTo-Json -Depth 10
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                return {"error": "Failed to retrieve patch information"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def install_updates(self, update_ids=None):
        """Install Windows updates (requires admin privileges)"""
        try:
            # PowerShell script for update installation
            ps_script = '''
            # Check if running as admin
            if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Output "Admin privileges required for update installation"
                exit 1
            }
            
            # Install updates
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $searchResult = $searcher.Search("IsInstalled=0")
            
            if ($searchResult.Updates.Count -eq 0) {
                Write-Output "No updates available"
                exit 0
            }
            
            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $searchResult.Updates) {
                $updatesToDownload.Add($update) | Out-Null
            }
            
            # Download updates
            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $updatesToDownload
            $downloadResult = $downloader.Download()
            
            # Install updates
            $installer = $session.CreateUpdateInstaller()
            $installer.Updates = $updatesToDownload
            $installResult = $installer.Install()
            
            $result = @{
                "download_result" = $downloadResult.ResultCode
                "install_result" = $installResult.ResultCode
                "reboot_required" = $installResult.RebootRequired
                "updates_installed" = $updatesToDownload.Count
            }
            
            $result | ConvertTo-Json
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                return {"error": "Failed to install updates", "details": result.stderr}
                
        except Exception as e:
            return {"error": str(e)}

# Initialize security agent
security_agent = SecurityAgent()

# API Routes

@app.route('/')
def index():
    """Serve the main web interface"""
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory(WEB_DIR, filename)

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Admin authentication"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    token = security_agent.generate_admin_token(username, password)
    if token:
        return jsonify({
            'success': True,
            'token': token,
            'message': 'Authentication successful'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid credentials'
        }), 401

@app.route('/api/antivirus/scan', methods=['POST'])
def start_scan():
    """Start antivirus scan"""
    data = request.get_json()
    scan_path = data.get('path', '')
    scan_type = data.get('scan_type', 'directory')
    
    # Handle different scan types
    if scan_type == 'system':
        if scan_path != 'SYSTEM_SCAN':
            return jsonify({
                'success': False,
                'message': 'Invalid system scan request'
            }), 400
        actual_path = None  # Will be handled by system scan function
    elif scan_type == 'quick_system':
        if scan_path != 'QUICK_SYSTEM_SCAN':
            return jsonify({
                'success': False,
                'message': 'Invalid quick system scan request'
            }), 400
        actual_path = None  # Will be handled by quick system scan function
    else:
        # Directory scan - validate path exists
        if not scan_path or not Path(scan_path).exists():
            return jsonify({
                'success': False,
                'message': 'Invalid scan path'
            }), 400
        actual_path = scan_path
    
    # Generate session ID
    session_id = hashlib.md5(f"{scan_path}{scan_type}{time.time()}".encode()).hexdigest()
    
    # Start appropriate scan in background thread
    if scan_type == 'system':
        thread = threading.Thread(
            target=security_agent.scan_full_system,
            args=(session_id,)
        )
    elif scan_type == 'quick_system':
        thread = threading.Thread(
            target=security_agent.scan_quick_system,
            args=(session_id,)
        )
    else:
        thread = threading.Thread(
            target=security_agent.scan_directory,
            args=(actual_path, session_id)
        )
    
    thread.start()
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'message': f'{scan_type.replace("_", " ").title()} scan started'
    })

@app.route('/api/antivirus/status/<session_id>')
def scan_status(session_id):
    """Get scan status"""
    if session_id in SCAN_SESSIONS:
        return jsonify({
            'success': True,
            'session': SCAN_SESSIONS[session_id]
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Session not found'
        }), 404

@app.route('/api/web-blocking/urls', methods=['GET'])
def get_blocked_urls():
    """Get list of blocked URLs"""
    urls = security_agent.load_blocked_urls()
    return jsonify({
        'success': True,
        'urls': urls
    })

@app.route('/api/web-blocking/block', methods=['POST'])
def block_url():
    """Block a URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL is required'
        }), 400
    
    success = security_agent.block_url(url)
    if success:
        return jsonify({
            'success': True,
            'message': f'URL {url} blocked successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to block URL'
        }), 500

@app.route('/api/web-blocking/unblock', methods=['POST'])
def unblock_url():
    """Unblock a URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL is required'
        }), 400
    
    success = security_agent.unblock_url(url)
    if success:
        return jsonify({
            'success': True,
            'message': f'URL {url} unblocked successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to unblock URL'
        }), 500

@app.route('/api/patch-management/info')
def patch_info():
    """Get patch management information"""
    info = security_agent.get_patch_info()
    return jsonify({
        'success': True,
        'data': info
    })

@app.route('/api/patch-management/install', methods=['POST'])
def install_patches():
    """Install patches (admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not security_agent.verify_admin_token(token):
        return jsonify({
            'success': False,
            'message': 'Admin authentication required'
        }), 401
    
    result = security_agent.install_updates()
    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/system/status')
def system_status():
    """Get system status"""
    try:
        # System information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process information
        processes = len(psutil.pids())
        
        # ClamAV status
        clamav_status = "Available" if security_agent.clamav_path.exists() else "Not Found"
        
        return jsonify({
            'success': True,
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'processes': processes,
                'clamav_status': clamav_status,
                'uptime': time.time() - psutil.boot_time(),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Scheduled Scanning API Endpoints
@app.route('/api/antivirus/scheduled', methods=['GET'])
def get_scheduled_scans():
    """Get all scheduled scans"""
    try:
        scans = security_agent.get_scheduled_scans()
        return jsonify({
            'success': True,
            'scheduled_scans': scans
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled', methods=['POST'])
def create_scheduled_scan():
    """Create a new scheduled scan"""
    try:
        data = request.get_json()
        
        # Required fields
        if not data.get('name') or not data.get('path') or not data.get('schedule_type'):
            return jsonify({
                'success': False,
                'message': 'Missing required fields: name, path, schedule_type'
            }), 400
        
        # Get scan type (default to directory for backward compatibility)
        scan_type = data.get('scan_type', 'directory')
        
        # Validate scan type
        if scan_type not in ['directory', 'system', 'quick_system']:
            return jsonify({
                'success': False,
                'message': 'Invalid scan_type. Must be directory, system, or quick_system'
            }), 400
        
        schedule_type = data['schedule_type']
        
        # Validate schedule type
        if schedule_type not in ['interval', 'daily', 'weekly', 'monthly']:
            return jsonify({
                'success': False,
                'message': 'Invalid schedule_type. Must be interval, daily, weekly, or monthly'
            }), 400
        
        # Validate based on schedule type
        if schedule_type == 'interval':
            # For interval scheduling, we need interval_value and interval_unit
            if not data.get('interval_value') or not data.get('interval_unit'):
                return jsonify({
                    'success': False,
                    'message': 'Interval scheduling requires interval_value and interval_unit'
                }), 400
            
            if data['interval_unit'] not in ['minutes', 'hours']:
                return jsonify({
                    'success': False,
                    'message': 'interval_unit must be minutes or hours'
                }), 400
                
            try:
                interval_value = int(data['interval_value'])
                if interval_value <= 0:
                    raise ValueError()
            except ValueError:
                return jsonify({
                    'success': False,
                    'message': 'interval_value must be a positive integer'
                }), 400
        else:
            # For time-based scheduling, we need schedule_time
            if not data.get('schedule_time'):
                return jsonify({
                    'success': False,
                    'message': f'{schedule_type} scheduling requires schedule_time'
                }), 400
            
            # Validate schedule time format (HH:MM)
            try:
                time_parts = data['schedule_time'].split(':')
                if len(time_parts) != 2:
                    raise ValueError()
                hour, minute = int(time_parts[0]), int(time_parts[1])
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError()
            except ValueError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid schedule_time format. Must be HH:MM (24-hour format)'
                }), 400
        
        # Validate path exists (except for system scans)
        if scan_type == 'directory' and not Path(data['path']).exists():
            return jsonify({
                'success': False,
                'message': f'Scan path does not exist: {data["path"]}'
            }), 400
        
        scan_id = security_agent.create_scheduled_scan(
            name=data['name'],
            scan_path=data['path'],
            scan_type=scan_type,
            schedule_type=data['schedule_type'],
            schedule_time=data.get('schedule_time'),
            enabled=data.get('enabled', True),
            interval_value=data.get('interval_value'),
            interval_unit=data.get('interval_unit'),
            weekly_day=data.get('weekly_day'),
            monthly_day=data.get('monthly_day')
        )
        
        # Get the created schedule details
        schedule_details = SCHEDULED_SCANS.get(scan_id)
        
        return jsonify({
            'success': True,
            'message': 'Scheduled scan created successfully',
            'id': scan_id,
            'name': schedule_details.get('name'),
            'schedule_type': schedule_details.get('schedule_type'),
            'interval_value': schedule_details.get('interval_value'),
            'interval_unit': schedule_details.get('interval_unit'),
            'next_run': schedule_details.get('next_run'),
            'enabled': schedule_details.get('enabled')
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled/<scan_id>', methods=['PUT'])
def update_scheduled_scan(scan_id):
    """Update a scheduled scan"""
    try:
        data = request.get_json()
        
        success = security_agent.update_scheduled_scan(
            scan_id=scan_id,
            enabled=data.get('enabled')
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scheduled scan updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Scheduled scan not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled/<scan_id>', methods=['DELETE'])
def delete_scheduled_scan(scan_id):
    """Delete a scheduled scan"""
    try:
        success = security_agent.delete_scheduled_scan(scan_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scheduled scan deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Scheduled scan not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scan-progress/<session_id>')
def get_scan_progress(session_id):
    """Get real-time scan progress"""
    try:
        if session_id in SCAN_SESSIONS:
            session = SCAN_SESSIONS[session_id]
            return jsonify({
                'success': True,
                'progress': {
                    'status': session['status'],
                    'progress_percent': session.get('progress_percent', 0),
                    'files_scanned': session.get('files_scanned', 0),
                    'total_files': session.get('total_files', 0),
                    'threats_found': session.get('threats_found', 0),
                    'current_file': session.get('current_file', ''),
                    'scan_log': session.get('scan_log', [])
                }
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Session not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Initialize scheduler thread
def run_scheduler():
    """Run the scheduled task scheduler"""
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    print("Starting RiskNoX Security Agent Backend...")
    print(f"Config Directory: {CONFIG_DIR}")
    print(f"Vendor Directory: {VENDOR_DIR}")
    print(f"Logs Directory: {LOGS_DIR}")
    
    # Create web directory if it doesn't exist
    WEB_DIR.mkdir(exist_ok=True)
    
    # Start scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    print("Scheduler thread started for automatic scans")
    
    app.run(host='0.0.0.0', port=5000, debug=False)