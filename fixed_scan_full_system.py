    def scan_full_system(self, session_id):
        """Production-ready full system scan with checkpointing and retry mechanisms"""
        import psutil
        import threading
        import time
        
        # Check for existing checkpoint and attempt recovery
        checkpoint_data = self._load_checkpoint(session_id)
        resume_from_checkpoint = checkpoint_data is not None
        
        # Initialize or restore session
        if resume_from_checkpoint:
            SCAN_SESSIONS[session_id] = checkpoint_data
            SCAN_SESSIONS[session_id].update({
                'status': 'resuming',
                'resumed_at': datetime.now(),
                'last_update': datetime.now(),
                'scan_stage': 'checkpoint_recovery'
            })
            self._add_scan_log(session_id, "🔄 Resuming full system scan from checkpoint...")
        else:
            SCAN_SESSIONS[session_id] = {
                'session_id': session_id,
                'status': 'initializing',
                'started_at': datetime.now(),
                'path': 'Full System Scan',
                'files_scanned': 0,
                'threats_found': 0,
                'progress_percent': 1,
                'scan_log': [],
                'threats': [],
                'last_update': datetime.now(),
                'total_files': 0,
                'current_file': 'Initializing production system scan...',
                'scan_speed': 0,
                'errors': [],
                'bytes_scanned': 0,
                'scan_stage': 'initialization',
                'sub_scans_completed': 0,
                'sub_scans_total': 0,
                'processed_locations': set(),
                'scan_timeout': datetime.now() + timedelta(hours=SCAN_TIMEOUT_HOURS),
                'performance_stats': {
                    'avg_files_per_second': 0,
                    'peak_memory_mb': 0,
                    'total_retries': 0,
                    'locations_skipped': 0
                }
            }
            self._add_scan_log(session_id, "🖥️ Initializing production-grade full system scan...")

        print(f"[SCAN {session_id[:8]}] Full system scan {'resumed' if resume_from_checkpoint else 'initialized'}")

        try:
            # Set up resource monitoring
            resource_monitor_active = True
            def resource_monitor():
                while resource_monitor_active and session_id in SCAN_SESSIONS:
                    self._monitor_system_resources(session_id)
                    time.sleep(30)
            
            resource_thread = threading.Thread(target=resource_monitor, daemon=True)
            resource_thread.start()

            # Build scan targets
            if not resume_from_checkpoint:
                # Get available drives
                drives = []
                for partition in psutil.disk_partitions():
                    try:
                        if partition.fstype in ['NTFS', 'FAT32', 'exFAT', '']:
                            drives.append(partition.mountpoint)
                    except:
                        continue

                # Priority locations
                critical_dirs = [
                    ("C:\\Users", "User profiles", "high"),
                    ("C:\\Program Files", "Applications", "high"),
                    ("C:\\Program Files (x86)", "32-bit applications", "high"),
                    ("C:\\ProgramData", "Application data", "high"),
                    ("C:\\Windows\\Temp", "Temporary files", "high"),
                    ("C:\\Windows\\System32", "System files", "medium")
                ]

                # Add other drives
                for drive in drives:
                    if drive != "C:\\":
                        critical_dirs.append((drive, f"Drive {drive}", "medium"))

                scan_targets = []
                processed_locations = SCAN_SESSIONS[session_id].get('processed_locations', set())
                
                for dir_path, description, priority in critical_dirs:
                    if Path(dir_path).exists() and dir_path not in processed_locations:
                        scan_targets.append((dir_path, description, priority))

                SCAN_SESSIONS[session_id]['sub_scans_total'] = len(scan_targets)
                self._add_scan_log(session_id, f"🎯 Identified {len(scan_targets)} strategic locations")
            else:
                scan_targets = []  # Will be handled during resume
                
            SCAN_SESSIONS[session_id]['status'] = 'scanning'

            # Process locations
            total_files_scanned = SCAN_SESSIONS[session_id].get('files_scanned', 0)
            total_threats = SCAN_SESSIONS[session_id].get('threats', [])
            processed_locations = SCAN_SESSIONS[session_id].get('processed_locations', set())

            for location_idx, (scan_path, description, priority) in enumerate(scan_targets):
                try:
                    # Check for cancellation/timeout
                    if session_id not in SCAN_SESSIONS:
                        self._add_scan_log(session_id, "⏹️ Scan cancelled")
                        resource_monitor_active = False
                        return {'status': 'cancelled'}

                    if datetime.now() > SCAN_SESSIONS[session_id]['scan_timeout']:
                        self._add_scan_log(session_id, f"⏰ Timeout reached ({SCAN_TIMEOUT_HOURS}h)")
                        self._save_checkpoint(session_id)
                        resource_monitor_active = False
                        return {'status': 'timeout'}

                    # Skip if already processed
                    if scan_path in processed_locations:
                        continue

                    # Update progress
                    progress = min(95, int(5 + (location_idx / max(len(scan_targets), 1)) * 90))
                    SCAN_SESSIONS[session_id].update({
                        'progress_percent': progress,
                        'current_file': f"[{location_idx+1}/{len(scan_targets)}] {priority.upper()}: {scan_path}",
                        'last_update': datetime.now()
                    })

                    self._add_scan_log(session_id, f"📂 [{location_idx+1}/{len(scan_targets)}] {priority.upper()}: {scan_path}")
                    print(f"[SCAN {session_id[:8]}] Location {location_idx+1}: {scan_path} [{priority}]")

                    # Scan location with retry
                    location_session = f"{session_id}_loc_{location_idx}"
                    scan_result = self.scan_directory(scan_path, location_session, is_scheduled=False)

                    if scan_result and location_session in SCAN_SESSIONS:
                        # Merge results
                        location_data = SCAN_SESSIONS[location_session]
                        location_files = location_data.get('files_scanned', 0)
                        location_threats = location_data.get('threats', [])
                        location_bytes = location_data.get('bytes_scanned', 0)

                        total_files_scanned += location_files
                        total_threats.extend(location_threats)

                        # Update main session
                        SCAN_SESSIONS[session_id].update({
                            'files_scanned': total_files_scanned,
                            'threats_found': len(total_threats),
                            'threats': total_threats,
                            'bytes_scanned': SCAN_SESSIONS[session_id].get('bytes_scanned', 0) + location_bytes,
                            'sub_scans_completed': location_idx + 1
                        })

                        # Mark as processed
                        processed_locations.add(scan_path)
                        SCAN_SESSIONS[session_id]['processed_locations'] = processed_locations

                        self._add_scan_log(session_id, f"   ✅ {location_files:,} files, {len(location_threats)} threats")
                        
                        # Cleanup
                        if location_session in SCAN_SESSIONS:
                            del SCAN_SESSIONS[location_session]

                    # Save checkpoint every 3 locations
                    if (location_idx + 1) % 3 == 0:
                        self._save_checkpoint(session_id)
                        self._add_scan_log(session_id, f"💾 Checkpoint saved")

                except Exception as location_error:
                    error_msg = f"Error processing {scan_path}: {str(location_error)}"
                    self._add_scan_log(session_id, f"❌ {error_msg}")
                    SCAN_SESSIONS[session_id]['errors'].append(error_msg)
                    continue

            # Finalize scan
            resource_monitor_active = False
            end_time = datetime.now()
            duration = end_time - SCAN_SESSIONS[session_id]['started_at']

            SCAN_SESSIONS[session_id].update({
                'status': 'completed',
                'completed_at': end_time,
                'progress_percent': 100,
                'scan_duration': duration.total_seconds(),
                'current_file': 'Production scan completed'
            })

            # Clean up checkpoint
            self._cleanup_checkpoint(session_id)

            # Final logging
            self._add_scan_log(session_id, "🏁 PRODUCTION SCAN COMPLETED!")
            self._add_scan_log(session_id, f"📊 Files: {total_files_scanned:,} | Threats: {len(total_threats)}")
            self._add_scan_log(session_id, f"⏱️ Duration: {duration.total_seconds():.1f}s")

            if len(total_threats) > 0:
                self._add_scan_log(session_id, f"🚨 {len(total_threats)} THREATS DETECTED!")
            else:
                self._add_scan_log(session_id, f"✅ SYSTEM CLEAN")

            print(f"[SCAN {session_id[:8]}] COMPLETED: {total_files_scanned:,} files, {len(total_threats)} threats")
            return True

        except Exception as e:
            resource_monitor_active = False
            error_msg = f'System scan error: {str(e)}'
            print(f"[SCAN {session_id[:8]}] ERROR: {error_msg}")

            # Save emergency checkpoint
            try:
                self._save_checkpoint(session_id)
            except:
                pass

            if session_id in SCAN_SESSIONS:
                SCAN_SESSIONS[session_id].update({
                    'status': 'error',
                    'error': error_msg,
                    'last_update': datetime.now()
                })

            return False