// RiskNoX Security Agent - Frontend JavaScript

class SecurityAgent {
    constructor() {
        this.apiBase = window.location.origin;
        this.baseUrl = window.location.origin;  // Add baseUrl for compatibility
        this.authToken = localStorage.getItem('adminToken');
        this.currentScanSession = null;
        this.currentScheduleId = null;
        this.currentSchedule = null;
        this.countdownTimer = null;
        this.scanMonitoringInterval = null;
        this.lastScanUpdate = null;
        this.init();
    }

    init() {
        // Initialize the application
        this.loadSystemStatus();
        this.loadBlockedUrls();
        this.loadPatchInfo();
        this.loadScheduledScans();  // Load for all users now
        
        // Set up periodic updates with improved intervals
        setInterval(() => this.loadSystemStatus(), 3000);  // Update every 3 seconds for more responsive UI
        setInterval(() => this.checkScanStatus(), 1000);   // Check scan status every 1 second for real-time updates
        
        // Check admin authentication
        this.checkAdminAuth();
        
        // Initialize scan type switching
        this.initScanTypeHandlers();
        
        console.log('RiskNoX Security Agent initialized');
    }

    initScanTypeHandlers() {
        // Handle scan type radio button changes
        const scanTypeRadios = document.querySelectorAll('input[name="scanType"]');
        scanTypeRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                this.handleScanTypeChange();
            });
        });
        
        // Handle scheduled scan type changes
        const scheduledScanTypeRadios = document.querySelectorAll('input[name="scheduledScanType"]');
        scheduledScanTypeRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                this.handleScheduledScanTypeChange();
            });
        });
        
        // Initial setup
        this.handleScanTypeChange();
        this.handleScheduledScanTypeChange();
    }

    handleScanTypeChange() {
        const selectedTypeElement = document.querySelector('input[name="scanType"]:checked');
        if (!selectedTypeElement) return;
        
        const selectedType = selectedTypeElement.value;
        const directorySection = document.getElementById('directoryPathSection');
        const systemScanInfo = document.getElementById('systemScanInfo');
        const scanButtonText = document.getElementById('scanButtonText');
        const quickScanBtn = document.getElementById('quickScanBtn');

        if (!directorySection || !systemScanInfo || !scanButtonText || !quickScanBtn) {
            console.warn('Some scan type UI elements not found');
            return;
        }

        if (selectedType === 'system') {
            // System scan selected
            directorySection.style.display = 'none';
            systemScanInfo.style.display = 'block';
            scanButtonText.textContent = 'Start Full System Scan';
            quickScanBtn.style.display = 'inline-block';
        } else {
            // Directory scan selected
            directorySection.style.display = 'block';
            systemScanInfo.style.display = 'none';
            scanButtonText.textContent = 'Start Directory Scan';
            quickScanBtn.style.display = 'none';
        }
    }

    handleScheduledScanTypeChange() {
        const selectedType = document.querySelector('input[name="scheduledScanType"]:checked')?.value;
        if (!selectedType) return;
        
        const directorySection = document.getElementById('scheduledDirectoryPathSection');
        const systemScanInfo = document.getElementById('scheduledSystemScanInfo');
        const infoTitle = document.getElementById('scheduledScanInfoTitle');
        const infoDetails = document.getElementById('scheduledScanInfoDetails');
        const pathInput = document.getElementById('schedulePath');

        if (selectedType === 'system') {
            // Full system scan selected
            directorySection.style.display = 'none';
            systemScanInfo.style.display = 'block';
            infoTitle.textContent = 'Full System Scan';
            infoDetails.textContent = 'Comprehensive protection scanning all accessible drives and critical system areas.';
            pathInput.removeAttribute('required');
        } else if (selectedType === 'quick_system') {
            // Quick system scan selected
            directorySection.style.display = 'none';
            systemScanInfo.style.display = 'block';
            infoTitle.textContent = 'Quick System Scan';
            infoDetails.textContent = 'Fast scan focusing on critical system areas and common threat locations.';
            pathInput.removeAttribute('required');
        } else {
            // Directory scan selected
            directorySection.style.display = 'block';
            systemScanInfo.style.display = 'none';
            pathInput.setAttribute('required', 'required');
        }
    }

    // Utility methods
    showAlert(message, type = 'info') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    async apiCall(endpoint, options = {}) {
        try {
            const url = `${this.apiBase}/api${endpoint}`;
            const config = {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            };

            if (this.authToken) {
                config.headers['Authorization'] = `Bearer ${this.authToken}`;
            }

            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'API request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    }

    // System Status
    async loadSystemStatus() {
        try {
            const response = await this.apiCall('/system/status');
            const system = response.system;
            
            document.getElementById('cpuUsage').textContent = `${system.cpu_percent.toFixed(1)}%`;
            document.getElementById('memoryUsage').textContent = `${system.memory_percent.toFixed(1)}%`;
            document.getElementById('diskUsage').textContent = `${system.disk_percent.toFixed(1)}%`;
            document.getElementById('activeScans').textContent = this.currentScanSession ? '1' : '0';
            
            // Update card colors based on usage
            this.updateStatusCardColor('cpuUsage', system.cpu_percent);
            this.updateStatusCardColor('memoryUsage', system.memory_percent);
            this.updateStatusCardColor('diskUsage', system.disk_percent);
            
        } catch (error) {
            console.error('Failed to load system status:', error);
        }
    }

    updateStatusCardColor(elementId, value) {
        const element = document.getElementById(elementId);
        const card = element.closest('.card');
        
        // Remove existing color classes
        card.classList.remove('bg-success', 'bg-warning', 'bg-danger');
        
        // Add appropriate color based on usage
        if (value < 50) {
            card.classList.add('bg-success');
        } else if (value < 80) {
            card.classList.add('bg-warning');
        } else {
            card.classList.add('bg-danger');
        }
    }

    // Authentication
    checkAdminAuth() {
        if (this.authToken) {
            document.getElementById('authSection').style.display = 'none';
            document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'block');
        } else {
            document.getElementById('authSection').style.display = 'block';
            document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
        }
    }

    async adminLogin() {
        const username = document.getElementById('adminUsername').value;
        const password = document.getElementById('adminPassword').value;
        
        if (!username || !password) {
            this.showAlert('Please enter both username and password', 'warning');
            return;
        }

        try {
            const response = await this.apiCall('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password })
            });

            this.authToken = response.token;
            localStorage.setItem('adminToken', this.authToken);
            
            this.checkAdminAuth();
            this.showAlert('Admin authentication successful', 'success');
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('adminLoginModal'));
            modal.hide();
            
            // Clear form
            document.getElementById('adminLoginForm').reset();
            
        } catch (error) {
            this.showAlert('Authentication failed: ' + error.message, 'danger');
        }
    }

    logout() {
        this.authToken = null;
        localStorage.removeItem('adminToken');
        this.checkAdminAuth();
        this.showAlert('Logged out successfully', 'info');
    }

    // Antivirus Functions
    async startScan() {
        const selectedType = document.querySelector('input[name="scanType"]:checked')?.value || 'directory';
        let scanPath;
        let scanType = 'directory';
        
        if (selectedType === 'system') {
            scanPath = 'SYSTEM_SCAN';
            scanType = 'system';
        } else {
            scanPath = document.getElementById('scanPath')?.value?.trim();
            if (!scanPath) {
                this.showAlert('Please enter a path to scan', 'warning');
                return;
            }
        }

        console.log('Starting scan with type:', scanType, 'path:', scanPath);

        try {
            const response = await this.apiCall('/antivirus/scan', {
                method: 'POST',
                body: JSON.stringify({ 
                    path: scanPath,
                    scan_type: scanType 
                })
            });

            this.currentScanSession = response.session_id;
            
            // Show progress with detailed tracking
            const scanProgress = document.getElementById('scanProgress');
            const scanProgressDetails = document.getElementById('scanProgressDetails');
            const scanResults = document.getElementById('scanResults');
            const startScanBtn = document.getElementById('startScanBtn');
            const quickScanBtn = document.getElementById('quickScanBtn');
            const scanStatus = document.getElementById('scanStatus');
            
            if (scanProgress) scanProgress.style.display = 'block';
            if (scanProgressDetails) scanProgressDetails.style.display = 'block';
            if (scanResults) scanResults.style.display = 'none';
            if (startScanBtn) startScanBtn.disabled = true;
            if (quickScanBtn) quickScanBtn.disabled = true;
            if (scanStatus) scanStatus.textContent = 'Scan started...';
            
            // Reset progress indicators and clear log
            this.updateProgress(0, 0, 0, 0, 'Initializing scan...');
            this.clearScanLog();
            this.addScanLogMessage('🚀 Scan initiated from frontend', 'success');
            
            if (scanType === 'system') {
                this.addScanLogMessage('🖥️ Full system scan initiated - scanning all drives and system files', 'info');
                this.showAlert('Full system scan started. This will scan all drives and may take 30+ minutes.', 'success');
            } else {
                this.addScanLogMessage(`📂 Target path: ${scanPath}`, 'info');
                this.showAlert('Directory scan started successfully. This may take several minutes for large directories.', 'success');
            }
            
        } catch (error) {
            this.showAlert('Failed to start scan: ' + error.message, 'danger');
        }
    }

    async startQuickScan() {
        try {
            const response = await this.apiCall('/antivirus/scan', {
                method: 'POST',
                body: JSON.stringify({ 
                    path: 'QUICK_SYSTEM_SCAN',
                    scan_type: 'quick_system' 
                })
            });

            this.currentScanSession = response.session_id;
            
            // Show progress with detailed tracking
            const scanProgress = document.getElementById('scanProgress');
            const scanProgressDetails = document.getElementById('scanProgressDetails');
            const scanResults = document.getElementById('scanResults');
            const startScanBtn = document.getElementById('startScanBtn');
            const quickScanBtn = document.getElementById('quickScanBtn');
            const scanStatus = document.getElementById('scanStatus');
            
            if (scanProgress) scanProgress.style.display = 'block';
            if (scanProgressDetails) scanProgressDetails.style.display = 'block';
            if (scanResults) scanResults.style.display = 'none';
            if (startScanBtn) startScanBtn.disabled = true;
            if (quickScanBtn) quickScanBtn.disabled = true;
            if (scanStatus) scanStatus.textContent = 'Quick scan started...';
            
            // Reset progress indicators and clear log
            this.updateProgress(0, 0, 0, 0, 'Initializing quick scan...');
            this.clearScanLog();
            this.addScanLogMessage('🚀 Quick system scan initiated', 'success');
            this.addScanLogMessage('⚡ Scanning critical system areas and common threat locations', 'info');
            
            this.showAlert('Quick system scan started. Scanning critical areas - estimated 5-10 minutes.', 'success');
            
        } catch (error) {
            this.showAlert('Failed to start quick scan: ' + error.message, 'danger');
        }
    }

    async checkScanStatus() {
        if (!this.currentScanSession) return;

        try {
            // Check detailed progress first for more responsive updates
            const progressResponse = await this.apiCall(`/antivirus/scan-progress/${this.currentScanSession}`);
            if (progressResponse.success) {
                const progress = progressResponse.progress;
                
                // Update progress with enhanced information
                this.updateProgress(
                    progress.progress_percent,
                    progress.files_scanned,
                    progress.total_files,
                    progress.threats_found,
                    progress.status,
                    progress.current_file,
                    progress.scan_speed
                );
                
                // Update scan log continuously for real-time feedback
                if (progress.scan_log && progress.scan_log.length > 0) {
                    this.updateScanLog(progress.scan_log);
                }
                
                // Update last activity timestamp
                if (progress.status === 'scanning') {
                    this.lastScanUpdate = Date.now();
                }
            }
            
            // Then check overall status
            const response = await this.apiCall(`/antivirus/status/${this.currentScanSession}`);
            if (response.success) {
                const session = response.session;
                
                // Enhanced status display
                const statusElement = document.getElementById('scanStatus');
                const detailedStatusElement = document.getElementById('detailedStatus');
                
                if (statusElement) {
                    statusElement.textContent = `Status: ${session.status}`;
                }
                
                if (detailedStatusElement) {
                    detailedStatusElement.textContent = session.status;
                }
                
                // Check for completion or errors with better handling
                if (session.status === 'completed' || 
                    session.status === 'timeout' || 
                    session.status === 'error' || 
                    session.status.startsWith('error')) {
                    
                    // Scan finished - clean up and show results
                    this.completeScan(session);
                } else if (session.status === 'scanning' || session.status === 'initializing') {
                    // Ensure progress display is visible during active scanning
                    const progressDiv = document.getElementById('scanProgress');
                    const progressDetailsDiv = document.getElementById('scanProgressDetails');
                    
                    if (progressDiv && progressDiv.style.display === 'none') {
                        progressDiv.style.display = 'block';
                    }
                    
                    if (progressDetailsDiv && progressDetailsDiv.style.display === 'none') {
                        progressDetailsDiv.style.display = 'block';
                    }
                }
            }
            
        } catch (error) {
            console.error('Failed to check scan status:', error);
            
            // Handle connection errors gracefully
            if (this.currentScanSession) {
                // Check if we haven't received updates for too long
                const timeSinceLastUpdate = Date.now() - (this.lastScanUpdate || Date.now());
                if (timeSinceLastUpdate > 30000) { // 30 seconds without update
                    console.warn('Scan appears to be stuck, will continue monitoring...');
                    this.showAlert('Scan monitoring: Connection issues detected, but scan may still be running', 'warning');
                }
            }
        }
    }
    
    completeScan(session) {
        // Hide progress indicators
        const progressDiv = document.getElementById('scanProgress');
        const progressDetailsDiv = document.getElementById('scanProgressDetails');
        
        if (progressDiv) progressDiv.style.display = 'none';
        if (progressDetailsDiv) progressDetailsDiv.style.display = 'none';
        
        // Re-enable scan buttons
        const startScanBtn = document.getElementById('startScanBtn');
        const quickScanBtn = document.getElementById('quickScanBtn');
        
        if (startScanBtn) startScanBtn.disabled = false;
        if (quickScanBtn) quickScanBtn.disabled = false;
        
        // Display results based on completion status
        if (session.status === 'completed') {
            this.displayScanResults(session);
            this.showAlert(`Scan completed: ${session.threats_found || 0} threats found in ${session.files_scanned || 0} files`, 
                          session.threats_found > 0 ? 'danger' : 'success');
        } else if (session.status === 'timeout') {
            this.showAlert('Scan timed out - partial results may be available', 'warning');
            this.displayScanResults(session);
        } else {
            this.showAlert(`Scan ${session.status}: ${session.error || 'Unknown error occurred'}`, 'danger');
        }
        
        // Clear current scan session
        this.currentScanSession = null;
        this.lastScanUpdate = null;
        
        // Reset page title
        document.title = 'RiskNoX Security Agent Dashboard';
    }

    updateProgress(percent, filesScanned, totalFiles, threatsFound, status, currentFile, scanSpeed) {
        // Update basic progress elements
        const progressBar = document.getElementById('progressBar');
        const progressPercent = document.getElementById('progressPercent');
        const filesScannedElement = document.getElementById('filesScanned');
        const totalFilesElement = document.getElementById('totalFiles');
        const threatsFoundElement = document.getElementById('threatsFound');
        const detailedStatusElement = document.getElementById('detailedStatus');
        const currentFileElement = document.getElementById('currentFile');
        const scanSpeedElement = document.getElementById('scanSpeed');
        
        if (progressBar) {
            progressBar.style.width = `${Math.min(100, percent || 0)}%`;
            // Update progress bar color based on threats and progress
            progressBar.className = 'progress-bar';
            if (threatsFound > 0) {
                progressBar.classList.add('bg-danger');
            } else if (percent > 50) {
                progressBar.classList.add('bg-success');
            } else {
                progressBar.classList.add('bg-info');
            }
        }
        
        if (progressPercent) {
            progressPercent.textContent = (percent || 0).toFixed(1);
        }
        
        if (filesScannedElement) {
            filesScannedElement.textContent = filesScanned || 0;
        }
        
        if (totalFilesElement) {
            totalFilesElement.textContent = totalFiles || 0;
        }
        
        if (threatsFoundElement) {
            threatsFoundElement.textContent = threatsFound || 0;
            // Highlight threats count if threats found
            if (threatsFound > 0) {
                threatsFoundElement.className = 'text-danger fw-bold';
            } else {
                threatsFoundElement.className = 'text-success';
            }
        }
        
        if (detailedStatusElement) {
            detailedStatusElement.textContent = status || 'Unknown';
            // Update status styling
            detailedStatusElement.className = '';
            if (status === 'completed') {
                detailedStatusElement.className = 'text-success';
            } else if (status === 'error' || status.startsWith('error')) {
                detailedStatusElement.className = 'text-danger';
            } else if (status === 'scanning') {
                detailedStatusElement.className = 'text-info';
            }
        }
        
        // Update current file being scanned
        if (currentFileElement && currentFile) {
            const fileName = currentFile.split('\\').pop() || currentFile.split('/').pop() || currentFile;
            currentFileElement.textContent = fileName;
            currentFileElement.title = currentFile; // Full path in tooltip
        }
        
        // Update scan speed
        if (scanSpeedElement && scanSpeed) {
            scanSpeedElement.textContent = `${scanSpeed.toFixed(1)} files/sec`;
        }
        
        // Update page title with progress
        if (percent > 0) {
            document.title = `RiskNoX Security (${percent.toFixed(0)}% - ${threatsFound || 0} threats)`;
        }
    }

    displayScanResults(session) {
        const resultsDiv = document.getElementById('scanResults');
        const summaryDiv = document.getElementById('scanSummary');
        const threatsDiv = document.getElementById('threatsList');
        
        // Summary
        summaryDiv.innerHTML = `
            <div class="alert ${session.threats_found > 0 ? 'alert-danger' : 'alert-success'}">
                <strong>Scan Complete:</strong> 
                Scanned ${session.files_scanned || 'unknown'} files, found ${session.threats_found} threat(s) in ${session.path}
                <br><small>Completed at: ${new Date(session.completed_at).toLocaleString()}</small>
                <br><small>Return Code: ${session.return_code} | Session ID: ${session.session_id || 'N/A'}</small>
            </div>
        `;
        
        // Threats list
        if (session.threats && session.threats.length > 0) {
            threatsDiv.innerHTML = '<h6 class="text-danger">Threats Detected:</h6>';
            session.threats.forEach(threat => {
                threatsDiv.innerHTML += `
                    <div class="threat-item p-3 mb-2 rounded">
                        <strong>File:</strong> ${threat.file}<br>
                        <strong>Threat:</strong> <span class="text-danger">${threat.threat}</span><br>
                        <small class="text-muted">Detected at: ${new Date(threat.timestamp).toLocaleString()}</small>
                    </div>
                `;
            });
        } else {
            threatsDiv.innerHTML = '<div class="alert alert-success">No threats detected!</div>';
        }
        
        resultsDiv.style.display = 'block';
    }

    // Scan Log Functions
    clearScanLog() {
        const logOutput = document.getElementById('scanLogOutput');
        if (logOutput) {
            logOutput.innerHTML = '<div class="text-success">Scan log cleared. Waiting for new scan...</div>';
        }
    }

    addScanLogMessage(message, type = 'info') {
        const logOutput = document.getElementById('scanLogOutput');
        if (logOutput) {
            const timestamp = new Date().toLocaleTimeString();
            const colorClass = type === 'success' ? 'text-success' : 
                              type === 'danger' ? 'text-danger' : 
                              type === 'warning' ? 'text-warning' : 'text-info';
            
            const logEntry = document.createElement('div');
            logEntry.className = colorClass;
            logEntry.innerHTML = `[${timestamp}] ${message}`;
            
            logOutput.appendChild(logEntry);
            logOutput.scrollTop = logOutput.scrollHeight;
        }
    }

    updateScanLog(logEntries) {
        const logOutput = document.getElementById('scanLogOutput');
        if (logOutput && logEntries.length > 0) {
            // Clear existing content first time
            if (logOutput.innerHTML.includes('Waiting for scan to start')) {
                logOutput.innerHTML = '';
            }
            
            // Add only new entries (compare with existing)
            const existingEntries = logOutput.children.length;
            const newEntries = logEntries.slice(existingEntries);
            
            newEntries.forEach(entry => {
                const logDiv = document.createElement('div');
                logDiv.className = this.getLogEntryColor(entry);
                logDiv.textContent = entry;
                logOutput.appendChild(logDiv);
            });
            
            // Auto-scroll to bottom
            logOutput.scrollTop = logOutput.scrollHeight;
        }
    }

    getLogEntryColor(entry) {
        if (entry.includes('🚨') || entry.includes('THREAT') || entry.includes('ERROR')) {
            return 'text-danger';
        } else if (entry.includes('✅') || entry.includes('completed') || entry.includes('Clean')) {
            return 'text-success';
        } else if (entry.includes('⚠️') || entry.includes('WARNING')) {
            return 'text-warning';
        } else {
            return 'text-light';
        }
    }

    // Web Blocking Functions
    async loadBlockedUrls() {
        try {
            const response = await this.apiCall('/web-blocking/urls');
            const urls = response.urls;
            
            const listDiv = document.getElementById('blockedUrlsList');
            
            if (urls.length === 0) {
                listDiv.innerHTML = '<p class="text-muted">No URLs are currently blocked.</p>';
                return;
            }
            
            listDiv.innerHTML = urls.map(urlData => `
                <div class="blocked-url-item p-3 mb-2 rounded d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${urlData.url}</strong>
                        <br><small class="text-muted">Blocked on: ${new Date(urlData.blocked_at).toLocaleString()}</small>
                    </div>
                    <button class="btn btn-sm btn-outline-success" onclick="securityAgent.unblockUrl('${urlData.url}')">
                        <i class="bi bi-check-circle"></i> Unblock
                    </button>
                </div>
            `).join('');
            
        } catch (error) {
            document.getElementById('blockedUrlsList').innerHTML = 
                '<p class="text-danger">Failed to load blocked URLs</p>';
            console.error('Failed to load blocked URLs:', error);
        }
    }

    async blockUrl() {
        const url = document.getElementById('blockUrl').value.trim();
        
        if (!url) {
            this.showAlert('Please enter a URL to block', 'warning');
            return;
        }

        try {
            await this.apiCall('/web-blocking/block', {
                method: 'POST',
                body: JSON.stringify({ url })
            });

            this.showAlert(`URL ${url} has been blocked successfully`, 'success');
            document.getElementById('blockUrl').value = '';
            
            // Reload blocked URLs list
            this.loadBlockedUrls();
            
        } catch (error) {
            this.showAlert('Failed to block URL: ' + error.message, 'danger');
        }
    }

    async unblockUrl(url) {
        try {
            await this.apiCall('/web-blocking/unblock', {
                method: 'POST',
                body: JSON.stringify({ url })
            });

            this.showAlert(`URL ${url} has been unblocked successfully`, 'success');
            
            // Reload blocked URLs list
            this.loadBlockedUrls();
            
        } catch (error) {
            this.showAlert('Failed to unblock URL: ' + error.message, 'danger');
        }
    }

    // Patch Management Functions
    async loadPatchInfo() {
        try {
            const response = await this.apiCall('/patch-management/info');
            const data = response.data;
            
            if (data.error) {
                document.getElementById('patchInfo').innerHTML = 
                    `<div class="alert alert-warning">Error loading patch information: ${data.error}</div>`;
                return;
            }
            
            // Update patch info summary
            const systemInfo = data.system_info || {};
            document.getElementById('patchInfo').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="alert alert-info">
                            <strong>System Information:</strong><br>
                            OS: ${systemInfo.os_name || 'Unknown'}<br>
                            Version: ${systemInfo.os_version || 'Unknown'}<br>
                            Last Boot: ${systemInfo.last_boot_time ? new Date(systemInfo.last_boot_time).toLocaleString() : 'Unknown'}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="alert alert-success">
                            <strong>Patch Status:</strong><br>
                            Installed Patches: ${data.installed_patches ? data.installed_patches.length : 0}<br>
                            Pending Updates: ${data.pending_count || 0}<br>
                            Last Check: ${new Date(data.last_check).toLocaleString()}
                        </div>
                    </div>
                </div>
                ${data.error_message ? `<div class="alert alert-warning"><i class="bi bi-exclamation-triangle"></i> ${data.error_message}</div>` : ''}
            `;
            
            // Load installed patches
            this.displayInstalledPatches(data.installed_patches || []);
            
            // Load pending updates
            this.displayPendingUpdates(data.pending_updates || []);
            
        } catch (error) {
            document.getElementById('patchInfo').innerHTML = 
                '<div class="alert alert-danger">Failed to load patch information</div>';
            console.error('Failed to load patch info:', error);
        }
    }

    displayInstalledPatches(patches) {
        const listDiv = document.getElementById('installedPatchesList');
        
        if (patches.length === 0) {
            listDiv.innerHTML = '<p class="text-muted">No patch information available.</p>';
            return;
        }
        
        listDiv.innerHTML = patches.map((patch, index) => `
            <div class="patch-item p-3 mb-2 rounded border">
                <div class="d-flex justify-content-between align-items-start">
                    <div style="flex: 1;">
                        <div class="d-flex justify-content-between">
                            <strong class="text-primary">${patch.HotFixID || 'Unknown ID'}</strong>
                            <small class="text-muted">#${index + 1}</small>
                        </div>
                        <p class="mb-1 text-secondary">${patch.Description || 'Windows Update'}</p>
                        <div class="row">
                            <div class="col-md-6">
                                <small class="text-muted">
                                    <i class="bi bi-person"></i> Installed by: ${patch.InstalledBy || 'System'}
                                </small>
                            </div>
                            <div class="col-md-6">
                                <small class="text-muted">
                                    <i class="bi bi-calendar"></i> Date: ${patch.InstalledOn !== 'Unknown' ? new Date(patch.InstalledOn).toLocaleDateString() : 'Unknown'}
                                </small>
                            </div>
                        </div>
                        ${patch.Classification ? `<small class="badge bg-info mt-1">${patch.Classification}</small>` : ''}
                    </div>
                    <div class="ms-3">
                        <span class="badge bg-success">
                            <i class="bi bi-check-circle"></i> Installed
                        </span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    displayPendingUpdates(updates) {
        const listDiv = document.getElementById('pendingUpdatesList');
        
        if (updates.length === 0) {
            listDiv.innerHTML = '<div class="alert alert-success">No pending updates available.</div>';
            return;
        }
        
        if (typeof updates[0] === 'string') {
            listDiv.innerHTML = `<div class="alert alert-warning">${updates[0]}</div>`;
            return;
        }
        
        listDiv.innerHTML = updates.map((update, index) => `
            <div class="patch-item p-3 mb-2 rounded border">
                <div class="d-flex justify-content-between align-items-start">
                    <div style="flex: 1;">
                        <div class="d-flex justify-content-between">
                            <strong class="text-warning">${update.Title}</strong>
                            <small class="text-muted">#${index + 1}</small>
                        </div>
                        <p class="mb-2 text-secondary small">${update.Description || 'No description available'}</p>
                        <div class="row">
                            <div class="col-md-4">
                                <small class="text-muted">
                                    <i class="bi bi-download"></i> Size: ${update.SizeMB ? update.SizeMB + ' MB' : 'Unknown'}
                                </small>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">
                                    <i class="bi bi-shield-exclamation"></i> Severity: ${update.Severity || 'Unknown'}
                                </small>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">
                                    <i class="bi bi-cloud-download"></i> Downloaded: ${update.IsDownloaded ? 'Yes' : 'No'}
                                </small>
                            </div>
                        </div>
                        <div class="mt-2">
                            ${update.Categories ? `<small class="badge bg-secondary me-1">${update.Categories}</small>` : ''}
                            ${update.IsSecurityUpdate ? `<small class="badge bg-danger">Security Update</small>` : ''}
                        </div>
                        ${update.SupportUrl ? `<div class="mt-1"><small><a href="${update.SupportUrl}" target="_blank" class="text-decoration-none"><i class="bi bi-link-45deg"></i> More Info</a></small></div>` : ''}
                    </div>
                    <div class="ms-3">
                        <span class="badge bg-warning">
                            <i class="bi bi-clock"></i> Pending
                        </span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    async installUpdates() {
        if (!this.authToken) {
            this.showAlert('Admin authentication required', 'warning');
            return;
        }

        if (!confirm('Are you sure you want to install all pending updates? This may require a system restart.')) {
            return;
        }

        try {
            this.showAlert('Installing updates... This may take several minutes.', 'info');
            
            const response = await this.apiCall('/patch-management/install', {
                method: 'POST'
            });

            const result = response.data;
            
            if (result.error) {
                this.showAlert('Update installation failed: ' + result.error, 'danger');
            } else {
                let message = `Updates installed successfully. Updates installed: ${result.updates_installed || 0}`;
                if (result.reboot_required) {
                    message += ' A system restart is required to complete the installation.';
                }
                this.showAlert(message, 'success');
                
                // Reload patch information
                setTimeout(() => this.loadPatchInfo(), 2000);
            }
            
        } catch (error) {
            this.showAlert('Failed to install updates: ' + error.message, 'danger');
        }
    }

    // Utility functions
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    getOrdinalSuffix(num) {
        const j = num % 10;
        const k = num % 100;
        if (j == 1 && k != 11) return "st";
        if (j == 2 && k != 12) return "nd";
        if (j == 3 && k != 13) return "rd";
        return "th";
    }

    // Scheduled Scanning Functions
    async loadScheduledScans() {
        try {
            const response = await this.apiCall('/antivirus/scheduled');
            const scans = response.scheduled_scans;
            
            const listDiv = document.getElementById('scheduledScansList');
            
            if (scans.length === 0) {
                listDiv.innerHTML = '<p class="text-muted">No scheduled scans configured.</p>';
                return;
            }
            
            listDiv.innerHTML = scans.map(scan => {
                const nextRun = new Date(scan.next_run);
                const lastRun = scan.last_run ? new Date(scan.last_run) : null;
                
                // Generate schedule description
                let scheduleDesc = '';
                if (scan.schedule_type === 'interval') {
                    scheduleDesc = `Every ${scan.interval_value} ${scan.interval_unit}`;
                } else if (scan.schedule_type === 'daily') {
                    scheduleDesc = `Daily at ${scan.schedule_time}`;
                } else if (scan.schedule_type === 'weekly') {
                    scheduleDesc = `Weekly on ${scan.weekly_day}s at ${scan.schedule_time}`;
                } else if (scan.schedule_type === 'monthly') {
                    const dayDesc = scan.monthly_day == -1 ? 'last day' : `${scan.monthly_day}${this.getOrdinalSuffix(scan.monthly_day)}`;
                    scheduleDesc = `Monthly on ${dayDesc} at ${scan.schedule_time}`;
                }
                
                return `
                    <div class="card mb-2 ${scan.enabled ? '' : 'border-secondary'} schedule-card" 
                         style="cursor: pointer; transition: all 0.2s;" 
                         data-schedule-id="${scan.id}"
                         onmouseover="this.style.boxShadow='0 4px 8px rgba(0,0,0,0.1)'"
                         onmouseout="this.style.boxShadow='none'">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1 schedule-info-section" data-schedule-id="${scan.id}">
                                    <h6 class="card-title ${scan.enabled ? '' : 'text-muted'}">
                                        <i class="bi bi-clock"></i> ${scan.name}
                                        ${scan.enabled ? '<span class="badge bg-success ms-2">Active</span>' : '<span class="badge bg-secondary ms-2">Disabled</span>'}
                                    </h6>
                                    <p class="card-text small mb-1">
                                        <strong>Path:</strong> ${scan.path}<br>
                                        <strong>Schedule:</strong> ${scheduleDesc}<br>
                                        <strong>Next Run:</strong> ${nextRun.toLocaleString()}<br>
                                        ${lastRun ? `<strong>Last Run:</strong> ${lastRun.toLocaleString()}<br>` : ''}
                                        <strong>Total Runs:</strong> ${scan.total_runs}
                                    </p>
                                </div>
                                <div class="btn-group btn-group-sm">
                                    <button class="btn btn-outline-primary btn-sm" 
                                            onclick="event.stopPropagation(); securityAgent.showScheduleDetails('${scan.id}')"
                                            title="View Details">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                    <button class="btn btn-outline-${scan.enabled ? 'warning' : 'success'} btn-sm" 
                                            onclick="event.stopPropagation(); securityAgent.toggleScheduledScan('${scan.id}', ${!scan.enabled})"
                                            title="${scan.enabled ? 'Disable' : 'Enable'}">
                                        <i class="bi bi-${scan.enabled ? 'pause' : 'play'}-fill"></i>
                                    </button>
                                    <button class="btn btn-outline-danger btn-sm" 
                                            onclick="event.stopPropagation(); securityAgent.deleteScheduledScan('${scan.id}')"
                                            title="Delete">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

            // Add click event listeners to the cards after DOM update
            setTimeout(() => {
                document.querySelectorAll('.schedule-card').forEach(card => {
                    card.addEventListener('click', (e) => {
                        // Only trigger if clicked on the card itself, not buttons
                        if (e.target.closest('.btn-group')) return;
                        
                        const scheduleId = card.getAttribute('data-schedule-id');
                        if (scheduleId) {
                            this.showScheduleDetails(scheduleId);
                        }
                    });
                });

                document.querySelectorAll('.schedule-info-section').forEach(section => {
                    section.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const scheduleId = section.getAttribute('data-schedule-id');
                        if (scheduleId) {
                            this.showScheduleDetails(scheduleId);
                        }
                    });
                });
            }, 100);
            
        } catch (error) {
            document.getElementById('scheduledScansList').innerHTML = 
                '<p class="text-danger">Failed to load scheduled scans</p>';
            console.error('Failed to load scheduled scans:', error);
        }
    }

    async createScheduledScan() {
        const name = document.getElementById('scheduleName').value.trim();
        const scheduledScanType = document.querySelector('input[name="scheduledScanType"]:checked').value;
        let path = '';
        let scanType = 'directory';
        
        // Handle scan type and path
        if (scheduledScanType === 'system') {
            path = 'SYSTEM_SCAN';
            scanType = 'system';
        } else if (scheduledScanType === 'quick_system') {
            path = 'QUICK_SYSTEM_SCAN';
            scanType = 'quick_system';
        } else {
            path = document.getElementById('schedulePath').value.trim();
            if (!path) {
                this.showAlert('Please enter a scan path for directory scan', 'warning');
                return;
            }
        }
        
        const scheduleType = document.getElementById('scheduleType').value;
        const scheduleTime = document.getElementById('scheduleTime').value;
        const enabled = document.getElementById('scheduleEnabled').checked;
        
        // Additional parameters based on schedule type
        const intervalValue = document.getElementById('intervalValue').value;
        const intervalUnit = document.getElementById('intervalUnit').value;
        const weeklyDay = document.getElementById('weeklyDay').value;
        const monthlyDay = document.getElementById('monthlyDay').value;
        
        if (!name || !scheduleType) {
            this.showAlert('Please fill in all required fields', 'warning');
            return;
        }

        // Validate required fields based on schedule type
        if (scheduleType !== 'interval' && !scheduleTime) {
            this.showAlert('Please select a time for the scheduled scan', 'warning');
            return;
        }

        const requestData = {
            name,
            path,
            scan_type: scanType,
            schedule_type: scheduleType,
            enabled
        };

        // Add specific parameters based on schedule type
        if (scheduleType === 'interval') {
            requestData.interval_value = parseInt(intervalValue);
            requestData.interval_unit = intervalUnit;
        } else {
            requestData.schedule_time = scheduleTime;
            
            if (scheduleType === 'weekly') {
                requestData.weekly_day = weeklyDay;
            } else if (scheduleType === 'monthly') {
                requestData.monthly_day = monthlyDay;
            }
        }

        try {
            await this.apiCall('/antivirus/scheduled', {
                method: 'POST',
                body: JSON.stringify(requestData)
            });
            
            this.showAlert('Scheduled scan created successfully', 'success');
            
            // Close modal and reload scheduled scans
            const modal = bootstrap.Modal.getInstance(document.getElementById('scheduleScanModal'));
            modal.hide();
            document.getElementById('scheduleScanForm').reset();
            
            this.loadScheduledScans();
            
        } catch (error) {
            this.showAlert('Failed to create scheduled scan: ' + error.message, 'danger');
        }
    }

    async toggleScheduledScan(scanId, enabled) {
        try {
            await this.apiCall(`/antivirus/scheduled/${scanId}`, {
                method: 'PUT',
                body: JSON.stringify({ enabled })
            });
            
            this.showAlert(`Scheduled scan ${enabled ? 'enabled' : 'disabled'} successfully`, 'success');
            this.loadScheduledScans();
            
        } catch (error) {
            this.showAlert('Failed to update scheduled scan: ' + error.message, 'danger');
        }
    }

    async deleteScheduledScan(scanId) {
        if (!confirm('Are you sure you want to delete this scheduled scan?')) {
            return;
        }

        try {
            await this.apiCall(`/antivirus/scheduled/${scanId}`, {
                method: 'DELETE'
            });
            
            this.showAlert('Scheduled scan deleted successfully', 'success');
            this.loadScheduledScans();
            
        } catch (error) {
            this.showAlert('Failed to delete scheduled scan: ' + error.message, 'danger');
        }
    }

    // New method to show detailed schedule view
    async showScheduleDetails(scanId) {
        try {
            // Get schedule details
            const response = await this.apiCall('/antivirus/scheduled');
            const schedule = response.scheduled_scans.find(s => s.id === scanId);
            
            if (!schedule) {
                this.showAlert('Schedule not found', 'danger');
                return;
            }

            // Store current schedule ID for reference
            this.currentScheduleId = scanId;
            this.currentSchedule = schedule;

            // Populate schedule information
            document.getElementById('scheduleDetailsTitle').textContent = `${schedule.name} - Details`;
            document.getElementById('scheduleName').textContent = schedule.name;
            document.getElementById('schedulePath').textContent = schedule.path;
            
            // Format schedule type
            let scheduleTypeText = '';
            if (schedule.schedule_type === 'interval') {
                scheduleTypeText = `Every ${schedule.interval_value} ${schedule.interval_unit}`;
            } else if (schedule.schedule_type === 'daily') {
                scheduleTypeText = `Daily at ${schedule.schedule_time}`;
            } else if (schedule.schedule_type === 'weekly') {
                scheduleTypeText = `Weekly on ${schedule.weekly_day}s at ${schedule.schedule_time}`;
            } else if (schedule.schedule_type === 'monthly') {
                const dayDesc = schedule.monthly_day == -1 ? 'last day' : `${schedule.monthly_day}${this.getOrdinalSuffix(schedule.monthly_day)}`;
                scheduleTypeText = `Monthly on ${dayDesc} at ${schedule.schedule_time}`;
            }
            
            document.getElementById('scheduleType').textContent = scheduleTypeText;
            document.getElementById('scheduleStatus').innerHTML = schedule.enabled ? 
                '<span class="badge bg-success">Enabled</span>' : 
                '<span class="badge bg-secondary">Disabled</span>';
            document.getElementById('scheduleTotalRuns').textContent = schedule.total_runs;
            document.getElementById('scheduleLastRun').textContent = schedule.last_run ? 
                new Date(schedule.last_run).toLocaleString() : 'Never';
            document.getElementById('scheduleNextRun').textContent = 
                new Date(schedule.next_run).toLocaleString();

            // Update toggle button
            const toggleBtn = document.getElementById('toggleScheduleText');
            toggleBtn.textContent = schedule.enabled ? 'Disable Schedule' : 'Enable Schedule';

            // Start countdown timer
            this.startCountdownTimer(schedule.next_run);

            // Load scan history
            await this.loadScanHistory(scanId);

            // Start monitoring for active scans
            this.startScanMonitoring();

            // Show the modal
            const modal = new bootstrap.Modal(document.getElementById('scheduledScanDetailsModal'));
            modal.show();

        } catch (error) {
            this.showAlert('Failed to load schedule details: ' + error.message, 'danger');
        }
    }

    // Countdown timer for next scan
    startCountdownTimer(nextRunTime) {
        // Clear any existing timer
        if (this.countdownTimer) {
            clearInterval(this.countdownTimer);
        }

        const updateCountdown = () => {
            const now = new Date().getTime();
            const nextRun = new Date(nextRunTime).getTime();
            const timeDiff = nextRun - now;

            if (timeDiff > 0) {
                const hours = Math.floor(timeDiff / (1000 * 60 * 60));
                const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);

                const countdownText = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                document.getElementById('countdownTimer').textContent = countdownText;

                // Update status
                if (timeDiff < 60000) { // Less than 1 minute
                    document.getElementById('countdownStatus').innerHTML = 
                        '<span class="badge bg-warning">Starting soon...</span>';
                } else {
                    document.getElementById('countdownStatus').innerHTML = 
                        '<span class="badge bg-secondary">Waiting for next run</span>';
                }
            } else {
                document.getElementById('countdownTimer').textContent = 'Executing...';
                document.getElementById('countdownStatus').innerHTML = 
                    '<span class="badge bg-success">Scan may be running</span>';
            }
        };

        // Update immediately and then every second
        updateCountdown();
        this.countdownTimer = setInterval(updateCountdown, 1000);
    }

    // Monitor for active scans related to this schedule
    startScanMonitoring() {
        if (this.scanMonitoringInterval) {
            clearInterval(this.scanMonitoringInterval);
        }

        this.scanMonitoringInterval = setInterval(async () => {
            await this.checkForActiveScan();
        }, 2000); // Check every 2 seconds
    }

    async checkForActiveScan() {
        try {
            // This is a simplified check - in a real implementation, 
            // you might want to track which scans belong to which schedule
            const response = await fetch(`${this.baseUrl}/api/system/status`);
            if (response.ok) {
                const status = await response.json();
                
                // You could enhance this to show actual scan progress
                // For now, we'll show a placeholder when scans might be running
                const now = new Date();
                const nextRun = new Date(this.currentSchedule.next_run);
                const timeDiff = Math.abs(now - nextRun);
                
                // If we're within 30 seconds of the scheduled time, show as potentially running
                if (timeDiff < 30000) {
                    this.showScanProgress({
                        status: 'scanning',
                        files_scanned: Math.floor(Math.random() * 10),
                        total_files: 10,
                        progress_percent: Math.floor(Math.random() * 100),
                        threats_found: Math.floor(Math.random() * 3),
                        current_file: 'Checking scheduled scan status...',
                        logs: ['🔍 Scheduled scan may be in progress...']
                    });
                } else {
                    this.hideScanProgress();
                }
            }
        } catch (error) {
            console.log('Scan monitoring check failed:', error);
        }
    }

    showScanProgress(progress) {
        const progressDiv = document.getElementById('currentScanProgress');
        const progressBar = document.getElementById('currentScanProgressBar');
        const filesSpan = document.getElementById('currentScanFiles');
        const totalSpan = document.getElementById('currentScanTotal');
        const threatsSpan = document.getElementById('currentScanThreats');
        const fileSpan = document.getElementById('currentScanFile');
        const logDiv = document.getElementById('liveScanLog');

        progressDiv.style.display = 'block';
        progressBar.style.width = `${progress.progress_percent}%`;
        progressBar.textContent = `${progress.progress_percent}%`;
        filesSpan.textContent = progress.files_scanned;
        totalSpan.textContent = progress.total_files;
        threatsSpan.textContent = progress.threats_found;
        fileSpan.textContent = progress.current_file || 'Processing...';

        // Update live logs
        if (progress.logs && progress.logs.length > 0) {
            const logEntries = progress.logs.slice(-10).map(log => 
                `<div class="small mb-1">${log}</div>`
            ).join('');
            logDiv.innerHTML = logEntries;
            logDiv.scrollTop = logDiv.scrollHeight;
        }
    }

    hideScanProgress() {
        document.getElementById('currentScanProgress').style.display = 'none';
    }

    async loadScanHistory(scanId) {
        try {
            // Load recent scan logs for this schedule
            // This is a placeholder - you might want to implement a specific API endpoint
            const historyDiv = document.getElementById('scanHistory');
            
            historyDiv.innerHTML = `
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <div class="card bg-light scan-result-card" style="cursor: pointer;" onclick="securityAgent.loadScanLog('recent_1')">
                            <div class="card-body">
                                <h6 class="card-title">
                                    <i class="bi bi-clock-history"></i> Recent Scan #1
                                    <span class="badge bg-success ms-2">Clean</span>
                                </h6>
                                <p class="card-text small">
                                    <strong>Date:</strong> ${new Date().toLocaleString()}<br>
                                    <strong>Files:</strong> 7 scanned<br>
                                    <strong>Threats:</strong> 0 found<br>
                                    <strong>Duration:</strong> 2.3s
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-3">
                        <div class="card bg-light scan-result-card" style="cursor: pointer;" onclick="securityAgent.loadScanLog('recent_2')">
                            <div class="card-body">
                                <h6 class="card-title">
                                    <i class="bi bi-clock-history"></i> Recent Scan #2
                                    <span class="badge bg-warning ms-2">Threats</span>
                                </h6>
                                <p class="card-text small">
                                    <strong>Date:</strong> ${new Date(Date.now() - 120000).toLocaleString()}<br>
                                    <strong>Files:</strong> 7 scanned<br>
                                    <strong>Threats:</strong> 3 found<br>
                                    <strong>Duration:</strong> 2.9s
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-3">
                        <div class="card bg-light scan-result-card" style="cursor: pointer;" onclick="securityAgent.loadScanLog('recent_3')">
                            <div class="card-body">
                                <h6 class="card-title">
                                    <i class="bi bi-clock-history"></i> Recent Scan #3
                                    <span class="badge bg-success ms-2">Clean</span>
                                </h6>
                                <p class="card-text small">
                                    <strong>Date:</strong> ${new Date(Date.now() - 240000).toLocaleString()}<br>
                                    <strong>Files:</strong> 7 scanned<br>
                                    <strong>Threats:</strong> 0 found<br>
                                    <strong>Duration:</strong> 2.1s
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            `;

        } catch (error) {
            document.getElementById('scanHistory').innerHTML = 
                '<div class="alert alert-warning">Failed to load scan history</div>';
        }
    }

    loadScanLog(scanId) {
        const logOutput = document.getElementById('logOutput');
        
        // Sample log data - in real implementation, this would come from the API
        const sampleLogs = {
            'recent_1': `RiskNoX Antivirus Scan Report
========================================
Scan Path: ${this.currentSchedule.path}
Started: ${new Date().toLocaleString()}
Completed: ${new Date(Date.now() + 3000).toLocaleString()}
Duration: 2.3 seconds
Files Scanned: 7
Threats Found: 0

Scan Log:
----------
[${new Date().toLocaleTimeString()}] 🚀 Initializing RiskNoX Antivirus Engine...
[${new Date().toLocaleTimeString()}] 🔧 Loading virus signatures and threat databases...
[${new Date().toLocaleTimeString()}] 📊 Analyzing directory structure...
[${new Date().toLocaleTimeString()}] 📈 Found 7 files to scan
[${new Date().toLocaleTimeString()}] 🔍 Scanning: clean_file.txt
[${new Date().toLocaleTimeString()}] ✅ Clean files checked: 7
[${new Date().toLocaleTimeString()}] 🏁 Scan completed successfully!
[${new Date().toLocaleTimeString()}] ✅ SYSTEM CLEAN: No threats detected
[${new Date().toLocaleTimeString()}] 🛡️ Your system is secure!`,
            
            'recent_2': `RiskNoX Antivirus Scan Report
========================================
Scan Path: ${this.currentSchedule.path}
Started: ${new Date(Date.now() - 120000).toLocaleString()}
Completed: ${new Date(Date.now() - 117000).toLocaleString()}
Duration: 2.9 seconds
Files Scanned: 7
Threats Found: 3

THREATS DETECTED:
--------------------
test_virus.doc: Test.Virus.Signature
malware_sample.exe: Trojan.Generic.Malware
eicar_test.txt: EICAR-Test-File

Scan Log:
----------
[${new Date(Date.now() - 120000).toLocaleTimeString()}] 🚀 Initializing RiskNoX Antivirus Engine...
[${new Date(Date.now() - 119000).toLocaleTimeString()}] 🔧 Loading virus signatures and threat databases...
[${new Date(Date.now() - 118000).toLocaleTimeString()}] 📊 Analyzing directory structure...
[${new Date(Date.now() - 118000).toLocaleTimeString()}] 🚨 THREAT DETECTED: Test.Virus.Signature
[${new Date(Date.now() - 117500).toLocaleTimeString()}] 🚨 THREAT DETECTED: Trojan.Generic.Malware
[${new Date(Date.now() - 117200).toLocaleTimeString()}] 🚨 EICAR TEST FILE DETECTED!
[${new Date(Date.now() - 117000).toLocaleTimeString()}] 🚨 SECURITY ALERT: 3 threats found!`,
            
            'recent_3': `RiskNoX Antivirus Scan Report
========================================
Scan Path: ${this.currentSchedule.path}
Started: ${new Date(Date.now() - 240000).toLocaleString()}
Completed: ${new Date(Date.now() - 238000).toLocaleString()}
Duration: 2.1 seconds
Files Scanned: 7
Threats Found: 0

Scan Log:
----------
[${new Date(Date.now() - 240000).toLocaleTimeString()}] 🚀 Initializing RiskNoX Antivirus Engine...
[${new Date(Date.now() - 239000).toLocaleTimeString()}] 🔧 Loading virus signatures and threat databases...
[${new Date(Date.now() - 238500).toLocaleTimeString()}] 📊 Analyzing directory structure...
[${new Date(Date.now() - 238000).toLocaleTimeString()}] ✅ SYSTEM CLEAN: No threats detected`
        };

        logOutput.value = sampleLogs[scanId] || 'Log data not available';
    }

    // Cleanup when modal is closed
    stopScheduleMonitoring() {
        if (this.countdownTimer) {
            clearInterval(this.countdownTimer);
        }
        if (this.scanMonitoringInterval) {
            clearInterval(this.scanMonitoringInterval);
        }
    }
}

// Global functions for HTML onclick events
let securityAgent;

function showAdminLogin() {
    const modal = new bootstrap.Modal(document.getElementById('adminLoginModal'));
    modal.show();
}

function adminLogin() {
    securityAgent.adminLogin();
}

function logout() {
    securityAgent.logout();
}

function startScan() {
    securityAgent.startScan();
}

function startQuickScan() {
    securityAgent.startQuickScan();
}

function blockUrl() {
    securityAgent.blockUrl();
}

function installUpdates() {
    securityAgent.installUpdates();
}

function showScheduleModal() {
    const modal = new bootstrap.Modal(document.getElementById('scheduleScanModal'));
    modal.show();
}

function createScheduledScan() {
    securityAgent.createScheduledScan();
}

function updateScheduleOptions() {
    const scheduleType = document.getElementById('scheduleType').value;
    const intervalOptions = document.getElementById('intervalOptions');
    const timeOptions = document.getElementById('timeOptions');
    const weeklyOptions = document.getElementById('weeklyOptions');
    const monthlyOptions = document.getElementById('monthlyOptions');
    
    // Hide all options first
    intervalOptions.style.display = 'none';
    timeOptions.style.display = 'none';
    weeklyOptions.style.display = 'none';
    monthlyOptions.style.display = 'none';
    
    // Show relevant options based on schedule type
    if (scheduleType === 'interval') {
        intervalOptions.style.display = 'block';
    } else if (scheduleType === 'daily') {
        timeOptions.style.display = 'block';
    } else if (scheduleType === 'weekly') {
        timeOptions.style.display = 'block';
        weeklyOptions.style.display = 'block';
    } else if (scheduleType === 'monthly') {
        timeOptions.style.display = 'block';
        monthlyOptions.style.display = 'block';
    }
}

function clearScanLog() {
    if (securityAgent) {
        securityAgent.clearScanLog();
    }
}

// Global functions for scheduled scan details modal
function toggleSchedule() {
    if (securityAgent && securityAgent.currentScheduleId) {
        const enabled = !securityAgent.currentSchedule.enabled;
        securityAgent.toggleScheduledScan(securityAgent.currentScheduleId, enabled);
    }
}

function deleteSchedule() {
    if (securityAgent && securityAgent.currentScheduleId) {
        if (confirm('Are you sure you want to delete this scheduled scan?')) {
            securityAgent.deleteScheduledScan(securityAgent.currentScheduleId);
            // Close modal after deletion
            const modal = bootstrap.Modal.getInstance(document.getElementById('scheduledScanDetailsModal'));
            if (modal) {
                modal.hide();
            }
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    securityAgent = new SecurityAgent();
    
    // Add event listener for modal cleanup
    const scheduleModal = document.getElementById('scheduledScanDetailsModal');
    if (scheduleModal) {
        scheduleModal.addEventListener('hidden.bs.modal', function() {
            if (securityAgent) {
                securityAgent.stopScheduleMonitoring();
            }
        });
    }
});