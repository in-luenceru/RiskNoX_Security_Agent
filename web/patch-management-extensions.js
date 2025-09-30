// Enhanced SecurityAgent methods for patch management display and control
// This file extends the SecurityAgent class with advanced patch management capabilities

// Ensure SecurityAgent exists before extending
if (typeof SecurityAgent !== 'undefined') {
    
    // Initialize selected updates set if not exists
    if (!SecurityAgent.prototype.selectedUpdates) {
        SecurityAgent.prototype.selectedUpdates = new Set();
    }
    
    // Method to display available updates with enhanced features
    SecurityAgent.prototype.displayAvailableUpdates = function(updates) {
        const listDiv = document.getElementById('availableUpdatesList');
        
        if (!updates || updates.length === 0) {
            listDiv.innerHTML = '<div class="alert alert-success"><i class="bi bi-check-circle"></i> No updates available. System is up to date.</div>';
            return;
        }
        
        if (typeof updates[0] === 'string') {
            listDiv.innerHTML = '<div class="alert alert-warning">' + updates[0] + '</div>';
            return;
        }
        
        let htmlContent = '';
        for (let i = 0; i < updates.length; i++) {
            const update = updates[i];
            const severity = update.Severity || 'Unknown';
            const severityClass = this.getSeverityClass(severity);
            const isSelected = this.selectedUpdates && this.selectedUpdates.has(update.UpdateID);
            
            htmlContent += '<div class="patch-item ' + severityClass + ' ' + (isSelected ? 'selected' : '') + ' p-3 mb-3 rounded border" data-update-id="' + update.UpdateID + '">';
            htmlContent += '<div class="d-flex align-items-start">';
            htmlContent += '<div class="form-check me-3">';
            htmlContent += '<input class="form-check-input update-checkbox" type="checkbox" id="update_' + i + '" ' + (isSelected ? 'checked' : '') + ' onchange="toggleUpdateSelection(\'' + update.UpdateID + '\')">';
            htmlContent += '</div>';
            htmlContent += '<div style="flex: 1;">';
            htmlContent += '<div class="d-flex justify-content-between align-items-start mb-2">';
            htmlContent += '<div>';
            htmlContent += '<strong class="text-dark">' + update.Title + '</strong>';
            htmlContent += '<div class="d-flex align-items-center mt-1">';
            htmlContent += this.getSeverityBadge(severity);
            if (update.Categories) {
                htmlContent += '<span class="badge bg-secondary update-category-badge ms-1">' + update.Categories + '</span>';
            }
            if (update.IsSecurityUpdate) {
                htmlContent += '<span class="badge bg-danger update-category-badge ms-1">Security</span>';
            }
            if (update.IsOptional) {
                htmlContent += '<span class="badge bg-info update-category-badge ms-1">Optional</span>';
            }
            htmlContent += '</div>';
            htmlContent += '</div>';
            htmlContent += '<div class="text-end">';
            htmlContent += '<small class="text-muted">#' + (i + 1) + '</small>';
            if (update.SizeMB) {
                htmlContent += '<div class="update-size">Size: ' + update.SizeMB + ' MB</div>';
            }
            htmlContent += '</div>';
            htmlContent += '</div>';
            htmlContent += '<p class="mb-2 text-secondary small">' + (update.Description || 'No description available') + '</p>';
            htmlContent += '<div class="row">';
            htmlContent += '<div class="col-md-6">';
            htmlContent += '<small class="text-muted">';
            htmlContent += '<strong>Update ID:</strong> ' + update.UpdateID + '<br>';
            htmlContent += '<strong>Release Date:</strong> ' + (update.ReleaseDate ? new Date(update.ReleaseDate).toLocaleDateString() : 'N/A') + '<br>';
            htmlContent += '<strong>Reboot Required:</strong> ' + (update.RebootRequired ? 'Yes' : 'No');
            htmlContent += '</small>';
            htmlContent += '</div>';
            htmlContent += '<div class="col-md-6">';
            htmlContent += '<small class="text-muted">';
            htmlContent += '<strong>Downloaded:</strong> ' + (update.IsDownloaded ? 'Yes' : 'No') + '<br>';
            htmlContent += '<strong>Mandatory:</strong> ' + (update.IsMandatory ? 'Yes' : 'No') + '<br>';
            if (update.SupportUrl) {
                htmlContent += '<a href="' + update.SupportUrl + '" target="_blank" class="text-decoration-none">Support Info</a>';
            }
            htmlContent += '</small>';
            htmlContent += '</div>';
            htmlContent += '</div>';
            htmlContent += '</div>';
            htmlContent += '</div>';
            htmlContent += '</div>';
        }
        
        listDiv.innerHTML = htmlContent;
        
        // Update counters
        this.updatePatchCounters(updates);
    };

    // Method to display installed patches history
    SecurityAgent.prototype.displayInstalledPatches = function(patches) {
        const container = document.getElementById('installed-updates-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!patches || patches.length === 0) {
            container.innerHTML = '<div class="alert alert-info">No installed updates found.</div>';
            return;
        }
        
        let tableHTML = '<div class="table-responsive">';
        tableHTML += '<table class="table table-striped table-hover">';
        tableHTML += '<thead class="table-dark">';
        tableHTML += '<tr>';
        tableHTML += '<th>Update Title</th>';
        tableHTML += '<th>Severity</th>';
        tableHTML += '<th>Install Date</th>';
        tableHTML += '<th>Description</th>';
        tableHTML += '<th>Actions</th>';
        tableHTML += '</tr>';
        tableHTML += '</thead>';
        tableHTML += '<tbody>';
        
        for (let i = 0; i < patches.length; i++) {
            const patch = patches[i];
            tableHTML += '<tr>';
            tableHTML += '<td class="fw-bold">' + patch.Title + '</td>';
            tableHTML += '<td>' + this.getSeverityBadge(patch.Severity || 'Unknown') + '</td>';
            tableHTML += '<td>' + (patch.InstallDate ? new Date(patch.InstallDate).toLocaleDateString() : 'N/A') + '</td>';
            tableHTML += '<td class="text-truncate" style="max-width: 200px;" title="' + (patch.Description || 'N/A') + '">';
            tableHTML += patch.Description ? patch.Description.substring(0, 100) + '...' : 'N/A';
            tableHTML += '</td>';
            tableHTML += '<td>';
            tableHTML += '<button class="btn btn-outline-danger btn-sm" onclick="uninstallUpdate(\'' + patch.UpdateID + '\')">';
            tableHTML += '<i class="bi bi-trash"></i> Uninstall';
            tableHTML += '</button>';
            tableHTML += '</td>';
            tableHTML += '</tr>';
        }
        
        tableHTML += '</tbody>';
        tableHTML += '</table>';
        tableHTML += '</div>';
        
        container.innerHTML = tableHTML;
    };

    // Method to update patch management control status
    SecurityAgent.prototype.updateControlStatus = function(data) {
        const autoUpdateStatus = document.getElementById('auto-update-status');
        const userUpdateStatus = document.getElementById('user-update-status');
        const lastScanTime = document.getElementById('last-scan-time');
        const systemStatus = document.getElementById('system-status');
        
        if (autoUpdateStatus) {
            autoUpdateStatus.textContent = data.AutoUpdatesBlocked ? 'Blocked' : 'Enabled';
            autoUpdateStatus.className = 'badge ' + (data.AutoUpdatesBlocked ? 'bg-danger' : 'bg-success');
        }
        
        if (userUpdateStatus) {
            userUpdateStatus.textContent = data.UserUpdatesBlocked ? 'Blocked' : 'Enabled';
            userUpdateStatus.className = 'badge ' + (data.UserUpdatesBlocked ? 'bg-danger' : 'bg-success');
        }
        
        if (lastScanTime) {
            lastScanTime.textContent = data.LastScan ? new Date(data.LastScan).toLocaleString() : 'Never';
        }
        
        if (systemStatus) {
            const isSecure = data.AutoUpdatesBlocked && data.UserUpdatesBlocked;
            systemStatus.textContent = isSecure ? 'Secured' : 'Open';
            systemStatus.className = 'badge ' + (isSecure ? 'bg-success' : 'bg-warning');
        }
        
        // Update policy indicators
        const policyIndicators = document.querySelectorAll('.policy-indicator');
        for (let i = 0; i < policyIndicators.length; i++) {
            const indicator = policyIndicators[i];
            const policyType = indicator.dataset.policy;
            if (data[policyType] !== undefined) {
                indicator.textContent = data[policyType] ? 'Active' : 'Inactive';
                indicator.className = 'badge policy-indicator ' + (data[policyType] ? 'bg-success' : 'bg-secondary');
            }
        }
    };

    // Utility method to get severity CSS class
    SecurityAgent.prototype.getSeverityClass = function(severity) {
        switch (severity && severity.toLowerCase()) {
            case 'critical': return 'border-danger bg-danger bg-opacity-10';
            case 'important': return 'border-warning bg-warning bg-opacity-10';
            case 'moderate': return 'border-info bg-info bg-opacity-10';
            case 'low': return 'border-light bg-light';
            default: return 'border-secondary bg-light';
        }
    };

    // Utility method to get severity badge
    SecurityAgent.prototype.getSeverityBadge = function(severity) {
        switch (severity && severity.toLowerCase()) {
            case 'critical': return '<span class="badge bg-danger">Critical</span>';
            case 'important': return '<span class="badge bg-warning text-dark">Important</span>';
            case 'moderate': return '<span class="badge bg-info">Moderate</span>';
            case 'low': return '<span class="badge bg-light text-dark">Low</span>';
            default: return '<span class="badge bg-secondary">Unknown</span>';
        }
    };

    // Method to update patch counters
    SecurityAgent.prototype.updatePatchCounters = function(updates) {
        const totalCount = updates.length;
        let securityUpdates = 0;
        let criticalUpdates = 0;
        let importantUpdates = 0;
        let rebootRequired = 0;
        
        for (let i = 0; i < updates.length; i++) {
            const update = updates[i];
            if (update.IsSecurityUpdate) securityUpdates++;
            if (update.Severity && update.Severity.toLowerCase() === 'critical') criticalUpdates++;
            if (update.Severity && update.Severity.toLowerCase() === 'important') importantUpdates++;
            if (update.RebootRequired) rebootRequired++;
        }
        
        // Update counter elements if they exist
        const counters = {
            'total-updates-count': totalCount,
            'security-updates-count': securityUpdates,
            'critical-updates-count': criticalUpdates,
            'important-updates-count': importantUpdates,
            'reboot-required-count': rebootRequired
        };
        
        for (const id in counters) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = counters[id];
                // Add visual indicator for important counters
                if (counters[id] > 0 && (id.includes('critical') || id.includes('security'))) {
                    const parent = element.parentElement;
                    if (parent) {
                        parent.classList.add('text-danger', 'fw-bold');
                    }
                }
            }
        }
    };

    // Method to handle real-time status updates
    SecurityAgent.prototype.refreshPatchStatus = function() {
        this.log('Refreshing patch management status...');
        
        // Show loading indicator
        const statusElements = document.querySelectorAll('.status-indicator');
        for (let i = 0; i < statusElements.length; i++) {
            statusElements[i].innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        }
        
        // Fetch current update control status
        const self = this;
        fetch('/api/patch/status')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    self.updateControlStatus(data.status);
                    self.log('Patch status refreshed successfully');
                } else {
                    self.log('Failed to refresh patch status: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(function(error) {
                self.log('Failed to refresh patch status: ' + error.message, 'error');
            });
        
        // Refresh available updates if on that tab
        const activeTab = document.querySelector('.nav-link.active');
        if (activeTab && activeTab.getAttribute('href') === '#available-updates') {
            this.scanForUpdates();
        }
    };

    // Enhanced scanning method with progress feedback
    SecurityAgent.prototype.scanForUpdates = function() {
        const scanButton = document.getElementById('scan-updates-btn');
        const progressBar = document.getElementById('scan-progress');
        const statusText = document.getElementById('scan-status');
        
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Scanning...';
        }
        
        if (progressBar) {
            progressBar.style.display = 'block';
            const progressBarInner = progressBar.querySelector('.progress-bar');
            if (progressBarInner) {
                progressBarInner.style.width = '0%';
            }
        }
        
        if (statusText) statusText.textContent = 'Initializing Windows Update scan...';
        
        this.log('Starting Windows Update scan...');
        
        const self = this;
        fetch('/api/patch/scan', { method: 'POST' })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    self.displayAvailableUpdates(data.updates || []);
                    if (statusText) statusText.textContent = 'Scan completed. Found ' + (data.updates || []).length + ' updates.';
                    self.log('Update scan completed. Found ' + (data.updates || []).length + ' updates.');
                } else {
                    self.log('Update scan failed: ' + (data.error || 'Unknown error'), 'error');
                    if (statusText) statusText.textContent = 'Scan failed: ' + (data.error || 'Unknown error');
                }
            })
            .catch(function(error) {
                self.log('Update scan request failed: ' + error.message, 'error');
                if (statusText) statusText.textContent = 'Scan request failed: ' + error.message;
            })
            .then(function() {
                // Finally block equivalent
                if (scanButton) {
                    scanButton.disabled = false;
                    scanButton.innerHTML = '<i class="bi bi-search"></i> Scan for Updates';
                }
                if (progressBar) {
                    const progressBarInner = progressBar.querySelector('.progress-bar');
                    if (progressBarInner) {
                        progressBarInner.style.width = '100%';
                    }
                    setTimeout(function() {
                        progressBar.style.display = 'none';
                    }, 2000);
                }
            });
    };

    console.log('[PatchMgmt] Enhanced SecurityAgent patch management methods loaded successfully');
    
} else {
    console.warn('[PatchMgmt] SecurityAgent class not found. Patch management extensions not loaded.');
}