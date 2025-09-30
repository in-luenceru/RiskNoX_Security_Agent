// Advanced Patch Management Functions for RiskNoX Security Agent

// Global variables for patch management
let selectedUpdates = new Set();
let autoRefreshInterval = null;
let commandLogEntries = [];

// Initialize patch management when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializePatchManagement();
});

function initializePatchManagement() {
    console.log('[PatchMgmt] Initializing advanced patch management...');
    
    // Initialize auto-refresh
    const autoRefreshCheckbox = document.getElementById('autoRefreshPatch');
    if (autoRefreshCheckbox) {
        autoRefreshCheckbox.addEventListener('change', function(e) {
            if (e.target.checked) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
        
        // Start auto-refresh by default
        if (autoRefreshCheckbox.checked) {
            startAutoRefresh();
        }
    }
    
    // Load initial control status
    loadControlStatus();
    
    console.log('[PatchMgmt] Patch management initialized successfully');
}

function startAutoRefresh() {
    stopAutoRefresh(); // Clear any existing interval
    autoRefreshInterval = setInterval(() => {
        if (typeof securityAgent !== 'undefined') {
            securityAgent.loadPatchInfo();
            loadControlStatus();
        }
    }, 30000); // Refresh every 30 seconds
    console.log('[PatchMgmt] Auto-refresh started');
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        console.log('[PatchMgmt] Auto-refresh stopped');
    }
}

// New comprehensive Windows Update control functions

async function implementComprehensiveBlocking() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin login required to implement comprehensive blocking', 'warning');
        return;
    }
    
    if (!confirm('This will implement comprehensive Windows Update blocking system-wide. This action will disable ALL Windows Update access points including automatic updates, user-initiated updates, Settings app access, and more. Continue?')) {
        return;
    }
    
    const blockBtn = document.getElementById('comprehensiveBlockBtn');
    const originalText = blockBtn ? blockBtn.textContent : '';
    
    try {
        if (blockBtn) {
            blockBtn.disabled = true;
            blockBtn.innerHTML = '<i class=\"fas fa-spinner fa-spin\"></i> Implementing...';
        }
        
        logCommand('Implementing comprehensive Windows Update blocking...');
        
        const response = await fetch('/api/patch-management/comprehensive-block', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${securityAgent.authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            securityAgent.showAlert('Comprehensive Windows Update blocking implemented successfully!', 'success');
            logCommand('✅ Comprehensive blocking completed successfully');
            
            // Show details of what was blocked
            if (result.details && result.details.length > 0) {
                logCommand('📋 Blocked components:');
                result.details.forEach(detail => logCommand(`   ${detail}`));
            }
            
            // Refresh control status
            setTimeout(() => loadControlStatus(), 2000);
            
        } else {
            securityAgent.showAlert(`Failed to implement comprehensive blocking: ${result.error}`, 'danger');
            logCommand(`❌ Comprehensive blocking failed: ${result.error}`);
        }
        
    } catch (error) {
        console.error('Comprehensive blocking error:', error);
        securityAgent.showAlert('Error implementing comprehensive blocking', 'danger');
        logCommand(`❌ Comprehensive blocking error: ${error.message}`);
    } finally {
        if (blockBtn) {
            blockBtn.disabled = false;
            blockBtn.textContent = originalText;
        }
    }
}

async function loadControlStatus() {
    try {
        const response = await fetch('/api/patch-management/control-status');
        const status = await response.json();
        
        if (status.success) {
            updateControlStatusDisplay(status);
        } else {
            console.error('Failed to load control status:', status.error);
        }
        
    } catch (error) {
        console.error('Error loading control status:', error);
    }
}

function updateControlStatusDisplay(status) {
    // Update control percentage
    const controlPercentageEl = document.getElementById('controlPercentage');
    if (controlPercentageEl) {
        const percentage = status.control_percentage || 0;
        controlPercentageEl.textContent = `${percentage}%`;
        controlPercentageEl.className = percentage === 100 ? 'text-success' : percentage > 50 ? 'text-warning' : 'text-danger';
    }
    
    // Update overall status
    const overallStatusEl = document.getElementById('overallControlStatus');
    if (overallStatusEl) {
        const isFullyControlled = status.fully_controlled || false;
        overallStatusEl.innerHTML = `
            <span class=\"${isFullyControlled ? 'text-success' : 'text-warning'}\">
                ${isFullyControlled ? '🔒 Fully Controlled' : '⚠️ Partially Controlled'}
            </span>
        `;
    }
    
    // Update individual component status
    updateComponentStatus('autoUpdatesStatus', status.auto_updates_blocked);
    updateComponentStatus('serviceStatus', status.wu_service_disabled);
    updateComponentStatus('uiAccessStatus', status.ui_access_blocked);
    updateComponentStatus('settingsAccessStatus', status.settings_access_blocked);
}

function updateComponentStatus(elementId, isControlled) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = isControlled ? 
            '<span class=\"text-success\">✅ Blocked</span>' : 
            '<span class=\"text-danger\">❌ Enabled</span>';
    }
}

async function installSpecificUpdate(updateId) {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin login required to install updates', 'warning');
        return;
    }
    
    if (!confirm(`Install update ${updateId}?`)) {
        return;
    }
    
    try {
        logCommand(`Installing specific update: ${updateId}...`);
        
        const response = await fetch('/api/patch-management/install-specific', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${securityAgent.authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                update_id: updateId
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            securityAgent.showAlert(`Update ${updateId} installed successfully!`, 'success');
            logCommand(`✅ Update ${updateId} installed successfully`);
            
            if (result.reboot_required) {
                securityAgent.showAlert('System reboot required to complete installation', 'info');
                logCommand('⚠️ System reboot required');
            }
            
            // Refresh patch info
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
            
        } else {
            securityAgent.showAlert(`Failed to install update ${updateId}: ${result.error}`, 'danger');
            logCommand(`❌ Failed to install ${updateId}: ${result.error}`);
        }
        
    } catch (error) {
        console.error('Install specific update error:', error);
        securityAgent.showAlert('Error installing update', 'danger');
        logCommand(`❌ Install error: ${error.message}`);
    }
}

async function forceUpdateCheck() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin login required to force update check', 'warning');
        return;
    }
    
    const checkBtn = document.getElementById('forceCheckBtn');
    const originalText = checkBtn ? checkBtn.textContent : '';
    
    try {
        if (checkBtn) {
            checkBtn.disabled = true;
            checkBtn.innerHTML = '<i class=\"fas fa-spinner fa-spin\"></i> Checking...';
        }
        
        logCommand('Forcing Windows Update check...');
        
        const response = await fetch('/api/patch-management/force-check', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${securityAgent.authToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            securityAgent.showAlert(`Update check completed! Found ${result.updates_found} updates.`, 'success');
            logCommand(`✅ Update check completed: ${result.updates_found} updates found`);
            
            // Refresh patch info to show new updates
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
            
        } else {
            securityAgent.showAlert(`Update check failed: ${result.error}`, 'danger');
            logCommand(`❌ Update check failed: ${result.error}`);
        }
        
    } catch (error) {
        console.error('Force update check error:', error);
        securityAgent.showAlert('Error during update check', 'danger');
        logCommand(`❌ Update check error: ${error.message}`);
    } finally {
        if (checkBtn) {
            checkBtn.disabled = false;
            checkBtn.textContent = originalText;
        }
    }
}

// Update selection functions
function toggleUpdateSelection(updateId) {
    if (selectedUpdates.has(updateId)) {
        selectedUpdates.delete(updateId);
    } else {
        selectedUpdates.add(updateId);
    }
    
    // Update visual state
    const updateItem = document.querySelector(`[data-update-id="${updateId}"]`);
    if (updateItem) {
        if (selectedUpdates.has(updateId)) {
            updateItem.classList.add('selected');
        } else {
            updateItem.classList.remove('selected');
        }
    }
    
    // Update install button state
    updateInstallButtonState();
}

function selectAllUpdates() {
    const updateCheckboxes = document.querySelectorAll('#availableUpdatesList .update-checkbox');
    updateCheckboxes.forEach(checkbox => {
        checkbox.checked = true;
        const updateId = checkbox.closest('[data-update-id]')?.getAttribute('data-update-id');
        if (updateId) {
            selectedUpdates.add(updateId);
            const updateItem = document.querySelector(`[data-update-id="${updateId}"]`);
            if (updateItem) {
                updateItem.classList.add('selected');
            }
        }
    });
    updateInstallButtonState();
}

function deselectAllUpdates() {
    const updateCheckboxes = document.querySelectorAll('#availableUpdatesList .update-checkbox');
    updateCheckboxes.forEach(checkbox => {
        checkbox.checked = false;
        const updateId = checkbox.closest('[data-update-id]')?.getAttribute('data-update-id');
        if (updateId) {
            selectedUpdates.delete(updateId);
            const updateItem = document.querySelector(`[data-update-id="${updateId}"]`);
            if (updateItem) {
                updateItem.classList.remove('selected');
            }
        }
    });
    updateInstallButtonState();
}

function updateInstallButtonState() {
    const installBtn = document.getElementById('installSelectedBtn');
    if (installBtn) {
        const count = selectedUpdates.size;
        if (count > 0) {
            installBtn.innerHTML = `<i class="bi bi-download"></i> Install Selected (${count})`;
            installBtn.disabled = false;
        } else {
            installBtn.innerHTML = `<i class="bi bi-download"></i> Install Selected`;
            installBtn.disabled = true;
        }
    }
}

// Filter functions
function filterUpdates() {
    const categoryFilter = document.getElementById('updateCategoryFilter').value;
    const severityFilter = document.getElementById('updateSeverityFilter').value;
    const searchFilter = document.getElementById('updateSearchFilter').value.toLowerCase();
    
    const updateItems = document.querySelectorAll('#availableUpdatesList .patch-item');
    
    updateItems.forEach(item => {
        const text = item.textContent.toLowerCase();
        const matchesSearch = !searchFilter || text.includes(searchFilter);
        const matchesCategory = !categoryFilter || text.includes(categoryFilter.toLowerCase());
        const matchesSeverity = !severityFilter || text.includes(severityFilter.toLowerCase());
        
        if (matchesSearch && matchesCategory && matchesSeverity) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

// Patch management API functions
async function blockAutomaticUpdates() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (!confirm('This will block automatic Windows updates system-wide. Users will not be able to install updates manually. Continue?')) {
        return;
    }

    const blockBtn = document.getElementById('blockAutoUpdatesBtn');
    const originalText = blockBtn.innerHTML;
    
    try {
        blockBtn.innerHTML = '<i class="bi bi-spinner-border spinner-border-sm"></i> Blocking...';
        blockBtn.disabled = true;
        
        logCommand('Blocking automatic Windows updates...');
        
        const response = await securityAgent.apiCall('/patch-management/block-auto-updates', {
            method: 'POST'
        });
        
        if (response.success) {
            securityAgent.showAlert('Automatic updates blocked successfully! System is now under centralized control.', 'success');
            logCommand('✓ Automatic updates blocked successfully', 'success');
            
            // Refresh status
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
        } else {
            securityAgent.showAlert('Failed to block automatic updates: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Failed to block automatic updates: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to block automatic updates: ' + error.message, 'danger');
        logCommand('✗ Error blocking automatic updates: ' + error.message, 'error');
    } finally {
        blockBtn.innerHTML = originalText;
        blockBtn.disabled = false;
    }
}

async function blockUserUpdates() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (!confirm('This will prevent users from manually checking for or installing updates through Windows Update. Continue?')) {
        return;
    }

    try {
        logCommand('Blocking user-initiated updates...');
        
        const response = await securityAgent.apiCall('/patch-management/block-user-updates', {
            method: 'POST'
        });
        
        if (response.success) {
            securityAgent.showAlert('User updates blocked successfully!', 'success');
            logCommand('✓ User updates blocked successfully', 'success');
            
            // Refresh status
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
        } else {
            securityAgent.showAlert('Failed to block user updates: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Failed to block user updates: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to block user updates: ' + error.message, 'danger');
        logCommand('✗ Error blocking user updates: ' + error.message, 'error');
    }
}

async function enableUpdates() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (!confirm('This will re-enable automatic updates and user access to Windows Update. Continue?')) {
        return;
    }

    try {
        logCommand('Enabling Windows updates...');
        
        const response = await securityAgent.apiCall('/patch-management/enable-updates', {
            method: 'POST'
        });
        
        if (response.success) {
            securityAgent.showAlert('Windows updates enabled successfully!', 'success');
            logCommand('✓ Windows updates enabled successfully', 'success');
            
            // Refresh status
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
        } else {
            securityAgent.showAlert('Failed to enable updates: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Failed to enable updates: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to enable updates: ' + error.message, 'danger');
        logCommand('✗ Error enabling updates: ' + error.message, 'error');
    }
}

async function installSelectedUpdates() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (selectedUpdates.size === 0) {
        securityAgent.showAlert('Please select at least one update to install', 'warning');
        return;
    }

    if (!confirm(`Are you sure you want to install ${selectedUpdates.size} selected update(s)? This may require a system restart.`)) {
        return;
    }

    const installBtn = document.getElementById('installSelectedBtn');
    const originalText = installBtn.innerHTML;
    
    try {
        installBtn.innerHTML = '<i class="bi bi-spinner-border spinner-border-sm"></i> Installing...';
        installBtn.disabled = true;
        
        logCommand(`Installing ${selectedUpdates.size} selected updates...`);
        
        const response = await securityAgent.apiCall('/patch-management/install', {
            method: 'POST',
            body: JSON.stringify({
                update_ids: Array.from(selectedUpdates)
            }),
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.success) {
            let message = `Installation completed successfully!`;
            if (response.updates_installed) {
                message += ` Updates installed: ${response.updates_installed}`;
            }
            if (response.updates_failed && response.updates_failed > 0) {
                message += ` Failed: ${response.updates_failed}`;
            }
            if (response.reboot_required) {
                message += ' ⚠️ System restart is required to complete the installation.';
            }
            
            securityAgent.showAlert(message, response.reboot_required ? 'warning' : 'success');
            logCommand('✓ Selected updates installed successfully', 'success');
            
            // Clear selections and refresh
            selectedUpdates.clear();
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
        } else {
            securityAgent.showAlert('Update installation failed: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Update installation failed: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to install updates: ' + error.message, 'danger');
        logCommand('✗ Error installing updates: ' + error.message, 'error');
    } finally {
        installBtn.innerHTML = originalText;
        installBtn.disabled = false;
    }
}

async function installSingleUpdate(updateId) {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (!confirm('Are you sure you want to install this update? This may require a system restart.')) {
        return;
    }

    try {
        logCommand(`Installing update ${updateId}...`);
        
        const response = await securityAgent.apiCall('/patch-management/install', {
            method: 'POST',
            body: JSON.stringify({
                update_ids: [updateId]
            }),
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.success) {
            securityAgent.showAlert('Update installed successfully!', 'success');
            logCommand('✓ Update installed successfully', 'success');
            
            // Refresh data
            setTimeout(() => securityAgent.loadPatchInfo(), 2000);
        } else {
            securityAgent.showAlert('Update installation failed: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Update installation failed: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to install update: ' + error.message, 'danger');
        logCommand('✗ Error installing update: ' + error.message, 'error');
    }
}

async function refreshAvailableUpdates() {
    logCommand('Refreshing available updates...');
    if (typeof securityAgent !== 'undefined') {
        await securityAgent.loadPatchInfo();
        logCommand('✓ Available updates refreshed', 'success');
    }
}

async function refreshPendingUpdates() {
    logCommand('Refreshing pending updates...');
    if (typeof securityAgent !== 'undefined') {
        await securityAgent.loadPatchInfo();
        logCommand('✓ Pending updates refreshed', 'success');
    }
}

async function refreshInstalledUpdates() {
    logCommand('Refreshing installed updates...');
    if (typeof securityAgent !== 'undefined') {
        await securityAgent.loadPatchInfo();
        logCommand('✓ Installed updates refreshed', 'success');
    }
}

async function refreshUpdateHistory() {
    logCommand('Refreshing update history...');
    if (typeof securityAgent !== 'undefined') {
        await securityAgent.loadPatchInfo();
        logCommand('✓ Update history refreshed', 'success');
    }
}

async function repairUpdateComponents() {
    if (!securityAgent.authToken) {
        securityAgent.showAlert('Admin authentication required', 'warning');
        return;
    }

    if (!confirm('This will run system file checker and repair Windows Update components. This may take several minutes. Continue?')) {
        return;
    }

    try {
        logCommand('Repairing Windows Update components...');
        
        const response = await securityAgent.apiCall('/patch-management/repair-components', {
            method: 'POST'
        });
        
        if (response.success) {
            securityAgent.showAlert('Windows Update components repaired successfully!', 'success');
            logCommand('✓ Windows Update components repaired successfully', 'success');
            
            // Refresh status
            setTimeout(() => securityAgent.loadPatchInfo(), 3000);
        } else {
            securityAgent.showAlert('Failed to repair components: ' + (response.error || 'Unknown error'), 'danger');
            logCommand('✗ Failed to repair components: ' + (response.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        securityAgent.showAlert('Failed to repair components: ' + error.message, 'danger');
        logCommand('✗ Error repairing components: ' + error.message, 'error');
    }
}

// Command logging functions
function logCommand(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const entry = {
        timestamp: timestamp,
        message: message,
        type: type
    };
    
    commandLogEntries.push(entry);
    
    // Keep only last 50 entries
    if (commandLogEntries.length > 50) {
        commandLogEntries = commandLogEntries.slice(-50);
    }
    
    updateCommandLog();
}

function updateCommandLog() {
    const logDiv = document.getElementById('commandLog');
    if (!logDiv) return;
    
    if (commandLogEntries.length === 0) {
        logDiv.innerHTML = '<p class="text-muted small">PowerShell commands and outputs will appear here...</p>';
        return;
    }
    
    logDiv.innerHTML = commandLogEntries.map(entry => 
        `<div class="command-log-entry ${entry.type}">
            <span class="text-muted">[${entry.timestamp}]</span> ${entry.message}
        </div>`
    ).join('');
    
    // Scroll to bottom
    logDiv.scrollTop = logDiv.scrollHeight;
}

function clearCommandLog() {
    commandLogEntries = [];
    updateCommandLog();
}

// Export functions
function exportUpdateReport() {
    logCommand('Exporting update report...');
    // Implementation for exporting update report
    securityAgent.showAlert('Update report export feature coming soon!', 'info');
}

function exportHistoryReport() {
    logCommand('Exporting history report...');
    // Implementation for exporting history report
    securityAgent.showAlert('History report export feature coming soon!', 'info');
}

// Main function to refresh all patch data
function refreshPatchData() {
    console.log('[PatchMgmt] Refreshing all patch data...');
    
    if (typeof securityAgent !== 'undefined') {
        // Refresh patch status
        if (typeof securityAgent.refreshPatchStatus === 'function') {
            securityAgent.refreshPatchStatus();
        }
        
        // Refresh patch information
        if (typeof securityAgent.loadPatchInfo === 'function') {
            securityAgent.loadPatchInfo();
        }
        
        // Scan for updates if available
        if (typeof securityAgent.scanForUpdates === 'function') {
            securityAgent.scanForUpdates();
        }
        
        console.log('[PatchMgmt] Patch data refresh completed');
    } else {
        console.warn('[PatchMgmt] SecurityAgent not available for data refresh');
    }
}

// Utility functions for patch management
function getSeverityClass(severity) {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'critical';
        case 'important': return 'important';
        case 'moderate': return 'moderate';
        case 'low': return 'low';
        default: return '';
    }
}

function getSeverityBadge(severity) {
    switch (severity?.toLowerCase()) {
        case 'critical':
            return '<span class="badge bg-danger">Critical</span>';
        case 'important':
            return '<span class="badge bg-warning">Important</span>';
        case 'moderate':
            return '<span class="badge bg-info">Moderate</span>';
        case 'low':
            return '<span class="badge bg-success">Low</span>';
        default:
            return '<span class="badge bg-secondary">Unknown</span>';
    }
}

console.log('[PatchMgmt] Advanced patch management functions loaded');