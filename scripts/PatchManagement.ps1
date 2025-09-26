#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Professional Patch Management Module
    
.DESCRIPTION
    Professional patch management system that integrates with Windows Update API (WUA)
    Provides enterprise-grade patch management capabilities including:
    - Checking for updates
    - Installing updates with progress tracking
    - Enforcing Windows Update policies
    - Blocking manual user updates
    - Update compliance reporting
    - Centralized dashboard integration
    
.NOTES
    Author: RiskNoX Security Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later, Administrator privileges
#>

class PatchManager {
    [string]$LogPath
    [hashtable]$PolicySettings
    [object]$UpdateSession
    [object]$UpdateSearcher
    
    PatchManager([string]$logPath) {
        $this.LogPath = $logPath
        $this.PolicySettings = @{}
        $this.InitializeWUA()
        $this.LoadPolicySettings()
    }
    
    [void] InitializeWUA() {
        try {
            $this.UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $this.UpdateSearcher = $this.UpdateSession.CreateUpdateSearcher()
            $this.WriteLog("WUA (Windows Update Agent) initialized successfully", "INFO")
        }
        catch {
            $this.WriteLog("Failed to initialize WUA: $($_.Exception.Message)", "ERROR")
            throw "Windows Update Agent initialization failed"
        }
    }
    
    [void] LoadPolicySettings() {
        $this.PolicySettings = @{
            "NoAutoUpdate" = $true
            "DisableWindowsUpdateAccess" = $true
            "NoAutoRebootWithLoggedOnUsers" = $true
            "ScheduledInstallDay" = 0  # 0 = Every day
            "ScheduledInstallTime" = 3  # 3 AM
            "RescheduleWaitTimeMinutes" = 10
            "RebootPromptTimeoutMinutes" = 5
        }
        $this.WriteLog("Patch management policies loaded", "INFO")
    }
    
    [void] WriteLog([string]$message, [string]$level) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$level] $message"
        
        # Write to console with color
        switch ($level) {
            "INFO" { Write-Host $logEntry -ForegroundColor Green }
            "WARN" { Write-Host $logEntry -ForegroundColor Yellow }
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "SUCCESS" { Write-Host $logEntry -ForegroundColor Cyan }
        }
        
        # Write to log file
        if ($this.LogPath) {
            $logDir = Split-Path $this.LogPath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $logEntry | Out-File -FilePath $this.LogPath -Append -Encoding UTF8
        }
    }
    
    # Core Update Functions
    [PSObject] CheckForUpdates() {
        $this.WriteLog("Starting update check...", "INFO")
        
        try {
            # Search for available updates
            $searchCriteria = "IsInstalled=0 and Type='Software' and IsHidden=0"
            $searchResult = $this.UpdateSearcher.Search($searchCriteria)
            
            $updates = @()
            foreach ($update in $searchResult.Updates) {
                $updateInfo = @{
                    Title = $update.Title
                    Description = $update.Description
                    KBArticleIDs = $update.KBArticleIDs -join ', '
                    SecurityBulletinIDs = $update.SecurityBulletinIDs -join ', '
                    MsrcSeverity = $update.MsrcSeverity
                    MaxDownloadSize = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                    SupportUrl = $update.SupportUrl
                    IsDownloaded = $update.IsDownloaded
                    RebootRequired = $update.RebootRequired
                    EulaAccepted = $update.EulaAccepted
                    Categories = ($update.Categories | ForEach-Object { $_.Name }) -join ', '
                    Classification = ($update.Categories | Where-Object { $_.Type -eq 0 } | Select-Object -First 1).Name
                    IsMandatory = $update.IsMandatory
                    LastDeploymentChangeTime = if ($update.LastDeploymentChangeTime) { $update.LastDeploymentChangeTime.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
                    MinDownloadSize = [math]::Round($update.MinDownloadSize / 1MB, 2)
                    UpdateID = $update.Identity.UpdateID
                    RevisionNumber = $update.Identity.RevisionNumber
                }
                $updates += $updateInfo
            }
            
            $result = @{
                Success = $true
                UpdateCount = $updates.Count
                Updates = $updates
                SearchCriteria = $searchCriteria
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
            
            $this.WriteLog("Found $($updates.Count) available updates", "SUCCESS")
            return $result
            
        }
        catch {
            $errorMsg = "Failed to check for updates: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{
                Success = $false
                Error = $errorMsg
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
    }
    
    [PSObject] InstallUpdates([array]$updateIds = @()) {
        $this.WriteLog("Starting update installation...", "INFO")
        
        try {
            # Search for updates to install
            $searchCriteria = if ($updateIds.Count -gt 0) {
                "IsInstalled=0 and Type='Software'"
            } else {
                "IsInstalled=0 and Type='Software' and IsHidden=0"
            }
            
            $searchResult = $this.UpdateSearcher.Search($searchCriteria)
            
            if ($searchResult.Updates.Count -eq 0) {
                $this.WriteLog("No updates available for installation", "INFO")
                return @{
                    Success = $true
                    Message = "No updates available"
                    UpdatesInstalled = 0
                    RebootRequired = $false
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
                }
            }
            
            # Filter updates if specific IDs provided
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            
            foreach ($update in $searchResult.Updates) {
                if ($updateIds.Count -eq 0 -or $updateIds -contains $update.Identity.UpdateID) {
                    # Accept EULA if required
                    if (-not $update.EulaAccepted) {
                        $update.AcceptEula()
                    }
                    $updatesToInstall.Add($update) | Out-Null
                }
            }
            
            if ($updatesToInstall.Count -eq 0) {
                $this.WriteLog("No matching updates found for installation", "WARN")
                return @{
                    Success = $false
                    Message = "No matching updates found"
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
                }
            }
            
            $this.WriteLog("Downloading $($updatesToInstall.Count) updates...", "INFO")
            
            # Download updates
            $downloader = $this.UpdateSession.CreateUpdateDownloader()
            $downloader.Updates = $updatesToInstall
            $downloader.Priority = 3  # High priority
            $downloadResult = $downloader.Download()
            
            $this.WriteLog("Download completed with result code: $($downloadResult.ResultCode)", "INFO")
            
            # Install updates
            $this.WriteLog("Installing updates...", "INFO")
            $installer = $this.UpdateSession.CreateUpdateInstaller()
            $installer.Updates = $updatesToInstall
            $installResult = $installer.Install()
            
            # Process installation results
            $successfulInstalls = 0
            $failedInstalls = 0
            $installDetails = @()
            
            for ($i = 0; $i -lt $installResult.GetUpdateResult.Count; $i++) {
                $updateResult = $installResult.GetUpdateResult($i)
                $update = $updatesToInstall.Item($i)
                
                $installDetail = @{
                    Title = $update.Title
                    KBArticleID = $update.KBArticleIDs -join ', '
                    ResultCode = $updateResult.ResultCode
                    Success = ($updateResult.ResultCode -eq 2)  # 2 = Succeeded
                    RebootRequired = $updateResult.RebootRequired
                }
                
                $installDetails += $installDetail
                
                if ($updateResult.ResultCode -eq 2) {
                    $successfulInstalls++
                } else {
                    $failedInstalls++
                }
            }
            
            $result = @{
                Success = ($installResult.ResultCode -eq 2)
                OverallResultCode = $installResult.ResultCode
                UpdatesInstalled = $successfulInstalls
                UpdatesFailed = $failedInstalls
                RebootRequired = $installResult.RebootRequired
                InstallDetails = $installDetails
                HResult = $installResult.HResult
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
            
            $this.WriteLog("Installation completed. Success: $successfulInstalls, Failed: $failedInstalls, Reboot Required: $($installResult.RebootRequired)", "SUCCESS")
            return $result
            
        }
        catch {
            $errorMsg = "Failed to install updates: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{
                Success = $false
                Error = $errorMsg
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
    }
    
    # Policy Enforcement Functions
    [PSObject] EnforceUpdatePolicies() {
        $this.WriteLog("Enforcing Windows Update policies...", "INFO")
        
        try {
            $results = @()
            
            # Windows Update registry path
            $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            $wuAUPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            
            # Create registry paths if they don't exist
            if (-not (Test-Path $wuPolicyPath)) {
                New-Item -Path $wuPolicyPath -Force | Out-Null
                $results += "Created Windows Update policy registry key"
            }
            
            if (-not (Test-Path $wuAUPolicyPath)) {
                New-Item -Path $wuAUPolicyPath -Force | Out-Null
                $results += "Created Windows Update AU policy registry key"
            }
            
            # Set core policies
            $policies = @(
                @{ Path = $wuAUPolicyPath; Name = "NoAutoUpdate"; Value = 1; Description = "Disable automatic updates" },
                @{ Path = $wuAUPolicyPath; Name = "AUOptions"; Value = 2; Description = "Notify before download" },
                @{ Path = $wuAUPolicyPath; Name = "ScheduledInstallDay"; Value = 0; Description = "Install updates every day" },
                @{ Path = $wuAUPolicyPath; Name = "ScheduledInstallTime"; Value = 3; Description = "Install at 3 AM" },
                @{ Path = $wuAUPolicyPath; Name = "NoAutoRebootWithLoggedOnUsers"; Value = 1; Description = "No auto reboot with logged on users" },
                @{ Path = $wuAUPolicyPath; Name = "RebootPromptTimeoutMinutes"; Value = 5; Description = "5 minute reboot prompt" },
                @{ Path = $wuPolicyPath; Name = "DisableWindowsUpdateAccess"; Value = 1; Description = "Disable Windows Update access" },
                @{ Path = $wuPolicyPath; Name = "WUServer"; Value = ""; Description = "Clear WSUS server setting" },
                @{ Path = $wuPolicyPath; Name = "WUStatusServer"; Value = ""; Description = "Clear WSUS status server setting" }
            )
            
            foreach ($policy in $policies) {
                try {
                    if ($policy.Name -in @("WUServer", "WUStatusServer")) {
                        # Remove WSUS server settings to use Windows Update
                        Remove-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                        $results += "Removed $($policy.Name) (using Windows Update directly)"
                    } else {
                        Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Type DWord -Force
                        $results += "Set $($policy.Name) = $($policy.Value) ($($policy.Description))"
                    }
                }
                catch {
                    $results += "Failed to set $($policy.Name): $($_.Exception.Message)"
                }
            }
            
            # Additional security policies
            $securityPolicies = @(
                @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"; Name = "CachedEngineVersion"; Description = "Clear cached engine version" },
                @{ Path = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"; Name = "UxOption"; Value = 1; Description = "Hide Windows Update in Settings" }
            )
            
            foreach ($policy in $securityPolicies) {
                try {
                    if ($policy.ContainsKey("Value")) {
                        if (-not (Test-Path $policy.Path)) {
                            New-Item -Path $policy.Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -Force
                        $results += "Set $($policy.Name) = $($policy.Value) ($($policy.Description))"
                    } else {
                        Remove-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                        $results += "Removed $($policy.Name) ($($policy.Description))"
                    }
                }
                catch {
                    $results += "Failed to configure $($policy.Name): $($_.Exception.Message)"
                }
            }
            
            # Restart Windows Update service to apply policies
            try {
                Restart-Service -Name "wuauserv" -Force -ErrorAction Stop
                $results += "Restarted Windows Update service to apply policies"
            }
            catch {
                $results += "Warning: Could not restart Windows Update service: $($_.Exception.Message)"
            }
            
            $this.WriteLog("Policy enforcement completed successfully", "SUCCESS")
            
            return @{
                Success = $true
                Results = $results
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
        catch {
            $errorMsg = "Failed to enforce policies: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{
                Success = $false
                Error = $errorMsg
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
    }
    
    [PSObject] CheckPolicyCompliance() {
        $this.WriteLog("Checking Windows Update policy compliance...", "INFO")
        
        try {
            $compliance = @()
            
            $expectedPolicies = @(
                @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; ExpectedValue = 1 },
                @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "AUOptions"; ExpectedValue = 2 },
                @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; ExpectedValue = 1 }
            )
            
            foreach ($policy in $expectedPolicies) {
                try {
                    $actualValue = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                    $isCompliant = $actualValue -and ($actualValue.$($policy.Name) -eq $policy.ExpectedValue)
                    
                    $compliance += @{
                        PolicyName = $policy.Name
                        Path = $policy.Path
                        ExpectedValue = $policy.ExpectedValue
                        ActualValue = if ($actualValue) { $actualValue.$($policy.Name) } else { "Not Set" }
                        IsCompliant = $isCompliant
                    }
                }
                catch {
                    $compliance += @{
                        PolicyName = $policy.Name
                        Path = $policy.Path
                        ExpectedValue = $policy.ExpectedValue
                        ActualValue = "Error: $($_.Exception.Message)"
                        IsCompliant = $false
                    }
                }
            }
            
            $compliantCount = ($compliance | Where-Object { $_.IsCompliant }).Count
            $totalCount = $compliance.Count
            
            return @{
                Success = $true
                OverallCompliance = ($compliantCount -eq $totalCount)
                CompliancePercentage = [math]::Round(($compliantCount / $totalCount) * 100, 2)
                ComplianceDetails = $compliance
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
        catch {
            $errorMsg = "Failed to check policy compliance: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{
                Success = $false
                Error = $errorMsg
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
    }
    
    # System Information and Reporting
    [PSObject] GetSystemUpdateStatus() {
        $this.WriteLog("Getting comprehensive system update status...", "INFO")
        
        try {
            # Get OS information
            $osInfo = Get-CimInstance Win32_OperatingSystem
            $computerInfo = Get-ComputerInfo
            
            # Get installed updates (last 30 days)
            $installedUpdates = Get-HotFix | Where-Object { 
                $_.InstalledOn -and $_.InstalledOn -gt (Get-Date).AddDays(-30) 
            } | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending
            
            # Check Windows Update service status
            $wuService = Get-Service -Name "wuauserv"
            
            # Get pending reboot status
            $rebootRequired = $this.CheckRebootRequired()
            
            # Get last update check time
            $lastUpdateCheck = $this.GetLastUpdateCheckTime()
            
            # Check for pending updates
            $pendingUpdates = $this.CheckForUpdates()
            
            # Get update history
            $updateHistory = $this.GetUpdateHistory()
            
            return @{
                Success = $true
                SystemInfo = @{
                    OSName = $osInfo.Caption
                    OSVersion = $osInfo.Version
                    OSBuild = $osInfo.BuildNumber
                    LastBootTime = $osInfo.LastBootUpTime.ToString('yyyy-MM-ddTHH:mm:ss')
                    TotalMemoryGB = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
                    FreeMemoryGB = [math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)
                    ComputerName = $env:COMPUTERNAME
                    WindowsUpdateServiceStatus = $wuService.Status
                }
                UpdateStatus = @{
                    RebootRequired = $rebootRequired
                    LastUpdateCheck = $lastUpdateCheck
                    PendingUpdatesCount = if ($pendingUpdates.Success) { $pendingUpdates.UpdateCount } else { -1 }
                    RecentUpdatesCount = $installedUpdates.Count
                    UpdateServiceRunning = ($wuService.Status -eq "Running")
                }
                RecentUpdates = $installedUpdates
                PendingUpdates = if ($pendingUpdates.Success) { $pendingUpdates.Updates } else { @() }
                UpdateHistory = $updateHistory
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
        catch {
            $errorMsg = "Failed to get system update status: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{
                Success = $false
                Error = $errorMsg
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            }
        }
    }
    
    [bool] CheckRebootRequired() {
        try {
            # Check multiple indicators for pending reboot
            $rebootPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts"
            )
            
            foreach ($path in $rebootPaths) {
                if (Test-Path $path) {
                    return $true
                }
            }
            
            # Check for pending file rename operations
            $pendingFileRenames = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            if ($pendingFileRenames) {
                return $true
            }
            
            return $false
        }
        catch {
            $this.WriteLog("Could not determine reboot status: $($_.Exception.Message)", "WARN")
            return $false
        }
    }
    
    [string] GetLastUpdateCheckTime() {
        try {
            $auClient = New-Object -ComObject Microsoft.Update.AutoUpdate
            if ($auClient.Results.LastSearchSuccessDate) {
                return $auClient.Results.LastSearchSuccessDate.ToString('yyyy-MM-ddTHH:mm:ss')
            }
            return "Unknown"
        }
        catch {
            return "Unknown"
        }
    }
    
    [array] GetUpdateHistory() {
        try {
            $updateHistory = @()
            $historySearcher = $this.UpdateSession.CreateUpdateHistorySearcher()
            $historyCount = $historySearcher.GetTotalHistoryCount()
            
            if ($historyCount -gt 0) {
                $count = [math]::Min($historyCount, 50)  # Get last 50 updates
                $history = $historySearcher.QueryHistory(0, $count)
                
                foreach ($entry in $history) {
                    $updateHistory += @{
                        Title = $entry.Title
                        Date = $entry.Date.ToString('yyyy-MM-ddTHH:mm:ss')
                        Operation = switch ($entry.Operation) {
                            1 { "Installation" }
                            2 { "Uninstallation" }
                            default { "Unknown" }
                        }
                        ResultCode = switch ($entry.ResultCode) {
                            1 { "In Progress" }
                            2 { "Succeeded" }
                            3 { "Succeeded with Errors" }
                            4 { "Failed" }
                            5 { "Aborted" }
                            default { "Unknown" }
                        }
                        HResult = $entry.HResult
                        UpdateIdentity = $entry.UpdateIdentity.UpdateID
                    }
                }
            }
            
            return $updateHistory
        }
        catch {
            $this.WriteLog("Could not retrieve update history: $($_.Exception.Message)", "WARN")
            return @()
        }
    }
    
    # Utility Functions
    [PSObject] RestartWindowsUpdateService() {
        try {
            $this.WriteLog("Restarting Windows Update service...", "INFO")
            
            # Stop dependent services first
            $dependentServices = @("cryptsvc", "bits", "msiserver")
            foreach ($service in $dependentServices) {
                try {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    $this.WriteLog("Stopped service: $service", "INFO")
                }
                catch {
                    $this.WriteLog("Could not stop service $service : $($_.Exception.Message)", "WARN")
                }
            }
            
            # Stop Windows Update service
            Stop-Service -Name "wuauserv" -Force
            Start-Sleep -Seconds 2
            
            # Start Windows Update service
            Start-Service -Name "wuauserv"
            
            # Start dependent services
            foreach ($service in $dependentServices) {
                try {
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                    $this.WriteLog("Started service: $service", "INFO")
                }
                catch {
                    $this.WriteLog("Could not start service $service : $($_.Exception.Message)", "WARN")
                }
            }
            
            $this.WriteLog("Windows Update service restarted successfully", "SUCCESS")
            return @{ Success = $true; Message = "Windows Update service restarted successfully" }
        }
        catch {
            $errorMsg = "Failed to restart Windows Update service: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{ Success = $false; Error = $errorMsg }
        }
    }
    
    [PSObject] ClearWindowsUpdateCache() {
        try {
            $this.WriteLog("Clearing Windows Update cache...", "INFO")
            
            # Stop Windows Update service
            Stop-Service -Name "wuauserv" -Force
            
            # Clear cache directories
            $cacheDirectories = @(
                "C:\Windows\SoftwareDistribution\Download",
                "C:\Windows\System32\catroot2"
            )
            
            foreach ($dir in $cacheDirectories) {
                if (Test-Path $dir) {
                    Remove-Item -Path "$dir\*" -Recurse -Force -ErrorAction SilentlyContinue
                    $this.WriteLog("Cleared cache directory: $dir", "INFO")
                }
            }
            
            # Reset Windows Update components
            $commands = @(
                "regsvr32.exe /s atl.dll",
                "regsvr32.exe /s urlmon.dll",
                "regsvr32.exe /s mshtml.dll",
                "regsvr32.exe /s shdocvw.dll",
                "regsvr32.exe /s browseui.dll",
                "regsvr32.exe /s jscript.dll",
                "regsvr32.exe /s vbscript.dll",
                "regsvr32.exe /s scrrun.dll",
                "regsvr32.exe /s msxml.dll",
                "regsvr32.exe /s msxml3.dll",
                "regsvr32.exe /s msxml6.dll",
                "regsvr32.exe /s actxprxy.dll",
                "regsvr32.exe /s softpub.dll",
                "regsvr32.exe /s wintrust.dll",
                "regsvr32.exe /s dssenh.dll",
                "regsvr32.exe /s rsaenh.dll",
                "regsvr32.exe /s gpkcsp.dll",
                "regsvr32.exe /s sccbase.dll",
                "regsvr32.exe /s slbcsp.dll",
                "regsvr32.exe /s cryptdlg.dll",
                "regsvr32.exe /s oleaut32.dll",
                "regsvr32.exe /s ole32.dll",
                "regsvr32.exe /s shell32.dll",
                "regsvr32.exe /s initpki.dll",
                "regsvr32.exe /s wuapi.dll",
                "regsvr32.exe /s wuaueng.dll",
                "regsvr32.exe /s wuaueng1.dll",
                "regsvr32.exe /s wucltui.dll",
                "regsvr32.exe /s wups.dll",
                "regsvr32.exe /s wups2.dll",
                "regsvr32.exe /s wuweb.dll",
                "regsvr32.exe /s qmgr.dll",
                "regsvr32.exe /s qmgrprxy.dll",
                "regsvr32.exe /s wucltux.dll",
                "regsvr32.exe /s muweb.dll",
                "regsvr32.exe /s wuwebv.dll"
            )
            
            foreach ($cmd in $commands) {
                try {
                    Invoke-Expression $cmd | Out-Null
                }
                catch {
                    # Ignore individual registration failures
                }
            }
            
            # Start Windows Update service
            Start-Service -Name "wuauserv"
            
            $this.WriteLog("Windows Update cache cleared and components reset", "SUCCESS")
            return @{ Success = $true; Message = "Windows Update cache cleared successfully" }
        }
        catch {
            $errorMsg = "Failed to clear Windows Update cache: $($_.Exception.Message)"
            $this.WriteLog($errorMsg, "ERROR")
            return @{ Success = $false; Error = $errorMsg }
        }
    }
}

# Export functions for use by the backend
function Initialize-PatchManager {
    param([string]$LogPath = "C:\temp\patch_management.log")
    return [PatchManager]::new($LogPath)
}

function Get-AvailableUpdates {
    param([PatchManager]$PatchManager)
    return $PatchManager.CheckForUpdates()
}

function Install-Updates {
    param(
        [PatchManager]$PatchManager,
        [array]$UpdateIds = @()
    )
    return $PatchManager.InstallUpdates($UpdateIds)
}

function Set-UpdatePolicies {
    param([PatchManager]$PatchManager)
    return $PatchManager.EnforceUpdatePolicies()
}

function Test-UpdateCompliance {
    param([PatchManager]$PatchManager)
    return $PatchManager.CheckPolicyCompliance()
}

function Get-SystemUpdateStatus {
    param([PatchManager]$PatchManager)
    return $PatchManager.GetSystemUpdateStatus()
}

function Reset-WindowsUpdateService {
    param([PatchManager]$PatchManager)
    return $PatchManager.RestartWindowsUpdateService()
}

function Clear-WindowsUpdateCache {
    param([PatchManager]$PatchManager)
    return $PatchManager.ClearWindowsUpdateCache()
}