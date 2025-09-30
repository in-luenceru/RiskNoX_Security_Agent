# Advanced Windows Update Management PowerShell Module for RiskNoX Security Agent
# This script provides comprehensive control over Windows Update system

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("BlockAutoUpdates", "BlockUserUpdates", "EnableUpdates", "GetUpdates", "InstallUpdates", "CheckCompliance", "RepairComponents")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string[]]$UpdateIDs,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Set execution policy and error handling
$ErrorActionPreference = "Stop"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Initialize logging
$LogPath = Join-Path $PSScriptRoot "logs\patch_management_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path $LogPath -Parent
if (!(Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry -ErrorAction SilentlyContinue
}

function Block-AutomaticUpdates {
    <#
    .SYNOPSIS
    Blocks automatic Windows updates system-wide
    #>
    try {
        Write-Log "Starting automatic updates blocking process"
        
        # Create registry paths
        $regPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        )
        
        foreach ($regPath in $regPaths) {
            if (!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Write-Log "Created registry path: $regPath"
            }
        }
        
        # Disable automatic updates
        Set-ItemProperty -Path $regPaths[0] -Name "NoAutoUpdate" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPaths[0] -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPaths[0] -Name "AUOptions" -Value 2 -Type DWord
        
        # Additional security measures
        Set-ItemProperty -Path $regPaths[1] -Name "DisableWindowsUpdateAccess" -Value 1 -Type DWord
        Set-ItemProperty -Path $regPaths[1] -Name "SetDisableUXWUAccess" -Value 1 -Type DWord
        
        # Stop and disable Windows Update service
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled
        
        Write-Log "Automatic updates blocked successfully" "SUCCESS"
        return @{ Success = $true; Message = "Automatic updates blocked successfully" }
        
    } catch {
        Write-Log "Failed to block automatic updates: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Block-UserUpdates {
    <#
    .SYNOPSIS
    Blocks user-initiated updates through UI and settings
    #>
    try {
        Write-Log "Starting user updates blocking process"
        
        # Block Windows Update in Settings app
        $settingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (!(Test-Path $settingsPath)) {
            New-Item -Path $settingsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $settingsPath -Name "SettingsPageVisibility" -Value "hide:windowsupdate" -Type String
        
        # Block update notifications
        $notificationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $notificationPath)) {
            New-Item -Path $notificationPath -Force | Out-Null
        }
        Set-ItemProperty -Path $notificationPath -Name "SetUpdateNotificationLevel" -Value 1 -Type DWord
        
        # Disable Windows Update Medic Service (prevents automatic re-enabling)
        try {
            Set-Service -Name "WaaSMedicSvc" -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name "WaaSMedicSvc" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Could not disable WaaSMedicSvc: $($_.Exception.Message)" "WARNING"
        }
        
        Write-Log "User updates blocked successfully" "SUCCESS"
        return @{ Success = $true; Message = "User updates blocked successfully" }
        
    } catch {
        Write-Log "Failed to block user updates: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Enable-Updates {
    <#
    .SYNOPSIS
    Re-enables Windows updates (removes all blocking)
    #>
    try {
        Write-Log "Starting updates re-enabling process"
        
        # Remove automatic update blocks
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (Test-Path $auPath) {
            Remove-ItemProperty -Path $auPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $auPath -Name "AUOptions" -ErrorAction SilentlyContinue
        }
        
        # Remove user update blocks
        $settingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (Test-Path $settingsPath) {
            Remove-ItemProperty -Path $settingsPath -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
        }
        
        $updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path $updatePath) {
            Remove-ItemProperty -Path $updatePath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $updatePath -Name "SetDisableUXWUAccess" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $updatePath -Name "SetUpdateNotificationLevel" -ErrorAction SilentlyContinue
        }
        
        # Re-enable services
        Set-Service -Name "wuauserv" -StartupType Automatic
        Set-Service -Name "WaaSMedicSvc" -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        
        Write-Log "Updates re-enabled successfully" "SUCCESS"
        return @{ Success = $true; Message = "Windows updates re-enabled successfully" }
        
    } catch {
        Write-Log "Failed to re-enable updates: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Get-AvailableUpdates {
    <#
    .SYNOPSIS
    Gets available Windows updates using Windows Update API
    #>
    try {
        Write-Log "Scanning for available Windows updates"
        
        # Import Windows Update PowerShell module if available
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate -Force
            $updates = Get-WindowsUpdate -AcceptAll -Download:$false
            
            $updateList = @()
            foreach ($update in $updates) {
                $updateInfo = @{
                    UpdateID = $update.UpdateID
                    Title = $update.Title
                    Description = $update.Description
                    Severity = $update.MsrcSeverity
                    Categories = $update.Categories -join ", "
                    SizeMB = [math]::Round($update.Size / 1MB, 2)
                    IsDownloaded = $update.IsDownloaded
                    IsMandatory = $update.IsMandatory
                    IsSecurityUpdate = $update.Categories -contains "Security Updates"
                    RebootRequired = $update.RebootRequired
                    ReleaseDate = $update.LastDeploymentChangeTime
                    SupportUrl = $update.SupportUrl
                }
                $updateList += $updateInfo
            }
            
            Write-Log "Found $($updateList.Count) available updates"
            return @{ Success = $true; Updates = $updateList; Count = $updateList.Count }
            
        } else {
            # Fallback: Use built-in Windows Update API through COM
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            
            Write-Log "Searching for updates using Windows Update API"
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            
            $updateList = @()
            foreach ($update in $searchResult.Updates) {
                $updateInfo = @{
                    UpdateID = $update.Identity.UpdateID
                    Title = $update.Title
                    Description = $update.Description
                    Severity = if($update.MsrcSeverity) { $update.MsrcSeverity } else { "Unknown" }
                    Categories = ($update.Categories | ForEach-Object { $_.Name }) -join ", "
                    SizeMB = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                    IsDownloaded = $update.IsDownloaded
                    IsMandatory = $update.IsMandatory
                    IsSecurityUpdate = $update.Categories | Where-Object { $_.Name -eq "Security Updates" }
                    RebootRequired = $update.RebootRequired
                    ReleaseDate = $update.LastDeploymentChangeTime
                    SupportUrl = ""
                }
                $updateList += $updateInfo
            }
            
            Write-Log "Found $($updateList.Count) available updates using COM API"
            return @{ Success = $true; Updates = $updateList; Count = $updateList.Count }
        }
        
    } catch {
        Write-Log "Failed to get available updates: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message; Updates = @() }
    }
}

function Install-SelectedUpdates {
    <#
    .SYNOPSIS
    Installs selected Windows updates
    #>
    param([string[]]$UpdateIDs)
    
    try {
        Write-Log "Starting installation of $($UpdateIDs.Count) selected updates"
        
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate -Force
            
            $installResults = @()
            foreach ($updateId in $UpdateIDs) {
                try {
                    Write-Log "Installing update: $updateId"
                    $result = Install-WindowsUpdate -UpdateID $updateId -AcceptAll -IgnoreReboot
                    $installResults += @{
                        UpdateID = $updateId
                        Status = "Installed"
                        RebootRequired = $result.RebootRequired
                    }
                } catch {
                    Write-Log "Failed to install update $updateId`: $($_.Exception.Message)" "ERROR"
                    $installResults += @{
                        UpdateID = $updateId
                        Status = "Failed"
                        Error = $_.Exception.Message
                    }
                }
            }
            
            $successCount = ($installResults | Where-Object { $_.Status -eq "Installed" }).Count
            $failedCount = ($installResults | Where-Object { $_.Status -eq "Failed" }).Count
            $rebootRequired = ($installResults | Where-Object { $_.RebootRequired }).Count -gt 0
            
            Write-Log "Installation completed: $successCount successful, $failedCount failed" "SUCCESS"
            return @{ 
                Success = $true
                Results = $installResults
                UpdatesInstalled = $successCount
                UpdatesFailed = $failedCount
                RebootRequired = $rebootRequired
            }
            
        } else {
            # Fallback installation using Windows Update API
            Write-Log "Installing updates using Windows Update API"
            
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            
            # Search for the specific updates
            foreach ($updateId in $UpdateIDs) {
                $searchResult = $updateSearcher.Search("UpdateID='$updateId'")
                if ($searchResult.Updates.Count -gt 0) {
                    $updatesToInstall.Add($searchResult.Updates.Item(0))
                }
            }
            
            if ($updatesToInstall.Count -gt 0) {
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updatesToInstall
                $installationResult = $installer.Install()
                
                Write-Log "Installation completed with result code: $($installationResult.ResultCode)"
                return @{
                    Success = $installationResult.ResultCode -eq 2  # 2 = Succeeded
                    UpdatesInstalled = $updatesToInstall.Count
                    RebootRequired = $installationResult.RebootRequired
                }
            } else {
                return @{ Success = $false; Error = "No matching updates found for installation" }
            }
        }
        
    } catch {
        Write-Log "Failed to install updates: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Repair-UpdateComponents {
    <#
    .SYNOPSIS
    Repairs Windows Update components
    #>
    try {
        Write-Log "Starting Windows Update components repair"
        
        # Stop services
        $services = @("wuauserv", "cryptSvc", "bits", "msiserver")
        foreach ($service in $services) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Log "Stopped service: $service"
        }
        
        # Clear Windows Update cache
        $cachePaths = @(
            "$env:SystemRoot\SoftwareDistribution",
            "$env:SystemRoot\System32\catroot2"
        )
        
        foreach ($path in $cachePaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Cleared cache: $path"
            }
        }
        
        # Run system file checker
        Write-Log "Running System File Checker"
        Start-Process -FilePath "sfc" -ArgumentList "/scannow" -Wait -NoNewWindow
        
        # Run DISM repair
        Write-Log "Running DISM repair"
        Start-Process -FilePath "DISM" -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -Wait -NoNewWindow
        
        # Re-register Windows Update DLLs
        $dlls = @(
            "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
            "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
            "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
            "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
            "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
            "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
            "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
        )
        
        foreach ($dll in $dlls) {
            try {
                Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s", $dll -Wait -NoNewWindow
            } catch {
                Write-Log "Failed to register DLL: $dll" "WARNING"
            }
        }
        
        # Restart services
        foreach ($service in $services) {
            Start-Service -Name $service -ErrorAction SilentlyContinue
            Write-Log "Started service: $service"
        }
        
        Write-Log "Windows Update components repair completed" "SUCCESS"
        return @{ Success = $true; Message = "Windows Update components repaired successfully" }
        
    } catch {
        Write-Log "Failed to repair Windows Update components: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Main execution based on action parameter
try {
    Write-Log "Starting patch management action: $Action"
    
    $result = switch ($Action) {
        "BlockAutoUpdates" { Block-AutomaticUpdates }
        "BlockUserUpdates" { Block-UserUpdates }
        "EnableUpdates" { Enable-Updates }
        "GetUpdates" { Get-AvailableUpdates }
        "InstallUpdates" { Install-SelectedUpdates -UpdateIDs $UpdateIDs }
        "RepairComponents" { Repair-UpdateComponents }
        default { 
            Write-Log "Invalid action specified: $Action" "ERROR"
            @{ Success = $false; Error = "Invalid action specified" }
        }
    }
    
    # Output result as JSON for API consumption
    $result | ConvertTo-Json -Depth 10
    
    Write-Log "Patch management action completed: $Action"
    
} catch {
    Write-Log "Critical error in patch management: $($_.Exception.Message)" "ERROR"
    @{ Success = $false; Error = $_.Exception.Message } | ConvertTo-Json
}