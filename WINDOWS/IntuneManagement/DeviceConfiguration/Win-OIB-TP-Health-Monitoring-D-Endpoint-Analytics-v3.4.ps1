# Script to create GPO from Intune Windows Health Monitoring Configuration JSON

#Requires -Modules GroupPolicy

param (
    [string]$JsonContentIn
)

# Helper function to clean the JSON content
function Clean-JsonContent {
    param ([string]$RawContent)
    $cleaned = $RawContent
    if ($cleaned.StartsWith("ÿþ")) {
        $cleaned = $cleaned.Substring(2)
    }
    $cleaned = $cleaned.Replace([char]0, "")
    return $cleaned
}

# Initialize
$setGPRegistryValueCommandsExecuted = 0
$interpretedSettingsFromJson = 0 # Counts relevant settings from JSON

# Clean and Parse JSON
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    exit 1
}

# Extract GPO Name and Description
$gpoName = $policyObject.displayName
$gpoDescription = $policyObject.description
if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Endpoint Analytics - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"

# Create New GPO
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify the existing one. Exiting."
        exit 1
    } else {
        $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription -ErrorAction Stop
        Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"
    }
} catch {
    Write-Error "Failed to create GPO '$gpoName'. Error: $($_.Exception.Message)"
    exit 1
}

# --- Registry Settings Mapping for Endpoint Analytics / Health Monitoring ---
$regKeyDataCollection = "SOFTWARE\Policies\Microsoft\Windows\DataCollection"

# 1. allowDeviceHealthMonitoring: "enabled"
# GPO: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow Telemetry
# Also: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow device health monitoring
# Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowDeviceHealthMonitoring (DWORD)
if ($policyObject.PSObject.Properties.Match('allowDeviceHealthMonitoring').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.allowDeviceHealthMonitoring -eq "enabled") {
        try {
            Write-Host "Applying setting: AllowDeviceHealthMonitoring = 1"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDataCollection -ValueName "AllowDeviceHealthMonitoring" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for AllowDeviceHealthMonitoring: $($_.Exception.Message)"
        }

        # Endpoint Analytics also requires "Allow commercial data pipeline"
        # GPO: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow commercial data pipeline
        # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowCommercialDataPipeline (DWORD)
        try {
            Write-Host "Applying setting: AllowCommercialDataPipeline = 1"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDataCollection -ValueName "AllowCommercialDataPipeline" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for AllowCommercialDataPipeline: $($_.Exception.Message)"
        }
        
        # Endpoint Analytics requires at least Basic telemetry.
        # GPO: Computer Configuration > Admin Templates > Windows Components > Data Collection and Preview Builds > Allow Telemetry
        # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry (DWORD) 
        # Values: 0 = Off (not recommended), 1 = Basic/Required, 2 = Enhanced (deprecated), 3 = Full/Optional
        # We set to 1 for Basic as a minimum for Endpoint Analytics.
        try {
            Write-Host "Applying setting: AllowTelemetry = 1 (Basic)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDataCollection -ValueName "AllowTelemetry" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for AllowTelemetry: $($_.Exception.Message)"
        }

    } else {
        Write-Warning "JSON setting 'allowDeviceHealthMonitoring' is 'disabled'. Endpoint Analytics GPO settings will not be applied to disable it, as the script's intent is to map enabled features. To disable, set AllowDeviceHealthMonitoring to 0."
    }
} else {
    Write-Warning "JSON field 'allowDeviceHealthMonitoring' not found. Skipping related GPO settings."
}

# 2. configDeviceHealthMonitoringScope
# This Intune setting (e.g., "bootPerformance", "windowsUpdates") does not have a direct one-to-one mapping to a single GPO registry key
# that Set-GPRegistryValue can easily configure with the same granularity.
# The settings above (AllowDeviceHealthMonitoring, AllowCommercialDataPipeline, AllowTelemetry) enable the general data flow.
# Specific data scopes are often implicitly included with these broader settings or require more complex configurations.
if ($policyObject.PSObject.Properties.Match('configDeviceHealthMonitoringScope').Count -gt 0) {
    $interpretedSettingsFromJson++ # Counted as an interpreted setting from JSON
    $scope = $policyObject.configDeviceHealthMonitoringScope
    Write-Warning "JSON setting 'configDeviceHealthMonitoringScope: $scope'. The general health monitoring and telemetry settings have been applied."
    Write-Warning "Specific GPO registry keys for granular scopes like '$scope' via Set-GPRegistryValue are limited. Ensure the 'AllowTelemetry' level (set to Basic) and 'AllowDeviceHealthMonitoring' cover necessary data points for the intended scope. For more granular control, review dedicated GPO settings for Data Collection and Preview Builds which might not be simple registry flags."
    if ($policyObject.PSObject.Properties.Match('configDeviceHealthMonitoringCustomScope').Count -gt 0 -and $policyObject.configDeviceHealthMonitoringCustomScope -ne $null) {
        Write-Warning "Additionally, 'configDeviceHealthMonitoringCustomScope' was specified: $($policyObject.configDeviceHealthMonitoringCustomScope). Custom scopes are not translated by this script."
         $interpretedSettingsFromJson++ 
    }
}

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Windows Health Monitoring Configuration (Intune)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Regarding 'settingCount':"
Write-Host "The input JSON is a specific Intune template type (WindowsHealthMonitoringConfiguration) which does not have a generic 'settings' array or a 'settingCount' field at its root."
Write-Host "Instead, the script interprets specific, known properties from this JSON template."
Write-Host ""
Write-Host "Number of distinct settings/properties interpreted from JSON for GPO translation: $interpretedSettingsFromJson"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation (if any):"
Write-Host "The count of 'interpreted settings' and 'executed commands' may differ because:"
Write-Host "  1. One Intune property (like 'allowDeviceHealthMonitoring') might translate to multiple registry values to ensure all necessary GPO prerequisites for Endpoint Analytics are met (e.g., AllowDeviceHealthMonitoring, AllowCommercialDataPipeline, AllowTelemetry)."
Write-Host "  2. Some Intune settings (like 'configDeviceHealthMonitoringScope') have limited direct GPO registry equivalents for the same level of granularity via simple Set-GPRegistryValue commands, so a warning is issued instead of direct mapping for the specific scope value."
Write-Host "This script focuses on enabling the core functionality for Endpoint Analytics data collection via available GPO registry keys."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - TP - Health Monitoring - D - Endpoint Analytics - v3.4.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
