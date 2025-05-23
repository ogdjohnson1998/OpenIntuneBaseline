# Script to create GPO from Intune Compliance Policy JSON

#Requires -Modules GroupPolicy

param (
    [string]$JsonContentIn
)

# Helper function to clean the JSON content
function Clean-JsonContent {
    param ([string]$RawContent)
    # Remove BOM (ÿþ) if present at the beginning
    $cleaned = $RawContent
    if ($cleaned.StartsWith("ÿþ")) {
        $cleaned = $cleaned.Substring(2)
    }
    # Remove null characters that are interspersed in UTF-16 strings
    $cleaned = $cleaned.Replace([char]0, "")
    return $cleaned
}

# Initialize
$setGPRegistryValueCommandsExecuted = 0
$interpretedSettingsFromJson = 0 # This will count how many settings from the JSON we attempt to translate

# Clean and Parse JSON
Write-Host "Raw JSON input length: $($JsonContentIn.Length)"
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
Write-Host "Cleaned JSON content (first 200 chars): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 200)))"

try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    # It might be useful to see more of the JSON if parsing fails
    # For security reasons, avoid printing the full JSON if it's very large or contains sensitive data not expected here.
    exit 1
}

# Extract GPO Name and Description
$gpoName = $policyObject.displayName
$gpoDescription = $policyObject.description # This is null in the provided JSON
if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune compliance policy '$gpoName' (Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"

# Create New GPO
try {
    Import-Module GroupPolicy -ErrorAction Stop
    # Check if GPO already exists
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify existing."
        # Or, optionally, remove it and recreate, or just modify. For now, we stop.
        # Remove-GPO -Name $gpoName -Force
        # $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription -ErrorAction Stop
        Write-Warning "Exiting to prevent changes to existing GPO."
        exit 1 # Or handle as appropriate
    } else {
        $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription -ErrorAction Stop
        Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"
    }
} catch {
    Write-Error "Failed to create GPO '$gpoName'. Error: $($_.Exception.Message)"
    exit 1
}

# --- Registry Settings Mapping ---
# This section translates Intune compliance policy settings to GPO registry values.
# Note: Compliance policies check for a state. GPOs enforce a state.
# The translation aims to ENFORCE the compliant state.

# 1. defenderEnabled: true
# Ensures Microsoft Defender Antivirus is enabled.
# GPO Path: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus
# Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware (DWORD)
# Value: 0 (to enable Defender, as the GPO setting is "Turn off...")
if ($policyObject.PSObject.Properties.Match('defenderEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.defenderEnabled -eq $true) {
        $regKey = "SOFTWARE\Policies\Microsoft\Windows Defender"
        $regValueName = "DisableAntiSpyware"
        $regValue = 0
        $regType = "DWord"
        try {
            Write-Host "Applying setting: Enable Defender (DisableAntiSpyware = 0)"
            Set-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValueName -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for enabling Defender: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "'defenderEnabled' is false in the JSON. This script enforces 'true' states for Defender components. No GPO setting applied for DisableAntiSpyware."
        # To enforce 'false', one would set DisableAntiSpyware to 1.
    }
} else {
    Write-Warning "JSON field 'defenderEnabled' not found. Skipping related GPO settings."
}


# 2. rtpEnabled: true
# Ensures Real-Time Protection is enabled.
# GPO Path: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Turn off real-time protection
# Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring (DWORD)
# Value: 0 (to enable Real-time Protection)
if ($policyObject.PSObject.Properties.Match('rtpEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.rtpEnabled -eq $true) {
        $regKeyRTP = "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        $regValue = 0 # Common value for enabling features (where 'Disable' is in the name)
        $regType = "DWord"

        # DisableRealtimeMonitoring = 0 (Enable RTP)
        try {
            Write-Host "Applying setting: Enable Real-Time Monitoring (DisableRealtimeMonitoring = 0)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyRTP -ValueName "DisableRealtimeMonitoring" -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for DisableRealtimeMonitoring: $($_.Exception.Message)"
        }

        # Behavior Monitoring: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring (DWORD) = 0
        # This is a sub-component of RTP. Considered part of the 'rtpEnabled' interpretation.
        try {
            Write-Host "Applying setting: Enable Behavior Monitoring (DisableBehaviorMonitoring = 0)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyRTP -ValueName "DisableBehaviorMonitoring" -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for DisableBehaviorMonitoring: $($_.Exception.Message)"
        }

        # Scan All Downloads: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection (DWORD) = 0
        try {
            Write-Host "Applying setting: Enable Scan All Downloads (DisableIOAVProtection = 0)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyRTP -ValueName "DisableIOAVProtection" -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for DisableIOAVProtection: $($_.Exception.Message)"
        }
        
        # Monitor file and program activity: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection (DWORD) = 0
        try {
            Write-Host "Applying setting: Enable monitoring of file and program activity (DisableOnAccessProtection = 0)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyRTP -ValueName "DisableOnAccessProtection" -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for DisableOnAccessProtection: $($_.Exception.Message)"
        }

    } else {
        Write-Warning "'rtpEnabled' is false in the JSON. This script enforces 'true' states for Defender components. No GPO settings applied for Real-Time Protection."
    }
} else {
    Write-Warning "JSON field 'rtpEnabled' not found. Skipping related GPO settings."
}


# 3. signatureOutOfDate: true (This means "Require signatures to be NOT out of date")
# This implies configuring Defender to update signatures regularly.
if ($policyObject.PSObject.Properties.Match('signatureOutOfDate').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.signatureOutOfDate -eq $true) { # Policy requires signatures to be current
        $regKeySU = "SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
        
        # Setting Signature Update Interval (e.g., every 4 hours)
        # GPO: Specify the interval to check for definition updates
        try {
            Write-Host "Applying setting: Set Signature Update Interval to 4 hours"
            Set-GPRegistryValue -Name $gpoName -Key $regKeySU -ValueName "SignatureUpdateInterval" -Type DWord -Value 4 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for SignatureUpdateInterval: $($_.Exception.Message)"
        }

        # Setting Fallback Order (ensure Microsoft Update Server is an option)
        # GPO: Define the order of sources for downloading definitions
        try {
            Write-Host "Applying setting: Set Signature Update Fallback Order"
            Set-GPRegistryValue -Name $gpoName -Key $regKeySU -ValueName "FallbackOrder" -Type String -Value "MicrosoftUpdateServer|InternalDefinitionUpdateServer|MMPC" -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for FallbackOrder: $($_.Exception.Message)"
        }
        
        # Check for new signatures before scheduled scans
        # GPO: Check for new virus and spyware definitions before scanning
        # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan\CheckForSignaturesBeforeRunningScan (DWORD) = 1
        try {
            Write-Host "Applying setting: Check for new signatures before scheduled scans (CheckForSignaturesBeforeRunningScan = 1)"
            Set-GPRegistryValue -Name $gpoName -Key "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -ValueName "CheckForSignaturesBeforeRunningScan" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for CheckForSignaturesBeforeRunningScan: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "'signatureOutOfDate' is false in the JSON (meaning it's OK for signatures to be out of date). No GPO settings applied for signature updates."
    }
} else {
    Write-Warning "JSON field 'signatureOutOfDate' not found. Skipping related GPO settings."
}

# --- Placeholder for settings not translated ---
Write-Host "---"
Write-Host "The following compliance settings from the JSON were noted but NOT directly translated into Set-GPRegistryValue commands by this script:"
$unmappedSettings = @(
    "passwordRequired", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", "passwordMinutesOfInactivityBeforeLock", 
    "passwordExpirationDays", "passwordMinimumLength", "passwordMinimumCharacterSetCount", "passwordRequiredType", 
    "passwordPreviousPasswordBlockCount", "requireHealthyDeviceReport", "osMinimumVersion", "osMaximumVersion", 
    "mobileOsMinimumVersion", "mobileOsMaximumVersion", "earlyLaunchAntiMalwareDriverEnabled", "bitLockerEnabled", 
    "secureBootEnabled", "codeIntegrityEnabled", "memoryIntegrityEnabled", "kernelDmaProtectionEnabled", 
    "virtualizationBasedSecurityEnabled", "firmwareProtectionEnabled", "storageRequireEncryption", "activeFirewallRequired", 
    "antivirusRequired", "antiSpywareRequired", "deviceThreatProtectionEnabled", 
    "deviceThreatProtectionRequiredSecurityLevel", "configurationManagerComplianceRequired", "tpmRequired",
    "deviceCompliancePolicyScript", "validOperatingSystemBuildRanges"
)
foreach ($settingName in $unmappedSettings) {
    if ($policyObject.PSObject.Properties.Match($settingName).Count -gt 0) {
        $value = $policyObject.$settingName
        if ($value -is [array]) { $value = $value -join ", " } # Basic array display
        if ($value -is $null) { $value = "null" }
        Write-Host "- $settingName: $value"
         # Increment if we want to count these as "interpreted" even if not mapped
         # $interpretedSettingsFromJson++ 
    }
}
Write-Host "Reasons for not mapping include: setting is 'false', represents a device state check not directly enforced by a simple registry key, requires complex GPO (e.g., MDE onboarding), or is outside Defender AV scope."
Write-Host "---"


# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Compliance Policy (Intune)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Regarding 'settingCount':"
Write-Host "The input JSON is an Intune Compliance Policy, which does not have a 'settingCount' field or a generic 'settings' array with 'settingDefinitionId'/'settingInstance'."
Write-Host "Therefore, the script interprets specific, known properties from the compliance policy JSON."
Write-Host ""
Write-Host "Number of distinct settings/conditions interpreted from JSON for GPO translation: $interpretedSettingsFromJson"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation:"
Write-Host "The count of 'interpreted settings' and 'executed commands' may differ because:"
Write-Host "  1. Some Intune compliance checks (e.g., 'rtpEnabled', 'signatureOutOfDate') are translated into multiple specific registry values to ensure comprehensive GPO enforcement."
Write-Host "  2. Compliance settings in the JSON that are 'false' (e.g., 'bitLockerEnabled: false') or not applicable for direct GPO registry enforcement are documented but skipped for Set-GPRegistryValue."
Write-Host "  3. If a property is missing from the JSON, it's skipped."
Write-Host "This script focuses on translating 'true' or active Defender-related compliance states into enforcing GPO settings."
Write-Host "--------------------------------------------------------------------"

# To use this script:
# 1. Save it as a .ps1 file.
# 2. Obtain the Intune Compliance Policy JSON content.
# 3. Run the script: .\ThisScript.ps1 -JsonContentIn (Get-Content -Raw ./path/to/your/policy.json)
# Ensure the execution policy allows running scripts and you have GPMC installed (RSAT tools).
# Example:
# $jsonFile = "WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - Compliance - U - Defender for Endpoint - v3.1.json"
# $jsonString = Get-Content -Path $jsonFile -Raw
# .\CreateGpoFromIntuneCompliance.ps1 -JsonContentIn $jsonString

Write-Host "Script finished."
